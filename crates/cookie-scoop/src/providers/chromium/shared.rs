use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::types::ValueRef;

use crate::types::{
    dedupe_cookies, BrowserName, Cookie, CookieSameSite, CookieSource, GetCookiesResult,
};
use crate::util::expire::normalize_expiration;
use crate::util::host_match::host_matches_cookie_scope;
use crate::util::origins::extract_host;
use crate::util::sqlite::{copy_database, host_predicate, table_columns, READ_ONLY};

use super::crypto::DecryptError;

pub type DecryptFn = Box<dyn Fn(&[u8], Option<&str>) -> Result<String, DecryptError> + Send + Sync>;

pub async fn get_cookies_from_chrome_sqlite_db(
    db_path: &str,
    profile: Option<&str>,
    include_expired: bool,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
    decrypt: DecryptFn,
    browser: BrowserName,
) -> GetCookiesResult {
    read_database(
        PathBuf::from(db_path),
        CookieSource {
            browser,
            profile: profile.map(str::to_owned),
            origin: None,
            store_id: None,
        },
        include_expired,
        origins,
        allowlist_names,
        decrypt,
    )
    .await
}

pub(crate) async fn read_database(
    db_path: PathBuf,
    source: CookieSource,
    include_expired: bool,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
    decrypt: DecryptFn,
) -> GetCookiesResult {
    let hosts: Vec<_> = origins
        .iter()
        .filter_map(|origin| extract_host(origin))
        .collect();
    if hosts.is_empty() {
        return GetCookiesResult {
            cookies: vec![],
            warnings: vec![],
        };
    }

    let names = allowlist_names.cloned();
    let result = tokio::task::spawn_blocking(move || {
        query_chromium_cookies(
            &db_path,
            &source,
            include_expired,
            &hosts,
            names.as_ref(),
            &decrypt,
        )
    })
    .await;
    match result {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => GetCookiesResult {
            cookies: vec![],
            warnings: vec![format!("Failed reading Chromium cookies: {error}")],
        },
        Err(error) => GetCookiesResult {
            cookies: vec![],
            warnings: vec![format!("Chromium cookie task failed: {error}")],
        },
    }
}

fn query_chromium_cookies(
    db_path: &Path,
    source: &CookieSource,
    include_expired: bool,
    hosts: &[String],
    allowlist_names: Option<&HashSet<String>>,
    decrypt: &DecryptFn,
) -> Result<GetCookiesResult, Box<dyn std::error::Error + Send + Sync>> {
    let temp = tempfile::Builder::new()
        .prefix("cookie-scoop-chrome-")
        .tempdir()?;
    let snapshot = temp.path().join("Cookies");
    copy_database(db_path, &snapshot)?;
    let conn = rusqlite::Connection::open_with_flags(snapshot, READ_ONLY)?;
    let verify_binding = read_meta_version(&conn) >= 24;
    let columns = table_columns(&conn, "cookies")?;
    let partition_key = if columns.contains("top_frame_site_key") {
        "top_frame_site_key"
    } else {
        "NULL"
    };
    let host_filter = host_predicate(hosts, "host_key");
    let mut stmt = conn.prepare(&format!(
        "SELECT name, value, host_key, path, expires_utc, samesite, encrypted_value,
                is_secure, is_httponly, {partition_key}
         FROM cookies WHERE ({host_filter}) ORDER BY expires_utc DESC"
    ))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut rows = stmt.query([])?;
    let mut cookies = Vec::new();
    let mut warnings = Vec::new();
    let mut partitioned = 0;
    let mut invalid_binding = 0;
    let mut app_bound = 0;
    let mut decrypt_failed = 0;
    let mut unsupported_type = false;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        if name.is_empty()
            || allowlist_names.is_some_and(|names| !names.is_empty() && !names.contains(&name))
        {
            continue;
        }

        let host: String = row.get(2)?;
        let host_only = !host.starts_with('.');
        if !hosts
            .iter()
            .any(|requested| host_matches_cookie_scope(requested, &host, host_only))
        {
            continue;
        }
        if row
            .get::<_, Option<String>>(9)?
            .is_some_and(|key| !key.trim().is_empty())
        {
            partitioned += 1;
            continue;
        }

        let expires = normalize_expiration(row.get(4)?);
        if !include_expired && expires.is_some_and(|expiry| expiry < now) {
            continue;
        }

        let value: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let value = if value.is_empty() {
            let encrypted = match row.get_ref(6)? {
                ValueRef::Blob(encrypted) if !encrypted.is_empty() => encrypted,
                ValueRef::Blob(_) | ValueRef::Null => continue,
                _ => {
                    unsupported_type = true;
                    continue;
                }
            };
            match decrypt(encrypted, verify_binding.then_some(host.as_str())) {
                Ok(value) => value,
                Err(error) => {
                    if encrypted.starts_with(b"v20") {
                        app_bound += 1;
                    } else if error == DecryptError::HostBinding {
                        invalid_binding += 1;
                    } else {
                        decrypt_failed += 1;
                    }
                    continue;
                }
            }
        } else {
            value
        };

        let same_site = match row.get::<_, Option<i32>>(5)? {
            Some(2) => Some(CookieSameSite::Strict),
            Some(1) => Some(CookieSameSite::Lax),
            Some(0) => Some(CookieSameSite::None),
            _ => None,
        };
        let path: String = row.get(3)?;
        cookies.push(Cookie {
            name,
            value,
            domain: Some(host.trim_start_matches('.').to_owned()),
            host_only: Some(host_only),
            path: Some(if path.is_empty() {
                "/".to_owned()
            } else {
                path
            }),
            url: None,
            expires,
            secure: Some(row.get::<_, i32>(7)? != 0),
            http_only: Some(row.get::<_, i32>(8)? != 0),
            same_site,
            source: Some(source.clone()),
        });
    }
    if partitioned != 0 {
        warnings.push(format!(
            "{partitioned} partitioned Chromium cookie(s) were excluded."
        ));
    }
    if invalid_binding != 0 {
        warnings.push(format!(
            "{invalid_binding} Chromium cookie(s) failed host binding verification."
        ));
    }
    if app_bound != 0 {
        warnings.push(format!("{app_bound} Chromium cookie(s) use v20 App-Bound Encryption and could not be decrypted."));
    }
    if decrypt_failed != 0 {
        warnings.push(format!(
            "{decrypt_failed} Chromium cookie(s) could not be decrypted."
        ));
    }
    if unsupported_type {
        warnings.push("Chromium cookie encrypted_value is in an unsupported type.".to_owned());
    }
    Ok(GetCookiesResult {
        cookies: dedupe_cookies(cookies),
        warnings,
    })
}

fn read_meta_version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'version'",
        [],
        |row| match row.get_ref(0)? {
            ValueRef::Integer(value) => Ok(value),
            ValueRef::Text(value) => Ok(std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)),
            _ => Ok(0),
        },
    )
    .unwrap_or(0)
}

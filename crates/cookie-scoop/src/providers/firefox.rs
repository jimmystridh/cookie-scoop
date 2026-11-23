use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{
    dedupe_cookies, BrowserName, Cookie, CookieSameSite, CookieSource, GetCookiesResult,
    ProfileSelection,
};
use crate::util::host_match::host_matches_cookie_scope;
use crate::util::origins::extract_host;
use crate::util::sqlite::{copy_database, host_predicate, table_columns, READ_ONLY};

pub async fn get_cookies_from_firefox(
    options: FirefoxOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
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
        let mut result = GetCookiesResult { cookies: vec![], warnings: vec![] };
        let mut seen = HashSet::new();
        for selector in super::profile_selectors(options.profiles.as_ref(), options.profile.as_deref()) {
            let databases = resolve_firefox_databases(selector);
            if databases.is_empty() {
                result.warnings.push("Firefox cookies database not found.".to_owned());
            }
            for db in databases {
                let identity = db.canonicalize().unwrap_or_else(|_| db.clone());
                if !seen.insert(identity) {
                    continue;
                }
                let profile = db.parent().and_then(Path::file_name).map(|name| name.to_string_lossy().into_owned());
                match read_firefox_database(&db, &hosts, options.include_expired.unwrap_or(false), names.as_ref(), profile) {
                    Ok((cookies, isolated)) => {
                        result.cookies.extend(dedupe_cookies(cookies));
                        if isolated != 0 {
                            result.warnings.push(format!("{isolated} Firefox cookie(s) with partition or container provenance were excluded."));
                        }
                    }
                    Err(error) => result.warnings.push(format!("Failed reading Firefox cookies: {error}")),
                }
            }
        }
        result
    })
    .await;
    result.unwrap_or_else(|error| GetCookiesResult {
        cookies: vec![],
        warnings: vec![format!("Firefox cookie task failed: {error}")],
    })
}

#[derive(Debug, Default)]
pub struct FirefoxOptions {
    pub profile: Option<String>,
    pub include_expired: Option<bool>,
    pub profiles: Option<ProfileSelection>,
}

fn read_firefox_database(
    db_path: &Path,
    hosts: &[String],
    include_expired: bool,
    allowlist_names: Option<&HashSet<String>>,
    profile: Option<String>,
) -> Result<(Vec<Cookie>, usize), Box<dyn std::error::Error>> {
    let temp = tempfile::Builder::new()
        .prefix("cookie-scoop-firefox-")
        .tempdir()?;
    let snapshot = temp.path().join("cookies.sqlite");
    copy_database(db_path, &snapshot)?;
    let conn = rusqlite::Connection::open_with_flags(snapshot, READ_ONLY)?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let columns = table_columns(&conn, "moz_cookies")?;

    let expiry_units_per_second = if version >= 16 { 1_000 } else { 1 };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now_in_db_units = if expiry_units_per_second == 1_000 {
        now.as_millis() as i64
    } else {
        now.as_secs() as i64
    };
    let expiry_filter = if include_expired {
        ""
    } else {
        "AND (expiry = 0 OR expiry > ?1)"
    };
    let origin_attributes = if columns.contains("originAttributes") {
        "originAttributes"
    } else {
        "NULL"
    };
    let partitioned = if columns.contains("isPartitionedAttributeSet") {
        "isPartitionedAttributeSet"
    } else {
        "NULL"
    };
    let hosts_sql = host_predicate(hosts, "host");
    let mut stmt = conn.prepare(&format!(
        "SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite,
                {origin_attributes}, {partitioned}
         FROM moz_cookies WHERE ({hosts_sql}) {expiry_filter} ORDER BY expiry DESC"
    ))?;
    let expiry_parameter = (!include_expired).then_some(now_in_db_units);
    let mut rows = stmt.query(rusqlite::params_from_iter(expiry_parameter))?;
    let mut cookies = Vec::new();
    let mut isolated = 0;
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
        let attributes: Option<String> = row.get(8)?;
        let partitioned: Option<i64> = row.get(9)?;
        if attributes.is_some_and(|value| !value.trim().is_empty()) || partitioned.unwrap_or(0) != 0
        {
            isolated += 1;
            continue;
        }
        let path: String = row.get(3)?;
        let expiry_seconds = row.get::<_, i64>(4)? / expiry_units_per_second;
        let same_site = match row.get::<_, Option<i32>>(7)? {
            Some(2) => Some(CookieSameSite::Strict),
            Some(1) => Some(CookieSameSite::Lax),
            Some(0) => Some(CookieSameSite::None),
            _ => None,
        };

        cookies.push(Cookie {
            name,
            value: row.get(1)?,
            domain: Some(host.trim_start_matches('.').to_owned()),
            host_only: Some(host_only),
            path: Some(if path.is_empty() {
                "/".to_owned()
            } else {
                path
            }),
            url: None,
            expires: (1..=253_402_300_799)
                .contains(&expiry_seconds)
                .then_some(expiry_seconds),
            secure: Some(row.get::<_, i32>(5)? != 0),
            http_only: Some(row.get::<_, i32>(6)? != 0),
            same_site,
            source: Some(CookieSource {
                browser: BrowserName::Firefox,
                profile: profile.clone(),
                origin: None,
                store_id: None,
            }),
        });
    }
    Ok((cookies, isolated))
}

fn resolve_firefox_databases(selector: super::ProfileSelector<'_>) -> Vec<PathBuf> {
    use super::chromium::paths::{expand_path, looks_like_path};
    use super::ProfileSelector;

    if let ProfileSelector::Named(profile) = selector {
        let expanded = expand_path(profile);
        if looks_like_path(profile) || expanded.is_file() {
            return if expanded.is_file() {
                vec![expanded]
            } else {
                let candidate = expanded.join("cookies.sqlite");
                candidate
                    .is_file()
                    .then_some(candidate)
                    .into_iter()
                    .collect()
            };
        }
    }

    let mut databases = Vec::new();
    for root in firefox_roots() {
        if let ProfileSelector::Named(profile) = selector {
            let candidate = root.join(profile).join("cookies.sqlite");
            if candidate.is_file() {
                return vec![candidate];
            }
            continue;
        }

        let mut profiles: Vec<_> = std::fs::read_dir(root)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().join("cookies.sqlite").is_file())
            .collect();
        profiles.sort_by_key(|entry| entry.file_name());
        let mut candidates = profiles.into_iter().map(|entry| {
            let preferred = entry
                .file_name()
                .to_string_lossy()
                .contains("default-release");
            (preferred, entry.path().join("cookies.sqlite"))
        });
        if selector == ProfileSelector::All {
            databases.extend(candidates.map(|(_, path)| path));
        } else if let Some((preferred, first)) = candidates.next() {
            if preferred {
                return vec![first];
            }
            return vec![candidates
                .find(|(preferred, _)| *preferred)
                .map_or(first, |(_, path)| path)];
        }
    }
    databases
}

fn firefox_roots() -> Vec<PathBuf> {
    if cfg!(target_os = "windows") {
        return std::env::var_os("APPDATA")
            .map(|root| PathBuf::from(root).join("Mozilla/Firefox/Profiles"))
            .into_iter()
            .collect();
    }
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    if cfg!(target_os = "macos") {
        return vec![home.join("Library/Application Support/Firefox/Profiles")];
    }
    if cfg!(target_os = "linux") {
        let config = super::chromium::paths::linux_config_home(&home);
        return vec![
            config.join("mozilla/firefox"),
            home.join(".mozilla/firefox"),
            home.join("snap/firefox/common/.mozilla/firefox"),
            home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
            home.join(".var/app/org.mozilla.firefox/config/mozilla/firefox"),
        ];
    }
    vec![]
}

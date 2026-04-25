use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::types::{
    dedupe_cookies, BrowserName, Cookie, CookieSameSite, CookieSource, GetCookiesResult,
};
use crate::util::host_match::host_matches_cookie_domain;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub struct FirefoxBrowser {
    pub name: BrowserName,
    label: &'static str,
    temp_prefix: &'static str,
    roots: fn() -> Vec<PathBuf>,
    preferred_profile_markers: &'static [&'static str],
}

#[derive(Debug, Default)]
pub struct FirefoxOptions {
    pub profile: Option<String>,
    pub include_expired: Option<bool>,
}

pub const FIREFOX: FirefoxBrowser = FirefoxBrowser {
    name: BrowserName::Firefox,
    label: "Firefox",
    temp_prefix: "cookie-scoop-firefox-",
    roots: firefox_roots,
    preferred_profile_markers: &["default-release"],
};

pub const ZEN: FirefoxBrowser = FirefoxBrowser {
    name: BrowserName::Zen,
    label: "Zen",
    temp_prefix: "cookie-scoop-zen-",
    roots: zen_roots,
    preferred_profile_markers: &["Default", "default"],
};

pub async fn get_cookies_from_firefox(
    browser: FirefoxBrowser,
    options: FirefoxOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    let Some(db_path) = resolve_firefox_cookies_db(
        options.profile.as_deref(),
        &(browser.roots)(),
        browser.preferred_profile_markers,
    ) else {
        return warning(format!("{} cookies database not found.", browser.label));
    };

    let temp_dir = match tempfile::Builder::new()
        .prefix(browser.temp_prefix)
        .tempdir()
    {
        Ok(d) => d,
        Err(e) => return warning(format!("Failed to create temp dir: {e}")),
    };

    let temp_db_path = temp_dir.path().join("cookies.sqlite");
    if let Err(e) = std::fs::copy(&db_path, &temp_db_path) {
        return warning(format!("Failed to copy {} cookie DB: {e}", browser.label));
    }
    copy_sidecar(&db_path, &temp_db_path, "-wal");
    copy_sidecar(&db_path, &temp_db_path, "-shm");

    let hosts: Vec<String> = origins
        .iter()
        .filter_map(|o| {
            Url::parse(o)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let include_expired = options.include_expired.unwrap_or(false);

    let where_clause = build_host_where_clause(&hosts);
    let expiry_clause = if include_expired {
        String::new()
    } else {
        format!(" AND (expiry = 0 OR expiry > {now})")
    };
    let sql = format!(
        "SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite \
         FROM moz_cookies WHERE ({where_clause}){expiry_clause} ORDER BY expiry DESC;"
    );

    let db_path_str = temp_db_path.to_string_lossy().to_string();
    let profile = options.profile.clone();
    let browser_name = browser.name;
    let names_owned = allowlist_names.cloned();
    let result = tokio::task::spawn_blocking(move || {
        query_firefox_cookies(
            &db_path_str,
            &sql,
            &hosts,
            include_expired,
            names_owned.as_ref(),
            profile.as_deref(),
            browser_name,
        )
    })
    .await;

    match result {
        Ok(Ok(cookies)) => GetCookiesResult {
            cookies: dedupe_cookies(cookies),
            warnings: vec![],
        },
        Ok(Err(e)) => warning(format!("Failed reading {} cookies: {e}", browser.label)),
        Err(e) => warning(format!("{} cookie task failed: {e}", browser.label)),
    }
}

fn query_firefox_cookies(
    db_path: &str,
    sql: &str,
    hosts: &[String],
    include_expired: bool,
    allowlist_names: Option<&HashSet<String>>,
    profile: Option<&str>,
    browser: BrowserName,
) -> Result<Vec<Cookie>, String> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;

    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let host: String = row.get(2)?;
            let path: String = row.get(3)?;
            let expiry: i64 = row.get(4)?;
            let is_secure: i32 = row.get(5)?;
            let is_http_only: i32 = row.get(6)?;
            let same_site: i32 = row.get(7)?;
            Ok((
                name,
                value,
                host,
                path,
                expiry,
                is_secure,
                is_http_only,
                same_site,
            ))
        })
        .map_err(|e| e.to_string())?;

    let mut cookies = Vec::new();
    for row in rows {
        let (name, value, host, path, expiry, is_secure, is_http_only, same_site) =
            row.map_err(|e| e.to_string())?;

        if name.is_empty() {
            continue;
        }
        if allowlist_names.is_some_and(|names| !names.is_empty() && !names.contains(&name)) {
            continue;
        }

        let cookie_domain = host.strip_prefix('.').unwrap_or(&host);
        if !hosts
            .iter()
            .any(|h| host_matches_cookie_domain(h, cookie_domain))
        {
            continue;
        }

        let expires = if expiry > 0 { Some(expiry) } else { None };
        if !include_expired && expires.is_some_and(|exp| exp < now) {
            continue;
        }

        let domain = host.strip_prefix('.').unwrap_or(&host).to_string();
        let same_site_val = match same_site {
            2 => Some(CookieSameSite::Strict),
            1 => Some(CookieSameSite::Lax),
            0 => Some(CookieSameSite::None),
            _ => None,
        };

        let source = CookieSource {
            browser,
            profile: profile.map(str::to_string),
            origin: None,
            store_id: None,
        };

        cookies.push(Cookie {
            name,
            value,
            domain: Some(domain),
            path: Some(if path.is_empty() {
                "/".to_string()
            } else {
                path
            }),
            url: None,
            expires,
            secure: Some(is_secure != 0),
            http_only: Some(is_http_only != 0),
            same_site: same_site_val,
            source: Some(source),
        });
    }

    Ok(cookies)
}

fn warning(message: impl Into<String>) -> GetCookiesResult {
    GetCookiesResult {
        cookies: vec![],
        warnings: vec![message.into()],
    }
}

fn resolve_firefox_cookies_db(
    profile: Option<&str>,
    roots: &[PathBuf],
    preferred_profile_markers: &[&str],
) -> Option<PathBuf> {
    if let Some(profile) = profile {
        if looks_like_path(profile) {
            let p = PathBuf::from(profile);
            let candidate = if profile.ends_with("cookies.sqlite") {
                p
            } else {
                p.join("cookies.sqlite")
            };
            return if candidate.exists() {
                Some(candidate)
            } else {
                None
            };
        }
    }

    for root in roots {
        if !root.exists() {
            continue;
        }
        if let Some(profile) = profile {
            let candidate = root.join(profile).join("cookies.sqlite");
            if candidate.exists() {
                return Some(candidate);
            }
            continue;
        }

        let entries = safe_readdir(root);
        let preferred_profile = preferred_profile_markers
            .iter()
            .find_map(|marker| entries.iter().find(|e| e.contains(marker)));
        let picked = preferred_profile.or(entries.first());
        if let Some(picked) = picked {
            let candidate = root.join(picked).join("cookies.sqlite");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn home_roots(paths: &[&str]) -> Vec<PathBuf> {
    dirs::home_dir()
        .map(|home| paths.iter().map(|path| home.join(path)).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn appdata_roots(paths: &[&str]) -> Vec<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|appdata| {
            paths
                .iter()
                .map(|path| PathBuf::from(&appdata).join(path))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn firefox_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/Firefox/Profiles"])
}

#[cfg(target_os = "macos")]
fn zen_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/zen/Profiles"])
}

#[cfg(target_os = "linux")]
fn firefox_roots() -> Vec<PathBuf> {
    home_roots(&[".mozilla/firefox"])
}

#[cfg(target_os = "linux")]
fn zen_roots() -> Vec<PathBuf> {
    home_roots(&[".zen", ".var/app/app.zen_browser.zen/.zen"])
}

#[cfg(target_os = "windows")]
fn firefox_roots() -> Vec<PathBuf> {
    appdata_roots(&["Mozilla/Firefox/Profiles"])
}

#[cfg(target_os = "windows")]
fn zen_roots() -> Vec<PathBuf> {
    appdata_roots(&["zen/Profiles"])
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn firefox_roots() -> Vec<PathBuf> {
    vec![]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn zen_roots() -> Vec<PathBuf> {
    vec![]
}

fn safe_readdir(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn copy_sidecar(source_db_path: &Path, temp_db_path: &Path, suffix: &str) {
    let sidecar = PathBuf::from(format!("{}{}", source_db_path.to_string_lossy(), suffix));
    let target = PathBuf::from(format!("{}{}", temp_db_path.to_string_lossy(), suffix));
    if sidecar.exists() {
        let _ = std::fs::copy(&sidecar, &target);
    }
}

fn build_host_where_clause(hosts: &[String]) -> String {
    let mut clauses = Vec::new();
    for host in hosts {
        let escaped = sql_literal(host);
        let escaped_dot = sql_literal(&format!(".{host}"));
        let escaped_like = sql_literal(&format!("%.{host}"));
        clauses.push(format!("host = {escaped}"));
        clauses.push(format!("host = {escaped_dot}"));
        clauses.push(format!("host LIKE {escaped_like}"));
    }
    if clauses.is_empty() {
        "1=0".to_string()
    } else {
        clauses.join(" OR ")
    }
}

fn sql_literal(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

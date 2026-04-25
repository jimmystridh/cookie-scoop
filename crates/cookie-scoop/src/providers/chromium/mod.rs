use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::path::Path;
use std::path::PathBuf;

use crate::types::{BrowserName, GetCookiesResult};

#[cfg(target_os = "windows")]
use crypto::decrypt_chromium_aes256_gcm;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crypto::{decrypt_chromium_aes128_cbc, derive_aes128_cbc_key};
#[cfg(target_os = "linux")]
use linux_keyring::{get_linux_chromium_safe_storage_password, LinuxKeyringApp};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use shared::{get_cookies_from_chrome_sqlite_db, DecryptFn};

pub mod crypto;
pub mod keychain;
pub mod linux_keyring;
pub mod shared;
pub mod windows_dpapi;
pub mod windows_master_key;

#[derive(Debug, Clone, Copy)]
pub struct ChromiumBrowser {
    pub name: BrowserName,
    label: &'static str,
    roots: fn() -> Vec<PathBuf>,
    #[cfg(target_os = "macos")]
    keychain_service: &'static str,
    #[cfg(target_os = "macos")]
    keychain_accounts: &'static [&'static str],
    #[cfg(target_os = "linux")]
    linux_keyring: LinuxKeyringApp,
    #[cfg(target_os = "windows")]
    windows_user_data: &'static str,
    #[cfg(target_os = "windows")]
    windows_key_label: &'static str,
}

#[derive(Debug, Default)]
pub struct ChromiumOptions {
    pub profile: Option<String>,
    pub timeout_ms: Option<u64>,
    pub include_expired: Option<bool>,
}

pub const CHROME: ChromiumBrowser = ChromiumBrowser {
    name: BrowserName::Chrome,
    label: "Chrome",
    roots: chrome_roots,
    #[cfg(target_os = "macos")]
    keychain_service: "Chrome Safe Storage",
    #[cfg(target_os = "macos")]
    keychain_accounts: &["Chrome Safe Storage"],
    #[cfg(target_os = "linux")]
    linux_keyring: LinuxKeyringApp {
        password_env: "SWEET_COOKIE_CHROME_SAFE_STORAGE_PASSWORD",
        service: "Chrome Safe Storage",
        account: "Chrome",
        folder: "Chrome Keys",
        gnome_application: "chrome",
    },
    #[cfg(target_os = "windows")]
    windows_user_data: "Google\\Chrome\\User Data",
    #[cfg(target_os = "windows")]
    windows_key_label: "Chrome",
};

pub const EDGE: ChromiumBrowser = ChromiumBrowser {
    name: BrowserName::Edge,
    label: "Edge",
    roots: edge_roots,
    #[cfg(target_os = "macos")]
    keychain_service: "Microsoft Edge Safe Storage",
    #[cfg(target_os = "macos")]
    keychain_accounts: &["Microsoft Edge Safe Storage", "Microsoft Edge"],
    #[cfg(target_os = "linux")]
    linux_keyring: LinuxKeyringApp {
        password_env: "SWEET_COOKIE_EDGE_SAFE_STORAGE_PASSWORD",
        service: "Microsoft Edge Safe Storage",
        account: "Microsoft Edge",
        folder: "Microsoft Edge Keys",
        gnome_application: "msedge",
    },
    #[cfg(target_os = "windows")]
    windows_user_data: "Microsoft\\Edge\\User Data",
    #[cfg(target_os = "windows")]
    windows_key_label: "Edge",
};

pub async fn get_cookies_from_chromium(
    browser: ChromiumBrowser,
    options: ChromiumOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    #[cfg(target_os = "macos")]
    {
        get_cookies_from_chromium_macos(browser, &options, origins, allowlist_names).await
    }
    #[cfg(target_os = "linux")]
    {
        get_cookies_from_chromium_linux(browser, &options, origins, allowlist_names).await
    }
    #[cfg(target_os = "windows")]
    {
        get_cookies_from_chromium_windows(browser, &options, origins, allowlist_names).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (browser, options, origins, allowlist_names);
        GetCookiesResult {
            cookies: vec![],
            warnings: vec![],
        }
    }
}

#[cfg(target_os = "macos")]
async fn get_cookies_from_chromium_macos(
    browser: ChromiumBrowser,
    options: &ChromiumOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    use keychain::read_keychain_generic_password_first;

    let Some(db_path) = resolve_db(browser, options) else {
        return warning(format!("{} cookies database not found.", browser.label));
    };

    let password = match read_keychain_generic_password_first(
        browser.label,
        browser.keychain_accounts,
        options.timeout_ms.unwrap_or(3_000),
        browser.keychain_service,
    )
    .await
    {
        Ok(password) if !password.trim().is_empty() => password,
        Ok(_) => {
            return warning(format!(
                "macOS Keychain returned an empty {} password.",
                browser.keychain_service
            ));
        }
        Err(e) => return warning(e),
    };

    let key = derive_aes128_cbc_key(password.trim(), 1003);
    read_cookies(
        browser,
        options,
        db_path,
        origins,
        allowlist_names,
        Box::new(move |encrypted_value, strip_hash_prefix| {
            decrypt_chromium_aes128_cbc(
                encrypted_value,
                std::slice::from_ref(&key),
                strip_hash_prefix,
                true,
            )
        }),
    )
    .await
}

#[cfg(target_os = "linux")]
async fn get_cookies_from_chromium_linux(
    browser: ChromiumBrowser,
    options: &ChromiumOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    let Some(db_path) = resolve_db(browser, options) else {
        return warning(format!("{} cookies database not found.", browser.label));
    };

    let (password, warnings) =
        get_linux_chromium_safe_storage_password(browser.linux_keyring, None).await;
    let v10_key = derive_aes128_cbc_key("peanuts", 1);
    let empty_key = derive_aes128_cbc_key("", 1);
    let v11_key = derive_aes128_cbc_key(&password, 1);

    with_warnings(
        warnings,
        read_cookies(
            browser,
            options,
            db_path,
            origins,
            allowlist_names,
            Box::new(move |encrypted_value, strip_hash_prefix| {
                match encrypted_value
                    .get(..3)
                    .and_then(|prefix| std::str::from_utf8(prefix).ok())
                {
                    Some("v10") => decrypt_chromium_aes128_cbc(
                        encrypted_value,
                        &[v10_key.clone(), empty_key.clone()],
                        strip_hash_prefix,
                        false,
                    ),
                    Some("v11") => decrypt_chromium_aes128_cbc(
                        encrypted_value,
                        &[v11_key.clone(), empty_key.clone()],
                        strip_hash_prefix,
                        false,
                    ),
                    _ => None,
                }
            }),
        )
        .await,
    )
}

#[cfg(target_os = "windows")]
async fn get_cookies_from_chromium_windows(
    browser: ChromiumBrowser,
    options: &ChromiumOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    use windows_master_key::get_windows_chromium_master_key;

    let (db_path, user_data_dir) =
        resolve_chromium_paths_windows(browser.windows_user_data, options.profile.as_deref());
    let Some(db_path) = db_path else {
        return warning(format!("{} cookies database not found.", browser.label));
    };
    let Some(user_data_dir) = user_data_dir else {
        return warning(format!("{} user data directory not found.", browser.label));
    };
    let master_key =
        match get_windows_chromium_master_key(&user_data_dir, browser.windows_key_label).await {
            Ok(key) => key,
            Err(e) => return warning(e),
        };

    read_cookies(
        browser,
        options,
        db_path,
        origins,
        allowlist_names,
        Box::new(move |encrypted_value, strip_hash_prefix| {
            decrypt_chromium_aes256_gcm(encrypted_value, &master_key, strip_hash_prefix)
        }),
    )
    .await
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn resolve_db(browser: ChromiumBrowser, options: &ChromiumOptions) -> Option<PathBuf> {
    resolve_cookies_db_from_profile_or_roots(options.profile.as_deref(), &(browser.roots)())
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
async fn read_cookies(
    browser: ChromiumBrowser,
    options: &ChromiumOptions,
    db_path: PathBuf,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
    decrypt: DecryptFn,
) -> GetCookiesResult {
    get_cookies_from_chrome_sqlite_db(
        &db_path.to_string_lossy(),
        options.profile.as_deref(),
        options.include_expired.unwrap_or(false),
        origins,
        allowlist_names,
        decrypt,
        browser.name,
    )
    .await
}

fn warning(message: impl Into<String>) -> GetCookiesResult {
    GetCookiesResult {
        cookies: vec![],
        warnings: vec![message.into()],
    }
}

fn with_warnings(mut warnings: Vec<String>, mut result: GetCookiesResult) -> GetCookiesResult {
    warnings.append(&mut result.warnings);
    result.warnings = warnings;
    result
}

fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn expand_path(input: &str) -> PathBuf {
    input
        .strip_prefix("~/")
        .and_then(|rest| dirs::home_dir().map(|home| home.join(rest)))
        .unwrap_or_else(|| {
            let path = PathBuf::from(input);
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
                    .join(path)
            }
        })
}

fn resolve_cookies_db_from_profile_or_roots(
    profile: Option<&str>,
    roots: &[PathBuf],
) -> Option<PathBuf> {
    let profile = profile.filter(|profile| !profile.trim().is_empty());

    if let Some(profile) = profile.filter(|profile| looks_like_path(profile)) {
        let expanded = expand_path(profile);
        return if expanded.is_file() {
            Some(expanded)
        } else {
            [expanded.join("Cookies"), expanded.join("Network/Cookies")]
                .into_iter()
                .find(|candidate| candidate.exists())
        };
    }

    let profile = profile.unwrap_or("Default");
    roots.iter().find_map(|root| {
        [
            root.join(profile).join("Cookies"),
            root.join(profile).join("Network/Cookies"),
        ]
        .into_iter()
        .find(|candidate| candidate.exists())
    })
}

#[cfg(target_os = "macos")]
fn home_roots(paths: &[&str]) -> Vec<PathBuf> {
    dirs::home_dir()
        .map(|home| paths.iter().map(|path| home.join(path)).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn config_roots(paths: &[&str]) -> Vec<PathBuf> {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .map(|config| paths.iter().map(|path| config.join(path)).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn local_app_data_roots(paths: &[&str]) -> Vec<PathBuf> {
    std::env::var("LOCALAPPDATA")
        .ok()
        .map(|local_app_data| {
            paths
                .iter()
                .map(|path| PathBuf::from(&local_app_data).join(path))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn chrome_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/Google/Chrome"])
}

#[cfg(target_os = "macos")]
fn edge_roots() -> Vec<PathBuf> {
    home_roots(&["Library/Application Support/Microsoft Edge"])
}

#[cfg(target_os = "linux")]
fn chrome_roots() -> Vec<PathBuf> {
    config_roots(&["google-chrome"])
}

#[cfg(target_os = "linux")]
fn edge_roots() -> Vec<PathBuf> {
    config_roots(&["microsoft-edge"])
}

#[cfg(target_os = "windows")]
fn chrome_roots() -> Vec<PathBuf> {
    local_app_data_roots(&["Google/Chrome/User Data"])
}

#[cfg(target_os = "windows")]
fn edge_roots() -> Vec<PathBuf> {
    local_app_data_roots(&["Microsoft/Edge/User Data"])
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn chrome_roots() -> Vec<PathBuf> {
    vec![]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn edge_roots() -> Vec<PathBuf> {
    vec![]
}

#[cfg(target_os = "windows")]
fn resolve_chromium_paths_windows(
    local_app_data_vendor_path: &str,
    profile: Option<&str>,
) -> (Option<PathBuf>, Option<PathBuf>) {
    let root = match std::env::var("LOCALAPPDATA") {
        Ok(local_app_data) => PathBuf::from(local_app_data).join(local_app_data_vendor_path),
        Err(_) => return (None, None),
    };

    if let Some(profile) = profile.filter(|profile| looks_like_path(profile)) {
        let expanded = expand_path(profile);
        let candidates = if expanded.to_string_lossy().ends_with("Cookies") {
            vec![expanded]
        } else {
            vec![
                expanded.join("Network/Cookies"),
                expanded.join("Cookies"),
                expanded.join("Default/Network/Cookies"),
            ]
        };
        if let Some(candidate) = candidates.into_iter().find(|candidate| candidate.exists()) {
            let user_data_dir = find_user_data_dir(&candidate);
            return (Some(candidate), user_data_dir);
        }
        if expanded.join("Local State").exists() {
            return (None, Some(expanded));
        }
    }

    let profile = profile
        .filter(|p| !p.trim().is_empty())
        .unwrap_or("Default");
    let db_path = [
        root.join(profile).join("Network/Cookies"),
        root.join(profile).join("Cookies"),
    ]
    .into_iter()
    .find(|candidate| candidate.exists());
    (db_path, Some(root))
}

#[cfg(target_os = "windows")]
fn find_user_data_dir(cookies_db_path: &Path) -> Option<PathBuf> {
    cookies_db_path.ancestors().take(6).find_map(|path| {
        path.join("Local State")
            .exists()
            .then(|| path.to_path_buf())
    })
}

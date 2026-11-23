pub mod crypto;
pub mod keychain;
pub mod linux_keyring;
pub mod paths;
pub mod shared;
pub mod windows_dpapi;
pub mod windows_master_key;

use std::collections::HashSet;

use crate::types::{
    BrowserName, ChromiumBrowser, CookieSource, GetCookiesResult, ProfileSelection,
};

use super::{profile_selectors, ProfileSelector};
use shared::DecryptFn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChromiumTarget {
    Chrome(ChromiumBrowser),
    Edge,
}

impl ChromiumTarget {
    fn browser_name(self) -> BrowserName {
        match self {
            Self::Chrome(_) => BrowserName::Chrome,
            Self::Edge => BrowserName::Edge,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Chrome(ChromiumBrowser::Chrome) => "Chrome",
            Self::Chrome(ChromiumBrowser::Brave) => "Brave",
            Self::Chrome(ChromiumBrowser::Arc) => "Arc",
            Self::Chrome(ChromiumBrowser::Chromium) => "Chromium",
            Self::Chrome(ChromiumBrowser::Dia) => "Dia",
            Self::Edge => "Microsoft Edge",
        }
    }

    fn supported(self) -> bool {
        match self {
            Self::Edge | Self::Chrome(ChromiumBrowser::Chrome) => {
                cfg!(any(
                    target_os = "macos",
                    target_os = "linux",
                    target_os = "windows"
                ))
            }
            Self::Chrome(ChromiumBrowser::Brave | ChromiumBrowser::Chromium) => {
                cfg!(any(target_os = "macos", target_os = "linux"))
            }
            Self::Chrome(ChromiumBrowser::Arc | ChromiumBrowser::Dia) => cfg!(target_os = "macos"),
        }
    }
}

pub(crate) struct ChromiumOptions<'a> {
    pub target: ChromiumTarget,
    pub explicit_target: bool,
    pub profile: Option<&'a str>,
    pub profiles: Option<&'a ProfileSelection>,
    pub timeout_ms: Option<u64>,
    pub include_expired: bool,
}

pub(crate) async fn get_cookies_from_chromium(
    options: ChromiumOptions<'_>,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    let mut result = GetCookiesResult {
        cookies: vec![],
        warnings: vec![],
    };
    if !options.target.supported() {
        if options.explicit_target {
            result.warnings.push(format!(
                "{} profile discovery is unavailable on this platform.",
                options.target.label()
            ));
        }
        return result;
    }
    if !origins
        .iter()
        .any(|origin| crate::util::origins::extract_host(origin).is_some())
    {
        return result;
    }

    let mut roots = paths::target_roots(options.target);
    if cfg!(target_os = "macos")
        && options.target == ChromiumTarget::Chrome(ChromiumBrowser::Chrome)
        && !options.explicit_target
    {
        roots.extend(paths::target_roots(ChromiumTarget::Chrome(
            ChromiumBrowser::Brave,
        )));
    }
    let selectors = profile_selectors(options.profiles, options.profile);
    let preserve_store = selectors.len() > 1 || selectors[0] == ProfileSelector::All;
    let mut seen = HashSet::new();
    for selector in selectors {
        let databases = paths::resolve_databases(&roots, selector, &mut result.warnings);
        if databases.is_empty() {
            result.warnings.push(format!(
                "{} cookies database not found.",
                options.target.label()
            ));
        }
        for database in databases {
            let identity = database
                .path
                .canonicalize()
                .unwrap_or_else(|_| database.path.clone());
            if !seen.insert(identity.clone()) {
                continue;
            }
            let target = if options.explicit_target || options.target == ChromiumTarget::Edge {
                options.target
            } else {
                infer_target(&identity)
                    .or_else(|| infer_target(&database.path))
                    .unwrap_or(options.target)
            };
            let decrypt =
                platform_decrypter(target, &database, options.timeout_ms, &mut result.warnings)
                    .await;
            let Some(decrypt) = decrypt else {
                continue;
            };
            let source = CookieSource {
                browser: target.browser_name(),
                profile: database.profile,
                origin: None,
                store_id: preserve_store.then(|| identity.to_string_lossy().into_owned()),
            };
            let profile_result = shared::read_database(
                database.path,
                source,
                options.include_expired,
                origins,
                allowlist_names,
                decrypt,
            )
            .await;
            result.cookies.extend(profile_result.cookies);
            result.warnings.extend(profile_result.warnings);
        }
    }
    result
}

fn infer_target(db: &std::path::Path) -> Option<ChromiumTarget> {
    use ChromiumBrowser::*;
    let candidates = [Chrome, Chromium, Brave, Arc, Dia];
    candidates
        .into_iter()
        .map(ChromiumTarget::Chrome)
        .filter(|target| target.supported())
        .find(|target| {
            paths::target_roots(*target)
                .iter()
                .any(|root| db.starts_with(root))
        })
        .or_else(|| {
            let browser = db
                .components()
                .filter_map(|part| part.as_os_str().to_str())
                .find_map(|part| match part.to_ascii_lowercase().as_str() {
                    "bravesoftware" | "brave-browser" | "brave browser" => Some(Brave),
                    "chromium" => Some(Chromium),
                    "arc" => Some(Arc),
                    "dia" => Some(Dia),
                    _ => None,
                })?;
            let target = ChromiumTarget::Chrome(browser);
            target.supported().then_some(target)
        })
}

#[cfg(target_os = "macos")]
async fn platform_decrypter(
    target: ChromiumTarget,
    _database: &paths::ChromiumDatabase,
    timeout_ms: Option<u64>,
    warnings: &mut Vec<String>,
) -> Option<DecryptFn> {
    use crypto::{decrypt_chromium_aes128_cbc, derive_aes128_cbc_key};

    let label = format!("{} Safe Storage", target.label());
    let mut services = vec![label.as_str()];
    if target == ChromiumTarget::Edge {
        services.push("Microsoft Edge");
    }
    let key = match keychain::read_keychain_generic_password_first(
        target.label(),
        &services,
        timeout_ms.unwrap_or(3_000),
        &label,
    )
    .await
    {
        Ok(password) if !password.is_empty() => derive_aes128_cbc_key(&password, 1003),
        Ok(_) => {
            warnings.push(format!(
                "macOS Keychain returned an empty {label} password."
            ));
            return None;
        }
        Err(error) => {
            warnings.push(error);
            return None;
        }
    };
    Some(Box::new(move |encrypted, host| {
        decrypt_chromium_aes128_cbc(encrypted, std::slice::from_ref(&key), host, true)
    }))
}

#[cfg(target_os = "linux")]
async fn platform_decrypter(
    target: ChromiumTarget,
    _database: &paths::ChromiumDatabase,
    timeout_ms: Option<u64>,
    warnings: &mut Vec<String>,
) -> Option<DecryptFn> {
    use crypto::{decrypt_chromium_aes128_cbc, derive_aes128_cbc_key, DecryptError};

    let (password, keyring_warnings) =
        linux_keyring::read_linux_safe_storage_password(target, None, timeout_ms).await;
    warnings.extend(keyring_warnings);
    let empty_key = derive_aes128_cbc_key("", 1);
    let v10_keys = [derive_aes128_cbc_key("peanuts", 1), empty_key.clone()];
    let v11_keys = [derive_aes128_cbc_key(&password, 1), empty_key];
    Some(Box::new(move |encrypted, host| {
        let keys = match encrypted.get(..3) {
            Some(b"v10") => &v10_keys,
            Some(b"v11") => &v11_keys,
            _ => return Err(DecryptError::InvalidCiphertext),
        };
        decrypt_chromium_aes128_cbc(encrypted, keys, host, false)
    }))
}

#[cfg(target_os = "windows")]
async fn platform_decrypter(
    target: ChromiumTarget,
    database: &paths::ChromiumDatabase,
    timeout_ms: Option<u64>,
    warnings: &mut Vec<String>,
) -> Option<DecryptFn> {
    let Some(user_data_dir) = &database.user_data_dir else {
        warnings.push(format!("{} user data directory not found.", target.label()));
        return None;
    };
    match windows_master_key::read_windows_chromium_master_key(
        user_data_dir,
        target.label(),
        timeout_ms,
    )
    .await
    {
        Ok(key) => Some(Box::new(move |encrypted, host| {
            crypto::decrypt_chromium_aes256_gcm(encrypted, &key, host)
        })),
        Err(error) => {
            warnings.push(error);
            None
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn platform_decrypter(
    _target: ChromiumTarget,
    _database: &paths::ChromiumDatabase,
    _timeout_ms: Option<u64>,
    _warnings: &mut Vec<String>,
) -> Option<DecryptFn> {
    None
}

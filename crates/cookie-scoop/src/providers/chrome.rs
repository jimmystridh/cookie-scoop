use std::collections::HashSet;

use crate::types::{ChromiumBrowser, GetCookiesResult, ProfileSelection};

use super::chromium::{get_cookies_from_chromium, ChromiumOptions, ChromiumTarget};

#[derive(Debug, Default)]
pub struct ChromeOptions {
    pub profile: Option<String>,
    pub timeout_ms: Option<u64>,
    pub include_expired: Option<bool>,
    pub debug: Option<bool>,
    pub profiles: Option<ProfileSelection>,
    pub chromium_browser: Option<ChromiumBrowser>,
}

pub async fn get_cookies_from_chrome(
    options: ChromeOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    get_cookies_from_chromium(
        ChromiumOptions {
            target: ChromiumTarget::Chrome(
                options.chromium_browser.unwrap_or(ChromiumBrowser::Chrome),
            ),
            explicit_target: options.chromium_browser.is_some(),
            profile: options.profile.as_deref(),
            profiles: options.profiles.as_ref(),
            timeout_ms: options.timeout_ms,
            include_expired: options.include_expired.unwrap_or(false),
        },
        origins,
        allowlist_names,
    )
    .await
}

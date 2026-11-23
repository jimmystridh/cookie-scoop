use std::collections::HashSet;

use crate::types::{GetCookiesResult, ProfileSelection};

use super::chromium::{get_cookies_from_chromium, ChromiumOptions, ChromiumTarget};

#[derive(Debug, Default)]
pub struct EdgeOptions {
    pub profile: Option<String>,
    pub timeout_ms: Option<u64>,
    pub include_expired: Option<bool>,
    pub debug: Option<bool>,
    pub profiles: Option<ProfileSelection>,
}

pub async fn get_cookies_from_edge(
    options: EdgeOptions,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    get_cookies_from_chromium(
        ChromiumOptions {
            target: ChromiumTarget::Edge,
            explicit_target: false,
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

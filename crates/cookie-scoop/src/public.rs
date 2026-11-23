use std::collections::HashSet;

use crate::providers::chrome::{get_cookies_from_chrome, ChromeOptions};
use crate::providers::edge::{get_cookies_from_edge, EdgeOptions};
use crate::providers::firefox::{get_cookies_from_firefox, FirefoxOptions};
use crate::providers::inline::{read_inline, InlineSource};
use crate::providers::safari::{get_cookies_from_safari, SafariOptions};
use crate::types::{
    cookie_key, dedupe_cookies, normalize_names, BrowserName, Cookie, CookieHeaderOptions,
    CookieHeaderSort, CookieMode, GetCookiesOptions, GetCookiesResult,
};
use crate::util::origins::normalize_origins;

const DEFAULT_BROWSERS: &[BrowserName] = &[
    BrowserName::Chrome,
    BrowserName::Safari,
    BrowserName::Firefox,
];

pub async fn get_cookies(options: GetCookiesOptions) -> GetCookiesResult {
    let mut warnings: Vec<String> = Vec::new();
    let origins = normalize_origins(&options.url, options.origins.as_deref());
    if origins.is_empty() {
        return GetCookiesResult {
            cookies: vec![],
            warnings,
        };
    }
    let names = normalize_names(&options.names);

    let browsers = if let Some(ref b) = options.browsers {
        if b.is_empty() {
            parse_browsers_env().unwrap_or_else(|| DEFAULT_BROWSERS.to_vec())
        } else {
            b.clone()
        }
    } else {
        parse_browsers_env().unwrap_or_else(|| DEFAULT_BROWSERS.to_vec())
    };

    let mode = options
        .mode
        .or_else(parse_mode_env)
        .unwrap_or(CookieMode::Merge);

    // Inline sources first
    let inline_sources = resolve_inline_sources(&options);
    let mut excluded_inline_isolation = false;
    for source in &inline_sources {
        let (inline_result, excluded_isolation) =
            read_inline(source, &origins, names.as_ref()).await;
        excluded_inline_isolation |= excluded_isolation;
        warnings.extend(inline_result.warnings);
        if !inline_result.cookies.is_empty() {
            return GetCookiesResult {
                cookies: inline_result.cookies,
                warnings,
            };
        }
    }
    if excluded_inline_isolation {
        return GetCookiesResult {
            cookies: vec![],
            warnings,
        };
    }

    let mut merged = Vec::new();
    let mut earlier_browser_keys = HashSet::new();

    for browser in &browsers {
        let result = match browser {
            BrowserName::Chrome => {
                let chrome_profile = options
                    .chrome_profile
                    .clone()
                    .or_else(|| options.profile.clone())
                    .or_else(|| read_env("SWEET_COOKIE_CHROME_PROFILE"));

                let chrome_options = ChromeOptions {
                    profile: chrome_profile,
                    profiles: options.chrome_profiles.clone(),
                    chromium_browser: options.chromium_browser,
                    timeout_ms: options.timeout_ms,
                    include_expired: options.include_expired,
                    debug: options.debug,
                };
                get_cookies_from_chrome(chrome_options, &origins, names.as_ref()).await
            }
            BrowserName::Edge => {
                let edge_profile = options
                    .edge_profile
                    .clone()
                    .or_else(|| options.profile.clone())
                    .or_else(|| read_env("SWEET_COOKIE_EDGE_PROFILE"))
                    .or_else(|| read_env("SWEET_COOKIE_CHROME_PROFILE"));

                let edge_options = EdgeOptions {
                    profile: edge_profile,
                    profiles: options.edge_profiles.clone(),
                    timeout_ms: options.timeout_ms,
                    include_expired: options.include_expired,
                    debug: options.debug,
                };
                get_cookies_from_edge(edge_options, &origins, names.as_ref()).await
            }
            BrowserName::Firefox => {
                let firefox_profile = options
                    .firefox_profile
                    .clone()
                    .or_else(|| read_env("SWEET_COOKIE_FIREFOX_PROFILE"));

                let firefox_options = FirefoxOptions {
                    profile: firefox_profile,
                    profiles: options.firefox_profiles.clone(),
                    include_expired: options.include_expired,
                };
                get_cookies_from_firefox(firefox_options, &origins, names.as_ref()).await
            }
            BrowserName::Safari => {
                let files = safari_file_selectors(&options);
                let mut safari = GetCookiesResult {
                    cookies: vec![],
                    warnings: vec![],
                };
                for file in files {
                    let safari_options = SafariOptions {
                        include_expired: options.include_expired,
                        file,
                    };
                    let result =
                        get_cookies_from_safari(safari_options, &origins, names.as_ref()).await;
                    safari.cookies.extend(result.cookies);
                    safari.warnings.extend(result.warnings);
                }
                safari.cookies = dedupe_cookies(safari.cookies);
                safari
            }
        };

        warnings.extend(result.warnings);

        if mode == CookieMode::First && !result.cookies.is_empty() {
            return GetCookiesResult {
                cookies: result.cookies,
                warnings,
            };
        }

        let mut browser_keys = HashSet::new();
        for cookie in result.cookies {
            let key = cookie_key(&cookie);
            if !earlier_browser_keys.contains(&key) {
                browser_keys.insert(key);
                merged.push(cookie);
            }
        }
        earlier_browser_keys.extend(browser_keys);
    }

    GetCookiesResult {
        cookies: merged,
        warnings,
    }
}

fn safari_file_selectors(options: &GetCookiesOptions) -> Vec<Option<String>> {
    if let Some(files) = &options.safari_cookies_files {
        let files: Vec<_> = files
            .iter()
            .map(|file| file.trim())
            .filter(|file| !file.is_empty())
            .map(|file| Some(file.to_owned()))
            .collect();
        if !files.is_empty() {
            return files;
        }
    }
    vec![options.safari_cookies_file.clone()]
}

pub fn to_cookie_header(cookies: &[Cookie], options: &CookieHeaderOptions) -> String {
    let mut items: Vec<(&str, &str)> = cookies
        .iter()
        .filter(|c| !c.name.is_empty())
        .map(|c| (c.name.as_str(), c.value.as_str()))
        .collect();

    if options.sort == CookieHeaderSort::Name {
        items.sort_by(|a, b| a.0.cmp(b.0));
    }

    if !options.dedupe_by_name {
        return items
            .iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
    }

    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for &(name, value) in &items {
        if seen.insert(name) {
            deduped.push((name, value));
        }
    }

    deduped
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn resolve_inline_sources(options: &GetCookiesOptions) -> Vec<InlineSource> {
    let mut sources = Vec::new();
    if let Some(ref json) = options.inline_cookies_json {
        sources.push(InlineSource {
            source: "inline-json".to_string(),
            payload: json.clone(),
        });
    }
    if let Some(ref b64) = options.inline_cookies_base64 {
        sources.push(InlineSource {
            source: "inline-base64".to_string(),
            payload: b64.clone(),
        });
    }
    if let Some(ref file) = options.inline_cookies_file {
        sources.push(InlineSource {
            source: "inline-file".to_string(),
            payload: file.clone(),
        });
    }
    sources
}

fn parse_browsers_env() -> Option<Vec<BrowserName>> {
    let raw = read_env("SWEET_COOKIE_BROWSERS").or_else(|| read_env("SWEET_COOKIE_SOURCES"))?;
    let tokens: Vec<String> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for token in &tokens {
        if let Some(browser) = BrowserName::from_str_loose(token) {
            if seen.insert(browser) {
                out.push(browser);
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_mode_env() -> Option<CookieMode> {
    let raw = read_env("SWEET_COOKIE_MODE")?;
    match raw.trim().to_lowercase().as_str() {
        "merge" => Some(CookieMode::Merge),
        "first" => Some(CookieMode::First),
        _ => None,
    }
}

fn read_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

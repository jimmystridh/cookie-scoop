use std::collections::{HashMap, HashSet};

use crate::providers::chromium::{
    get_cookies_from_chromium, ChromiumBrowser, ChromiumOptions, CHROME, EDGE,
};
use crate::providers::firefox::{get_cookies_from_firefox, FirefoxOptions};
use crate::providers::inline::{get_cookies_from_inline, InlineSource};
use crate::providers::safari::{get_cookies_from_safari, SafariOptions};
use crate::types::{
    normalize_names, BrowserName, Cookie, CookieHeaderOptions, CookieHeaderSort, CookieMode,
    GetCookiesOptions, GetCookiesResult,
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
    for source in &inline_sources {
        let inline_result = get_cookies_from_inline(source, &origins, names.as_ref()).await;
        warnings.extend(inline_result.warnings);
        if !inline_result.cookies.is_empty() {
            return GetCookiesResult {
                cookies: inline_result.cookies,
                warnings,
            };
        }
    }

    let mut merged: HashMap<String, Cookie> = HashMap::new();

    for browser in &browsers {
        let result = match browser {
            BrowserName::Chrome | BrowserName::Edge => {
                let (browser, envs): (ChromiumBrowser, &[&str]) = match browser {
                    BrowserName::Chrome => (CHROME, &["SWEET_COOKIE_CHROME_PROFILE"]),
                    BrowserName::Edge => (
                        EDGE,
                        &["SWEET_COOKIE_EDGE_PROFILE", "SWEET_COOKIE_CHROME_PROFILE"],
                    ),
                    _ => unreachable!(),
                };

                get_cookies_from_chromium(
                    browser,
                    ChromiumOptions {
                        profile: resolve_profile(&options, browser.name, true, envs),
                        timeout_ms: options.timeout_ms,
                        include_expired: options.include_expired,
                    },
                    &origins,
                    names.as_ref(),
                )
                .await
            }
            BrowserName::Firefox => {
                get_cookies_from_firefox(
                    FirefoxOptions {
                        profile: resolve_profile(
                            &options,
                            BrowserName::Firefox,
                            false,
                            &["SWEET_COOKIE_FIREFOX_PROFILE"],
                        ),
                        include_expired: options.include_expired,
                    },
                    &origins,
                    names.as_ref(),
                )
                .await
            }
            BrowserName::Safari => {
                let safari_options = SafariOptions {
                    include_expired: options.include_expired,
                    file: options.safari_cookies_file.clone(),
                };
                get_cookies_from_safari(safari_options, &origins, names.as_ref()).await
            }
        };

        warnings.extend(result.warnings);

        if mode == CookieMode::First && !result.cookies.is_empty() {
            return GetCookiesResult {
                cookies: result.cookies,
                warnings,
            };
        }

        for cookie in result.cookies {
            let domain = cookie.domain.as_deref().unwrap_or("");
            let path = cookie.path.as_deref().unwrap_or("");
            let key = format!("{}|{}|{}", cookie.name, domain, path);
            merged.entry(key).or_insert(cookie);
        }
    }

    GetCookiesResult {
        cookies: merged.into_values().collect(),
        warnings,
    }
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

fn resolve_profile(
    options: &GetCookiesOptions,
    browser: BrowserName,
    use_generic_profile: bool,
    envs: &[&str],
) -> Option<String> {
    options
        .profiles
        .get(&browser)
        .cloned()
        .or_else(|| {
            use_generic_profile
                .then(|| options.profile.clone())
                .flatten()
        })
        .or_else(|| envs.iter().find_map(|key| read_env(key)))
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

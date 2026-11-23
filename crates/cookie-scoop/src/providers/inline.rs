use std::collections::HashSet;

use crate::types::{Cookie, GetCookiesResult};
use crate::util::base64::try_decode_base64_json;
use crate::util::host_match::host_matches_cookie_scope;
use crate::util::origins::extract_host;
use serde_json::Value;
use url::Url;

pub struct InlineSource {
    pub source: String,
    pub payload: String,
}

pub async fn get_cookies_from_inline(
    inline: &InlineSource,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> GetCookiesResult {
    read_inline(inline, origins, allowlist_names).await.0
}

pub(crate) async fn read_inline(
    inline: &InlineSource,
    origins: &[String],
    allowlist_names: Option<&HashSet<String>>,
) -> (GetCookiesResult, bool) {
    let raw_payload = if inline.source.ends_with("file")
        || inline.payload.ends_with(".json")
        || inline.payload.ends_with(".base64")
    {
        match tokio::fs::read_to_string(&inline.payload).await {
            Ok(content) => content,
            Err(_) => inline.payload.clone(),
        }
    } else {
        inline.payload.clone()
    };

    let decoded = try_decode_base64_json(&raw_payload).unwrap_or_else(|| raw_payload.clone());
    let parsed = match try_parse_cookie_payload(&decoded) {
        Some(cookies) => cookies,
        None => {
            return (
                GetCookiesResult {
                    cookies: vec![],
                    warnings: vec![],
                },
                false,
            );
        }
    };

    let host_allow: HashSet<String> = origins
        .iter()
        .filter_map(|origin| extract_host(origin))
        .collect();
    if host_allow.is_empty() {
        return (
            GetCookiesResult {
                cookies: vec![],
                warnings: vec![],
            },
            false,
        );
    }

    let mut cookies = Vec::new();
    let mut isolated = 0;
    for record in parsed {
        let Some(name) = record
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if let Some(names) = allowlist_names {
            if !names.is_empty() && !names.contains(name) {
                continue;
            }
        }
        if has_unsupported_isolation(&record) {
            isolated += 1;
            continue;
        }
        let Ok(cookie) = serde_json::from_value::<Cookie>(record) else {
            continue;
        };
        let domain = cookie.domain.as_deref().map(|d| d.to_string()).or_else(|| {
            cookie
                .url
                .as_deref()
                .and_then(|u| Url::parse(u).ok())
                .and_then(|u| u.host_str().map(|h| h.to_string()))
        });
        if let Some(ref domain) = domain {
            if !host_allow
                .iter()
                .any(|host| host_matches_cookie_scope(host, domain, cookie.host_only == Some(true)))
            {
                continue;
            }
        }
        cookies.push(cookie);
    }

    let warnings = if isolated == 0 {
        vec![]
    } else {
        vec![format!("{isolated} inline cookie(s) with partition or container provenance were excluded because replay cannot preserve their isolation context.")]
    };
    (GetCookiesResult { cookies, warnings }, isolated != 0)
}

fn try_parse_cookie_payload(input: &str) -> Option<Vec<Value>> {
    match serde_json::from_str(input).ok()? {
        Value::Array(records) => Some(records),
        Value::Object(mut object) => match object.remove("cookies")? {
            Value::Array(records) => Some(records),
            _ => None,
        },
        _ => None,
    }
}

fn has_unsupported_isolation(record: &Value) -> bool {
    record
        .get("partitionKey")
        .is_some_and(|value| !value.is_null())
        || record["partitionKeyOpaque"] == true
        || ["top_frame_site_key", "originAttributes"]
            .iter()
            .any(|field| {
                record[*field]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty())
            })
        || [Value::from(true), Value::from(1), Value::from("1")]
            .contains(&record["isPartitionedAttributeSet"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_json_array() {
        let source = InlineSource {
            source: "inline-json".to_string(),
            payload: r#"[{"name":"foo","value":"bar","domain":"example.com"}]"#.to_string(),
        };
        let origins = vec!["https://example.com/".to_string()];
        let result = get_cookies_from_inline(&source, &origins, None).await;
        assert_eq!(result.cookies.len(), 1);
        assert_eq!(result.cookies[0].name, "foo");
        assert_eq!(result.cookies[0].value, "bar");
    }

    #[tokio::test]
    async fn parses_wrapped_object() {
        let source = InlineSource {
            source: "inline-json".to_string(),
            payload: r#"{"cookies":[{"name":"foo","value":"bar","domain":"example.com"}]}"#
                .to_string(),
        };
        let origins = vec!["https://example.com/".to_string()];
        let result = get_cookies_from_inline(&source, &origins, None).await;
        assert_eq!(result.cookies.len(), 1);
    }

    #[tokio::test]
    async fn filters_by_domain() {
        let source = InlineSource {
            source: "inline-json".to_string(),
            payload: r#"[{"name":"foo","value":"bar","domain":"other.com"}]"#.to_string(),
        };
        let origins = vec!["https://example.com/".to_string()];
        let result = get_cookies_from_inline(&source, &origins, None).await;
        assert_eq!(result.cookies.len(), 0);
    }

    #[tokio::test]
    async fn filters_by_name() {
        let source = InlineSource {
            source: "inline-json".to_string(),
            payload: r#"[{"name":"foo","value":"bar","domain":"example.com"},{"name":"baz","value":"qux","domain":"example.com"}]"#.to_string(),
        };
        let origins = vec!["https://example.com/".to_string()];
        let mut names = HashSet::new();
        names.insert("foo".to_string());
        let result = get_cookies_from_inline(&source, &origins, Some(&names)).await;
        assert_eq!(result.cookies.len(), 1);
        assert_eq!(result.cookies[0].name, "foo");
    }

    #[tokio::test]
    async fn base64_encoded_json() {
        use base64::Engine;
        let json = r#"[{"name":"foo","value":"bar","domain":"example.com"}]"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(json);
        let source = InlineSource {
            source: "inline-base64".to_string(),
            payload: encoded,
        };
        let origins = vec!["https://example.com/".to_string()];
        let result = get_cookies_from_inline(&source, &origins, None).await;
        assert_eq!(result.cookies.len(), 1);
    }
}

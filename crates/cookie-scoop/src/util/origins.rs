use url::{Origin, Url};

pub fn normalize_origins(url_str: &str, extra_origins: Option<&[String]>) -> Vec<String> {
    let mut origins = Vec::new();

    if let Some(origin) = parse_origin(url_str) {
        origins.push(origin);
    }

    if let Some(extras) = extra_origins {
        for raw in extras {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(origin) = parse_origin(trimmed) {
                origins.push(origin);
            }
        }
    }

    // Dedupe while preserving order
    let mut seen = std::collections::HashSet::new();
    origins.retain(|o| seen.insert(o.clone()));
    origins
}

fn parse_origin(input: &str) -> Option<String> {
    let origin = Url::parse(input).ok()?.origin();
    matches!(origin, Origin::Tuple(..)).then(|| format!("{}/", origin.ascii_serialization()))
}

pub fn extract_host(origin: &str) -> Option<String> {
    Url::parse(origin)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_origin() {
        let origins = normalize_origins("https://example.com/path", None);
        assert_eq!(origins, vec!["https://example.com/"]);
    }

    #[test]
    fn with_extras() {
        let extras = vec!["https://other.com".to_string()];
        let origins = normalize_origins("https://example.com", Some(&extras));
        assert_eq!(origins.len(), 2);
        assert!(origins.contains(&"https://example.com/".to_string()));
        assert!(origins.contains(&"https://other.com/".to_string()));
    }

    #[test]
    fn dedupes() {
        let extras = vec!["https://example.com/".to_string()];
        let origins = normalize_origins("https://example.com", Some(&extras));
        assert_eq!(origins.len(), 1);
    }

    #[test]
    fn ignores_malformed() {
        let extras = vec!["not-a-url".to_string()];
        let origins = normalize_origins("https://example.com", Some(&extras));
        assert_eq!(origins.len(), 1);
    }
}

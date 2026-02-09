use cookie_scoop::{CookieHeaderOptions, CookieHeaderSort, GetCookiesOptions};

const URL: &str = "https://jira.visma.com/rest/tempo-core/1/user/schedule?user=jimmy.stridh&from=2026-03-01&to=2026-03-31&_=1770632294227";

#[tokio::main]
async fn main() {
    let base_url = "https://jira.visma.com";

    eprintln!("Extracting cookies for {base_url} ...");

    let result = cookie_scoop::get_cookies(GetCookiesOptions::new(base_url).debug(true)).await;

    for warning in &result.warnings {
        eprintln!("  warning: {warning}");
    }

    let count = result.cookies.len();
    eprintln!("  found {count} cookies");

    for c in &result.cookies {
        let src = c
            .source
            .as_ref()
            .map(|s| format!("{:?}", s.browser))
            .unwrap_or_default();
        eprintln!(
            "    {} = {}... [{}]",
            c.name,
            &c.value[..c.value.len().min(20)],
            src
        );
    }

    let header = cookie_scoop::to_cookie_header(
        &result.cookies,
        &CookieHeaderOptions {
            dedupe_by_name: true,
            sort: CookieHeaderSort::Name,
        },
    );

    if header.is_empty() {
        eprintln!("No cookies found — the request will likely fail with 401.");
    }

    eprintln!("\nRequesting: {URL}");

    let client = reqwest::Client::new();
    let response = client
        .get(URL)
        .header("Cookie", &header)
        .header("Accept", "application/json")
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            eprintln!("HTTP {status}");
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("(read error: {e})"));
            println!("{body}");
        }
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    }
}

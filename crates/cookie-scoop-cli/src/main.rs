use clap::Parser;
use cookie_scoop::{
    BrowserName, CookieHeaderOptions, CookieHeaderSort, CookieMode, GetCookiesOptions,
};

#[derive(Parser)]
#[command(
    name = "cookie-scoop",
    about = "Extract browser cookies from Chrome, Edge, Firefox, and Safari"
)]
struct Cli {
    /// URL to extract cookies for (must include protocol)
    #[arg(long)]
    url: String,

    /// Browser backends to try (comma-separated: chrome,edge,firefox,safari)
    #[arg(long, value_delimiter = ',')]
    browsers: Option<Vec<String>>,

    /// Cookie retrieval mode
    #[arg(long, default_value = "merge")]
    mode: String,

    /// Output as Cookie header string instead of JSON
    #[arg(long)]
    header: bool,

    /// Chrome profile name or path
    #[arg(long)]
    chrome_profile: Option<String>,

    /// Edge profile name or path
    #[arg(long)]
    edge_profile: Option<String>,

    /// Firefox profile name or path
    #[arg(long)]
    firefox_profile: Option<String>,

    /// Safari cookies file path
    #[arg(long)]
    safari_cookies_file: Option<String>,

    /// Allowlist of cookie names (comma-separated)
    #[arg(long, value_delimiter = ',')]
    names: Option<Vec<String>>,

    /// Additional origins (comma-separated)
    #[arg(long, value_delimiter = ',')]
    origins: Option<Vec<String>>,

    /// Include expired cookies
    #[arg(long)]
    include_expired: bool,

    /// Timeout for OS helper calls in milliseconds
    #[arg(long)]
    timeout_ms: Option<u64>,

    /// Inline cookies JSON string
    #[arg(long)]
    inline_json: Option<String>,

    /// Inline cookies base64 string
    #[arg(long)]
    inline_base64: Option<String>,

    /// Inline cookies file path
    #[arg(long)]
    inline_file: Option<String>,

    /// Dedupe cookies by name in header output
    #[arg(long)]
    dedupe_by_name: bool,

    /// Sort cookies by name in header output
    #[arg(long, default_value = "true")]
    sort: bool,

    /// Enable debug output
    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let browsers: Option<Vec<BrowserName>> = cli.browsers.map(|b| {
        b.iter()
            .filter_map(|s| BrowserName::from_str_loose(s))
            .collect()
    });

    let mode = match cli.mode.to_lowercase().as_str() {
        "first" => Some(CookieMode::First),
        _ => Some(CookieMode::Merge),
    };

    let mut options = GetCookiesOptions::new(&cli.url);
    if let Some(b) = browsers {
        options = options.browsers(b);
    }
    if let Some(m) = mode {
        options = options.mode(m);
    }
    if let Some(ref p) = cli.chrome_profile {
        options = options.chrome_profile(p);
    }
    if let Some(ref p) = cli.edge_profile {
        options = options.edge_profile(p);
    }
    if let Some(ref p) = cli.firefox_profile {
        options = options.firefox_profile(p);
    }
    if let Some(ref f) = cli.safari_cookies_file {
        options = options.safari_cookies_file(f);
    }
    if let Some(ref n) = cli.names {
        options = options.names(n.clone());
    }
    if let Some(ref o) = cli.origins {
        options = options.origins(o.clone());
    }
    if cli.include_expired {
        options = options.include_expired(true);
    }
    if let Some(t) = cli.timeout_ms {
        options = options.timeout_ms(t);
    }
    if let Some(ref j) = cli.inline_json {
        options = options.inline_cookies_json(j);
    }
    if let Some(ref b) = cli.inline_base64 {
        options = options.inline_cookies_base64(b);
    }
    if let Some(ref f) = cli.inline_file {
        options = options.inline_cookies_file(f);
    }
    if cli.debug {
        options = options.debug(true);
    }

    let result = cookie_scoop::get_cookies(options).await;

    if cli.debug {
        for warning in &result.warnings {
            eprintln!("warning: {warning}");
        }
    }

    if cli.header {
        let header_options = CookieHeaderOptions {
            dedupe_by_name: cli.dedupe_by_name,
            sort: if cli.sort {
                CookieHeaderSort::Name
            } else {
                CookieHeaderSort::None
            },
        };
        println!(
            "{}",
            cookie_scoop::to_cookie_header(&result.cookies, &header_options)
        );
    } else {
        match serde_json::to_string_pretty(&result) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Failed to serialize result: {e}");
                std::process::exit(1);
            }
        }
    }
}

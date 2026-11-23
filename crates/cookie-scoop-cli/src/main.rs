use clap::{Parser, ValueEnum};
use cookie_scoop::{
    BrowserName, ChromiumBrowser, CookieHeaderOptions, CookieHeaderSort, CookieMode,
    GetCookiesOptions, ProfileSelection,
};

#[derive(Clone, ValueEnum)]
enum ChromiumTarget {
    Chrome,
    Chromium,
    Brave,
    Arc,
    Dia,
}

impl From<ChromiumTarget> for ChromiumBrowser {
    fn from(target: ChromiumTarget) -> Self {
        match target {
            ChromiumTarget::Chrome => Self::Chrome,
            ChromiumTarget::Chromium => Self::Chromium,
            ChromiumTarget::Brave => Self::Brave,
            ChromiumTarget::Arc => Self::Arc,
            ChromiumTarget::Dia => Self::Dia,
        }
    }
}

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

    /// Chrome profile name or path. Repeat to read multiple profiles
    #[arg(long)]
    chrome_profile: Vec<String>,

    /// Edge profile name or path. Repeat to read multiple profiles
    #[arg(long)]
    edge_profile: Vec<String>,

    /// Firefox profile name or path. Repeat to read multiple profiles
    #[arg(long)]
    firefox_profile: Vec<String>,

    /// Read all discovered profiles for selected Chrome, Edge, and Firefox backends
    #[arg(long, conflicts_with_all = ["chrome_profile", "edge_profile", "firefox_profile"])]
    all_profiles: bool,

    /// Browser targeted by the Chrome backend (Arc and Dia are macOS-only)
    #[arg(long, value_enum)]
    chromium_browser: Option<ChromiumTarget>,

    /// Safari cookies file path. Repeat to read multiple files
    #[arg(long)]
    safari_cookies_file: Vec<String>,

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
    if let Some(profiles) = cli_profiles(cli.all_profiles, cli.chrome_profile) {
        options = options.chrome_profiles(profiles);
    }
    if let Some(profiles) = cli_profiles(cli.all_profiles, cli.edge_profile) {
        options = options.edge_profiles(profiles);
    }
    if let Some(profiles) = cli_profiles(cli.all_profiles, cli.firefox_profile) {
        options = options.firefox_profiles(profiles);
    }
    if let Some(browser) = cli.chromium_browser {
        options = options.chromium_browser(browser.into());
    }
    if !cli.safari_cookies_file.is_empty() {
        options = options.safari_cookies_files(cli.safari_cookies_file);
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

fn cli_profiles(all: bool, names: Vec<String>) -> Option<ProfileSelection> {
    if all {
        Some(ProfileSelection::All)
    } else if names.is_empty() {
        None
    } else {
        Some(ProfileSelection::Selected(names))
    }
}

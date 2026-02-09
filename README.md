# cookie-scoop

Cross-platform browser cookie extraction for Rust. Reads cookies from Chrome, Edge, Firefox, and Safari with full decryption support.

This is a Rust reimplementation of the concepts from [@steipete/sweet-cookie](https://github.com/steipete/sweet-cookie) (TypeScript) and [SweetCookieKit](https://github.com/steipete/SweetCookieKit) (Swift), providing the same inline-first approach and best-effort local reads as a native Rust library and CLI.

## Features

- **Chrome & Edge** (macOS / Windows / Linux) — reads Chromium SQLite cookie databases with AES-128-CBC (macOS/Linux) and AES-256-GCM (Windows) decryption
- **Firefox** (macOS / Windows / Linux) — reads `cookies.sqlite` with profile discovery
- **Safari** (macOS only) — parses `Cookies.binarycookies`
- **Inline cookies** — accepts JSON, base64, or file-based cookie payloads for environments where browser DB access isn't possible
- **Zero native dependencies** — SQLite is bundled via `rusqlite`, OS integration uses platform CLI tools (`security`, `secret-tool`, `kwallet-query`, PowerShell)
- **Async** — built on tokio with `spawn_blocking` for SQLite and `tokio::process` for OS commands
- **Never panics** — `get_cookies()` returns `GetCookiesResult` (not `Result`), accumulating issues in a `warnings` vec. Partial results are always returned.

## Install

### Library

```toml
[dependencies]
cookie-scoop = "0.1"
tokio = { version = "1", features = ["full"] }
```

### CLI

```bash
cargo install cookie-scoop-cli
```

## Library usage

```rust
use cookie_scoop::{
    get_cookies, to_cookie_header,
    BrowserName, GetCookiesOptions, CookieHeaderOptions,
};

#[tokio::main]
async fn main() {
    let result = get_cookies(
        GetCookiesOptions::new("https://example.com")
            .browsers(vec![BrowserName::Chrome, BrowserName::Firefox])
            .names(vec!["session".into(), "csrf".into()])
    ).await;

    for w in &result.warnings {
        eprintln!("warning: {w}");
    }

    let header = to_cookie_header(&result.cookies, &CookieHeaderOptions::default());
    println!("Cookie: {header}");
}
```

### Multiple origins

Useful for sites with SSO/OAuth across subdomains:

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://app.example.com")
        .origins(vec![
            "https://accounts.example.com".into(),
            "https://login.example.com".into(),
        ])
        .names(vec!["session".into(), "xsrf".into()])
).await;
```

### Merge vs first mode

`merge` (default) combines cookies from all requested browsers. `first` stops after the first browser that returns any cookies.

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://example.com")
        .browsers(vec![BrowserName::Chrome, BrowserName::Firefox])
        .mode(CookieMode::First)
).await;
```

### Specific profile

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://example.com")
        .browsers(vec![BrowserName::Chrome])
        .chrome_profile("Profile 1") // name or full path to Cookies DB
).await;
```

### Inline cookies

Works on any OS/runtime — no browser DB access required:

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://example.com")
        .inline_cookies_json(r#"[{"name":"session","value":"abc123","domain":"example.com"}]"#)
).await;
```

Also supports `inline_cookies_base64()` and `inline_cookies_file()`.

## CLI usage

```bash
# JSON output (all browsers, merge mode)
cookie-scoop --url https://example.com

# Specific browsers
cookie-scoop --url https://example.com --browsers chrome,firefox

# Cookie header string
cookie-scoop --url https://example.com --header --browsers chrome

# Specific profile
cookie-scoop --url https://example.com --browsers chrome --chrome-profile "Profile 1"

# Filter by cookie name
cookie-scoop --url https://example.com --names session,csrf

# Include expired cookies
cookie-scoop --url https://example.com --include-expired

# First-match mode
cookie-scoop --url https://example.com --mode first
```

## Supported browsers and platforms

| Browser | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Chrome  |   Y   |   Y   |    Y    |
| Edge    |   Y   |   Y   |    Y    |
| Firefox |   Y   |   Y   |    Y    |
| Safari  |   Y   |   -   |    -    |

Chrome/Edge require modern Chromium cookie DB schemas (roughly Chrome >= 100).

Safari requires Full Disk Access on macOS.

## How decryption works

| Platform | Method |
|----------|--------|
| macOS    | Reads the safe storage password from Keychain via `security find-generic-password`, derives a key with PBKDF2-SHA1 (1003 iterations), decrypts with AES-128-CBC |
| Linux    | Reads the safe storage password from GNOME Keyring (`secret-tool`) or KDE Wallet (`kwallet-query`), derives a key with PBKDF2-SHA1 (1 iteration), decrypts with AES-128-CBC. Falls back to the hardcoded `peanuts` password when using `basic` backend. |
| Windows  | Reads the encrypted master key from Chrome's `Local State` JSON, decrypts it with DPAPI via PowerShell, then decrypts cookies with AES-256-GCM |

### Implementation notes

- **Cookie DB copying** — the Chromium/Firefox SQLite databases are copied to a temp directory (along with `-wal` and `-shm` sidecars) before reading, avoiding locks from running browsers. Temp files are cleaned up automatically via `tempfile::TempDir` RAII.
- **Chromium meta version** — the `meta` table's `version` column is stored as TEXT in modern Chrome. cookie-scoop reads it as a string and parses to integer, correctly handling the hash-prefix stripping introduced in version 24+.
- **GNOME keyring v2 schema** — modern Chrome stores the safe storage password under the `application=chrome` attribute rather than the legacy `service`/`account` attributes. cookie-scoop tries the v2 schema first, falling back to v1.
- **Cookie deduplication** — cookies are deduped by `name|domain|path` key, keeping the first occurrence. This prevents duplicates when merge mode combines results from multiple browsers.

## Environment variables

| Variable | Description |
|----------|-------------|
| `SWEET_COOKIE_BROWSERS` | Comma-separated browser list: `chrome,edge,firefox,safari` |
| `SWEET_COOKIE_MODE` | `merge` (default) or `first` |
| `SWEET_COOKIE_CHROME_PROFILE` | Chrome profile name or path |
| `SWEET_COOKIE_EDGE_PROFILE` | Edge profile name or path |
| `SWEET_COOKIE_FIREFOX_PROFILE` | Firefox profile name or path |
| `SWEET_COOKIE_LINUX_KEYRING` | Linux keyring backend: `gnome`, `kwallet`, or `basic` |
| `SWEET_COOKIE_CHROME_SAFE_STORAGE_PASSWORD` | Override Chrome safe storage password (Linux) |
| `SWEET_COOKIE_EDGE_SAFE_STORAGE_PASSWORD` | Override Edge safe storage password (Linux) |

Environment variable names are kept compatible with the original [sweet-cookie](https://github.com/steipete/sweet-cookie) TypeScript library.

## Acknowledgments

This project is a Rust reimplementation of the cookie extraction approach pioneered by:

- **[sweet-cookie](https://github.com/steipete/sweet-cookie)** by [@steipete](https://github.com/steipete) — the original TypeScript library with inline-first cookie extraction and zero native Node dependencies
- **[SweetCookieKit](https://github.com/steipete/SweetCookieKit)** by [@steipete](https://github.com/steipete) — a Swift 6 package for native macOS cookie extraction supporting Safari, Chromium, and Firefox

## License

MIT

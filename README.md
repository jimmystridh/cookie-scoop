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
use cookie_scoop::{get_cookies, to_cookie_header, GetCookiesOptions, CookieHeaderOptions};

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

### Specific profile

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://example.com")
        .browsers(vec![BrowserName::Chrome])
        .chrome_profile("Profile 1")
).await;
```

### Inline cookies

```rust
let result = get_cookies(
    GetCookiesOptions::new("https://example.com")
        .inline_cookies_json(r#"[{"name":"session","value":"abc123","domain":"example.com"}]"#)
).await;
```

## CLI usage

```bash
# JSON output
cookie-scoop --url https://example.com --browsers chrome,firefox

# Cookie header string
cookie-scoop --url https://example.com --header --browsers chrome

# Specific profile
cookie-scoop --url https://example.com --browsers chrome --chrome-profile "Profile 1"

# Filter by cookie name
cookie-scoop --url https://example.com --names session,csrf
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
| macOS    | Reads the safe storage password from Keychain via `security find-generic-password`, derives a key with PBKDF2-SHA1, decrypts with AES-128-CBC |
| Linux    | Reads the safe storage password from GNOME Keyring (`secret-tool`) or KDE Wallet (`kwallet-query`), derives a key with PBKDF2-SHA1, decrypts with AES-128-CBC |
| Windows  | Reads the encrypted master key from Chrome's `Local State` JSON, decrypts it with DPAPI via PowerShell, then decrypts cookies with AES-256-GCM |

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

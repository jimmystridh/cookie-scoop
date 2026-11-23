use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use cookie_scoop::providers::chromium::crypto::decrypt_chromium_aes256_gcm;
use cookie_scoop::providers::chromium::shared::get_cookies_from_chrome_sqlite_db;
use cookie_scoop::{get_cookies, BrowserName, GetCookiesOptions, ProfileSelection};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

fn firefox_options(url: &str, db: &Path) -> GetCookiesOptions {
    GetCookiesOptions::new(url)
        .browsers(vec![BrowserName::Firefox])
        .firefox_profile(db.to_string_lossy())
}

fn firefox_database(path: &Path, version: i64) -> Connection {
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "user_version", version).unwrap();
    db.execute_batch(
        "CREATE TABLE moz_cookies (
            name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
            isSecure INTEGER, isHttpOnly INTEGER, sameSite INTEGER,
            originAttributes TEXT, isPartitionedAttributeSet INTEGER
        )",
    )
    .unwrap();
    db
}

fn insert_firefox_cookie(
    db: &Connection,
    name: &str,
    host: &str,
    expiry: i64,
    attributes: &str,
    partitioned: bool,
) {
    db.execute(
        "INSERT INTO moz_cookies VALUES (?1, 'fixture', ?2, '/', ?3, 0, 0, 0, ?4, ?5)",
        params![name, host, expiry, attributes, partitioned],
    )
    .unwrap();
}

fn large_origins() -> Vec<String> {
    (0..1_200)
        .map(|index| format!("https://origin{index}.test/"))
        .collect()
}

#[tokio::test]
async fn firefox_filters_and_normalizes_modern_expiry_with_many_origins() {
    let scratch = tempfile::tempdir().unwrap();
    let db_path = scratch.path().join("renamed.db");
    let db = firefox_database(&db_path, 16);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let future = now + 3_600;
    let past = now - 3_600;
    insert_firefox_cookie(&db, "future", ".example.test", future * 1_000, "", false);
    insert_firefox_cookie(&db, "expired", ".example.test", past * 1_000, "", false);
    insert_firefox_cookie(&db, "host", "example.test", 0, "", false);
    insert_firefox_cookie(
        &db,
        "container",
        ".example.test",
        0,
        "^userContextId=1",
        false,
    );
    insert_firefox_cookie(&db, "partitioned", ".example.test", 0, "", true);
    insert_firefox_cookie(
        &db,
        "out_of_range",
        ".example.test",
        253_402_300_800_000,
        "",
        false,
    );
    drop(db);

    let result = get_cookies(
        firefox_options("https://child.example.test", &db_path).origins(large_origins()),
    )
    .await;
    assert_eq!(result.cookies.len(), 2, "{:?}", result.warnings);
    let read = result
        .cookies
        .iter()
        .find(|cookie| cookie.name == "future")
        .unwrap();
    assert_eq!(read.expires, Some(future));
    assert_eq!(read.host_only, Some(false));
    assert!(result
        .cookies
        .iter()
        .any(|cookie| cookie.name == "out_of_range" && cookie.expires.is_none()));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.starts_with("2 Firefox")));

    let with_expired =
        get_cookies(firefox_options("https://child.example.test", &db_path).include_expired(true))
            .await;
    assert!(with_expired
        .cookies
        .iter()
        .any(|cookie| cookie.name == "expired" && cookie.expires == Some(past)));
}

#[tokio::test]
async fn firefox_keeps_distinct_profiles_and_preserves_legacy_expiry() {
    let scratch = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = ["cookies.sqlite", "second"]
        .iter()
        .map(|profile| {
            let directory = scratch.path().join(profile);
            std::fs::create_dir(&directory).unwrap();
            let db_path = directory.join("cookies.sqlite");
            let db = firefox_database(&db_path, 15);
            insert_firefox_cookie(&db, "same", "example.test", 2_500_000_000, "", false);
            directory
        })
        .collect();

    let selectors = vec![
        paths[0].to_string_lossy().into_owned(),
        paths[0]
            .join("cookies.sqlite")
            .to_string_lossy()
            .into_owned(),
        paths[1].to_string_lossy().into_owned(),
    ];
    let result = get_cookies(
        GetCookiesOptions::new("https://example.test")
            .browsers(vec![BrowserName::Firefox])
            .firefox_profiles(ProfileSelection::Selected(selectors)),
    )
    .await;
    let profiles: Vec<_> = result
        .cookies
        .iter()
        .map(|cookie| {
            assert_eq!(cookie.expires, Some(2_500_000_000));
            cookie.source.as_ref().unwrap().profile.as_deref().unwrap()
        })
        .collect();
    assert_eq!(profiles, ["cookies.sqlite", "second"]);
}

#[tokio::test]
async fn opaque_urls_and_isolated_inline_payloads_fail_closed() {
    let scratch = tempfile::tempdir().unwrap();
    let db_path = scratch.path().join("cookies.sqlite");
    let db = firefox_database(&db_path, 15);
    insert_firefox_cookie(&db, "local", "example.test", 0, "", false);
    drop(db);

    let opaque = get_cookies(
        firefox_options("file:///fixture", &db_path).inline_cookies_json(
            r#"[{"name":"inline","value":"fixture","domain":"example.test"}]"#,
        ),
    )
    .await;
    assert!(opaque.cookies.is_empty());

    let scoped = get_cookies(
        firefox_options("https://child.example.test", &db_path).inline_cookies_json(
            r#"[{"name":"inline","value":"fixture","domain":"example.test","hostOnly":true}]"#,
        ),
    )
    .await;
    assert!(scoped.cookies.is_empty());

    let options = || {
        firefox_options("https://example.test", &db_path).inline_cookies_json(
        r#"[{"name":"inline","value":"fixture","domain":"example.test","partitionKeyOpaque":true}]"#
    )
    };
    let isolated = get_cookies(options()).await;
    assert!(isolated.cookies.is_empty());
    assert_eq!(isolated.warnings.len(), 1);
    assert!(isolated.warnings[0].contains("partition or container"));

    let inline_file = scratch.path().join("valid.json");
    std::fs::write(
        &inline_file,
        r#"[{"name":"fallback","value":"fixture","domain":"example.test","hostOnly":true}]"#,
    )
    .unwrap();
    let fallback = get_cookies(options().inline_cookies_file(inline_file.to_string_lossy())).await;
    assert_eq!(fallback.cookies[0].name, "fallback");
    assert_eq!(fallback.cookies[0].host_only, Some(true));
}

#[tokio::test]
async fn chromium_verifies_host_binding_and_scope_across_many_origins() {
    let scratch = tempfile::tempdir().unwrap();
    let db_path = scratch.path().join("Cookies");
    let db = Connection::open(&db_path).unwrap();
    db.execute_batch(
        "CREATE TABLE meta (key TEXT, value TEXT);
         INSERT INTO meta VALUES ('version', '24');
         CREATE TABLE cookies (
            name TEXT, value TEXT, host_key TEXT, path TEXT, expires_utc INTEGER,
            samesite INTEGER, encrypted_value BLOB, is_secure INTEGER,
            is_httponly INTEGER, top_frame_site_key TEXT
         );",
    )
    .unwrap();
    let key = [0x42; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let insert = |name: &str, host: &str, payload: &[u8], partition: &str| {
        db.execute(
            "INSERT INTO cookies VALUES (?1, '', ?2, '/', 0, 0, ?3, 0, 0, ?4)",
            params![name, host, payload, partition],
        )
        .unwrap();
    };
    let encrypt = |prefix: &[u8], plaintext: &[u8], number: u8| {
        let nonce = [number; 12];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .unwrap();
        [prefix, &nonce, ciphertext.as_slice()].concat()
    };
    let domain_value = [Sha256::digest(b".example.test").as_slice(), b"domain"].concat();
    let host_value = [Sha256::digest(b"example.test").as_slice(), b"host"].concat();
    insert(
        "same",
        ".example.test",
        &encrypt(b"v10", &domain_value, 1),
        "",
    );
    insert("same", "example.test", &encrypt(b"v10", &host_value, 2), "");
    insert(
        "mismatch",
        ".example.test",
        &encrypt(b"v10", &host_value, 3),
        "",
    );
    insert(
        "truncated",
        ".example.test",
        &encrypt(b"v10", b"short", 4),
        "",
    );
    insert("app_bound", ".example.test", b"v20unreadable", "");
    insert(
        "partitioned",
        ".example.test",
        &encrypt(b"v10", &domain_value, 5),
        "https://other.test",
    );
    drop(db);

    let mut origins = large_origins();
    origins.push("https://example.test/".to_owned());
    let read = |origins| {
        get_cookies_from_chrome_sqlite_db(
            db_path.to_str().unwrap(),
            None,
            false,
            origins,
            None,
            Box::new(move |value, host| decrypt_chromium_aes256_gcm(value, &key, host)),
            BrowserName::Edge,
        )
    };
    let result = read(&origins).await;
    assert_eq!(result.cookies.len(), 2, "{:?}", result.warnings);
    assert!(result
        .cookies
        .iter()
        .any(|cookie| cookie.host_only == Some(true) && cookie.value == "host"));
    assert!(result
        .cookies
        .iter()
        .any(|cookie| cookie.host_only == Some(false) && cookie.value == "domain"));
    assert!(result
        .cookies
        .iter()
        .all(|cookie| cookie.source.as_ref().unwrap().browser == BrowserName::Edge));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.starts_with("2 Chromium") && warning.contains("host binding")));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("v20 App-Bound")));
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("partitioned Chromium")));
    let child = read(&["https://child.example.test/".to_owned()]).await;
    assert_eq!(child.cookies.len(), 1);
    assert_eq!(child.cookies[0].host_only, Some(false));
}

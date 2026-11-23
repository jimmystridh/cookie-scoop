use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::{ChromiumTarget, ProfileSelector};
use crate::types::ChromiumBrowser;

pub fn looks_like_path(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

pub fn expand_path(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    let path = PathBuf::from(input);
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

pub(crate) struct ChromiumDatabase {
    pub path: PathBuf,
    pub profile: Option<String>,
    #[cfg(target_os = "windows")]
    pub user_data_dir: Option<PathBuf>,
}

pub fn resolve_cookies_db_from_profile_or_roots(
    profile: Option<&str>,
    roots: &[PathBuf],
) -> Option<PathBuf> {
    resolve_databases(
        roots,
        profile.map_or(ProfileSelector::Default, ProfileSelector::Named),
        &mut vec![],
    )
    .into_iter()
    .next()
    .map(|database| database.path)
}

pub(crate) fn resolve_databases(
    roots: &[PathBuf],
    selector: ProfileSelector<'_>,
    warnings: &mut Vec<String>,
) -> Vec<ChromiumDatabase> {
    if let ProfileSelector::Named(profile) = selector {
        let explicit = expand_path(profile);
        if looks_like_path(profile) || explicit.is_file() {
            let path = if is_file(&explicit, warnings) {
                Some(explicit)
            } else {
                first_profile_database(&explicit, warnings)
                    .or_else(|| first_profile_database(&explicit.join("Default"), warnings))
            };
            return path.into_iter().map(database_from_path).collect();
        }
    }

    let mut databases = Vec::new();
    for root in roots {
        match selector {
            ProfileSelector::Default => {
                if let Some(path) = first_profile_database(&root.join("Default"), warnings) {
                    return vec![database_from_path(path)];
                }
            }
            ProfileSelector::Named(profile) => {
                let path = first_profile_database(&root.join(profile), warnings).or_else(|| {
                    profile_aliases(root, warnings)
                        .into_iter()
                        .filter(|(_, name)| name.eq_ignore_ascii_case(profile))
                        .find_map(|(directory, _)| {
                            first_profile_database(&root.join(directory), warnings)
                        })
                });
                if let Some(path) = path {
                    return vec![database_from_path(path)];
                }
            }
            ProfileSelector::All => {
                databases.extend(
                    profile_directories(root, warnings)
                        .filter_map(|directory| first_profile_database(&directory, warnings))
                        .map(database_from_path),
                );
            }
        }
    }
    databases
}

fn profile_directories(root: &Path, warnings: &mut Vec<String>) -> impl Iterator<Item = PathBuf> {
    let mut paths: BTreeSet<_> = profile_aliases(root, warnings)
        .into_iter()
        .map(|(directory, _)| root.join(directory))
        .collect();
    match std::fs::read_dir(root) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        paths.insert(entry.path());
                    }
                    Err(error) => warn_if_permission_denied(&error, root, warnings),
                }
            }
        }
        Err(error) => warn_if_permission_denied(&error, root, warnings),
    }
    let default = root.join("Default");
    let has_default = paths.remove(&default);
    has_default.then_some(default).into_iter().chain(paths)
}

fn first_profile_database(directory: &Path, warnings: &mut Vec<String>) -> Option<PathBuf> {
    let file_names = if cfg!(target_os = "windows") {
        ["Network/Cookies", "Cookies"]
    } else {
        ["Cookies", "Network/Cookies"]
    };
    file_names
        .into_iter()
        .map(|name| directory.join(name))
        .find(|path| is_file(path, warnings))
}

fn database_from_path(path: PathBuf) -> ChromiumDatabase {
    let profile_dir = path.parent().and_then(|parent| {
        if path.file_name() == Some(std::ffi::OsStr::new("Cookies"))
            && parent.file_name() == Some(std::ffi::OsStr::new("Network"))
        {
            parent.parent()
        } else {
            Some(parent)
        }
    });
    ChromiumDatabase {
        profile: profile_dir
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned()),
        #[cfg(target_os = "windows")]
        user_data_dir: find_user_data_dir(&path),
        path,
    }
}

fn profile_aliases(root: &Path, warnings: &mut Vec<String>) -> Vec<(String, String)> {
    let state = root.join("Local State");
    let raw = match std::fs::read_to_string(&state) {
        Ok(raw) => raw,
        Err(error) => {
            warn_if_permission_denied(&error, &state, warnings);
            return vec![];
        }
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return vec![];
    };
    let Some(cache) = parsed["profile"]["info_cache"].as_object() else {
        return vec![];
    };
    cache
        .iter()
        .filter_map(|(folder, details)| {
            let mut components = Path::new(folder).components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
            {
                return None;
            }
            Some((folder.clone(), details["name"].as_str()?.to_owned()))
        })
        .collect()
}

fn is_file(path: &Path, warnings: &mut Vec<String>) -> bool {
    match path.metadata() {
        Ok(metadata) => metadata.is_file(),
        Err(error) => {
            warn_if_permission_denied(&error, path, warnings);
            false
        }
    }
}

fn warn_if_permission_denied(error: &std::io::Error, path: &Path, warnings: &mut Vec<String>) {
    if error.kind() == ErrorKind::PermissionDenied {
        warnings.push(format!(
            "Permission denied reading Chromium profile data at {}.",
            path.display()
        ));
    }
}

pub(crate) fn linux_config_home(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".config"))
}

pub fn chrome_roots() -> Vec<PathBuf> {
    target_roots(ChromiumTarget::Chrome(ChromiumBrowser::Chrome))
}

pub fn edge_roots() -> Vec<PathBuf> {
    target_roots(ChromiumTarget::Edge)
}

pub(crate) fn target_roots(target: ChromiumTarget) -> Vec<PathBuf> {
    use ChromiumBrowser::*;
    use ChromiumTarget::{Chrome as Family, Edge};

    if cfg!(target_os = "windows") {
        let root = match target {
            Family(Chrome) => "Google/Chrome/User Data",
            Edge => "Microsoft/Edge/User Data",
            _ => return vec![],
        };
        return std::env::var_os("LOCALAPPDATA")
            .map(|path| PathBuf::from(path).join(root))
            .into_iter()
            .collect();
    }
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    if cfg!(target_os = "macos") {
        let root = match target {
            Family(Chrome) => "Google/Chrome",
            Family(Chromium) => "Chromium",
            Family(Brave) => "BraveSoftware/Brave-Browser",
            Family(Arc) => "Arc/User Data",
            Family(Dia) => "Dia/User Data",
            Edge => "Microsoft Edge",
        };
        return vec![home.join("Library/Application Support").join(root)];
    }
    if cfg!(target_os = "linux") {
        let config = linux_config_home(&home);
        return match target {
            Family(Chrome) => vec![
                config.join("google-chrome"),
                home.join(".var/app/com.google.Chrome/config/google-chrome"),
            ],
            Family(Chromium) => vec![
                config.join("chromium"),
                home.join("snap/chromium/common/chromium"),
                home.join(".var/app/org.chromium.Chromium/config/chromium"),
            ],
            Family(Brave) => vec![
                config.join("BraveSoftware/Brave-Browser"),
                home.join("snap/brave/common/BraveSoftware/Brave-Browser"),
                home.join(".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
            ],
            Edge => vec![config.join("microsoft-edge")],
            _ => vec![],
        };
    }
    vec![]
}

#[cfg(target_os = "windows")]
pub fn resolve_chromium_paths_windows(
    local_app_data_vendor_path: &str,
    profile: Option<&str>,
) -> (Option<PathBuf>, Option<PathBuf>) {
    let roots: Vec<_> = std::env::var_os("LOCALAPPDATA")
        .map(|path| PathBuf::from(path).join(local_app_data_vendor_path))
        .into_iter()
        .collect();
    let database = resolve_databases(
        &roots,
        profile.map_or(ProfileSelector::Default, ProfileSelector::Named),
        &mut vec![],
    )
    .into_iter()
    .next();
    match database {
        Some(database) => (Some(database.path), database.user_data_dir),
        None => (None, None),
    }
}

#[cfg(target_os = "windows")]
fn find_user_data_dir(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .find(|directory| directory.join("Local State").is_file())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_display_names_and_discovers_cookie_databases_once() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().to_path_buf();
        let default = root.join("Default/Cookies");
        let named = root.join("Profile 1/Network/Cookies");
        for database in [&default, &named] {
            std::fs::create_dir_all(database.parent().unwrap()).unwrap();
            std::fs::write(database, "").unwrap();
        }
        std::fs::create_dir(root.join("System Profile")).unwrap();
        std::fs::write(
            root.join("Local State"),
            r#"{"profile":{"info_cache":{"Profile 1":{"name":"Work"},"System Profile":{"name":"Auxiliary"}}}}"#,
        ).unwrap();

        let mut warnings = Vec::new();
        let selected = resolve_databases(
            std::slice::from_ref(&root),
            ProfileSelector::Named("Work"),
            &mut warnings,
        );
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].path, named);
        assert_eq!(selected[0].profile.as_deref(), Some("Profile 1"));

        let discovered: Vec<_> = resolve_databases(&[root], ProfileSelector::All, &mut warnings)
            .into_iter()
            .map(|database| database.path)
            .collect();
        assert_eq!(discovered, [default, named]);
        assert!(warnings.is_empty());
    }
}

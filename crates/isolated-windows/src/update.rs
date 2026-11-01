//! The in-app updater. Checks GitHub Releases for a newer version, downloads
//! `isolated.exe`, verifies it against the published SHA-256, and swaps it in
//! place of the running exe (Windows allows renaming a running exe). Nothing
//! runs in the background: checks happen when the window opens or when users
//! ask.

use crate::Result;
use isolated_core::version;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const REPO: &str = "tacobellerontop-sudo/Isolated";
pub const REPO_URL: &str = "https://github.com/tacobellerontop-sudo/Isolated";
pub const ASSET: &str = "isolated.exe";
pub const CHECKSUM_ASSET: &str = "isolated.exe.sha256";

/// A release newer than this build.
#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub version: String,
    pub notes: String,
    pub page_url: String,
    pub exe_url: String,
    pub checksum_url: String,
    pub size: u64,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// Parses the GitHub "latest release" response. Returns `None` when the
/// release is not newer than `current`, is a draft or pre-release, or has no
/// exe and checksum.
pub fn parse_latest(json: &str, current: &str) -> Result<Option<Release>> {
    let r: ApiRelease = serde_json::from_str(json).map_err(|e| format!("unexpected answer from GitHub: {e}"))?;
    if r.draft || r.prerelease || !version::is_newer(&r.tag_name, current) {
        return Ok(None);
    }
    let find = |n: &str| r.assets.iter().find(|a| a.name.eq_ignore_ascii_case(n));
    let (Some(exe), Some(sum)) = (find(ASSET), find(CHECKSUM_ASSET)) else {
        return Ok(None);
    };
    Ok(Some(Release {
        version: r.tag_name.trim_start_matches(['v', 'V']).to_string(),
        notes: r.body.unwrap_or_default(),
        page_url: r.html_url,
        exe_url: exe.browser_download_url.clone(),
        checksum_url: sum.browser_download_url.clone(),
        size: exe.size,
    }))
}

/// Parses a `.sha256` file: the first token, as lowercase hex.
pub fn parse_checksum(text: &str) -> Result<String> {
    let token = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(token)
    } else {
        Err("the release's checksum file is not valid".into())
    }
}

#[allow(unused_variables)]
fn fetch(url: &str, progress: &mut dyn FnMut(u64, Option<u64>)) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        crate::win::http::get(
            url,
            &[("Accept", "application/vnd.github+json, application/octet-stream")],
            |chunk, got, total| {
                out.extend_from_slice(chunk);
                if out.len() > 64 << 20 {
                    return Err("the download is unexpectedly large".into());
                }
                progress(got, total);
                Ok(())
            },
        )?;
        Ok(out)
    }
    #[cfg(not(windows))]
    Err("Updates are only available on Windows.".into())
}

/// Asks GitHub for the latest release. `Ok(None)` means up to date.
pub fn check() -> Result<Option<Release>> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = fetch(&url, &mut |_, _| {})?;
    parse_latest(&String::from_utf8_lossy(&body), version::CURRENT)
}

fn old_path(exe: &Path) -> PathBuf {
    exe.with_extension("exe.old")
}

/// Downloads, verifies and installs a release over the running exe. Returns
/// the exe path, ready to be restarted.
pub fn install(release: &Release, mut progress: impl FnMut(u64, Option<u64>)) -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let expected = parse_checksum(&String::from_utf8_lossy(&fetch(&release.checksum_url, &mut |_, _| {})?))?;
    let bytes = fetch(&release.exe_url, &mut progress)?;
    let actual = isolated_core::sha256::hex_digest(&bytes);
    if actual != expected {
        return Err("The downloaded update does not match its published checksum, so it was not installed.".into());
    }
    if bytes.len() < 1024 || &bytes[..2] != b"MZ" {
        return Err("The downloaded update is not a Windows program, so it was not installed.".into());
    }
    replace_exe(&exe, &bytes)?;
    Ok(exe)
}

/// Writes `bytes` as the new exe, keeping the old one as `.exe.old` until the
/// next start, and rolling back on failure.
pub fn replace_exe(exe: &Path, bytes: &[u8]) -> Result<()> {
    let new = exe.with_extension("exe.new");
    let old = old_path(exe);
    std::fs::write(&new, bytes).map_err(|e| {
        format!(
            "Could not save the update next to {} ({e}). If Isolated is in a protected folder, use Install in Settings first.",
            exe.display()
        )
    })?;
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(exe, &old) {
        let _ = std::fs::remove_file(&new);
        return Err(format!("could not move the current version aside: {e}"));
    }
    if let Err(e) = std::fs::rename(&new, exe) {
        let _ = std::fs::rename(&old, exe);
        let _ = std::fs::remove_file(&new);
        return Err(format!("could not put the new version in place: {e}"));
    }
    Ok(())
}

/// Deletes the previous version left by an update. Called at startup; it may
/// still be in use by a sandbox watcher, in which case it is tried next time.
pub fn cleanup_old() {
    if let Ok(exe) = std::env::current_exe() {
        let old = old_path(&exe);
        if old.exists() {
            let _ = std::fs::remove_file(old);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "tag_name": "v0.2.0", "html_url": "https://github.com/x/y/releases/tag/v0.2.0",
        "body": "Notes", "draft": false, "prerelease": false,
        "assets": [
            {"name": "isolated.exe", "browser_download_url": "https://e/isolated.exe", "size": 3000000},
            {"name": "isolated.exe.sha256", "browser_download_url": "https://e/isolated.exe.sha256", "size": 90}
        ]
    }"#;

    #[test]
    fn newer_release_found() {
        let r = parse_latest(SAMPLE, "0.1.0").unwrap().unwrap();
        assert_eq!(r.version, "0.2.0");
        assert_eq!(r.exe_url, "https://e/isolated.exe");
        assert_eq!(r.checksum_url, "https://e/isolated.exe.sha256");
        assert!(parse_latest(SAMPLE, "0.2.0").unwrap().is_none());
    }

    #[test]
    fn missing_checksum_is_ignored() {
        let j = SAMPLE.replace("isolated.exe.sha256", "other.txt");
        assert!(parse_latest(&j, "0.1.0").unwrap().is_none());
    }

    #[test]
    fn checksums() {
        let h = "A".repeat(64);
        assert_eq!(parse_checksum(&format!("{h}  isolated.exe\n")).unwrap(), "a".repeat(64));
        assert!(parse_checksum("xyz").is_err());
    }

    #[test]
    fn replace_and_rollback() {
        let dir = std::env::temp_dir().join(format!("isolated-upd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("isolated.exe");
        std::fs::write(&exe, b"old").unwrap();
        replace_exe(&exe, b"new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(old_path(&exe)).unwrap(), b"old");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

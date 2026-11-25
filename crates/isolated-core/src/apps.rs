//! Recognises programs built on Chromium (browsers, Electron and CEF apps
//! such as most AI desktop apps and the Steam client), the way Sandboxie
//! recognises them: by the files Chromium ships next to its exe.
//!
//! Chromium runs its own sandbox, which cannot start inside the compatible
//! tier's low-integrity token. Those apps are told to skip it; Isolated's
//! sandbox still contains them.

use std::path::Path;

/// What a program is built on, as far as starting it is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Chrome, Edge, Electron apps and other Chromium-based programs.
    Chromium,
    /// The Steam client, which starts its Chromium (CEF) helper itself.
    Steam,
    /// Apps that show their window with Microsoft WebView2 (Tauri apps and
    /// others), which starts Edge's engine for them.
    WebView2,
    Other,
}

const CHROMIUM_MARKERS: &[&str] = &[
    "chrome_100_percent.pak",
    "resources.pak",
    "chrome_elf.dll",
    "libcef.dll",
    "v8_context_snapshot.bin",
];

pub fn engine(exe: &Path) -> Engine {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name == "steam.exe" {
        return Engine::Steam;
    }
    let Some(dir) = exe.parent() else {
        return Engine::Other;
    };
    let has = |p: &Path| CHROMIUM_MARKERS.iter().any(|m| p.join(m).is_file());
    // Chrome and Edge keep these in a folder named after their version.
    let in_version_folder = || {
        std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.contains('.')
                && n.chars().all(|c| c.is_ascii_digit() || c == '.')
                && (has(&e.path()) || e.path().join("msedge_elf.dll").is_file())
        })
    };
    if has(dir) || dir.join("resources").join("app.asar").is_file() || in_version_folder() {
        Engine::Chromium
    } else if dir.join("WebView2Loader.dll").is_file() || mentions_webview2(exe) {
        Engine::WebView2
    } else {
        Engine::Other
    }
}

/// True if the exe links the WebView2 loader (Tauri and others build it in).
fn mentions_webview2(exe: &Path) -> bool {
    const NEEDLE: &[u8] = b"CreateCoreWebView2Environment";
    match std::fs::metadata(exe) {
        Ok(m) if m.len() <= 300 * 1024 * 1024 => {}
        _ => return false,
    }
    std::fs::read(exe)
        .map(|data| data.windows(NEEDLE.len()).any(|w| w == NEEDLE))
        .unwrap_or(false)
}

/// Arguments that make a program skip its own sandbox, put before its
/// other arguments.
pub fn own_sandbox_off_args(exe: &Path) -> Vec<String> {
    match engine(exe) {
        Engine::Chromium => vec!["--no-sandbox".into()],
        Engine::Steam => vec!["-no-cef-sandbox".into()],
        Engine::WebView2 | Engine::Other => Vec::new(),
    }
}

/// True if an installer's file name follows the naming of Tauri
/// (`App_1.2.3_x64-setup.exe`) or electron-builder (`App Setup 1.2.3.exe`)
/// installers, whose apps need the compatible tier.
pub fn installer_looks_web(file_name: &str) -> bool {
    let n = file_name.to_ascii_lowercase();
    let version = |v: &str| !v.is_empty() && v.contains('.') && v.chars().all(|c| c.is_ascii_digit() || c == '.');
    for arch in ["_x64-setup.exe", "_x86-setup.exe", "_arm64-setup.exe"] {
        if let Some(rest) = n.strip_suffix(arch) {
            if let Some((_, v)) = rest.rsplit_once('_') {
                return version(v);
            }
        }
    }
    if let Some(rest) = n.strip_suffix(".exe") {
        if let Some((_, v)) = rest.rsplit_once(" setup ") {
            return version(v);
        }
    }
    false
}

/// Folders outside the box that an app is known to insist on writing to,
/// found by a name in `text` (a box name or program path). These are kept
/// inside the box automatically.
pub fn known_kept_folders(text: &str) -> &'static [&'static str] {
    let t = text.to_ascii_lowercase();
    if t.contains("kryoto") {
        // Kryoto Desktop downloads and installs games here, whatever
        // folder it was installed to.
        &["%USERPROFILE%\\Kryoto Games"]
    } else {
        &[]
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_folders() {
        assert_eq!(super::known_kept_folders("C:\\x\\Kryoto Desktop\\kryoto.exe"), &["%USERPROFILE%\\Kryoto Games"]);
        assert!(super::known_kept_folders("notepad.exe").is_empty());
    }

    #[test]
    fn web_installer_names() {
        use super::installer_looks_web as w;
        assert!(w("Kryoto-Desktop_0.4.0_x64-setup.exe"));
        assert!(w("pot_3.0.7_x64-setup.exe"));
        assert!(w("Some App Setup 1.2.3.exe"));
        assert!(!w("7z2408-x64.exe"));
        assert!(!w("setup.exe"));
        assert!(!w("npp.8.6.Installer.x64.exe"));
    }

    use super::*;

    #[test]
    fn spots_chromium_apps_by_their_files() {
        let d = std::env::temp_dir().join(format!("iso-apps-{}", std::process::id()));
        std::fs::create_dir_all(d.join("resources")).unwrap();
        let exe = d.join("AiChat.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(engine(&exe), Engine::Other);
        let tauri = d.join("tauri-app.exe");
        std::fs::write(&tauri, b"MZ...CreateCoreWebView2Environment...").unwrap();
        assert_eq!(engine(&tauri), Engine::WebView2);
        std::fs::remove_file(&tauri).unwrap();
        std::fs::create_dir_all(d.join("131.0.2903.70")).unwrap();
        std::fs::write(d.join("131.0.2903.70").join("msedge_elf.dll"), b"").unwrap();
        assert_eq!(engine(&exe), Engine::Chromium);
        std::fs::remove_dir_all(d.join("131.0.2903.70")).unwrap();
        assert_eq!(engine(&exe), Engine::Other);
        std::fs::write(d.join("resources").join("app.asar"), b"").unwrap();
        assert_eq!(engine(&exe), Engine::Chromium);
        assert_eq!(own_sandbox_off_args(&exe), vec!["--no-sandbox".to_string()]);
        assert_eq!(engine(&d.join("Steam.exe")), Engine::Steam);
        let _ = std::fs::remove_dir_all(&d);
    }
}

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
    if has(dir) || dir.join(r"resources\app.asar").is_file() {
        Engine::Chromium
    } else {
        Engine::Other
    }
}

/// Arguments that make a program skip its own sandbox, put before its
/// other arguments.
pub fn own_sandbox_off_args(exe: &Path) -> Vec<String> {
    match engine(exe) {
        Engine::Chromium => vec!["--no-sandbox".into()],
        Engine::Steam => vec!["-no-cef-sandbox".into()],
        Engine::Other => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_chromium_apps_by_their_files() {
        let d = std::env::temp_dir().join(format!("iso-apps-{}", std::process::id()));
        std::fs::create_dir_all(d.join("resources")).unwrap();
        let exe = d.join("AiChat.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(engine(&exe), Engine::Other);
        std::fs::write(d.join(r"resources").join("app.asar"), b"").unwrap();
        if cfg!(windows) {
            assert_eq!(engine(&exe), Engine::Chromium);
        }
        std::fs::write(d.join("resources.pak"), b"").unwrap();
        assert_eq!(engine(&exe), Engine::Chromium);
        assert_eq!(own_sandbox_off_args(&exe), vec!["--no-sandbox".to_string()]);
        assert_eq!(engine(&d.join("Steam.exe")), Engine::Steam);
        let _ = std::fs::remove_dir_all(&d);
    }
}

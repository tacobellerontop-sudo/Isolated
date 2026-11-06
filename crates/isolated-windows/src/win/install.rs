//! Per-user install and uninstall. The exe is its own installer: no MSI,
//! no admin, nothing resident.

use super::menu;
use super::shell::{self, KnownFolder};
use std::path::PathBuf;
use windows::Win32::System::Registry::HKEY_CURRENT_USER;

const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Isolated";

fn shortcut_path() -> Option<PathBuf> {
    shell::known_folder(KnownFolder::StartMenuPrograms).map(|p| p.join("Isolated.lnk"))
}

fn write_uninstall_entry(exe: &std::path::Path) -> Result<(), String> {
    let k = menu::create_key(HKEY_CURRENT_USER, UNINSTALL_KEY)?;
    let e = exe.to_string_lossy();
    menu::set_string(&k, Some("DisplayName"), "Isolated")?;
    menu::set_string(&k, Some("DisplayVersion"), isolated_core::version::CURRENT)?;
    menu::set_string(&k, Some("Publisher"), "Isolated")?;
    menu::set_string(&k, Some("DisplayIcon"), &format!("{e},0"))?;
    menu::set_string(&k, Some("UninstallString"), &format!("\"{e}\" uninstall"))?;
    menu::set_string(&k, Some("QuietUninstallString"), &format!("\"{e}\" uninstall --quiet"))?;
    if let Some(dir) = exe.parent() {
        menu::set_string(&k, Some("InstallLocation"), &dir.to_string_lossy())?;
    }
    menu::set_string(&k, Some("URLInfoAbout"), crate::update::REPO_URL)?;
    menu::set_dword(&k, "NoModify", 1)?;
    menu::set_dword(&k, "NoRepair", 1)?;
    menu::set_dword(
        &k,
        "EstimatedSize",
        (std::fs::metadata(exe).map(|m| m.len()).unwrap_or(0) / 1024) as u32,
    )?;
    Ok(())
}

pub fn install() -> Result<PathBuf, String> {
    let dir = crate::install::install_dir().ok_or("LOCALAPPDATA is not set")?;
    let dest = dir.join("isolated.exe");
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    if !crate::install::is_running_installed() {
        // An older copy may be running (for example as a sandbox watcher);
        // move it aside instead of failing.
        if dest.exists() && std::fs::remove_file(&dest).is_err() {
            let old = dest.with_extension("exe.old");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(&dest, &old).map_err(|e| format!("could not replace the installed copy: {e}"))?;
        }
        std::fs::copy(&me, &dest).map_err(|e| format!("could not copy Isolated to {}: {e}", dest.display()))?;
    }
    if let Some(lnk) = shortcut_path() {
        shell::create_shortcut(&lnk, &dest, "Run programs in a sandbox")?;
    }
    menu::register(&dest)?;
    write_uninstall_entry(&dest)?;
    Ok(dest)
}

/// After an update: records the new version and rewrites the right-click
/// menu, whose entries may have changed. Does nothing when up to date.
pub fn refresh_version() {
    if menu::get_string(UNINSTALL_KEY, Some("DisplayName")).is_none() {
        return;
    }
    // Only the installed copy speaks for the installed version.
    let key = |p: &std::path::Path| isolated_core::profile::normalize_path_key(&p.to_string_lossy());
    let (Some(registered), Ok(me)) = (menu::registered_exe(), std::env::current_exe()) else {
        return;
    };
    if key(&registered) != key(&me) {
        return;
    }
    let current = isolated_core::version::CURRENT;
    if menu::get_string(UNINSTALL_KEY, Some("DisplayVersion")).as_deref() == Some(current) {
        return;
    }
    if let Ok(k) = menu::create_key(HKEY_CURRENT_USER, UNINSTALL_KEY) {
        let _ = menu::set_string(&k, Some("DisplayVersion"), current);
    }
    let _ = menu::register(&registered);
}

pub fn uninstall(dirs: &isolated_core::Dirs, remove_data: bool) -> Result<(), String> {
    let _ = crate::repair(dirs);
    menu::unregister()?;
    if let Some(lnk) = shortcut_path() {
        let _ = std::fs::remove_file(lnk);
    }
    menu::delete_tree(UNINSTALL_KEY)?;
    if remove_data {
        let _ = std::fs::remove_dir_all(&dirs.config);
        let _ = std::fs::remove_dir_all(&dirs.data);
    }
    // The running exe cannot delete itself; a short-lived cmd does it once
    // this process has exited.
    if let Some(dir) = crate::install::install_dir() {
        if dir.exists() {
            let d = dir.to_string_lossy().to_string();
            let mut cmd = std::process::Command::new(std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into()));
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.raw_arg(format!("/d /c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{d}\""))
                .creation_flags(CREATE_NO_WINDOW);
            let _ = cmd.spawn();
        }
    }
    Ok(())
}

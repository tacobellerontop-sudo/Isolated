//! The right-click "Run in Isolated" menu, as plain per-user registry verbs
//! (no shell extension DLL, no admin).

use super::util::{win32_err, Wide};
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ,
};
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};

/// File classes that get the menu.
pub const CLASSES: &[&str] = &[
    "exefile",
    "lnkfile",
    "batfile",
    "cmdfile",
    "Microsoft.PowerShellScript.1",
    "Msi.Package",
];
const VERB: &str = "Isolated";

fn key_path(class: &str) -> String {
    format!(r"Software\Classes\{class}\shell\{VERB}")
}

pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

pub fn create_key(root: HKEY, path: &str) -> Result<Key, String> {
    let w = Wide::new(path);
    let mut hk = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            root,
            w.pcwstr(),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hk,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(&format!(r"could not write registry key HKCU\{path}"), rc));
    }
    Ok(Key(hk))
}

pub fn set_string(key: &Key, name: Option<&str>, value: &str) -> Result<(), String> {
    let n = name.map(Wide::new);
    let v = Wide::new(value);
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(v.0.as_ptr() as *const u8, v.0.len() * 2) };
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            n.as_ref().map(|n| n.pcwstr()).unwrap_or(windows::core::PCWSTR::null()),
            None,
            REG_SZ,
            Some(bytes),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err("could not write a registry value", rc));
    }
    Ok(())
}

pub fn set_dword(key: &Key, name: &str, value: u32) -> Result<(), String> {
    let n = Wide::new(name);
    let rc = unsafe {
        RegSetValueExW(
            key.0,
            n.pcwstr(),
            None,
            windows::Win32::System::Registry::REG_DWORD,
            Some(&value.to_le_bytes()),
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err("could not write a registry value", rc));
    }
    Ok(())
}

pub fn get_string(path: &str, name: Option<&str>) -> Option<String> {
    let p = Wide::new(path);
    let n = name.map(Wide::new);
    let mut buf = vec![0u16; 4096];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            p.pcwstr(),
            n.as_ref().map(|n| n.pcwstr()).unwrap_or(windows::core::PCWSTR::null()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut size),
        )
    };
    (rc == ERROR_SUCCESS).then(|| super::util::from_wide_buf(&buf))
}

pub fn delete_tree(path: &str) -> Result<(), String> {
    let w = Wide::new(path);
    let rc = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, w.pcwstr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        return Err(win32_err(&format!(r"could not remove HKCU\{path}"), rc));
    }
    Ok(())
}

fn notify() {
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None) }
}

pub fn register(exe: &Path) -> Result<(), String> {
    let exe = exe.to_string_lossy();
    let q = format!("\"{exe}\"");
    let install = ("06install", "Install in Isolated...", format!("{q} box options \"%1\""));
    let entries: [(&str, &str, String); 5] = [
        ("01run", "Run in Isolated", format!("{q} run \"%1\"")),
        (
            "02offline",
            "Run in Isolated (offline)",
            format!("{q} run --no-net \"%1\""),
        ),
        (
            "03folders",
            "Run in Isolated with folders...",
            format!("{q} run --ask-folders \"%1\""),
        ),
        (
            "04options",
            "Run in Isolated with options...",
            format!("{q} options \"%1\""),
        ),
        (
            "05profile",
            "Edit Isolated profile...",
            format!("{q} profile edit \"%1\""),
        ),
    ];
    for class in CLASSES {
        let base = key_path(class);
        let _ = delete_tree(&base);
        let k = create_key(HKEY_CURRENT_USER, &base)?;
        set_string(&k, Some("MUIVerb"), "Run in Isolated")?;
        set_string(&k, Some("Icon"), &format!("{exe},0"))?;
        set_string(&k, Some("SubCommands"), "")?;
        // Installers: .msi files only get the install entry; programs get it
        // after the run entries.
        let list: Vec<&(&str, &str, String)> = match *class {
            "Msi.Package" => vec![&install],
            "exefile" => entries.iter().chain(std::iter::once(&install)).collect(),
            _ => entries.iter().collect(),
        };
        if *class == "Msi.Package" {
            set_string(&k, Some("MUIVerb"), "Install in Isolated")?;
        }
        for (sub, label, command) in list {
            let sk = create_key(HKEY_CURRENT_USER, &format!(r"{base}\shell\{sub}"))?;
            set_string(&sk, Some("MUIVerb"), label)?;
            let ck = create_key(HKEY_CURRENT_USER, &format!(r"{base}\shell\{sub}\command"))?;
            set_string(&ck, None, command)?;
        }
    }
    notify();
    Ok(())
}

pub fn unregister() -> Result<(), String> {
    let mut first = None;
    for class in CLASSES {
        if let Err(e) = delete_tree(&key_path(class)) {
            first.get_or_insert(e);
        }
    }
    notify();
    first.map_or(Ok(()), Err)
}

pub fn registered_exe() -> Option<PathBuf> {
    let cmd = get_string(&format!(r"{}\shell\01run\command", key_path("exefile")), None)?;
    let exe = cmd.trim_start_matches('"').split('"').next()?.to_string();
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

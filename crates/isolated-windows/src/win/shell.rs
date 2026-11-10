//! Message boxes, file pickers, known folders, shortcuts, and opening URLs.

use super::util::{err, from_wide_buf, from_wide_ptr, Wide};
use crate::shell::Icon;
use std::path::{Path, PathBuf};
use windows::core::{Interface, GUID, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    STGM_READ,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow,
    FOLDERID_Profile, FOLDERID_Programs, FOLDERID_RoamingAppData, FileOpenDialog, IFileOpenDialog, IShellLinkW,
    SHGetKnownFolderPath, ShellExecuteW, ShellLink, FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, KF_FLAG_DEFAULT,
    SIGDN_FILESYSPATH, SLR_NO_UI,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MB_YESNO,
    SW_SHOWNORMAL,
};

fn com_init() {
    unsafe {
        // Already initialized (by winit, or earlier) is fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
}

pub fn message_box(title: &str, text: &str, icon: Icon) {
    let t = Wide::new(title);
    let m = Wide::new(text);
    let style = match icon {
        Icon::Info => MB_ICONINFORMATION,
        Icon::Warning => MB_ICONWARNING,
        Icon::Error => MB_ICONERROR,
    };
    unsafe {
        MessageBoxW(None, m.pcwstr(), t.pcwstr(), MB_OK | style | MB_SETFOREGROUND);
    }
}

pub fn confirm(title: &str, text: &str) -> bool {
    let t = Wide::new(title);
    let m = Wide::new(text);
    unsafe {
        MessageBoxW(
            None,
            m.pcwstr(),
            t.pcwstr(),
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND,
        ) == IDYES
    }
}

pub fn open(target: &str) {
    let t = Wide::new(target);
    let verb = Wide::new("open");
    unsafe {
        ShellExecuteW(
            None,
            verb.pcwstr(),
            t.pcwstr(),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}

pub fn pick(folder: bool) -> Option<PathBuf> {
    pick_with(folder, "Programs and scripts", "*.exe;*.lnk;*.bat;*.cmd;*.ps1;*.com")
}

pub fn pick_any() -> Option<PathBuf> {
    pick_with(false, "All files", "*.*")
}

pub fn pick_installer() -> Option<PathBuf> {
    pick_with(false, "Installers", "*.exe;*.msi")
}

fn pick_with(folder: bool, kind: &str, pattern: &str) -> Option<PathBuf> {
    com_init();
    unsafe {
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let mut opts = dialog.GetOptions().ok()? | FOS_FORCEFILESYSTEM;
        if folder {
            opts |= FOS_PICKFOLDERS;
        }
        dialog.SetOptions(opts).ok()?;
        let n1 = Wide::new(kind);
        let s1 = Wide::new(pattern);
        let n2 = Wide::new("All files");
        let s2 = Wide::new("*.*");
        if !folder {
            let specs = [
                COMDLG_FILTERSPEC {
                    pszName: n1.pcwstr(),
                    pszSpec: s1.pcwstr(),
                },
                COMDLG_FILTERSPEC {
                    pszName: n2.pcwstr(),
                    pszSpec: s2.pcwstr(),
                },
            ];
            let _ = dialog.SetFileTypes(&specs);
        }
        dialog.Show(None).ok()?;
        let item = dialog.GetResult().ok()?;
        let name = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let path = from_wide_ptr(name.0);
        CoTaskMemFree(Some(name.0 as *const _));
        Some(PathBuf::from(path))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KnownFolder {
    Profile,
    Downloads,
    Desktop,
    Documents,
    LocalAppDataLow,
    RoamingAppData,
    LocalAppData,
    StartMenuPrograms,
}

pub fn known_folder(f: KnownFolder) -> Option<PathBuf> {
    let id: &GUID = match f {
        KnownFolder::Profile => &FOLDERID_Profile,
        KnownFolder::Downloads => &FOLDERID_Downloads,
        KnownFolder::Desktop => &FOLDERID_Desktop,
        KnownFolder::Documents => &FOLDERID_Documents,
        KnownFolder::LocalAppDataLow => &FOLDERID_LocalAppDataLow,
        KnownFolder::RoamingAppData => &FOLDERID_RoamingAppData,
        KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
        KnownFolder::StartMenuPrograms => &FOLDERID_Programs,
    };
    unsafe {
        let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = from_wide_ptr(p.0);
        CoTaskMemFree(Some(p.0 as *const _));
        (!s.is_empty()).then(|| PathBuf::from(s))
    }
}

pub struct ShortcutInfo {
    pub target: PathBuf,
    pub arguments: String,
    pub workdir: PathBuf,
}

pub fn resolve_shortcut(lnk: &Path) -> Result<ShortcutInfo, String> {
    com_init();
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| err("could not read the shortcut", e))?;
        let file: IPersistFile = link.cast().map_err(|e| err("could not read the shortcut", e))?;
        let w = Wide::new(lnk.as_os_str());
        file.Load(w.pcwstr(), STGM_READ)
            .map_err(|e| err("could not open the shortcut", e))?;
        let _ = link.Resolve(Default::default(), SLR_NO_UI.0 as u32);
        let mut target = vec![0u16; 32768];
        let _ = link.GetPath(&mut target, std::ptr::null_mut(), 0);
        let mut args = vec![0u16; 32768];
        let _ = link.GetArguments(&mut args);
        let mut wd = vec![0u16; 32768];
        let _ = link.GetWorkingDirectory(&mut wd);
        Ok(ShortcutInfo {
            target: PathBuf::from(from_wide_buf(&target)),
            arguments: from_wide_buf(&args),
            workdir: PathBuf::from(from_wide_buf(&wd)),
        })
    }
}

pub fn create_shortcut(lnk: &Path, target: &Path, description: &str) -> Result<(), String> {
    com_init();
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| err("could not create a shortcut", e))?;
        let t = Wide::new(target.as_os_str());
        link.SetPath(t.pcwstr())
            .map_err(|e| err("could not create a shortcut", e))?;
        let d = Wide::new(description);
        let _ = link.SetDescription(d.pcwstr());
        let _ = link.SetIconLocation(t.pcwstr(), 0);
        if let Some(dir) = target.parent() {
            let wd = Wide::new(dir.as_os_str());
            let _ = link.SetWorkingDirectory(wd.pcwstr());
        }
        let file: IPersistFile = link.cast().map_err(|e| err("could not save the shortcut", e))?;
        let w = Wide::new(lnk.as_os_str());
        file.Save(w.pcwstr(), true)
            .map_err(|e| err("could not save the shortcut", e))
    }
}

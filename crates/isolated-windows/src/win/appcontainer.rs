//! AppContainer identities and capability SIDs.

use super::util::{err, from_wide_ptr, LocalBox, Wide};
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    GetAppContainerFolderPath,
};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, FreeSid, PSID};
use windows::Win32::System::Com::CoTaskMemFree;

/// An AppContainer SID, freed on drop.
pub struct ContainerSid {
    pub sid: PSID,
}

impl Drop for ContainerSid {
    fn drop(&mut self) {
        if !self.sid.0.is_null() {
            unsafe {
                FreeSid(self.sid);
            }
        }
    }
}

impl ContainerSid {
    pub fn to_string_sid(&self) -> String {
        sid_to_string(self.sid)
    }

    /// The container's private storage folder
    /// (`%LOCALAPPDATA%\Packages\<name>\AC`).
    pub fn folder(&self) -> Result<std::path::PathBuf, String> {
        let s = Wide::new(self.to_string_sid());
        unsafe {
            let p = GetAppContainerFolderPath(s.pcwstr())
                .map_err(|e| err("could not find the sandbox's storage folder", e))?;
            let path = from_wide_ptr(p.0);
            CoTaskMemFree(Some(p.0 as *const _));
            Ok(path.into())
        }
    }
}

pub fn sid_to_string(sid: PSID) -> String {
    unsafe {
        let mut out = PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut out).is_err() {
            return String::new();
        }
        let s = from_wide_ptr(out.0);
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
        s
    }
}

/// Creates the AppContainer profile, or opens it if it already exists.
pub fn create_or_open(name: &str, display: &str) -> Result<ContainerSid, String> {
    let wname = Wide::new(name);
    let wdisplay = Wide::new(display);
    let wdesc = Wide::new("Sandbox created by Isolated");
    unsafe {
        match CreateAppContainerProfile(wname.pcwstr(), wdisplay.pcwstr(), wdesc.pcwstr(), None) {
            Ok(sid) => Ok(ContainerSid { sid }),
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                let sid = DeriveAppContainerSidFromAppContainerName(wname.pcwstr())
                    .map_err(|e| err("could not open the sandbox identity", e))?;
                Ok(ContainerSid { sid })
            }
            Err(e) => Err(err("could not create the sandbox identity (AppContainer)", e)),
        }
    }
}

/// Capability SIDs derived from capability names such as `internetClient`.
/// Keeps the memory alive for as long as the SIDs are used.
#[derive(Default)]
pub struct Capabilities {
    pub sids: Vec<PSID>,
    _owned: Vec<LocalBox>,
}

impl Capabilities {
    pub fn add(&mut self, name: &str) -> Result<(), String> {
        let wname = Wide::new(name);
        unsafe {
            let mut groups: *mut PSID = std::ptr::null_mut();
            let mut ngroups = 0u32;
            let mut caps: *mut PSID = std::ptr::null_mut();
            let mut ncaps = 0u32;
            DeriveCapabilitySidsFromName(wname.pcwstr(), &mut groups, &mut ngroups, &mut caps, &mut ncaps)
                .map_err(|e| err(&format!("could not derive the '{name}' capability"), e))?;
            for i in 0..ngroups as usize {
                self._owned.push(LocalBox((*groups.add(i)).0));
            }
            self._owned.push(LocalBox(groups as *mut _));
            for i in 0..ncaps as usize {
                let sid = *caps.add(i);
                self.sids.push(sid);
                self._owned.push(LocalBox(sid.0));
            }
            self._owned.push(LocalBox(caps as *mut _));
        }
        Ok(())
    }
}

/// AppContainer names allow letters, digits, `.`, `-`, `_`, up to 64 chars.
pub fn container_name(profile: &str, program_key: &str) -> String {
    let clean: String = profile
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(32)
        .collect();
    format!(
        "Isolated.{}.{:016x}",
        clean,
        isolated_core::state::stable_hash(program_key)
    )
}

/// Identity of an isolated folder, shared by every program in it. Kept short
/// on purpose: inside a sandbox Windows puts the LocalAppData and LocalLow
/// folders at `<user folder>\AppData\Local\Packages\<name>\AC`, and the user
/// folder is itself in `...\Packages\<name>\AC\Home`, so the name appears
/// twice in every path an app saves there. Long names pushed real game save
/// paths past Windows' 260-character limit.
pub fn folder_container_name(folder_key: &str) -> String {
    format!(
        "Isolated.f.{:08x}",
        isolated_core::state::stable_hash(folder_key) as u32
    )
}

/// Identity of an app box: fixed per box, so its folders persist across
/// runs whatever program is started in it.
pub fn box_container_name(box_name: &str) -> String {
    let clean: String = box_name
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(24)
        .collect();
    format!(
        "Isolated.box.{}.{:08x}",
        clean,
        isolated_core::state::stable_hash(&box_name.trim().to_lowercase()) as u32
    )
}

/// Deletes an AppContainer profile and its storage folder.
pub fn delete(name: &str) -> Result<(), String> {
    let w = Wide::new(name);
    unsafe { DeleteAppContainerProfile(w.pcwstr()) }.map_err(|e| err("could not remove the box's storage", e))
}

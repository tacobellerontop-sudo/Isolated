//! Temporary file-system grants to a sandbox SID, recorded in a journal so
//! they are always removed, even after a crash.

use super::util::{win32_err, LocalBox, Wide};
use isolated_core::state::{Access, Dirs, JournalEntry};
use std::path::Path;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows::Win32::Storage::FileSystem::{DELETE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE};

fn access_mask(a: Access) -> u32 {
    match a {
        Access::Read => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        Access::Write | Access::RegistryCreate => {
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0 | FILE_GENERIC_WRITE.0 | DELETE.0
        }
    }
}

fn modify(
    path: &Path,
    sid: PSID,
    mode: windows::Win32::Security::Authorization::ACCESS_MODE,
    mask: u32,
) -> Result<(), String> {
    let wpath = Wide::new(path.as_os_str());
    let inherit: ACE_FLAGS = if path.is_dir() {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    unsafe {
        let mut old_dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetNamedSecurityInfoW(
            wpath.pcwstr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_dacl),
            None,
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(win32_err(
                &format!("could not read permissions of {}", path.display()),
                rc,
            ));
        }
        let _sd = LocalBox(sd.0);
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: mode,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0 as *mut u16),
            },
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(&[ea]), Some(old_dacl), &mut new_dacl);
        if rc != ERROR_SUCCESS {
            return Err(win32_err("could not build new permissions", rc));
        }
        let _new = LocalBox(new_dacl as *mut _);
        let rc = SetNamedSecurityInfoW(
            wpath.pcwstr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl),
            None,
        );
        if rc != ERROR_SUCCESS {
            return Err(win32_err(
                &format!("could not change permissions of {}", path.display()),
                rc,
            ));
        }
    }
    Ok(())
}

pub fn grant(path: &Path, sid: PSID, access: Access) -> Result<(), String> {
    if access == Access::RegistryCreate {
        return super::reg::grant_create(&path.to_string_lossy(), sid);
    }
    modify(path, sid, GRANT_ACCESS, access_mask(access))
}

pub fn revoke(path: &Path, sid: PSID) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    modify(path, sid, REVOKE_ACCESS, 0)
}

/// A SID parsed from its string form, freed on drop.
pub struct StringSid(pub PSID);

impl StringSid {
    pub fn parse(s: &str) -> Result<StringSid, String> {
        let w = Wide::new(s);
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(w.pcwstr(), &mut sid).map_err(|e| super::util::err("bad SID in journal", e))?;
        }
        Ok(StringSid(sid))
    }
}

impl Drop for StringSid {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

/// True if another live sandbox with the same SID still needs this path.
pub fn still_needed(dirs: &Dirs, me: &str, sid: &str, path: &str) -> bool {
    JournalEntry::list(dirs).iter().any(|j| {
        j.sandbox_id != me
            && j.sid == sid
            && super::util::is_process_alive(j.watcher_pid)
            && j.grants.iter().any(|g| g.path == path)
    })
}

/// Revokes every grant in a journal entry (skipping ones another live
/// sandbox still uses) and deletes the entry.
pub fn revoke_entry(dirs: &Dirs, entry: &JournalEntry) -> Result<(), String> {
    let sid = StringSid::parse(&entry.sid)?;
    let mut first_err = None;
    for g in &entry.grants {
        if still_needed(dirs, &entry.sandbox_id, &entry.sid, &g.path) {
            continue;
        }
        let r = if g.access == Access::RegistryCreate {
            super::reg::revoke_create(&g.path, sid.0)
        } else {
            revoke(Path::new(&g.path), sid.0)
        };
        if let Err(e) = r {
            first_err.get_or_insert(e);
        }
    }
    match first_err {
        None => {
            JournalEntry::remove(dirs, &entry.sandbox_id);
            Ok(())
        }
        Some(e) => Err(e),
    }
}

pub fn replay_journal(dirs: &Dirs) -> Result<usize, String> {
    let mut n = 0;
    let mut last_err = None;
    for entry in JournalEntry::list(dirs) {
        if super::util::is_process_alive(entry.watcher_pid) {
            continue;
        }
        match revoke_entry(dirs, &entry) {
            Ok(()) => n += 1,
            Err(e) => last_err = Some(e),
        }
        isolated_core::state::RunningEntry::remove(dirs, &entry.sandbox_id);
    }
    match last_err {
        Some(e) if n == 0 => Err(e),
        _ => Ok(n),
    }
}

/// Lets every sandboxed app read the attributes (not the contents) of one
/// folder, without touching anything inside it. Node, Electron and other
/// runtimes look at each folder above a file when they resolve its real path,
/// and an AppContainer can't even do that for `C:\` or the user folder.
/// Windows grants the same right to Store apps on many system folders.
/// Returns true if the folder was changed (or, with `check_only`, needs to be).
///
/// This uses SetFileSecurityW on purpose: SetNamedSecurityInfo would walk
/// every file below the folder, which for `C:\` is the whole drive.
pub fn allow_attribute_read(path: &Path, check_only: bool) -> Result<bool, String> {
    use windows::Win32::Security::{
        EqualSid, GetAce, GetSecurityDescriptorControl, InitializeSecurityDescriptor, SetFileSecurityW,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, SECURITY_DESCRIPTOR,
        SECURITY_DESCRIPTOR_CONTROL, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED,
    };
    use windows::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    const ALLOWED: u8 = 0; // ACCESS_ALLOWED_ACE_TYPE
    let packages = StringSid::parse("S-1-15-2-1")?;
    let wpath = Wide::new(path.as_os_str());
    unsafe {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetNamedSecurityInfoW(
            wpath.pcwstr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(win32_err(
                &format!("could not read permissions of {}", path.display()),
                rc,
            ));
        }
        let _sd = LocalBox(sd.0);
        if dacl.is_null() {
            return Ok(false); // no DACL: everyone already has full access
        }
        for i in 0..(*dacl).AceCount as u32 {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace).is_err() {
                continue;
            }
            let ace = ace as *const ACCESS_ALLOWED_ACE;
            if (*ace).Header.AceType == ALLOWED
                && (*ace).Mask & FILE_READ_ATTRIBUTES.0 != 0
                && EqualSid(PSID(&(*ace).SidStart as *const u32 as *mut _), packages.0).is_ok()
            {
                return Ok(false);
            }
        }
        if check_only {
            return Ok(true);
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_READ_ATTRIBUTES.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(packages.0 .0 as *mut u16),
            },
        };
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(&[ea]), Some(dacl), &mut new_dacl);
        if rc != ERROR_SUCCESS {
            return Err(win32_err("could not build new permissions", rc));
        }
        let _new = LocalBox(new_dacl as *mut _);
        let mut control = 0u16;
        let mut revision = 0u32;
        let _ = GetSecurityDescriptorControl(sd, &mut control, &mut revision);
        let mut fresh = SECURITY_DESCRIPTOR::default();
        let fresh_sd = PSECURITY_DESCRIPTOR(&mut fresh as *mut _ as *mut _);
        InitializeSecurityDescriptor(fresh_sd, 1).map_err(|e| super::util::err("could not build permissions", e))?;
        SetSecurityDescriptorDacl(fresh_sd, true, Some(new_dacl), false)
            .map_err(|e| super::util::err("could not build permissions", e))?;
        let keep = SECURITY_DESCRIPTOR_CONTROL(SE_DACL_PROTECTED.0 | SE_DACL_AUTO_INHERITED.0);
        let _ = SetSecurityDescriptorControl(fresh_sd, keep, SECURITY_DESCRIPTOR_CONTROL(control & keep.0));
        if !SetFileSecurityW(wpath.pcwstr(), DACL_SECURITY_INFORMATION, fresh_sd).as_bool() {
            return Err(super::util::err(
                &format!("could not change permissions of {}", path.display()),
                windows::core::Error::from_thread(),
            ));
        }
    }
    Ok(true)
}

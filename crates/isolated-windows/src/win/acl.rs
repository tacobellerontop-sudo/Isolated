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
        Access::Write => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0 | FILE_GENERIC_WRITE.0 | DELETE.0,
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
        if let Err(e) = revoke(Path::new(&g.path), sid.0) {
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

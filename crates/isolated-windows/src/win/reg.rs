//! The one registry grant Isolated makes: while an installer runs in a box,
//! its sandbox may create new keys under the user's uninstall key, because
//! installers such as Inno Setup stop if they cannot register themselves.
//!
//! Existing keys are never opened up: the grant is set with
//! `RegSetKeySecurity`, which does not propagate to existing subkeys, and the
//! inheritable part applies only to keys created afterwards. When the grant
//! is revoked, every subkey carrying the sandbox's SID (the ones the
//! installer created) is deleted, so no uninstall entry pointing into a box
//! is left where Windows Settings could run it outside the sandbox.

use super::util::{win32_err, Wide};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS, TRUSTEE_IS_SID,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::{
    EqualSid, GetAce, GetSecurityDescriptorDacl, InitializeSecurityDescriptor, SetSecurityDescriptorDacl, ACE_FLAGS,
    ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegEnumKeyExW, RegGetKeySecurity, RegOpenKeyExW, RegSetKeySecurity,
    HKEY, HKEY_CURRENT_USER, KEY_ALL_ACCESS, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS,
};

/// The key installers register uninstall entries under, relative to HKCU.
pub const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

fn strip_root(path: &str) -> &str {
    path.strip_prefix(r"HKCU\").unwrap_or(path)
}

fn open(path: &str, access: u32, create: bool) -> Result<Key, String> {
    let w = Wide::new(strip_root(path));
    let mut hk = HKEY::default();
    let rc = unsafe {
        if create {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                w.pcwstr(),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                REG_SAM_FLAGS(access),
                None,
                &mut hk,
                None,
            )
        } else {
            RegOpenKeyExW(HKEY_CURRENT_USER, w.pcwstr(), None, REG_SAM_FLAGS(access), &mut hk)
        }
    };
    if rc != ERROR_SUCCESS {
        return Err(win32_err(&format!(r"could not open HKCU\{}", strip_root(path)), rc));
    }
    Ok(Key(hk))
}

/// The key's security descriptor (self-relative).
fn get_dacl_sd(key: &Key) -> Result<Vec<u8>, String> {
    let mut size = 0u32;
    unsafe {
        let rc = RegGetKeySecurity(key.0, DACL_SECURITY_INFORMATION, None, &mut size);
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return Err(win32_err("could not read registry permissions", rc));
        }
        let mut buf = vec![0u8; size as usize];
        let rc = RegGetKeySecurity(
            key.0,
            DACL_SECURITY_INFORMATION,
            Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut _)),
            &mut size,
        );
        if rc != ERROR_SUCCESS {
            return Err(win32_err("could not read registry permissions", rc));
        }
        Ok(buf)
    }
}

fn dacl_of(sd: &mut [u8]) -> Result<*mut ACL, String> {
    let mut present = Default::default();
    let mut defaulted = Default::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(sd.as_mut_ptr() as *mut _),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
        .map_err(|e| super::util::err("could not read registry permissions", e))?;
    }
    Ok(dacl)
}

fn trustee(sid: PSID) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
        ptstrName: PWSTR(sid.0 as *mut u16),
    }
}

/// Applies `entries` to the key's DACL, without touching existing subkeys.
fn set_entries(key: &Key, entries: &[EXPLICIT_ACCESS_W]) -> Result<(), String> {
    let mut sd = get_dacl_sd(key)?;
    let old = dacl_of(&mut sd)?;
    unsafe {
        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(entries), Some(old), &mut new_dacl);
        if rc != ERROR_SUCCESS {
            return Err(win32_err("could not build registry permissions", rc));
        }
        let _free = super::util::LocalBox(new_dacl as *mut _);
        let mut abs: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let psd = PSECURITY_DESCRIPTOR(&mut abs as *mut _ as *mut _);
        InitializeSecurityDescriptor(psd, 1).map_err(|e| super::util::err("could not set registry permissions", e))?;
        SetSecurityDescriptorDacl(psd, true, Some(new_dacl), false)
            .map_err(|e| super::util::err("could not set registry permissions", e))?;
        let rc = RegSetKeySecurity(key.0, DACL_SECURITY_INFORMATION, psd);
        if rc != ERROR_SUCCESS {
            return Err(win32_err("could not set registry permissions", rc));
        }
    }
    Ok(())
}

/// Lets `sid` create new subkeys of `path` (and use the keys it creates).
pub fn grant_create(path: &str, sid: PSID) -> Result<(), String> {
    let key = open(path, READ_CONTROL | WRITE_DAC, true)?;
    let entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEY_CREATE_SUB_KEY.0 | KEY_READ.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee(sid),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEY_ALL_ACCESS.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | INHERIT_ONLY_ACE.0),
            Trustee: trustee(sid),
        },
    ];
    set_entries(&key, &entries)
}

/// True if the key's DACL has an allow entry for `sid`.
fn has_sid(key: &Key, sid: PSID) -> bool {
    let Ok(mut sd) = get_dacl_sd(key) else { return false };
    let Ok(dacl) = dacl_of(&mut sd) else { return false };
    if dacl.is_null() {
        return false;
    }
    unsafe {
        for i in 0..(*dacl).AceCount as u32 {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace).is_err() {
                continue;
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            // ACCESS_ALLOWED_ACE: header (4 bytes), mask (4 bytes), SID.
            let ace_sid = PSID((ace as *mut u8).add(8) as *mut _);
            if EqualSid(ace_sid, sid).is_ok() {
                return true;
            }
        }
    }
    false
}

/// Deletes the subkeys `sid` created, then removes its entries from `path`.
pub fn revoke_create(path: &str, sid: PSID) -> Result<(), String> {
    let key = match open(
        path,
        READ_CONTROL | WRITE_DAC | KEY_ENUMERATE_SUB_KEYS.0 | KEY_QUERY_VALUE.0,
        false,
    ) {
        Ok(k) => k,
        Err(_) => return Ok(()),
    };
    let mut created = Vec::new();
    let mut i = 0u32;
    loop {
        let mut name = vec![0u16; 512];
        let mut len = name.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                i,
                Some(PWSTR(name.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        i += 1;
        if rc != ERROR_SUCCESS {
            continue;
        }
        let sub = String::from_utf16_lossy(&name[..len as usize]);
        if let Ok(k) = open(&format!(r"{}\{sub}", strip_root(path)), READ_CONTROL, false) {
            if has_sid(&k, sid) {
                created.push(sub);
            }
        }
    }
    let mut first_err = None;
    for sub in created {
        let w = Wide::new(&sub);
        let rc = unsafe { RegDeleteTreeW(key.0, PCWSTR(w.0.as_ptr())) };
        if rc != ERROR_SUCCESS {
            first_err.get_or_insert(win32_err(&format!("could not remove the uninstall entry {sub}"), rc));
        }
    }
    let revoke = [EXPLICIT_ACCESS_W {
        grfAccessPermissions: 0,
        grfAccessMode: REVOKE_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: trustee(sid),
    }];
    set_entries(&key, &revoke)?;
    first_err.map_or(Ok(()), Err)
}

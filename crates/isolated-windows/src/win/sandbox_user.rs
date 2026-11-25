//! The hidden sandbox user. Apps in a "Works with more apps" (compatible)
//! container can read whatever the signed-in user can. Running them as a
//! separate, hidden standard Windows account instead puts the user's own
//! folder and settings out of their reach, enforced by Windows itself, with
//! no driver.
//!
//! Setting it up needs administrator rights once (creating an account).
//! Its password is random, never shown, and kept encrypted for the signed-in
//! user with DPAPI. Launches go through the Secondary Logon service
//! (`CreateProcessWithLogonW`), which any user may call; the started copy of
//! Isolated then applies the usual low-integrity sandbox as that account.

use super::acl;
use super::util::{err, OwnedHandle, Wide};
use crate::Result;
use isolated_core::state::{Access, Dirs};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
use windows::Win32::System::Threading::{
    CreateProcessWithLogonW, CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTUPINFOW,
};

/// The account's name. Hidden from the sign-in screen.
pub const ACCOUNT: &str = crate::sandbox_user::ACCOUNT;

const HIDE_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

fn secret_path(dirs: &Dirs) -> PathBuf {
    dirs.data.join("sandbox-user.bin")
}

/// True when the account exists and this user holds its password.
pub fn ready(dirs: &Dirs) -> bool {
    secret_path(dirs).is_file() && sid().is_ok()
}

/// The account's SID, as a string.
pub fn sid() -> Result<String> {
    let name = Wide::new(ACCOUNT);
    let mut sid = vec![0u8; 256];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            name.pcwstr(),
            Some(PSID(sid.as_mut_ptr() as *mut c_void)),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
        .map_err(|e| err("the sandbox user doesn't exist", e))?;
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(PSID(sid.as_mut_ptr() as *mut c_void), &mut s)
            .map_err(|e| err("could not read the sandbox user's SID", e))?;
        let out = s.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
        Ok(out)
    }
}

fn random_password() -> Result<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!#%+=";
    let mut buf = [0u8; 32];
    unsafe {
        BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            .ok()
            .map_err(|e| err("could not make a password", e))?;
    }
    // Starts with one of each kind, for password rules that ask for them.
    let mut p = String::from("Aa1!");
    p.extend(buf.iter().map(|b| CHARS[*b as usize % CHARS.len()] as char));
    Ok(p)
}

fn protect(data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        if encrypt {
            CryptProtectData(&input, PCWSTR::null(), None, None, None, 0, &mut output)
                .map_err(|e| err("could not encrypt the sandbox user's password", e))?;
        } else {
            CryptUnprotectData(&input, None, None, None, None, 0, &mut output)
                .map_err(|e| err("could not read the sandbox user's password", e))?;
        }
        let out = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut c_void)));
        Ok(out)
    }
}

fn password(dirs: &Dirs) -> Result<String> {
    let enc = std::fs::read(secret_path(dirs)).map_err(|e| format!("the sandbox user isn't set up: {e}"))?;
    String::from_utf8(protect(&enc, false)?).map_err(|_| "the sandbox user's password is damaged".into())
}

/// Creates the account (or gives it a new password) and hides it. Needs
/// administrator rights; `Err` starting with "access" means they are missing.
pub fn setup(dirs: &Dirs) -> Result<()> {
    use windows::Win32::NetworkManagement::NetManagement::{
        NetUserAdd, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD, UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1,
        USER_INFO_1003, USER_PRIV_USER,
    };
    const NERR_USER_EXISTS: u32 = 2224;
    const ACCESS_DENIED: u32 = 5;
    let pw = random_password()?;
    let mut wname = Wide::new(ACCOUNT);
    let mut wpw = Wide::new(&pw);
    let mut comment = Wide::new("Runs apps from Isolated containers set to \"Works with more apps\".");
    let info = USER_INFO_1 {
        usri1_name: wname.pwstr(),
        usri1_password: wpw.pwstr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: PWSTR::null(),
        usri1_comment: comment.pwstr(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: PWSTR::null(),
    };
    let mut rc = unsafe { NetUserAdd(PCWSTR::null(), 1, &info as *const _ as *const u8, None) };
    if rc == NERR_USER_EXISTS {
        let pinfo = USER_INFO_1003 {
            usri1003_password: wpw.pwstr(),
        };
        rc = unsafe {
            NetUserSetInfo(
                PCWSTR::null(),
                wname.pcwstr(),
                1003,
                &pinfo as *const _ as *const u8,
                None,
            )
        };
    }
    if rc == ACCESS_DENIED {
        return Err("access denied: setting up the sandbox user needs administrator rights".into());
    }
    if rc != 0 {
        return Err(format!("could not create the sandbox user (error {rc})"));
    }
    hide(true);
    std::fs::create_dir_all(&dirs.data).map_err(|e| e.to_string())?;
    std::fs::write(secret_path(dirs), protect(pw.as_bytes(), true)?).map_err(|e| e.to_string())?;
    Ok(())
}

/// Deletes the account and its user folder. Needs administrator rights.
pub fn remove(dirs: &Dirs) -> Result<()> {
    use windows::Win32::NetworkManagement::NetManagement::NetUserDel;
    let sid = sid().ok();
    let name = Wide::new(ACCOUNT);
    let rc = unsafe { NetUserDel(PCWSTR::null(), name.pcwstr()) };
    if rc == 5 {
        return Err("access denied: removing the sandbox user needs administrator rights".into());
    }
    if rc != 0 && rc != 2221 {
        return Err(format!("could not remove the sandbox user (error {rc})"));
    }
    if let Some(sid) = sid {
        let w = Wide::new(&sid);
        unsafe {
            let _ = windows::Win32::UI::Shell::DeleteProfileW(w.pcwstr(), PCWSTR::null(), PCWSTR::null());
        }
    }
    hide(false);
    let _ = std::fs::remove_file(secret_path(dirs));
    Ok(())
}

fn hide(on: bool) {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_OPTION_NON_VOLATILE,
    };
    let key = Wide::new(HIDE_KEY);
    let value = Wide::new(ACCOUNT);
    unsafe {
        let mut h = HKEY::default();
        if RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key.pcwstr(),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut h,
            None,
        )
        .is_ok()
        {
            if on {
                let zero = 0u32.to_le_bytes();
                let _ = RegSetValueExW(h, value.pcwstr(), None, REG_DWORD, Some(&zero));
            } else {
                let _ = RegDeleteValueW(h, value.pcwstr());
            }
            let _ = RegCloseKey(h);
        }
    }
}

/// Lets the sandbox user use a box's folder (once per box) and run this
/// copy of Isolated.
pub fn grant(base: &Path, sid: &str) -> Result<()> {
    let s = acl::StringSid::parse(sid)?;
    let mark = base.join(".sandbox-user");
    if std::fs::read_to_string(&mark).ok().as_deref() != Some(sid) {
        acl::grant(base, s.0, Access::Write)?;
        let _ = std::fs::write(&mark, sid);
    }
    if let Ok(exe) = std::env::current_exe() {
        acl::grant(&exe, s.0, Access::Read)?;
    }
    Ok(())
}

/// Starts `exe args` as the sandbox user, in `cwd`, with that account's
/// own environment and user folder.
pub fn spawn(dirs: &Dirs, exe: &Path, command_line: &str, cwd: &Path) -> Result<(OwnedHandle, u32)> {
    let pw = password(dirs)?;
    let user = Wide::new(ACCOUNT);
    let domain = Wide::new(".");
    let wpw = Wide::new(&pw);
    let app = Wide::new(exe.as_os_str());
    let mut cmd = Wide::new(command_line);
    let wcwd = Wide::new(cwd.as_os_str());
    unsafe {
        let mut si: STARTUPINFOW = zeroed();
        si.cb = size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = zeroed();
        CreateProcessWithLogonW(
            user.pcwstr(),
            domain.pcwstr(),
            wpw.pcwstr(),
            LOGON_WITH_PROFILE,
            app.pcwstr(),
            Some(cmd.pwstr()),
            CREATE_UNICODE_ENVIRONMENT,
            None,
            wcwd.pcwstr(),
            &si,
            &mut pi,
        )
        .map_err(|e| err("could not start the app as the sandbox user", e))?;
        drop(OwnedHandle(pi.hThread));
        Ok((OwnedHandle(pi.hProcess), pi.dwProcessId))
    }
}

/// The signed-in user's SID, as a string.
pub fn current_user_sid() -> Result<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut tok = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).map_err(|e| err("could not open the token", e))?;
        let tok = OwnedHandle(tok);
        let mut buf = [0u8; 256];
        let mut needed = 0u32;
        GetTokenInformation(
            tok.raw(),
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            buf.len() as u32,
            &mut needed,
        )
        .map_err(|e| err("could not read the token", e))?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s).map_err(|e| err("could not read the user's SID", e))?;
        let out = s.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
        Ok(out)
    }
}

/// Lets `sid` (the signed-in user) stop and query a job the sandbox user
/// created, so Isolated's window can stop the app.
pub fn allow_on_job(job: windows::Win32::Foundation::HANDLE, sid: &str) -> Result<()> {
    use windows::Win32::Security::Authorization::{
        GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE,
        SE_KERNEL_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR};
    const JOB_OBJECT_ALL_ACCESS: u32 = 0x1F003F;
    let s = acl::StringSid::parse(sid)?;
    unsafe {
        let mut old: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetSecurityInfo(
            job,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old),
            None,
            Some(&mut sd),
        );
        if rc.0 != 0 {
            return Err(format!("could not read the job's permissions (error {})", rc.0));
        }
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: JOB_OBJECT_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(s.0 .0 as *mut u16),
            },
        };
        let mut new: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(&[ea]), Some(old), &mut new);
        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if rc.0 != 0 {
            return Err(format!("could not change the job's permissions (error {})", rc.0));
        }
        let rc = SetSecurityInfo(
            job,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new),
            None,
        );
        let _ = LocalFree(Some(HLOCAL(new as *mut c_void)));
        if rc.0 != 0 {
            return Err(format!("could not change the job's permissions (error {})", rc.0));
        }
    }
    Ok(())
}

//! Wide strings, owned handles, and other small helpers.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, STILL_ACTIVE};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

/// A NUL-terminated UTF-16 string.
pub struct Wide(pub Vec<u16>);

impl Wide {
    pub fn new(s: impl AsRef<OsStr>) -> Wide {
        Wide(s.as_ref().encode_wide().chain(std::iter::once(0)).collect())
    }
    pub fn pcwstr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }
    pub fn pwstr(&mut self) -> PWSTR {
        PWSTR(self.0.as_mut_ptr())
    }
}

/// Reads a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point to a valid NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

pub fn from_wide_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// A kernel handle closed on drop.
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0 .0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// Handles are plain kernel references; moving them between threads is fine.
unsafe impl Send for OwnedHandle {}

/// Memory freed with `LocalFree` on drop.
pub struct LocalBox(pub *mut core::ffi::c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let h = OwnedHandle(h);
        let mut code = 0u32;
        GetExitCodeProcess(h.raw(), &mut code).is_ok() && code == STILL_ACTIVE.0 as u32
    }
}

/// Connects to the parent's console if there is one. Returns true if output
/// has somewhere to go: an attached console, or redirected standard handles
/// (for example `isolated ps > list.txt`, or a script capturing output).
pub fn attach_console() -> bool {
    let has = |h: STD_HANDLE| unsafe {
        GetStdHandle(h)
            .map(|h| !h.is_invalid() && !h.0.is_null())
            .unwrap_or(false)
    };
    if has(STD_OUTPUT_HANDLE) || has(STD_ERROR_HANDLE) {
        return true;
    }
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS).is_ok() }
}

/// Formats a Windows error for users.
pub fn err(context: &str, e: windows::core::Error) -> String {
    format!("{context}: {}", e.message().trim())
}

pub fn win32_err(context: &str, code: windows::Win32::Foundation::WIN32_ERROR) -> String {
    err(context, windows::core::Error::from(code.to_hresult()))
}

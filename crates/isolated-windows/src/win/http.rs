//! Minimal HTTPS GET over WinHTTP, which uses the system's TLS, proxy
//! settings and certificate store, so the updater adds no dependencies.

use super::util::{err, Wide};
use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::*;

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn check(h: *mut c_void, what: &str) -> Result<Handle, String> {
    if h.is_null() {
        Err(err(what, windows::core::Error::from_thread()))
    } else {
        Ok(Handle(h))
    }
}

/// Fetches `url`, calling `on_chunk` with each piece of the body and
/// `(received, total)` progress. Follows redirects. Fails on non-2xx status.
pub fn get(
    url: &str,
    headers: &[(&str, &str)],
    mut on_chunk: impl FnMut(&[u8], u64, Option<u64>) -> Result<(), String>,
) -> Result<(), String> {
    let wurl = Wide::new(url);
    unsafe {
        let mut comps: URL_COMPONENTS = std::mem::zeroed();
        comps.dwStructSize = std::mem::size_of::<URL_COMPONENTS>() as u32;
        comps.dwHostNameLength = u32::MAX;
        comps.dwUrlPathLength = u32::MAX;
        comps.dwExtraInfoLength = u32::MAX;
        WinHttpCrackUrl(&wurl.0[..wurl.0.len() - 1], 0, &mut comps).map_err(|e| err("bad update URL", e))?;
        if comps.nScheme != WINHTTP_INTERNET_SCHEME_HTTPS {
            return Err("updates are only downloaded over HTTPS".into());
        }
        let host = String::from_utf16_lossy(std::slice::from_raw_parts(
            comps.lpszHostName.0,
            comps.dwHostNameLength as usize,
        ));
        let mut path = String::from_utf16_lossy(std::slice::from_raw_parts(
            comps.lpszUrlPath.0,
            comps.dwUrlPathLength as usize,
        ));
        if comps.dwExtraInfoLength > 0 {
            path.push_str(&String::from_utf16_lossy(std::slice::from_raw_parts(
                comps.lpszExtraInfo.0,
                comps.dwExtraInfoLength as usize,
            )));
        }

        let agent = Wide::new(format!("Isolated/{}", isolated_core::version::CURRENT));
        let session = check(
            WinHttpOpen(
                agent.pcwstr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                0,
            ),
            "could not start an internet session",
        )?;
        let whost = Wide::new(&host);
        let conn = check(
            WinHttpConnect(session.0, whost.pcwstr(), comps.nPort, 0),
            "could not connect",
        )?;
        let wpath = Wide::new(&path);
        let verb = Wide::new("GET");
        let req = check(
            WinHttpOpenRequest(
                conn.0,
                verb.pcwstr(),
                wpath.pcwstr(),
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                WINHTTP_FLAG_SECURE,
            ),
            "could not create the request",
        )?;
        let mut hdr = String::new();
        for (k, v) in headers {
            hdr.push_str(&format!("{k}: {v}\r\n"));
        }
        let whdr: Vec<u16> = hdr.encode_utf16().collect();
        WinHttpSendRequest(req.0, if whdr.is_empty() { None } else { Some(&whdr) }, None, 0, 0, 0)
            .map_err(|e| err("could not reach the update server", e))?;
        WinHttpReceiveResponse(req.0, std::ptr::null_mut())
            .map_err(|e| err("no response from the update server", e))?;

        let mut status = 0u32;
        let mut size = 4u32;
        WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut c_void),
            &mut size,
            std::ptr::null_mut(),
        )
        .map_err(|e| err("could not read the response", e))?;
        if !(200..300).contains(&status) {
            return Err(format!("the update server answered with HTTP {status}"));
        }
        let mut total = 0u64;
        let mut tsize = 8u32;
        let total = WinHttpQueryHeaders(
            req.0,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER64,
            PCWSTR::null(),
            Some(&mut total as *mut u64 as *mut c_void),
            &mut tsize,
            std::ptr::null_mut(),
        )
        .ok()
        .map(|_| total);

        let mut received = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(req.0, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut read)
                .map_err(|e| err("the download was interrupted", e))?;
            if read == 0 {
                break;
            }
            received += read as u64;
            on_chunk(&buf[..read as usize], received, total)?;
        }
        Ok(())
    }
}

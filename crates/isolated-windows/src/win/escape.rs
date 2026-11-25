//! Warns when a program in a sandbox gets another program started outside
//! it. That happens when users approve an administrator prompt: Windows
//! starts the elevated program from a system service, outside the sandbox's
//! job and token, with full rights. No user-mode sandbox can keep it in, so
//! Isolated tells users right away.

use super::shell::message_box;
use super::util::OwnedHandle;
use crate::shell::Icon;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::JobObjects::{
    JobObjectBasicProcessIdList, QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
};

/// Helpers Windows starts for any program; never worth a warning.
const IGNORE: &[&str] = &["conhost.exe", "werfault.exe", "werfaultsecure.exe", "wermgr.exe"];

/// How long a sandboxed process id is remembered after it exits, so a
/// program started just before its parent quit is still caught, while a
/// reused id soon stops counting.
const REMEMBER: Duration = Duration::from_secs(15);

pub struct Watch {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watch {
    /// Watches the job until [`Watch::stop`]. `label` names the sandboxed
    /// program in the warning.
    /// Each warning is also added to `log`.
    pub fn start(job: HANDLE, label: String, log: std::path::PathBuf) -> Watch {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let job = job.0 as isize;
        let thread = std::thread::spawn(move || run(HANDLE(job as *mut c_void), &label, &log, &flag));
        Watch {
            stop,
            thread: Some(thread),
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn job_pids(job: HANDLE) -> Vec<u32> {
    let mut buf = vec![0usize; 2 + 1024];
    unsafe {
        if QueryInformationJobObject(
            Some(job),
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * size_of::<usize>()) as u32,
            None,
        )
        .is_err()
        {
            return Vec::new();
        }
        let list = &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST);
        let n = (list.NumberOfProcessIdsInList as usize).min(1024);
        std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), n)
            .iter()
            .map(|p| *p as u32)
            .collect()
    }
}

/// (pid, parent pid, exe name) of every process.
fn processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let snap = OwnedHandle(snap);
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap.raw(), &mut e).is_ok();
        while ok {
            let len = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
            out.push((
                e.th32ProcessID,
                e.th32ParentProcessID,
                String::from_utf16_lossy(&e.szExeFile[..len]),
            ));
            ok = Process32NextW(snap.raw(), &mut e).is_ok();
        }
    }
    out
}

fn run(job: HANDLE, label: &str, log: &std::path::Path, stop: &AtomicBool) {
    let mut seen: HashMap<u32, Instant> = HashMap::new();
    let mut warned: HashSet<u32> = HashSet::new();
    // Processes that existed before the sandbox started are never its children.
    let before: HashSet<u32> = processes().iter().map(|p| p.0).collect();
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        let inside: HashSet<u32> = job_pids(job).into_iter().collect();
        for pid in &inside {
            seen.insert(*pid, now);
        }
        seen.retain(|pid, t| inside.contains(pid) || now.duration_since(*t) < REMEMBER);
        for (pid, parent, name) in processes() {
            if inside.contains(&pid)
                || before.contains(&pid)
                || warned.contains(&pid)
                || !seen.contains_key(&parent)
                || IGNORE.iter().any(|i| name.eq_ignore_ascii_case(i))
            {
                continue;
            }
            // The job list was read before the snapshot, so a child started
            // in between looks outside; ask Windows about this process.
            if in_job(pid, job) {
                continue;
            }
            warned.insert(pid);
            let detail = describe(pid);
            let text = format!(
                "{label} (in a sandbox) got {name} started outside the sandbox, most likely through an administrator prompt.\n\n\
                 {name} is not isolated: it can see and change your PC, with administrator rights if you approved them. \
                 If you didn't expect this, close it.\n\nTo avoid this, answer No to administrator prompts that come from \
                 sandboxed apps."
            );
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
                use std::io::Write;
                let _ = writeln!(
                    f,
                    "{label} -> {name} (pid {pid}, parent {parent}) started outside the sandbox: {detail}"
                );
            }
            eprintln!("Warning: {label} got {name} started outside the sandbox.");
            std::thread::spawn(move || message_box("Isolated: a program left the sandbox", &text, Icon::Warning));
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

/// Path and integrity level of a process, for the log.
fn describe(pid: u32) -> String {
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let Ok(p) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return "gone or not readable".into();
        };
        let p = OwnedHandle(p);
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let path = if QueryFullProcessImageNameW(
            p.raw(),
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok()
        {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            "?".into()
        };
        let mut level = String::from("?");
        let mut tok = HANDLE::default();
        if OpenProcessToken(p.raw(), TOKEN_QUERY, &mut tok).is_ok() {
            let tok = OwnedHandle(tok);
            let mut info = [0u8; 256];
            let mut needed = 0u32;
            if GetTokenInformation(
                tok.raw(),
                TokenIntegrityLevel,
                Some(info.as_mut_ptr() as *mut c_void),
                info.len() as u32,
                &mut needed,
            )
            .is_ok()
            {
                let label = &*(info.as_ptr() as *const TOKEN_MANDATORY_LABEL);
                let count = *GetSidSubAuthorityCount(label.Label.Sid);
                if count > 0 {
                    level = format!("{:#x}", *GetSidSubAuthority(label.Label.Sid, count as u32 - 1));
                }
            }
        }
        format!("{path}, integrity {level}")
    }
}

/// True if the process is in the job, or is gone (nothing to warn about).
fn in_job(pid: u32, job: HANDLE) -> bool {
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let Ok(p) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return true;
        };
        let p = OwnedHandle(p);
        let mut result = windows::core::BOOL(0);
        IsProcessInJob(p.raw(), Some(job), &mut result).is_err() || result.as_bool()
    }
}

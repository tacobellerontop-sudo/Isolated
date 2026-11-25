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
            warned.insert(pid);
            let text = format!(
                "{label} (in a sandbox) got {name} started outside the sandbox, most likely through an administrator prompt.\n\n\
                 {name} is not isolated: it can see and change your PC, with administrator rights if you approved them. \
                 If you didn't expect this, close it.\n\nTo avoid this, answer No to administrator prompts that come from \
                 sandboxed apps."
            );
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
                use std::io::Write;
                let _ = writeln!(f, "{label} -> {name} (pid {pid}) started outside the sandbox");
            }
            eprintln!("Warning: {label} got {name} started outside the sandbox.");
            std::thread::spawn(move || message_box("Isolated: a program left the sandbox", &text, Icon::Warning));
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

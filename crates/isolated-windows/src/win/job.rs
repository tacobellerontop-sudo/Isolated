//! Job Objects: every process in a sandbox lives in one job, which carries
//! the resource limits and UI restrictions and lets the watcher know when
//! the last process has exited.

use super::util::{err, OwnedHandle, Wide};
use crate::Stats;
use isolated_core::Policy;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::JobObjects::*;
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{OpenProcess, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ};
use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED};

pub struct Job {
    pub handle: OwnedHandle,
    port: OwnedHandle,
}

const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
const JOB_OBJECT_QUERY: u32 = 0x4;
const JOB_OBJECT_TERMINATE: u32 = 0x8;

const PORT_KEY: usize = 0x150_1A7E;

unsafe fn set<T>(job: HANDLE, class: JOBOBJECTINFOCLASS, info: &T) -> windows::core::Result<()> {
    SetInformationJobObject(job, class, info as *const T as *const c_void, size_of::<T>() as u32)
}

impl Job {
    pub fn create(name: &str, policy: &Policy) -> Result<Job, String> {
        let wname = Wide::new(name);
        unsafe {
            let h = CreateJobObjectW(None, wname.pcwstr()).map_err(|e| err("could not create the sandbox job", e))?;
            let handle = OwnedHandle(h);

            let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if policy.resources.max_processes > 0 {
                flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                ext.BasicLimitInformation.ActiveProcessLimit = policy.resources.max_processes;
            }
            if let Some(bytes) = policy.memory_max_bytes() {
                flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                ext.JobMemoryLimit = bytes as usize;
            }
            ext.BasicLimitInformation.LimitFlags = flags;
            set(h, JobObjectExtendedLimitInformation, &ext).map_err(|e| err("could not set sandbox limits", e))?;

            let mut ui = JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
            if !policy.devices.clipboard.can_read() {
                ui |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
            }
            if !policy.devices.clipboard.can_write() {
                ui |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
            }
            let uir = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                UIRestrictionsClass: ui,
            };
            set(h, JobObjectBasicUIRestrictions, &uir).map_err(|e| err("could not set sandbox UI restrictions", e))?;

            if policy.resources.cpu_percent < 100 {
                let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = zeroed();
                cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
                cpu.Anonymous.CpuRate = policy.resources.cpu_percent.clamp(1, 100) * 100;
                set(h, JobObjectCpuRateControlInformation, &cpu).map_err(|e| err("could not set the CPU limit", e))?;
            }

            let port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1)
                .map_err(|e| err("could not create a completion port", e))?;
            let port = OwnedHandle(port);
            let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: PORT_KEY as *mut c_void,
                CompletionPort: port.raw(),
            };
            set(h, JobObjectAssociateCompletionPortInformation, &assoc)
                .map_err(|e| err("could not watch the sandbox job", e))?;

            Ok(Job { handle, port })
        }
    }

    /// Blocks until no process is left in the job.
    pub fn wait_empty(&self) {
        loop {
            let mut msg = 0u32;
            let mut key = 0usize;
            let mut ov: *mut OVERLAPPED = std::ptr::null_mut();
            let ok = unsafe { GetQueuedCompletionStatus(self.port.raw(), &mut msg, &mut key, &mut ov, INFINITE) };
            if ok.is_err() {
                // The port failed; fall back to polling the process count.
                while active_processes(self.handle.raw()) > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                return;
            }
            if key == PORT_KEY && msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
                return;
            }
        }
    }
}

fn active_processes(job: HANDLE) -> u32 {
    unsafe {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
        if QueryInformationJobObject(
            Some(job),
            JobObjectBasicAccountingInformation,
            &mut info as *mut _ as *mut c_void,
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .is_err()
        {
            return 0;
        }
        info.ActiveProcesses
    }
}

fn open_named(name: &str, access: u32) -> Option<OwnedHandle> {
    let w = Wide::new(name);
    unsafe { OpenJobObjectW(access, false, w.pcwstr()).ok().map(OwnedHandle) }
}

pub fn terminate_named(name: &str) -> Result<(), String> {
    let h = open_named(name, JOB_OBJECT_TERMINATE).ok_or("the sandbox has already stopped")?;
    unsafe { TerminateJobObject(h.raw(), 1).map_err(|e| err("could not stop the sandbox", e)) }
}

pub fn stats_named(name: &str) -> Option<Stats> {
    let h = open_named(name, JOB_OBJECT_QUERY)?;
    unsafe {
        let mut acct: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
        QueryInformationJobObject(
            Some(h.raw()),
            JobObjectBasicAccountingInformation,
            &mut acct as *mut _ as *mut c_void,
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .ok()?;
        // Room for 256 process ids after the two counters.
        let mut buf = vec![0usize; 2 + 256];
        let mut memory = 0u64;
        if QueryInformationJobObject(
            Some(h.raw()),
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr() as *mut c_void,
            (buf.len() * size_of::<usize>()) as u32,
            None,
        )
        .is_ok()
        {
            let list = &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST);
            let count = list.NumberOfProcessIdsInList as usize;
            let ids = std::slice::from_raw_parts(list.ProcessIdList.as_ptr(), count.min(256));
            for &pid in ids {
                if let Ok(p) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid as u32) {
                    let p = OwnedHandle(p);
                    let mut pmc: PROCESS_MEMORY_COUNTERS = zeroed();
                    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
                    if K32GetProcessMemoryInfo(p.raw(), &mut pmc, pmc.cb).as_bool() {
                        memory += pmc.WorkingSetSize as u64;
                    }
                }
            }
        }
        Some(Stats {
            processes: acct.ActiveProcesses,
            memory_bytes: memory,
            cpu_ms: ((acct.TotalUserTime + acct.TotalKernelTime) / 10_000) as u64,
        })
    }
}

//! Starting a sandbox: AppContainer (or restricted token), Job Object, ACL
//! grants, private folders, environment, and `CreateProcess`.

use super::acl;
use super::appcontainer::{self, Capabilities, ContainerSid};
use super::job::Job;
use super::marker::{self, Marker};
use super::shell;
use super::util::{err, OwnedHandle, Wide};
use crate::{LaunchRequest, Result};
use isolated_core::cmdline::{self, TargetKind};
use isolated_core::profile::{expand_path, normalize_path_key};
use isolated_core::state::{new_sandbox_id, now_unix, Access, Dirs, Grant, JournalEntry, RunningEntry};
use isolated_core::{Gap, NetworkMode, Policy, Severity, Tier};
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateRestrictedToken, GetLengthSid, SetTokenInformation, TokenIntegrityLevel, DISABLE_MAX_PRIVILEGE, PSID,
    SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Threading::*;

/// `PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON`: a heap
/// corruption ends the process instead of continuing.
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_INTEGRITY: u32 = 0x20;

const MITIGATION_HEAP_TERMINATE: u64 = 0x1 << 12;
/// `PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON`.
const MITIGATION_BOTTOM_UP_ASLR: u64 = 0x1 << 16;

/// What the backend cannot enforce for a policy.
pub fn gaps(policy: &Policy) -> Vec<Gap> {
    let mut g = Vec::new();
    match policy.tier {
        Tier::Isolated => {
            match policy.network.mode {
                NetworkMode::Loopback => g.push(Gap::notice(
                    "Loopback-only network is not available yet; the app will have no network.",
                )),
                NetworkMode::Allowlist => g.push(Gap::notice(
                    "Host allowlists are not available yet; the app will have no network.",
                )),
                _ => {}
            }
            if !policy.process.see_other_processes {
                g.push(Gap::notice(
                    "The app can still see the names of other running programs, but cannot read or control them.",
                ));
            }
        }
        Tier::Compatible => {
            if policy.network.mode != NetworkMode::Full {
                g.push(Gap::weaker("The compatible tier cannot block the network."));
            }
            g.push(Gap::notice(
                "In the compatible tier the app can read your files. It can only change files in its private folders.",
            ));
            if !policy.folder.trim().is_empty() {
                g.push(Gap::weaker(
                    "The compatible tier cannot keep an app to its isolated folder: it could read your other files and could not change the folder.",
                ));
            }
            if !policy.filesystem.read_write.is_empty() {
                g.push(Gap::notice(
                    "Read-write folders are not available in the compatible tier yet.",
                ));
            }
            if !policy.devices.microphone || !policy.devices.camera {
                g.push(Gap::notice(
                    "The compatible tier cannot block the microphone or camera.",
                ));
            }
        }
    }
    if policy.ui.separate_desktop {
        g.push(Gap::weaker("Running on a separate desktop is not available yet."));
    }
    if !policy.devices.gpu {
        g.push(Gap::weaker("Blocking GPU access is not supported."));
    }
    if policy.devices.printers {
        g.push(Gap::notice("Printing may not work inside the sandbox."));
    }
    if policy.ui.mark_windows {
        g.push(Gap::notice(
            "Colored borders on sandboxed windows are not available yet.",
        ));
    }
    g
}

/// The thing to start, after resolving shortcuts and scripts.
struct Prepared {
    /// File the program (or script) lives in: used for identity and grants.
    program: PathBuf,
    /// Full command line.
    command_line: String,
    /// Explicit application path for `CreateProcess`.
    application: Option<PathBuf>,
    /// Working directory requested by a shortcut, if any.
    workdir: Option<PathBuf>,
}

/// Removes the `\\?\` prefix `canonicalize` adds, when it is safe to.
fn simplify(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        if rest.len() < 260 && rest.as_bytes().get(1) == Some(&b':') {
            return PathBuf::from(rest);
        }
    }
    p
}

fn canonical(p: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(p)
        .map(simplify)
        .map_err(|e| format!("{}: {}", p.display(), e))
}

fn system_dir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
}

fn prepare(target: &Path, args: &[String], depth: u32, installer: bool) -> Result<Prepared> {
    let target = canonical(target)?;
    let ts = target.to_string_lossy().to_string();
    match cmdline::classify(&ts) {
        TargetKind::Executable => Ok(Prepared {
            command_line: cmdline::join(&ts, args),
            application: Some(target.clone()),
            program: target,
            workdir: None,
        }),
        TargetKind::BatchScript => {
            let cmd = system_dir().join("cmd.exe");
            Ok(Prepared {
                command_line: cmdline::batch_command_line(&cmd.to_string_lossy(), &ts, args),
                application: Some(cmd),
                program: target,
                workdir: None,
            })
        }
        TargetKind::PowerShellScript => {
            let ps = system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe");
            let mut all = vec![
                "-NoProfile".to_string(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-File".into(),
                ts.clone(),
            ];
            all.extend(args.iter().cloned());
            Ok(Prepared {
                command_line: cmdline::join(&ps.to_string_lossy(), &all),
                application: Some(ps),
                program: target,
                workdir: None,
            })
        }
        TargetKind::Shortcut => {
            if depth > 2 {
                return Err("This shortcut points to another shortcut too many times.".into());
            }
            let link = shell::resolve_shortcut(&target)?;
            if link.target.as_os_str().is_empty() {
                return Err("This shortcut does not point to a program file (it may be a store app or a web link).".into());
            }
            let mut all = split_args(&link.arguments);
            all.extend(args.iter().cloned());
            let mut p = prepare(&link.target, &all, depth + 1, installer)?;
            if p.workdir.is_none() && !link.workdir.as_os_str().is_empty() {
                p.workdir = Some(link.workdir);
            }
            Ok(p)
        }
        TargetKind::Installer if installer && ts.to_ascii_lowercase().ends_with(".msi") => Err(
            "Isolated unpacks .msi files itself instead of running them. Use Install in Isolated.".into(),
        ),
        TargetKind::Installer if installer => Err(
            "Store app packages (.msix, .appx) cannot be installed in a sandbox. Use the app's regular installer (.exe or .msi)."
                .into(),
        ),
        TargetKind::Installer => Err(
            "This is an installer. Use Install in Isolated instead, which installs the app into a box you can run it from later."
                .into(),
        ),
        TargetKind::Unsupported => Err(format!(
            "Isolated can run programs (.exe), shortcuts (.lnk), and scripts (.bat, .cmd, .ps1). '{}' is none of these.",
            target.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
        )),
    }
}

/// Splits a shortcut's argument string the way programs usually do.
pub fn split_args(s: &str) -> Vec<String> {
    cmdline::split(s)
}

fn home_dir() -> PathBuf {
    shell::known_folder(shell::KnownFolder::Profile)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_default()
}

fn under(p: &Path, base: &Path) -> bool {
    let p = normalize_path_key(&p.to_string_lossy());
    let b = normalize_path_key(&base.to_string_lossy());
    !b.is_empty() && (p == b || p.starts_with(&format!("{b}\\")))
}

/// Refuses grants that would be far too broad or slow.
fn check_grant(p: &Path, access: Access) -> Result<()> {
    let home = home_dir();
    let comps = p.components().count();
    if comps <= 2 && p.to_string_lossy().len() <= 3 || p.parent().is_none() {
        return Err(format!(
            "Refusing to give a sandbox access to a whole drive ({}).",
            p.display()
        ));
    }
    if !home.as_os_str().is_empty() && (under(&home, p)) {
        return Err(format!(
            "Refusing to give a sandbox access to {} because it contains your whole user folder. Pick a specific folder instead.",
            p.display()
        ));
    }
    if access == Access::Write {
        for var in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"] {
            if let Some(v) = std::env::var_os(var) {
                if under(p, Path::new(&v)) {
                    return Err(format!(
                        "Refusing to let a sandbox change system files in {}.",
                        p.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Folders every AppContainer can already read.
fn readable_by_all_apps(p: &Path) -> bool {
    ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(std::env::var_os)
        .any(|v| under(p, Path::new(&v)))
}

/// The grant that lets the program read itself: its folder, or only the file
/// when it sits in a shared folder such as Downloads or the Desktop.
fn program_grant(program: &Path) -> Option<PathBuf> {
    if readable_by_all_apps(program) {
        return None;
    }
    let folder = program.parent()?.to_path_buf();
    let shared = [
        shell::KnownFolder::Downloads,
        shell::KnownFolder::Desktop,
        shell::KnownFolder::Documents,
        shell::KnownFolder::Profile,
    ]
    .into_iter()
    .filter_map(shell::known_folder)
    .chain(std::env::var_os("TEMP").map(PathBuf::from))
    .chain(std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("OneDrive")))
    .any(|k| normalize_path_key(&k.to_string_lossy()) == normalize_path_key(&folder.to_string_lossy()));
    let is_root = folder.parent().is_none();
    if shared || is_root {
        Some(program.to_path_buf())
    } else {
        Some(folder)
    }
}

/// Checks a folder users want to share before the sandbox starts.
pub fn check_shared_folder(raw: &str, write: bool) -> Result<()> {
    let expanded = expand_path(raw, &home_dir(), env_var);
    let p = canonical(&expanded).map_err(|_| format!("The folder '{raw}' does not exist."))?;
    check_grant(&p, if write { Access::Write } else { Access::Read })
}

fn env_var(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// The profile's isolated folder, checked: it must exist and be specific
/// enough to hand over for reading and writing.
fn isolated_folder(policy: &Policy) -> Result<Option<PathBuf>> {
    if policy.folder.trim().is_empty() {
        return Ok(None);
    }
    let expanded = expand_path(&policy.folder, &home_dir(), env_var);
    let p = canonical(&expanded).map_err(|_| format!("The isolated folder '{}' does not exist.", policy.folder))?;
    if !p.is_dir() {
        return Err(format!("The isolated folder '{}' is not a folder.", policy.folder));
    }
    check_grant(&p, Access::Write)?;
    Ok(Some(p))
}

/// Checks that a folder can be isolated (all its programs get to read and
/// change it).
pub fn check_isolated_folder(raw: &str) -> Result<()> {
    let p = Policy {
        folder: raw.to_string(),
        ..Default::default()
    };
    isolated_folder(&p).map(|_| ())
}

/// Builds the grant list for an AppContainer sandbox.
fn grants_for(policy: &Policy, program: &Path) -> Result<Vec<Grant>> {
    let home = home_dir();
    let mut out: Vec<Grant> = Vec::new();
    let push = |p: PathBuf, access: Access, out: &mut Vec<Grant>| {
        let s = p.to_string_lossy().to_string();
        if let Some(g) = out
            .iter_mut()
            .find(|g| normalize_path_key(&g.path) == normalize_path_key(&s))
        {
            if access == Access::Write {
                g.access = Access::Write;
            }
        } else {
            out.push(Grant { path: s, access });
        }
    };
    let folder = isolated_folder(policy)?;
    if let Some(f) = &folder {
        push(f.clone(), Access::Write, &mut out);
    }
    if policy.filesystem.program_folder {
        if let Some(p) = program_grant(program) {
            // Programs inside the isolated folder can already read themselves.
            if !folder.as_ref().is_some_and(|f| under(&p, f)) {
                push(p, Access::Read, &mut out);
            }
        }
    }
    for (list, access) in [
        (&policy.filesystem.read_only, Access::Read),
        (&policy.filesystem.read_write, Access::Write),
    ] {
        for raw in list {
            let expanded = expand_path(raw, &home, env_var);
            let p = canonical(&expanded).map_err(|_| format!("The folder '{raw}' in this profile does not exist."))?;
            check_grant(&p, access)?;
            push(p, access, &mut out);
        }
    }
    Ok(out)
}

/// Variables every program expects; others are dropped unless the profile
/// passes them.
const BASE_ENV: &[&str] = &[
    "ALLUSERSPROFILE",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "COMPUTERNAME",
    "ComSpec",
    "DriverData",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "Path",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "PSModulePath",
    "PUBLIC",
    "SystemDrive",
    "SystemRoot",
    "USERDOMAIN",
    "USERNAME",
    "windir",
    "LANG",
    "TZ",
];

const HOME_ENV: &[&str] = &[
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "OneDrive",
];

/// Folders a box gives its apps in place of the PC's shared ones.
struct BoxEnv<'a> {
    /// The box's base folder (what its apps see as LocalAppData).
    base: &'a Path,
    /// Where installers in the box put programs.
    programs: PathBuf,
    installer: bool,
}

fn build_env(
    policy: &Policy,
    home: Option<&Path>,
    temp: Option<&Path>,
    installer: bool,
    in_box: Option<&BoxEnv>,
) -> Vec<u16> {
    let appcontainer = policy.tier == Tier::Isolated;
    // Keys compare case-insensitively on Windows.
    let mut env: BTreeMap<String, (String, String)> = BTreeMap::new();
    let set = |k: &str, v: String, env: &mut BTreeMap<String, (String, String)>| {
        env.insert(k.to_uppercase(), (k.to_string(), v));
    };
    let current: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let wanted = |k: &str| {
        BASE_ENV.iter().any(|b| b.eq_ignore_ascii_case(k))
            || policy.env.pass.iter().any(|b| b.eq_ignore_ascii_case(k))
            || (home.is_none() && HOME_ENV.iter().any(|b| b.eq_ignore_ascii_case(k)))
    };
    for (k, v) in &current {
        if wanted(k) {
            set(k, v.clone(), &mut env);
        }
    }
    if let Some(h) = home {
        let home = h.to_string_lossy().to_string();
        set("USERPROFILE", home.clone(), &mut env);
        // Command-line tools (Git, SSH, many AI and developer CLIs) look at
        // HOME first: keep their dotfolders (.cache, .config, ...) inside.
        set("HOME", home.clone(), &mut env);
        set("APPDATA", h.join(r"AppData\Roaming").to_string_lossy().into(), &mut env);
        // Windows rewrites LOCALAPPDATA for AppContainer processes to
        // `<value>\Packages\<container>\AC`. Passing the real value makes it
        // the container's own folder, which exists and is writable.
        let local = match std::env::var("LOCALAPPDATA").ok().filter(|_| appcontainer) {
            Some(real) => real,
            None => h.join(r"AppData\Local").to_string_lossy().into(),
        };
        set("LOCALAPPDATA", local, &mut env);
        if home.len() > 2 && home.as_bytes()[1] == b':' {
            set("HOMEDRIVE", home[..2].to_string(), &mut env);
            set("HOMEPATH", home[2..].to_string(), &mut env);
        }
    }
    if !appcontainer && !installer {
        // WebView2 apps (Tauri and others) start Edge's engine themselves.
        set("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--no-sandbox".into(), &mut env);
    }
    if let Some(p) = temp {
        set("TEMP", p.to_string_lossy().into(), &mut env);
        set("TMP", p.to_string_lossy().into(), &mut env);
    }
    if let Some(b) = in_box {
        // Like Sandboxie and App-V, give apps in a box their own copy of the
        // folders shared by all users: the real ones are read-only to a
        // sandbox, and installers that write there would fail.
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        set("ProgramData", s(b.base.join("ProgramData")), &mut env);
        set("ALLUSERSPROFILE", s(b.base.join("ProgramData")), &mut env);
        set("PUBLIC", s(b.base.join(r"Users\Public")), &mut env);
        if b.installer {
            // Installers that build paths from these install into the box.
            for k in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
                set(k, s(b.programs.clone()), &mut env);
            }
            for k in ["CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432"] {
                set(k, s(b.programs.join("Common Files")), &mut env);
            }
        }
    }
    set("ISOLATED_SANDBOX", "1".into(), &mut env);
    // Start programs that ask for administrator rights without them instead
    // of showing an administrator prompt: what users approve there would run
    // outside the sandbox. Most installers then install for the current
    // user only. (Sandboxie gets the same effect by hiding installer
    // detection.)
    set("__COMPAT_LAYER", "RunAsInvoker".into(), &mut env);
    for (k, v) in &policy.env.set {
        set(k, v.clone(), &mut env);
    }
    let mut block: Vec<u16> = Vec::new();
    for (_, (k, v)) in env {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

struct PrivateDirs {
    home: PathBuf,
    temp: PathBuf,
}

fn make_private_dirs(base: &Path, with_home: bool) -> Result<PrivateDirs> {
    let home = base.join("Home");
    let temp = base.join("Temp");
    let mut dirs = vec![temp.clone()];
    if with_home {
        // Inside an AppContainer, Windows puts the LocalAppData and LocalLow
        // known folders at <user folder>\AppData\Local\Packages\<container>\AC
        // and fails with "path not found" when that is missing. Apps such as
        // Unity games quit at startup without them, so it exists up front.
        let is_container_folder = base.file_name().is_some_and(|n| n.eq_ignore_ascii_case("AC"));
        if let Some(container) = base.parent().and_then(Path::file_name).filter(|_| is_container_folder) {
            dirs.push(home.join(r"AppData\Local\Packages").join(container).join("AC"));
        }
        // Start menu and Programs folders exist up front so installers that
        // look them up find them inside the sandbox.
        dirs.push(home.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
        dirs.push(home.join(r"AppData\Local\Programs"));
        dirs.push(base.join("Programs"));
        // Box copies of the folders shared by all users (see build_env).
        dirs.push(base.join(r"ProgramData\Microsoft\Windows\Start Menu\Programs"));
        dirs.push(base.join(r"Users\Public\Desktop"));
        dirs.push(base.join(r"Users\Public\Documents"));
        dirs.push(home.join("Documents"));
        dirs.push(home.join("Downloads"));
        dirs.push(home.join("Desktop"));
    }
    for d in dirs {
        std::fs::create_dir_all(&d).map_err(|e| format!("could not create the sandbox folder {}: {e}", d.display()))?;
    }
    Ok(PrivateDirs { home, temp })
}

/// A proc-thread attribute list with its backing memory.
struct AttrList {
    buf: Vec<u8>,
}

impl AttrList {
    fn new(count: u32) -> Result<AttrList> {
        unsafe {
            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(None, count, None, &mut size);
            let mut buf = vec![0u8; size];
            InitializeProcThreadAttributeList(
                Some(LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut c_void)),
                count,
                None,
                &mut size,
            )
            .map_err(|e| err("could not prepare process attributes", e))?;
            Ok(AttrList { buf })
        }
    }

    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buf.as_mut_ptr() as *mut c_void)
    }

    /// # Safety
    /// `value` must stay alive and unmoved until the process is created.
    unsafe fn set<T>(&mut self, attr: u32, value: *const T) -> Result<()> {
        UpdateProcThreadAttribute(
            self.ptr(),
            0,
            attr as usize,
            Some(value as *const c_void),
            size_of::<T>(),
            None,
            None,
        )
        .map_err(|e| err("could not set a process attribute", e))
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.ptr()) }
    }
}

/// A running sandbox, owned by its watcher.
pub struct Running {
    id: String,
    app_pid: u32,
    /// `None` when the app runs as the sandbox user: the copy of Isolated
    /// started as that user owns the job and watches it.
    job: Option<Job>,
    process: OwnedHandle,
    dirs: Dirs,
    journal: Option<JournalEntry>,
    /// The program's file name, for messages.
    label: String,
    marker: Option<Marker>,
}

impl Running {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn app_pid(&self) -> u32 {
        self.app_pid
    }

    pub fn wait(self) -> Result<u32> {
        match &self.job {
            Some(job) => {
                let escapes = super::escape::Watch::start(
                    job.handle.raw(),
                    self.label.clone(),
                    self.dirs.data.join("escapes.log"),
                );
                job.wait_empty();
                escapes.stop();
            }
            None => unsafe {
                let _ = WaitForSingleObject(self.process.raw(), INFINITE);
            },
        }
        if let Some(m) = self.marker {
            m.stop();
        }
        let mut code = 0u32;
        unsafe {
            let _ = GetExitCodeProcess(self.process.raw(), &mut code);
        }
        let mut result = Ok(code);
        if let Some(j) = &self.journal {
            if let Err(e) = acl::revoke_entry(&self.dirs, j) {
                result = Err(format!(
                    "The app exited, but Isolated could not remove its folder access: {e}. Use Repair in Settings."
                ));
            }
        }
        RunningEntry::remove(&self.dirs, &self.id);
        result
    }
}

/// Set in the copy of Isolated that runs as the sandbox user: where the
/// boxes are (the signed-in user's LocalLow), since its own LocalLow differs.
static COMPAT_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
/// Also set there: the sandbox id the signed-in user's Isolated recorded,
/// and that user's SID, who may stop the job.
static INNER_ID: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// True if launches for this policy go through the sandbox user.
pub fn uses_sandbox_user(dirs: &Dirs, policy: &Policy) -> bool {
    policy.tier == Tier::Compatible && COMPAT_ROOT.get().is_none() && super::sandbox_user::ready(dirs)
}

/// What the copy of Isolated started as the sandbox user is asked to run.
#[derive(serde::Serialize, serde::Deserialize)]
struct InnerRequest {
    policy: Policy,
    profile_name: String,
    target: PathBuf,
    args: Vec<String>,
    accept_weaker: bool,
    app_box: String,
    installer: bool,
    raw_tail: String,
    workdir: Option<PathBuf>,
    /// Where boxes live: the signed-in user's `LocalLow\Isolated`.
    root: PathBuf,
    kept_folders: Vec<String>,
    settings: isolated_core::Settings,
    id: String,
    owner_sid: String,
}

/// Starts a box's app as the hidden sandbox user: a copy of Isolated runs as
/// that account and starts the app in the usual low-integrity sandbox.
fn launch_as_sandbox_user(dirs: &Dirs, policy: &Policy, req: &LaunchRequest, box_name: &str) -> Result<Running> {
    let base = box_folder(policy, box_name)?;
    let id = new_sandbox_id();
    let sid = super::sandbox_user::sid()?;
    super::sandbox_user::grant(&base, &sid)?;
    // The sandbox user can't read the signed-in user's folders, so an
    // installer from Downloads is copied into the box first.
    let mut target = req.target.clone();
    if req.installer {
        let stage = base.join("Setup");
        let _ = std::fs::create_dir_all(&stage);
        if let Some(name) = target.file_name() {
            let copy = stage.join(name);
            std::fs::copy(&target, &copy).map_err(|e| format!("could not copy {}: {e}", target.display()))?;
            target = copy;
        }
    }
    let inner = InnerRequest {
        policy: policy.clone(),
        profile_name: req.profile_name.clone(),
        target: target.clone(),
        args: req.args.clone(),
        accept_weaker: req.accept_weaker,
        app_box: box_name.to_string(),
        installer: req.installer,
        raw_tail: req.raw_tail.clone(),
        workdir: req.workdir.clone(),
        root: base.parent().map(Path::to_path_buf).unwrap_or_default(),
        kept_folders: isolated_core::boxes::AppBox::load(dirs, box_name)
            .map(|b| b.kept_folders)
            .unwrap_or_default(),
        settings: isolated_core::Settings::load(dirs),
        id: id.clone(),
        owner_sid: super::sandbox_user::current_user_sid()?,
    };
    let file = base.join(format!("launch-{id}.json"));
    std::fs::write(&file, serde_json::to_vec(&inner).map_err(|e| e.to_string())?)
        .map_err(|e| format!("could not write {}: {e}", file.display()))?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let command_line = format!("\"{}\" __sandbox-user-run \"{}\"", exe.display(), file.display());
    let (process, pid) = super::sandbox_user::spawn(dirs, &exe, &command_line, &base)?;
    let entry = RunningEntry {
        id: id.clone(),
        profile: req.profile_name.clone(),
        program: target.to_string_lossy().into(),
        watcher_pid: std::process::id(),
        app_pid: pid,
        started: now_unix(),
        container: appcontainer::box_container_name(box_name),
        job_name: format!("Local\\Isolated-{id}"),
    };
    let _ = entry.save(dirs);
    Ok(Running {
        id,
        app_pid: pid,
        job: None,
        process,
        dirs: dirs.clone(),
        journal: None,
        label: file_name_of(&target),
        marker: None,
    })
}

/// Runs in the copy of Isolated started as the sandbox user: starts the app
/// described in `file` and returns its exit code once all of it has ended.
pub fn run_as_sandbox_user(file: &Path) -> Result<u32> {
    let text = std::fs::read(file).map_err(|e| format!("could not read {}: {e}", file.display()))?;
    let _ = std::fs::remove_file(file);
    let r: InnerRequest = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
    let _ = COMPAT_ROOT.set(r.root.clone());
    let _ = INNER_ID.set((r.id.clone(), r.owner_sid.clone()));
    let dirs = Dirs::standard();
    let _ = r.settings.save(&dirs);
    // Kept folders are the sandbox user's own (its %USERPROFILE%).
    let b = isolated_core::boxes::AppBox {
        name: r.app_box.clone(),
        kept_folders: r.kept_folders.clone(),
        ..Default::default()
    };
    for note in crate::boxes::keep_folders(&r.policy, &b) {
        let text = note.clone();
        std::thread::spawn(move || shell::message_box("Isolated", &text, crate::shell::Icon::Warning));
    }
    let req = LaunchRequest {
        profile_name: r.profile_name,
        target: r.target,
        args: r.args,
        accept_weaker: r.accept_weaker,
        app_box: Some(r.app_box),
        installer: r.installer,
        raw_tail: r.raw_tail,
        workdir: r.workdir,
    };
    let result = launch(&dirs, &r.policy, &req).and_then(|run| run.wait());
    crate::boxes::release_folders(&b);
    result
}

pub fn launch(dirs: &Dirs, policy: &Policy, req: &LaunchRequest) -> Result<Running> {
    if let Some(b) = &req.app_box {
        if uses_sandbox_user(dirs, policy) {
            return launch_as_sandbox_user(dirs, policy, req, b);
        }
    }
    let weaker: Vec<String> = gaps(policy)
        .into_iter()
        .filter(|g| g.severity == Severity::Weaker)
        .map(|g| g.message)
        .collect();
    if !weaker.is_empty() && !req.accept_weaker {
        return Err(format!(
            "The sandbox would be weaker than the profile asks:\n{}",
            weaker.join("\n")
        ));
    }

    let mut prepared = prepare(&req.target, &req.args, 0, req.installer)?;
    if policy.tier == Tier::Isolated
        && !req.installer
        && matches!(
            isolated_core::apps::engine(&prepared.program),
            isolated_core::apps::Engine::Chromium | isolated_core::apps::Engine::Steam
        )
    {
        return Err(format!(
            "{} is built on web technology (Chromium or WebView2, like Electron apps, Steam and Kryoto), which \
             Windows doesn't let start in a locked-down container. Install it into a container set to \
             \"Works with more apps\" (the compatible profile) instead; what it saves still stays in that container.",
            file_name_of(&prepared.program)
        ));
    }
    if policy.tier == Tier::Compatible && !req.installer && prepared.application.as_ref() == Some(&prepared.program) {
        // Chromium's own sandbox can't start under a low-integrity token.
        let mut args = isolated_core::apps::own_sandbox_off_args(&prepared.program);
        if !args.is_empty() && !req.args.iter().any(|a| args.contains(a)) {
            args.extend(req.args.iter().cloned());
            prepared = prepare(&req.target, &args, 0, req.installer)?;
        }
    }
    if !req.raw_tail.is_empty() {
        prepared.command_line.push(' ');
        prepared.command_line.push_str(&req.raw_tail);
    }
    let program_key = normalize_path_key(&prepared.program.to_string_lossy());
    let id = INNER_ID.get().map(|(id, _)| id.clone()).unwrap_or_else(new_sandbox_id);
    let job_name = format!("Local\\Isolated-{id}");
    // All programs of an isolated folder share one identity, so they keep
    // the same settings and can start each other.
    let container_name = match &req.app_box {
        Some(b) => appcontainer::box_container_name(b),
        None if !policy.folder.trim().is_empty() => {
            appcontainer::folder_container_name(&normalize_path_key(&policy.folder))
        }
        None => appcontainer::container_name(&req.profile_name, &program_key),
    };
    // A box always keeps its own user folders: that is where apps install.
    let private_home = policy.filesystem.private_home || req.app_box.is_some();

    // Identity, grants and private folders.
    let mut container: Option<ContainerSid> = None;
    let mut caps = Capabilities::default();
    let mut journal: Option<JournalEntry> = None;
    let private: Option<PrivateDirs>;
    match policy.tier {
        Tier::Isolated => {
            let display = format!("Isolated: {}", req.profile_name);
            let c = appcontainer::create_or_open(&container_name, &display)?;
            if policy.network.mode == NetworkMode::Full {
                caps.add("internetClient")?;
                caps.add("privateNetworkClientServer")?;
            }
            if policy.devices.microphone {
                caps.add("microphone")?;
            }
            if policy.devices.camera {
                caps.add("webcam")?;
            }
            let base = c.folder()?;
            private = Some(make_private_dirs(&base, private_home)?);
            // The container already owns its folder; never grant inside it.
            let mut grants: Vec<Grant> = grants_for(policy, &prepared.program)?
                .into_iter()
                .filter(|g| !under(Path::new(&g.path), &base))
                .collect();
            if req.installer && req.app_box.is_some() {
                // Installers stop if they cannot register an uninstall
                // entry. Allow creating new ones; they are deleted when the
                // installer exits.
                grants.push(Grant {
                    path: format!(r"HKCU\{}", super::reg::UNINSTALL_KEY),
                    access: Access::RegistryCreate,
                });
            }
            if !grants.is_empty() {
                let entry = JournalEntry {
                    sandbox_id: id.clone(),
                    watcher_pid: std::process::id(),
                    sid: c.to_string_sid(),
                    grants,
                };
                entry
                    .save(dirs)
                    .map_err(|e| format!("could not write the cleanup journal: {e}"))?;
                for g in &entry.grants {
                    if let Err(e) = acl::grant(Path::new(&g.path), c.sid, g.access) {
                        let _ = acl::revoke_entry(dirs, &entry);
                        return Err(e);
                    }
                }
                journal = Some(entry);
            }
            container = Some(c);
        }
        Tier::Compatible => {
            // Low-integrity processes can write only to LocalLow.
            let base = compatible_base(&container_name)?;
            private = Some(make_private_dirs(&base, private_home)?);
        }
    }

    let cleanup_on_error = |e: String| -> String {
        if let Some(j) = &journal {
            let _ = acl::revoke_entry(dirs, j);
        }
        e
    };

    let home = private.as_ref().filter(|_| private_home).map(|p| p.home.as_path());
    let box_base = private.as_ref().and_then(|p| p.home.parent()).map(Path::to_path_buf);
    let box_env = match (&req.app_box, &box_base) {
        (Some(_), Some(base)) => Some(BoxEnv {
            base,
            programs: box_install_dir(policy, base, "x")
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| base.join("Programs")),
            installer: req.installer,
        }),
        _ => None,
    };
    let env = build_env(
        policy,
        home,
        private.as_ref().map(|p| p.temp.as_path()),
        req.installer,
        box_env.as_ref(),
    );
    // Also set here: some Windows versions read it from the caller.
    std::env::set_var("__COMPAT_LAYER", "RunAsInvoker");

    let job = Job::create(&job_name, policy).map_err(cleanup_on_error)?;
    if let Some((_, owner)) = INNER_ID.get() {
        // Running as the sandbox user: let the signed-in user's Isolated
        // window stop and measure the app.
        let _ = super::sandbox_user::allow_on_job(job.handle.raw(), owner);
    }

    let cwd = req
        .workdir
        .clone()
        .filter(|d| d.is_dir())
        .or_else(|| prepared.workdir.clone().filter(|d| d.is_dir()))
        .or_else(|| match program_grant(&prepared.program) {
            Some(g) if g.is_dir() => Some(g),
            None => prepared.program.parent().map(Path::to_path_buf),
            _ => None,
        })
        .or_else(|| private.as_ref().map(|p| p.temp.clone()))
        .unwrap_or_else(|| PathBuf::from(r"C:\"));

    if container.is_some() {
        // Node, Electron and others look at every folder above their files.
        crate::compat::prepare_user();
    }
    let spawn = || -> Result<(OwnedHandle, u32)> {
        unsafe {
            let mut attrs = AttrList::new(3)?;
            let job_handle: HANDLE = job.handle.raw();
            attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle)?;
            let mitigation: u64 = MITIGATION_HEAP_TERMINATE | MITIGATION_BOTTOM_UP_ASLR;
            attrs.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigation)?;

            let mut cap_attrs: Vec<SID_AND_ATTRIBUTES> = caps
                .sids
                .iter()
                .map(|s| SID_AND_ATTRIBUTES {
                    Sid: *s,
                    Attributes: SE_GROUP_ENABLED,
                })
                .collect();
            let sc;
            if let Some(c) = &container {
                sc = SECURITY_CAPABILITIES {
                    AppContainerSid: c.sid,
                    Capabilities: if cap_attrs.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        cap_attrs.as_mut_ptr()
                    },
                    CapabilityCount: cap_attrs.len() as u32,
                    Reserved: 0,
                };
                attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc)?;
            }

            let mut si: STARTUPINFOEXW = zeroed();
            si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            si.lpAttributeList = attrs.ptr();
            let mut pi: PROCESS_INFORMATION = zeroed();
            let app = prepared.application.as_ref().map(|a| Wide::new(a.as_os_str()));
            let app_ptr = app.as_ref().map(|a| a.pcwstr()).unwrap_or(PCWSTR::null());
            let mut cmd = Wide::new(&prepared.command_line);
            let wcwd = Wide::new(cwd.as_os_str());
            let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;

            let created = if policy.tier == Tier::Compatible {
                let token = low_integrity_token()?;
                CreateProcessAsUserW(
                    Some(token.raw()),
                    app_ptr,
                    Some(cmd.pwstr()),
                    None,
                    None,
                    false,
                    flags,
                    Some(env.as_ptr() as *const c_void),
                    wcwd.pcwstr(),
                    &si.StartupInfo,
                    &mut pi,
                )
            } else {
                CreateProcessW(
                    app_ptr,
                    Some(cmd.pwstr()),
                    None,
                    None,
                    false,
                    flags,
                    Some(env.as_ptr() as *const c_void),
                    wcwd.pcwstr(),
                    &si.StartupInfo,
                    &mut pi,
                )
            };
            created.map_err(|e| {
                if e.code() == windows::Win32::Foundation::ERROR_ELEVATION_REQUIRED.to_hresult() {
                    format!(
                        "{} asks for administrator rights, which a sandbox cannot give. If it is an installer, right-click it and choose Install in Isolated.",
                        file_name_of(&prepared.program)
                    )
                } else {
                    err(&format!("could not start {}", prepared.program.display()), e)
                }
            })?;
            drop(OwnedHandle(pi.hThread));
            Ok((OwnedHandle(pi.hProcess), pi.dwProcessId))
        }
    };
    let (process, app_pid) = spawn().map_err(cleanup_on_error)?;

    let entry = RunningEntry {
        id: id.clone(),
        profile: req.profile_name.clone(),
        program: prepared.program.to_string_lossy().into(),
        watcher_pid: std::process::id(),
        app_pid,
        started: now_unix(),
        container: container_name,
        job_name,
    };
    let _ = entry.save(dirs);

    let marker = start_marker(dirs, policy, req, &job);

    Ok(Running {
        id,
        app_pid,
        job: Some(job),
        process,
        dirs: dirs.clone(),
        journal,
        label: file_name_of(&prepared.program),
        marker,
    })
}

/// Starts marking the sandbox's windows as the settings ask.
fn start_marker(dirs: &Dirs, policy: &Policy, req: &LaunchRequest, job: &Job) -> Option<Marker> {
    let settings = isolated_core::Settings::load(dirs);
    let label = match &req.app_box {
        Some(b) => Some(b.clone()),
        None if !policy.folder.trim().is_empty() => Path::new(policy.folder.trim())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
        None => None,
    };
    let opts = marker::Options {
        frame: settings
            .window_frame
            .then(|| isolated_core::marker::frame_color(&settings.window_frame_color)),
        tag: settings
            .window_title_tag
            .then(|| isolated_core::marker::title_tag(label.as_deref())),
    };
    marker::trace(format_args!("start {opts:?}"));
    Marker::start(job.handle.raw(), opts)
}

fn file_name_of(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// Private folder of a compatible-tier sandbox. Low-integrity processes can
/// write only under LocalLow.
pub fn compatible_base(container_name: &str) -> Result<PathBuf> {
    if let Some(root) = COMPAT_ROOT.get() {
        return Ok(root.join(container_name));
    }
    Ok(shell::known_folder(shell::KnownFolder::LocalAppDataLow)
        .ok_or("could not find the LocalLow folder")?
        .join("Isolated")
        .join(container_name))
}

/// The base folder of a box for a policy's tier, created if needed. Its
/// `Home` subfolder is the user folder apps inside the box see.
pub fn box_folder(policy: &Policy, box_name: &str) -> Result<PathBuf> {
    let name = appcontainer::box_container_name(box_name);
    let base = match policy.tier {
        Tier::Isolated => appcontainer::create_or_open(&name, &format!("Isolated box: {box_name}"))?.folder()?,
        Tier::Compatible => compatible_base(&name)?,
    };
    make_private_dirs(&base, true)?;
    Ok(base)
}

/// The sandbox's own base folder for an isolated folder's programs, created
/// if needed. Its `Home` subfolder is the user folder they see, and their
/// settings and saves (AppData, LocalLow) live under it.
pub fn isolated_folder_base(policy: &Policy, profile_name: &str) -> Result<PathBuf> {
    if policy.folder.trim().is_empty() {
        return Err(format!("'{profile_name}' is not an isolated folder."));
    }
    let name = appcontainer::folder_container_name(&normalize_path_key(&policy.folder));
    let base = match policy.tier {
        Tier::Isolated => appcontainer::create_or_open(&name, &format!("Isolated: {profile_name}"))?.folder()?,
        Tier::Compatible => compatible_base(&name)?,
    };
    make_private_dirs(&base, true)?;
    Ok(base)
}

/// The folder an installer is asked to use inside a box: the
/// `%LOCALAPPDATA%\Programs\<name>` that programs inside the box see.
pub fn box_install_dir(policy: &Policy, base: &Path, app: &str) -> PathBuf {
    match policy.tier {
        Tier::Isolated => base.join("Programs").join(app),
        Tier::Compatible => base.join(r"Home\AppData\Local\Programs").join(app),
    }
}

/// Removes a box's folders and sandbox identity.
pub fn delete_box(box_name: &str) -> Result<()> {
    let name = appcontainer::box_container_name(box_name);
    if let Ok(base) = compatible_base(&name) {
        let _ = std::fs::remove_dir_all(base);
    }
    appcontainer::delete(&name)
}

/// A copy of this process's token with every privilege removed and the
/// integrity level lowered to Low.
fn low_integrity_token() -> Result<OwnedHandle> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut tok,
        )
        .map_err(|e| err("could not open the process token", e))?;
        let tok = OwnedHandle(tok);
        let mut restricted = HANDLE::default();
        CreateRestrictedToken(tok.raw(), DISABLE_MAX_PRIVILEGE, None, None, None, &mut restricted)
            .map_err(|e| err("could not create a restricted token", e))?;
        let restricted = OwnedHandle(restricted);
        let w = Wide::new("S-1-16-4096");
        let mut sid = PSID::default();
        ConvertStringSidToSidW(w.pcwstr(), &mut sid).map_err(|e| err("could not build the low integrity SID", e))?;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_INTEGRITY,
            },
        };
        let r = SetTokenInformation(
            restricted.raw(),
            TokenIntegrityLevel,
            &label as *const _ as *const c_void,
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(sid),
        );
        let _ = LocalFree(Some(HLOCAL(sid.0)));
        r.map_err(|e| err("could not lower the integrity level", e))?;
        Ok(restricted)
    }
}

#[cfg(test)]
mod tests {
    use super::split_args;

    #[test]
    fn splits() {
        assert_eq!(split_args(r#"-a "b c" d\"e"#), vec!["-a", "b c", "d\"e"]);
        assert_eq!(split_args(""), Vec::<String>::new());
        assert_eq!(split_args(r#""""#), vec![""]);
    }
}

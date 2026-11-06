//! Windows backend for Isolated.
//!
//! Turns a [`Policy`] into an AppContainer (or, for the compatible tier, a
//! restricted low-integrity token), a Job Object with limits and UI
//! restrictions, and temporary ACL grants that are journaled and removed when
//! the sandbox ends. Also holds the other Windows integration: the right-click
//! menu, install/uninstall, shell helpers, and the self-updater.
//!
//! On other platforms every entry point compiles but returns an error, so the
//! core and GUI can be built and tested anywhere.

use isolated_core::{Gap, Policy};
use std::path::PathBuf;

pub mod update;

#[cfg(windows)]
mod win;

pub type Result<T> = std::result::Result<T, String>;

/// Something to run in a sandbox.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    /// Profile name recorded in the running list.
    pub profile_name: String,
    /// The program, shortcut, or script users picked.
    pub target: PathBuf,
    pub args: Vec<String>,
    /// Launch even if the sandbox would be weaker than the policy asks.
    pub accept_weaker: bool,
    /// Run inside this app box, whose folders are kept between runs.
    pub app_box: Option<String>,
    /// The target is an installer: start it without asking for
    /// administrator rights. (`.msi` files are unpacked, not run: see
    /// `isolated_core::msi`.)
    pub installer: bool,
    /// Appended to the command line as is (for switches such as NSIS's
    /// `/D=` that must not be quoted).
    pub raw_tail: String,
}

/// Live numbers for a running sandbox.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub processes: u32,
    pub memory_bytes: u64,
    /// Total CPU time used, in milliseconds.
    pub cpu_ms: u64,
}

/// A started sandbox. Call [`Sandbox::wait`] to stay with it until it ends
/// and clean up afterwards.
pub struct Sandbox {
    #[cfg(windows)]
    inner: win::launch::Running,
    #[cfg(not(windows))]
    _never: std::convert::Infallible,
}

impl Sandbox {
    pub fn id(&self) -> &str {
        #[cfg(windows)]
        return self.inner.id();
        #[cfg(not(windows))]
        match self._never {}
    }

    pub fn app_pid(&self) -> u32 {
        #[cfg(windows)]
        return self.inner.app_pid();
        #[cfg(not(windows))]
        match self._never {}
    }

    /// Waits until every process in the sandbox has exited, then removes the
    /// temporary grants and the running entry. Returns the program's exit code.
    pub fn wait(self) -> Result<u32> {
        #[cfg(windows)]
        return self.inner.wait();
        #[cfg(not(windows))]
        match self._never {}
    }
}

#[allow(dead_code)]
fn unsupported<T>() -> Result<T> {
    Err("This feature is only available on Windows.".into())
}

/// What this backend cannot enforce for a policy.
pub fn gaps(policy: &Policy) -> Vec<Gap> {
    #[cfg(windows)]
    return win::launch::gaps(policy);
    #[cfg(not(windows))]
    {
        let _ = policy;
        vec![Gap::weaker("Sandboxing is only available on Windows in this version.")]
    }
}

/// Starts a sandbox.
pub fn launch(dirs: &isolated_core::Dirs, policy: &Policy, req: &LaunchRequest) -> Result<Sandbox> {
    #[cfg(windows)]
    return win::launch::launch(dirs, policy, req).map(|inner| Sandbox { inner });
    #[cfg(not(windows))]
    {
        let _ = (dirs, policy, req);
        unsupported()
    }
}

/// App boxes: the folders behind [`isolated_core::boxes::AppBox`].
pub mod boxes {
    use super::*;
    use isolated_core::boxes::{FoundExe, FoundShortcut};
    use std::collections::BTreeSet;
    use std::path::Path;

    /// The box's base folder for the policy's tier, created if needed. Apps
    /// in the box see `<folder>\Home` as their user folder.
    pub fn folder(policy: &Policy, box_name: &str) -> Result<PathBuf> {
        #[cfg(windows)]
        return crate::win::launch::box_folder(policy, box_name);
        #[cfg(not(windows))]
        {
            let _ = (policy, box_name);
            unsupported()
        }
    }

    /// A drive letter mapped to a box folder while an installer runs (see
    /// `win/drive.rs` for why). Removed on drop.
    pub struct DriveAlias {
        #[cfg(windows)]
        inner: crate::win::drive::DriveAlias,
    }

    impl DriveAlias {
        pub fn map(folder: &Path) -> Result<DriveAlias> {
            #[cfg(windows)]
            return crate::win::drive::DriveAlias::map(folder).map(|inner| DriveAlias { inner });
            #[cfg(not(windows))]
            {
                let _ = folder;
                unsupported()
            }
        }

        /// The drive root, such as `Y:\\`.
        pub fn root(&self) -> PathBuf {
            #[cfg(windows)]
            return self.inner.root();
            #[cfg(not(windows))]
            PathBuf::new()
        }

        pub fn to_real(&self, p: &Path) -> PathBuf {
            #[cfg(windows)]
            return self.inner.to_real(p);
            #[cfg(not(windows))]
            p.to_path_buf()
        }
    }

    /// Where an installer is asked to install `app` inside the box.
    pub fn install_dir(policy: &Policy, folder: &Path, app: &str) -> PathBuf {
        #[cfg(windows)]
        return crate::win::launch::box_install_dir(policy, folder, app);
        #[cfg(not(windows))]
        {
            let _ = policy;
            folder.join("Programs").join(app)
        }
    }

    /// Deletes the box's folders and sandbox identity.
    pub fn delete(box_name: &str) -> Result<()> {
        #[cfg(windows)]
        return crate::win::launch::delete_box(box_name);
        #[cfg(not(windows))]
        {
            let _ = box_name;
            Ok(())
        }
    }

    /// True if any app in the box is running.
    pub fn in_use(dirs: &isolated_core::Dirs, box_name: &str) -> bool {
        let c = container_name(box_name);
        crate::running(dirs).iter().any(|e| e.container == c)
    }

    /// Deletes a box: its saved list, folders and sandbox identity. Refused
    /// while an app in it is running.
    pub fn remove(dirs: &isolated_core::Dirs, box_name: &str) -> Result<()> {
        if in_use(dirs, box_name) {
            return Err(format!("Box '{box_name}' is in use. Stop its apps first."));
        }
        delete(box_name)?;
        isolated_core::boxes::AppBox::remove(dirs, box_name);
        Ok(())
    }

    /// The sandbox identity name of a box, as recorded in the running list.
    pub fn container_name(box_name: &str) -> String {
        #[cfg(windows)]
        return crate::win::appcontainer::box_container_name(box_name);
        #[cfg(not(windows))]
        format!("Isolated.box.{box_name}")
    }

    const MAX_FILES: usize = 300_000;
    const MAX_DEPTH: usize = 14;

    fn walk(dir: &Path, depth: usize, out: &mut Vec<(PathBuf, u64)>, seen: &mut usize) {
        if depth > MAX_DEPTH || *seen > MAX_FILES {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            *seen += 1;
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                walk(&p, depth + 1, out, seen);
            } else if ft.is_file() {
                let ext = p
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| x.to_ascii_lowercase())
                    .unwrap_or_default();
                if ext == "exe" || ext == "lnk" {
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    out.push((p, size));
                }
            }
        }
    }

    fn list(folder: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut seen = 0;
        // Skip the private temp folder: installers unpack themselves there.
        let Ok(rd) = std::fs::read_dir(folder) else { return out };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            if p.is_dir() && name != "temp" && name != "inetcache" {
                walk(&p, 1, &mut out, &mut seen);
            }
        }
        out
    }

    /// Programs and shortcuts in a box, to compare before and after an install.
    pub fn snapshot(folder: &Path) -> BTreeSet<String> {
        list(folder)
            .into_iter()
            .map(|(p, _)| isolated_core::profile::normalize_path_key(&p.to_string_lossy()))
            .collect()
    }

    /// Shortcuts and programs that appeared in the box since `before`.
    /// Shortcuts pointing outside the box are ignored.
    pub fn found_since(
        folder: &Path,
        before: &BTreeSet<String>,
        alias: Option<&DriveAlias>,
    ) -> (Vec<FoundShortcut>, Vec<FoundExe>) {
        let root = isolated_core::profile::normalize_path_key(&folder.to_string_lossy());
        let mut shortcuts = Vec::new();
        let mut exes = Vec::new();
        for (p, size) in list(folder) {
            let s = p.to_string_lossy().into_owned();
            if before.contains(&isolated_core::profile::normalize_path_key(&s)) {
                continue;
            }
            if s.to_ascii_lowercase().ends_with(".lnk") {
                if let Some((target, args)) = shell::read_shortcut(&p) {
                    let target = match alias {
                        Some(a) => a.to_real(&target),
                        None => target,
                    };
                    let t = target.to_string_lossy().into_owned();
                    if !isolated_core::profile::normalize_path_key(&t).starts_with(&root) || !target.is_file() {
                        continue;
                    }
                    shortcuts.push(FoundShortcut {
                        name: p
                            .file_stem()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        target: t,
                        args,
                    });
                }
            } else {
                exes.push(FoundExe { path: s, size });
            }
        }
        shortcuts.sort_by_key(|a| a.name.to_lowercase());
        (shortcuts, exes)
    }
}

/// Running sandboxes whose watcher is still alive. Entries left by crashed
/// watchers are removed.
pub fn running(dirs: &isolated_core::Dirs) -> Vec<isolated_core::state::RunningEntry> {
    let all = isolated_core::state::RunningEntry::list(dirs);
    all.into_iter()
        .filter(|e| {
            let alive = is_process_alive(e.watcher_pid);
            if !alive {
                isolated_core::state::RunningEntry::remove(dirs, &e.id);
            }
            alive
        })
        .collect()
}

/// Stops every process in a sandbox. Its watcher then cleans up.
pub fn stop(entry: &isolated_core::state::RunningEntry) -> Result<()> {
    #[cfg(windows)]
    return win::job::terminate_named(&entry.job_name);
    #[cfg(not(windows))]
    {
        let _ = entry;
        unsupported()
    }
}

pub fn stats(entry: &isolated_core::state::RunningEntry) -> Option<Stats> {
    #[cfg(windows)]
    return win::job::stats_named(&entry.job_name);
    #[cfg(not(windows))]
    {
        let _ = entry;
        None
    }
}

pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    return win::util::is_process_alive(pid);
    #[cfg(not(windows))]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
}

/// Removes grants left behind by sandboxes whose watcher died (for example
/// after a crash or power loss). Returns how many sandboxes were repaired.
pub fn repair(dirs: &isolated_core::Dirs) -> Result<usize> {
    #[cfg(windows)]
    return win::acl::replay_journal(dirs);
    #[cfg(not(windows))]
    {
        let _ = dirs;
        Ok(0)
    }
}

/// The right-click "Run in Isolated" menu.
pub mod menu {
    use super::*;

    /// Adds the menu for the current user (no admin), pointing at `exe`.
    pub fn register(exe: &std::path::Path) -> Result<()> {
        #[cfg(windows)]
        return crate::win::menu::register(exe);
        #[cfg(not(windows))]
        {
            let _ = exe;
            unsupported()
        }
    }

    pub fn unregister() -> Result<()> {
        #[cfg(windows)]
        return crate::win::menu::unregister();
        #[cfg(not(windows))]
        unsupported()
    }

    /// The exe the menu currently points at, if registered.
    pub fn registered_exe() -> Option<PathBuf> {
        #[cfg(windows)]
        return crate::win::menu::registered_exe();
        #[cfg(not(windows))]
        None
    }
}

/// Per-user install: copies the exe to `%LOCALAPPDATA%\Programs\Isolated`,
/// adds the Start menu shortcut, the right-click menu, and an entry in
/// Settings > Apps so users can uninstall it like any app.
pub mod install {
    use super::*;

    pub fn install_dir() -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Programs").join("Isolated"))
    }

    pub fn installed_exe() -> Option<PathBuf> {
        install_dir().map(|d| d.join("isolated.exe"))
    }

    /// True if the running exe is the installed copy.
    pub fn is_running_installed() -> bool {
        match (std::env::current_exe().ok(), installed_exe()) {
            (Some(a), Some(b)) => {
                isolated_core::profile::normalize_path_key(&a.to_string_lossy())
                    == isolated_core::profile::normalize_path_key(&b.to_string_lossy())
            }
            _ => false,
        }
    }

    /// Installs the running exe. Returns the installed exe path.
    pub fn install() -> Result<PathBuf> {
        #[cfg(windows)]
        return crate::win::install::install();
        #[cfg(not(windows))]
        unsupported()
    }

    /// Removes the shortcut, menu, Apps entry and installed files. User
    /// profiles and settings are kept unless `remove_data` is set.
    pub fn uninstall(dirs: &isolated_core::Dirs, remove_data: bool) -> Result<()> {
        #[cfg(windows)]
        return crate::win::install::uninstall(dirs, remove_data);
        #[cfg(not(windows))]
        {
            let _ = (dirs, remove_data);
            unsupported()
        }
    }

    /// Updates the version shown in Settings > Apps after a self-update.
    pub fn refresh_version() {
        #[cfg(windows)]
        crate::win::install::refresh_version();
    }
}

/// Small shell helpers used by the GUI and CLI.
pub mod shell {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Icon {
        Info,
        Warning,
        Error,
    }

    pub fn message_box(title: &str, text: &str, icon: Icon) {
        #[cfg(windows)]
        crate::win::shell::message_box(title, text, icon);
        #[cfg(not(windows))]
        eprintln!("{title}: {text} ({icon:?})");
    }

    /// Yes/No question; true for Yes.
    pub fn confirm(title: &str, text: &str) -> bool {
        #[cfg(windows)]
        return crate::win::shell::confirm(title, text);
        #[cfg(not(windows))]
        {
            let _ = (title, text);
            false
        }
    }

    /// Opens a URL or path with its default handler.
    pub fn open(target: &str) {
        #[cfg(windows)]
        crate::win::shell::open(target);
        #[cfg(not(windows))]
        {
            let _ = std::process::Command::new("xdg-open").arg(target).spawn();
        }
    }

    /// Asks users to pick a program or script.
    pub fn pick_program() -> Option<PathBuf> {
        #[cfg(windows)]
        return crate::win::shell::pick(false);
        #[cfg(not(windows))]
        None
    }

    pub fn pick_folder() -> Option<PathBuf> {
        #[cfg(windows)]
        return crate::win::shell::pick(true);
        #[cfg(not(windows))]
        None
    }

    /// A shortcut's target and arguments.
    pub fn read_shortcut(lnk: &std::path::Path) -> Option<(PathBuf, Vec<String>)> {
        #[cfg(windows)]
        {
            let info = crate::win::shell::resolve_shortcut(lnk).ok()?;
            if info.target.as_os_str().is_empty() {
                return None;
            }
            Some((info.target, crate::win::launch::split_args(&info.arguments)))
        }
        #[cfg(not(windows))]
        {
            let _ = lnk;
            None
        }
    }

    /// Asks users to pick an installer.
    pub fn pick_installer() -> Option<PathBuf> {
        #[cfg(windows)]
        return crate::win::shell::pick_installer();
        #[cfg(not(windows))]
        None
    }

    /// Connects to the parent console, if started from a terminal, so CLI
    /// output is visible. Returns true if a console is attached.
    pub fn attach_console() -> bool {
        #[cfg(windows)]
        return crate::win::util::attach_console();
        #[cfg(not(windows))]
        true
    }
}

/// Checks that a folder can be shared with a sandbox (it exists and is not
/// far too broad, such as a whole drive or the whole user folder).
pub fn check_shared_folder(path: &str, write: bool) -> Result<()> {
    #[cfg(windows)]
    return win::launch::check_shared_folder(path, write);
    #[cfg(not(windows))]
    {
        let _ = write;
        if std::path::Path::new(path).is_dir() {
            Ok(())
        } else {
            Err(format!("The folder '{path}' does not exist."))
        }
    }
}

/// Starts this exe again, detached, with the given arguments.
pub fn spawn_self(args: &[&str]) -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start Isolated: {e}"))
}

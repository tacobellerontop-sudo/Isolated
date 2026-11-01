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

    /// Connects to the parent console, if started from a terminal, so CLI
    /// output is visible. Returns true if a console is attached.
    pub fn attach_console() -> bool {
        #[cfg(windows)]
        return crate::win::util::attach_console();
        #[cfg(not(windows))]
        true
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

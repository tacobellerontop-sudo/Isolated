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
    /// Folder the program starts in, instead of its own folder.
    pub workdir: Option<PathBuf>,
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

    fn same_path(a: &Path, b: &Path) -> bool {
        let n = |p: &Path| {
            let s = p.to_string_lossy().to_ascii_lowercase();
            s.strip_prefix(r"\\?\").unwrap_or(&s).trim_end_matches('\\').to_string()
        };
        n(a) == n(b)
    }

    /// True if `real` is a link into this box's copy.
    fn is_kept_link(real: &Path, copy: &Path) -> bool {
        std::fs::read_link(real).is_ok_and(|t| same_path(&t, copy))
    }

    /// Links each of the box's kept folders to the box's own copy, so apps
    /// that insist on a folder outside the box write into the box. A folder
    /// that already holds files on the PC is left alone. Returns a note for
    /// each folder that couldn't be kept.
    pub fn keep_folders(policy: &Policy, b: &isolated_core::boxes::AppBox) -> Vec<String> {
        let mut notes = Vec::new();
        if b.kept_folders.is_empty() {
            return notes;
        }
        let base = match folder(policy, &b.name) {
            Ok(f) => f,
            Err(e) => return vec![e],
        };
        for k in &b.kept_folders {
            let real = PathBuf::from(isolated_core::boxes::expand_env(k));
            let copy = isolated_core::boxes::kept_copy(&base, &real.to_string_lossy());
            if let Err(e) = std::fs::create_dir_all(&copy) {
                notes.push(format!("{}: {e}", copy.display()));
                continue;
            }
            if is_kept_link(&real, &copy) {
                continue;
            }
            if real.exists() {
                let empty = std::fs::read_dir(&real)
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(false);
                if !(empty && real.is_dir() && std::fs::remove_dir(&real).is_ok()) {
                    notes.push(format!(
                        "{} already exists on your PC with files in it, so it was left alone. Move or delete it to keep it in the container.",
                        real.display()
                    ));
                    continue;
                }
            }
            if real.parent().is_none_or(|p| !p.is_dir()) {
                notes.push(format!("{}: its parent folder doesn't exist", real.display()));
                continue;
            }
            #[cfg(windows)]
            if let Err(e) = crate::win::junction::create(&real, &copy) {
                notes.push(e);
            }
        }
        notes
    }

    /// Removes the links [`keep_folders`] made; the box keeps its copies.
    pub fn release_folders(b: &isolated_core::boxes::AppBox) {
        let marker = format!("\\{}\\", container_name(&b.name).to_ascii_lowercase());
        for k in &b.kept_folders {
            let real = PathBuf::from(isolated_core::boxes::expand_env(k));
            if let Ok(t) = std::fs::read_link(&real) {
                let t = t.to_string_lossy().to_ascii_lowercase();
                if t.contains(&marker) && t.contains("\\kept\\") {
                    let _ = std::fs::remove_dir(&real);
                }
            }
        }
    }

    /// The user folder apps in the box see (Documents, Downloads, Desktop
    /// and their settings), created if needed. This is where their
    /// creations usually are.
    pub fn home(policy: &Policy, box_name: &str) -> Result<PathBuf> {
        folder(policy, box_name).map(|f| f.join("Home"))
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
        if let Some(b) = isolated_core::boxes::AppBox::load(dirs, box_name) {
            release_folders(&b);
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

    /// The sandbox's own files for an isolated folder (see
    /// `win::launch::isolated_folder_base`), created if needed.
    pub fn isolated_folder_base(policy: &Policy, profile_name: &str) -> Result<PathBuf> {
        #[cfg(windows)]
        return crate::win::launch::isolated_folder_base(policy, profile_name);
        #[cfg(not(windows))]
        {
            let _ = (policy, profile_name);
            unsupported()
        }
    }

    /// Programs (.exe) in a folder and its subfolders, sorted, at most
    /// `limit` of them.
    pub fn programs_in(folder: &Path, limit: usize) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut seen = 0;
        walk(folder, 0, &mut out, &mut seen);
        let mut v: Vec<PathBuf> = out
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
            .collect();
        v.sort_by_key(|p| p.to_string_lossy().to_lowercase());
        v.truncate(limit);
        v
    }

    /// Copies `.msi` packages that appear in a box while an installer runs.
    ///
    /// Many setup programs only unpack a Windows Installer package and hand
    /// it to the Windows Installer service, which a sandbox cannot reach, so
    /// they fail and often delete the package again. Capture tools such as
    /// Cameyo and Turbo record what an installer lays down; Isolated keeps a
    /// copy of each package (and the `.cab` files beside it) as it appears,
    /// so it can unpack it itself afterwards.
    pub struct MsiCatcher {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<Vec<PathBuf>>>,
    }

    impl MsiCatcher {
        /// Watches `box_folder` and copies packages into `keep`.
        pub fn start(box_folder: &Path, keep: &Path) -> MsiCatcher {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (folder, keep, flag) = (box_folder.to_path_buf(), keep.to_path_buf(), stop.clone());
            let thread = std::thread::spawn(move || {
                let mut seen: std::collections::HashMap<PathBuf, (u64, Option<std::time::SystemTime>, PathBuf)> =
                    std::collections::HashMap::new();
                loop {
                    let last = flag.load(std::sync::atomic::Ordering::Relaxed);
                    catch_once(&folder, &keep, &mut seen);
                    if last {
                        break;
                    }
                    for _ in 0..7 {
                        if flag.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
                let mut out: Vec<PathBuf> = seen.into_values().map(|(_, _, d)| d).filter(|d| is_msi(d)).collect();
                out.sort();
                out
            });
            MsiCatcher {
                stop,
                thread: Some(thread),
            }
        }

        /// Stops watching (after one last look) and returns the copies.
        pub fn finish(mut self) -> Vec<PathBuf> {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            self.thread.take().and_then(|t| t.join().ok()).unwrap_or_default()
        }
    }

    impl Drop for MsiCatcher {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn is_msi(p: &Path) -> bool {
        use std::io::Read;
        let mut head = [0u8; 8];
        std::fs::File::open(p)
            .and_then(|mut f| f.read_exact(&mut head))
            .is_ok_and(|_| head == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    }

    fn catch_once(
        folder: &Path,
        keep: &Path,
        seen: &mut std::collections::HashMap<PathBuf, (u64, Option<std::time::SystemTime>, PathBuf)>,
    ) {
        let mut found = Vec::new();
        find_packages(folder, keep, 0, &mut found);
        for p in found {
            let Ok(meta) = std::fs::metadata(&p) else { continue };
            let stamp = (meta.len(), meta.modified().ok());
            let dest = match seen.get(&p) {
                Some((len, time, _)) if (*len, *time) == stamp => continue,
                Some((_, _, d)) => d.clone(),
                None => {
                    let slot = keep.join(format!("{}", seen.len() + 1));
                    slot.join(p.file_name().unwrap_or_default())
                }
            };
            let Some(slot) = dest.parent() else { continue };
            if std::fs::create_dir_all(slot).is_err() || std::fs::copy(&p, &dest).is_err() {
                continue;
            }
            // Packages may keep their files in cabinets beside them.
            if dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")) {
                if let Some(Ok(rd)) = p.parent().map(std::fs::read_dir) {
                    for e in rd.flatten() {
                        let c = e.path();
                        if c.extension().is_some_and(|x| x.eq_ignore_ascii_case("cab")) {
                            let _ = std::fs::copy(&c, slot.join(e.file_name()));
                        }
                    }
                }
            }
            seen.insert(p, (stamp.0, stamp.1, dest));
        }
    }

    fn find_packages(dir: &Path, keep: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth > 10 || out.len() > 64 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                // Installed programs are large and never hold the package
                // being installed.
                let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                if name == "programs" || p == keep {
                    continue;
                }
                find_packages(&p, keep, depth + 1, out);
            } else if ft.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("msi")) {
                out.push(p);
            }
        }
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

/// Lets sandboxed apps read the attributes of the folders above the user
/// folder (`C:\`, `C:\Users`, ...). Node, Electron and most other runtimes
/// check every folder above a file when they find its real path, and fail
/// without this. Only attributes such as "this is a folder" become visible,
/// never names or contents, and nothing below each folder changes.
pub mod compat {
    use std::path::PathBuf;

    /// Folders inside the user's own profile; changed without asking.
    pub fn user_folders() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            out.push(home.join("AppData"));
            out.push(home);
        }
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            let packages = local.join("Packages");
            // Each container's own folder sits above the AC folder its apps
            // live in, and Windows gives the container no access to it.
            if let Ok(list) = std::fs::read_dir(&packages) {
                out.extend(
                    list.flatten()
                        .filter(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .to_ascii_lowercase()
                                .starts_with("isolated.")
                        })
                        .map(|e| e.path()),
                );
            }
            out.push(packages);
            out.push(local);
        }
        out.retain(|p| p.is_dir());
        out
    }

    /// Folders that need an administrator: the drive roots and `C:\Users`.
    pub fn system_folders() -> Vec<PathBuf> {
        #[allow(unused_mut)]
        let mut out: Vec<PathBuf> = Vec::new();
        if let Some(users) = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .and_then(|h| h.parent().map(PathBuf::from))
        {
            out.push(users);
        }
        #[cfg(windows)]
        out.extend(crate::win::drive::fixed_roots());
        out
    }

    /// Fixes the user's own folders, quietly. Called before each launch.
    pub fn prepare_user() {
        #[cfg(windows)]
        for p in user_folders() {
            let _ = crate::win::acl::allow_attribute_read(&p, false);
        }
    }

    /// True if some drive root or `C:\Users` still blocks Node and Electron.
    pub fn system_needed() -> bool {
        #[cfg(windows)]
        return system_folders()
            .iter()
            .any(|p| crate::win::acl::allow_attribute_read(p, true).unwrap_or(false));
        #[cfg(not(windows))]
        false
    }

    /// Fixes the system folders. Needs to run as administrator. Returns how
    /// many folders were changed.
    pub fn fix_system() -> crate::Result<usize> {
        #[allow(unused_mut)]
        let mut n = 0;
        #[cfg(windows)]
        for p in system_folders() {
            match crate::win::acl::allow_attribute_read(&p, false) {
                Ok(true) => n += 1,
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(n)
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

    /// Starts `exe` as administrator; Windows asks users first. False if
    /// they said no.
    pub fn run_as_admin(exe: &std::path::Path, args: &str) -> bool {
        #[cfg(windows)]
        return crate::win::shell::run_as_admin(exe, args);
        #[cfg(not(windows))]
        {
            let _ = (exe, args);
            false
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

    /// The user's known folders as this process sees them (for diagnosing
    /// what a sandboxed app gets), as (name, path).
    pub fn known_folders() -> Vec<(&'static str, Option<PathBuf>)> {
        #[cfg(windows)]
        {
            use crate::win::shell::{known_folder, KnownFolder as K};
            vec![
                ("Profile", known_folder(K::Profile)),
                ("Documents", known_folder(K::Documents)),
                ("Desktop", known_folder(K::Desktop)),
                ("Downloads", known_folder(K::Downloads)),
                ("LocalAppDataLow", known_folder(K::LocalAppDataLow)),
                ("RoamingAppData", known_folder(K::RoamingAppData)),
                ("LocalAppData", known_folder(K::LocalAppData)),
                ("ProgramData", known_folder(K::ProgramData)),
                ("CommonPrograms", known_folder(K::CommonPrograms)),
                ("PublicDesktop", known_folder(K::PublicDesktop)),
                ("ProgramFiles", known_folder(K::ProgramFiles)),
            ]
        }
        #[cfg(not(windows))]
        Vec::new()
    }

    /// For diagnosis: how Windows resolves the folders apps save to.
    pub fn known_folders_detail() -> Vec<(&'static str, String)> {
        #[cfg(windows)]
        {
            use crate::win::shell::{known_folder_detail, KnownFolder as K};
            [
                ("Profile", K::Profile),
                ("LocalAppDataLow", K::LocalAppDataLow),
                ("LocalAppData", K::LocalAppData),
                ("RoamingAppData", K::RoamingAppData),
            ]
            .into_iter()
            .map(|(n, k)| (n, known_folder_detail(k)))
            .collect()
        }
        #[cfg(not(windows))]
        Vec::new()
    }

    /// Asks users to pick any file.
    pub fn pick_file() -> Option<PathBuf> {
        #[cfg(windows)]
        return crate::win::shell::pick_any();
        #[cfg(not(windows))]
        None
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

/// Checks that a folder can be isolated: it exists and is not far too broad
/// or a system folder, since every program in it may change it.
pub fn check_isolated_folder(path: &str) -> Result<()> {
    #[cfg(windows)]
    return win::launch::check_isolated_folder(path);
    #[cfg(not(windows))]
    {
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

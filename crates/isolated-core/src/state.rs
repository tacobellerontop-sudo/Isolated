//! Folders, settings, the list of running sandboxes, and the ACL cleanup
//! journal. All plain files, so nothing has to stay resident.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Isolated's folders.
#[derive(Debug, Clone)]
pub struct Dirs {
    /// Roaming config: profiles and settings (`%APPDATA%\Isolated`).
    pub config: PathBuf,
    /// Local state: running list, journal, temp files (`%LOCALAPPDATA%\Isolated`).
    pub data: PathBuf,
}

impl Dirs {
    /// Standard locations for the current user.
    pub fn standard() -> Dirs {
        let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let home = env("USERPROFILE")
            .or_else(|| env("HOME"))
            .unwrap_or_else(std::env::temp_dir);
        let config = env("APPDATA")
            .or_else(|| env("XDG_CONFIG_HOME"))
            .unwrap_or_else(|| home.join(".config"))
            .join("Isolated");
        let data = env("LOCALAPPDATA")
            .or_else(|| env("XDG_STATE_HOME"))
            .unwrap_or_else(|| home.join(".local").join("state"))
            .join("Isolated");
        Dirs { config, data }
    }

    pub fn under(root: &Path) -> Dirs {
        Dirs {
            config: root.join("config"),
            data: root.join("data"),
        }
    }

    pub fn profiles(&self) -> PathBuf {
        self.config.join("profiles")
    }
    pub fn boxes(&self) -> PathBuf {
        self.config.join("boxes")
    }
    pub fn settings_file(&self) -> PathBuf {
        self.config.join("settings.toml")
    }
    pub fn running(&self) -> PathBuf {
        self.data.join("running")
    }
    pub fn journal(&self) -> PathBuf {
        self.data.join("journal")
    }
    pub fn tmp(&self) -> PathBuf {
        self.data.join("tmp")
    }
    pub fn log_file(&self) -> PathBuf {
        self.data.join("isolated.log")
    }
}

/// App settings edited in the GUI's Settings view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Check GitHub Releases for a new version when the window opens.
    pub check_for_updates: bool,
    /// Unix time of the last update check.
    pub last_update_check: u64,
    /// A version the user chose to skip.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub skipped_version: String,
    /// Profile used for programs without a saved profile.
    pub default_profile: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            check_for_updates: true,
            last_update_check: 0,
            skipped_version: String::new(),
            default_profile: crate::profile::DEFAULT_PROFILE.into(),
        }
    }
}

impl Settings {
    pub fn load(dirs: &Dirs) -> Settings {
        fs::read_to_string(dirs.settings_file())
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dirs: &Dirs) -> std::io::Result<()> {
        write_atomic(
            &dirs.settings_file(),
            toml::to_string(self).unwrap_or_default().as_bytes(),
        )
    }
}

/// A folder users chose to share with an app for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFolder {
    pub path: String,
    /// The app may change files there, not only read them.
    #[serde(default)]
    pub write: bool,
}

/// The folders each app was last given, so the folder picker can start
/// from them. Kept in `shared-folders.toml`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FolderChoices {
    app: Vec<AppFolders>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AppFolders {
    program: String,
    #[serde(default)]
    folder: Vec<SharedFolder>,
}

const MAX_REMEMBERED_APPS: usize = 200;

impl FolderChoices {
    fn file(dirs: &Dirs) -> PathBuf {
        dirs.config.join("shared-folders.toml")
    }

    pub fn load(dirs: &Dirs) -> FolderChoices {
        fs::read_to_string(Self::file(dirs))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, dirs: &Dirs) -> std::io::Result<()> {
        write_atomic(&Self::file(dirs), toml::to_string(self).unwrap_or_default().as_bytes())
    }

    /// The folders last chosen for a program.
    pub fn get(&self, program: &str) -> Vec<SharedFolder> {
        let key = crate::profile::normalize_path_key(program);
        self.app
            .iter()
            .find(|a| crate::profile::normalize_path_key(&a.program) == key)
            .map(|a| a.folder.clone())
            .unwrap_or_default()
    }

    /// Remembers the folders for a program (most recent first).
    pub fn set(&mut self, program: &str, folders: Vec<SharedFolder>) {
        let key = crate::profile::normalize_path_key(program);
        self.app
            .retain(|a| crate::profile::normalize_path_key(&a.program) != key);
        self.app.insert(
            0,
            AppFolders {
                program: program.to_string(),
                folder: folders,
            },
        );
        self.app.truncate(MAX_REMEMBERED_APPS);
    }
}

/// One running sandbox, as recorded in `running\<id>.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunningEntry {
    pub id: String,
    pub profile: String,
    pub program: String,
    /// The Isolated process watching this sandbox.
    pub watcher_pid: u32,
    /// The sandboxed program's first process.
    pub app_pid: u32,
    /// Unix time the sandbox started.
    pub started: u64,
    /// Name of the native sandbox identity (AppContainer name on Windows).
    pub container: String,
    /// Name of the kernel object used to stop the sandbox (Job Object name).
    pub job_name: String,
}

impl RunningEntry {
    pub fn save(&self, dirs: &Dirs) -> std::io::Result<()> {
        let path = dirs.running().join(format!("{}.toml", self.id));
        write_atomic(&path, toml::to_string(self).unwrap_or_default().as_bytes())
    }

    pub fn remove(dirs: &Dirs, id: &str) {
        let _ = fs::remove_file(dirs.running().join(format!("{id}.toml")));
    }

    /// All recorded entries. Liveness is checked by the caller, which knows
    /// how to test whether `watcher_pid` is still alive.
    pub fn list(dirs: &Dirs) -> Vec<RunningEntry> {
        let mut out: Vec<RunningEntry> = read_toml_dir(&dirs.running());
        out.sort_by_key(|e| e.started);
        out
    }
}

/// Access granted on a path for a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
    /// Installers in a box may create keys under the user's registry key
    /// for uninstall entries (`path`). Keys they create are deleted when
    /// the grant is revoked.
    RegistryCreate,
    /// Only lets the sandbox see that this folder exists (its attributes),
    /// not list or open what is in it. Set on the folder alone, never
    /// passed down to what it contains.
    Attributes,
}

/// A recorded ACL grant, written before the grant is applied and removed
/// after it is revoked, so a crash never leaves access behind for good.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub path: String,
    pub access: Access,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub sandbox_id: String,
    pub watcher_pid: u32,
    /// String form of the SID the grants were made to.
    pub sid: String,
    pub grants: Vec<Grant>,
}

impl JournalEntry {
    pub fn path(dirs: &Dirs, id: &str) -> PathBuf {
        dirs.journal().join(format!("{id}.toml"))
    }

    pub fn save(&self, dirs: &Dirs) -> std::io::Result<()> {
        write_atomic(
            &Self::path(dirs, &self.sandbox_id),
            toml::to_string(self).unwrap_or_default().as_bytes(),
        )
    }

    pub fn remove(dirs: &Dirs, id: &str) {
        let _ = fs::remove_file(Self::path(dirs, id));
    }

    pub fn list(dirs: &Dirs) -> Vec<JournalEntry> {
        read_toml_dir(&dirs.journal())
    }
}

fn read_toml_dir<T: for<'de> Deserialize<'de>>(dir: &Path) -> Vec<T> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("toml") {
                if let Some(v) = fs::read_to_string(&p).ok().and_then(|t| toml::from_str(&t).ok()) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Writes a file via a temporary file and rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short random id for a sandbox, such as `k3f9a2`.
pub fn new_sandbox_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    format!("{:08x}", h.finish() as u32)
}

/// Stable short hash (FNV-1a) used to derive per-program identities.
pub fn stable_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_and_journal_roundtrip() {
        let root = std::env::temp_dir().join(format!("isolated-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dirs = Dirs::under(&root);
        let e = RunningEntry {
            id: new_sandbox_id(),
            profile: "strict".into(),
            program: r"C:\a.exe".into(),
            watcher_pid: 1,
            app_pid: 2,
            started: now_unix(),
            container: "Isolated.strict.abc".into(),
            job_name: "Local\\Isolated-x".into(),
        };
        e.save(&dirs).unwrap();
        assert_eq!(RunningEntry::list(&dirs), vec![e.clone()]);
        RunningEntry::remove(&dirs, &e.id);
        assert!(RunningEntry::list(&dirs).is_empty());

        let j = JournalEntry {
            sandbox_id: e.id.clone(),
            watcher_pid: 1,
            sid: "S-1-15-2-1".into(),
            grants: vec![Grant {
                path: r"C:\x".into(),
                access: Access::Write,
            }],
        };
        j.save(&dirs).unwrap();
        assert_eq!(JournalEntry::list(&dirs), vec![j]);

        let mut s = Settings::load(&dirs);
        assert!(s.check_for_updates);
        s.skipped_version = "0.2.0".into();
        s.save(&dirs).unwrap();
        assert_eq!(Settings::load(&dirs), s);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ids_differ() {
        assert_ne!(new_sandbox_id(), new_sandbox_id());
        assert_eq!(stable_hash("a"), stable_hash("a"));
    }

    #[test]
    fn folder_choices_round_trip() {
        let root = std::env::temp_dir().join(format!("isolated-test-fc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dirs = Dirs::under(&root);
        let mut c = FolderChoices::load(&dirs);
        assert!(c.get(r"C:\A\app.exe").is_empty());
        let list = vec![
            SharedFolder {
                path: r"C:\Users\u\Pictures".into(),
                write: false,
            },
            SharedFolder {
                path: r"D:\Work".into(),
                write: true,
            },
        ];
        c.set(r"C:\A\app.exe", list.clone());
        c.save(&dirs).unwrap();
        let c = FolderChoices::load(&dirs);
        assert_eq!(c.get(r"c:/a/APP.exe"), list);
        let _ = fs::remove_dir_all(&root);
    }
}

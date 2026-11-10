//! Profiles: TOML files on disk plus the built-in set, with `extends` support
//! and lookup by program path.

use crate::policy::Policy;
use std::fs;
use std::path::{Path, PathBuf};

/// Built-in profiles, embedded in the binary.
pub const BUILTIN: &[(&str, &str)] = &[
    ("strict", include_str!("../../../profiles/strict.toml")),
    ("offline", include_str!("../../../profiles/offline.toml")),
    ("online", include_str!("../../../profiles/online.toml")),
    ("folders", include_str!("../../../profiles/folders.toml")),
    ("game-mod", include_str!("../../../profiles/game-mod.toml")),
    ("dev-build", include_str!("../../../profiles/dev-build.toml")),
    ("compatible", include_str!("../../../profiles/compatible.toml")),
];

/// The profile used when a program has no saved profile.
pub const DEFAULT_PROFILE: &str = "strict";

const MAX_EXTENDS_DEPTH: usize = 8;

/// Where a profile came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Builtin,
    User,
}

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub policy: Policy,
    pub source: Source,
    pub path: Option<PathBuf>,
}

/// Reads and writes profiles in one folder.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    dir: PathBuf,
}

impl ProfileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        ProfileStore { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn is_builtin(name: &str) -> bool {
        BUILTIN.iter().any(|(n, _)| *n == name)
    }

    fn builtin_text(name: &str) -> Option<&'static str> {
        BUILTIN.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
    }

    fn user_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.toml", file_stem(name)))
    }

    /// Raw TOML text of a profile by name. User profiles shadow built-ins.
    fn text_of(&self, name: &str) -> Option<String> {
        if let Ok(t) = fs::read_to_string(self.user_path(name)) {
            return Some(t);
        }
        // A user file may be named differently from its `name` field.
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("toml") {
                    continue;
                }
                if let Ok(t) = fs::read_to_string(&p) {
                    if let Ok(pol) = Policy::from_toml(&t) {
                        if pol.name == name {
                            return Some(t);
                        }
                    }
                }
            }
        }
        Self::builtin_text(name).map(str::to_string)
    }

    /// Loads a profile by name with `extends` resolved.
    pub fn load(&self, name: &str) -> Result<Policy, String> {
        let text = self.text_of(name).ok_or_else(|| format!("no profile named '{name}'"))?;
        self.resolve_text(&text)
    }

    /// Parses profile text and resolves its `extends` chain. Values set in a
    /// profile override the ones it extends; tables merge key by key.
    pub fn resolve_text(&self, text: &str) -> Result<Policy, String> {
        let mut table: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut seen = Vec::new();
        while let Some(parent) = table.get("extends").and_then(|v| v.as_str()).map(str::to_string) {
            if seen.contains(&parent) || seen.len() >= MAX_EXTENDS_DEPTH {
                return Err(format!("profile 'extends' chain loops or is too deep at '{parent}'"));
            }
            seen.push(parent.clone());
            let ptext = self
                .text_of(&parent)
                .ok_or_else(|| format!("extends unknown profile '{parent}'"))?;
            let mut base: toml::Table = toml::from_str(&ptext).map_err(|e| format!("{parent}: {e}"))?;
            table.remove("extends");
            // The parent's own name/description/program never leak into the child.
            for k in ["name", "description", "program", "folder"] {
                base.remove(k);
            }
            merge(&mut base, table);
            table = base;
        }
        let mut policy: Policy = table.try_into().map_err(|e: toml::de::Error| e.to_string())?;
        if let Some(first) = seen.first() {
            policy.extends = Some(first.clone());
        }
        policy.validate().map_err(|e| e.join("; "))?;
        Ok(policy)
    }

    /// All user profiles, sorted by name. Files that fail to parse are
    /// returned as errors so the GUI can show them.
    pub fn list_user(&self) -> (Vec<ProfileEntry>, Vec<(PathBuf, String)>) {
        let mut ok = Vec::new();
        let mut bad = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("toml") {
                    continue;
                }
                match fs::read_to_string(&p)
                    .map_err(|e| e.to_string())
                    .and_then(|t| self.resolve_text(&t))
                {
                    Ok(policy) => ok.push(ProfileEntry {
                        policy,
                        source: Source::User,
                        path: Some(p),
                    }),
                    Err(err) => bad.push((p, err)),
                }
            }
        }
        ok.sort_by_key(|a| a.policy.name.to_lowercase());
        (ok, bad)
    }

    /// Built-in profiles, resolved.
    pub fn list_builtin(&self) -> Vec<ProfileEntry> {
        BUILTIN
            .iter()
            .filter_map(|(_, text)| {
                // Resolve against built-ins only, so user files can't change them.
                ProfileStore::new(PathBuf::new())
                    .resolve_text(text)
                    .ok()
                    .map(|policy| ProfileEntry {
                        policy,
                        source: Source::Builtin,
                        path: None,
                    })
            })
            .collect()
    }

    /// The saved user profile for a program: one made for that exact
    /// program, otherwise the isolated folder it sits in (the innermost one
    /// if folders are nested).
    pub fn find_for_program(&self, program: &str) -> Option<Policy> {
        let want = normalize_path_key(program);
        if want.is_empty() {
            return None;
        }
        let list = self.list_user().0;
        if let Some(e) = list
            .iter()
            .find(|e| !e.policy.program.is_empty() && normalize_path_key(&e.policy.program) == want)
        {
            return Some(e.policy.clone());
        }
        list.into_iter()
            .filter(|e| !e.policy.folder.is_empty() && path_is_under(&want, &e.policy.folder))
            .max_by_key(|e| normalize_path_key(&e.policy.folder).len())
            .map(|e| e.policy)
    }

    /// The saved profile that isolates exactly this folder.
    pub fn find_for_folder(&self, folder: &str) -> Option<Policy> {
        let want = normalize_path_key(folder);
        if want.is_empty() {
            return None;
        }
        self.list_user()
            .0
            .into_iter()
            .find(|e| !e.policy.folder.is_empty() && normalize_path_key(&e.policy.folder) == want)
            .map(|e| e.policy)
    }

    /// A new profile that isolates `folder`: programs in it may read and
    /// change the folder and nothing else of the user's; copy and paste
    /// work; internet only if `internet`. Not saved yet.
    pub fn new_folder_profile(&self, folder: &str, internet: bool) -> Result<Policy, String> {
        let mut p = self.load(DEFAULT_PROFILE)?;
        p.extends = Some(DEFAULT_PROFILE.to_string());
        p.folder = folder.trim().to_string();
        let stem = Path::new(&p.folder.replace('\\', "/"))
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("folder")
            .to_string();
        p.name = self.suggest_name(&format!("{}-folder", stem.replace('.', "-")));
        p.description = "Isolated folder".into();
        p.devices.clipboard = crate::policy::Clipboard::Full;
        p.network.mode = if internet {
            crate::policy::NetworkMode::Full
        } else {
            crate::policy::NetworkMode::None
        };
        Ok(p)
    }

    /// Every isolated folder, sorted by folder path.
    pub fn list_folders(&self) -> Vec<Policy> {
        let mut v: Vec<Policy> = self
            .list_user()
            .0
            .into_iter()
            .map(|e| e.policy)
            .filter(|p| !p.folder.is_empty())
            .collect();
        v.sort_by_key(|p| normalize_path_key(&p.folder));
        v
    }

    /// Saves a user profile, returning its path. Refuses to overwrite a
    /// built-in name so built-ins stay recognizable.
    pub fn save(&self, policy: &Policy) -> Result<PathBuf, String> {
        policy.validate().map_err(|e| e.join("; "))?;
        if Self::is_builtin(&policy.name) {
            return Err(format!(
                "'{}' is a built-in profile name; choose another name",
                policy.name
            ));
        }
        fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let path = self.user_path(&policy.name);
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, policy.to_toml()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn delete(&self, name: &str) -> Result<(), String> {
        let (list, _) = self.list_user();
        match list.into_iter().find(|e| e.policy.name == name) {
            Some(ProfileEntry { path: Some(p), .. }) => fs::remove_file(p).map_err(|e| e.to_string()),
            _ => Err(format!("no user profile named '{name}'")),
        }
    }

    /// A profile name not used yet, based on a program's file name.
    pub fn suggest_name(&self, program: &str) -> String {
        let stem = Path::new(&program.replace('\\', "/"))
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("app")
            .to_string();
        let base = file_stem(&stem.to_lowercase());
        let base = if base.is_empty() { "app".to_string() } else { base };
        let taken = |n: &str| Self::is_builtin(n) || self.user_path(n).exists();
        if !taken(&base) {
            return base;
        }
        (2..).map(|i| format!("{base}-{i}")).find(|n| !taken(n)).unwrap()
    }
}

/// Merges `over` into `base`: tables merge recursively, other values replace.
fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// A safe file stem from a profile name: letters, digits, `-`, `_`, `.`.
pub fn file_stem(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    s.trim_matches(|c| c == '.' || c == '-').chars().take(64).collect()
}

/// Key for comparing Windows paths: case-insensitive, `/` and `\` equal,
/// surrounding quotes and trailing separators ignored.
pub fn normalize_path_key(p: &str) -> String {
    let mut s = p.trim().trim_matches('"').replace('/', "\\").to_lowercase();
    if let Some(rest) = s.strip_prefix("\\\\?\\") {
        s = rest.to_string();
    }
    while s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// Company and product from a Unity `app.info` file, if both are usable as
/// single folder names.
pub fn unity_app_info(text: &str) -> Option<(String, String)> {
    let mut lines = text.lines().map(str::trim);
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 120
            && s != "."
            && s != ".."
            && !s.ends_with('.')
            && !s
                .chars()
                .any(|c| matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
    };
    let company = lines.next()?.to_string();
    let product = lines.next()?.to_string();
    (ok(&company) && ok(&product)).then_some((company, product))
}

/// True if `path` is `folder` or inside it (Windows rules, see
/// [`normalize_path_key`]).
pub fn path_is_under(path: &str, folder: &str) -> bool {
    let p = normalize_path_key(path);
    let f = normalize_path_key(folder);
    if f.is_empty() {
        return false;
    }
    p == f || p.starts_with(&format!("{}\\", f.trim_end_matches('\\')))
}

/// Expands a leading `~` to the user's home folder and `%VAR%` references.
pub fn expand_path(p: &str, home: &Path, var: impl Fn(&str) -> Option<String>) -> PathBuf {
    let p = p.trim();
    if p == "~" {
        return home.to_path_buf();
    }
    if let Some(r) = p.strip_prefix("~\\").or_else(|| p.strip_prefix("~/")) {
        return home.join(expand_vars(r, &var));
    }
    PathBuf::from(expand_vars(p, &var))
}

fn expand_vars(s: &str, var: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => match var(&after[..end]) {
                Some(v) => {
                    out.push_str(&v);
                    rest = &after[end + 1..];
                }
                None => {
                    out.push('%');
                    rest = after;
                }
            },
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Clipboard, NetworkMode, Tier};

    fn tmp_store(tag: &str) -> ProfileStore {
        let d = std::env::temp_dir().join(format!("isolated-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        ProfileStore::new(d)
    }

    #[test]
    fn builtins_resolve() {
        let s = tmp_store("b");
        let list = s.list_builtin();
        assert_eq!(list.len(), BUILTIN.len());
        let online = s.load("online").unwrap();
        assert_eq!(online.network.mode, NetworkMode::Full);
        assert_eq!(online.devices.clipboard, Clipboard::Full);
        assert_eq!(online.extends.as_deref(), Some("strict"));
        assert_eq!(online.name, "online");
        let strict = s.load("strict").unwrap();
        assert_eq!(strict.network.mode, NetworkMode::None);
        assert_eq!(s.load("compatible").unwrap().tier, Tier::Compatible);
        let folders = s.load("folders").unwrap();
        assert!(folders.filesystem.ask_for_folders);
        assert_eq!(folders.network.mode, NetworkMode::None);
        assert!(!strict.filesystem.ask_for_folders);
        assert!(!strict.to_toml().contains("ask_for_folders"));
    }

    #[test]
    fn extends_merges_tables() {
        let s = tmp_store("m");
        let p = s
            .resolve_text("name='a'\nextends='game-mod'\n[resources]\nmemory_max='1G'")
            .unwrap();
        assert_eq!(p.resources.memory_max, "1G");
        assert_eq!(p.resources.max_processes, 128);
        assert_eq!(p.network.mode, NetworkMode::Full);
    }

    #[test]
    fn extends_loop_detected() {
        let s = tmp_store("l");
        fs::create_dir_all(s.dir()).unwrap();
        fs::write(s.dir().join("a.toml"), "name='a'\nextends='b'").unwrap();
        fs::write(s.dir().join("b.toml"), "name='b'\nextends='a'").unwrap();
        assert!(s.load("a").unwrap_err().contains("loops"));
    }

    #[test]
    fn save_find_delete() {
        let s = tmp_store("s");
        let mut p = s.load("offline").unwrap();
        p.name = "conv".into();
        p.program = r"C:\Tools\Conv\conv.exe".into();
        s.save(&p).unwrap();
        let found = s.find_for_program(r"c:/tools/conv/CONV.EXE").unwrap();
        assert_eq!(found.name, "conv");
        assert_eq!(s.suggest_name(r"C:\x\Conv.exe"), "conv-2");
        s.delete("conv").unwrap();
        assert!(s.find_for_program(r"C:\Tools\Conv\conv.exe").is_none());
        p.name = "strict".into();
        assert!(s.save(&p).is_err());
    }

    #[test]
    fn isolated_folders() {
        let s = tmp_store("f");
        let mut p = s.load("strict").unwrap();
        p.name = "games".into();
        p.folder = r"C:\Games\Old".into();
        s.save(&p).unwrap();
        let mut inner = p.clone();
        inner.name = "games-mods".into();
        inner.folder = r"C:\Games\Old\Mods".into();
        s.save(&inner).unwrap();
        let mut exact = p.clone();
        exact.name = "tool".into();
        exact.folder.clear();
        exact.program = r"C:\Games\Old\tool.exe".into();
        s.save(&exact).unwrap();
        assert_eq!(s.find_for_program(r"c:/games/old/bin/game.exe").unwrap().name, "games");
        assert_eq!(
            s.find_for_program(r"C:\Games\Old\Mods\x\m.exe").unwrap().name,
            "games-mods"
        );
        assert_eq!(s.find_for_program(r"C:\Games\Old\tool.exe").unwrap().name, "tool");
        assert!(s.find_for_program(r"C:\Games\Older\a.exe").is_none());
        assert_eq!(s.find_for_folder(r"c:\games\old\").unwrap().name, "games");
        assert_eq!(s.list_folders().len(), 2);
        let n = s.new_folder_profile(r"D:\Work\My Stuff", true).unwrap();
        assert_eq!(n.name, "my-stuff-folder");
        assert_eq!(n.network.mode, NetworkMode::Full);
        assert_eq!(n.devices.clipboard, Clipboard::Full);
        s.save(&n).unwrap();
        assert_eq!(s.find_for_program(r"D:\Work\My Stuff\a\b.exe").unwrap().name, n.name);
        // A child profile never inherits its parent's folder.
        let child = s.resolve_text("name='c'\nextends='games'").unwrap();
        assert!(child.folder.is_empty());
    }

    #[test]
    fn unity_info() {
        assert_eq!(
            unity_app_info("Some Studio\r\nMy Game\r\n"),
            Some(("Some Studio".into(), "My Game".into()))
        );
        assert_eq!(unity_app_info("Co\n..\n"), None);
        assert_eq!(unity_app_info("Co\na\\b\n"), None);
        assert_eq!(unity_app_info("OnlyOne"), None);
    }

    #[test]
    fn under_folder() {
        assert!(path_is_under(r"C:\A\b.exe", r"c:\a"));
        assert!(path_is_under(r"C:\A", r"c:\a\"));
        assert!(!path_is_under(r"C:\AB\b.exe", r"c:\a"));
        assert!(path_is_under(r"D:\x.exe", r"D:\"));
    }

    #[test]
    fn path_keys() {
        assert_eq!(normalize_path_key("\"C:/A/b.exe\""), r"c:\a\b.exe");
        assert_eq!(normalize_path_key(r"\\?\C:\A\"), r"c:\a");
        assert_eq!(file_stem("My App!"), "My-App");
    }

    #[test]
    fn expands_home_and_vars() {
        let home = Path::new("/home/u");
        let var = |k: &str| (k == "APPDATA").then(|| "/ad".to_string());
        assert_eq!(expand_path("~\\Docs", home, var), home.join("Docs"));
        assert_eq!(expand_path("%APPDATA%/x", home, var), PathBuf::from("/ad/x"));
        assert_eq!(expand_path("50%off", home, var), PathBuf::from("50%off"));
        assert_eq!(expand_path("%NOPE%x", home, var), PathBuf::from("%NOPE%x"));
    }
}

//! Unpacking `.msi` packages into a box without Windows Installer.
//!
//! Windows Installer runs as a system service that a sandbox cannot use (and
//! should not: the service works outside it). Instead, Isolated reads the
//! package's tables, places each file where the package says, inside the
//! box, and reads the Start menu shortcuts to learn which programs to offer.
//! No code from the package runs, so custom actions, services, drivers and
//! registry entries are not installed.
//!
//! The package is untrusted input. Parsing is done in memory-safe code, every
//! path is built from cleaned single names under one of the box's folders,
//! and the total size is capped.

use crate::boxes::FoundShortcut;
use crate::cabinet::Cabinet;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Folders inside a box that standard installer folders map to.
#[derive(Debug, Clone)]
pub struct BoxFolders {
    /// `%LOCALAPPDATA%\Programs` as programs in the box see it.
    pub programs: PathBuf,
    /// `%LOCALAPPDATA%` as programs in the box see it.
    pub local_app_data: PathBuf,
    /// The box's user folder (`%USERPROFILE%` inside the box).
    pub home: PathBuf,
}

impl BoxFolders {
    fn app_data(&self) -> PathBuf {
        self.home.join("AppData").join("Roaming")
    }

    fn start_menu(&self) -> PathBuf {
        self.app_data().join(r"Microsoft\Windows\Start Menu")
    }

    /// Where a standard Windows Installer folder property lands, or `None`
    /// for Windows system folders, whose files are left out.
    fn standard(&self, key: &str) -> Option<Option<PathBuf>> {
        let p = match key {
            "TARGETDIR" | "ProgramFilesFolder" | "ProgramFiles64Folder" | "ProgramFiles6432Folder" => {
                self.programs.clone()
            }
            "CommonFilesFolder" | "CommonFiles64Folder" | "CommonFiles6432Folder" => self.programs.join("Common Files"),
            "LocalAppDataFolder" => self.local_app_data.clone(),
            "AppDataFolder" => self.app_data(),
            "CommonAppDataFolder" => self.local_app_data.join("ProgramData"),
            "PersonalFolder" => self.home.join("Documents"),
            "DesktopFolder" => self.home.join("Desktop"),
            "StartMenuFolder" => self.start_menu(),
            "ProgramMenuFolder" => self.start_menu().join("Programs"),
            "TempFolder" => self.local_app_data.join("Temp"),
            // Files for these would change Windows itself, autostart, or
            // apply to every user. They are skipped.
            "SystemFolder" | "System64Folder" | "System16Folder" | "WindowsFolder" | "WindowsVolume"
            | "FontsFolder" | "StartupFolder" | "AdminToolsFolder" | "TemplateFolder" | "SendToFolder"
            | "NetHoodFolder" | "PrintHoodFolder" | "RecentFolder" | "FavoritesFolder" | "MyPicturesFolder" => {
                return Some(None)
            }
            _ => return None,
        };
        Some(Some(p))
    }
}

/// What unpacking produced.
#[derive(Debug, Default)]
pub struct Unpacked {
    /// `ProductName` from the package, if any.
    pub product: String,
    pub files: usize,
    pub bytes: u64,
    /// Files left out because they belong in Windows system folders.
    pub skipped_system: usize,
    /// Start menu and desktop shortcuts the package defines, pointing at
    /// unpacked files.
    pub shortcuts: Vec<FoundShortcut>,
}

/// Limits for untrusted packages.
pub const MAX_TOTAL_BYTES: u64 = 32 << 30;
const MAX_FILES: usize = 200_000;
const MAX_DEPTH: usize = 48;

fn text(row: &::msi::Row, col: &str) -> String {
    if !row.has_column(col) {
        return String::new();
    }
    row[col].as_str().unwrap_or_default().to_string()
}

fn rows<F: Read + std::io::Seek>(pkg: &mut ::msi::Package<F>, table: &str) -> Vec<::msi::Row> {
    if !pkg.has_table(table) {
        return Vec::new();
    }
    match pkg.select_rows(::msi::Select::table(table)) {
        Ok(r) => r.collect(),
        Err(_) => Vec::new(),
    }
}

/// The long name from a `short|long` table value.
fn long_name(s: &str) -> &str {
    s.rsplit('|').next().unwrap_or(s)
}

/// A single file or folder name that is safe to join: no separators, no
/// `..`, no characters Windows rejects, no device names.
pub fn clean_name(raw: &str) -> Option<String> {
    let mut s: String = raw
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 32 => '_',
            c => c,
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let s = s.trim_start().to_string();
    if s.is_empty() || s == "." || s == ".." || s.len() > 255 {
        return None;
    }
    let stem = s.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    const DEVICES: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1",
        "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$", "CONOUT$",
    ];
    if DEVICES.contains(&stem.as_str()) {
        return Some(format!("_{s}"));
    }
    Some(s)
}

struct Dir {
    parent: String,
    default_dir: String,
}

/// Resolves Directory table keys to folders inside the box.
struct Dirs<'a> {
    table: HashMap<String, Dir>,
    folders: &'a BoxFolders,
    cache: HashMap<String, Option<PathBuf>>,
}

impl<'a> Dirs<'a> {
    fn resolve(&mut self, key: &str) -> Option<PathBuf> {
        self.resolve_depth(key, 0)
    }

    fn resolve_depth(&mut self, key: &str, depth: usize) -> Option<PathBuf> {
        if let Some(p) = self.cache.get(key) {
            return p.clone();
        }
        if depth > MAX_DEPTH {
            return None;
        }
        let out = match self.folders.standard(key) {
            Some(p) => p,
            None => match self.table.get(key) {
                None => None,
                Some(d) => {
                    // DefaultDir is `[target:]source`, each `short|long`.
                    let target = d.default_dir.split(':').next().unwrap_or("");
                    let name = long_name(target).to_string();
                    let parent = d.parent.clone();
                    let base = if parent.is_empty() || parent == key {
                        // A root other than TARGETDIR: treat it like TARGETDIR.
                        Some(self.folders.programs.clone())
                    } else {
                        self.resolve_depth(&parent, depth + 1)
                    };
                    match base {
                        None => None,
                        Some(b) if name == "." || name.is_empty() || name.eq_ignore_ascii_case("SourceDir") => Some(b),
                        Some(b) => clean_name(&name).map(|n| b.join(n)),
                    }
                }
            },
        };
        self.cache.insert(key.to_string(), out.clone());
        out
    }
}

/// Simple 64-bit conditions on components, so 32-bit-only copies of a file
/// do not replace the 64-bit ones.
fn component_wanted(condition: &str) -> bool {
    let c: String = condition
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    !matches!(
        c.as_str(),
        "not versionnt64" | "not msix64" | "not (versionnt64)" | "not(versionnt64)"
    )
}

fn under(p: &Path, base: &Path) -> bool {
    let p = crate::profile::normalize_path_key(&p.to_string_lossy());
    let b = crate::profile::normalize_path_key(&base.to_string_lossy());
    p == b || p.starts_with(&format!("{b}\\"))
}

fn key_of(p: &Path) -> String {
    crate::profile::normalize_path_key(&p.to_string_lossy())
}

/// A shortcut target such as `[INSTALLDIR]bin\app.exe`.
fn formatted_dir_path(target: &str, dirs: &mut Dirs) -> Option<PathBuf> {
    let rest = target.strip_prefix('[')?;
    let (key, tail) = rest.split_once(']')?;
    if tail.contains('[') {
        return None;
    }
    let mut p = dirs.resolve(key)?;
    for part in tail.split(['\\', '/']).filter(|s| !s.is_empty()) {
        p = p.join(clean_name(part)?);
    }
    Some(p)
}

/// Unpacks `msi_path` into the box folders. Existing files are replaced.
pub fn unpack(msi_path: &Path, box_root: &Path, folders: &BoxFolders) -> Result<Unpacked, String> {
    let file = fs::File::open(msi_path).map_err(|e| format!("{}: {e}", msi_path.display()))?;
    let mut pkg = ::msi::Package::open(std::io::BufReader::new(file))
        .map_err(|e| format!("This file is not a Windows Installer package ({e})."))?;
    let mut out = Unpacked::default();

    for r in rows(&mut pkg, "Property") {
        if text(&r, "Property") == "ProductName" {
            out.product = text(&r, "Value");
        }
    }

    let mut dirs = Dirs {
        table: rows(&mut pkg, "Directory")
            .iter()
            .map(|r| {
                (
                    text(r, "Directory"),
                    Dir {
                        parent: text(r, "Directory_Parent"),
                        default_dir: text(r, "DefaultDir"),
                    },
                )
            })
            .collect(),
        folders,
        cache: HashMap::new(),
    };

    // Component -> (directory key, key path file, wanted)
    let mut components: HashMap<String, (String, String, bool)> = HashMap::new();
    for r in rows(&mut pkg, "Component") {
        components.insert(
            text(&r, "Component"),
            (
                text(&r, "Directory_"),
                text(&r, "KeyPath"),
                component_wanted(&text(&r, "Condition")),
            ),
        );
    }

    // File key -> destination path.
    let mut dest: HashMap<String, PathBuf> = HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut ordered: Vec<(String, PathBuf)> = Vec::new();
    for r in rows(&mut pkg, "File") {
        let key = text(&r, "File");
        let Some((dir, _, wanted)) = components.get(&text(&r, "Component_")).cloned() else {
            continue;
        };
        let Some(name) = clean_name(long_name(&text(&r, "FileName"))) else {
            continue;
        };
        match dirs.resolve(&dir) {
            None => out.skipped_system += 1,
            Some(_) if !wanted => {}
            Some(folder) => {
                let path = folder.join(name);
                if !under(&path, box_root) {
                    continue;
                }
                let norm = key_of(&path);
                if taken.insert(norm) {
                    dest.insert(key.clone(), path.clone());
                    ordered.push((key, path));
                }
            }
        }
    }
    if ordered.len() > MAX_FILES {
        return Err("This installer has more files than Isolated allows.".into());
    }

    // Embedded cabinets are streams named in the Media table with a `#`.
    let mut cabinets: Vec<String> = Vec::new();
    let mut external = false;
    for r in rows(&mut pkg, "Media") {
        let cab = text(&r, "Cabinet");
        if let Some(stream) = cab.strip_prefix('#') {
            cabinets.push(stream.to_string());
        } else if !cab.is_empty() {
            external = true;
        }
    }

    let mut done: HashSet<String> = HashSet::new();
    let mut budget = MAX_TOTAL_BYTES;
    for name in &cabinets {
        let mut data = Vec::new();
        pkg.read_stream(name)
            .and_then(|mut s| s.read_to_end(&mut data))
            .map_err(|e| format!("Could not read the installer's files ({name}): {e}"))?;
        let cab = Cabinet::parse(&data)?;
        let used = cab.extract(budget, |entry| {
            let Some(path) = dest.get(&entry.name) else {
                return Ok(None);
            };
            if !done.insert(entry.name.clone()) {
                return Ok(None);
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("could not create {}: {e}", parent.display()))?;
            }
            let f = fs::File::create(path).map_err(|e| format!("could not write {}: {e}", path.display()))?;
            out.files += 1;
            out.bytes += entry.size as u64;
            Ok(Some(Box::new(std::io::BufWriter::new(f)) as Box<dyn Write>))
        })?;
        budget = budget.saturating_sub(used);
    }

    let missing = ordered.iter().filter(|(k, _)| !done.contains(k)).count();
    if out.files == 0 {
        return Err(if external || !ordered.is_empty() {
            "This installer keeps its files outside the .msi (next to it, or in .cab files), which Isolated cannot unpack yet.".into()
        } else {
            "This installer does not contain any files Isolated can unpack.".into()
        });
    }
    if missing > 0 && external {
        return Err(format!(
            "{missing} of this installer's files are kept outside the .msi, which Isolated cannot unpack yet."
        ));
    }

    let unpacked_paths: HashSet<String> = dest
        .iter()
        .filter(|(k, _)| done.contains(*k))
        .map(|(_, p)| key_of(p))
        .collect();

    // Shortcuts: the programs to offer. A target is a feature (advertised:
    // use the component's key file) or a formatted path like [#file].
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for r in rows(&mut pkg, "Shortcut") {
        let name = long_name(&text(&r, "Name")).to_string();
        let target = text(&r, "Target");
        let file_key = if let Some(k) = target.strip_prefix("[#").or_else(|| target.strip_prefix("[!")) {
            k.strip_suffix(']').map(str::to_string)
        } else if !target.contains('[') {
            components.get(&text(&r, "Component_")).map(|c| c.1.clone())
        } else {
            None
        };
        let path = match file_key {
            Some(k) if done.contains(&k) => dest.get(&k).cloned(),
            Some(_) => None,
            None => formatted_dir_path(&target, &mut dirs),
        };
        let Some(path) = path.filter(|p| unpacked_paths.contains(&key_of(p))) else {
            continue;
        };
        let args_raw = text(&r, "Arguments");
        // Arguments with [properties] would need the installer to fill them in.
        let args = if args_raw.contains('[') {
            Vec::new()
        } else {
            crate::cmdline::split(&args_raw)
        };
        let t = path.to_string_lossy().into_owned();
        if seen.insert(format!("{name}\u{0}{t}"), ()).is_none() {
            out.shortcuts.push(FoundShortcut { name, target: t, args });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean_name("7zFM.exe").as_deref(), Some("7zFM.exe"));
        assert_eq!(clean_name(".."), None);
        assert_eq!(clean_name("."), None);
        assert_eq!(clean_name("a\\..\\b").as_deref(), Some("a_.._b"));
        assert_eq!(clean_name("x/y").as_deref(), Some("x_y"));
        assert_eq!(clean_name("C:").as_deref(), Some("C_"));
        assert_eq!(clean_name("con.txt").as_deref(), Some("_con.txt"));
        assert_eq!(clean_name("trail. . ").as_deref(), Some("trail"));
        assert_eq!(clean_name("  "), None);
    }

    #[test]
    fn long_names() {
        assert_eq!(long_name("PROGRA~1|Program Files"), "Program Files");
        assert_eq!(long_name("7z.exe"), "7z.exe");
    }

    #[test]
    fn directories_resolve_inside_the_box() {
        let f = BoxFolders {
            programs: PathBuf::from(r"B:\Programs"),
            local_app_data: PathBuf::from(r"B:"),
            home: PathBuf::from(r"B:\Home"),
        };
        let mut table = HashMap::new();
        let mut add = |k: &str, p: &str, d: &str| {
            table.insert(
                k.to_string(),
                Dir {
                    parent: p.into(),
                    default_dir: d.into(),
                },
            )
        };
        add("TARGETDIR", "", "SourceDir");
        add("ProgramFiles64Folder", "TARGETDIR", ".");
        add("INSTALLDIR", "ProgramFiles64Folder", "7-ZIP~1|7-Zip");
        add("Lang", "INSTALLDIR", "Lang");
        add("Evil", "INSTALLDIR", "..");
        add("Loop1", "Loop2", "a");
        add("Loop2", "Loop1", "b");
        add("Sys", "SystemFolder", "x");
        let mut d = Dirs {
            table,
            folders: &f,
            cache: HashMap::new(),
        };
        assert_eq!(
            d.resolve("INSTALLDIR"),
            Some(PathBuf::from(r"B:\Programs").join("7-Zip"))
        );
        assert_eq!(
            d.resolve("Lang"),
            Some(PathBuf::from(r"B:\Programs").join("7-Zip").join("Lang"))
        );
        assert_eq!(d.resolve("Evil"), None);
        assert_eq!(d.resolve("Loop1"), None);
        assert_eq!(d.resolve("Sys"), None);
        assert_eq!(d.resolve("Nope"), None);
    }

    /// Unpacks a real package named by `ISOLATED_TEST_MSI`, if set.
    #[test]
    fn real_package() {
        let Some(msi) = std::env::var_os("ISOLATED_TEST_MSI") else {
            return;
        };
        let root = std::env::temp_dir().join(format!("isolated-msi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let f = BoxFolders {
            programs: root.join("Programs"),
            local_app_data: root.clone(),
            home: root.join("Home"),
        };
        let u = unpack(Path::new(&msi), &root, &f).unwrap();
        eprintln!("{u:#?}");
        assert!(u.files > 0);
        for s in &u.shortcuts {
            assert!(Path::new(&s.target).is_file(), "{}", s.target);
        }
    }

    #[test]
    fn conditions() {
        assert!(component_wanted(""));
        assert!(component_wanted("VersionNT64"));
        assert!(!component_wanted("NOT  VersionNT64"));
    }
}

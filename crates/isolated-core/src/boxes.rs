//! App boxes: sandboxes that keep their files between runs, so users can run
//! an installer inside one and launch the installed programs again later.
//!
//! A box is a small TOML file in `%APPDATA%\Isolated\boxes` naming the
//! profile it runs with and the programs saved in it. The files the programs
//! install live in the box's private folder, which the platform backend owns.

use crate::state::{now_unix, write_atomic, Dirs};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// One saved box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppBox {
    pub name: String,
    /// Profile the box runs with. Its private folders are always kept.
    pub profile: String,
    /// Unix time the box was created.
    pub created: u64,
    /// Programs users can start from the box.
    #[serde(rename = "app")]
    pub apps: Vec<BoxApp>,
}

impl Default for AppBox {
    fn default() -> Self {
        AppBox {
            name: String::new(),
            profile: crate::profile::DEFAULT_PROFILE.into(),
            created: now_unix(),
            apps: Vec::new(),
        }
    }
}

/// A program saved in a box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoxApp {
    /// Name shown to users, usually from the installer's shortcut.
    pub name: String,
    /// Full path of the program inside the box's folder.
    pub path: String,
    /// Arguments the shortcut passed, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

impl AppBox {
    pub fn new(name: &str, profile: &str) -> AppBox {
        AppBox {
            name: name.to_string(),
            profile: profile.to_string(),
            ..AppBox::default()
        }
    }

    fn path(dirs: &Dirs, name: &str) -> PathBuf {
        dirs.boxes().join(format!("{}.toml", crate::profile::file_stem(name)))
    }

    pub fn load(dirs: &Dirs, name: &str) -> Option<AppBox> {
        fs::read_to_string(Self::path(dirs, name))
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
    }

    pub fn exists(dirs: &Dirs, name: &str) -> bool {
        Self::path(dirs, name).exists()
    }

    pub fn save(&self, dirs: &Dirs) -> Result<(), String> {
        check_name(&self.name)?;
        write_atomic(
            &Self::path(dirs, &self.name),
            toml::to_string(self).unwrap_or_default().as_bytes(),
        )
        .map_err(|e| format!("could not save box '{}': {e}", self.name))
    }

    /// Removes the box's file. The backend removes its folder.
    pub fn remove(dirs: &Dirs, name: &str) {
        let _ = fs::remove_file(Self::path(dirs, name));
    }

    /// All boxes, sorted by name.
    pub fn list(dirs: &Dirs) -> Vec<AppBox> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(dirs.boxes()) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("toml") {
                    continue;
                }
                if let Some(b) = fs::read_to_string(&p)
                    .ok()
                    .and_then(|t| toml::from_str::<AppBox>(&t).ok())
                {
                    out.push(b);
                }
            }
        }
        out.sort_by_key(|b| b.name.to_lowercase());
        out
    }

    /// Finds a saved program by name (case-insensitive) or by path.
    pub fn find_app(&self, name_or_path: &str) -> Option<&BoxApp> {
        let key = crate::profile::normalize_path_key(name_or_path);
        self.apps
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name_or_path))
            .or_else(|| {
                self.apps
                    .iter()
                    .find(|a| crate::profile::normalize_path_key(&a.path) == key)
            })
    }

    /// Adds programs not already saved. Returns how many were added.
    pub fn add_apps(&mut self, apps: Vec<BoxApp>) -> usize {
        let mut added = 0;
        for mut a in apps {
            let key = crate::profile::normalize_path_key(&a.path);
            if self
                .apps
                .iter()
                .any(|b| crate::profile::normalize_path_key(&b.path) == key && b.args == a.args)
            {
                continue;
            }
            // Keep names unique so `box run <box> <name>` is unambiguous.
            let base = a.name.clone();
            let mut n = 2;
            while self.apps.iter().any(|b| b.name.eq_ignore_ascii_case(&a.name)) {
                a.name = format!("{base} ({n})");
                n += 1;
            }
            self.apps.push(a);
            added += 1;
        }
        added
    }
}

/// Box names become file names and part of the sandbox identity, so they are
/// kept to letters, digits, spaces, `-`, `_` and `.`.
pub fn check_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("A box needs a name.".into());
    }
    if n.len() > 40 {
        return Err("Box names can be at most 40 characters.".into());
    }
    if !n
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err("Box names can use letters, digits, spaces, '-', '_' and '.'.".into());
    }
    Ok(())
}

/// A box name based on an installer's file name, such as `Firefox` for
/// `Firefox Setup 120.0.exe`, that no existing box uses.
pub fn suggest_name(dirs: &Dirs, installer: &str) -> String {
    let base = name_from_installer(installer);
    if !AppBox::exists(dirs, &base) {
        return base;
    }
    (2..)
        .map(|i| format!("{base} {i}"))
        .find(|n| !AppBox::exists(dirs, n))
        .unwrap()
}

/// Strips installer words and version numbers from a file name.
pub fn name_from_installer(installer: &str) -> String {
    let stem = Path::new(&installer.replace('\\', "/"))
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("app")
        .to_string();
    const NOISE: &[&str] = &[
        "setup",
        "installer",
        "install",
        "x64",
        "x86",
        "win64",
        "win32",
        "win",
        "windows",
        "amd64",
        "arm64",
        "64bit",
        "32bit",
        "64-bit",
        "32-bit",
        "full",
        "online",
        "offline",
        "web",
        "latest",
        "user",
        "release",
    ];
    let words: Vec<String> = stem
        .split([' ', '_', '-', '.', '(', ')'])
        .filter(|w| !w.is_empty())
        .filter(|w| !NOISE.contains(&w.to_ascii_lowercase().as_str()))
        .filter(|w| {
            let w = w.trim_start_matches(['v', 'V']);
            w.is_empty() || !w.chars().all(|c| c.is_ascii_digit())
        })
        .map(|w| {
            w.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect()
        })
        .filter(|w: &String| !w.is_empty())
        .collect();
    let mut name = words.join(" ");
    if name.is_empty() {
        name = "App".into();
    }
    let mut c = name.chars();
    let mut out: String = match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => "App".into(),
    };
    out.truncate(40);
    out.trim().to_string()
}

/// A shortcut the installer created inside the box.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundShortcut {
    /// Shortcut file name without `.lnk`.
    pub name: String,
    pub target: String,
    pub args: Vec<String>,
}

/// A program file the installer created inside the box.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundExe {
    pub path: String,
    pub size: u64,
}

fn is_helper(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const WORDS: &[&str] = &[
        "unins",
        "uninst",
        "setup",
        "install",
        "update",
        "helper",
        "crash",
        "report",
        "elevate",
        "notification",
        "squirrel",
        "vc_redist",
        "vcredist",
        "dxsetup",
        "readme",
        "license",
        "help",
        "website",
        "manual",
    ];
    WORDS.iter().any(|w| n.contains(w))
}

fn depth(p: &str) -> usize {
    p.split(['\\', '/']).count()
}

/// Picks the programs to save after an install: the shortcuts the installer
/// made (skipping uninstallers and help links), or, if it made none, the
/// main-looking programs it wrote.
pub fn choose_apps(shortcuts: &[FoundShortcut], exes: &[FoundExe]) -> Vec<BoxApp> {
    let mut out: Vec<BoxApp> = Vec::new();
    for s in shortcuts {
        let target_lower = s.target.to_ascii_lowercase();
        if !(target_lower.ends_with(".exe") || target_lower.ends_with(".bat") || target_lower.ends_with(".cmd")) {
            continue;
        }
        let target_name = Path::new(&s.target.replace('\\', "/"))
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Squirrel apps start through Update.exe --processStart, which is fine.
        let via_updater = target_name.eq_ignore_ascii_case("update.exe") && !s.args.is_empty();
        if is_helper(&s.name) || (!via_updater && is_helper(&target_name)) {
            continue;
        }
        if out.iter().any(|a| a.path == s.target && a.args == s.args) {
            continue;
        }
        out.push(BoxApp {
            name: s.name.clone(),
            path: s.target.clone(),
            args: s.args.clone(),
        });
    }
    if !out.is_empty() {
        return out;
    }
    let mut candidates: Vec<&FoundExe> = exes
        .iter()
        .filter(|e| {
            let name = Path::new(&e.path.replace('\\', "/"))
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            !is_helper(&name)
        })
        .collect();
    // Shallowest first (the main program usually sits at the top of its
    // install folder), then biggest.
    candidates.sort_by(|a, b| depth(&a.path).cmp(&depth(&b.path)).then(b.size.cmp(&a.size)));
    let Some(top) = candidates.first().map(|c| depth(&c.path)) else {
        return out;
    };
    for c in candidates.into_iter().filter(|c| depth(&c.path) == top).take(3) {
        let name = Path::new(&c.path.replace('\\', "/"))
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "App".into());
        out.push(BoxApp {
            name,
            path: c.path.clone(),
            args: Vec::new(),
        });
    }
    out
}

/// Installer technology, guessed from the installer's bytes, so the right
/// per-user switches can be passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerKind {
    Inno,
    Nsis,
    Other,
}

pub fn detect_installer(head: &[u8]) -> InstallerKind {
    let has = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if has(b"Inno Setup") {
        InstallerKind::Inno
    } else if has(b"Nullsoft") || has(b"NSIS Error") {
        InstallerKind::Nsis
    } else {
        InstallerKind::Other
    }
}

/// Extra arguments that ask an installer to install for the current user
/// only, into `dir` when the installer lets us choose. Users' own arguments
/// come after these, except NSIS's `/D=` which must be last.
pub fn per_user_args(kind: InstallerKind, dir: &str, has_user_args: bool) -> (Vec<String>, Vec<String>) {
    match kind {
        InstallerKind::Inno => (vec!["/CURRENTUSER".into(), format!("/DIR={dir}")], vec![]),
        // `/D=` must be the last argument and is never quoted.
        InstallerKind::Nsis if !has_user_args => (vec![], vec![format!("/D={dir}")]),
        _ => (vec![], vec![]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_from_installers() {
        assert_eq!(name_from_installer(r"C:\D\Firefox Setup 120.0.exe"), "Firefox");
        assert_eq!(name_from_installer("npp.8.6.Installer.x64.exe"), "Npp");
        assert_eq!(name_from_installer("VSCodeUserSetup-x64-1.85.1.exe"), "VSCodeUserSetup");
        assert_eq!(name_from_installer("7z2301-x64.exe"), "7z2301");
        assert_eq!(name_from_installer("setup.exe"), "App");
        assert_eq!(name_from_installer("GIMP_v2.10_setup.msi"), "GIMP");
    }

    #[test]
    fn box_roundtrip() {
        let root = std::env::temp_dir().join(format!("isolated-boxes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dirs = Dirs::under(&root);
        assert!(AppBox::list(&dirs).is_empty());
        let mut b = AppBox::new("My App", "online");
        assert_eq!(
            b.add_apps(vec![
                BoxApp {
                    name: "App".into(),
                    path: r"C:\b\app.exe".into(),
                    args: vec![],
                },
                BoxApp {
                    name: "app".into(),
                    path: r"C:\b\other.exe".into(),
                    args: vec![],
                },
                BoxApp {
                    name: "dup".into(),
                    path: r"c:/B/APP.exe".into(),
                    args: vec![],
                },
            ]),
            2
        );
        assert_eq!(b.apps[1].name, "app (2)");
        b.save(&dirs).unwrap();
        assert_eq!(AppBox::load(&dirs, "My App"), Some(b.clone()));
        assert_eq!(AppBox::list(&dirs), vec![b.clone()]);
        assert_eq!(b.find_app("APP").unwrap().path, r"C:\b\app.exe");
        assert_eq!(b.find_app(r"c:\b\other.exe").unwrap().name, "app (2)");
        assert_eq!(suggest_name(&dirs, "My App.exe"), "My App 2");
        AppBox::remove(&dirs, "My App");
        assert!(AppBox::list(&dirs).is_empty());
        assert!(AppBox::new("bad/name", "strict").save(&dirs).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn chooses_shortcuts_then_exes() {
        let sc = |n: &str, t: &str, a: &[&str]| FoundShortcut {
            name: n.into(),
            target: t.into(),
            args: a.iter().map(|s| s.to_string()).collect(),
        };
        let apps = choose_apps(
            &[
                sc("Notepad++", r"C:\b\npp\notepad++.exe", &[]),
                sc("Uninstall Notepad++", r"C:\b\npp\uninstall.exe", &[]),
                sc(
                    "Discord",
                    r"C:\b\Discord\Update.exe",
                    &["--processStart", "Discord.exe"],
                ),
                sc("Website", r"C:\b\npp\site.url", &[]),
            ],
            &[],
        );
        let names: Vec<&str> = apps.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["Notepad++", "Discord"]);

        let ex = |p: &str, size: u64| FoundExe { path: p.into(), size };
        let apps = choose_apps(
            &[],
            &[
                ex(r"C:\b\Programs\Tool\tool.exe", 5_000_000),
                ex(r"C:\b\Programs\Tool\unins000.exe", 3_000_000),
                ex(r"C:\b\Programs\Tool\bin\worker.exe", 9_000_000),
                ex(r"C:\b\Programs\Tool\crashpad_handler.exe", 1_000),
            ],
        );
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "tool");
        assert!(choose_apps(&[], &[]).is_empty());
    }

    #[test]
    fn installer_kinds_and_args() {
        assert_eq!(detect_installer(b"xx Inno Setup yy"), InstallerKind::Inno);
        assert_eq!(detect_installer(b"Nullsoft Install System"), InstallerKind::Nsis);
        assert_eq!(detect_installer(b"MZ...."), InstallerKind::Other);
        let (pre, post) = per_user_args(InstallerKind::Nsis, r"C:\x y\App", false);
        assert!(pre.is_empty());
        assert_eq!(post, vec![r"/D=C:\x y\App".to_string()]);
        assert!(per_user_args(InstallerKind::Nsis, "d", true).1.is_empty());
        assert_eq!(per_user_args(InstallerKind::Inno, "d", false).0[0], "/CURRENTUSER");
    }
}

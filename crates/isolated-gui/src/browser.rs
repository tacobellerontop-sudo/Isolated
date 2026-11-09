//! The file view of a container: browse the files its apps made, copy them
//! out to the PC, add files from the PC, and start programs that are inside.
//!
//! The window runs outside the sandbox, so it only lists and copies files.
//! It never opens a file with its default program, which would run that
//! program outside the container.

use eframe::egui::{self, Color32, RichText};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Most entries listed in one folder, so huge folders stay responsive.
const MAX_ENTRIES: usize = 3000;

pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

/// What users asked for in the file view; the window carries it out.
pub enum Action {
    Close,
    /// Start a program from the container inside it.
    Run(PathBuf),
    /// Save a program in the container's app list.
    SaveApp(PathBuf),
    Status(String, bool),
}

pub struct Browser {
    pub box_name: String,
    /// The container's base folder; the view never leaves it.
    root: PathBuf,
    dir: PathBuf,
    entries: Vec<Entry>,
    truncated: bool,
    error: Option<String>,
    /// Messages from copies running in the background.
    done: Arc<Mutex<Vec<(String, bool)>>>,
    busy: Arc<Mutex<u32>>,
}

impl Browser {
    /// Opens the view on the container's user folder (`<root>\Home`).
    pub fn new(box_name: &str, root: PathBuf) -> Browser {
        let start = root.join("Home");
        let mut b = Browser {
            box_name: box_name.to_string(),
            dir: if start.is_dir() { start } else { root.clone() },
            root,
            entries: Vec::new(),
            truncated: false,
            error: None,
            done: Arc::new(Mutex::new(Vec::new())),
            busy: Arc::new(Mutex::new(0)),
        };
        b.reload();
        b
    }

    #[cfg(test)]
    fn dir(&self) -> &Path {
        &self.dir
    }

    fn inside(&self, p: &Path) -> bool {
        let key = |p: &Path| isolated_core::profile::normalize_path_key(&p.to_string_lossy());
        let (p, r) = (key(p), key(&self.root));
        p == r || p.starts_with(&format!("{r}\\"))
    }

    fn go(&mut self, dir: PathBuf) {
        if self.inside(&dir) && dir.is_dir() {
            self.dir = dir;
            self.reload();
        }
    }

    pub fn reload(&mut self) {
        self.error = None;
        self.entries.clear();
        self.truncated = false;
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.error = Some(format!("Could not open this folder: {e}"));
                return;
            }
        };
        for e in rd.flatten() {
            if self.entries.len() >= MAX_ENTRIES {
                self.truncated = true;
                break;
            }
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            self.entries.push(Entry {
                name: e.file_name().to_string_lossy().into_owned(),
                path: e.path(),
                is_dir: meta.is_dir(),
                size: if meta.is_dir() { 0 } else { meta.len() },
                modified: meta.modified().ok(),
            });
        }
        self.entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }

    /// Copies `src` into `dest_dir` on a background thread.
    pub fn copy(&self, src: PathBuf, dest_dir: PathBuf, ctx: &egui::Context) {
        let done = self.done.clone();
        let busy = self.busy.clone();
        *busy.lock().unwrap() += 1;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let msg = match isolated_core::boxes::copy_into(&src, &dest_dir) {
                Ok(p) => (format!("Copied {} to {}.", file_name(&src), p.display()), false),
                Err(e) => (e, true),
            };
            done.lock().unwrap().push(msg);
            *busy.lock().unwrap() -= 1;
            ctx.request_repaint();
        });
    }

    /// Adds a file or folder from the PC to the folder being viewed.
    pub fn add_from_pc(&self, src: PathBuf, ctx: &egui::Context) {
        if self.inside(&src) {
            return;
        }
        self.copy(src, self.dir.clone(), ctx);
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Vec<Action> {
        let ctx = ui.ctx().clone();
        let mut actions = Vec::new();
        let finished: Vec<(String, bool)> = std::mem::take(&mut *self.done.lock().unwrap());
        if !finished.is_empty() {
            self.reload();
        }
        for (m, e) in finished {
            actions.push(Action::Status(m, e));
        }
        let busy = *self.busy.lock().unwrap();

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("< Containers").clicked() {
                actions.push(Action::Close);
            }
            ui.heading(format!("Files in {}", self.box_name));
        });
        ui.label(
            RichText::new(
                "These files exist only inside this container. Copy what you made to your PC to use it outside, or drop files here to add them. Start programs with Run here: opening them from Explorer would run them outside the container.",
            )
            .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(6.0);

        // Where we are, as clickable folders from the container's root.
        let mut go_to: Option<PathBuf> = None;
        ui.horizontal_wrapped(|ui| {
            let rel = self.dir.strip_prefix(&self.root).unwrap_or(Path::new("")).to_path_buf();
            if ui.link(&self.box_name).clicked() {
                go_to = Some(self.root.clone());
            }
            let mut acc = self.root.clone();
            for c in rel.components() {
                acc.push(c);
                ui.label(">");
                if ui.link(c.as_os_str().to_string_lossy()).clicked() {
                    go_to = Some(acc.clone());
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            let up = self.dir.parent().map(Path::to_path_buf);
            if ui.add_enabled(self.dir != self.root, egui::Button::new("Up")).clicked() {
                go_to = up;
            }
            for (label, sub) in [
                ("Home", "Home"),
                ("Downloads", r"Home\Downloads"),
                ("Documents", r"Home\Documents"),
                ("Desktop", r"Home\Desktop"),
                ("Programs", "Programs"),
            ] {
                let p = self.root.join(sub);
                if p.is_dir() && ui.button(label).clicked() {
                    go_to = Some(p);
                }
            }
            ui.separator();
            if ui.button("Add file from PC...").clicked() {
                if let Some(p) = isolated_windows::shell::pick_file() {
                    self.add_from_pc(p, &ctx);
                }
            }
            if ui.button("Add folder from PC...").clicked() {
                if let Some(p) = isolated_windows::shell::pick_folder() {
                    self.add_from_pc(p, &ctx);
                }
            }
            if ui
                .button("Open in Explorer")
                .on_hover_text(
                    "Browse this folder in Windows Explorer. Programs opened there run outside the container.",
                )
                .clicked()
            {
                isolated_windows::shell::open(&self.dir.to_string_lossy());
            }
            if ui.button("Refresh").clicked() {
                self.reload();
            }
        });
        if busy > 0 {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Copying...");
            });
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        if let Some(p) = go_to {
            self.go(p);
        }
        ui.add_space(6.0);

        if let Some(e) = &self.error {
            ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
            return actions;
        }
        if self.entries.is_empty() {
            ui.label(RichText::new("This folder is empty.").color(ui.visuals().weak_text_color()));
        }
        let now = SystemTime::now();
        let mut open: Option<PathBuf> = None;
        let mut copy_out: Option<PathBuf> = None;
        egui::Grid::new(("files", &self.dir))
            .num_columns(4)
            .striped(true)
            .spacing([14.0, 4.0])
            .show(ui, |ui| {
                for e in &self.entries {
                    if e.is_dir {
                        if ui.link(format!("{}\\", e.name)).clicked() {
                            open = Some(e.path.clone());
                        }
                        ui.label("");
                    } else {
                        ui.label(&e.name);
                        ui.label(RichText::new(format_size(e.size)).color(ui.visuals().weak_text_color()));
                    }
                    let age = e
                        .modified
                        .and_then(|m| now.duration_since(m).ok())
                        .map(|d| format_age(d.as_secs()))
                        .unwrap_or_default();
                    ui.label(RichText::new(age).color(ui.visuals().weak_text_color()));
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("Copy to PC...")
                            .on_hover_text("Choose a folder on your PC to copy this to")
                            .clicked()
                        {
                            copy_out = Some(e.path.clone());
                        }
                        if !e.is_dir && runnable(&e.name) {
                            if ui
                                .small_button("Run here")
                                .on_hover_text("Start it inside this container")
                                .clicked()
                            {
                                actions.push(Action::Run(e.path.clone()));
                            }
                            if ui
                                .small_button("Save as app")
                                .on_hover_text("Add it to this container's apps so it can be started from the list")
                                .clicked()
                            {
                                actions.push(Action::SaveApp(e.path.clone()));
                            }
                        }
                    });
                    ui.end_row();
                }
            });
        if self.truncated {
            ui.label(format!(
                "Only the first {MAX_ENTRIES} items are shown. Open in Explorer to see all."
            ));
        }
        if let Some(p) = open {
            self.go(p);
        }
        if let Some(src) = copy_out {
            if let Some(dest) = isolated_windows::shell::pick_folder() {
                if self.inside(&dest) {
                    actions.push(Action::Status(
                        "Choose a folder on your PC, outside the container.".into(),
                        true,
                    ));
                } else {
                    self.copy(src, dest, &ctx);
                }
            }
        }
        actions
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn runnable(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".exe", ".bat", ".cmd", ".lnk", ".ps1", ".com"]
        .iter()
        .any(|x| n.ends_with(x))
}

pub fn format_size(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f < K {
        format!("{b} B")
    } else if f < K * K {
        format!("{:.0} KB", f / K)
    } else if f < K * K * K {
        format!("{:.1} MB", f / (K * K))
    } else {
        format!("{:.1} GB", f / (K * K * K))
    }
}

pub fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_ages() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(format_age(10), "just now");
        assert_eq!(format_age(7200), "2 h ago");
        assert_eq!(format_age(3 * 86_400), "3 days ago");
        assert!(runnable("Tool.EXE"));
        assert!(!runnable("photo.png"));
    }

    #[test]
    fn stays_inside_the_container() {
        let root = std::env::temp_dir().join(format!("isolated-browser-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Home").join("Downloads")).unwrap();
        std::fs::write(root.join("Home").join("a.txt"), "hi").unwrap();
        let mut b = Browser::new("Test", root.clone());
        assert_eq!(b.dir(), root.join("Home"));
        assert_eq!(b.entries.len(), 2);
        assert!(b.entries[0].is_dir, "folders come first");
        b.go(root.parent().unwrap().to_path_buf());
        assert_eq!(b.dir(), root.join("Home"), "cannot leave the container");
        b.go(root.join("Home").join("Downloads"));
        assert!(b.entries.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}

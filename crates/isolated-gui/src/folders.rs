//! The small "Choose folders" window shown before an app whose profile asks
//! for folders starts. It returns the folders picked; the caller starts the
//! sandbox with them.

use crate::{file_name, fonts, icon, weak};
use eframe::egui::{self, Color32, RichText};
use isolated_core::state::SharedFolder;
use isolated_windows::shell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What users chose in the folder picker.
#[derive(Debug, Clone)]
pub struct FolderChoice {
    pub folders: Vec<SharedFolder>,
    /// Remember these folders for the next start of this app.
    pub remember: bool,
}

struct Picker {
    target: PathBuf,
    profile: String,
    folders: Vec<SharedFolder>,
    remember: bool,
    error: Option<String>,
    result: Arc<Mutex<Option<FolderChoice>>>,
}

impl Picker {
    fn add(&mut self, path: PathBuf) {
        if !path.is_dir() {
            self.error = Some(format!("{} is not a folder.", path.display()));
            return;
        }
        let s = path.to_string_lossy().into_owned();
        let key = isolated_core::profile::normalize_path_key(&s);
        if self
            .folders
            .iter()
            .any(|f| isolated_core::profile::normalize_path_key(&f.path) == key)
        {
            return;
        }
        match isolated_windows::check_shared_folder(&s, false) {
            Ok(()) => {
                self.folders.push(SharedFolder { path: s, write: false });
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn check_all(&self) -> Result<(), String> {
        for f in &self.folders {
            isolated_windows::check_shared_folder(&f.path, f.write)?;
        }
        Ok(())
    }
}

impl eframe::App for Picker {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        for p in dropped {
            self.add(p);
        }
        let mut run = false;
        let mut cancel = false;
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new(file_name(&self.target)).size(18.0).strong());
            ui.label(weak(ui, format!("Profile: {}", self.profile)));
            ui.add_space(6.0);
            ui.label("Pick the folders this app can see. Everything else on your computer stays hidden from it.");
            ui.label(weak(
                ui,
                "Tick \"Can change files\" only for folders the app needs to save into. You can also drop folders on this window.",
            ));
            ui.add_space(8.0);
            egui::ScrollArea::vertical().max_height(220.0).auto_shrink([false, true]).show(ui, |ui| {
                if self.folders.is_empty() {
                    ui.label(weak(ui, "No folders yet: the app will only see its own private folders."));
                }
                let mut remove = None;
                for (i, f) in self.folders.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut f.write, "Can change files");
                        if ui.small_button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.monospace(&f.path);
                    });
                }
                if let Some(i) = remove {
                    self.folders.remove(i);
                }
            });
            ui.add_space(6.0);
            if ui.button("Add folder...").clicked() {
                if let Some(p) = shell::pick_folder() {
                    self.add(p);
                }
            }
            ui.add_space(8.0);
            ui.checkbox(&mut self.remember, "Offer these folders again next time");
            if let Some(e) = &self.error {
                ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Run").strong()).clicked() {
                    run = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if run {
            match self.check_all() {
                Ok(()) => {
                    *self.result.lock().unwrap() = Some(FolderChoice {
                        folders: self.folders.clone(),
                        remember: self.remember,
                    });
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Err(e) => self.error = Some(e),
            }
        }
        if cancel {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

/// Shows the folder picker and waits for it to close. Returns `None` if
/// users cancelled.
pub fn ask_folders(target: &Path, profile: &str, initial: Vec<SharedFolder>) -> Result<Option<FolderChoice>, String> {
    let result = Arc::new(Mutex::new(None));
    // Folders that have gone missing since last time are dropped quietly.
    let folders: Vec<SharedFolder> = initial.into_iter().filter(|f| Path::new(&f.path).is_dir()).collect();
    let picker = Picker {
        target: target.to_path_buf(),
        profile: profile.to_string(),
        folders,
        remember: true,
        error: None,
        result: result.clone(),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("Choose folders: {}", file_name(target)))
            .with_inner_size([560.0, 420.0])
            .with_min_inner_size([420.0, 300.0])
            .with_icon(Arc::new(icon::app_icon()))
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "Isolated folders",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            Ok(Box::new(picker))
        }),
    )
    .map_err(|e| format!("Could not open the Isolated window: {e}"))?;
    let out = result.lock().unwrap().take();
    Ok(out)
}

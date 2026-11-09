//! The Isolated window: app profiles, containers (boxes) with their installed
//! apps and files, the profile editor, running sandboxes, settings, the update banner, and the "Run with
//! options" dialog.
//!
//! The window only opens when users ask for it. Sandboxes are always started
//! as a separate `isolated.exe run` process, so closing the window never
//! affects them.

#![forbid(unsafe_code)]

use eframe::egui::{self, Color32, RichText};
use isolated_core::boxes::{AppBox, BoxApp};
use isolated_core::profile::{ProfileEntry, ProfileStore};
use isolated_core::state::{now_unix, RunningEntry};
use isolated_core::{Clipboard, Dirs, Gap, NetworkMode, Policy, Settings, Severity, Tier};
use isolated_windows::update::{self, Release};
use isolated_windows::{install, menu, shell, Stats};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod browser;
mod folders;
mod fonts;
mod icon;

pub use folders::{ask_folders, FolderChoice};

/// What the window opens on.
#[derive(Debug, Clone)]
pub enum Start {
    Home,
    /// Edit (or create) the profile for this program.
    EditFor(PathBuf),
    /// The compact "Run in Isolated with options..." dialog for this target.
    Options(PathBuf),
    /// The installed apps view with the install form filled in for this
    /// installer.
    Install(PathBuf),
}

pub fn run(start: Start) -> Result<(), String> {
    let (title, size) = match &start {
        Start::Options(t) => (format!("Run in Isolated: {}", file_name(t)), [520.0, 640.0]),
        _ => ("Isolated".to_string(), [880.0, 620.0]),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(&title)
            .with_inner_size(size)
            .with_min_inner_size([480.0, 380.0])
            .with_icon(Arc::new(icon::app_icon()))
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "Isolated",
        options,
        Box::new(move |cc| {
            fonts::install(&cc.egui_ctx);
            Ok(Box::new(App::new(&cc.egui_ctx, start)))
        }),
    )
    .map_err(|e| format!("Could not open the Isolated window: {e}"))
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Apps,
    Installed,
    Running,
    Settings,
}

#[derive(Debug, Clone)]
enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Available(Release),
    Downloading { got: u64, total: Option<u64> },
    Ready(PathBuf, String),
    Failed(String),
}

/// The profile being edited.
struct Editor {
    policy: Policy,
    /// Name of the saved profile this edits, if any.
    original: Option<String>,
    new_ro: String,
    new_rw: String,
    allow_text: String,
    error: Option<String>,
}

impl Editor {
    fn new(policy: Policy, original: Option<String>) -> Editor {
        let allow_text = policy.network.allow.join("\n");
        Editor {
            policy,
            original,
            new_ro: String::new(),
            new_rw: String::new(),
            allow_text,
            error: None,
        }
    }

    fn sync(&mut self) {
        self.policy.network.allow = self
            .allow_text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
    }
}

/// The "Install an app" form.
struct InstallForm {
    installer: String,
    /// Box to install into; a new box is created if no box has this name.
    box_name: String,
    /// Profile for a new box.
    profile: String,
    net: bool,
    /// Close the window once the install starts (opened from the right-click menu).
    close_after: bool,
    error: Option<String>,
}

/// The "New container" form.
struct NewContainer {
    name: String,
    profile: String,
    internet: bool,
    error: Option<String>,
}

/// State of the "with options" dialog.
struct OptionsDialog {
    target: PathBuf,
    base: String,
    editor: Editor,
    accept_weaker: bool,
}

struct App {
    dirs: Dirs,
    store: ProfileStore,
    settings: Settings,
    view: View,
    user: Vec<ProfileEntry>,
    bad: Vec<(PathBuf, String)>,
    builtin: Vec<ProfileEntry>,
    editor: Option<Editor>,
    options: Option<OptionsDialog>,
    running: Vec<(RunningEntry, Option<Stats>)>,
    last_refresh: Option<Instant>,
    update: Arc<Mutex<UpdateState>>,
    status: Option<(String, bool, Instant)>,
    confirm_delete: Option<String>,
    menu_exe: Option<PathBuf>,
    boxes: Vec<AppBox>,
    install: Option<InstallForm>,
    confirm_delete_box: Option<String>,
    new_container: Option<NewContainer>,
    browser: Option<browser::Browser>,
    /// Whether each box's apps can reach the internet, refreshed with the list.
    box_net: std::collections::HashMap<String, bool>,
}

impl App {
    fn new(ctx: &egui::Context, start: Start) -> App {
        let dirs = Dirs::standard();
        let store = ProfileStore::new(dirs.profiles());
        let settings = Settings::load(&dirs);
        let mut app = App {
            builtin: store.list_builtin(),
            store,
            settings,
            view: View::Apps,
            user: Vec::new(),
            bad: Vec::new(),
            editor: None,
            options: None,
            running: Vec::new(),
            last_refresh: None,
            update: Arc::new(Mutex::new(UpdateState::Idle)),
            status: None,
            confirm_delete: None,
            menu_exe: menu::registered_exe(),
            boxes: Vec::new(),
            install: None,
            confirm_delete_box: None,
            new_container: None,
            browser: None,
            box_net: Default::default(),
            dirs,
        };
        app.reload_boxes();
        app.reload_profiles();
        let _ = isolated_windows::repair(&app.dirs);
        match start {
            Start::Home => {}
            Start::Install(target) => {
                app.open_install_form(&target.to_string_lossy(), None);
                if let Some(f) = app.install.as_mut() {
                    f.close_after = true;
                }
            }
            Start::EditFor(target) => app.edit_for_program(&target),
            Start::Options(target) => {
                let (base, policy) = app.policy_for(&target);
                app.options = Some(OptionsDialog {
                    target,
                    base,
                    editor: Editor::new(policy, None),
                    accept_weaker: false,
                });
            }
        }
        if app.options.is_none() && app.settings.check_for_updates {
            app.check_updates(ctx, false);
        }
        app
    }

    fn reload_profiles(&mut self) {
        let (user, bad) = self.store.list_user();
        self.user = user;
        self.bad = bad;
    }

    fn set_status(&mut self, msg: impl Into<String>, error: bool) {
        self.status = Some((msg.into(), error, Instant::now()));
    }

    /// The saved profile for a program, or the default profile.
    fn policy_for(&self, target: &Path) -> (String, Policy) {
        let t = target.to_string_lossy();
        if let Some(p) = self.store.find_for_program(&t) {
            return (p.name.clone(), p);
        }
        let name = self.settings.default_profile.clone();
        let p = self
            .store
            .load(&name)
            .or_else(|_| self.store.load(isolated_core::profile::DEFAULT_PROFILE))
            .unwrap_or_default();
        (p.name.clone(), p)
    }

    fn new_profile_for(&self, program: &Path) -> Policy {
        let mut p = self
            .store
            .load(&self.settings.default_profile)
            .or_else(|_| self.store.load(isolated_core::profile::DEFAULT_PROFILE))
            .unwrap_or_default();
        let base = p.name.clone();
        p.extends = Some(base);
        p.program = program.to_string_lossy().into_owned();
        p.name = self.store.suggest_name(&p.program);
        p.description = String::new();
        p
    }

    fn edit_for_program(&mut self, program: &Path) {
        self.view = View::Apps;
        match self.store.find_for_program(&program.to_string_lossy()) {
            Some(p) => {
                let name = p.name.clone();
                self.editor = Some(Editor::new(p, Some(name)));
            }
            None => self.editor = Some(Editor::new(self.new_profile_for(program), None)),
        }
    }

    fn check_updates(&mut self, ctx: &egui::Context, manual: bool) {
        let state = self.update.clone();
        *state.lock().unwrap() = UpdateState::Checking;
        self.settings.last_update_check = now_unix();
        let _ = self.settings.save(&self.dirs);
        let skipped = if manual {
            String::new()
        } else {
            self.settings.skipped_version.clone()
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let next = match update::check() {
                Ok(Some(r)) if r.version != skipped => UpdateState::Available(r),
                Ok(_) => {
                    if manual {
                        UpdateState::UpToDate
                    } else {
                        UpdateState::Idle
                    }
                }
                Err(e) => {
                    if manual {
                        UpdateState::Failed(e)
                    } else {
                        UpdateState::Idle
                    }
                }
            };
            *state.lock().unwrap() = next;
            ctx.request_repaint();
        });
    }

    fn start_update(&mut self, ctx: &egui::Context, release: Release) {
        let state = self.update.clone();
        *state.lock().unwrap() = UpdateState::Downloading {
            got: 0,
            total: Some(release.size),
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let st = state.clone();
            let c2 = ctx.clone();
            let result = update::install(&release, move |got, total| {
                *st.lock().unwrap() = UpdateState::Downloading { got, total };
                c2.request_repaint();
            });
            *state.lock().unwrap() = match result {
                Ok(exe) => UpdateState::Ready(exe, release.version.clone()),
                Err(e) => UpdateState::Failed(e),
            };
            ctx.request_repaint();
        });
    }

    fn run_profile(&mut self, policy: &Policy) {
        if policy.program.is_empty() {
            self.set_status("This profile has no program. Edit it and choose one.", true);
            return;
        }
        match isolated_windows::spawn_self(&["run", "--profile", &policy.name, "--", &policy.program]) {
            Ok(()) => self.set_status(
                format!("Started {} in a sandbox.", file_name(Path::new(&policy.program))),
                false,
            ),
            Err(e) => self.set_status(e, true),
        }
    }

    fn refresh_running(&mut self) {
        let due = self
            .last_refresh
            .is_none_or(|t| t.elapsed() > Duration::from_millis(1000));
        if due {
            self.reload_boxes();
            self.running = isolated_windows::running(&self.dirs)
                .into_iter()
                .map(|e| {
                    let s = isolated_windows::stats(&e);
                    (e, s)
                })
                .collect();
            self.last_refresh = Some(Instant::now());
        }
    }

    fn reload_boxes(&mut self) {
        self.boxes = AppBox::list(&self.dirs);
        self.box_net = self
            .boxes
            .iter()
            .map(|b| {
                (
                    b.name.clone(),
                    b.has_internet(&self.store.load(&b.profile).unwrap_or_default()),
                )
            })
            .collect();
    }

    /// The policy a box's apps run with.
    fn box_policy(&self, b: &AppBox) -> Policy {
        let mut p = self.store.load(&b.profile).unwrap_or_default();
        b.apply(&mut p);
        p
    }

    fn open_box_files(&mut self, name: &str) {
        let Some(b) = self.boxes.iter().find(|b| b.name == name).cloned() else {
            return;
        };
        match isolated_windows::boxes::folder(&self.box_policy(&b), &b.name) {
            Ok(f) => {
                self.install = None;
                self.new_container = None;
                self.browser = Some(browser::Browser::new(&b.name, f));
            }
            Err(e) => self.set_status(e, true),
        }
    }

    fn create_container(&mut self) {
        let Some(f) = self.new_container.as_mut() else { return };
        let name = f.name.trim().to_string();
        let checked = isolated_core::boxes::check_name(&name).and_then(|_| {
            if AppBox::exists(&self.dirs, &name) {
                Err(format!("A container named '{name}' already exists."))
            } else {
                Ok(())
            }
        });
        if let Err(e) = checked {
            f.error = Some(
                e.replace("Box names", "Container names")
                    .replace("A box", "A container"),
            );
            return;
        }
        let mut b = AppBox::new(&name, &f.profile);
        b.internet = Some(f.internet);
        let internet = f.internet;
        let mut policy = self.store.load(&b.profile).unwrap_or_default();
        b.apply(&mut policy);
        let made = isolated_windows::boxes::folder(&policy, &b.name).and_then(|_| b.save(&self.dirs));
        match made {
            Ok(()) => {
                self.new_container = None;
                self.reload_boxes();
                self.set_status(
                    format!(
                        "Created container '{name}' ({}). Install an app into it, run a program in it, or open its command prompt.",
                        if internet { "internet allowed" } else { "no internet" }
                    ),
                    false,
                );
            }
            Err(e) => {
                if let Some(f) = self.new_container.as_mut() {
                    f.error = Some(e);
                }
            }
        }
    }

    fn set_box_internet(&mut self, name: &str, on: bool) {
        if let Some(mut b) = AppBox::load(&self.dirs, name) {
            b.internet = Some(on);
            match b.save(&self.dirs) {
                Ok(()) => {
                    let running = isolated_windows::boxes::in_use(&self.dirs, name);
                    self.set_status(
                        format!(
                            "Internet for '{name}' is now {}.{}",
                            if on { "allowed" } else { "blocked" },
                            if running {
                                " Apps already running keep the old setting until they are restarted."
                            } else {
                                ""
                            }
                        ),
                        false,
                    );
                }
                Err(e) => self.set_status(e, true),
            }
        }
        self.reload_boxes();
    }

    fn save_box_program(&mut self, name: &str, p: &Path) {
        if let Some(mut b) = AppBox::load(&self.dirs, name) {
            let app = BoxApp {
                name: p
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "App".into()),
                path: p.to_string_lossy().into_owned(),
                args: Vec::new(),
            };
            let added = b.add_apps(vec![app]);
            match b.save(&self.dirs) {
                Ok(()) if added == 0 => {
                    self.set_status(format!("{} is already in '{name}'s apps.", file_name(p)), false)
                }
                Ok(()) => self.set_status(format!("Saved {} in container '{name}'.", file_name(p)), false),
                Err(e) => self.set_status(e, true),
            }
            self.last_refresh = None;
        }
    }

    fn run_in_box(&mut self, name: &str, p: &Path) {
        let path = p.to_string_lossy().into_owned();
        match isolated_windows::spawn_self(&["box", "run", name, &path]) {
            Ok(()) => self.set_status(format!("Started {} in container '{name}'.", file_name(p)), false),
            Err(e) => self.set_status(e, true),
        }
    }

    fn add_dropped_or_picked(&mut self, path: PathBuf) {
        let is_msi = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("msi"));
        if self.view == View::Installed || is_msi {
            self.open_install_form(&path.to_string_lossy(), None);
        } else {
            self.edit_for_program(&path);
        }
    }

    /// Opens the install form, into `into` or a new box named after the installer.
    fn open_install_form(&mut self, installer: &str, into: Option<&str>) {
        self.view = View::Installed;
        self.editor = None;
        self.browser = None;
        self.new_container = None;
        let box_name = match into {
            Some(b) => b.to_string(),
            None if installer.is_empty() => String::new(),
            None => isolated_core::boxes::suggest_name(&self.dirs, installer),
        };
        self.install = Some(InstallForm {
            installer: installer.to_string(),
            box_name,
            profile: self.settings.default_profile.clone(),
            net: true,
            close_after: false,
            error: None,
        });
    }

    fn start_install(&mut self, ctx: &egui::Context) {
        let Some(f) = self.install.as_mut() else { return };
        let installer = f.installer.trim().trim_matches('"').to_string();
        let box_name = f.box_name.trim().to_string();
        let checked = isolated_core::boxes::check_name(&box_name).and_then(|_| {
            if Path::new(&installer).is_file() {
                Ok(())
            } else {
                Err("Choose an installer file (.exe or .msi).".to_string())
            }
        });
        if let Err(e) = checked {
            f.error = Some(e);
            return;
        }
        let mut args: Vec<String> = vec!["box".into(), "install".into(), "--box".into(), box_name.clone()];
        if !AppBox::exists(&self.dirs, &box_name) {
            args.push("--profile".into());
            args.push(f.profile.clone());
        }
        args.push(if f.net { "--net" } else { "--no-net" }.into());
        args.push("--".into());
        args.push(installer.clone());
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match isolated_windows::spawn_self(&refs) {
            Ok(()) => {
                let close = f.close_after;
                self.install = None;
                self.set_status(
                    format!(
                        "Installing {} into container '{box_name}'. A message appears when the installer has finished.",
                        file_name(Path::new(&installer))
                    ),
                    false,
                );
                if close {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
            Err(e) => f.error = Some(e),
        }
    }

    fn run_box_app(&mut self, b: &AppBox, a: &BoxApp) {
        match isolated_windows::spawn_self(&["box", "run", &b.name, &a.path]) {
            Ok(()) => self.set_status(format!("Started {} from container '{}'.", a.name, b.name), false),
            Err(e) => self.set_status(e, true),
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.options.is_some() {
            self.options_ui(ui, &ctx);
            return;
        }

        // Programs dropped on the window get a profile.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        match self
            .browser
            .as_ref()
            .filter(|_| self.view == View::Installed && self.editor.is_none())
        {
            // Files dropped on a container's file view are copied into it.
            Some(b) => {
                for p in dropped {
                    b.add_from_pc(p, &ctx);
                }
            }
            None => {
                if let Some(p) = dropped.into_iter().next() {
                    self.add_dropped_or_picked(p);
                }
            }
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Isolated").size(20.0).strong());
                ui.add_space(16.0);
                for (v, label) in [
                    (View::Apps, "Apps"),
                    (View::Installed, "Containers"),
                    (View::Running, "Running"),
                    (View::Settings, "Settings"),
                ] {
                    let text = if v == View::Running && !self.running.is_empty() {
                        format!("{label} ({})", self.running.len())
                    } else {
                        label.to_string()
                    };
                    if ui.selectable_label(self.view == v, text).clicked() {
                        if v == View::Installed && self.view == View::Installed {
                            self.browser = None;
                        }
                        self.view = v;
                        self.editor = None;
                    }
                }
            });
            ui.add_space(4.0);
            self.update_banner(ui, &ctx);
        });

        if let Some((msg, error, at)) = self.status.clone() {
            if at.elapsed() < Duration::from_secs(8) {
                egui::Panel::bottom("status").show(ui, |ui| {
                    let color = if error {
                        Color32::from_rgb(220, 80, 70)
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.add_space(3.0);
                    ui.label(RichText::new(msg).color(color));
                    ui.add_space(3.0);
                });
                ctx.request_repaint_after(Duration::from_secs(1));
            } else {
                self.status = None;
            }
        }

        // Keep the running count fresh on every view.
        self.refresh_running();
        ctx.request_repaint_after(Duration::from_millis(1000));

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                if self.editor.is_some() {
                    self.editor_ui(ui);
                    return;
                }
                match self.view {
                    View::Apps => self.apps_ui(ui),
                    View::Installed => self.installed_ui(ui, &ctx),
                    View::Running => self.running_ui(ui),
                    View::Settings => self.settings_ui(ui, &ctx),
                }
            });
        });
    }
}

fn weak(ui: &egui::Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into()).color(ui.visuals().weak_text_color())
}

fn gap_ui(ui: &mut egui::Ui, gaps: &[Gap]) {
    for g in gaps {
        let (prefix, color) = match g.severity {
            Severity::Weaker => ("Weaker: ", Color32::from_rgb(220, 120, 40)),
            Severity::Notice => ("Note: ", ui.visuals().weak_text_color()),
        };
        ui.label(RichText::new(format!("{prefix}{}", g.message)).color(color).small());
    }
}

fn summary(p: &Policy) -> String {
    let net = match p.network.mode {
        NetworkMode::None => "no network",
        NetworkMode::Loopback => "loopback",
        NetworkMode::Full => "internet",
        NetworkMode::Allowlist => "allowlist",
    };
    let clip = match p.devices.clipboard {
        Clipboard::None => "no clipboard",
        Clipboard::Read => "paste only",
        Clipboard::Write => "copy only",
        Clipboard::Full => "clipboard",
    };
    let folders = p.filesystem.read_only.len() + p.filesystem.read_write.len();
    let mut s = format!(
        "{net} · {clip} · {folders} folder{}",
        if folders == 1 { "" } else { "s" }
    );
    if p.filesystem.ask_for_folders {
        s.push_str(" · asks for folders");
    }
    if p.tier == Tier::Compatible {
        s.push_str(" · compatible tier");
    }
    s
}

impl App {
    fn update_banner(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let state = self.update.lock().unwrap().clone();
        match state {
            UpdateState::Available(r) => {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("Isolated {} is available.", r.version)).strong());
                        if ui.button("Update now").clicked() {
                            self.start_update(ctx, r.clone());
                        }
                        if ui.button("What's new").clicked() {
                            shell::open(&r.page_url);
                        }
                        if ui.button("Skip this version").clicked() {
                            self.settings.skipped_version = r.version.clone();
                            let _ = self.settings.save(&self.dirs);
                            *self.update.lock().unwrap() = UpdateState::Idle;
                        }
                    });
                });
            }
            UpdateState::Downloading { got, total } => {
                ui.horizontal(|ui| {
                    ui.label("Downloading update...");
                    let frac = total.filter(|t| *t > 0).map(|t| got as f32 / t as f32).unwrap_or(0.0);
                    ui.add(
                        egui::ProgressBar::new(frac.clamp(0.0, 1.0))
                            .desired_width(200.0)
                            .show_percentage(),
                    );
                });
            }
            UpdateState::Ready(exe, version) => {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("Isolated {version} is installed.")).strong());
                        if ui.button("Restart now").clicked() {
                            let _ = std::process::Command::new(&exe).spawn();
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        ui.label(weak(ui, "Running sandboxes are not affected."));
                    });
                });
            }
            UpdateState::Failed(e) => {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("Update failed: {e}")).color(Color32::from_rgb(220, 80, 70)));
                    if ui.small_button("Dismiss").clicked() {
                        *self.update.lock().unwrap() = UpdateState::Idle;
                    }
                });
            }
            _ => {}
        }
    }

    fn apps_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Your apps");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Add app...").clicked() {
                    if let Some(p) = shell::pick_program() {
                        self.add_dropped_or_picked(p);
                    }
                }
            });
        });
        ui.label(weak(
            ui,
            "Right-click any program in Explorer and choose Run in Isolated, or drop a program here to give it its own profile.",
        ));
        ui.add_space(8.0);

        if self.user.is_empty() {
            ui.label("No app profiles yet. Programs without a profile run with the default profile.");
        }
        let mut run = None;
        let mut edit = None;
        for e in &self.user {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&e.policy.name).strong());
                        if !e.policy.program.is_empty() {
                            ui.label(weak(ui, &e.policy.program));
                        }
                        ui.label(weak(ui, summary(&e.policy)).small());
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Delete").clicked() {
                            self.confirm_delete = Some(e.policy.name.clone());
                        }
                        if ui.button("Edit").clicked() {
                            edit = Some(e.policy.clone());
                        }
                        if ui
                            .add_enabled(!e.policy.program.is_empty(), egui::Button::new("Run"))
                            .clicked()
                        {
                            run = Some(e.policy.clone());
                        }
                    });
                });
                if self.confirm_delete.as_deref() == Some(e.policy.name.as_str()) {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "Delete the profile '{}'? The app itself is not touched.",
                            e.policy.name
                        ));
                        if ui.button("Delete profile").clicked() {
                            let r = self.store.delete(&e.policy.name);
                            self.confirm_delete = None;
                            if let Err(err) = r {
                                self.status = Some((err, true, Instant::now()));
                            }
                        }
                        if ui.button("Keep").clicked() {
                            self.confirm_delete = None;
                        }
                    });
                }
            });
            ui.add_space(4.0);
        }
        if let Some(p) = run {
            self.run_profile(&p);
        }
        if let Some(p) = edit {
            let name = p.name.clone();
            self.editor = Some(Editor::new(p, Some(name)));
        }
        self.reload_profiles();

        for (path, err) in &self.bad {
            ui.label(
                RichText::new(format!("Could not read {}: {err}", path.display()))
                    .color(Color32::from_rgb(220, 80, 70)),
            );
        }

        ui.add_space(12.0);
        egui::CollapsingHeader::new("Built-in profiles")
            .default_open(false)
            .show(ui, |ui| {
                let mut dup = None;
                for e in &self.builtin {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&e.policy.name).strong());
                        ui.label(weak(ui, &e.policy.description));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Use as template").clicked() {
                                dup = Some(e.policy.clone());
                            }
                        });
                    });
                }
                if let Some(mut p) = dup {
                    p.extends = Some(p.name.clone());
                    p.name = self.store.suggest_name(&format!("my-{}", p.name));
                    p.description.clear();
                    self.editor = Some(Editor::new(p, None));
                }
            });
    }

    fn installed_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Some(mut br) = self.browser.take() {
            let actions = br.ui(ui);
            let name = br.box_name.clone();
            let mut keep = true;
            for a in actions {
                match a {
                    browser::Action::Close => keep = false,
                    browser::Action::Run(p) => self.run_in_box(&name, &p),
                    browser::Action::SaveApp(p) => self.save_box_program(&name, &p),
                    browser::Action::Status(m, e) => self.set_status(m, e),
                }
            }
            if keep && self.browser.is_none() {
                self.browser = Some(br);
            }
            return;
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Containers");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Install an app...").clicked() {
                    if let Some(p) = shell::pick_installer() {
                        self.open_install_form(&p.to_string_lossy(), None);
                    }
                }
                if ui.button("New container...").clicked() {
                    self.install = None;
                    let profile = if self.store.load("online").is_ok() {
                        "online".to_string()
                    } else {
                        self.settings.default_profile.clone()
                    };
                    self.new_container = Some(NewContainer {
                        name: String::new(),
                        profile,
                        internet: true,
                        error: None,
                    });
                }
            });
        });
        ui.label(weak(
            ui,
            "A container is a separate space with its own files. Apps you install, download or run in it keep their settings there, and everything they save stays inside it instead of on your PC. Open its files to take out what you made. Right-click an installer and choose Install in Isolated, or drop one here.",
        ));
        ui.add_space(8.0);

        if self.new_container.is_some() {
            self.new_container_ui(ui);
            ui.add_space(8.0);
        }
        if self.install.is_some() {
            self.install_form_ui(ui, ctx);
            ui.add_space(8.0);
        }

        if self.boxes.is_empty() && self.install.is_none() && self.new_container.is_none() {
            ui.label("No containers yet. Make one with New container, or install an app.");
        }
        let running: Vec<String> = self.running.iter().map(|(e, _)| e.container.clone()).collect();
        let mut run: Option<(AppBox, BoxApp)> = None;
        let mut forget: Option<(String, String)> = None;
        let mut install_into: Option<String> = None;
        let mut run_program: Option<String> = None;
        let mut open_files: Option<String> = None;
        let mut open_shell: Option<String> = None;
        let mut set_net: Option<(String, bool)> = None;
        let mut delete: Option<String> = None;
        for b in &self.boxes {
            let in_use = running.contains(&isolated_windows::boxes::container_name(&b.name));
            let net = self.box_net.get(&b.name).copied().unwrap_or(false);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&b.name).strong());
                    let mut on = net;
                    if ui
                        .checkbox(&mut on, "Internet")
                        .on_hover_text("Let apps in this container reach the internet")
                        .changed()
                    {
                        set_net = Some((b.name.clone(), on));
                    }
                    let profile = format!("profile {}", b.profile);
                    ui.label(weak(ui, profile).small());
                    if in_use {
                        ui.label(RichText::new("running").small().color(Color32::from_rgb(80, 160, 90)));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Delete").clicked() {
                            self.confirm_delete_box = Some(b.name.clone());
                        }
                        if ui.small_button("Install an app here...").clicked() {
                            install_into = Some(b.name.clone());
                        }
                        if ui
                            .small_button("Run a program...")
                            .on_hover_text("Start any program or script inside this container (it runs with the container's files)")
                            .clicked()
                        {
                            run_program = Some(b.name.clone());
                        }
                        if ui
                            .small_button("Command prompt")
                            .on_hover_text("Open a command prompt inside this container. Everything started from it stays in the container.")
                            .clicked()
                        {
                            open_shell = Some(b.name.clone());
                        }
                        if ui
                            .button(RichText::new("Open files").strong())
                            .on_hover_text("Browse this container's files and copy out what its apps made")
                            .clicked()
                        {
                            open_files = Some(b.name.clone());
                        }
                    });
                });
                if b.apps.is_empty() {
                    ui.label(weak(ui, "No apps saved in this container yet."));
                }
                for a in &b.apps {
                    ui.horizontal(|ui| {
                        if ui.button("Run").clicked() {
                            run = Some((b.clone(), a.clone()));
                        }
                        ui.label(&a.name).on_hover_text(&a.path);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .small_button("Remove")
                                .on_hover_text("Remove from this list. The app's files stay in the container.")
                                .clicked()
                            {
                                forget = Some((b.name.clone(), a.path.clone()));
                            }
                        });
                    });
                }
                if self.confirm_delete_box.as_deref() == Some(b.name.as_str()) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!(
                            "Delete container '{}' and everything in it, including its apps, their settings and the files they made?",
                            b.name
                        ));
                        if ui.button("Delete container").clicked() {
                            delete = Some(b.name.clone());
                        }
                        if ui.button("Keep").clicked() {
                            self.confirm_delete_box = None;
                        }
                    });
                }
            });
            ui.add_space(4.0);
        }

        if let Some((b, a)) = run {
            self.run_box_app(&b, &a);
        }
        if let Some((name, path)) = forget {
            if let Some(mut b) = AppBox::load(&self.dirs, &name) {
                b.apps.retain(|a| a.path != path);
                if let Err(e) = b.save(&self.dirs) {
                    self.set_status(e, true);
                }
            }
            self.last_refresh = None;
        }
        if let Some(name) = install_into {
            match shell::pick_installer() {
                Some(p) => self.open_install_form(&p.to_string_lossy(), Some(&name)),
                None => self.open_install_form("", Some(&name)),
            }
        }
        if let Some(name) = run_program {
            if let Some(p) = shell::pick_program() {
                self.run_in_box(&name, &p);
            }
        }
        if let Some(name) = open_shell {
            match isolated_windows::spawn_self(&["box", "shell", &name]) {
                Ok(()) => self.set_status(format!("Opened a command prompt inside '{name}'."), false),
                Err(e) => self.set_status(e, true),
            }
        }
        if let Some((name, on)) = set_net {
            self.set_box_internet(&name, on);
        }
        if let Some(name) = open_files {
            self.open_box_files(&name);
        }
        if let Some(name) = delete {
            self.confirm_delete_box = None;
            match isolated_windows::boxes::remove(&self.dirs, &name) {
                Ok(()) => self.set_status(format!("Deleted container '{name}'."), false),
                Err(e) => self.set_status(e, true),
            }
            self.last_refresh = None;
        }
    }

    fn new_container_ui(&mut self, ui: &mut egui::Ui) {
        let mut names: Vec<String> = self.builtin.iter().map(|e| e.policy.name.clone()).collect();
        names.extend(self.user.iter().map(|e| e.policy.name.clone()));
        let mut go = false;
        let mut cancel = false;
        let f = self.new_container.as_mut().unwrap();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("New container").strong());
            ui.add_space(4.0);
            egui::Grid::new("new_container")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    let r = ui.add(
                        egui::TextEdit::singleline(&mut f.name)
                            .hint_text("for example AI apps")
                            .desired_width(240.0),
                    );
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        go = true;
                    }
                    ui.end_row();
                    ui.label("Profile");
                    egui::ComboBox::from_id_salt("new_container_profile")
                        .selected_text(&f.profile)
                        .show_ui(ui, |ui| {
                            for n in &names {
                                ui.selectable_value(&mut f.profile, n.clone(), n);
                            }
                        });
                    ui.end_row();
                });
            ui.checkbox(&mut f.internet, "Allow internet (apps can download models, sign in, and so on)");
            ui.label(
                weak(
                    ui,
                    "Apps in the container cannot see your personal files. What they download or save goes into the container's own Documents, Downloads and Desktop.",
                )
                .small(),
            );
            if let Some(e) = &f.error {
                ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
            }
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Create").strong()).clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if cancel {
            self.new_container = None;
        } else if go {
            self.create_container();
        }
    }

    fn install_form_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mut names: Vec<String> = self.builtin.iter().map(|e| e.policy.name.clone()).collect();
        names.extend(self.user.iter().map(|e| e.policy.name.clone()));
        let box_names: Vec<String> = self.boxes.iter().map(|b| b.name.clone()).collect();
        let mut go = false;
        let mut cancel = false;
        let f = self.install.as_mut().unwrap();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Install an app").strong());
            ui.add_space(4.0);
            egui::Grid::new("install_form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Installer");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.installer).desired_width(340.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = shell::pick_installer() {
                                f.installer = p.to_string_lossy().into_owned();
                            }
                        }
                    });
                    ui.end_row();
                    ui.label("Container");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.box_name).desired_width(200.0));
                        if !box_names.is_empty() {
                            egui::ComboBox::from_id_salt("box_pick")
                                .selected_text("Existing container")
                                .show_ui(ui, |ui| {
                                    for n in &box_names {
                                        if ui.selectable_label(f.box_name == *n, n).clicked() {
                                            f.box_name = n.clone();
                                        }
                                    }
                                });
                        }
                    });
                    ui.end_row();
                    let existing = box_names.iter().any(|n| n.eq_ignore_ascii_case(f.box_name.trim()));
                    ui.label("Profile");
                    if existing {
                        ui.label(weak(ui, "Uses the container's profile"));
                    } else {
                        egui::ComboBox::from_id_salt("install_profile")
                            .selected_text(&f.profile)
                            .show_ui(ui, |ui| {
                                for n in &names {
                                    ui.selectable_value(&mut f.profile, n.clone(), n);
                                }
                            });
                    }
                    ui.end_row();
                });
            ui.checkbox(&mut f.net, "Allow internet while installing (many installers download files)");
            ui.label(weak(
                ui,
                "The installer runs without administrator rights and installs into the container only. Apps installed later in the same container can see each other.",
            ).small());
            if let Some(e) = &f.error {
                ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
            }
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Install").strong()).clicked() {
                    go = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if cancel {
            let close = f.close_after;
            self.install = None;
            if close {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        } else if go {
            self.start_install(ctx);
        }
    }

    /// Permission controls shared by the editor and the options dialog.
    fn permissions_ui(ui: &mut egui::Ui, ed: &mut Editor) {
        let p = &mut ed.policy;

        ui.add_space(6.0);
        ui.label(RichText::new("Files").strong());
        ui.checkbox(
            &mut p.filesystem.private_home,
            "Give the app its own empty user folders (AppData, Documents, temp)",
        );
        ui.checkbox(&mut p.filesystem.program_folder, "Let the app read the folder it is in");
        ui.checkbox(
            &mut p.filesystem.ask_for_folders,
            "Ask which folders to share each time the app starts",
        );
        for (title, list, new, hint) in [
            ("Folders it can read", &mut p.filesystem.read_only, &mut ed.new_ro, "ro"),
            (
                "Folders it can read and change",
                &mut p.filesystem.read_write,
                &mut ed.new_rw,
                "rw",
            ),
        ] {
            ui.label(title);
            let mut remove = None;
            for (i, f) in list.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.monospace(f);
                    if ui.small_button("Remove").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                list.remove(i);
            }
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(new)
                        .hint_text(r"C:\path or ~\Documents\folder")
                        .id_salt(hint)
                        .desired_width(260.0),
                );
                if ui.button("Add").clicked() && !new.trim().is_empty() {
                    list.push(new.trim().to_string());
                    new.clear();
                }
                if ui.button("Browse...").clicked() {
                    if let Some(f) = shell::pick_folder() {
                        list.push(f.to_string_lossy().into_owned());
                    }
                }
            });
        }

        ui.add_space(8.0);
        ui.label(RichText::new("Network").strong());
        egui::ComboBox::from_id_salt("net")
            .selected_text(p.network.mode.label())
            .width(260.0)
            .show_ui(ui, |ui| {
                for m in NetworkMode::ALL {
                    ui.selectable_value(&mut p.network.mode, m, m.label());
                }
            });
        if p.network.mode == NetworkMode::Allowlist {
            ui.label(weak(ui, "One host:port per line, such as api.example.com:443"));
            ui.add(egui::TextEdit::multiline(&mut ed.allow_text).desired_rows(3));
        }

        ui.add_space(8.0);
        ui.label(RichText::new("Devices").strong());
        ui.horizontal(|ui| {
            ui.label("Clipboard");
            egui::ComboBox::from_id_salt("clip")
                .selected_text(p.devices.clipboard.label())
                .show_ui(ui, |ui| {
                    for c in Clipboard::ALL {
                        ui.selectable_value(&mut p.devices.clipboard, c, c.label());
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut p.devices.microphone, "Microphone");
            ui.checkbox(&mut p.devices.camera, "Camera");
            ui.checkbox(&mut p.devices.printers, "Printers");
            ui.checkbox(&mut p.devices.gpu, "GPU");
        });

        ui.add_space(8.0);
        ui.label(RichText::new("Limits").strong());
        egui::Grid::new("limits")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Memory cap");
                ui.add(
                    egui::TextEdit::singleline(&mut p.resources.memory_max)
                        .hint_text("none, or e.g. 2G")
                        .desired_width(120.0),
                );
                ui.end_row();
                ui.label("CPU cap");
                ui.add(egui::Slider::new(&mut p.resources.cpu_percent, 1..=100).suffix("%"));
                ui.end_row();
                ui.label("Max processes");
                ui.add(egui::DragValue::new(&mut p.resources.max_processes).range(0..=4096));
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label(RichText::new("Isolation").strong());
        ui.radio_value(&mut p.tier, Tier::Isolated, "Full isolation (recommended)");
        ui.radio_value(
            &mut p.tier,
            Tier::Compatible,
            "Compatible: for apps that break under full isolation. Weaker: the app can read your files and use the network.",
        );
        ed.sync();
    }

    fn editor_ui(&mut self, ui: &mut egui::Ui) {
        let mut close = false;
        let mut save_and_run = false;
        let mut save = false;
        {
            let ed = self.editor.as_mut().unwrap();
            ui.add_space(6.0);
            ui.heading(if ed.original.is_some() {
                "Edit app profile"
            } else {
                "New app profile"
            });
            ui.add_space(6.0);
            egui::Grid::new("ident")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut ed.policy.name);
                    ui.end_row();
                    ui.label("Program");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut ed.policy.program).desired_width(360.0));
                        if ui.button("Browse...").clicked() {
                            if let Some(p) = shell::pick_program() {
                                ed.policy.program = p.to_string_lossy().into_owned();
                            }
                        }
                    });
                    ui.end_row();
                    ui.label("Description");
                    ui.text_edit_singleline(&mut ed.policy.description);
                    ui.end_row();
                });
            Self::permissions_ui(ui, ed);
            ui.add_space(8.0);
            gap_ui(ui, &isolated_windows::gaps(&ed.policy));
            if let Some(e) = &ed.error {
                ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
            }
            ui.label(weak(
                ui,
                "Environment variables and other advanced settings can be edited in the profile file.",
            ));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Save").strong()).clicked() {
                    save = true;
                }
                if ui.button("Save and run").clicked() {
                    save = true;
                    save_and_run = true;
                }
                if ui.button("Cancel").clicked() {
                    close = true;
                }
            });
        }
        if save {
            let ed = self.editor.as_mut().unwrap();
            ed.policy.name = ed.policy.name.trim().to_string();
            let renamed = ed.original.as_deref() != Some(ed.policy.name.as_str());
            let taken = renamed && self.user.iter().any(|e| e.policy.name == ed.policy.name);
            let result = if taken {
                Err(format!(
                    "A profile named '{}' already exists. Choose another name.",
                    ed.policy.name
                ))
            } else {
                self.store.save(&ed.policy).inspect(|_| {
                    // A rename leaves the old file behind; remove it.
                    if let Some(old) = ed.original.as_ref().filter(|_| renamed) {
                        let _ = self.store.delete(old);
                    }
                })
            };
            match result {
                Ok(_) => {
                    let p = ed.policy.clone();
                    self.editor = None;
                    self.reload_profiles();
                    self.set_status(format!("Saved profile '{}'.", p.name), false);
                    if save_and_run {
                        self.run_profile(&p);
                    }
                }
                Err(e) => ed.error = Some(e),
            }
        } else if close {
            self.editor = None;
        }
    }

    fn running_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Running sandboxes");
        ui.add_space(6.0);
        if self.running.is_empty() {
            ui.label("Nothing is running in a sandbox right now.");
            return;
        }
        let mut stop = None;
        egui::Grid::new("running")
            .striped(true)
            .num_columns(6)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                for h in ["App", "Profile", "Running for", "Processes", "Memory", ""] {
                    ui.label(RichText::new(h).strong());
                }
                ui.end_row();
                for (e, s) in &self.running {
                    ui.label(file_name(Path::new(&e.program))).on_hover_text(&e.program);
                    ui.label(&e.profile);
                    ui.label(format_duration(now_unix().saturating_sub(e.started)));
                    ui.label(s.map(|s| s.processes.to_string()).unwrap_or_else(|| "-".into()));
                    ui.label(s.map(|s| format_bytes(s.memory_bytes)).unwrap_or_else(|| "-".into()));
                    if ui.button("Stop").clicked() {
                        stop = Some(e.clone());
                    }
                    ui.end_row();
                }
            });
        if let Some(e) = stop {
            match isolated_windows::stop(&e) {
                Ok(()) => self.set_status(format!("Stopped {}.", file_name(Path::new(&e.program))), false),
                Err(err) => self.set_status(err, true),
            }
            self.last_refresh = None;
        }
    }

    fn settings_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(6.0);
        ui.heading("Settings");

        ui.add_space(10.0);
        ui.label(RichText::new("Right-click menu").strong());
        let me = std::env::current_exe().ok();
        match &self.menu_exe {
            Some(exe) => {
                ui.label(format!(
                    "On. Programs, shortcuts and scripts show Run in Isolated, using {}.",
                    exe.display()
                ));
                if me.as_ref().map(|m| m != exe).unwrap_or(false) && !exe.exists() {
                    ui.label(
                        RichText::new("That copy of Isolated no longer exists. Turn the menu on again to fix it.")
                            .color(Color32::from_rgb(220, 120, 40)),
                    );
                }
            }
            None => {
                ui.label("Off.");
            }
        }
        ui.label(weak(ui, "On Windows 11 it appears under Show more options."));
        ui.horizontal(|ui| {
            if ui
                .button(if self.menu_exe.is_some() {
                    "Turn on again"
                } else {
                    "Turn on"
                })
                .clicked()
            {
                if let Some(me) = &me {
                    match menu::register(me) {
                        Ok(()) => self.set_status("Added Run in Isolated to the right-click menu.", false),
                        Err(e) => self.set_status(e, true),
                    }
                }
                self.menu_exe = menu::registered_exe();
            }
            if self.menu_exe.is_some() && ui.button("Turn off").clicked() {
                match menu::unregister() {
                    Ok(()) => self.set_status("Removed Run in Isolated from the right-click menu.", false),
                    Err(e) => self.set_status(e, true),
                }
                self.menu_exe = menu::registered_exe();
            }
        });

        ui.add_space(12.0);
        ui.label(RichText::new("Install").strong());
        if install::is_running_installed() {
            ui.label("Isolated is installed for this user.");
            ui.label(weak(
                ui,
                "Uninstall it from Windows Settings > Apps, or run: isolated uninstall",
            ));
        } else {
            ui.label(format!(
                "Isolated is running from {}. Installing copies it to your user folder, adds it to the Start menu and the right-click menu, and lets it update itself in place. No administrator rights needed.",
                me.as_ref().map(|m| m.display().to_string()).unwrap_or_default()
            ));
            if ui.button("Install for this user").clicked() {
                match install::install() {
                    Ok(dest) => {
                        self.menu_exe = menu::registered_exe();
                        let _ = std::process::Command::new(&dest).spawn();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Err(e) => self.set_status(e, true),
                }
            }
        }

        ui.add_space(12.0);
        ui.label(RichText::new("Updates").strong());
        ui.label(format!("Version {}", isolated_core::version::CURRENT));
        if ui
            .checkbox(
                &mut self.settings.check_for_updates,
                "Check for updates when Isolated opens",
            )
            .changed()
        {
            let _ = self.settings.save(&self.dirs);
        }
        ui.horizontal(|ui| {
            let busy = matches!(
                *self.update.lock().unwrap(),
                UpdateState::Checking | UpdateState::Downloading { .. }
            );
            if ui.add_enabled(!busy, egui::Button::new("Check now")).clicked() {
                self.check_updates(ctx, true);
            }
            match &*self.update.lock().unwrap() {
                UpdateState::Checking => {
                    ui.spinner();
                }
                UpdateState::UpToDate => {
                    ui.label("You have the latest version.");
                }
                _ => {}
            }
        });

        ui.add_space(12.0);
        ui.label(RichText::new("Programs without a profile").strong());
        let mut names: Vec<String> = self.builtin.iter().map(|e| e.policy.name.clone()).collect();
        names.extend(self.user.iter().map(|e| e.policy.name.clone()));
        let before = self.settings.default_profile.clone();
        egui::ComboBox::from_id_salt("default_profile")
            .selected_text(&self.settings.default_profile)
            .show_ui(ui, |ui| {
                for n in names {
                    ui.selectable_value(&mut self.settings.default_profile, n.clone(), n);
                }
            });
        if before != self.settings.default_profile {
            let _ = self.settings.save(&self.dirs);
        }

        ui.add_space(12.0);
        ui.label(RichText::new("Maintenance").strong());
        ui.horizontal(|ui| {
            if ui
                .button("Repair folder permissions")
                .on_hover_text(
                    "Removes folder access left behind if a sandbox was interrupted, for example by a power cut.",
                )
                .clicked()
            {
                match isolated_windows::repair(&self.dirs) {
                    Ok(0) => self.set_status("Nothing needed repairing.", false),
                    Ok(n) => self.set_status(format!("Repaired {n} interrupted sandbox(es)."), false),
                    Err(e) => self.set_status(e, true),
                }
            }
            if ui.button("Open profiles folder").clicked() {
                let _ = std::fs::create_dir_all(self.dirs.profiles());
                shell::open(&self.dirs.profiles().to_string_lossy());
            }
            if ui.button("Project page").clicked() {
                shell::open(update::REPO_URL);
            }
        });
    }

    fn options_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mut run = false;
        let mut save_run = false;
        let mut cancel = false;
        let mut rebase: Option<String> = None;
        let mut names: Vec<String> = self.user.iter().map(|e| e.policy.name.clone()).collect();
        names.extend(self.builtin.iter().map(|e| e.policy.name.clone()));
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                let dlg = self.options.as_mut().unwrap();
                ui.add_space(4.0);
                ui.label(RichText::new(file_name(&dlg.target)).size(18.0).strong());
                ui.label(weak(ui, dlg.target.display().to_string()));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Start from");
                    let mut base = dlg.base.clone();
                    egui::ComboBox::from_id_salt("base")
                        .selected_text(&base)
                        .show_ui(ui, |ui| {
                            for n in &names {
                                ui.selectable_value(&mut base, n.clone(), n);
                            }
                        });
                    if base != dlg.base {
                        rebase = Some(base);
                    }
                });
                Self::permissions_ui(ui, &mut dlg.editor);
                ui.add_space(8.0);
                let gaps = isolated_windows::gaps(&dlg.editor.policy);
                gap_ui(ui, &gaps);
                let weaker = gaps.iter().any(|g| g.severity == Severity::Weaker);
                if weaker {
                    ui.checkbox(&mut dlg.accept_weaker, "Run anyway with a weaker sandbox");
                }
                if let Some(e) = &dlg.editor.error {
                    ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 70)));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok = !weaker || dlg.accept_weaker;
                    if ui
                        .add_enabled(ok, egui::Button::new(RichText::new("Run").strong()))
                        .clicked()
                    {
                        run = true;
                    }
                    if ui
                        .add_enabled(ok, egui::Button::new("Save as app profile and run"))
                        .clicked()
                    {
                        save_run = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        });

        if let Some(base) = rebase {
            if let Ok(p) = self.store.load(&base) {
                let dlg = self.options.as_mut().unwrap();
                dlg.base = base;
                dlg.editor = Editor::new(p, None);
            }
        }
        if cancel {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if run || save_run {
            let target = self.options.as_ref().unwrap().target.clone();
            let accept = self.options.as_ref().unwrap().accept_weaker;
            let mut policy = self.options.as_ref().unwrap().editor.policy.clone();
            let result = if save_run {
                let existing = self.store.find_for_program(&target.to_string_lossy());
                let base = policy.name.clone();
                if existing.as_ref().map(|e| e.name != base).unwrap_or(true) || ProfileStore::is_builtin(&base) {
                    policy.name = existing
                        .map(|e| e.name)
                        .unwrap_or_else(|| self.store.suggest_name(&target.to_string_lossy()));
                    if ProfileStore::is_builtin(&base) {
                        policy.extends = Some(base);
                    }
                }
                policy.program = target.to_string_lossy().into_owned();
                self.store.save(&policy).and_then(|_| {
                    let mut args = vec!["run", "--profile", policy.name.as_str()];
                    if accept {
                        args.push("--accept-weaker");
                    }
                    args.push("--");
                    let t = target.to_string_lossy().into_owned();
                    args.push(&t);
                    isolated_windows::spawn_self(&args)
                })
            } else {
                let file = self
                    .dirs
                    .tmp()
                    .join(format!("{}.toml", isolated_core::state::new_sandbox_id()));
                policy
                    .validate()
                    .map_err(|e| e.join("; "))
                    .and_then(|_| {
                        isolated_core::state::write_atomic(&file, policy.to_toml().as_bytes())
                            .map_err(|e| e.to_string())
                    })
                    .and_then(|_| {
                        let f = file.to_string_lossy().into_owned();
                        let t = target.to_string_lossy().into_owned();
                        let mut args = vec!["run", "--profile-file", f.as_str()];
                        if accept {
                            args.push("--accept-weaker");
                        }
                        args.push("--");
                        args.push(&t);
                        isolated_windows::spawn_self(&args)
                    })
            };
            match result {
                Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                Err(e) => self.options.as_mut().unwrap().editor.error = Some(e),
            }
        }
    }
}

fn format_bytes(b: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    if b as f64 >= 1024.0 * MB {
        format!("{:.1} GB", b as f64 / (1024.0 * MB))
    } else {
        format!("{:.0} MB", b as f64 / MB)
    }
}

fn format_duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(format_bytes(50 * 1024 * 1024), "50 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(format_duration(42), "42s");
        assert_eq!(format_duration(3700), "1h 1m");
        let p = Policy::default();
        assert_eq!(summary(&p), "no network · no clipboard · 0 folders");
    }
}

//! `isolated.exe`: the right-click menu target, the window, and the
//! command-line tool, in one small binary. Which one runs depends on the
//! arguments. A sandbox launch only opens a window when the profile asks
//! which folders to share; the process then becomes a windowless watcher
//! that cleans up and exits when the app exits.

#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use isolated_core::boxes::{AppBox, BoxApp};
use isolated_core::profile::{ProfileStore, DEFAULT_PROFILE};
use isolated_core::state::{FolderChoices, RunningEntry};
use isolated_core::{Dirs, NetworkMode, Overrides, Policy, Settings, Severity, Tier};
use isolated_windows::shell::{self, Icon};
use isolated_windows::{install, menu, update, LaunchRequest};
use lexopt::prelude::*;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
Isolated: run any program in a sandbox.

Usage:
  isolated                              Open the Isolated window
  isolated run [options] [--] <program> [args...]
                                        Run a program, shortcut or script in a sandbox
  isolated options <program>            Choose permissions in a dialog, then run
  isolated box install [options] [<box>] -- <installer> [args...]
                                        Install an app into a box (a sandbox that keeps its files)
  isolated box run <box> <app> [args...]
                                        Start an app saved in a box (by name or path)
  isolated box options <installer>      Choose the box and network in a dialog, then install
  isolated box list                     List boxes and their apps
  isolated box create <box> [--profile <name>] [--net | --no-net]
                                        Make an empty box (internet allowed unless --no-net)
  isolated box shell <box>              Open a command prompt inside a box
  isolated box files <box>              Show a box's files in Explorer (prints the folder)
  isolated box net <box> on|off|profile Allow or block internet for apps in a box
  isolated box add <box> <program> [--name <name>]
                                        Save a program inside a box as an app
  isolated box forget <box> <app>       Remove an app from a box's list (files are kept)
  isolated box delete <box>             Delete a box and everything installed in it
  isolated folder <folder>              Isolate a folder, or manage it, in a window
  isolated folder add <folder> [--net]  Isolate a folder: programs started from it may read and
                                        change everything in it and nothing else (no internet
                                        unless --net)
  isolated folder remove <folder>       Stop isolating a folder (its files are kept)
  isolated folder list                  List isolated folders
  isolated folder files <folder>        Show where its programs keep settings and saves
  isolated ps                           List running sandboxes
  isolated kill <id>                    Stop a sandbox and everything it started
  isolated profile list                 List profiles
  isolated profile show <name>          Print a profile with 'extends' resolved
  isolated profile check <file>         Check a profile file for mistakes
  isolated profile edit <program>       Open the profile editor for a program
  isolated install                      Install for this user (Start menu, right-click menu)
  isolated uninstall [--remove-data]    Uninstall
  isolated register | unregister        Add or remove the right-click menu only
  isolated update [--check]             Update to the latest release
  isolated repair                       Remove folder access left by interrupted sandboxes
  isolated --version

'container' works everywhere 'box' does: a box is what the window calls a
container.

Run options:
  --profile <name>        Use this profile (default: the program's saved profile, or strict)
  --profile-file <file>   Use a profile file
  --no-net                No network for this run
  --net                   Allow internet for this run
  --ro <path>             Also allow reading this folder or file (repeatable)
  --rw <path>             Also allow reading and changing this folder or file (repeatable)
  --ask-folders           Ask which folders to share before starting
  --no-ask                Do not ask for folders, even if the profile does
  --compatible            Use the weaker compatible tier
  --accept-weaker         Run even if the sandbox would be weaker than the profile asks
  --verbose               Print notes about the sandbox

Box install options:
  --profile <name>        Profile for a new box (default: the default profile)
  --net / --no-net        Allow or block internet while installing (default: allowed)
  --accept-weaker         Install even if the sandbox would be weaker than the profile asks
";

/// Where messages go: the terminal if we were started from one, otherwise
/// a message box.
struct Out {
    console: bool,
}

impl Out {
    fn info(&self, msg: &str) {
        if self.console {
            println!("{msg}");
        }
    }

    fn error(&self, msg: &str) -> ExitCode {
        if self.console {
            eprintln!("isolated: {msg}");
        } else {
            shell::message_box("Isolated", msg, Icon::Error);
        }
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    update::cleanup_old();
    install::refresh_version();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        return gui(isolated_gui::Start::Home);
    }
    let console = shell::attach_console();
    let out = Out { console };
    match dispatch(args, &out) {
        Ok(code) => code,
        Err(e) => out.error(&e),
    }
}

fn gui(start: isolated_gui::Start) -> ExitCode {
    match isolated_gui::run(start) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            shell::message_box("Isolated", &e, Icon::Error);
            ExitCode::from(1)
        }
    }
}

fn dispatch(args: Vec<OsString>, out: &Out) -> Result<ExitCode, String> {
    let mut parser = lexopt::Parser::from_args(args);
    let first = parser.next().map_err(|e| e.to_string())?;
    let cmd = match first {
        Some(Long("help")) | Some(Short('h')) => {
            out.info(HELP);
            if !out.console {
                shell::message_box("Isolated", HELP, Icon::Info);
            }
            return Ok(ExitCode::SUCCESS);
        }
        Some(Long("version")) | Some(Short('V')) => {
            out.info(&format!("isolated {}", isolated_core::version::CURRENT));
            return Ok(ExitCode::SUCCESS);
        }
        Some(Long("register")) => "register".to_string(),
        Some(Long("unregister")) => "unregister".to_string(),
        Some(Value(v)) => v.string().map_err(|_| "invalid command")?,
        Some(other) => return Err(format!("{}. Try 'isolated --help'.", other.unexpected())),
        None => unreachable!(),
    };
    let dirs = Dirs::standard();
    match cmd.as_str() {
        "run" => run(parser, &dirs, out),
        "options" => {
            let target = single_path(&mut parser)?;
            Ok(gui(isolated_gui::Start::Options(target)))
        }
        "box" | "boxes" | "container" | "containers" => app_box(parser, &dirs, out),
        "folder" | "folders" => folder(parser, &dirs, out),
        "ps" | "list" => ps(&dirs, out),
        "kill" | "stop" => {
            let id = single_value(&mut parser, "a sandbox id")?;
            let entry = isolated_windows::running(&dirs)
                .into_iter()
                .find(|e| e.id == id)
                .ok_or_else(|| format!("no running sandbox with id {id}"))?;
            isolated_windows::stop(&entry)?;
            out.info(&format!("Stopped sandbox {id}."));
            Ok(ExitCode::SUCCESS)
        }
        "profile" | "profiles" => profile(parser, &dirs, out),
        "install" => {
            let quiet = flags(&mut parser, &["quiet"])?.contains(&"quiet");
            let dest = install::install()?;
            let msg = format!(
                "Isolated is installed at {}.\n\nRight-click any program and choose Run in Isolated. On Windows 11 it is under Show more options.",
                dest.display()
            );
            out.info(&msg);
            if !out.console && !quiet {
                shell::message_box("Isolated", &msg, Icon::Info);
            }
            Ok(ExitCode::SUCCESS)
        }
        "uninstall" => {
            let f = flags(&mut parser, &["quiet", "remove-data"])?;
            let quiet = f.contains(&"quiet");
            if !out.console
                && !quiet
                && !shell::confirm(
                    "Uninstall Isolated",
                    "Remove Isolated, its Start menu entry and its right-click menu?\n\nYour app profiles are kept.",
                )
            {
                return Ok(ExitCode::SUCCESS);
            }
            install::uninstall(&dirs, f.contains(&"remove-data"))?;
            out.info("Isolated was uninstalled.");
            if !out.console && !quiet {
                shell::message_box("Isolated", "Isolated was uninstalled.", Icon::Info);
            }
            Ok(ExitCode::SUCCESS)
        }
        "register" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            menu::register(&exe)?;
            out.info("Added Run in Isolated to the right-click menu.");
            Ok(ExitCode::SUCCESS)
        }
        "unregister" => {
            menu::unregister()?;
            out.info("Removed Run in Isolated from the right-click menu.");
            Ok(ExitCode::SUCCESS)
        }
        "update" => {
            let check_only = flags(&mut parser, &["check"])?.contains(&"check");
            match update::check()? {
                None => out.info(&format!(
                    "Isolated {} is the latest version.",
                    isolated_core::version::CURRENT
                )),
                Some(r) if check_only => out.info(&format!("Isolated {} is available: {}", r.version, r.page_url)),
                Some(r) => {
                    out.info(&format!("Downloading Isolated {}...", r.version));
                    update::install(&r, |_, _| {})?;
                    out.info(&format!("Updated to Isolated {}.", r.version));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        // Hidden: writes the known folders this process sees, and whether
        // each can be written, to a file. Run inside a sandbox to see what
        // apps get.
        "diag-folders" => {
            let file = single_path(&mut parser)?;
            let mut text = String::new();
            for (name, path) in shell::known_folders() {
                let writable = path.as_ref().is_some_and(|p| {
                    let probe = p.join(".isolated-probe");
                    let ok = std::fs::create_dir_all(p).is_ok() && std::fs::write(&probe, b"x").is_ok();
                    let _ = std::fs::remove_file(&probe);
                    ok
                });
                let shown = path.map(|p| p.display().to_string()).unwrap_or_else(|| "(none)".into());
                text.push_str(&format!("{name} = {shown} (writable: {writable})\n"));
            }
            for (name, detail) in shell::known_folders_detail() {
                text.push_str(&format!("{name}: {detail}\n"));
            }
            for var in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP"] {
                text.push_str(&format!("%{var}% = {}\n", std::env::var(var).unwrap_or_default()));
            }
            std::fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))?;
            Ok(ExitCode::SUCCESS)
        }
        "repair" => {
            let n = isolated_windows::repair(&dirs)?;
            out.info(&format!("Repaired {n} interrupted sandbox(es)."));
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command '{other}'. Try 'isolated --help'.")),
    }
}

fn flags(parser: &mut lexopt::Parser, allowed: &[&'static str]) -> Result<Vec<&'static str>, String> {
    let mut found = Vec::new();
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long(name) => match allowed.iter().find(|a| **a == name) {
                Some(a) => found.push(*a),
                None => return Err(format!("unknown option --{name}")),
            },
            other => return Err(other.unexpected().to_string()),
        }
    }
    Ok(found)
}

fn single_value(parser: &mut lexopt::Parser, what: &str) -> Result<String, String> {
    match parser.next().map_err(|e| e.to_string())? {
        Some(Value(v)) => v.string().map_err(|_| format!("invalid {what}")),
        _ => Err(format!("expected {what}")),
    }
}

fn single_path(parser: &mut lexopt::Parser) -> Result<PathBuf, String> {
    match parser.next().map_err(|e| e.to_string())? {
        Some(Value(v)) => Ok(PathBuf::from(v)),
        _ => Err("expected a program path".into()),
    }
}

fn run(mut parser: lexopt::Parser, dirs: &Dirs, out: &Out) -> Result<ExitCode, String> {
    let mut profile: Option<String> = None;
    let mut profile_file: Option<PathBuf> = None;
    let mut ov = Overrides::default();
    let mut accept_weaker = false;
    let mut verbose = false;
    let mut ask: Option<bool> = None;
    let mut target: Option<PathBuf> = None;
    let mut args: Vec<String> = Vec::new();

    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("profile") | Short('p') => {
                profile = Some(
                    parser
                        .value()
                        .map_err(|e| e.to_string())?
                        .string()
                        .map_err(|_| "invalid profile name")?,
                )
            }
            Long("profile-file") => profile_file = Some(parser.value().map_err(|e| e.to_string())?.into()),
            Long("no-net") | Long("offline") => ov.network = Some(NetworkMode::None),
            Long("net") => ov.network = Some(NetworkMode::Full),
            Long("ro") => ov.read_only.push(
                parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .string()
                    .map_err(|_| "invalid path")?,
            ),
            Long("rw") => ov.read_write.push(
                parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .string()
                    .map_err(|_| "invalid path")?,
            ),
            Long("compatible") => ov.tier = Some(Tier::Compatible),
            Long("private-home") => ov.private_home = Some(true),
            Long("accept-weaker") => accept_weaker = true,
            Long("ask-folders") => ask = Some(true),
            Long("no-ask") => ask = Some(false),
            Long("verbose") | Short('v') => verbose = true,
            Value(v) => {
                target = Some(PathBuf::from(v));
                // Everything after the program goes to the program.
                for rest in parser.raw_args().map_err(|e| e.to_string())? {
                    args.push(rest.to_string_lossy().into_owned());
                }
                break;
            }
            other => return Err(format!("{}. Try 'isolated --help'.", other.unexpected())),
        }
    }
    let target = target.ok_or("expected a program to run, for example: isolated run app.exe")?;
    let target = std::path::absolute(&target).unwrap_or(target);
    if !target.exists() {
        return Err(format!("{} does not exist.", target.display()));
    }

    let store = ProfileStore::new(dirs.profiles());
    let settings = Settings::load(dirs);
    let mut policy: Policy = if let Some(file) = &profile_file {
        let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
        // One-off profiles written by the options dialog are removed after use.
        if file.starts_with(dirs.tmp()) {
            let _ = std::fs::remove_file(file);
        }
        store.resolve_text(&text)?
    } else if let Some(name) = &profile {
        store.load(name)?
    } else if let Some(p) = store.find_for_program(&target.to_string_lossy()) {
        p
    } else {
        store
            .load(&settings.default_profile)
            .or_else(|_| store.load(DEFAULT_PROFILE))?
    };
    let explicit_folders = !ov.read_only.is_empty() || !ov.read_write.is_empty();
    ov.apply(&mut policy);
    policy.validate().map_err(|e| e.join("; "))?;
    if ask.unwrap_or(policy.filesystem.ask_for_folders && !explicit_folders)
        && !choose_folders(dirs, &target, &mut policy)?
    {
        return Ok(ExitCode::from(1));
    }

    // Clean up after any sandbox that was interrupted.
    let _ = isolated_windows::repair(dirs);

    let gaps = isolated_windows::gaps(&policy);
    let weaker: Vec<&str> = gaps
        .iter()
        .filter(|g| g.severity == Severity::Weaker)
        .map(|g| g.message.as_str())
        .collect();
    if verbose {
        for g in gaps.iter().filter(|g| g.severity == Severity::Notice) {
            out.info(&format!("note: {}", g.message));
        }
    }
    if !weaker.is_empty() && !accept_weaker {
        let list = weaker.join("\n");
        if out.console {
            return Err(format!(
                "the sandbox would be weaker than profile '{}' asks:\n{list}\nRun again with --accept-weaker to continue.",
                policy.name
            ));
        }
        if !shell::confirm(
            "Isolated",
            &format!(
                "The sandbox for this app would be weaker than profile '{}' asks:\n\n{list}\n\nRun it anyway?",
                policy.name
            ),
        ) {
            return Ok(ExitCode::from(1));
        }
        accept_weaker = true;
    }

    let req = LaunchRequest {
        profile_name: policy.name.clone(),
        target: target.clone(),
        args,
        accept_weaker,
        app_box: None,
        installer: false,
        raw_tail: String::new(),
        workdir: None,
    };
    let sandbox = isolated_windows::launch(dirs, &policy, &req)?;
    out.info(&format!(
        "Started {} in sandbox {} (profile {}).",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sandbox.id(),
        policy.name
    ));
    let code = sandbox.wait()?;
    if verbose {
        out.info(&format!("The app exited with code {code}."));
    }
    Ok(ExitCode::from(code.min(255) as u8))
}

/// A folder path as Explorer passes it. A quoted drive root such as
/// `"D:\"` arrives as `D:"`, so stray quotes are dropped.
fn folder_arg(v: OsString) -> Result<PathBuf, String> {
    let s = os_string(v)?;
    let s = s.trim().trim_matches('"');
    let s = if s.len() == 2 && s.ends_with(':') {
        format!("{s}\\")
    } else {
        s.to_string()
    };
    let p = PathBuf::from(&s);
    let p = std::path::absolute(&p).unwrap_or(p);
    Ok(p)
}

fn folder(mut parser: lexopt::Parser, dirs: &Dirs, out: &Out) -> Result<ExitCode, String> {
    let store = ProfileStore::new(dirs.profiles());
    let first = match parser.next().map_err(|e| e.to_string())? {
        Some(Value(v)) => v,
        Some(other) => return Err(format!("{}. Try 'isolated --help'.", other.unexpected())),
        None => return Ok(gui(isolated_gui::Start::Folders(None))),
    };
    let sub = first.to_string_lossy().to_lowercase();
    match sub.as_str() {
        "list" | "ls" => {
            let list = store.list_folders();
            if list.is_empty() {
                out.info("No isolated folders yet. Isolate one with: isolated folder add <folder>");
            }
            for p in list {
                let net = if p.network.mode == NetworkMode::Full {
                    "internet"
                } else {
                    "no internet"
                };
                out.info(&format!("{}  (profile {}, {net})", p.folder, p.name));
            }
            Ok(ExitCode::SUCCESS)
        }
        "add" => {
            let mut path = None;
            let mut net = false;
            while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
                match arg {
                    Long("net") => net = true,
                    Long("no-net") => net = false,
                    Value(v) if path.is_none() => path = Some(folder_arg(v)?),
                    other => return Err(format!("{}. Try 'isolated --help'.", other.unexpected())),
                }
            }
            let path = path.ok_or("expected a folder, for example: isolated folder add D:\\Games\\Old")?;
            let s = path.to_string_lossy().into_owned();
            isolated_windows::check_isolated_folder(&s)?;
            if let Some(p) = store.find_for_folder(&s) {
                out.info(&format!("{s} is already isolated (profile {}).", p.name));
                return Ok(ExitCode::SUCCESS);
            }
            let p = store.new_folder_profile(&s, net)?;
            store.save(&p)?;
            out.info(&format!(
                "Isolated {s} (profile {}). Right-click a program in it and choose Run in Isolated: it can change the files in this folder and nothing else.",
                p.name
            ));
            Ok(ExitCode::SUCCESS)
        }
        "files" | "data" => {
            let path = match parser.next().map_err(|e| e.to_string())? {
                Some(Value(v)) => folder_arg(v)?,
                _ => return Err("expected a folder, for example: isolated folder files D:\\Games\\Old".into()),
            };
            let s = path.to_string_lossy().into_owned();
            let p = store
                .find_for_folder(&s)
                .ok_or_else(|| format!("{s} is not an isolated folder."))?;
            let base = isolated_windows::boxes::isolated_folder_base(&p, &p.name)?;
            // Programs see this as LocalAppData and LocalLow (see make_private_dirs).
            let app_data = match (base.file_name(), base.parent().and_then(|b| b.file_name())) {
                (Some(ac), Some(container)) if ac.eq_ignore_ascii_case("AC") => {
                    base.join(r"Home\AppData\Local\Packages").join(container).join("AC")
                }
                _ => base.join("Home"),
            };
            out.info(&format!("Private files: {}", base.display()));
            out.info(&format!(
                "App data (their AppData\\Local and AppData\\LocalLow): {}",
                app_data.display()
            ));
            out.info(&format!(
                "Roaming (their AppData\\Roaming): {}",
                base.join(r"Home\AppData\Roaming").display()
            ));
            Ok(ExitCode::SUCCESS)
        }
        "remove" | "rm" | "delete" => {
            let path = match parser.next().map_err(|e| e.to_string())? {
                Some(Value(v)) => folder_arg(v)?,
                _ => return Err("expected a folder".into()),
            };
            let s = path.to_string_lossy().into_owned();
            let p = store
                .find_for_folder(&s)
                .ok_or_else(|| format!("{s} is not an isolated folder."))?;
            store.delete(&p.name)?;
            out.info(&format!("{s} is no longer isolated. Its files were not touched."));
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            let path = folder_arg(first)?;
            if !path.is_dir() {
                return Err(format!("{} is not a folder.", path.display()));
            }
            Ok(gui(isolated_gui::Start::Folders(Some(path))))
        }
    }
}

fn ps(dirs: &Dirs, out: &Out) -> Result<ExitCode, String> {
    let list: Vec<RunningEntry> = isolated_windows::running(dirs);
    if list.is_empty() {
        out.info("No sandboxes are running.");
        return Ok(ExitCode::SUCCESS);
    }
    out.info(&format!(
        "{:<10} {:<14} {:>6} {:>9}  PROGRAM",
        "ID", "PROFILE", "PROCS", "MEMORY"
    ));
    for e in list {
        let s = isolated_windows::stats(&e).unwrap_or_default();
        out.info(&format!(
            "{:<10} {:<14} {:>6} {:>7}MB  {}",
            e.id,
            e.profile,
            s.processes,
            s.memory_bytes / (1024 * 1024),
            e.program
        ));
    }
    Ok(ExitCode::SUCCESS)
}

fn profile(mut parser: lexopt::Parser, dirs: &Dirs, out: &Out) -> Result<ExitCode, String> {
    let store = ProfileStore::new(dirs.profiles());
    let sub = single_value(&mut parser, "list, show, check or edit").unwrap_or_else(|_| "list".into());
    match sub.as_str() {
        "list" => {
            for e in store.list_builtin() {
                out.info(&format!("{:<14} (built-in) {}", e.policy.name, e.policy.description));
            }
            let (user, bad) = store.list_user();
            for e in user {
                let what = if e.policy.folder.is_empty() {
                    &e.policy.program
                } else {
                    &e.policy.folder
                };
                out.info(&format!("{:<14} {what}", e.policy.name));
            }
            for (p, err) in bad {
                out.info(&format!("{}: {err}", p.display()));
            }
            Ok(ExitCode::SUCCESS)
        }
        "show" => {
            let name = single_value(&mut parser, "a profile name")?;
            out.info(&store.load(&name)?.to_toml());
            Ok(ExitCode::SUCCESS)
        }
        "check" => {
            let file = single_path(&mut parser)?;
            let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let policy = store.resolve_text(&text)?;
            out.info(&format!("{}: OK (profile '{}')", file.display(), policy.name));
            for g in isolated_windows::gaps(&policy) {
                let kind = if g.severity == Severity::Weaker {
                    "weaker"
                } else {
                    "note"
                };
                out.info(&format!("  {kind}: {}", g.message));
            }
            Ok(ExitCode::SUCCESS)
        }
        "edit" => {
            let target = single_path(&mut parser)?;
            let target = std::path::absolute(&target).unwrap_or(target);
            Ok(gui(isolated_gui::Start::EditFor(target)))
        }
        other => Err(format!("unknown profile command '{other}'")),
    }
}

/// Asks about (or refuses) a sandbox weaker than the profile. Returns
/// `Ok(false)` if users said no.
fn accept_gaps(policy: &Policy, accept_weaker: &mut bool, out: &Out) -> Result<bool, String> {
    let gaps = isolated_windows::gaps(policy);
    let weaker: Vec<&str> = gaps
        .iter()
        .filter(|g| g.severity == Severity::Weaker)
        .map(|g| g.message.as_str())
        .collect();
    if weaker.is_empty() || *accept_weaker {
        return Ok(true);
    }
    let list = weaker.join("\n");
    if out.console {
        return Err(format!(
            "the sandbox would be weaker than profile '{}' asks:\n{list}\nRun again with --accept-weaker to continue.",
            policy.name
        ));
    }
    if !shell::confirm(
        "Isolated",
        &format!(
            "The sandbox would be weaker than profile '{}' asks:\n\n{list}\n\nContinue anyway?",
            policy.name
        ),
    ) {
        return Ok(false);
    }
    *accept_weaker = true;
    Ok(true)
}

/// Shows the folder picker and adds the folders chosen to the policy.
/// Returns `Ok(false)` if users cancelled.
fn choose_folders(dirs: &Dirs, target: &std::path::Path, policy: &mut Policy) -> Result<bool, String> {
    let program = target.to_string_lossy().into_owned();
    let mut remembered = FolderChoices::load(dirs);
    let Some(choice) = isolated_gui::ask_folders(target, &policy.name, remembered.get(&program))? else {
        return Ok(false);
    };
    if choice.remember {
        remembered.set(&program, choice.folders.clone());
        let _ = remembered.save(dirs);
    }
    for f in choice.folders {
        if f.write {
            policy.filesystem.read_write.push(f.path);
        } else {
            policy.filesystem.read_only.push(f.path);
        }
    }
    Ok(true)
}

/// The policy a box runs with: its profile, always with private folders.
fn box_policy(store: &ProfileStore, b: &AppBox) -> Result<Policy, String> {
    let mut policy = store
        .load(&b.profile)
        .map_err(|e| format!("box '{}' uses profile '{}': {e}", b.name, b.profile))?;
    b.apply(&mut policy);
    Ok(policy)
}

/// Runs a program inside a box and waits for it, like `box run`.
#[allow(clippy::too_many_arguments)]
fn box_launch(
    dirs: &Dirs,
    store: &ProfileStore,
    b: &AppBox,
    target: PathBuf,
    args: Vec<String>,
    mut accept_weaker: bool,
    workdir: Option<PathBuf>,
    label: &str,
    out: &Out,
) -> Result<ExitCode, String> {
    let mut policy = box_policy(store, b)?;
    if policy.filesystem.ask_for_folders && !choose_folders(dirs, &target, &mut policy)? {
        return Ok(ExitCode::from(1));
    }
    let _ = isolated_windows::repair(dirs);
    if !accept_gaps(&policy, &mut accept_weaker, out)? {
        return Ok(ExitCode::from(1));
    }
    let req = LaunchRequest {
        profile_name: policy.name.clone(),
        target,
        args,
        accept_weaker,
        app_box: Some(b.name.clone()),
        installer: false,
        raw_tail: String::new(),
        workdir,
    };
    let sandbox = isolated_windows::launch(dirs, &policy, &req)?;
    out.info(&format!(
        "Started {label} from box {} in sandbox {}.",
        b.name,
        sandbox.id()
    ));
    let code = sandbox.wait()?;
    Ok(ExitCode::from(code.min(255) as u8))
}

fn load_box(dirs: &Dirs, name: &str) -> Result<AppBox, String> {
    AppBox::load(dirs, name).ok_or_else(|| format!("no box named '{name}'. See 'isolated box list'."))
}

fn os_string(v: OsString) -> Result<String, String> {
    v.into_string().map_err(|_| "invalid text in an argument".to_string())
}

fn app_box(mut parser: lexopt::Parser, dirs: &Dirs, out: &Out) -> Result<ExitCode, String> {
    let sub = single_value(&mut parser, "install, run, list, add, forget or delete").unwrap_or_else(|_| "list".into());
    let store = ProfileStore::new(dirs.profiles());
    match sub.as_str() {
        "list" | "ls" => {
            let boxes = AppBox::list(dirs);
            if boxes.is_empty() {
                out.info("No boxes yet. Install an app with: isolated box install -- <installer>");
            }
            for b in boxes {
                out.info(&format!("{} (profile {})", b.name, b.profile));
                if b.apps.is_empty() {
                    out.info("    no apps saved");
                }
                for a in &b.apps {
                    out.info(&format!("    {:<24} {}", a.name, a.path));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        "install" => box_install(parser, dirs, &store, out),
        "options" => {
            let target = single_path(&mut parser)?;
            let target = std::path::absolute(&target).unwrap_or(target);
            Ok(gui(isolated_gui::Start::Install(target)))
        }
        "run" | "start" => {
            let mut accept_weaker = false;
            let mut positional: Vec<String> = Vec::new();
            let mut args: Vec<String> = Vec::new();
            while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
                match arg {
                    Long("accept-weaker") => accept_weaker = true,
                    Value(v) => {
                        positional.push(os_string(v)?);
                        if positional.len() == 2 {
                            for rest in parser.raw_args().map_err(|e| e.to_string())? {
                                args.push(rest.to_string_lossy().into_owned());
                            }
                            break;
                        }
                    }
                    other => return Err(other.unexpected().to_string()),
                }
            }
            let [box_name, app] = <[String; 2]>::try_from(positional)
                .map_err(|_| "usage: isolated box run <box> <app> [args...]".to_string())?;
            let b = load_box(dirs, &box_name)?;
            let (target, mut all_args) = match b.find_app(&app) {
                Some(a) => (PathBuf::from(&a.path), a.args.clone()),
                None if std::path::Path::new(&app).is_file() => (PathBuf::from(&app), Vec::new()),
                None => return Err(format!("box '{}' has no app named '{app}'.", b.name)),
            };
            if !target.exists() {
                return Err(format!(
                    "{} is no longer in box '{}'. It may have been uninstalled.",
                    target.display(),
                    b.name
                ));
            }
            all_args.extend(args);
            // Programs from outside the box start in the box's user folder,
            // so what they save lands with the box's other files.
            let folder = isolated_windows::boxes::folder(&box_policy(&store, &b)?, &b.name)?;
            let inside = isolated_core::profile::normalize_path_key(&target.to_string_lossy())
                .starts_with(&isolated_core::profile::normalize_path_key(&folder.to_string_lossy()));
            let workdir = (!inside).then(|| folder.join("Home"));
            box_launch(dirs, &store, &b, target, all_args, accept_weaker, workdir, &app, out)
        }
        "create" | "new" => {
            let mut name: Option<String> = None;
            let mut profile: Option<String> = None;
            let mut internet = true;
            while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
                match arg {
                    Long("profile") | Short('p') => {
                        profile = Some(os_string(parser.value().map_err(|e| e.to_string())?)?)
                    }
                    Long("net") => internet = true,
                    Long("no-net") | Long("offline") => internet = false,
                    Value(v) if name.is_none() => name = Some(os_string(v)?),
                    other => return Err(other.unexpected().to_string()),
                }
            }
            let name = name.ok_or("usage: isolated box create <box> [--profile <name>] [--net | --no-net]")?;
            let name = name.trim().to_string();
            isolated_core::boxes::check_name(&name)?;
            if AppBox::exists(dirs, &name) {
                return Err(format!("A box named '{name}' already exists."));
            }
            let profile = profile.unwrap_or_else(|| "online".into());
            store.load(&profile)?;
            let mut b = AppBox::new(&name, &profile);
            b.internet = Some(internet);
            let folder = isolated_windows::boxes::folder(&box_policy(&store, &b)?, &b.name)?;
            b.save(dirs)?;
            out.info(&format!(
                "Created box {name} ({}). Its files are in {}",
                if internet { "internet allowed" } else { "no internet" },
                folder.join("Home").display()
            ));
            Ok(ExitCode::SUCCESS)
        }
        "shell" | "cmd" | "enter" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let b = load_box(dirs, &box_name)?;
            let home = isolated_windows::boxes::home(&box_policy(&store, &b)?, &b.name)?;
            let comspec = std::env::var_os("ComSpec")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
            let banner = format!(
                "title Isolated box: {0} & echo You are inside box {0}. Programs started here stay in the box, and files saved here stay in its folder. & echo.",
                b.name
            );
            box_launch(
                dirs,
                &store,
                &b,
                comspec,
                vec!["/k".into(), banner],
                false,
                Some(home),
                "a command prompt",
                out,
            )
        }
        "files" | "open" | "explore" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let b = load_box(dirs, &box_name)?;
            let home = isolated_windows::boxes::home(&box_policy(&store, &b)?, &b.name)?;
            out.info(&home.to_string_lossy());
            if !out.console {
                shell::open(&home.to_string_lossy());
            }
            Ok(ExitCode::SUCCESS)
        }
        "net" | "internet" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let choice = single_value(&mut parser, "on, off or profile")?;
            let mut b = load_box(dirs, &box_name)?;
            b.internet = match choice.to_ascii_lowercase().as_str() {
                "on" | "yes" | "true" | "allow" => Some(true),
                "off" | "no" | "false" | "block" => Some(false),
                "profile" | "default" => None,
                other => return Err(format!("expected on, off or profile, not '{other}'")),
            };
            b.save(dirs)?;
            let policy = box_policy(&store, &b)?;
            out.info(&format!(
                "Internet for box {} is now {}. Apps already running keep their old setting until restarted.",
                b.name,
                if policy.network.mode == NetworkMode::None {
                    "blocked"
                } else {
                    "allowed"
                }
            ));
            Ok(ExitCode::SUCCESS)
        }
        "add" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let program = single_path(&mut parser)?;
            let mut name = None;
            while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
                match arg {
                    Long("name") => name = Some(os_string(parser.value().map_err(|e| e.to_string())?)?),
                    other => return Err(other.unexpected().to_string()),
                }
            }
            let mut b = load_box(dirs, &box_name)?;
            let program = std::path::absolute(&program).unwrap_or(program);
            if !program.is_file() {
                return Err(format!("{} does not exist.", program.display()));
            }
            let name = name.unwrap_or_else(|| {
                program
                    .file_stem()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "App".into())
            });
            b.add_apps(vec![BoxApp {
                name: name.clone(),
                path: program.to_string_lossy().into_owned(),
                args: Vec::new(),
            }]);
            b.save(dirs)?;
            out.info(&format!("Saved {name} in box {}.", b.name));
            Ok(ExitCode::SUCCESS)
        }
        "forget" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let app = single_value(&mut parser, "an app name")?;
            let mut b = load_box(dirs, &box_name)?;
            let path = b
                .find_app(&app)
                .map(|a| a.path.clone())
                .ok_or_else(|| format!("box '{}' has no app named '{app}'.", b.name))?;
            b.apps.retain(|a| a.path != path);
            b.save(dirs)?;
            out.info(&format!("Removed {app} from box {}.", b.name));
            Ok(ExitCode::SUCCESS)
        }
        "delete" | "remove" => {
            let box_name = single_value(&mut parser, "a box name")?;
            let b = load_box(dirs, &box_name)?;
            isolated_windows::boxes::remove(dirs, &b.name)?;
            out.info(&format!("Deleted box {}.", b.name));
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown box command '{other}'")),
    }
}

fn box_install(mut parser: lexopt::Parser, dirs: &Dirs, store: &ProfileStore, out: &Out) -> Result<ExitCode, String> {
    let mut profile: Option<String> = None;
    let mut net = true;
    let mut accept_weaker = false;
    let mut box_name: Option<String> = None;
    let mut target: Option<PathBuf> = None;
    let mut args: Vec<String> = Vec::new();
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Long("profile") | Short('p') => profile = Some(os_string(parser.value().map_err(|e| e.to_string())?)?),
            Long("net") => net = true,
            Long("no-net") | Long("offline") => net = false,
            Long("accept-weaker") => accept_weaker = true,
            Long("box") => box_name = Some(os_string(parser.value().map_err(|e| e.to_string())?)?),
            Value(v) if box_name.is_none() && target.is_none() => {
                // `box install <box> -- <installer>` or `box install <installer>`.
                let v = os_string(v)?;
                let looks_like_file = std::path::Path::new(&v).is_file();
                if looks_like_file {
                    target = Some(PathBuf::from(v));
                    for rest in parser.raw_args().map_err(|e| e.to_string())? {
                        args.push(rest.to_string_lossy().into_owned());
                    }
                    break;
                }
                box_name = Some(v);
            }
            Value(v) => {
                target = Some(PathBuf::from(v));
                for rest in parser.raw_args().map_err(|e| e.to_string())? {
                    args.push(rest.to_string_lossy().into_owned());
                }
                break;
            }
            other => return Err(format!("{}. Try 'isolated --help'.", other.unexpected())),
        }
    }
    let target = target.ok_or("expected an installer, for example: isolated box install -- setup.exe")?;
    let target = std::path::absolute(&target).unwrap_or(target);
    if !target.is_file() {
        return Err(format!("{} does not exist.", target.display()));
    }
    let target_s = target.to_string_lossy().into_owned();
    let box_name = match box_name {
        Some(n) => n.trim().to_string(),
        None => isolated_core::boxes::suggest_name(dirs, &target_s),
    };
    isolated_core::boxes::check_name(&box_name)?;
    let mut b = match AppBox::load(dirs, &box_name) {
        Some(b) => b,
        None => {
            let settings = Settings::load(dirs);
            let p = profile.clone().unwrap_or(settings.default_profile);
            let p = if store.load(&p).is_ok() {
                p
            } else {
                DEFAULT_PROFILE.to_string()
            };
            AppBox::new(&box_name, &p)
        }
    };
    if let Some(p) = profile {
        store.load(&p)?;
        b.profile = p;
    }
    b.save(dirs)?;

    let mut policy = box_policy(store, &b)?;
    if net {
        policy.network.mode = NetworkMode::Full;
    } else {
        policy.network.mode = NetworkMode::None;
    }
    let _ = isolated_windows::repair(dirs);
    if !accept_gaps(&policy, &mut accept_weaker, out)? {
        return Ok(ExitCode::from(1));
    }

    let folder = isolated_windows::boxes::folder(&policy, &b.name)?;
    let before = isolated_windows::boxes::snapshot(&folder);
    if target_s.to_ascii_lowercase().ends_with(".msi") {
        return msi_install(&target, &b, &policy, &folder, &before, dirs, out);
    }
    // Fully isolated sandboxes cannot see the system drive's root, which
    // some installers check; give them a drive whose root is the box.
    let alias = if policy.tier == Tier::Isolated {
        isolated_windows::boxes::DriveAlias::map(&folder).ok()
    } else {
        None
    };

    // Ask installers we recognize to install for this user, into the box.
    let mut pre = Vec::new();
    let mut raw_tail = String::new();
    if target_s.to_ascii_lowercase().ends_with(".exe") {
        let head = read_head(&target, 8 << 20);
        let kind = isolated_core::boxes::detect_installer(&head);
        let app_dir = isolated_core::boxes::name_from_installer(&target_s);
        let base = alias.as_ref().map(|a| a.root()).unwrap_or_else(|| folder.clone());
        let dir = isolated_windows::boxes::install_dir(&policy, &base, &app_dir);
        let (p, tail) = isolated_core::boxes::per_user_args(kind, &dir.to_string_lossy(), !args.is_empty());
        pre = p;
        raw_tail = tail.join(" ");
    }
    pre.extend(args);

    let req = LaunchRequest {
        profile_name: policy.name.clone(),
        target: target.clone(),
        args: pre,
        accept_weaker,
        app_box: Some(b.name.clone()),
        installer: true,
        raw_tail,
        workdir: None,
    };
    let sandbox = isolated_windows::launch(dirs, &policy, &req)?;
    out.info(&format!(
        "Installing {} into box {} (sandbox {}). Isolated waits until the installer and anything it started have closed.",
        target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        b.name,
        sandbox.id()
    ));
    let code = sandbox.wait()?;

    let (shortcuts, exes) = isolated_windows::boxes::found_since(&folder, &before, alias.as_ref());
    drop(alias);
    let found = isolated_core::boxes::choose_apps(&shortcuts, &exes);
    // Re-read: the window may have changed the box while we waited.
    let mut b = AppBox::load(dirs, &b.name).unwrap_or(b);
    let names: Vec<String> = found.iter().map(|a| a.name.clone()).collect();
    let added = b.add_apps(found);
    b.save(dirs)?;

    let msg = if added > 0 {
        format!(
            "Installed into box '{}'. Saved {}.\n\nStart it from the Installed apps list in the Isolated window, or run: isolated box run \"{}\" \"{}\"",
            b.name,
            names.join(", "),
            b.name,
            names[0]
        )
    } else if !b.apps.is_empty() {
        format!(
            "The installer finished (exit code {code}). No new programs were found, so box '{}' keeps its saved apps.",
            b.name
        )
    } else {
        format!(
            "The installer finished (exit code {code}), but no program was found in box '{}'.\n\nIf the installer showed an error, it may need administrator rights, which a sandbox cannot give. Otherwise, add the program from the Installed apps list.",
            b.name
        )
    };
    finish_install(&b, added, &msg, out)
}

fn finish_install(b: &AppBox, added: usize, msg: &str, out: &Out) -> Result<ExitCode, String> {
    out.info(msg);
    if !out.console {
        shell::message_box("Isolated", msg, if added > 0 { Icon::Info } else { Icon::Warning });
    }
    Ok(ExitCode::from(if added > 0 || !b.apps.is_empty() { 0 } else { 2 }))
}

/// Installs a `.msi` package by unpacking it into the box. Windows Installer
/// is a system service a sandbox cannot use, so no installer code runs:
/// Isolated places the package's files and reads its shortcuts itself.
fn msi_install(
    target: &std::path::Path,
    b: &AppBox,
    policy: &Policy,
    folder: &std::path::Path,
    before: &std::collections::BTreeSet<String>,
    dirs: &Dirs,
    out: &Out,
) -> Result<ExitCode, String> {
    use isolated_core::msi::{unpack, BoxFolders};
    let programs = isolated_windows::boxes::install_dir(policy, folder, "x")
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or("could not find the box's Programs folder")?;
    let folders = BoxFolders {
        local_app_data: programs
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| folder.to_path_buf()),
        programs,
        home: folder.join("Home"),
    };
    out.info(&format!(
        "Unpacking {} into box {}...",
        target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        b.name
    ));
    let u = unpack(target, folder, &folders).map_err(|e| format!("Could not install {}: {e}", target.display()))?;

    let (mut shortcuts, exes) = isolated_windows::boxes::found_since(folder, before, None);
    shortcuts.extend(u.shortcuts.iter().cloned());
    let found = isolated_core::boxes::choose_apps(&shortcuts, &exes);
    let mut b = AppBox::load(dirs, &b.name).unwrap_or_else(|| b.clone());
    let names: Vec<String> = found.iter().map(|a| a.name.clone()).collect();
    let added = b.add_apps(found);
    b.save(dirs)?;

    let product = if u.product.is_empty() {
        "The app".to_string()
    } else {
        u.product.clone()
    };
    let mut msg = if added > 0 {
        format!(
            "{product} was unpacked into box '{}' ({} files). Saved {}.\n\nStart it from the Installed apps list in the Isolated window, or run: isolated box run \"{}\" \"{}\"",
            b.name,
            u.files,
            names.join(", "),
            b.name,
            names[0]
        )
    } else if !b.apps.is_empty() {
        format!(
            "{product} was unpacked into box '{}' ({} files). No new programs were found, so the box keeps its saved apps.",
            b.name, u.files
        )
    } else {
        format!(
            "{product} was unpacked into box '{}' ({} files), but no program was found in it. Add the program from the Installed apps list.",
            b.name, u.files
        )
    };
    msg.push_str("\n\nIsolated unpacks .msi files itself, without running the installer's own code, so settings, services or file types the installer would set up are left out.");
    if u.skipped_system > 0 {
        msg.push_str(&format!(
            " {} files meant for Windows system folders were skipped.",
            u.skipped_system
        ));
    }
    finish_install(&b, added, &msg, out)
}

fn read_head(path: &std::path::Path, max: u64) -> Vec<u8> {
    use std::io::Read;
    let mut buf = Vec::new();
    if let Ok(f) = std::fs::File::open(path) {
        let _ = f.take(max).read_to_end(&mut buf);
    }
    buf
}

# Isolated: Project Plan

Isolated is an app isolation tool written in Rust. It lets users run any program
inside a sandbox that limits what the program can see and touch: files, network,
other processes, devices, and system resources. The goal is that a user can say
"run this app, but only let it read my Downloads folder and never reach the
internet" and trust that the operating system enforces it.

This document covers what Isolated is for, how it is built, how isolation works
on each platform, and the order in which it will be delivered.

> **Target for v1:** **Windows 10 (1809+) and Windows 11**, delivered as a
> small **egui desktop app** whose main entry point is a **"Run in Isolated"
> option in the Windows right-click context menu**. A command-line tool ships
> alongside it, sharing the same core. Linux and macOS backends come in later
> milestones.
>
> **Lightweight is a core requirement.** No web view, no runtime, no always-on
> background service, and nothing running at all when no sandbox is active.
> See section 3.1 for concrete budgets.

---

## 1. Goals and non-goals

### Goals

- **Run untrusted or semi-trusted apps safely.** Downloaded installers and
  executables, closed-source tools, game mods, scripts, AI agents, and so on.
- **Least privilege by default.** A sandboxed app starts with nothing (no user
  folders, no network, no clipboard) and users grant only what it needs.
- **Easy for non-technical users.** Right-click an `.exe` and choose "Run in
  Isolated", or drag it onto the Isolated window. No configuration required
  for the safe default.
- **Readable, shareable policies.** Every sandbox is described by a small TOML
  profile that the GUI edits and that advanced users can review and reuse.
- **No administrator rights for everyday use.** Use AppContainer, restricted
  tokens, and Job Objects, which work for standard users. Admin is needed only
  for optional features (network allowlists) installed once.
- **Clear feedback.** When a sandboxed app is denied something, users see what
  was blocked and can choose to allow it.

### Non-goals (for now)

- Full virtual machines. Isolated is process-level sandboxing, lighter than
  Windows Sandbox or Hyper-V. A VM tier may be considered much later.
- Replacing container runtimes like Docker for deploying services.
- Defending against kernel or driver exploits. Isolated reduces attack surface
  but relies on the Windows kernel being sound.
- Mobile platforms.

---

## 2. Who uses it and how

| User | What they want |
| --- | --- |
| Everyday desktop users | Open a sketchy download or a closed-source app without giving it their whole user folder. |
| Gamers and modders | Run mods, trainers, and launchers without exposing personal files or browser data. |
| Developers | Run third-party build scripts and tools without exposing SSH keys, tokens, or the network. |
| People running AI agents or automation | Give a tool a scratch folder and nothing else. |
| Security-minded users | Write strict profiles for specific apps and audit what they try to do. |

### Main GUI flows

1. **Quick run (primary flow).** Right-click an `.exe` (or a shortcut, `.bat`,
   `.cmd`, `.ps1`, or `.msi` extracted payload) in Explorer and choose
   **Run in Isolated**. It launches straight away with the app's saved profile,
   or with `strict` if there isn't one: empty private folder, no network, no
   clipboard. No window opens unless something needs the user's attention.
   A submenu offers **Run in Isolated (offline)**, **Run in Isolated with
   options...** (opens a small egui dialog with permission toggles), and
   **Edit Isolated profile...**.
2. **Create an app profile.** In the Isolated window, choose **Add app**, pick an
   executable, and toggle permissions: folders (read-only or read-write),
   network (off, on, or allowlist), clipboard, microphone, camera, printers.
   The app then appears as a tile users can launch.
3. **See what's running.** A **Running** view lists every sandbox, its processes,
   CPU and memory use, and a **Stop** button.
4. **Handle a denial.** When an app is blocked from something, a notification
   says what was denied ("Converter tried to read Documents\\Taxes"). Users can
   allow once, allow always (updates the profile), or ignore.
5. **Learn mode.** Run an app with monitoring on, use it normally, and Isolated
   proposes a profile with only the access it actually used.

### Command-line companion

The same features are available from a terminal for scripting:

```powershell
isolated run --no-net --private-home -- .\suspicious.exe
isolated run --ro "$HOME\Documents\input" --rw "$HOME\Documents\output" -- converter.exe
isolated run --profile game-mod -- .\launcher.exe
isolated ps
isolated kill <id>
```

---

## 3. Architecture overview

```
   Explorer right-click ──► isolated.exe run "<target>"      (no window)
                                   │
   isolated.exe (egui window) ─────┤   same single binary
   isolated.exe (CLI)  ────────────┤
                                   ▼
             ┌─────────────────────────────────────────┐
             │ isolated-core                           │
             │ policy, profiles, lifecycle, events     │
             └──────────────────┬──────────────────────┘
                                │ Backend trait
             ┌──────────────────┼───────────────────────┐
             ▼                  ▼                       ▼
     isolated-windows    isolated-linux (later)  isolated-macos (later)
     AppContainer,       namespaces, Landlock,   Seatbelt
     Job Objects,        seccomp, cgroups v2
     restricted tokens
                                │
                                ▼
     per-sandbox watcher: the same isolated.exe process stays alive,
     windowless, waiting on the Job Object; exits when the app exits

     isolated-service.exe (optional, admin install): WFP network allowlists
```

Key ideas:

1. **One small binary.** `isolated.exe` is the context-menu handler target, the
   GUI, and the CLI. Which one runs depends on the arguments. There is no
   separate agent or helper DLL to install or keep running.
2. **Context menu first.** The right-click entry is the main way users start
   sandboxes. The egui window is for managing profiles, viewing running
   sandboxes, and responding to denials, and only opens when asked for.
3. **Nothing resident.** No startup entry and no background service by default.
   When a sandbox is launched, that `isolated.exe` process becomes a windowless
   watcher: it waits on the Job Object, cleans up ACLs and temp folders when the
   app exits, then exits itself. Running sandboxes register in a small shared
   file under `%LOCALAPPDATA%\Isolated\running\` so the GUI and `isolated ps`
   can list and stop them.
4. **One policy model, many backends.** Users configure one profile. Each
   platform backend translates it into native mechanisms and reports anything
   it cannot enforce, so nothing is silently weaker than requested.
5. **Fail closed.** If a requested restriction cannot be applied, the launch
   fails with a clear message unless the user explicitly accepts a weaker
   sandbox.
6. **Admin only where unavoidable.** Network allowlists need Windows Filtering
   Platform rules, which require a privileged service. That service is an
   optional install; everything else works for standard users.

### 3.1 Lightweight budgets

These are release-blocking targets, measured in CI:

| Measure | Target |
| --- | --- |
| Installer size | under 5 MB |
| `isolated.exe` size (GUI + CLI + backend) | under 6 MB |
| Memory when no sandbox is running | 0 (no process running) |
| Memory per sandbox watcher | under 3 MB working set |
| GUI window memory | under 40 MB |
| Context-menu click to app start | under 150 ms |
| Runtime dependencies | none (no .NET, no WebView2, no VC++ redistributable: CRT statically linked) |

How the plan meets them:

- **egui via `eframe` with the `glow` (OpenGL) backend** instead of `wgpu`, which
  keeps the binary small. Fall back to software rendering if no GPU driver.
- **No async runtime.** Launching and watching a sandbox is a handful of Win32
  calls and one blocking wait; plain `std` threads are enough. No `tokio`.
- **Minimal dependencies.** Only the `windows` crate features actually used are
  enabled; `default-features = false` everywhere.
- **Release profile:** `opt-level = "s"`, `lto = "fat"`, `codegen-units = 1`,
  `panic = "abort"`, `strip = true`, `+crt-static`.
- **The watcher never loads the GUI.** The egui and OpenGL code paths are only
  touched when a window is opened, so a context-menu launch stays tiny.
- **Dependency and size checks in CI** (`cargo bloat`, `cargo tree -d`) fail the
  build if a budget is exceeded.

### The `Backend` trait (sketch)

```rust
pub trait Backend {
    /// What this platform can enforce, so core can warn or refuse.
    fn capabilities(&self) -> Capabilities;

    /// Apply the policy and start the program. Returns a handle to the sandbox.
    fn spawn(&self, policy: &Policy, cmd: &Command) -> Result<SandboxHandle, SpawnError>;
}

pub trait SandboxHandle {
    fn id(&self) -> SandboxId;
    fn wait(&mut self) -> Result<ExitStatus, Error>;
    fn kill(&mut self) -> Result<(), Error>;
    fn events(&mut self) -> Box<dyn Iterator<Item = SandboxEvent> + '_>;
}
```

---

## 4. Policy model

A policy is a plain data structure in `isolated-core`. Profiles are TOML files
(stored under `%APPDATA%\Isolated\profiles\`) that deserialize into it. The GUI
reads and writes these same files.

```toml
name = "converter"
description = "Image converter: reads input, writes output, nothing else"
program = 'C:\Tools\Converter\converter.exe'

[filesystem]
read_only    = ['~\Documents\input']
read_write   = ['~\Documents\output']
private_home = true        # app gets its own empty AppData/profile folders

[network]
mode = "none"              # none | loopback | full | allowlist
# allow = ["api.example.com:443"]   # needs isolated-service

[process]
see_other_processes = false

[devices]
clipboard  = "none"        # none | read | write | full
microphone = false
camera     = false
printers   = false
gpu        = true          # most GUI apps need it

[ui]
separate_desktop = false   # run on its own desktop to block keylogging/screen reads
mark_windows     = true    # colored border on sandboxed windows

[resources]
memory_max    = "2G"
cpu_percent   = 100
max_processes = 64

[env]
pass = ["LANG"]
set  = { NO_UPDATE_CHECK = "1" }
```

Rules:

- Everything not granted is denied.
- Profiles are matched to programs by full path (and optionally file hash), so
  the context menu picks the right profile automatically.
- Paths are canonicalized, with junctions, symlinks, and 8.3 short names
  resolved before enforcement.
- Built-in profiles ship for common cases (`strict`, `offline`, `game-mod`,
  `dev-build`, `browser-like`) and profiles can `extends = "strict"`.
- CLI flags and one-off GUI toggles override profile values for a single run.

---

## 5. Isolation mechanisms per platform

### 5.1 Windows (v1)

#### Context-menu integration

Kept as light as possible: **plain registry verbs, no shell extension DLL**.
The installer (or `isolated.exe --register`, per-user, no admin) writes keys
under `HKCU\Software\Classes`:

```
HKCU\Software\Classes\exefile\shell\Isolated
    MUIVerb      = "Run in Isolated"
    Icon         = "C:\...\isolated.exe,0"
    SubCommands  = ""
    shell\01run\command      = "C:\...\isolated.exe" run "%1"
    shell\02offline\command  = "C:\...\isolated.exe" run --no-net "%1"
    shell\03options\command  = "C:\...\isolated.exe" options "%1"
    shell\04profile\command  = "C:\...\isolated.exe" profile edit "%1"
```

Equivalent entries are added for `lnkfile`, `batfile`, `cmdfile`, and
`Microsoft.PowerShellScript.1`. `isolated.exe --unregister` removes them all.

Tradeoff: on **Windows 11** classic registry verbs appear under
**Show more options**, not in the compact top-level menu. Getting into the
top-level menu requires an `IExplorerCommand` COM handler registered through a
sparse MSIX package. That is planned as an **optional add-on in M3**, written
as a tiny separate DLL so the main binary stays unchanged. Users who don't
want it keep the zero-DLL setup.

#### Isolation mechanisms

| Concern | Mechanism | Notes |
| --- | --- | --- |
| Identity | **AppContainer** with a per-profile SID (`CreateAppContainerProfile`) | The app runs as the user but with a capability-based token that is denied almost everything by default. |
| Stricter identity | **Less Privileged AppContainer (LPAC)** for the `strict` profile | Also blocks access to resources that grant "ALL APPLICATION PACKAGES". |
| Filesystem | ACL grants to the AppContainer SID on allowed paths only | Grants are recorded in a journal and removed on exit, crash, or next Isolated launch. |
| Private home | Per-sandbox AppContainer storage folder, plus `USERPROFILE`/`APPDATA`/`TEMP` redirected to it | App can write settings without touching real ones. |
| Registry | AppContainer's private registry hive; no grants to `HKCU` by default | |
| Network: none / full | AppContainer capabilities (`internetClient`, `privateNetworkClientServer`) omitted or granted | Enforced by the OS firewall for AppContainers. |
| Network: loopback | Loopback exemption scoped to the sandbox SID | |
| Network: allowlist | **Windows Filtering Platform** filters keyed on the AppContainer SID, installed by `isolated-service` | Needs the optional admin service. |
| Processes and resources | **Job Objects**: kill-on-job-close, active process limit, memory and CPU rate limits, breakaway disabled | Every child the app spawns stays in the job. |
| Window and input isolation | Job UI restrictions (clipboard read/write, global atoms, `SetWindowsHookEx` blocked via UIPI and low integrity), optional **separate desktop** | Separate desktop stops screen scraping and key logging of other apps. |
| Privilege | Restricted token, low integrity level, all privileges removed | |
| Exploit mitigations | `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`: disable child process creation (when profile allows), block non-Microsoft-signed DLLs (opt-in), CFG/CET strict, no remote image loads | Applied at `CreateProcess` time. |
| Devices | AppContainer capabilities for microphone, webcam, removable storage, documents library | Off unless the profile grants them. |

Launch sequence on Windows (triggered by the context menu, GUI, or CLI):

1. `isolated.exe` loads the profile matching the target path (or `strict`),
   validates it, and checks Windows build and features.
2. Create or open the AppContainer profile for this app (or LPAC for strict).
3. Apply ACL grants for allowed paths and write them to the cleanup journal.
4. If network allowlist is set, ask `isolated-service` to install WFP filters
   for the sandbox SID.
5. Create a Job Object with limits and UI restrictions; optionally create a
   separate desktop.
6. Build `STARTUPINFOEX` with the AppContainer security capabilities, mitigation
   policies, job list, and handle allowlist (no inherited handles except
   stdio), then `CreateProcessW` suspended.
7. Assign to job, resume the main thread.
8. The same process drops into windowless watcher mode: it registers the
   sandbox in the running list, waits on the job, then removes ACLs, WFP
   filters, and temporary folders and exits.

Known challenges and how the plan handles them:

- **Many classic Win32 apps break in AppContainer** (they expect to write
  next to their `.exe`, read `HKCU`, or use COM servers). Mitigation: a
  "compatible" tier that uses a restricted token + low integrity + Job Object
  without AppContainer, clearly labeled in the GUI as weaker. Built-in profiles
  record which tier each common app needs.
- **Installers that need admin.** Since v0.2, installers run inside an *app
  box*: a sandbox whose folders are kept. The installer starts without admin
  rights (`RunAsInvoker`), Inno Setup and NSIS installers are asked to install
  for the current user into the box, and `.msi` files go through per-user
  `msiexec`. Afterwards the shortcuts and programs the installer created are
  saved in the box so users can start them again. Installers that truly need
  admin (drivers, services, system-wide components) still cannot be
  sandboxed, and the GUI says so.
- **ACL leftovers after a crash.** The cleanup journal is replayed on the next
  launch of `isolated.exe`; a "Repair" button in the GUI does the same on
  demand.
- **Denial visibility.** Windows doesn't report AppContainer access denials
  directly. Isolated reads them from **ETW** (Kernel-File, Security auditing
  for object access, WFP drop events) filtered by the sandbox SID. This also
  powers learn mode.
- **Code signing and SmartScreen.** Release binaries are signed (Azure Trusted
  Signing or an EV certificate) so users aren't warned away at install time.

### 5.2 Linux (milestone 5)

| Concern | Mechanism |
| --- | --- |
| Filesystem view | Mount namespace, bind mounts, `pivot_root` onto a tmpfs root |
| Filesystem access (second layer) | **Landlock** (kernel 5.13+) |
| Network | Network namespace; allowlists via `pasta`/`slirp4netns` and a filtering proxy |
| Processes, IPC, users | PID, IPC, UTS, and user namespaces (no root needed) |
| System calls | **seccomp-bpf** filter |
| Privilege | `PR_SET_NO_NEW_PRIVS`, drop all capabilities |
| Resources | cgroups v2 via systemd user slices |
| Display | Wayland socket passthrough; X11 only with a warning |

Caveat: Ubuntu 23.10+ restricts unprivileged user namespaces through AppArmor,
so Isolated will ship an AppArmor profile.

### 5.3 macOS (milestone 6)

| Concern | Mechanism |
| --- | --- |
| Filesystem, network, IPC | **Seatbelt** profiles (SBPL) generated from the policy and applied via `sandbox_init` before exec |
| Resources | `setrlimit`, process group tracking |

Seatbelt's public API is deprecated but still widely used (Chrome, Bazel); the
backend is kept separate so it can be replaced if needed.

### 5.4 Capability matrix

| Feature | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Filesystem allowlist | Yes | Yes | Yes |
| Hidden filesystem (not just denied) | Partial | Yes | No |
| No network | Yes | Yes | Yes |
| Host:port allowlist | Yes (service) | Yes (proxy) | Partial |
| Clipboard and input isolation | Yes | Partial (Wayland) | No |
| Process visibility | Partial | Yes | No |
| Syscall filtering | Partial (mitigations) | Yes | No |
| Resource limits | Yes | Yes | Partial |
| No admin/root needed | Yes* | Yes** | Yes |

\* Except network allowlists. \*\* Requires unprivileged user namespaces.

---

## 6. Crate layout

A Cargo workspace:

```
isolated/
├── Cargo.toml                # workspace
├── crates/
│   ├── isolated-core/        # policy, profiles, Backend trait, lifecycle, events
│   ├── isolated-windows/     # Windows backend: AppContainer, jobs, ACLs, context-menu registration
│   ├── isolated-gui/         # egui screens (library, linked into the main binary)
│   ├── isolated/             # the single `isolated.exe`: CLI + GUI + watcher
│   ├── isolated-service/     # optional admin Windows service for WFP (M4)
│   ├── isolated-shellext/    # optional Windows 11 top-level menu DLL (M3)
│   ├── isolated-linux/       # later
│   └── isolated-macos/       # later
├── profiles/                 # built-in profiles
├── installer/                # WiX / MSIX packaging
├── tests/                    # escape tests and integration tests
└── docs/
```

### Third-party crates

Kept deliberately short.

| Purpose | Crate |
| --- | --- |
| Windows APIs (AppContainer, jobs, ACLs, WFP, desktops, registry) | `windows` (official Microsoft bindings, only needed features enabled) |
| GUI | `eframe` / `egui` with the `glow` renderer |
| CLI parsing | `lexopt` (tiny) or `clap` with default features off |
| Profiles | `serde`, `toml` |
| Errors | `thiserror` in libraries; plain `Box<dyn Error>` in the binary |
| Logging | `log` + a small file logger (off unless enabled) |
| ETW denial events (M4) | `ferrisetw`, behind a cargo feature |
| Windows service (M4, optional) | `windows-service` |
| Linux later | `rustix`, `landlock`, `seccompiler` |
| Testing (dev only) | `assert_cmd`, `insta`, `proptest` |

**Why egui:** it is pure Rust, builds into the same binary as the core with no
web view or runtime, starts instantly, and needs no separate frontend toolchain.
It also runs on Linux and macOS when those backends arrive.

---

## 7. Security approach

- **Defense in depth.** AppContainer identity, low integrity, restricted token,
  Job Object, and mitigation policies each block different escape routes.
- **Minimal `unsafe`.** All Win32 calls live in `isolated-windows` behind small,
  documented safe wrappers (owned handles, RAII ACL grants that revert on drop).
  `isolated-core` and `isolated-gui` use `#![forbid(unsafe_code)]`.
- **Context-menu input is untrusted.** Paths arriving from `%1` are
  canonicalized and checked before use; the verb never runs through a shell.
- **Small privileged surface.** `isolated-service` only installs and removes WFP
  filters for SIDs it created, validates every request, and accepts connections
  only from `isolated.exe` processes run by the same user.
- **Escape test suite.** Small hostile programs that try to read the real user
  folder, browser profiles, and SSH keys; open sockets; inject into or read
  memory of other processes; hook keyboard input; read the clipboard; escape
  the job by breakaway; abuse junctions and TOCTOU races; fork-bomb. Every one
  must fail in CI.
- **Fuzzing.** `cargo-fuzz` targets for profile parsing, path normalization, and
  service request decoding.
- **Supply chain.** `cargo-deny` and `cargo-audit` in CI; a short, reviewed
  dependency list; signed releases.
- **Threat model doc.** A `docs/THREAT_MODEL.md` written in M0 stating exactly
  what Isolated defends against and what it does not.
- **Disclosure.** `SECURITY.md` with a private reporting address before the
  first public release.

---

## 8. Milestones

Each milestone ends with something users can run.

### Status: v0.1.0 shipped

v0.1.0 delivers the core of M0 to M3 in one release: policy and profiles,
the AppContainer + Job Object engine with journaled ACL grants, the
right-click menu, the egui window, the CLI, and a real-Windows smoke test
suite in CI. Two changes from the plan below, both in the spirit of keeping
it light:

- **Installer:** instead of a WiX MSI, `isolated.exe` installs itself per
  user (`isolated install` or Settings > Install): it copies itself to
  `%LOCALAPPDATA%\Programs\Isolated`, adds a Start menu shortcut, the
  right-click menu, and a Settings > Apps uninstall entry. No admin.
- **Auto-updater (added):** on window open, Isolated checks GitHub Releases,
  downloads `isolated.exe`, verifies it against the published
  `isolated.exe.sha256`, and swaps it in place. No background service.

Still to come from M2 to M4: window marking, separate desktop, the Windows 11
top-level menu add-on, code signing, winget, denial notifications, learn
mode, loopback and allowlist networking.

### M0: Foundations (1 to 2 weeks)
- Cargo workspace; CI on Windows (fmt, clippy, tests, `cargo-deny`), with Linux
  and macOS build checks for the core.
- `isolated-core` policy types, TOML profiles, validation, unit tests.
- `THREAT_MODEL.md` first draft.
- **Deliverable:** `isolated profile check <file>` validates a profile.

### M1: Windows sandbox engine (4 weeks)
- AppContainer and LPAC creation, per-sandbox storage and private home.
- ACL grants with cleanup journal; Job Objects with limits and UI restrictions.
- Restricted token, low integrity, mitigation policies.
- Network none / full / loopback via capabilities.
- `isolated run` CLI and windowless watcher mode; escape test suite v1.
- Size and memory budgets wired into CI from the start.
- **Deliverable:** a working CLI sandbox on Windows (early testers).

### M2: Context menu and egui app (3 to 4 weeks)
- `isolated --register` / `--unregister` writing the per-user context-menu
  verbs for `.exe`, `.lnk`, `.bat`, `.cmd`, `.ps1`.
- Profile matching by program path, so a right-click uses the saved profile.
- egui window: app profiles list, permission toggles, **Running** view with
  stop, the "with options..." dialog, settings.
- Sandboxed-window marking (border or badge).
- Built-in profiles; "compatible" tier for apps that break in AppContainer.
- **Deliverable:** users can right-click any program and run it sandboxed.

### M3: First release (2 to 3 weeks)
- Small installer (WiX MSI) and a portable zip; winget package; code signing.
- Optional Windows 11 top-level context-menu add-on (`IExplorerCommand` DLL).
- Clipboard, microphone, camera, printer permission controls.
- Optional separate-desktop mode.
- **Deliverable:** first public release, **v0.1**, within the size budgets.

### M4: Denials, learn mode, and network allowlists (4 weeks)
- ETW-based denial events surfaced as Windows toast notifications with allow
  once / allow always (the watcher raises them; the GUI isn't needed).
- Learn mode that proposes a profile from observed access.
- `isolated-service` and WFP-based host:port allowlists, installed on demand.
- **Deliverable:** v0.2.

### M5: Linux backend (4 weeks)
- Namespaces, Landlock, seccomp, cgroups v2; egui app and CLI work unchanged.
- File-manager integration (Nautilus/Dolphin actions) mirroring the context menu.
- **Deliverable:** v0.3 with Linux support.

### M6: macOS backend (3 to 4 weeks)
- Seatbelt profile generation; signed and notarized app.
- **Deliverable:** v0.4 with macOS support, then stabilization toward **v1.0**.

---

## 9. Testing strategy

| Layer | How |
| --- | --- |
| Policy and profile logic | Unit tests and `proptest` in `isolated-core`. |
| Windows backend | Integration tests on GitHub Actions Windows runners that launch real sandboxes and assert what the child can and cannot do. |
| Escape suite | Hostile test binaries run under each built-in profile; any success fails CI. |
| OS coverage | Test matrix across Windows 10 22H2, Windows 11 current, and Windows Server 2022 (runner image). |
| App compatibility | A list of popular apps (7-Zip, VLC, Notepad++, game launchers, Python, Node) launched under their built-in profiles in a nightly VM job. |
| Context menu | Tests that `--register` / `--unregister` write and remove exactly the expected keys, and that the verbs launch correctly with tricky paths (spaces, Unicode, quotes). |
| GUI | Unit tests on GUI state; `egui_kittest` snapshot tests of key screens. |
| Footprint | CI fails if binary size, installer size, watcher memory, or launch time exceeds the budgets in section 3.1. |
| CLI | `assert_cmd` + `insta` snapshots of output and error messages. |
| Performance | Benchmark launch overhead (target under 150 ms); regressions over 20% fail CI. |

---

## 10. Open questions

1. **Compatibility versus strictness.** How prominently should the GUI offer the
   weaker "compatible" tier for apps that break in AppContainer?
2. **Licensing.** Apache-2.0 / MIT dual license is the Rust norm; GPL is an
   option to keep forks open.
3. **Distribution.** MSI + winget only, or also the Microsoft Store (MSIX)? Store
   packaging limits the admin service.
4. **Windows 11 top-level menu.** Is the optional `IExplorerCommand` add-on
   worth shipping in v0.1, or is "Show more options" acceptable at first?
5. **Pricing / openness.** Fully open source, or open core with paid extras?

---

## 11. Prior art to learn from

- **Sandboxie Plus**: Windows app sandboxing UX and compatibility lessons.
- **Chromium sandbox**: the reference design for AppContainer + jobs + tokens.
- **Windows Sandbox** and **Microsoft's Win32 app isolation**: Microsoft's own
  approaches and where they draw lines.
- **Bubblewrap**, **Flatpak**, **Firejail**: Linux sandboxing for the later
  backend.
- **Firecracker**'s `seccompiler` and the `landlock` crate for Linux.

# Isolated: Project Plan

Isolated is an app isolation tool written in Rust. It lets users run any program
inside a sandbox that limits what the program can see and touch: files, network,
other processes, devices, and system resources. The goal is that a user can say
"run this app, but only let it read my Downloads folder and never reach the
internet" and trust that the operating system enforces it.

This document covers what Isolated is for, how it is built, how isolation works
on each platform, and the order in which it will be delivered.

> **Target for v1:** **Windows 10 (1809+) and Windows 11**, delivered as a
> **desktop GUI app**. A command-line tool ships alongside it, sharing the same
> core. Linux and macOS backends come in later milestones. The architecture is
> designed so those additions do not require reworking the core.

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

1. **Quick run.** Right-click an `.exe` in Explorer, choose **Run in Isolated**.
   It launches with the `strict` profile: empty private folder, no network, no
   clipboard. A colored border or taskbar badge marks the window as sandboxed.
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
   ┌──────────────────────────────────────────────────────────────┐
   │ Front ends                                                   │
   │ isolated-gui (v1, Tauri)        isolated-cli (v1, companion) │
   │ Explorer context-menu handler                                │
   └──────────────┬───────────────────────────────────────────────┘
                  │ local IPC (named pipe)
   ┌──────────────▼───────────────────────────────────────────────┐
   │ isolated-agent  (per-user background process, no admin)      │
   │ • Launches and tracks sandboxes                              │
   │ • Collects denial events, raises notifications               │
   │ • Cleans up ACLs and temp folders on exit or crash           │
   └──────────────┬───────────────────────────┬───────────────────┘
                  │ uses                      │ optional, named pipe
   ┌──────────────▼──────────────┐   ┌────────▼───────────────────┐
   │ isolated-core               │   │ isolated-service           │
   │ policy, profiles, lifecycle │   │ (Windows service, admin    │
   │ events, Backend trait       │   │ install) WFP network rules │
   └──────────────┬──────────────┘   └────────────────────────────┘
                  │ Backend trait
     ┌────────────┼───────────────────────┐
     ▼            ▼                       ▼
isolated-windows  isolated-linux (later)  isolated-macos (later)
AppContainer,     namespaces, Landlock,   Seatbelt
Job Objects,      seccomp, cgroups v2
restricted tokens
```

Key ideas:

1. **One policy model, many backends.** Users configure one profile. Each
   platform backend translates it into native mechanisms and reports anything
   it cannot enforce, so nothing is silently weaker than requested.
2. **Fail closed.** If a requested restriction cannot be applied, the launch
   fails with a clear message unless the user explicitly accepts a weaker
   sandbox.
3. **Thin front ends.** The GUI and CLI only collect input and display results.
   All logic lives in `isolated-core` and the agent, so both behave identically.
4. **A per-user agent from day one.** The GUI needs live sandbox lists, denial
   notifications, and reliable cleanup even when the GUI is closed, so a small
   per-user agent (started at login, runs without admin) owns sandbox
   lifecycles. The CLI talks to the agent if it's running and can launch
   sandboxes directly if not.
5. **Admin only where unavoidable.** Network allowlists need Windows Filtering
   Platform rules, which require a privileged service. That service is an
   optional install; everything else works for standard users.

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
- Paths are canonicalized, with junctions, symlinks, and 8.3 short names
  resolved before enforcement.
- Built-in profiles ship for common cases (`strict`, `offline`, `game-mod`,
  `dev-build`, `browser-like`) and profiles can `extends = "strict"`.
- CLI flags and one-off GUI toggles override profile values for a single run.

---

## 5. Isolation mechanisms per platform

### 5.1 Windows (v1)

Windows has no single sandbox primitive, so Isolated layers several, the same
approach Chromium and Edge use.

| Concern | Mechanism | Notes |
| --- | --- | --- |
| Identity | **AppContainer** with a per-profile SID (`CreateAppContainerProfile`) | The app runs as the user but with a capability-based token that is denied almost everything by default. |
| Stricter identity | **Less Privileged AppContainer (LPAC)** for the `strict` profile | Also blocks access to resources that grant "ALL APPLICATION PACKAGES". |
| Filesystem | ACL grants to the AppContainer SID on allowed paths only | Grants are recorded in a journal and removed on exit, crash, or next agent start. |
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

Launch sequence on Windows:

1. Agent loads and validates the policy; checks Windows build and features.
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
8. Agent watches the job for process events and exit, collects denial events,
   then removes ACLs, WFP filters, and temporary folders.

Known challenges and how the plan handles them:

- **Many classic Win32 apps break in AppContainer** (they expect to write
  next to their `.exe`, read `HKCU`, or use COM servers). Mitigation: a
  "compatible" tier that uses a restricted token + low integrity + Job Object
  without AppContainer, clearly labeled in the GUI as weaker. Built-in profiles
  record which tier each common app needs.
- **Installers that need admin.** Out of scope for v1; the GUI explains that
  elevated programs cannot be sandboxed and suggests extracting or using
  portable versions.
- **ACL leftovers after a crash.** The cleanup journal is replayed on agent
  start; a "Repair" button in settings does the same on demand.
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
│   ├── isolated-ipc/         # agent/service protocol types and named-pipe transport
│   ├── isolated-windows/     # Windows backend: AppContainer, jobs, ACLs, ETW
│   ├── isolated-agent/       # per-user agent
│   ├── isolated-service/     # optional admin Windows service (WFP)
│   ├── isolated-shell/       # Explorer context-menu handler (COM, IExplorerCommand)
│   ├── isolated-cli/         # `isolated` binary
│   ├── isolated-gui/         # Tauri desktop app
│   ├── isolated-linux/       # later
│   └── isolated-macos/       # later
├── gui/                      # GUI frontend (TypeScript + a small component library)
├── profiles/                 # built-in profiles
├── installer/                # WiX / MSIX packaging
├── tests/                    # escape tests and integration tests
└── docs/
```

### Third-party crates

| Purpose | Crate |
| --- | --- |
| Windows APIs (AppContainer, jobs, ACLs, WFP, desktops) | `windows` (official Microsoft bindings) |
| ETW consumption for denial events | `ferrisetw` |
| Windows service | `windows-service` |
| Explorer integration (COM) | `windows` with `implement` feature |
| GUI shell | `tauri` v2 (uses WebView2, present on Windows 10/11) |
| Notifications | `tauri-plugin-notification` |
| CLI parsing | `clap` (derive) |
| Config and profiles | `serde`, `toml` |
| IPC messages | `serde` + `postcard` over named pipes (`tokio::net::windows::named_pipe`) |
| Async (agent, service, GUI) | `tokio` |
| Errors | `thiserror` (libraries), `anyhow` (binaries) |
| Logging | `tracing`, `tracing-subscriber`, `tracing-appender` |
| Linux later | `rustix`, `landlock`, `seccompiler` |
| Testing | `assert_cmd`, `insta`, `proptest` |

**Why Tauri for the GUI:** WebView2 ships with Windows 10/11, so the installer
stays small; the UI can be built quickly with familiar web tooling; the Rust
side calls `isolated-core` directly; and Tauri runs on Linux and macOS when
those backends arrive. `iced` or `slint` are pure-Rust alternatives if a
web-free UI becomes a priority.

---

## 7. Security approach

- **Defense in depth.** AppContainer identity, low integrity, restricted token,
  Job Object, and mitigation policies each block different escape routes.
- **Minimal `unsafe`.** All Win32 calls live in `isolated-windows` behind small,
  documented safe wrappers (owned handles, RAII ACL grants that revert on drop).
  `isolated-core`, `isolated-cli`, and the GUI use `#![forbid(unsafe_code)]`.
- **Small privileged surface.** `isolated-service` only installs and removes WFP
  filters for SIDs it created, validates every request, and accepts connections
  only from the user's agent.
- **Escape test suite.** Small hostile programs that try to read the real user
  folder, browser profiles, and SSH keys; open sockets; inject into or read
  memory of other processes; hook keyboard input; read the clipboard; escape
  the job by breakaway; abuse junctions and TOCTOU races; fork-bomb. Every one
  must fail in CI.
- **Fuzzing.** `cargo-fuzz` targets for profile parsing, path normalization, and
  IPC message decoding.
- **Supply chain.** `cargo-deny` and `cargo-audit` in CI; npm dependencies for the
  GUI pinned and audited; signed releases.
- **Threat model doc.** A `docs/THREAT_MODEL.md` written in M0 stating exactly
  what Isolated defends against and what it does not.
- **Disclosure.** `SECURITY.md` with a private reporting address before the
  first public release.

---

## 8. Milestones

Each milestone ends with something users can run.

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
- `isolated run` CLI for testing the engine; escape test suite v1.
- **Deliverable:** a working CLI sandbox on Windows (internal / early testers).

### M2: GUI and agent MVP (4 to 5 weeks)
- `isolated-agent` with named-pipe IPC, sandbox tracking, crash cleanup.
- Tauri app: app list, **Add app** wizard with permission toggles, launch,
  **Running** view with stop, settings.
- Sandboxed-window marking (border or badge).
- Built-in profiles; "compatible" tier for apps that break in AppContainer.
- **Deliverable:** users can install Isolated, add an app, and run it sandboxed
  from the GUI.

### M3: Windows integration and first release (3 weeks)
- Explorer **Run in Isolated** context menu; drag-and-drop onto the window.
- Start-menu shortcuts for sandboxed apps.
- MSI installer (WiX) and winget package; code signing; auto-update.
- Clipboard, microphone, camera, printer permission controls.
- Optional separate-desktop mode.
- **Deliverable:** first public release, **v0.1**.

### M4: Denials, learn mode, and network allowlists (4 weeks)
- ETW-based denial events surfaced as GUI notifications with allow once /
  allow always.
- Learn mode that proposes a profile from observed access.
- `isolated-service` and WFP-based host:port allowlists, installed on demand.
- **Deliverable:** v0.2.

### M5: Linux backend (4 weeks)
- Namespaces, Landlock, seccomp, cgroups v2; GUI and CLI work unchanged on Linux.
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
| GUI | Frontend component tests; end-to-end tests with WebDriver (`tauri-driver`). |
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
4. **GUI framework.** Tauri is the recommendation above; confirm before M2.
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

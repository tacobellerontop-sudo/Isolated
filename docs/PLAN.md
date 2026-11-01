# Isolated: Project Plan

Isolated is an app isolation tool written in Rust. It lets users run any program
inside a sandbox that limits what the program can see and touch: files, network,
other processes, devices, and system resources. The goal is that a user can say
"run this app, but only let it read my Downloads folder and never reach the
internet" and trust that the operating system enforces it.

This document covers what Isolated is for, how it is built, how isolation works
on each platform, and the order in which it will be delivered.

> **Working assumptions (to confirm):** v1 targets **Linux** and ships as a
> **command-line tool**. Windows and macOS backends, and a desktop GUI, come in
> later milestones. The architecture below is designed so that none of those
> later additions require reworking the core.

---

## 1. Goals and non-goals

### Goals

- **Run untrusted or semi-trusted apps safely.** Downloaded binaries, build
  scripts, browser-adjacent tools, AI agents, game mods, and so on.
- **Least privilege by default.** A sandboxed app starts with nothing (no home
  directory, no network, no devices) and users grant only what it needs.
- **Readable, shareable policies.** Users describe a sandbox in a small TOML
  profile that can be reviewed, versioned, and reused.
- **No root required for everyday use.** Use unprivileged mechanisms (user
  namespaces, Landlock, seccomp, AppContainer, Seatbelt) wherever possible.
- **Fast startup.** Launching an app in a sandbox should add well under 100 ms.
- **Clear feedback.** When a sandboxed app is denied something, users can see
  what was blocked and choose to allow it.

### Non-goals (for now)

- Full virtual machines or hardware virtualization. Isolated is process-level
  sandboxing; a VM backend may be considered much later.
- Replacing container runtimes like Docker or Podman for deploying services.
- Defending against kernel exploits. Isolated reduces attack surface but relies
  on the OS kernel being sound.
- Mobile platforms.

---

## 2. Who uses it and how

| User | What they want |
| --- | --- |
| Everyday desktop users | Open a sketchy download or a closed-source app without giving it their whole home folder. |
| Developers | Run `npm install`, `cargo build`, or third-party scripts without exposing SSH keys, tokens, or the network. |
| People running AI agents or automation | Give a tool a scratch directory and nothing else. |
| Security-minded users | Write strict profiles for specific apps and audit what they try to do. |

Example sessions users should be able to run:

```sh
# Run a program with no network and an empty, temporary home directory
isolated run --no-net --tmp-home -- ./suspicious-binary

# Allow read-only access to one folder and read-write to another
isolated run --ro ~/Documents/input --rw ~/Documents/output -- converter

# Use a saved profile
isolated run --profile firefox -- firefox

# Watch what an app tries to access, then generate a starter profile from it
isolated learn -- ./some-tool
isolated profile show some-tool

# List and stop running sandboxes
isolated ps
isolated kill <id>
```

---

## 3. Architecture overview

```
            ┌──────────────────────────────────────────────┐
            │  Front ends                                  │
            │  isolated-cli (v1)      isolated-gui (later) │
            └───────────────┬──────────────────────────────┘
                            │  uses
            ┌───────────────▼──────────────────────────────┐
            │  isolated-core                               │
            │  • Policy model + validation                 │
            │  • Profile loading (TOML)                    │
            │  • Sandbox lifecycle (spawn, wait, kill)     │
            │  • Event stream (denials, exits, stats)      │
            └───────────────┬──────────────────────────────┘
                            │  Backend trait
     ┌──────────────────────┼───────────────────────────┐
     ▼                      ▼                           ▼
isolated-linux        isolated-windows            isolated-macos
namespaces,           AppContainer,               Seatbelt
Landlock, seccomp,    Job Objects,                (sandbox_init),
cgroups v2            restricted tokens           posix_spawn
```

Key ideas:

1. **One policy model, many backends.** Users write one profile. Each platform
   backend translates it into native mechanisms and reports anything it cannot
   enforce, so nothing is silently weaker than requested.
2. **Fail closed.** If a requested restriction cannot be applied, the launch
   fails with a clear error unless the user explicitly passes `--allow-weaker`.
3. **Thin front ends.** The CLI and the future GUI only parse input and display
   output; all logic lives in `isolated-core` so behavior is identical.
4. **Optional daemon.** v1 runs without a background service. A daemon
   (`isolatedd`) arrives later for the GUI, sandbox listing across sessions,
   and permission prompts.

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
that deserialize into it.

```toml
# ~/.config/isolated/profiles/converter.toml
name = "converter"
description = "Image converter: reads input, writes output, nothing else"

[filesystem]
read_only  = ["~/Documents/input", "/usr", "/lib", "/etc/fonts"]
read_write = ["~/Documents/output"]
tmp_home   = true          # fresh empty $HOME, deleted on exit

[network]
mode = "none"              # none | loopback | full | allowlist
# allow = ["api.example.com:443"]   # used when mode = "allowlist"

[process]
see_other_processes = false
allow_new_privileges = false

[devices]
gpu = false
audio = false
camera = false
display = "none"           # none | x11 | wayland

[resources]
memory_max = "2G"
cpu_percent = 100
max_processes = 64

[env]
pass = ["LANG", "TERM"]
set  = { NO_UPDATE_CHECK = "1" }
```

Rules:

- Everything not granted is denied.
- Paths are canonicalized and symlinks resolved before enforcement.
- Built-in profiles ship for common cases (`strict`, `offline`, `dev-build`,
  `gui-app`) and users can `extends = "strict"` to build on them.
- CLI flags override profile values for a single run.

---

## 5. Isolation mechanisms per platform

### 5.1 Linux (v1)

Linux offers the richest, unprivileged toolset. Isolated layers several
mechanisms so that a gap in one is covered by another.

| Concern | Mechanism | Notes |
| --- | --- | --- |
| Filesystem view | Mount namespace + bind mounts + `pivot_root` onto a tmpfs root | Only granted paths are mounted in, read-only where requested. |
| Filesystem access (second layer) | **Landlock** (kernel 5.13+, ABI v3+ preferred) | Enforces path rules even if a mount escape exists. |
| Network | Network namespace | `none` = empty namespace; `loopback` = only `lo`; `full` = host network; `allowlist` = namespace + userspace proxy (via `slirp4netns` or `pasta`) filtering by host:port. |
| Processes | PID namespace | Sandboxed app sees only its own process tree; Isolated is PID 1 inside and reaps zombies. |
| Users | User namespace | Allows all of the above without root. Maps the user to an unprivileged ID inside. |
| IPC / hostname | IPC and UTS namespaces | Blocks shared memory and System V IPC with the host. |
| System calls | **seccomp-bpf** filter | Default deny list for dangerous calls (`ptrace`, `kexec_load`, `bpf`, `mount` after setup, `keyctl`, etc.). Optional notify mode for the `learn` command. |
| Privilege | `PR_SET_NO_NEW_PRIVS`, drop all capabilities | Stops setuid binaries from gaining power. |
| Resources | cgroups v2 (via systemd user slice when available) | Memory, CPU, and process count limits. |
| Display | Wayland socket passthrough (preferred) or X11 with a warning | X11 cannot be meaningfully isolated; profiles must opt in. |

Launch sequence on Linux:

1. Parse and validate the policy; check kernel features (user namespaces
   enabled, Landlock ABI, cgroups v2).
2. `clone3` a child with new user, mount, PID, net, IPC, and UTS namespaces.
3. Parent writes UID/GID maps and, if needed, sets up the network helper.
4. Child builds a tmpfs root, bind-mounts granted paths, mounts `/proc`,
   minimal `/dev`, then `pivot_root` and unmounts the old root.
5. Child applies Landlock rules, drops capabilities, sets `no_new_privs`,
   loads the seccomp filter (last, because it blocks `mount`).
6. Child `execve`s the target program.
7. Parent tracks the sandbox, forwards signals, streams events, cleans up.

Distribution caveats to handle: Ubuntu 23.10+ restricts unprivileged user
namespaces via AppArmor (Isolated will ship an AppArmor profile and explain the
fix); some hardened kernels disable user namespaces entirely (fall back to a
setuid helper only if the user installs it explicitly).

### 5.2 Windows (milestone 4)

| Concern | Mechanism |
| --- | --- |
| Filesystem, registry, named objects | **AppContainer** (or Less Privileged AppContainer) with per-sandbox SID; grant ACLs only to allowed paths. |
| Network | AppContainer capabilities (`internetClient` etc. omitted for no-network); Windows Filtering Platform rules for allowlists. |
| Privilege | Restricted token, low integrity level, removed privileges. |
| Processes and resources | **Job Objects**: kill-on-close, process count, memory and CPU limits, UI restrictions (clipboard, desktop). |
| Mitigations | `SetProcessMitigationPolicy` (block dynamic code, non-Microsoft DLLs where possible, disable Win32k for console apps). |

Crate: `windows` (official Microsoft bindings). ACL changes on user folders must
be reversible and recorded so cleanup always removes them.

### 5.3 macOS (milestone 5)

| Concern | Mechanism |
| --- | --- |
| Filesystem, network, IPC | **Seatbelt** sandbox profiles (SBPL) generated from the policy and applied via `sandbox_init` before exec. |
| Resources | `setrlimit`, process group tracking. |
| Privilege | Run as the user; no new privileges via launch constraints where available. |

Caveat: Seatbelt's public API is deprecated though still used widely (Chrome,
Bazel, Codex CLI). The plan treats it as the pragmatic option and keeps the
backend isolated so it can be replaced if Apple removes it. The Endpoint
Security framework could later power the `learn` command and live denial
events, but it requires an Apple entitlement.

### 5.4 Capability matrix

| Feature | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Filesystem allowlist | Yes | Yes | Yes |
| Hidden filesystem (not just denied) | Yes | Partial | No |
| No network | Yes | Yes | Yes |
| Host:port allowlist | Yes (proxy) | Yes (WFP) | Partial |
| Process visibility | Yes | Partial | No |
| Syscall filtering | Yes | Partial (mitigations) | No |
| Resource limits | Yes | Yes | Partial |
| No root/admin needed | Yes* | Yes | Yes |

\* Requires unprivileged user namespaces to be enabled.

---

## 6. Crate layout

A Cargo workspace:

```
isolated/
├── Cargo.toml                # workspace
├── crates/
│   ├── isolated-core/        # policy, profiles, Backend trait, lifecycle, events
│   ├── isolated-linux/       # Linux backend
│   ├── isolated-windows/     # Windows backend (later)
│   ├── isolated-macos/       # macOS backend (later)
│   ├── isolated-net/         # allowlist proxy shared by backends
│   ├── isolated-cli/         # `isolated` binary
│   ├── isolated-daemon/      # `isolatedd` (later)
│   └── isolated-gui/         # desktop app (later)
├── profiles/                 # built-in profiles
├── tests/                    # escape tests and integration tests
└── docs/
```

### Third-party crates

| Purpose | Crate |
| --- | --- |
| Linux syscalls, namespaces, mounts | `rustix` (preferred) and `nix` where needed |
| Landlock | `landlock` |
| seccomp filters | `seccompiler` (from Firecracker) or `libseccomp` |
| cgroups | direct cgroupfs writes via `rustix`; `zbus` for systemd scopes |
| Windows APIs | `windows` |
| CLI parsing | `clap` (derive) |
| Config and profiles | `serde`, `toml` |
| Errors | `thiserror` (libraries), `anyhow` (binaries) |
| Logging | `tracing`, `tracing-subscriber` |
| Async (daemon, proxy only) | `tokio` |
| Daemon IPC | Unix socket / named pipe with `serde_json` or `postcard` messages |
| GUI | `tauri` or `iced` (decided at milestone 6) |
| Testing | `assert_cmd`, `insta`, `proptest` |

The sandbox launch path itself stays synchronous and small. Code that runs
between `clone` and `execve` must avoid allocation and locks where possible,
since the child of a multithreaded parent is in a fragile state.

---

## 7. Security approach

- **Defense in depth.** On Linux, a filesystem rule is enforced by both mount
  namespaces and Landlock; a network rule by both a network namespace and
  seccomp socket filtering.
- **Minimal `unsafe`.** All `unsafe` lives in the backend crates behind small,
  documented functions. `isolated-core` and `isolated-cli` use
  `#![forbid(unsafe_code)]`.
- **Escape test suite.** A set of small hostile programs that try to read
  `~/.ssh`, open sockets, `ptrace` the parent, escape via `/proc`, abuse
  symlinks and TOCTOU races, fork-bomb, and so on. Every one must fail in CI on
  every supported platform.
- **Fuzzing.** `cargo-fuzz` targets for profile parsing and path normalization.
- **Supply chain.** `cargo-deny` and `cargo-audit` in CI; minimal dependencies in
  the launch path.
- **Threat model doc.** A `docs/THREAT_MODEL.md` written in milestone 1 stating
  exactly what Isolated defends against and what it does not.
- **Disclosure.** `SECURITY.md` with a private reporting address before the
  first public release.

---

## 8. Milestones

Each milestone ends with something users can run.

### M0: Foundations (1 to 2 weeks)
- Cargo workspace, CI (fmt, clippy, tests, `cargo-deny`) on Linux, Windows, macOS.
- `isolated-core` policy types, TOML profile loading, validation, and unit tests.
- `THREAT_MODEL.md` first draft.
- **Deliverable:** `isolated profile check <file>` validates a profile.

### M1: Linux MVP (3 to 4 weeks)
- User, mount, PID, IPC, UTS namespaces; tmpfs root with bind mounts.
- `--no-net` via empty network namespace.
- `no_new_privs`, capability drop, baseline seccomp filter.
- `isolated run` with `--ro`, `--rw`, `--tmp-home`, `--no-net`, `--profile`.
- Escape test suite v1.
- **Deliverable:** users can run a CLI program on Linux with filesystem and
  network isolation, no root needed.

### M2: Linux hardening and usability (3 weeks)
- Landlock second layer; cgroups v2 resource limits.
- Wayland, audio (PipeWire), and GPU passthrough options for GUI apps.
- Built-in profiles; `extends` support.
- Clear diagnostics for disabled user namespaces and AppArmor restrictions.
- Packages: `.deb`, `.rpm`, AUR, and a static musl binary.
- **Deliverable:** first public release, **v0.1**.

### M3: Network allowlists and learn mode (3 weeks)
- `isolated-net` filtering proxy; `mode = "allowlist"`.
- `isolated learn` using seccomp user notifications and Landlock audit to record
  what an app accesses, then propose a profile.
- Denial event stream in the CLI (`--verbose-denials`).
- **Deliverable:** v0.2.

### M4: Windows backend (4 to 6 weeks)
- AppContainer, Job Objects, restricted tokens, mitigation policies.
- Reversible ACL management; escape tests on Windows CI.
- MSI or winget package.
- **Deliverable:** v0.3 with Windows support.

### M5: macOS backend (3 to 4 weeks)
- Seatbelt profile generation from the policy model.
- Homebrew formula, signed and notarized binary.
- **Deliverable:** v0.4 with macOS support.

### M6: Daemon and desktop GUI (6+ weeks)
- `isolatedd` for tracking sandboxes across sessions and live permission prompts.
- Desktop app: browse profiles, launch apps, see running sandboxes and denials,
  approve or deny access requests.
- Desktop integration: "Open in Isolated" in file managers, sandboxed app
  launchers.
- **Deliverable:** v1.0.

---

## 9. Testing strategy

| Layer | How |
| --- | --- |
| Policy and profile logic | Unit tests and `proptest` in `isolated-core`. |
| Backends | Integration tests that launch real sandboxes and assert on what the child can and cannot do. |
| Escape suite | Hostile test binaries run under strict profiles; any success fails CI. |
| Cross-kernel | Linux CI matrix across kernel versions (5.15 LTS, 6.1 LTS, latest) using VM runners. |
| CLI | `assert_cmd` + `insta` snapshots of output and error messages. |
| Performance | Benchmark launch overhead; regressions over 20% fail CI. |

---

## 10. Open questions

1. **First platform and interface.** This plan assumes Linux and CLI first.
   If Windows or a GUI matters more to users, milestones 1 to 4 reorder.
2. **Licensing.** Apache-2.0 / MIT dual license is the Rust norm; GPL is an
   option if users want to keep forks open.
3. **Network allowlist helper.** Bundle `pasta`/`slirp4netns`, or write a small
   userspace network stack in Rust (for example on `smoltcp`)?
4. **GUI toolkit.** Tauri (web UI, familiar) versus iced (pure Rust, smaller).
5. **Setuid fallback.** Ship an optional setuid helper for systems without
   unprivileged user namespaces, or simply document the limitation?

---

## 11. Prior art to learn from

- **Bubblewrap** and **Flatpak**: Linux namespace sandboxing for desktop apps.
- **Firejail**: profile-driven Linux sandboxing (and lessons from its setuid
  security issues).
- **gVisor** and **Firecracker**: stronger isolation tiers; Firecracker's
  `seccompiler` is reused here.
- **Sandboxie Plus**: Windows app sandboxing UX.
- **Chromium sandbox**: per-platform sandbox design reference.
- **Landlock examples** and the `landlock` crate documentation.

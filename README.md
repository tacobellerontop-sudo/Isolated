<p align="center"><img src="assets/icon256.png" width="96" alt=""></p>

# Isolated

Run any Windows program in a sandbox, straight from the right-click menu.
Isolated starts the program with nothing: no access to your files, no
network, no clipboard. You grant only what it needs.

- **Right-click → Run in Isolated** on any `.exe`, shortcut, `.bat`, `.cmd` or `.ps1`.
- **Small and quiet:** one ~4 MB exe, no installer framework, no background
  service, nothing running when no sandbox is.
- **No admin rights:** uses Windows AppContainer, Job Objects and per-user
  settings.
- **Updates itself** from GitHub Releases, after verifying the download's
  SHA-256.

## Install

1. Download `isolated.exe` from the [latest release](https://github.com/tacobellerontop-sudo/Isolated/releases/latest).
2. Open it, go to **Settings**, and choose **Install for this user**
   (or run `isolated install`).

This copies Isolated to `%LOCALAPPDATA%\Programs\Isolated`, adds a Start menu
entry, the right-click menu, and an entry in **Settings > Apps** for
uninstalling. Requires Windows 10 (1809) or later, 64-bit.

Windows SmartScreen may warn about the download because releases are not
code-signed yet. Choose **More info > Run anyway** if you trust the source;
the release page lists each file's SHA-256.

## Use

**Right-click a program** and choose **Run in Isolated**. On Windows 11 the
entry is under **Show more options**. The submenu has:

| Entry | What it does |
| --- | --- |
| Run in Isolated | Runs with the app's saved profile, or `strict` if it has none |
| Run in Isolated (offline) | Same, but with no network for this run |
| Run in Isolated with options... | Pick permissions in a small dialog first |
| Edit Isolated profile... | Save permissions for this app |

**The Isolated window** (Start menu) lists app profiles, shows running
sandboxes with a Stop button, and holds settings. Drop a program on it to
create a profile.

**From a terminal:**

```powershell
isolated run --no-net -- .\suspicious.exe
isolated run --ro "$HOME\Documents\input" --rw "$HOME\Documents\output" -- converter.exe
isolated run --profile game-mod -- .\launcher.exe
isolated ps
isolated kill <id>
isolated update
```

Run `isolated --help` for everything. Because `isolated.exe` is a windowed
app, `cmd` doesn't wait for it; use `start /wait isolated run ...` in scripts
that need the exit code.

## What a sandbox can and cannot do

By default (the `strict` profile) a sandboxed program:

- **can** read its own folder (or only its own file if it sits in Downloads,
  Desktop or Documents) and Windows system files;
- **gets** its own empty user folders, AppData and temp, kept between runs;
- **cannot** read or change your files, reach the network, use the
  clipboard, the microphone or camera, or change system settings;
- **cannot** escape by starting other programs: everything it starts stays in
  the same sandbox, and stopping the sandbox stops all of it.

Folder grants are temporary. They are recorded in a journal before they are
applied and removed when the program exits, or on the next start of Isolated
after a crash.

Built-in profiles: `strict`, `offline`, `online`, `game-mod`, `dev-build`,
and `compatible` (a weaker tier for programs that break under full isolation:
low integrity and no privileges, but the program can read your files and use
the network). See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for limits.

## Profiles

Profiles are TOML files in `%APPDATA%\Isolated\profiles`. The window edits
them; you can also write them by hand:

```toml
name = "converter"
program = 'C:\Tools\Converter\converter.exe'
extends = "offline"

[filesystem]
read_only  = ['~\Documents\input']
read_write = ['~\Documents\output']

[resources]
memory_max = "2G"
```

Check a file with `isolated profile check converter.toml`.

## Build

```powershell
cargo build --release --target x86_64-pc-windows-msvc
```

Linux can cross-compile with `x86_64-pc-windows-gnu` and MinGW. CI runs unit
tests, a 6 MB size budget, and real sandbox smoke tests
([scripts/smoke-test.ps1](scripts/smoke-test.ps1)) on Windows before every
release. Pushing a `v*` tag publishes a release.

See [docs/PLAN.md](docs/PLAN.md) for the design and roadmap.

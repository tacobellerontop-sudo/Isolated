<p align="center"><img src="assets/icon256.png" width="96" alt=""></p>

# Isolated

Run any Windows program in a sandbox, straight from the right-click menu.
Isolated starts the program with nothing: no access to your files, no
network, no clipboard. You grant only what it needs.

- **Right-click → Run in Isolated** on any `.exe`, shortcut, `.bat`, `.cmd` or `.ps1`.
- **Containers:** separate spaces with their own files and, if you like,
  internet. Install or download apps (AI tools, for example) into one, and
  everything they save stays inside it instead of on your PC. Open its
  files to copy out what you made.
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
| Run in Isolated with folders... | Pick which of your folders the app can see, then run |
| Run in Isolated with options... | Pick permissions in a small dialog first |
| Edit Isolated profile... | Save permissions for this app |
| Install in Isolated... | Install this app into a box (programs and `.msi` files) |

**Right-click a folder** (or the empty space inside one) and choose
**Isolate this folder...** to make it an *isolated folder*: every program
started from it, or from its subfolders, can open, change, add and delete
the files in that folder and nothing else of yours. Good for a portable app
or game that keeps its saves next to it, or a set of tools that work on the
same files. Programs in the folder share one sandbox identity, so they keep
the same settings and can start each other. No internet unless you allow it;
copy and paste work.

Settings and saves that programs write to your user folder (AppData,
LocalLow) go to the sandbox's own copy instead. **Private files** in the
**Folders** tab shows them: drop your existing saves into **App data** (what
the programs see as AppData\Local and AppData\LocalLow) or **Roaming**, and
copy anything out to your PC. For example, a Unity game that saves to
`%USERPROFILE%\AppData\LocalLow\<company>\<game>` reads
`App data\<company>\<game>` in the sandbox. `isolated folder files <folder>`
prints these paths.

Start the programs with **Run in Isolated** (it picks the folder's profile
automatically) or with **Run** in the window's **Folders** tab, which also
has the **Internet** switch and **Stop isolating**. Opening a program by
double-clicking it still runs it normally, outside the sandbox. A whole
drive, your whole user folder, and Windows or Program Files cannot be
isolated, because every program in them would get to change them.

**The Isolated window** (Start menu) lists app profiles, shows running
sandboxes with a Stop button, and holds settings. Drop a program on it to
create a profile.

**Containers.** In the window's **Containers** tab, choose **New
container...**, give it a name (for example `AI apps`) and choose whether
its apps may use the internet. Then:

- **Install an app here...** runs an installer inside it (see below).
- **Run a program...** starts any program or script from your PC inside
  it, such as a portable app you downloaded. It starts in the container's
  own user folder, so what it saves lands there.
- **Command prompt** opens `cmd` inside the container, for tools you set up
  from a terminal. Everything started from it stays in the container.
- **Open files** shows the container's files: its own Documents, Downloads,
  Desktop and Programs. Copy anything to your PC with **Copy to PC...**, add
  files by dropping them on the view, and start programs with **Run here**
  (**Open in Explorer** is there too, but programs opened from Explorer run
  outside the container).
- The **Internet** switch allows or blocks the network for the container's
  apps from their next start.

Apps in a container cannot see your personal files, and Windows keeps
everything they write in the container's folder, so nothing is left on
your PC. Deleting a container removes all of it. A container is the same
thing as a box below; `isolated container ...` and `isolated box ...` are
the same commands.

**Installed apps.** To keep an app instead of running it once, right-click
its installer and choose **Install in Isolated...**, or use **Install an
app...** in the window's **Containers** tab. Pick a box (a new one is
named after the app) and whether the installer may use the internet. The
installer runs inside the box without administrator rights, and when it
finishes, Isolated saves the programs it created. They appear under
the box in **Containers** with a **Run** button, and run with the box's profile,
so they still cannot see your files. Each box keeps its own files and
settings; apps installed into the same box can see each other. Deleting a
box removes everything installed in it.

Installers that can install for one user work this way. Inno Setup
installers are tested on every build; NSIS and Squirrel (Electron)
installers are expected to work. Installers that must change Windows itself,
such as drivers, services and system-wide runtimes, cannot run in a sandbox.

**`.msi` files** are not run at all. Windows Installer is a system service
that works outside any sandbox, so instead Isolated reads the package and
unpacks its files into the box itself, in the folders the package names
(Program Files becomes the box's own Programs folder), and saves the programs
its Start menu shortcuts point to. No code from the package runs, so
anything the installer would set up beyond its files (settings in the
registry, services, file types, files for Windows system folders) is left
out. Most apps that ship as an `.msi` only need their files; the 7-Zip
`.msi` is tested on every build. Packages that keep their files outside the
`.msi` are not supported yet.

**Choosing folders.** **Run in Isolated with folders...** opens a small
window before the app starts: add the folders it may see (or drop them on
the window), and tick **Can change files** for the ones it may save into.
Everything else stays hidden. The folders are offered again next time, and
access ends when the app exits. To always ask for an app, give it the
built-in `folders` profile, or tick **Ask which folders to share each time
the app starts** in its profile. Apps in a box whose profile asks get the
same window.

While an installer runs, Isolated briefly maps a spare drive letter to the
box (some installers check the drive's root, which a sandbox cannot read)
and lets the installer add its entry under the user's list of uninstallable
apps. Both are removed when the installer finishes, so a box's uninstaller
never runs outside the sandbox.

**From a terminal:**

```powershell
isolated run --no-net -- .\suspicious.exe
isolated run --ro "$HOME\Documents\input" --rw "$HOME\Documents\output" -- converter.exe
isolated run --profile game-mod -- .\launcher.exe
isolated run --ask-folders -- .\editor.exe
isolated folder add D:\Games\OldGame
isolated folder list
isolated folder files D:\Games\OldGame
isolated folder remove D:\Games\OldGame
isolated box install --box 7-Zip -- .\7z2408-x64.msi
isolated box install --box Editor -- .\EditorSetup.exe
isolated box list
isolated box run Editor "Editor"
isolated container create "AI apps"
isolated container run "AI apps" .\portable-tool.exe
isolated container shell "AI apps"
isolated container net "AI apps" off
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

Built-in profiles: `strict`, `offline`, `online`, `folders` (asks which
folders to share each time; no network), `game-mod`, `dev-build`,
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

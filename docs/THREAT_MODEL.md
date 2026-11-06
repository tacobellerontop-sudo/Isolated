# Threat model (v0.1)

## What Isolated defends against

A program users run with Isolated is assumed hostile or careless. With the
default `strict` profile, Isolated aims to stop it from:

- reading or changing users' files outside what they granted (documents,
  browser profiles, SSH keys, tokens);
- reaching the network;
- reading or writing the clipboard;
- changing system settings, display settings, or logging users off;
- outliving the sandbox or escaping it through child processes;
- using unlimited memory, CPU, or processes, when limits are set;
- keeping access after the sandbox ends (grants are journaled and revoked).

Mechanisms: AppContainer identity per app and profile, Job Object with
kill-on-close, UI restrictions and limits, temporary ACL grants, a filtered
environment, and process mitigations (heap terminate, bottom-up ASLR).

## What it does not defend against

- **Kernel and driver exploits.** Isolated relies on the Windows kernel.
- **Programs that need administrator rights.** They cannot be sandboxed;
  Isolated refuses installers.
- **The `compatible` tier** is intentionally weaker: the program can read
  users' files and use the network. It only blocks writes outside its private
  folders and the protections of the Job Object.
- **Process names.** A sandboxed program can see which other programs are
  running, but cannot open, read, or control them.
- **Screen reading and keystrokes.** Separate-desktop mode is not available
  yet; a sandboxed program shares the desktop with other windows (UIPI still
  blocks it from driving higher-integrity windows).
- **Data users grant.** A folder granted read-write can be changed or
  encrypted by the program.
- **Network firewall off.** AppContainer network isolation is enforced by
  the Windows Filtering Platform; policies that disable it can weaken it.

## `.msi` packages

Isolated never hands an `.msi` to Windows Installer, whose service runs
outside the sandbox. It parses the package itself, in memory-safe Rust,
writes only into the box's own folders (every name is cleaned and checked
to stay inside the box), caps the unpacked size, and runs none of the
package's custom actions. The parsing happens in Isolated's own process, so
a bug in it could matter; there is no unsafe code in it.

## Updates

The updater only downloads over HTTPS from this repository's GitHub
Releases, and only installs a file whose SHA-256 matches the checksum
published with the release. Releases are not code-signed yet.

## Reporting

See [SECURITY.md](../SECURITY.md).

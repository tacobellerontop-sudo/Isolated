//! The policy model: what a sandboxed program may see and do.
//!
//! A [`Policy`] is plain data. Profiles are TOML files that deserialize into
//! it, the GUI edits it, and each platform backend translates it into native
//! mechanisms. Everything not granted is denied.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A complete sandbox policy. Field defaults are the strict, deny-everything
/// values, so an empty profile is the safest possible sandbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Short identifier, used for file names and the sandbox identity.
    pub name: String,
    /// Optional human description shown in the GUI.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Full path of the program this profile is for. Used to pick the profile
    /// automatically when users right-click a program.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub program: String,
    /// Name of a profile whose values this one starts from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    /// Which isolation tier to use.
    pub tier: Tier,
    pub filesystem: Filesystem,
    pub network: Network,
    pub process: Process,
    pub devices: Devices,
    pub ui: Ui,
    pub resources: Resources,
    pub env: Env,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            name: "unnamed".into(),
            description: String::new(),
            program: String::new(),
            extends: None,
            tier: Tier::default(),
            filesystem: Filesystem::default(),
            network: Network::default(),
            process: Process::default(),
            devices: Devices::default(),
            ui: Ui::default(),
            resources: Resources::default(),
            env: Env::default(),
        }
    }
}

/// Isolation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Full isolation (AppContainer on Windows). The default.
    #[default]
    Isolated,
    /// Weaker isolation for programs that break under full isolation
    /// (restricted token and low integrity on Windows). Cannot block the
    /// network or hide files from reads.
    Compatible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filesystem {
    /// Folders or files the program may read.
    pub read_only: Vec<String>,
    /// Folders or files the program may read and change.
    pub read_write: Vec<String>,
    /// Give the program its own empty profile, AppData and temp folders.
    pub private_home: bool,
    /// Let the program read the folder it is installed in (needed by almost
    /// every program, so on by default).
    pub program_folder: bool,
}

impl Default for Filesystem {
    fn default() -> Self {
        Filesystem {
            read_only: Vec::new(),
            read_write: Vec::new(),
            private_home: true,
            program_folder: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    /// `host:port` entries, used when `mode = "allowlist"`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    None,
    Loopback,
    /// Internet and local network.
    Full,
    Allowlist,
}

impl NetworkMode {
    pub const ALL: [NetworkMode; 4] = [
        NetworkMode::None,
        NetworkMode::Loopback,
        NetworkMode::Full,
        NetworkMode::Allowlist,
    ];

    pub fn label(self) -> &'static str {
        match self {
            NetworkMode::None => "No network",
            NetworkMode::Loopback => "This computer only (loopback)",
            NetworkMode::Full => "Internet and local network",
            NetworkMode::Allowlist => "Only listed hosts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Process {
    pub see_other_processes: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Devices {
    pub clipboard: Clipboard,
    pub microphone: bool,
    pub camera: bool,
    pub printers: bool,
    pub gpu: bool,
}

impl Default for Devices {
    fn default() -> Self {
        Devices {
            clipboard: Clipboard::None,
            microphone: false,
            camera: false,
            printers: false,
            gpu: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Clipboard {
    #[default]
    None,
    Read,
    Write,
    Full,
}

impl Clipboard {
    pub const ALL: [Clipboard; 4] = [Clipboard::None, Clipboard::Read, Clipboard::Write, Clipboard::Full];

    pub fn can_read(self) -> bool {
        matches!(self, Clipboard::Read | Clipboard::Full)
    }

    pub fn can_write(self) -> bool {
        matches!(self, Clipboard::Write | Clipboard::Full)
    }

    pub fn label(self) -> &'static str {
        match self {
            Clipboard::None => "No access",
            Clipboard::Read => "Paste only (read)",
            Clipboard::Write => "Copy only (write)",
            Clipboard::Full => "Copy and paste",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    /// Run on a separate desktop to block screen reading and key logging.
    pub separate_desktop: bool,
    /// Draw a colored border on sandboxed windows (planned; off by default).
    pub mark_windows: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resources {
    /// Memory cap for the whole sandbox, such as "2G" or "512M". Empty means
    /// no cap.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub memory_max: String,
    /// CPU cap as a percentage of all cores, 1 to 100.
    pub cpu_percent: u32,
    /// Maximum number of processes alive at once in the sandbox. 0 means no
    /// limit.
    pub max_processes: u32,
}

impl Default for Resources {
    fn default() -> Self {
        Resources {
            memory_max: String::new(),
            cpu_percent: 100,
            max_processes: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Env {
    /// Variables passed through from the caller's environment, in addition to
    /// the basic ones every program needs (PATH, SystemRoot, ...).
    pub pass: Vec<String>,
    /// Variables set to fixed values.
    pub set: BTreeMap<String, String>,
}

/// Parses a size such as `512M`, `2G`, `1.5G` or a plain byte count.
pub fn parse_size(text: &str) -> Result<u64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("empty size".into());
    }
    let (num, mult) = match t.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&t[..t.len() - 1], 1u64 << 10),
        Some('M') => (&t[..t.len() - 1], 1u64 << 20),
        Some('G') => (&t[..t.len() - 1], 1u64 << 30),
        Some('T') => (&t[..t.len() - 1], 1u64 << 40),
        _ => (t, 1),
    };
    let value: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("'{text}' is not a size like 512M or 2G"))?;
    if !(value.is_finite() && value > 0.0) {
        return Err(format!("'{text}' must be greater than zero"));
    }
    Ok((value * mult as f64) as u64)
}

impl Policy {
    /// Checks the policy for values that are invalid on every platform.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.name.trim().is_empty() {
            errors.push("name must not be empty".to_string());
        }
        if !self.resources.memory_max.is_empty() {
            match parse_size(&self.resources.memory_max) {
                Ok(n) if n < (16 << 20) => errors.push("resources.memory_max must be at least 16M".into()),
                Ok(_) => {}
                Err(e) => errors.push(format!("resources.memory_max: {e}")),
            }
        }
        if !(1..=100).contains(&self.resources.cpu_percent) {
            errors.push("resources.cpu_percent must be between 1 and 100".into());
        }
        if self.network.mode == NetworkMode::Allowlist && self.network.allow.is_empty() {
            errors.push("network.allow must list at least one host:port for allowlist mode".into());
        }
        for entry in &self.network.allow {
            match entry.rsplit_once(':') {
                Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
                _ => errors.push(format!("network.allow entry '{entry}' must be host:port")),
            }
        }
        for p in self.filesystem.read_only.iter().chain(&self.filesystem.read_write) {
            if p.trim().is_empty() {
                errors.push("filesystem paths must not be empty".into());
            }
        }
        for key in self.env.set.keys().chain(&self.env.pass) {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                errors.push(format!("env variable name '{key}' is not valid"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// The memory cap in bytes, if any.
    pub fn memory_max_bytes(&self) -> Option<u64> {
        if self.resources.memory_max.is_empty() {
            None
        } else {
            parse_size(&self.resources.memory_max).ok()
        }
    }

    /// Serializes to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    /// Parses TOML. Does not resolve `extends`; see
    /// [`crate::profile::ProfileStore::resolve`].
    pub fn from_toml(text: &str) -> Result<Policy, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }
}

/// One-off changes applied on top of a profile for a single run, from CLI
/// flags or the "with options" dialog.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub network: Option<NetworkMode>,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub private_home: Option<bool>,
    pub clipboard: Option<Clipboard>,
    pub tier: Option<Tier>,
}

impl Overrides {
    pub fn apply(&self, policy: &mut Policy) {
        if let Some(n) = self.network {
            policy.network.mode = n;
        }
        policy.filesystem.read_only.extend(self.read_only.iter().cloned());
        policy.filesystem.read_write.extend(self.read_write.iter().cloned());
        if let Some(p) = self.private_home {
            policy.filesystem.private_home = p;
        }
        if let Some(c) = self.clipboard {
            policy.devices.clipboard = c;
        }
        if let Some(t) = self.tier {
            policy.tier = t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_is_strict() {
        let p = Policy::from_toml("name = 'x'").unwrap();
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.devices.clipboard, Clipboard::None);
        assert!(p.filesystem.private_home);
        assert!(p.filesystem.read_write.is_empty());
        assert!(!p.devices.microphone);
    }

    #[test]
    fn plan_example_parses() {
        let text = r#"
name = "converter"
description = "Image converter"
program = 'C:\Tools\Converter\converter.exe'

[filesystem]
read_only    = ['~\Documents\input']
read_write   = ['~\Documents\output']
private_home = true

[network]
mode = "none"

[process]
see_other_processes = false

[devices]
clipboard  = "none"
microphone = false
camera     = false
printers   = false
gpu        = true

[ui]
separate_desktop = false
mark_windows     = true

[resources]
memory_max    = "2G"
cpu_percent   = 100
max_processes = 64

[env]
pass = ["LANG"]
set  = { NO_UPDATE_CHECK = "1" }
"#;
        let p = Policy::from_toml(text).unwrap();
        p.validate().unwrap();
        assert_eq!(p.memory_max_bytes(), Some(2 << 30));
        assert_eq!(p.env.set["NO_UPDATE_CHECK"], "1");
        let round = Policy::from_toml(&p.to_toml()).unwrap();
        assert_eq!(round, p);
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(Policy::from_toml("name='x'\n[network]\nmodee='full'").is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_size("1.5g").unwrap(), 3 << 29);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("lots").is_err());
        assert!(parse_size("-1G").is_err());
    }

    #[test]
    fn validation_catches_bad_values() {
        let mut p = Policy::default();
        p.resources.cpu_percent = 0;
        p.network.mode = NetworkMode::Allowlist;
        p.resources.memory_max = "1M".into();
        let errs = p.validate().unwrap_err();
        assert_eq!(errs.len(), 3, "{errs:?}");
    }

    #[test]
    fn overrides_apply() {
        let mut p = Policy::default();
        p.network.mode = NetworkMode::Full;
        Overrides {
            network: Some(NetworkMode::None),
            read_write: vec!["C:\\out".into()],
            ..Default::default()
        }
        .apply(&mut p);
        assert_eq!(p.network.mode, NetworkMode::None);
        assert_eq!(p.filesystem.read_write, vec!["C:\\out".to_string()]);
    }
}

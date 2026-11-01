//! Platform-independent core of Isolated: the policy model, profiles, and
//! the small amount of shared state (settings, running sandboxes, cleanup
//! journal). Platform backends turn a [`Policy`] into native isolation.

#![forbid(unsafe_code)]

pub mod cmdline;
pub mod policy;
pub mod profile;
pub mod sha256;
pub mod state;
pub mod version;

pub use policy::{Clipboard, NetworkMode, Overrides, Policy, Tier};
pub use profile::{ProfileStore, Source};
pub use state::{Dirs, Settings};

/// How strongly the current platform can enforce one part of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The sandbox would be weaker than requested. Launch is refused unless
    /// the user accepts a weaker sandbox.
    Weaker,
    /// Cosmetic or convenience feature not available; launch continues.
    Notice,
}

/// One part of a policy the backend cannot enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    pub severity: Severity,
    pub message: String,
}

impl Gap {
    pub fn weaker(m: impl Into<String>) -> Gap {
        Gap {
            severity: Severity::Weaker,
            message: m.into(),
        }
    }
    pub fn notice(m: impl Into<String>) -> Gap {
        Gap {
            severity: Severity::Notice,
            message: m.into(),
        }
    }
}

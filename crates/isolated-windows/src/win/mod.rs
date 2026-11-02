//! Win32 implementation. All `unsafe` code in Isolated lives under here,
//! behind small safe wrappers.

pub mod acl;
pub mod appcontainer;
pub mod drive;
pub mod http;
pub mod install;
pub mod job;
pub mod launch;
pub mod menu;
pub mod reg;
pub mod shell;
pub mod util;

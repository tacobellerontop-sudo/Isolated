//! Win32 implementation. All `unsafe` code in Isolated lives under here,
//! behind small safe wrappers.

pub mod acl;
pub mod appcontainer;
pub mod drive;
pub mod escape;
pub mod http;
pub mod install;
pub mod job;
pub mod junction;
pub mod launch;
pub mod marker;
pub mod menu;
pub mod reg;
pub mod sandbox_user;
pub mod shell;
pub mod util;

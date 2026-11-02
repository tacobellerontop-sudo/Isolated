//! A temporary drive letter for a box's folder while an installer runs.
//!
//! Sandboxed programs cannot read the root of the system drive, and some
//! installers (Inno Setup) refuse an install folder whose drive root they
//! cannot see. Mapping a free letter to the box folder gives them a drive
//! whose root is the box itself. The mapping is removed when the install
//! ends (and in any case at sign-out).

use super::util::{err, Wide};
use std::path::{Path, PathBuf};
use windows::Win32::Storage::FileSystem::{
    DefineDosDeviceW, GetLogicalDrives, DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM, DDD_REMOVE_DEFINITION,
};

pub struct DriveAlias {
    letter: char,
    target: PathBuf,
}

impl DriveAlias {
    /// Maps the last free letter from Z: down to M: to `target`.
    pub fn map(target: &Path) -> Result<DriveAlias, String> {
        let used = unsafe { GetLogicalDrives() };
        let letter = ('M'..='Z')
            .rev()
            .find(|c| used & (1 << (*c as u32 - 'A' as u32)) == 0)
            .ok_or("no free drive letter for the installer")?;
        let dev = Wide::new(format!("{letter}:"));
        let t = Wide::new(target.as_os_str());
        unsafe {
            DefineDosDeviceW(DDD_NO_BROADCAST_SYSTEM, dev.pcwstr(), t.pcwstr())
                .map_err(|e| err("could not map a drive letter for the installer", e))?;
        }
        Ok(DriveAlias {
            letter,
            target: target.to_path_buf(),
        })
    }

    /// The drive root, such as `Y:\`.
    pub fn root(&self) -> PathBuf {
        PathBuf::from(format!("{}:\\", self.letter))
    }

    /// Turns a path on the mapped drive back into the real folder path.
    pub fn to_real(&self, p: &Path) -> PathBuf {
        let s = p.to_string_lossy();
        let prefix = format!("{}:\\", self.letter);
        match s.get(..3) {
            Some(head) if head.eq_ignore_ascii_case(&prefix) => self.target.join(&s[3..]),
            _ => p.to_path_buf(),
        }
    }
}

impl Drop for DriveAlias {
    fn drop(&mut self) {
        let dev = Wide::new(format!("{}:", self.letter));
        let t = Wide::new(self.target.as_os_str());
        unsafe {
            let _ = DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE | DDD_NO_BROADCAST_SYSTEM,
                dev.pcwstr(),
                t.pcwstr(),
            );
        }
    }
}

//! Directory junctions, used to keep a folder an app insists on (such as
//! `C:\Users\<name>\Kryoto Games`) inside its container: the real path
//! becomes a junction into the container's own copy, so what the app writes
//! there lands in the container. Only the empty junction is left on the PC.

use super::util::{err, OwnedHandle, Wide};
use std::path::Path;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;

/// Makes `link` (an empty or missing folder) a junction to `target`.
pub fn create(link: &Path, target: &Path) -> Result<(), String> {
    if !link.exists() {
        std::fs::create_dir(link).map_err(|e| format!("could not create {}: {e}", link.display()))?;
    }
    let t = target.to_string_lossy();
    let t = t.strip_prefix(r"\\?\").unwrap_or(&t);
    let substitute: Vec<u16> = format!(r"\??\{t}").encode_utf16().collect();
    let print: Vec<u16> = t.encode_utf16().collect();
    let sub_bytes = (substitute.len() * 2) as u16;
    let print_bytes = (print.len() * 2) as u16;
    // Mount point data: offsets and lengths, then both names, each followed by a NUL.
    let mut path_buffer: Vec<u16> = Vec::new();
    path_buffer.extend(&substitute);
    path_buffer.push(0);
    path_buffer.extend(&print);
    path_buffer.push(0);
    let data_len = (8 + path_buffer.len() * 2) as u16;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buf.extend(data_len.to_le_bytes());
    buf.extend(0u16.to_le_bytes());
    buf.extend(0u16.to_le_bytes()); // substitute name offset
    buf.extend(sub_bytes.to_le_bytes());
    buf.extend((sub_bytes + 2).to_le_bytes()); // print name offset
    buf.extend(print_bytes.to_le_bytes());
    for c in path_buffer {
        buf.extend(c.to_le_bytes());
    }
    let w = Wide::new(link.as_os_str());
    unsafe {
        let h = CreateFileW(
            w.pcwstr(),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        .map_err(|e| err(&format!("could not open {}", link.display()), e))?;
        let h = OwnedHandle(h);
        let mut returned = 0u32;
        DeviceIoControl(
            h.raw(),
            FSCTL_SET_REPARSE_POINT,
            Some(buf.as_ptr() as *const _),
            buf.len() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
        .map_err(|e| {
            let _ = std::fs::remove_dir(link);
            err(&format!("could not link {}", link.display()), e)
        })?;
    }
    Ok(())
}

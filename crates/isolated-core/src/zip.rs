//! Unpacking `.zip` files, for apps shipped as a portable folder instead of
//! an installer. Supports stored and deflated entries and ZIP64; encrypted
//! entries are refused.
//!
//! The archive is untrusted input: every name is split into parts and each
//! part cleaned to a single file name, so nothing lands outside the target
//! folder, and the total size is capped.

use std::fs;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_FILES: usize = 200_000;

struct Entry {
    parts: Vec<String>,
    dir: bool,
    method: u16,
    packed: u64,
    size: u64,
    local: u64,
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn bad() -> String {
    "This .zip file is damaged or not a .zip file.".into()
}

fn read_at(f: &mut fs::File, at: u64, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    f.seek(SeekFrom::Start(at)).map_err(|e| e.to_string())?;
    f.read_exact(&mut buf).map_err(|_| bad())?;
    Ok(buf)
}

fn entries(f: &mut fs::File) -> Result<Vec<Entry>, String> {
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    let tail_len = len.min(65_557) as usize;
    let tail = read_at(f, len - tail_len as u64, tail_len)?;
    let eocd = (0..tail_len.saturating_sub(21))
        .rev()
        .find(|i| u32_at(&tail, *i) == Some(0x0605_4b50))
        .ok_or_else(bad)?;
    let mut count = u16_at(&tail, eocd + 10).ok_or_else(bad)? as u64;
    let mut cd_size = u32_at(&tail, eocd + 12).ok_or_else(bad)? as u64;
    let mut cd_at = u32_at(&tail, eocd + 16).ok_or_else(bad)? as u64;
    // ZIP64: a locator just before the end record points at the real one.
    if eocd >= 20 && u32_at(&tail, eocd - 20) == Some(0x0706_4b50) {
        let at = u64_at(&tail, eocd - 12).ok_or_else(bad)?;
        let rec = read_at(f, at, 56)?;
        if u32_at(&rec, 0) != Some(0x0606_4b50) {
            return Err(bad());
        }
        count = u64_at(&rec, 32).ok_or_else(bad)?;
        cd_size = u64_at(&rec, 40).ok_or_else(bad)?;
        cd_at = u64_at(&rec, 48).ok_or_else(bad)?;
    }
    if count as usize > MAX_FILES || cd_size > 512 << 20 || cd_at.checked_add(cd_size).is_none_or(|e| e > len) {
        return Err(bad());
    }
    let cd = read_at(f, cd_at, cd_size as usize)?;
    let mut out = Vec::new();
    let mut p = 0usize;
    for _ in 0..count {
        if u32_at(&cd, p) != Some(0x0201_4b50) {
            return Err(bad());
        }
        let flags = u16_at(&cd, p + 8).ok_or_else(bad)?;
        let method = u16_at(&cd, p + 10).ok_or_else(bad)?;
        let mut packed = u32_at(&cd, p + 20).ok_or_else(bad)? as u64;
        let mut size = u32_at(&cd, p + 24).ok_or_else(bad)? as u64;
        let name_len = u16_at(&cd, p + 28).ok_or_else(bad)? as usize;
        let extra_len = u16_at(&cd, p + 30).ok_or_else(bad)? as usize;
        let comment_len = u16_at(&cd, p + 32).ok_or_else(bad)? as usize;
        let mut local = u32_at(&cd, p + 42).ok_or_else(bad)? as u64;
        let name_raw = cd.get(p + 46..p + 46 + name_len).ok_or_else(bad)?;
        let extra = cd
            .get(p + 46 + name_len..p + 46 + name_len + extra_len)
            .ok_or_else(bad)?;
        // ZIP64 extra field: the 64-bit values, in order, for those that
        // overflowed.
        let mut e = 0;
        while e + 4 <= extra.len() {
            let id = u16_at(extra, e).unwrap_or(0);
            let n = u16_at(extra, e + 2).unwrap_or(0) as usize;
            if id == 1 {
                let mut q = e + 4;
                for v in [&mut size, &mut packed, &mut local] {
                    if *v == 0xFFFF_FFFF {
                        *v = u64_at(extra, q).ok_or_else(bad)?;
                        q += 8;
                    }
                }
            }
            e += 4 + n;
        }
        if flags & 1 != 0 {
            return Err("This .zip file is password-protected, which Isolated cannot open.".into());
        }
        let name = if flags & 0x800 != 0 {
            String::from_utf8_lossy(name_raw).into_owned()
        } else {
            name_raw.iter().map(|b| *b as char).collect()
        };
        let dir = name.ends_with('/') || name.ends_with('\\');
        let parts: Option<Vec<String>> = name
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
            .map(crate::msi::clean_name)
            .collect();
        if let Some(parts) = parts.filter(|v| !v.is_empty() && v.len() <= 64) {
            out.push(Entry {
                parts,
                dir,
                method,
                packed,
                size,
                local,
            });
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    Ok(out)
}

/// What unpacking produced.
#[derive(Debug, Default)]
pub struct Unzipped {
    pub files: usize,
    pub bytes: u64,
}

/// Unpacks `zip` into `dest`. When everything in the archive sits in one
/// top folder, that folder's contents go straight into `dest`.
pub fn unpack(zip: &Path, dest: &Path) -> Result<Unzipped, String> {
    let mut f = fs::File::open(zip).map_err(|e| format!("{}: {e}", zip.display()))?;
    let list = entries(&mut f)?;
    let strip = {
        let first = list.iter().find(|e| !e.parts.is_empty()).map(|e| e.parts[0].clone());
        match first {
            Some(top)
                if list
                    .iter()
                    .all(|e| e.parts[0].eq_ignore_ascii_case(&top) && (e.parts.len() > 1 || e.dir)) =>
            {
                1
            }
            _ => 0,
        }
    };
    let mut out = Unzipped::default();
    let mut budget = crate::msi::MAX_TOTAL_BYTES;
    for e in &list {
        let rel: PathBuf = e.parts.iter().skip(strip).collect();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let path = dest.join(rel);
        if e.dir {
            fs::create_dir_all(&path).map_err(|err| format!("could not create {}: {err}", path.display()))?;
            continue;
        }
        if e.size > budget {
            return Err("This .zip file unpacks to more data than Isolated allows.".into());
        }
        let head = read_at(&mut f, e.local, 30)?;
        if u32_at(&head, 0) != Some(0x0403_4b50) {
            return Err(bad());
        }
        let skip = 30 + u16_at(&head, 26).unwrap_or(0) as u64 + u16_at(&head, 28).unwrap_or(0) as u64;
        f.seek(SeekFrom::Start(e.local + skip)).map_err(|err| err.to_string())?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("could not create {}: {err}", parent.display()))?;
        }
        let mut w = BufWriter::new(
            fs::File::create(&path).map_err(|err| format!("could not write {}: {err}", path.display()))?,
        );
        let raw = (&mut f).take(e.packed);
        // Read at most the declared size plus one byte, to notice lies.
        let copied = match e.method {
            0 => std::io::copy(&mut raw.take(e.size + 1), &mut w),
            8 => std::io::copy(&mut flate2::read::DeflateDecoder::new(raw).take(e.size + 1), &mut w),
            _ => {
                return Err(format!(
                    "This .zip file uses a compression method Isolated cannot open ({}).",
                    e.method
                ))
            }
        }
        .map_err(|err| format!("could not unpack {}: {err}", path.display()))?;
        if copied != e.size {
            return Err(bad());
        }
        budget -= copied;
        out.files += 1;
        out.bytes += copied;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny zip made by hand: `App/` and `App/app.exe` (stored), plus
    /// `App/sub/../../evil.txt` which must stay inside.
    fn sample() -> Vec<u8> {
        let files: &[(&str, &[u8])] = &[("App/", b""), ("App/app.exe", b"MZhello"), ("App/../../evil.txt", b"x")];
        let mut data = Vec::new();
        let mut cd = Vec::new();
        for (name, body) in files {
            let off = data.len() as u32;
            let crc = 0u32;
            data.extend(0x0403_4b50u32.to_le_bytes());
            data.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            data.extend(crc.to_le_bytes());
            data.extend((body.len() as u32).to_le_bytes());
            data.extend((body.len() as u32).to_le_bytes());
            data.extend((name.len() as u16).to_le_bytes());
            data.extend(0u16.to_le_bytes());
            data.extend(name.as_bytes());
            data.extend(*body);
            cd.extend(0x0201_4b50u32.to_le_bytes());
            cd.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            cd.extend(crc.to_le_bytes());
            cd.extend((body.len() as u32).to_le_bytes());
            cd.extend((body.len() as u32).to_le_bytes());
            cd.extend((name.len() as u16).to_le_bytes());
            cd.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            cd.extend(off.to_le_bytes());
            cd.extend(name.as_bytes());
        }
        let cd_at = data.len() as u32;
        data.extend(&cd);
        data.extend(0x0605_4b50u32.to_le_bytes());
        data.extend([0, 0, 0, 0]);
        data.extend((files.len() as u16).to_le_bytes());
        data.extend((files.len() as u16).to_le_bytes());
        data.extend((cd.len() as u32).to_le_bytes());
        data.extend(cd_at.to_le_bytes());
        data.extend([0, 0]);
        data
    }

    #[test]
    fn unpacks_and_stays_inside() {
        let root = std::env::temp_dir().join(format!("isolated-zip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let z = root.join("a.zip");
        fs::write(&z, sample()).unwrap();
        let dest = root.join("out");
        let u = unpack(&z, &dest).unwrap();
        assert_eq!(u.files, 1);
        assert_eq!(fs::read(dest.join("app.exe")).unwrap(), b"MZhello");
        // `..` parts are refused, so the evil entry is dropped entirely.
        assert!(!root.join("evil.txt").exists());
        assert!(!dest.join("evil.txt").exists());
        fs::write(&z, b"not a zip at all").unwrap();
        assert!(unpack(&z, &dest).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    /// Unpacks a real archive named by `ISOLATED_TEST_ZIP`, if set.
    #[test]
    fn real_zip() {
        let Some(z) = std::env::var_os("ISOLATED_TEST_ZIP") else {
            return;
        };
        let dest = std::env::temp_dir().join(format!("isolated-zip-real-{}", std::process::id()));
        let u = unpack(Path::new(&z), &dest).unwrap();
        eprintln!("{u:?}");
        for e in fs::read_dir(&dest).unwrap() {
            eprintln!("{}", e.unwrap().path().display());
        }
        let _ = fs::remove_dir_all(&dest);
    }
}

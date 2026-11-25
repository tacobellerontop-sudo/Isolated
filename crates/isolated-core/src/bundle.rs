//! Installers that are an `.exe` wrapped around `.msi` packages.
//!
//! Many apps ship a setup program that only unpacks and starts one or more
//! `.msi` packages (WiX "Burn" bundles, which Visual Studio redistributables,
//! many developer tools and most WiX-built apps use). Inside a sandbox the
//! setup program cannot reach Windows Installer, so it fails. Capture tools
//! such as Cameyo and Turbo solve this by taking the packages out and laying
//! their files down themselves; Isolated does the same: it reads the bundle's
//! attached containers (plain cabinets), takes out the `.msi` packages and
//! their `.cab` files, and unpacks them with [`crate::msi`].
//!
//! The file is untrusted input. Nothing in it runs, sizes are checked against
//! the file, and every written name is cleaned to a single file name.

use crate::cabinet::Cabinet;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const BURN_MAGIC: u32 = 0x00f1_4300;
/// Largest bundle read into memory.
const MAX_BUNDLE: u64 = 4 << 30;

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The raw `.wixburn` section of a PE file, if it has one.
fn burn_section(d: &[u8]) -> Option<&[u8]> {
    if d.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(d, 0x3c)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = u16_at(d, pe + 6)? as usize;
    let opt = u16_at(d, pe + 20)? as usize;
    let mut s = pe + 24 + opt;
    for _ in 0..sections.min(96) {
        let name = d.get(s..s + 8)?;
        if name.starts_with(b".wixburn") {
            let size = u32_at(d, s + 16)? as usize;
            let at = u32_at(d, s + 20)? as usize;
            return d.get(at..at.checked_add(size)?);
        }
        s += 40;
    }
    None
}

/// True if the bytes are a WiX Burn bundle.
pub fn is_burn(head: &[u8]) -> bool {
    burn_section(head).is_some_and(|s| u32_at(s, 0) == Some(BURN_MAGIC))
}

/// The bundle's containers in order: the first holds the setup program's
/// own files and its manifest, the rest hold the packages.
fn containers(d: &[u8]) -> Result<Vec<&[u8]>, String> {
    let s = burn_section(d).ok_or("not a bundle")?;
    if u32_at(s, 0) != Some(BURN_MAGIC) {
        return Err("not a bundle".into());
    }
    let stub = u32_at(s, 24).ok_or("damaged bundle")? as usize;
    let format = u32_at(s, 40).ok_or("damaged bundle")?;
    let count = u32_at(s, 44).ok_or("damaged bundle")? as usize;
    if format != 1 || count == 0 || count > 64 {
        return Err("this bundle stores its packages in a way Isolated does not know".into());
    }
    let mut out = Vec::new();
    let mut pos = stub;
    for i in 0..count {
        let size = u32_at(s, 48 + 4 * i).ok_or("damaged bundle")? as usize;
        // A signature may sit between containers; find the next cabinet of
        // exactly the recorded size.
        let mut found = None;
        let mut at = pos;
        let limit = pos.saturating_add(1 << 20).min(d.len());
        while at + 12 <= limit {
            if &d[at..at + 4] == b"MSCF" && u32_at(d, at + 8) == Some(size as u32) {
                found = Some(at);
                break;
            }
            at += 1;
        }
        let at = found.ok_or("damaged bundle: a container is missing")?;
        let end = at.checked_add(size).filter(|e| *e <= d.len()).ok_or("damaged bundle")?;
        out.push(&d[at..end]);
        pos = end;
    }
    Ok(out)
}

/// Value of `name="..."` in one XML start tag, with entities decoded.
fn attr(tag: &str, name: &str) -> Option<String> {
    let mut rest = tag;
    loop {
        let i = rest.find(name)?;
        let before_ok = i == 0 || rest.as_bytes()[i - 1].is_ascii_whitespace();
        let after = rest[i + name.len()..].trim_start();
        if before_ok {
            if let Some(v) = after.strip_prefix('=') {
                let v = v.trim_start();
                let q = v.chars().next()?;
                if q == '"' || q == '\'' {
                    let end = v[1..].find(q)?;
                    return Some(decode(&v[1..1 + end]));
                }
            }
        }
        rest = &rest[i + name.len()..];
    }
}

fn decode(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Every start tag named `name` (`<Payload .../>`) in the manifest.
fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        if after.starts_with(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>') {
            let end = after.find('>').unwrap_or(after.len());
            out.push(&after[..end]);
            rest = &after[end..];
        } else {
            rest = after;
        }
    }
    out
}

/// A package file taken out of a bundle.
#[derive(Debug, Clone)]
pub struct Extracted {
    /// `.msi` packages, in the bundle's order.
    pub packages: Vec<PathBuf>,
    /// Programs the bundle would run (prerequisites such as runtimes, or
    /// `.exe` packages), which are left out.
    pub skipped_programs: usize,
    /// Packages the bundle downloads while it runs, which are not inside it.
    pub not_included: usize,
}

/// Takes the `.msi` packages (and the `.cab` files next to them) out of a
/// Burn bundle into `out`. Errors if the file is not a bundle or is damaged.
pub fn extract_burn(exe: &Path, out: &Path) -> Result<Extracted, String> {
    let len = fs::metadata(exe).map_err(|e| format!("{}: {e}", exe.display()))?.len();
    if len > MAX_BUNDLE {
        return Err("This installer is too large to unpack.".into());
    }
    let data = fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
    let cs = containers(&data)?;
    let ux = Cabinet::parse(cs[0])?;
    // The manifest is the file named "0" in the first container.
    if !ux.files().iter().any(|f| f.name == "0") {
        return Err("damaged bundle: no manifest".into());
    }
    let manifest = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    {
        struct Sink(std::rc::Rc<std::cell::RefCell<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        ux.extract(64 << 20, |e| {
            Ok((e.name == "0").then(|| Box::new(Sink(manifest.clone())) as Box<dyn Write>))
        })?;
    }
    let xml = String::from_utf8_lossy(&manifest.borrow()).into_owned();

    // Packaging and container of each payload, by its name in the container.
    let mut wanted: HashMap<String, String> = HashMap::new();
    let mut not_included = 0;
    let mut skipped_programs = 0;
    let mut order: Vec<String> = Vec::new();
    for t in tags(&xml, "Payload") {
        let (Some(file_path), Some(source)) = (attr(t, "FilePath"), attr(t, "SourcePath")) else {
            continue;
        };
        let lower = file_path.to_ascii_lowercase();
        let packaging = attr(t, "Packaging").unwrap_or_default();
        let is_package = lower.ends_with(".msi") || lower.ends_with(".cab");
        if !is_package {
            if lower.ends_with(".exe") && attr(t, "Container").is_some() {
                skipped_programs += 1;
            }
            continue;
        }
        if packaging.eq_ignore_ascii_case("external") || packaging.eq_ignore_ascii_case("download") {
            if lower.ends_with(".msi") {
                not_included += 1;
            }
            continue;
        }
        // Keep only the file name: the package and its cabinets sit
        // together, which is how the package finds them.
        let name = file_path.rsplit(['\\', '/']).next().unwrap_or("");
        let Some(name) = crate::msi::clean_name(name) else {
            continue;
        };
        if lower.ends_with(".msi") {
            order.push(name.clone());
        }
        wanted.insert(source, name);
    }

    fs::create_dir_all(out).map_err(|e| format!("could not create {}: {e}", out.display()))?;
    let mut budget = crate::msi::MAX_TOTAL_BYTES;
    for c in &cs[1..] {
        let cab = Cabinet::parse(c)?;
        let used = cab.extract(budget, |e| {
            let Some(name) = wanted.get(&e.name) else {
                return Ok(None);
            };
            let p = out.join(name);
            let f = fs::File::create(&p).map_err(|err| format!("could not write {}: {err}", p.display()))?;
            Ok(Some(Box::new(std::io::BufWriter::new(f)) as Box<dyn Write>))
        })?;
        budget = budget.saturating_sub(used);
    }
    let packages = order.into_iter().map(|n| out.join(n)).filter(|p| p.is_file()).collect();
    Ok(Extracted {
        packages,
        skipped_programs,
        not_included,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_attributes() {
        let xml = r#"<?xml?><BurnManifest><UX><Payload Id="ux" FilePath="BA.dll" SourcePath="u0"/></UX>
            <Payload Id="p1" FilePath="redist\app &amp; co.msi" Packaging='embedded' SourcePath="a0" Container="WixAttachedContainer" />
            <PayloadGroup/><Payloads/></BurnManifest>"#;
        let t = tags(xml, "Payload");
        assert_eq!(t.len(), 2);
        assert_eq!(attr(t[1], "FilePath").as_deref(), Some(r"redist\app & co.msi"));
        assert_eq!(attr(t[1], "Packaging").as_deref(), Some("embedded"));
        assert_eq!(attr(t[1], "Id").as_deref(), Some("p1"));
        assert_eq!(attr(t[0], "Container"), None);
    }

    #[test]
    fn not_a_bundle() {
        assert!(!is_burn(b"MZ\0\0"));
        assert!(!is_burn(b""));
        let dir = std::env::temp_dir().join(format!("isolated-burn-{}", std::process::id()));
        let f = dir.with_extension("exe");
        fs::write(&f, b"MZ not really").unwrap();
        assert!(extract_burn(&f, &dir).is_err());
        let _ = fs::remove_file(&f);
    }

    /// Extracts a real bundle named by `ISOLATED_TEST_BURN`, if set.
    #[test]
    fn real_bundle() {
        let Some(exe) = std::env::var_os("ISOLATED_TEST_BURN") else {
            return;
        };
        let head = fs::read(&exe).unwrap();
        assert!(is_burn(&head));
        let out = std::env::temp_dir().join(format!("isolated-burn-real-{}", std::process::id()));
        let x = extract_burn(Path::new(&exe), &out).unwrap();
        eprintln!("{x:#?}");
        assert!(!x.packages.is_empty());
        let with_arch: Vec<_> = x.packages.iter().map(|p| (p.clone(), crate::msi::arch(p))).collect();
        eprintln!("{with_arch:?}");
        let root = out.join("box");
        let f = crate::msi::BoxFolders {
            programs: root.join("Programs"),
            local_app_data: root.clone(),
            home: root.join("Home"),
        };
        for p in crate::msi::pick_for_pc(&with_arch) {
            let u = crate::msi::unpack(&p, &root, &f).unwrap();
            eprintln!("{}: {} files, {} shortcuts", p.display(), u.files, u.shortcuts.len());
        }
        let _ = fs::remove_dir_all(&out);
    }
}

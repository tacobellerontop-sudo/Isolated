//! A small reader for Microsoft cabinet (`.cab`) files, the archives inside
//! `.msi` packages. It streams each folder once from start to end, so a
//! cabinet with thousands of files is decompressed exactly one time.
//!
//! Supports stored, MSZIP and LZX data (Quantum is not used by modern
//! installers). Cabinets split across several files are not supported.

use std::io::Write;

/// One file listed in a cabinet.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub size: u32,
    folder: u16,
    offset: u32,
}

/// A parsed cabinet held in memory.
pub struct Cabinet<'a> {
    data: &'a [u8],
    folders: Vec<Folder>,
    files: Vec<Entry>,
    data_reserve: usize,
}

#[derive(Debug, Clone, Copy)]
struct Folder {
    first_block: u32,
    blocks: u16,
    compression: u16,
}

fn bad(msg: impl Into<String>) -> String {
    format!("damaged cabinet: {}", msg.into())
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn at(data: &'a [u8], pos: usize) -> Cursor<'a> {
        Cursor { data, pos }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len());
        match end {
            Some(end) => {
                let s = &self.data[self.pos..end];
                self.pos = end;
                Ok(s)
            }
            None => Err(bad("unexpected end of data")),
        }
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn cstr(&mut self) -> Result<&'a [u8], String> {
        let rest = &self.data[self.pos.min(self.data.len())..];
        let n = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| bad("unterminated name"))?;
        let s = &rest[..n];
        self.pos += n + 1;
        Ok(s)
    }
}

const FLAG_PREV: u16 = 0x1;
const FLAG_NEXT: u16 = 0x2;
const FLAG_RESERVE: u16 = 0x4;
const ATTR_UTF8: u16 = 0x80;

impl<'a> Cabinet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Cabinet<'a>, String> {
        let mut c = Cursor::at(data, 0);
        if c.bytes(4)? != b"MSCF" {
            return Err(bad("not a cabinet"));
        }
        c.bytes(12)?; // reserved1, cbCabinet, reserved2
        let files_at = c.u32()? as usize;
        c.bytes(6)?; // reserved3, version
        let n_folders = c.u16()?;
        let n_files = c.u16()?;
        let flags = c.u16()?;
        c.bytes(4)?; // setID, iCabinet
        let (mut header_reserve, mut folder_reserve, mut data_reserve) = (0usize, 0usize, 0usize);
        if flags & FLAG_RESERVE != 0 {
            header_reserve = c.u16()? as usize;
            folder_reserve = c.u8()? as usize;
            data_reserve = c.u8()? as usize;
        }
        c.bytes(header_reserve)?;
        if flags & FLAG_PREV != 0 || flags & FLAG_NEXT != 0 {
            return Err(
                "This installer's files are split across several cabinets, which Isolated cannot unpack yet.".into(),
            );
        }
        let mut folders = Vec::with_capacity(n_folders as usize);
        for _ in 0..n_folders {
            folders.push(Folder {
                first_block: c.u32()?,
                blocks: c.u16()?,
                compression: c.u16()?,
            });
            c.bytes(folder_reserve)?;
        }
        let mut c = Cursor::at(data, files_at);
        let mut files = Vec::with_capacity(n_files as usize);
        for _ in 0..n_files {
            let size = c.u32()?;
            let offset = c.u32()?;
            let folder = c.u16()?;
            c.bytes(4)?; // date, time
            let attribs = c.u16()?;
            let raw = c.cstr()?;
            let name = if attribs & ATTR_UTF8 != 0 {
                String::from_utf8_lossy(raw).into_owned()
            } else {
                raw.iter().map(|b| *b as char).collect()
            };
            if folder as usize >= folders.len() {
                return Err(
                    "This installer's files are split across several cabinets, which Isolated cannot unpack yet."
                        .into(),
                );
            }
            files.push(Entry {
                name,
                size,
                folder,
                offset,
            });
        }
        Ok(Cabinet {
            data,
            folders,
            files,
            data_reserve,
        })
    }

    pub fn files(&self) -> &[Entry] {
        &self.files
    }

    /// Decompresses every file. `open` is called once per file, in archive
    /// order, and returns where to write it (or `None` to skip it). Stops
    /// with an error once more than `max_total` bytes have been produced.
    pub fn extract(
        &self,
        max_total: u64,
        mut open: impl FnMut(&Entry) -> Result<Option<Box<dyn Write>>, String>,
    ) -> Result<u64, String> {
        let mut total = 0u64;
        for (fi, folder) in self.folders.iter().enumerate() {
            let mut files: Vec<&Entry> = self.files.iter().filter(|f| f.folder as usize == fi).collect();
            if files.is_empty() {
                continue;
            }
            files.sort_by_key(|f| f.offset);
            let mut dec = Decoder::new(folder.compression)?;
            let mut c = Cursor::at(self.data, folder.first_block as usize);
            let mut pos = 0u64; // uncompressed offset of the current block
            let mut next = 0usize; // next file to start
                                   // Files being written. Several can be open at once because
                                   // identical files may share the same data.
            let mut active: Vec<(&Entry, Option<Box<dyn Write>>)> = Vec::new();
            for _ in 0..folder.blocks {
                c.bytes(4)?; // checksum
                let packed = c.u16()? as usize;
                let unpacked = c.u16()? as usize;
                c.bytes(self.data_reserve)?;
                let chunk = c.bytes(packed)?;
                let out = dec.block(chunk, unpacked)?;
                total += out.len() as u64;
                if total > max_total {
                    return Err("This installer unpacks to more data than Isolated allows.".into());
                }
                let (bstart, bend) = (pos, pos + out.len() as u64);
                while let Some(f) = files.get(next) {
                    if f.offset as u64 >= bend {
                        break;
                    }
                    active.push((f, open(f)?));
                    next += 1;
                }
                let mut i = 0;
                while i < active.len() {
                    let f = active[i].0;
                    let fend = f.offset as u64 + f.size as u64;
                    let s = (f.offset as u64).max(bstart);
                    let e = fend.min(bend);
                    if s < e {
                        if let Some(w) = active[i].1.as_mut() {
                            w.write_all(&out[(s - bstart) as usize..(e - bstart) as usize])
                                .map_err(|e| format!("could not write {}: {e}", f.name))?;
                        }
                    }
                    if fend <= bend {
                        if let (_, Some(mut w)) = active.swap_remove(i) {
                            w.flush().map_err(|e| format!("could not write {}: {e}", f.name))?;
                        }
                    } else {
                        i += 1;
                    }
                }
                pos = bend;
            }
            if !active.is_empty() || files[next..].iter().any(|f| f.size > 0) {
                return Err(bad("data ends before the last file"));
            }
            for f in &files[next..] {
                if let Some(mut w) = open(f)? {
                    let _ = w.flush();
                }
            }
        }
        Ok(total)
    }
}

enum Decoder {
    Stored,
    MsZip { inflate: flate2::Decompress, dict: Vec<u8> },
    Lzx(Box<lzxd::Lzxd>),
}

const DICT: usize = 0x8000;

impl Decoder {
    fn new(compression: u16) -> Result<Decoder, String> {
        Ok(match compression & 0x0f {
            0 => Decoder::Stored,
            1 => Decoder::MsZip {
                inflate: flate2::Decompress::new(false),
                dict: Vec::new(),
            },
            3 => {
                use lzxd::WindowSize as W;
                let w = match (compression >> 8) & 0x1f {
                    15 => W::KB32,
                    16 => W::KB64,
                    17 => W::KB128,
                    18 => W::KB256,
                    19 => W::KB512,
                    20 => W::MB1,
                    21 => W::MB2,
                    22 => W::MB4,
                    23 => W::MB8,
                    24 => W::MB16,
                    25 => W::MB32,
                    n => return Err(bad(format!("LZX window {n}"))),
                };
                Decoder::Lzx(Box::new(lzxd::Lzxd::new(w)))
            }
            2 => return Err("This installer uses Quantum compression, which Isolated cannot unpack.".into()),
            n => return Err(bad(format!("compression type {n}"))),
        })
    }

    fn block(&mut self, chunk: &[u8], unpacked: usize) -> Result<Vec<u8>, String> {
        match self {
            Decoder::Stored => {
                if chunk.len() != unpacked {
                    return Err(bad("stored block size"));
                }
                Ok(chunk.to_vec())
            }
            Decoder::Lzx(d) => d
                .decompress_next(chunk, unpacked)
                .map(|b| b.to_vec())
                .map_err(|e| bad(format!("LZX: {e}"))),
            Decoder::MsZip { inflate, dict } => {
                let data = chunk.strip_prefix(b"CK").ok_or_else(|| bad("MSZIP signature"))?;
                // Each block is its own deflate stream that may refer back
                // into the previous 32 KB, so prime the window with them as
                // a stored block first.
                inflate.reset(false);
                if !dict.is_empty() {
                    let n = dict.len() as u16;
                    let mut primer = Vec::with_capacity(dict.len() + 5);
                    primer.push(0);
                    primer.extend_from_slice(&n.to_le_bytes());
                    primer.extend_from_slice(&(!n).to_le_bytes());
                    primer.extend_from_slice(dict);
                    let mut sink = Vec::with_capacity(dict.len());
                    inflate
                        .decompress_vec(&primer, &mut sink, flate2::FlushDecompress::Sync)
                        .map_err(|e| bad(format!("MSZIP: {e}")))?;
                }
                let mut out = Vec::with_capacity(unpacked);
                inflate
                    .decompress_vec(data, &mut out, flate2::FlushDecompress::Finish)
                    .map_err(|e| bad(format!("MSZIP: {e}")))?;
                if out.len() != unpacked {
                    return Err(bad("MSZIP block size"));
                }
                if out.len() >= DICT {
                    *dict = out[out.len() - DICT..].to_vec();
                } else {
                    dict.extend_from_slice(&out);
                    if dict.len() > DICT {
                        let cut = dict.len() - DICT;
                        dict.drain(..cut);
                    }
                }
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    type Buf = Rc<RefCell<Vec<u8>>>;

    struct Collect(Buf);

    impl Write for Collect {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn sample(i: usize, len: usize) -> Vec<u8> {
        // Compressible but not trivial, so MSZIP blocks refer back across
        // block boundaries.
        (0..len)
            .map(|j| ((j * 7 + i * 13) % 251) as u8 ^ (j / 1000) as u8)
            .collect()
    }

    fn round_trip(ctype: cab::CompressionType) {
        let files: Vec<(String, Vec<u8>)> = vec![
            ("small.txt".into(), b"hello".to_vec()),
            ("empty.dat".into(), Vec::new()),
            ("big.bin".into(), sample(1, 200_000)),
            ("mid.bin".into(), sample(2, 40_000)),
        ];
        let mut b = cab::CabinetBuilder::new();
        {
            let folder = b.add_folder(ctype);
            for (n, _) in &files {
                folder.add_file(n.as_str());
            }
        }
        let mut w = b.build(std::io::Cursor::new(Vec::new())).unwrap();
        let mut i = 0;
        while let Some(mut fw) = w.next_file().unwrap() {
            fw.write_all(&files[i].1).unwrap();
            i += 1;
        }
        let data = w.finish().unwrap().into_inner();

        let cab = Cabinet::parse(&data).unwrap();
        assert_eq!(cab.files().len(), files.len());
        let got: Rc<RefCell<BTreeMap<String, Buf>>> = Default::default();
        let total = cab
            .extract(u64::MAX, |e| {
                let buf = Rc::new(RefCell::new(Vec::new()));
                got.borrow_mut().insert(e.name.clone(), buf.clone());
                Ok(Some(Box::new(Collect(buf)) as Box<dyn Write>))
            })
            .unwrap();
        assert_eq!(total, files.iter().map(|f| f.1.len() as u64).sum::<u64>());
        for (n, d) in &files {
            assert_eq!(&*got.borrow()[n].borrow(), d, "{n}");
        }
        // The size cap stops extraction.
        assert!(cab.extract(1000, |_| Ok(None)).is_err());
    }

    #[test]
    fn stored_and_mszip() {
        round_trip(cab::CompressionType::None);
        round_trip(cab::CompressionType::MsZip);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Cabinet::parse(b"nope").is_err());
        assert!(Cabinet::parse(b"MSCF\0\0").is_err());
    }
}

// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::fs::File;
use std::path::Path;

use goblin::elf::program_header::PT_LOAD;
use memmap2::Mmap;

use crate::error::{Error, Result};

use super::notes;

/// Owns the raw bytes of an ELF file (a core dump or a reference libc).
///
/// Large core dumps are memory-mapped rather than read into a `Vec` so we don't
/// pull gigabytes into RAM just to walk a few structures.
pub struct Image {
    backing: Backing,
}

enum Backing {
    Mapped(Mmap),
    Owned(Vec<u8>),
}

impl Image {
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        // SAFETY: we only ever read the mapping. Another process mutating the
        // file underneath us could yield inconsistent bytes, but that surfaces
        // as a parse/analysis error, not memory unsafety, which is the accepted
        // trade-off for mmap-based file readers.
        let mmap = unsafe { Mmap::map(&file) }.map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        check_magic(&mmap, path)?;
        Ok(Image {
            backing: Backing::Mapped(mmap),
        })
    }

    /// Build an image from in-memory bytes. Used by tests to feed synthetic ELF
    /// data without touching the filesystem.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        check_magic(&data, Path::new("<memory>"))?;
        Ok(Image {
            backing: Backing::Owned(data),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        match &self.backing {
            Backing::Mapped(m) => m,
            Backing::Owned(v) => v,
        }
    }

    pub fn parse(&self) -> Result<Elf<'_>> {
        Elf::parse(self.bytes())
    }
}

fn check_magic(data: &[u8], path: &Path) -> Result<()> {
    if data.starts_with(b"\x7fELF") {
        Ok(())
    } else {
        Err(Error::NotElf {
            path: path.to_path_buf(),
        })
    }
}

/// A parsed ELF, borrowing its backing bytes.
///
/// Kept separate from [`Image`] because goblin's `Elf` borrows the byte slice:
/// the `Image` must outlive the `Elf`, which is why you can't chain
/// `Image::load(p)?.parse()?` in one expression.
pub struct Elf<'a> {
    inner: goblin::elf::Elf<'a>,
    data: &'a [u8],
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let inner = goblin::elf::Elf::parse(data)?;
        Ok(Elf { inner, data })
    }

    pub fn is_64bit(&self) -> bool {
        self.inner.is_64
    }

    pub fn machine(&self) -> u16 {
        self.inner.header.e_machine
    }

    /// The whole file. Used by `locate::compute_identity` for the content-hash
    /// fallback.
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Access to the underlying goblin structures (symbols, relocations,
    /// version definitions). Internal crate use only.
    pub fn inner(&self) -> &goblin::elf::Elf<'a> {
        &self.inner
    }

    pub fn notes(&self) -> Vec<notes::Note<'a>> {
        notes::walk_all_notes(&self.inner, self.data)
    }

    /// The `[start, end)` file-backed virtual range of the `PT_LOAD` segment
    /// containing `addr`, or `None` if no segment does.
    pub fn segment_bounds(&self, addr: u64) -> Option<(u64, u64)> {
        for ph in &self.inner.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            let end = ph.p_vaddr.checked_add(ph.p_filesz)?;
            if addr >= ph.p_vaddr && addr < end {
                return Some((ph.p_vaddr, end));
            }
        }
        None
    }

    /// Read `len` bytes at virtual address `addr`.
    ///
    /// Only the file-backed part of a segment counts: `p_filesz` can be smaller
    /// than `p_memsz` (BSS tails, or a core truncated by `coredump_filter`), and
    /// those bytes have no file content behind them. Returning them as zeros
    /// would masquerade as a zero-sized chunk and mislead the walker, so an
    /// address past `p_filesz` is `AddressNotMapped`. All arithmetic is checked
    /// because `addr`/`len` derive from untrusted heap data.
    pub fn read_bytes(&self, addr: u64, len: usize) -> Result<&'a [u8]> {
        let len_u64 = len as u64;
        for ph in &self.inner.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            if addr < ph.p_vaddr {
                continue;
            }
            let off_in_seg = addr - ph.p_vaddr;
            let past = match off_in_seg.checked_add(len_u64) {
                Some(p) => p,
                None => continue,
            };
            if past > ph.p_filesz {
                continue;
            }
            let file_off = match ph.p_offset.checked_add(off_in_seg) {
                Some(o) => o,
                None => continue,
            };
            let Ok(file_off) = usize::try_from(file_off) else {
                continue;
            };
            let Some(end) = file_off.checked_add(len) else {
                continue;
            };
            if let Some(slice) = self.data.get(file_off..end) {
                return Ok(slice);
            }
        }
        Err(Error::AddressNotMapped { addr })
    }

    /// Read a little-endian `u64` at virtual address `addr`.
    pub fn read_u64(&self, addr: u64) -> Result<u64> {
        let bytes = self.read_bytes(addr, 8)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| Error::AddressNotMapped { addr })?;
        Ok(u64::from_le_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        match Image::from_bytes(b"not an elf".to_vec()) {
            Err(Error::NotElf { .. }) => {}
            Err(e) => panic!("expected NotElf, got {e:?}"),
            Ok(_) => panic!("expected NotElf, got Ok"),
        }
    }
}

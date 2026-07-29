// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! ELF and core-dump parsing.
//!
//! [`Image`] owns the file bytes (memory-mapped when possible) and hands out an
//! [`Elf`] view for reading. All addresses resolved through [`Elf::read_u64`] go
//! via the `PT_LOAD` table, so a value that lived at a virtual address in the
//! crashed process can be read straight out of the core.

pub mod coredump;
pub mod image;
pub mod notes;

pub use image::{Elf, Image};

use crate::error::Result;

/// Read access to process memory by virtual address.
///
/// The heap walkers only ever need to read a word at an address, so they take
/// this rather than a concrete [`Elf`]. In production it's backed by the core's
/// `PT_LOAD` segments; in tests a synthetic address→word map stands in, which is
/// how the chunk/fastbin/tcache traversals are exercised without a real dump.
pub trait MemReader {
    fn read_u64(&self, addr: u64) -> Result<u64>;

    /// Start address of the mapped segment containing `addr`, or `None`. Used by
    /// the main-arena heap walk to tell whether `sbrk_base` is mapped and, on
    /// aarch64, to fall back to the segment holding `top`.
    fn segment_start(&self, addr: u64) -> Option<u64>;
}

impl MemReader for Elf<'_> {
    fn read_u64(&self, addr: u64) -> Result<u64> {
        Elf::read_u64(self, addr)
    }

    fn segment_start(&self, addr: u64) -> Option<u64> {
        self.segment_bounds(addr).map(|(start, _)| start)
    }
}

/// Little-endian `u32` at `off`, bounds-checked. Our targets (x86-64, aarch64)
/// are little-endian, and core dumps store data in target byte order.
pub(crate) fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Little-endian `u64` at `off`, bounds-checked.
pub(crate) fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes: [u8; 8] = buf.get(off..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Little-endian `u16` at `off`, bounds-checked.
pub(crate) fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// A machine word — 8 bytes on 64-bit, 4 on 32-bit — zero-extended to `u64`.
pub(crate) fn read_word(buf: &[u8], off: usize, is_64bit: bool) -> Option<u64> {
    if is_64bit {
        read_u64_le(buf, off)
    } else {
        read_u32_le(buf, off).map(u64::from)
    }
}

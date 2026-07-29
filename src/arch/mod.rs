// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Per-architecture differences behind one trait.
//!
//! Everything that varies by target architecture — how to read registers out of
//! `NT_PRSTATUS`, where the thread pointer comes from, which relocation type
//! marks the TLS offset — lives behind [`Arch`]. Adding an architecture is one
//! new submodule plus one line in [`by_elf_machine`].

mod aarch64;
mod x86_64;

use crate::error::Result;

/// The few register values we need out of a thread's `NT_PRSTATUS`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadRegs {
    pub pc: u64,
    pub sp: u64,
    /// Thread pointer. On some architectures (aarch64) this is 0 here and comes
    /// from a separate TLS note; see [`Arch::parse_tls_note`].
    pub tp: u64,
    pub thread_id: i32,
}

pub trait Arch: Sync {
    fn elf_machine(&self) -> u16;

    /// Human-readable name for the `arch` JSON field (`"x86_64"` / `"aarch64"`).
    /// A method rather than `Debug` so the public schema doesn't leak internal
    /// type names or drift when the impl is renamed.
    fn name(&self) -> &'static str;

    /// Relocation type whose target address holds the libc-relative TLS offset
    /// of a variable (`R_X86_64_TPOFF64` etc.).
    fn tp_off_reloc_type(&self) -> u32;

    fn parse_prstatus(&self, desc: &[u8]) -> Result<ThreadRegs>;

    /// Note type carrying the thread pointer, for architectures that don't put
    /// it in `NT_PRSTATUS`. `None` (the default) means "it's already in
    /// prstatus".
    fn tls_note_type(&self) -> Option<u32> {
        None
    }

    /// Extract the thread pointer from such a note. Returns `None` on a
    /// truncated descriptor.
    fn parse_tls_note(&self, _desc: &[u8]) -> Option<u64> {
        None
    }
}

/// Look up the handler for a core dump's `e_machine`, or `None` if we don't
/// implement it.
pub fn by_elf_machine(e_machine: u16) -> Option<&'static dyn Arch> {
    const X86_64: x86_64::X86_64 = x86_64::X86_64;
    const AARCH64: aarch64::Aarch64 = aarch64::Aarch64;
    match e_machine {
        goblin::elf::header::EM_X86_64 => Some(&X86_64),
        goblin::elf::header::EM_AARCH64 => Some(&AARCH64),
        _ => None,
    }
}

/// Read a little-endian `u64` at `off`, or `None` if the slice is too short.
/// Shared by the register parsers; every access is bounds-checked because the
/// note descriptor is untrusted core-dump data.
fn le_u64(buf: &[u8], off: usize) -> Option<u64> {
    let bytes: [u8; 8] = buf.get(off..off + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn le_i32(buf: &[u8], off: usize) -> Option<i32> {
    let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

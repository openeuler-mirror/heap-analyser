// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use super::{le_i32, le_u64, Arch, ThreadRegs};
use crate::error::{Error, Result};

/// `NT_PRSTATUS` (`struct elf_prstatus`) field offsets on x86-64.
///
/// `pr_reg` is a `struct user_regs_struct`; the register order there puts `rip`
/// at index 16, `rsp` at 19 and `fs_base` at 21. On x86-64 the thread pointer
/// *is* `fs_base`, so unlike aarch64 we don't need a separate TLS note.
mod prstatus {
    pub const PR_PID: usize = 32;
    pub const PR_REG: usize = 112;
    pub const RIP: usize = PR_REG + 16 * 8;
    pub const RSP: usize = PR_REG + 19 * 8;
    pub const FS_BASE: usize = PR_REG + 21 * 8;
    /// Smallest descriptor we can read every field from.
    pub const MIN_LEN: usize = FS_BASE + 8;
}

/// `R_X86_64_TPOFF64`.
const R_X86_64_TPOFF64: u32 = 18;

pub struct X86_64;

impl Arch for X86_64 {
    fn elf_machine(&self) -> u16 {
        goblin::elf::header::EM_X86_64
    }

    fn name(&self) -> &'static str {
        "x86_64"
    }

    fn tp_off_reloc_type(&self) -> u32 {
        R_X86_64_TPOFF64
    }

    fn parse_prstatus(&self, desc: &[u8]) -> Result<ThreadRegs> {
        if desc.len() < prstatus::MIN_LEN {
            return Err(Error::NoteTooShort {
                expected: prstatus::MIN_LEN,
                actual: desc.len(),
            });
        }
        let short = || Error::NoteTooShort {
            expected: prstatus::MIN_LEN,
            actual: desc.len(),
        };
        Ok(ThreadRegs {
            pc: le_u64(desc, prstatus::RIP).ok_or_else(short)?,
            sp: le_u64(desc, prstatus::RSP).ok_or_else(short)?,
            tp: le_u64(desc, prstatus::FS_BASE).ok_or_else(short)?,
            thread_id: le_i32(desc, prstatus::PR_PID).ok_or_else(short)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registers_at_expected_offsets() {
        let mut desc = vec![0u8; prstatus::MIN_LEN];
        desc[prstatus::PR_PID..prstatus::PR_PID + 4].copy_from_slice(&4242i32.to_le_bytes());
        desc[prstatus::RIP..prstatus::RIP + 8].copy_from_slice(&0x4011a0u64.to_le_bytes());
        desc[prstatus::RSP..prstatus::RSP + 8].copy_from_slice(&0x7fffffffe000u64.to_le_bytes());
        desc[prstatus::FS_BASE..prstatus::FS_BASE + 8]
            .copy_from_slice(&0x7ffff7d00740u64.to_le_bytes());

        let regs = X86_64.parse_prstatus(&desc).unwrap();
        assert_eq!(regs.thread_id, 4242);
        assert_eq!(regs.pc, 0x4011a0);
        assert_eq!(regs.sp, 0x7fffffffe000);
        assert_eq!(regs.tp, 0x7ffff7d00740);
    }

    #[test]
    fn rejects_short_descriptor() {
        let desc = vec![0u8; prstatus::MIN_LEN - 1];
        assert!(matches!(
            X86_64.parse_prstatus(&desc),
            Err(Error::NoteTooShort { .. })
        ));
    }

    #[test]
    fn has_no_tls_note() {
        assert_eq!(X86_64.tls_note_type(), None);
    }
}

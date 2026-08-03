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

/// `NT_PRSTATUS` field offsets on aarch64.
///
/// `pr_reg` is `struct user_regs_struct { u64 regs[31]; u64 sp; u64 pc; ... }`,
/// so `sp` sits at register index 31 and `pc` at 32. The thread pointer is
/// *not* here — it arrives in a separate `NT_ARM_TLS` note (see below).
mod prstatus {
    pub const PR_PID: usize = 32;
    pub const PR_REG: usize = 112;
    pub const SP: usize = PR_REG + 31 * 8;
    pub const PC: usize = PR_REG + 32 * 8;
    pub const MIN_LEN: usize = PC + 8;
}

/// `NT_ARM_TLS` — the note carrying `tpidr_el0`, i.e. the thread pointer.
const NT_ARM_TLS: u32 = 0x401;
/// `R_AARCH64_TLS_TPREL64`.
const R_AARCH64_TLS_TPREL64: u32 = 1030;

pub struct Aarch64;

impl Arch for Aarch64 {
    fn elf_machine(&self) -> u16 {
        goblin::elf::header::EM_AARCH64
    }

    fn name(&self) -> &'static str {
        "aarch64"
    }

    fn tp_off_reloc_type(&self) -> u32 {
        R_AARCH64_TLS_TPREL64
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
            pc: le_u64(desc, prstatus::PC).ok_or_else(short)?,
            sp: le_u64(desc, prstatus::SP).ok_or_else(short)?,
            // Filled in later from NT_ARM_TLS by elf::coredump::threads.
            tp: 0,
            thread_id: le_i32(desc, prstatus::PR_PID).ok_or_else(short)?,
        })
    }

    fn tls_note_type(&self) -> Option<u32> {
        Some(NT_ARM_TLS)
    }

    fn parse_tls_note(&self, desc: &[u8]) -> Option<u64> {
        le_u64(desc, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pc_sp_pid_and_leaves_tp_zero() {
        let mut desc = vec![0u8; prstatus::MIN_LEN];
        desc[prstatus::PR_PID..prstatus::PR_PID + 4].copy_from_slice(&7i32.to_le_bytes());
        desc[prstatus::SP..prstatus::SP + 8].copy_from_slice(&0xffffdeadbeefu64.to_le_bytes());
        desc[prstatus::PC..prstatus::PC + 8].copy_from_slice(&0x400abcu64.to_le_bytes());

        let regs = Aarch64.parse_prstatus(&desc).unwrap();
        assert_eq!(regs.thread_id, 7);
        assert_eq!(regs.sp, 0xffffdeadbeef);
        assert_eq!(regs.pc, 0x400abc);
        assert_eq!(regs.tp, 0, "tp comes from NT_ARM_TLS, not prstatus");
    }

    #[test]
    fn tls_note_carries_thread_pointer() {
        assert_eq!(Aarch64.tls_note_type(), Some(NT_ARM_TLS));
        let desc = 0x1234_5678_9abc_def0u64.to_le_bytes();
        assert_eq!(Aarch64.parse_tls_note(&desc), Some(0x1234_5678_9abc_def0));
        assert_eq!(Aarch64.parse_tls_note(&[0u8; 4]), None);
    }

    #[test]
    fn rejects_short_descriptor() {
        assert!(matches!(
            Aarch64.parse_prstatus(&[0u8; 8]),
            Err(Error::NoteTooShort { .. })
        ));
    }
}

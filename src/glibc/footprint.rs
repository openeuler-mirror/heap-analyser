// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Read the allocator-wide counters used for the malloc footprint summary.

use crate::elf::MemReader;

use super::DetectedLayout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectMmapCounters {
    pub count: Option<u64>,
    pub bytes: Option<u64>,
}

pub(crate) fn arena_system_mem(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    malloc_state_addr: u64,
) -> Option<u64> {
    let offset = layout.malloc_state_system_mem_offset?;
    read_word(
        mem,
        malloc_state_addr.checked_add(u64::from(offset))?,
        layout,
    )
}

pub(crate) fn direct_mmap_counters(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
) -> DirectMmapCounters {
    let base = libc_addr.checked_add(layout.mp.value);
    let count = base
        .zip(layout.mp_n_mmaps_offset)
        .and_then(|(base, offset)| base.checked_add(u64::from(offset)))
        .and_then(|address| mem.read_u64(address).ok())
        .map(|value| value as u32 as i32)
        .and_then(|value| u64::try_from(value).ok());
    let bytes = base
        .zip(layout.mp_mmapped_mem_offset)
        .and_then(|(base, offset)| base.checked_add(u64::from(offset)))
        .and_then(|address| read_word(mem, address, layout));
    DirectMmapCounters { count, bytes }
}

fn read_word(mem: &impl MemReader, address: u64, layout: &DetectedLayout) -> Option<u64> {
    let value = mem.read_u64(address).ok()?;
    match layout.word_size {
        8 => Some(value),
        4 => Some(value & u64::from(u32::MAX)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    #[test]
    fn reads_system_mem_and_direct_mmap_counters() {
        let mut layout = test_layout(8);
        layout.malloc_state_system_mem_offset = Some(0x20);
        layout.mp_n_mmaps_offset = Some(0x30);
        layout.mp_mmapped_mem_offset = Some(0x38);
        layout.mp.value = 0x100;

        let mut mem = FakeMem::new();
        mem.set(0x2020, 0x40_0000);
        mem.set(0x1130, 7);
        mem.set(0x1138, 0x80_0000);

        assert_eq!(arena_system_mem(&mem, &layout, 0x2000), Some(0x40_0000));
        assert_eq!(
            direct_mmap_counters(&mem, &layout, 0x1000),
            DirectMmapCounters {
                count: Some(7),
                bytes: Some(0x80_0000),
            }
        );
    }

    #[test]
    fn rejects_negative_mmap_count_and_missing_layout() {
        let mut layout = test_layout(8);
        layout.mp_n_mmaps_offset = Some(0x30);
        layout.mp.value = 0x100;

        let mut mem = FakeMem::new();
        mem.set(0x1130, u64::from(u32::MAX));

        assert_eq!(
            direct_mmap_counters(&mem, &layout, 0x1000),
            DirectMmapCounters {
                count: None,
                bytes: None,
            }
        );
        assert_eq!(arena_system_mem(&mem, &layout, 0x2000), None);
    }
}

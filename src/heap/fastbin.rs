// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Fastbin free-list traversal.
//!
//! Each fastbin is a singly-linked LIFO of same-size chunks. The head comes from
//! `malloc_state.fastbinsY[i]` (read by the caller); each chunk's `fd` sits at
//! `chunk + 2*word`. On glibc ≥ 2.32 `fd` is safe-linked and must be revealed
//! with the *storage location* — this is gated on the detected capability, since
//! XOR-ing an already-plain pointer on older glibc would corrupt it.

use std::collections::HashSet;

use crate::elf::MemReader;
use crate::glibc::DetectedLayout;
use crate::problem::Problem;

/// Traversal cap; the visited set already bounds cyclic chains.
const MAX_CHAIN: usize = 10_000;

/// Nominal payload size of chunks in fastbin `i`.
pub fn fastbin_index_to_size(layout: &DetectedLayout, i: u32) -> u64 {
    u64::from(layout.minsize) - u64::from(layout.header_size)
        + u64::from(i) * u64::from(layout.malloc_alignment)
}

pub struct FastbinBinResult {
    pub index: u32,
    pub size: u64,
    pub count: u64,
}

/// Walk one fastbin from `head` (a chunk pointer). `head == 0` is an empty bin.
pub fn walk_fastbin(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    head: u64,
    arena_index: u32,
    bin_index: u32,
) -> (FastbinBinResult, Vec<Problem>) {
    let mut result = FastbinBinResult {
        index: bin_index,
        size: fastbin_index_to_size(layout, bin_index),
        count: 0,
    };
    let mut problems = Vec::new();
    if head == 0 {
        return (result, problems);
    }

    let fd_offset = 2 * u64::from(layout.word_size);
    let mut visited = HashSet::new();
    let mut current = head;

    loop {
        if !visited.insert(current) || visited.len() > MAX_CHAIN {
            problems.push(Problem::FastbinCycleDetected {
                arena: arena_index,
                bin_index,
            });
            break;
        }
        result.count += 1;

        let fd_slot = current.wrapping_add(fd_offset);
        let stored = match mem.read_u64(fd_slot) {
            Ok(v) => v,
            Err(_) => {
                problems.push(Problem::FastbinChunkReadFailed {
                    arena: arena_index,
                    bin_index,
                    address: format!("{fd_slot:#x}"),
                });
                break;
            }
        };
        let next = reveal(layout, fd_slot, stored);
        if next == 0 {
            break;
        }
        current = next;
    }
    (result, problems)
}

/// Undo safe-linking for a pointer stored at `location`, when the target glibc
/// uses it. The location — not the value — is the XOR key.
pub(super) fn reveal(layout: &DetectedLayout, location: u64, stored: u64) -> u64 {
    if layout.capabilities.has_safe_linking {
        (location >> 12) ^ stored
    } else {
        stored
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    #[test]
    fn sizes_match_glibc_formula() {
        let layout = test_layout(8); // minsize 32, header 8, align 16
        assert_eq!(fastbin_index_to_size(&layout, 0), 24);
        assert_eq!(fastbin_index_to_size(&layout, 1), 40);
        assert_eq!(fastbin_index_to_size(&layout, 5), 104);
    }

    #[test]
    fn counts_a_three_chunk_bin_without_safe_linking() {
        let mut layout = test_layout(8);
        layout.capabilities.has_safe_linking = false;
        let (c0, c1, c2) = (0x1000, 0x1100, 0x1200);
        let fd = 16u64;
        let mut mem = FakeMem::new();
        mem.set(c0 + fd, c1);
        mem.set(c1 + fd, c2);
        mem.set(c2 + fd, 0);

        let (result, problems) = walk_fastbin(&mem, &layout, c0, 0, 0);
        assert!(problems.is_empty());
        assert_eq!(result.count, 3);
    }

    #[test]
    fn reveals_safe_linked_chain() {
        let mut layout = test_layout(8);
        layout.capabilities.has_safe_linking = true;
        let (c0, c1) = (0x55000u64, 0x66000u64);
        let fd = 16u64;
        let mut mem = FakeMem::new();
        // stored = real ^ (fd_slot >> 12); the tail real pointer is 0.
        mem.set(c0 + fd, c1 ^ ((c0 + fd) >> 12));
        mem.set(c1 + fd, (c1 + fd) >> 12);

        let (result, problems) = walk_fastbin(&mem, &layout, c0, 0, 0);
        assert!(problems.is_empty());
        assert_eq!(result.count, 2);
    }

    #[test]
    fn cycle_is_reported() {
        let mut layout = test_layout(8);
        layout.capabilities.has_safe_linking = false;
        let (c0, c1) = (0x1000, 0x1100);
        let fd = 16u64;
        let mut mem = FakeMem::new();
        mem.set(c0 + fd, c1);
        mem.set(c1 + fd, c0); // loop

        let (_result, problems) = walk_fastbin(&mem, &layout, c0, 3, 2);
        assert!(matches!(
            problems.as_slice(),
            [Problem::FastbinCycleDetected {
                arena: 3,
                bin_index: 2
            }]
        ));
    }

    #[test]
    fn empty_bin_reads_nothing() {
        let layout = test_layout(8);
        let mem = FakeMem::new();
        let (result, problems) = walk_fastbin(&mem, &layout, 0, 0, 0);
        assert_eq!(result.count, 0);
        assert!(problems.is_empty());
    }
}

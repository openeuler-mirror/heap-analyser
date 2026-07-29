// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Linear chunk traversal over one heap region.
//!
//! This is pure iteration: it emits a [`ChunkEvent`] per chunk and knows how a
//! non-main-arena heap ends (the sentinel), but keeps no running totals — that's
//! `stats`'s job. The size-field address is what advances: chunk `N`'s size
//! field sits at `p + word`, and the next chunk's size field is exactly
//! `full_size` further on, so stepping the size-field address by `full_size`
//! lands on the next one.

use crate::elf::MemReader;
use crate::glibc::DetectedLayout;
use crate::problem::Problem;

use super::chunk::{chunk_size, NON_MAIN_ARENA, PREV_INUSE};

/// Extra safety cap on chunks per region, independent of the region bound.
const MAX_CHUNKS: u64 = 10_000_000;

pub struct ChunkEvent {
    /// Address of the chunk's `size` field (not the `prev_size`-bearing start;
    /// the two differ by one word).
    pub size_field_addr: u64,
    /// User/mem pointer = `size_field_addr + word`.
    pub user_addr: u64,
    /// Payload bytes = `full_size - header_size` (one word of header).
    pub user_size: u64,
    /// Full chunk size including header, flags masked off.
    pub full_size: u64,
    /// In-use per the *next* chunk's `PREV_INUSE` bit. This misses chunks parked
    /// in fastbins/tcache, which keep the bit set; `stats` corrects for those.
    pub prev_inuse_says_in_use: bool,
}

/// Walk `[region_start, region_end)` where `region_start` is the first chunk's
/// size-field address and `region_end` is one word past the last usable chunk
/// (`top + word` for the last heap of an arena).
///
/// Returns partial results with a `Problem` on any corruption rather than
/// aborting — a damaged chunk shouldn't cost us the chunks before it. The
/// sentinel check applies only to non-main arenas; see the flag logic below.
pub fn walk_region(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    arena_index: u32,
    region_start: u64,
    region_end: u64,
    is_main_arena: bool,
) -> (Vec<ChunkEvent>, Vec<Problem>) {
    let word = u64::from(layout.word_size);
    let header = u64::from(layout.header_size);
    let alignment = u64::from(layout.malloc_alignment);
    let mut events = Vec::new();
    let mut problems = Vec::new();

    if region_start > region_end {
        problems.push(Problem::HeapWalkTruncated {
            arena: arena_index,
            reason: "region_start > region_end".to_string(),
        });
        return (events, problems);
    }
    if region_start == region_end {
        return (events, problems);
    }

    // `next_header_address` is the size-field address of the chunk we're about
    // to emit; `next_header` is its (already read) raw size field.
    let mut next_header_address = region_start;
    let mut next_header = match mem.read_u64(next_header_address) {
        Ok(v) => v,
        Err(_) => {
            problems.push(Problem::ChunkReadFailed {
                arena: arena_index,
                address: format!("{next_header_address:#x}"),
            });
            return (events, problems);
        }
    };

    let mut seen = 0u64;
    while next_header_address != region_end {
        seen += 1;
        if seen > MAX_CHUNKS {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena_index,
                reason: "chunk count cap exceeded".to_string(),
            });
            break;
        }

        let size_field_addr = next_header_address;
        let current_header = next_header;
        let full_size = chunk_size(current_header);

        // Corruption checks: below the minimum chunk, or not a multiple of
        // MALLOC_ALIGNMENT (glibc always rounds up to it).
        if full_size < 2 * word {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena_index,
                reason: "chunk size below minimum".to_string(),
            });
            break;
        }
        if full_size % alignment != 0 {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena_index,
                reason: "chunk size not aligned".to_string(),
            });
            break;
        }

        // Advance to the next size field. `full_size` is core-read, so the add
        // is checked; landing past the region means the size drove us out of
        // bounds (which AddressNotMapped can't catch — it might land in another
        // live mapping).
        let next_cursor = match size_field_addr.checked_add(full_size) {
            Some(v) => v,
            None => {
                problems.push(Problem::HeapWalkTruncated {
                    arena: arena_index,
                    reason: "address arithmetic overflow".to_string(),
                });
                break;
            }
        };
        if next_cursor > region_end {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena_index,
                reason: "chunk extends past region end".to_string(),
            });
            break;
        }
        next_header_address = next_cursor;
        next_header = match mem.read_u64(next_header_address) {
            Ok(v) => v,
            Err(_) => {
                problems.push(Problem::ChunkReadFailed {
                    arena: arena_index,
                    address: format!("{next_header_address:#x}"),
                });
                break;
            }
        };

        // Sentinel: a non-main-arena chunk that has lost its NON_MAIN_ARENA flag
        // is the fake top bridging to the next heap. If the next chunk's end plus
        // one word hits region_end and that word is a bare PREV_INUSE, this is
        // the end of an intermediate heap — stop without counting this bridge.
        // The last heap's real chunks keep the flag, so this never fires there.
        if !is_main_arena && current_header & NON_MAIN_ARENA == 0 {
            let next_size = chunk_size(next_header);
            if let Some(sentinel_addr) = next_cursor.checked_add(next_size) {
                if sentinel_addr.checked_add(word) == Some(region_end)
                    && mem.read_u64(sentinel_addr).ok() == Some(PREV_INUSE)
                {
                    break;
                }
            }
        }

        events.push(ChunkEvent {
            size_field_addr,
            user_addr: size_field_addr + word,
            user_size: full_size - header,
            full_size,
            prev_inuse_says_in_use: next_header & PREV_INUSE != 0,
        });
    }

    (events, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    /// Lay out a main-arena heap of three 0x20 chunks then top, at word-aligned
    /// size-field addresses, and check counts + in-use flags.
    #[test]
    fn walks_main_arena_chunks() {
        let layout = test_layout(8);
        let mut mem = FakeMem::new();
        // size fields at 0x100, 0x120, 0x140; top's size field at 0x160.
        // Chunk 0: allocated (next PREV_INUSE set), chunk 1: free, chunk 2: allocated.
        mem.set(0x100, 0x20 | PREV_INUSE);
        mem.set(0x120, 0x20 | PREV_INUSE); // chunk1 header; its PREV_INUSE => chunk0 in use
        mem.set(0x140, 0x20); // chunk2 header; PREV_INUSE clear => chunk1 free
        mem.set(0x160, 0x20 | PREV_INUSE); // top; PREV_INUSE set => chunk2 in use
        let region_end = 0x160;

        let (events, problems) = walk_region(&mem, &layout, 0, 0x100, region_end, true);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].user_addr, 0x108);
        assert_eq!(events[0].user_size, 0x18); // 0x20 - 8
        assert!(events[0].prev_inuse_says_in_use);
        assert!(!events[1].prev_inuse_says_in_use);
        assert!(events[2].prev_inuse_says_in_use);
    }

    #[test]
    fn stops_on_unaligned_chunk() {
        let layout = test_layout(8);
        let mut mem = FakeMem::new();
        mem.set(0x100, 0x18 | PREV_INUSE); // 0x18 not a multiple of 16
        let (events, problems) = walk_region(&mem, &layout, 0, 0x100, 0x200, true);
        assert!(events.is_empty());
        assert!(matches!(
            problems.as_slice(),
            [Problem::HeapWalkTruncated { reason, .. }] if reason.contains("aligned")
        ));
    }

    #[test]
    fn stops_when_chunk_exceeds_region() {
        let layout = test_layout(8);
        let mut mem = FakeMem::new();
        mem.set(0x100, 0x40 | PREV_INUSE); // would end at 0x140, past region_end 0x120
        let (events, problems) = walk_region(&mem, &layout, 0, 0x100, 0x120, true);
        assert!(events.is_empty());
        assert!(matches!(
            problems.as_slice(),
            [Problem::HeapWalkTruncated { reason, .. }] if reason.contains("past region")
        ));
    }

    #[test]
    fn empty_region_yields_nothing() {
        let layout = test_layout(8);
        let mem = FakeMem::new();
        let (events, problems) = walk_region(&mem, &layout, 0, 0x100, 0x100, true);
        assert!(events.is_empty());
        assert!(problems.is_empty());
    }
}

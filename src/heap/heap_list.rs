// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Enumerate the heap regions of an arena and, for each, the exact
//! `[region_start, region_end)` the chunk walker should scan.
//!
//! The main arena has a single sbrk'd region; a secondary arena is a `prev`-
//! linked chain of `_heap_info` blocks. In both cases the first chunk doesn't
//! begin right at the region start — there's zero padding (the unused
//! `prev_size` slot), and a secondary arena's first heap also embeds the arena's
//! `malloc_state` right after its `_heap_info`. Both are accounted for here so
//! the walker just consumes `region_start`/`region_end`.
//!
//! `wrapping_add` is used for base+offset arithmetic on core-read addresses;
//! results feed mapping-checked reads.

use std::collections::HashSet;

use crate::elf::MemReader;
use crate::error::Result;
use crate::glibc::DetectedLayout;
use crate::problem::Problem;

use super::arena::Arena;

/// Guard against a corrupt `prev` chain.
const MAX_HEAPS: u32 = 10_000;

pub struct Heap {
    /// Segment/`_heap_info` start of this heap.
    pub address: u64,
    /// In-use extent of the heap in bytes.
    pub size: u64,
    /// Bytes actually committed (mprotect'd); equals `size` for the main arena.
    pub mprotect_size: u64,
    /// Size-field address of the first real chunk (zero padding and any embedded
    /// `malloc_state` already skipped).
    pub region_start: u64,
    /// One word past the last usable chunk.
    pub region_end: u64,
}

pub fn list(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
    arena: &Arena,
) -> Result<(Vec<Heap>, Vec<Problem>)> {
    if arena.is_main() {
        list_main(mem, layout, libc_addr, arena)
    } else {
        list_secondary(mem, layout, arena)
    }
}

fn list_main(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
    arena: &Arena,
) -> Result<(Vec<Heap>, Vec<Problem>)> {
    let word = u64::from(layout.word_size);
    let mp_addr = libc_addr.wrapping_add(layout.mp.value);
    // These two reads are the starting point; if they fail the whole arena is
    // unusable (main arena is core to the report), so propagate.
    let sbrk_base = mem.read_u64(mp_addr.wrapping_add(u64::from(layout.mp_sbrk_base_offset)))?;
    let top = mem.read_u64(
        arena
            .malloc_state_addr
            .wrapping_add(u64::from(layout.malloc_state_top_offset)),
    )?;
    // A brand-new process that hasn't grown its heap: legitimately empty.
    if sbrk_base == 0 || top == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut problems = Vec::new();
    let last_address = top.wrapping_add(word);

    // Normally sbrk_base is the heap start. On aarch64 the main arena can be
    // mmap-backed and sbrk_base points elsewhere; fall back to the start of the
    // segment holding top, bounded so we don't scan a huge merged mapping.
    let heap_start = if mem.segment_start(sbrk_base).is_some() {
        sbrk_base
    } else {
        match mem.segment_start(top) {
            Some(seg_start) => {
                let max_scan = layout.heap_max_size.saturating_mul(4);
                seg_start.max(top.saturating_sub(max_scan))
            }
            // Can't determine where the heap starts — that's a diagnostic, not a
            // silent "no heap": the user needs to tell the two cases apart.
            None => {
                problems.push(Problem::HeapWalkTruncated {
                    arena: arena.index,
                    reason: "main arena heap start undeterminable".to_string(),
                });
                return Ok((Vec::new(), problems));
            }
        }
    };

    // `top` and `heap_start` are both core-read addresses; an inverted result is
    // corruption, not a valid empty extent.
    let size = match top.checked_sub(heap_start) {
        Some(s) => s,
        None => {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena.index,
                reason: "top is below heap start".to_string(),
            });
            0
        }
    };

    let region_start = skip_zero_padding(mem, heap_start, last_address, word);
    let heap = Heap {
        address: heap_start,
        size,
        mprotect_size: size,
        region_start,
        region_end: last_address,
    };
    Ok((vec![heap], problems))
}

fn list_secondary(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    arena: &Arena,
) -> Result<(Vec<Heap>, Vec<Problem>)> {
    let word = u64::from(layout.word_size);
    let top = mem.read_u64(
        arena
            .malloc_state_addr
            .wrapping_add(u64::from(layout.malloc_state_top_offset)),
    )?;
    if top == 0 {
        return Ok((Vec::new(), Vec::new()));
    }

    // The heap holding `top` is where the chain starts; walk `prev` back to the
    // oldest heap.
    let top_heap = to_heap_start(top, layout.heap_max_size);
    let mut current = top_heap;
    let mut heaps = Vec::new();
    let mut problems = Vec::new();
    // A corrupt `prev` chain must not spin us or produce duplicate heaps; a
    // repeated `_heap_info` address is a cycle.
    let mut visited = HashSet::new();

    loop {
        if heaps.len() >= MAX_HEAPS as usize {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena.index,
                reason: "heap_info prev chain exceeded limit".to_string(),
            });
            break;
        }
        if !visited.insert(current) {
            problems.push(Problem::HeapWalkTruncated {
                arena: arena.index,
                reason: "heap_info prev chain forms a cycle".to_string(),
            });
            break;
        }

        let info = match read_heap_info(mem, layout, current) {
            Ok(info) => info,
            Err(e) if heaps.is_empty() => return Err(e), // no starting point at all
            Err(_) => {
                problems.push(Problem::HeapWalkTruncated {
                    arena: arena.index,
                    reason: "heap_info unreadable".to_string(),
                });
                break;
            }
        };

        // region_end mixes in a core-read size, so the add is checked; an
        // overflow means the size is garbage.
        let is_top_heap = current == top_heap;
        let region_end = if is_top_heap {
            top.wrapping_add(word)
        } else {
            match current.checked_add(info.size) {
                Some(end) => end,
                None => {
                    problems.push(Problem::HeapWalkTruncated {
                        arena: arena.index,
                        reason: "heap_info size overflows its region".to_string(),
                    });
                    break;
                }
            }
        };

        // First heap (prev == 0) has the arena's malloc_state embedded right
        // after its _heap_info, so the first chunk starts further in.
        let mut heap_start = current.wrapping_add(u64::from(layout.heap_info_size));
        if info.prev == 0 {
            heap_start = heap_start.wrapping_add(layout.main_arena.size);
        }
        let region_start = skip_zero_padding(mem, heap_start, region_end, word);

        heaps.push(Heap {
            address: current,
            size: info.size,
            mprotect_size: info.mprotect_size,
            region_start,
            region_end,
        });

        if info.prev == 0 {
            break;
        }
        current = info.prev;
    }
    Ok((heaps, problems))
}

struct HeapInfo {
    size: u64,
    mprotect_size: u64,
    prev: u64,
}

fn read_heap_info(mem: &impl MemReader, layout: &DetectedLayout, addr: u64) -> Result<HeapInfo> {
    Ok(HeapInfo {
        size: mem.read_u64(addr.wrapping_add(u64::from(layout.heap_info_size_offset)))?,
        mprotect_size: mem
            .read_u64(addr.wrapping_add(u64::from(layout.heap_info_mprotect_size_offset)))?,
        prev: mem.read_u64(addr.wrapping_add(u64::from(layout.heap_info_prev_offset)))?,
    })
}

/// Mask an address down to the `heap_max_size` boundary — the `_heap_info` for a
/// secondary heap sits at the start of its aligned region.
fn to_heap_start(addr: u64, heap_max_size: u64) -> u64 {
    addr & !(heap_max_size - 1)
}

/// Advance past the zero words (the unused `prev_size` slot) to the first real
/// size field. Stops at `end` if the whole region is zero. A read failure also
/// stops the scan; the walker will re-hit and report it.
fn skip_zero_padding(mem: &impl MemReader, mut start: u64, end: u64, word: u64) -> u64 {
    while start < end {
        match mem.read_u64(start) {
            Ok(0) => start = start.wrapping_add(word),
            _ => break,
        }
    }
    start
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    const LIBC: u64 = 0x1000;

    #[test]
    fn main_arena_single_region() {
        let layout = test_layout(8);
        let arena = Arena {
            malloc_state_addr: LIBC,
            index: 0,
        };
        let sbrk_base = 0x40000;
        let top = 0x40800;
        let mut mem = FakeMem::new();
        mem.add_segment(0x40000, 0x41000);
        mem.set(LIBC + u64::from(layout.mp_sbrk_base_offset), sbrk_base);
        mem.set(LIBC + u64::from(layout.malloc_state_top_offset), top);
        // first word at sbrk_base is a real size field (no zero padding here)
        mem.set(sbrk_base, 0x20 | 1);

        let (heaps, problems) = list(&mem, &layout, LIBC, &arena).unwrap();
        assert!(problems.is_empty());
        assert_eq!(heaps.len(), 1);
        assert_eq!(heaps[0].address, sbrk_base);
        assert_eq!(heaps[0].region_start, sbrk_base);
        assert_eq!(heaps[0].region_end, top + 8);
        assert_eq!(heaps[0].size, top - sbrk_base);
    }

    #[test]
    fn main_arena_empty_when_top_zero() {
        let layout = test_layout(8);
        let arena = Arena {
            malloc_state_addr: LIBC,
            index: 0,
        };
        let mut mem = FakeMem::new();
        mem.set(LIBC + u64::from(layout.mp_sbrk_base_offset), 0x40000);
        mem.set(LIBC + u64::from(layout.malloc_state_top_offset), 0);
        let (heaps, _) = list(&mem, &layout, LIBC, &arena).unwrap();
        assert!(heaps.is_empty());
    }

    #[test]
    fn secondary_single_heap_skips_embedded_malloc_state() {
        let mut layout = test_layout(8);
        layout.main_arena.size = 0x8b0; // sizeof(malloc_state) on 64-bit-ish
        let hms = layout.heap_max_size;
        let heap_addr = 0x7f0000000000 & !(hms - 1);
        let top = heap_addr + 0x2000;
        let arena = Arena {
            malloc_state_addr: 0x9000,
            index: 1,
        };
        let mut mem = FakeMem::new();
        mem.set(0x9000 + u64::from(layout.malloc_state_top_offset), top);
        // _heap_info at heap_addr: size, mprotect_size, prev(=0 => first heap)
        mem.set(heap_addr + u64::from(layout.heap_info_size_offset), 0x2000);
        mem.set(
            heap_addr + u64::from(layout.heap_info_mprotect_size_offset),
            0x2000,
        );
        mem.set(heap_addr + u64::from(layout.heap_info_prev_offset), 0);
        // first chunk size field right after _heap_info + embedded malloc_state
        let first_chunk = heap_addr + u64::from(layout.heap_info_size) + 0x8b0;
        mem.set(first_chunk, 0x30 | 4 | 1);

        let (heaps, problems) = list(&mem, &layout, LIBC, &arena).unwrap();
        assert!(problems.is_empty());
        assert_eq!(heaps.len(), 1);
        assert_eq!(heaps[0].address, heap_addr);
        assert_eq!(
            heaps[0].region_start, first_chunk,
            "region_start must skip _heap_info + embedded malloc_state"
        );
        assert_eq!(heaps[0].region_end, top + 8);
    }

    #[test]
    fn secondary_prev_chain_cycle_is_bounded_and_flagged() {
        let layout = test_layout(8);
        let hms = layout.heap_max_size;
        let a = 0x40000000 & !(hms - 1);
        let b = a + hms; // distinct, also heap_max_size aligned
        let arena = Arena {
            malloc_state_addr: 0x9000,
            index: 2,
        };
        let mut mem = FakeMem::new();
        mem.set(
            0x9000 + u64::from(layout.malloc_state_top_offset),
            a + 0x1000,
        );
        // A.prev = B, B.prev = A -> a cycle that must not spin or duplicate.
        for h in [a, b] {
            mem.set(h + u64::from(layout.heap_info_size_offset), 0x2000);
            mem.set(h + u64::from(layout.heap_info_mprotect_size_offset), 0x2000);
        }
        mem.set(a + u64::from(layout.heap_info_prev_offset), b);
        mem.set(b + u64::from(layout.heap_info_prev_offset), a);

        let (heaps, problems) = list(&mem, &layout, LIBC, &arena).unwrap();
        assert_eq!(heaps.len(), 2, "each distinct heap visited once");
        assert!(matches!(
            problems.as_slice(),
            [Problem::HeapWalkTruncated { reason, .. }] if reason.contains("cycle")
        ));
    }
}

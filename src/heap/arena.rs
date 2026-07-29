// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Enumerate arenas by following `malloc_state.next` from `main_arena`.
//!
//! Address arithmetic here is `wrapping_add`: the base is a `malloc_state`
//! pointer read from the (untrusted) core, and adding a fixed layout offset must
//! not panic on a corrupt value. Any bogus result is caught by the
//! mapping-checked read that follows.

use std::collections::HashSet;

use crate::elf::MemReader;
use crate::error::Result;
use crate::glibc::DetectedLayout;
use crate::problem::Problem;

/// Defensive ceiling; the cycle check below normally ends the walk first.
const MAX_ARENAS: u32 = 1024;

pub struct Arena {
    pub malloc_state_addr: u64,
    pub index: u32,
}

impl Arena {
    pub fn is_main(&self) -> bool {
        self.index == 0
    }
}

/// List every arena. The main arena is index 0; secondary arenas follow the
/// `next` ring.
///
/// Fails only if the main arena's own fields can't be read — without a starting
/// point there's nothing to return. A `next` pointer that breaks partway yields
/// the arenas found so far plus a [`Problem`], per the two-tier rule.
pub fn list(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
) -> Result<(Vec<Arena>, Vec<Problem>)> {
    let next_off = u64::from(layout.malloc_state_next_offset);
    let top_off = u64::from(layout.malloc_state_top_offset);
    let main_addr = libc_addr.wrapping_add(layout.main_arena.value);

    // Starting-point probe: if we can't even read main_arena.top, bail hard.
    mem.read_u64(main_addr.wrapping_add(top_off))?;

    let mut arenas = vec![Arena {
        malloc_state_addr: main_addr,
        index: 0,
    }];
    let mut problems = Vec::new();
    let mut visited = HashSet::from([main_addr]);
    let mut current = main_addr;
    let mut index = 1u32;

    loop {
        if index >= MAX_ARENAS {
            problems.push(Problem::HeapWalkTruncated {
                arena: index,
                reason: "arena list did not cycle back within limit".to_string(),
            });
            break;
        }
        let next = match mem.read_u64(current.wrapping_add(next_off)) {
            Ok(n) => n,
            Err(_) => {
                problems.push(Problem::HeapWalkTruncated {
                    arena: index,
                    reason: "next pointer unreadable".to_string(),
                });
                break;
            }
        };
        // Only a link back to main_arena (or a null terminator) is a clean end.
        if next == main_addr || next == 0 {
            break;
        }
        // A link to an already-seen node that isn't main_arena means the ring is
        // corrupt — record it rather than silently treating it as a clean end.
        if !visited.insert(next) {
            problems.push(Problem::HeapWalkTruncated {
                arena: index,
                reason: "arena next pointer forms a mid-chain cycle".to_string(),
            });
            break;
        }
        // Verify the candidate is itself readable before trusting it as an arena.
        if mem.read_u64(next.wrapping_add(next_off)).is_err() {
            problems.push(Problem::HeapWalkTruncated {
                arena: index,
                reason: "next arena malloc_state unreadable".to_string(),
            });
            break;
        }
        arenas.push(Arena {
            malloc_state_addr: next,
            index,
        });
        current = next;
        index += 1;
    }

    Ok((arenas, problems))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    const LIBC: u64 = 0x1000;

    fn with_top(mem: &mut FakeMem, layout: &DetectedLayout, arena: u64) {
        mem.set(arena + u64::from(layout.malloc_state_top_offset), 0xdead);
    }

    #[test]
    fn single_main_arena_ring() {
        let layout = test_layout(8);
        let next_off = u64::from(layout.malloc_state_next_offset);
        let mut mem = FakeMem::new();
        with_top(&mut mem, &layout, LIBC);
        mem.set(LIBC + next_off, LIBC); // main.next -> main (single arena)

        let (arenas, problems) = list(&mem, &layout, LIBC).unwrap();
        assert!(problems.is_empty());
        assert_eq!(arenas.len(), 1);
        assert!(arenas[0].is_main());
    }

    #[test]
    fn two_arenas() {
        let layout = test_layout(8);
        let next_off = u64::from(layout.malloc_state_next_offset);
        let arena2 = 0x50000;
        let mut mem = FakeMem::new();
        with_top(&mut mem, &layout, LIBC);
        mem.set(LIBC + next_off, arena2);
        mem.set(arena2 + next_off, LIBC); // ring back

        let (arenas, problems) = list(&mem, &layout, LIBC).unwrap();
        assert!(problems.is_empty());
        assert_eq!(arenas.len(), 2);
        assert_eq!(arenas[1].malloc_state_addr, arena2);
        assert!(!arenas[1].is_main());
    }

    #[test]
    fn mid_chain_cycle_is_flagged() {
        let layout = test_layout(8);
        let next_off = u64::from(layout.malloc_state_next_offset);
        let arena2 = 0x50000;
        let mut mem = FakeMem::new();
        with_top(&mut mem, &layout, LIBC);
        mem.set(LIBC + next_off, arena2);
        mem.set(arena2 + next_off, arena2); // points to itself, never back to main

        let (arenas, problems) = list(&mem, &layout, LIBC).unwrap();
        assert_eq!(arenas.len(), 2);
        assert!(matches!(
            problems.as_slice(),
            [Problem::HeapWalkTruncated { reason, .. }] if reason.contains("cycle")
        ));
    }

    #[test]
    fn unreadable_main_arena_is_hard_error() {
        let layout = test_layout(8);
        let mem = FakeMem::new(); // nothing mapped
        assert!(list(&mem, &layout, LIBC).is_err());
    }
}

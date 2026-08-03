// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Per-thread tcache traversal.
//!
//! tcache is thread-local: the `tcache_perthread_struct` is reached through the
//! thread's TLS block, and its `entries[i]` point at *user* addresses (a
//! tcache_entry's `next` is at offset 0 of the payload). Like fastbins the chain
//! is safe-linked on glibc ≥ 2.32, revealed with the storage location as key.

use std::collections::HashSet;

use crate::elf::MemReader;
use crate::error::Result;
use crate::glibc::DetectedLayout;
use crate::problem::Problem;

use super::fastbin::{fastbin_index_to_size, reveal};

const MAX_CHAIN: usize = 10_000;

pub fn tcache_index_to_size(layout: &DetectedLayout, i: u32) -> u64 {
    fastbin_index_to_size(layout, i)
}

/// Resolve a thread's `tcache_perthread_struct` address.
///
/// `Ok(0)` means the thread has no tcache yet (not an error); `Err` is a read
/// failure the caller turns into `ThreadTlsResolutionFailed`. Preconditions
/// (`tp_off_reloc_addr` present, `thread_tp != 0`) are the caller's; the
/// defensive `Ok(0)` on a missing relocation just avoids reading a bogus offset.
pub fn tcache_ptr(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
    thread_tp: u64,
) -> Result<u64> {
    read_tls_var(mem, layout, libc_addr, thread_tp, layout.tcache.value)
}

/// Resolve a thread's current `thread_arena` (a `malloc_state` address). Same
/// shape as [`tcache_ptr`], reaching a different TLS variable. Requires
/// `thread_arena` to be present (checked by the caller).
pub fn read_thread_arena(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
    thread_tp: u64,
) -> Result<u64> {
    read_tls_var(mem, layout, libc_addr, thread_tp, layout.thread_arena.value)
}

/// A TLS variable's value = `*(thread_tp + *libc_tp_offset + var_offset)`, where
/// `libc_tp_offset` is stored at the TP-offset relocation's target.
fn read_tls_var(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    libc_addr: u64,
    thread_tp: u64,
    var_offset: u64,
) -> Result<u64> {
    let Some(reloc) = layout.tp_off_reloc_addr else {
        return Ok(0);
    };
    let libc_tp_offset = mem.read_u64(libc_addr.wrapping_add(reloc))?;
    // Adding real runtime addresses/offsets read from the core; the sum was a
    // live virtual address, and the read that follows validates the mapping.
    let addr = thread_tp
        .wrapping_add(libc_tp_offset)
        .wrapping_add(var_offset);
    mem.read_u64(addr)
}

pub struct TcacheBinResult {
    pub index: u32,
    pub size: u64,
    pub user_addrs: Vec<u64>,
}

/// Walk one tcache bin from `head` (a user address). `head == 0` is empty.
pub fn walk_tcache_bin(
    mem: &impl MemReader,
    layout: &DetectedLayout,
    head: u64,
    thread_id: i32,
    bin_index: u32,
) -> (TcacheBinResult, Vec<Problem>) {
    let mut result = TcacheBinResult {
        index: bin_index,
        size: tcache_index_to_size(layout, bin_index),
        user_addrs: Vec::new(),
    };
    let mut problems = Vec::new();
    if head == 0 {
        return (result, problems);
    }

    let mut visited = HashSet::new();
    let mut cur = head;

    loop {
        if !visited.insert(cur) || visited.len() > MAX_CHAIN {
            problems.push(Problem::TcacheCycleDetected {
                thread_id,
                bin_index,
            });
            break;
        }
        result.user_addrs.push(cur);

        let stored = match mem.read_u64(cur) {
            Ok(v) => v,
            Err(_) => {
                problems.push(Problem::TcacheChunkReadFailed {
                    thread_id,
                    bin_index,
                    address: format!("{cur:#x}"),
                });
                break;
            }
        };
        // The next pointer is stored *at* the current entry, so `cur` is the key.
        let next = reveal(layout, cur, stored);
        if next == 0 {
            break;
        }
        cur = next;
    }
    (result, problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glibc::test_layout;
    use crate::heap::test_support::FakeMem;

    #[test]
    fn walks_safe_linked_entries() {
        let mut layout = test_layout(8);
        layout.capabilities.has_safe_linking = true;
        let (e0, e1, e2) = (0x1010u64, 0x2010u64, 0x3010u64);
        let mut mem = FakeMem::new();
        mem.set(e0, e1 ^ (e0 >> 12));
        mem.set(e1, e2 ^ (e1 >> 12));
        mem.set(e2, e2 >> 12); // tail: real pointer 0, safe-linked

        let (result, problems) = walk_tcache_bin(&mem, &layout, e0, 7, 0);
        assert!(problems.is_empty());
        assert_eq!(result.user_addrs, vec![e0, e1, e2]);
    }

    #[test]
    fn read_failure_is_partial() {
        let mut layout = test_layout(8);
        layout.capabilities.has_safe_linking = false;
        let (e0, e1) = (0x1010u64, 0x2010u64);
        let mut mem = FakeMem::new();
        mem.set(e0, e1); // e1 itself is not mapped
        let (result, problems) = walk_tcache_bin(&mem, &layout, e0, 7, 3);
        assert_eq!(result.user_addrs, vec![e0, e1]);
        assert!(matches!(
            problems.as_slice(),
            [Problem::TcacheChunkReadFailed {
                thread_id: 7,
                bin_index: 3,
                ..
            }]
        ));
    }

    #[test]
    fn tcache_ptr_reads_through_tls() {
        let layout = test_layout(8); // tp_off_reloc_addr Some(0), tcache.value 0
        let libc = 0x400000u64;
        let tp = 0x7f0000u64;
        let tp_offset = 0x40u64;
        let base = 0x8888u64;
        let mut mem = FakeMem::new();
        mem.set(libc, tp_offset); // *reloc = libc_tp_offset
        mem.set(tp + tp_offset, base); // *(tp + off + 0) = tcache base
        assert_eq!(tcache_ptr(&mem, &layout, libc, tp).unwrap(), base);
    }
}

// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Fold chunk events and free-list results into per-arena allocated/free totals.
//!
//! Three sources decide a chunk's fate, in this order:
//!   1. tcache — a chunk whose `PREV_INUSE` says "in use" but whose user address
//!      is in a tcache bin is actually free (glibc doesn't clear the neighbour's
//!      bit for tcache/fastbin puts).
//!   2. fastbins — counted from the chains, moved out of allocated into free by
//!      nominal bin size.
//!   3. everything the walk marked free via a cleared `PREV_INUSE`.
//!
//! Pure and I/O-free: it only produces `StatsInconsistent`, when a fastbin holds
//! more chunks of a size than were seen allocated (a truncated walk or
//! corruption). Everything else was reported upstream.

use std::collections::{BTreeMap, BTreeSet};

use crate::glibc::DetectedLayout;
use crate::problem::Problem;

use super::fastbin::FastbinBinResult;
use super::tcache::tcache_index_to_size;
use super::walk::ChunkEvent;

/// A running count/bytes total plus a size→count histogram.
#[derive(Default)]
pub struct SizeTally {
    pub count: u64,
    pub bytes: u64,
    /// Payload size → number of chunks. Bytes for a bucket are `size * count`.
    pub histogram: BTreeMap<u64, u64>,
}

impl SizeTally {
    fn add(&mut self, size: u64) {
        self.add_n(size, 1);
    }

    fn add_n(&mut self, size: u64, n: u64) {
        self.count = self.count.saturating_add(n);
        self.bytes = self.bytes.saturating_add(size.saturating_mul(n));
        let e = self.histogram.entry(size).or_default();
        *e = e.saturating_add(n);
    }

    /// Remove `n` chunks of `size`. Returns `true` if this would have gone
    /// negative (the totals are inconsistent), clamping at zero.
    fn remove_n(&mut self, size: u64, n: u64) -> bool {
        let bucket = self.histogram.entry(size).or_default();
        let underflow = self.count < n || *bucket < n;
        self.count = self.count.saturating_sub(n);
        self.bytes = self.bytes.saturating_sub(size.saturating_mul(n));
        *bucket = bucket.saturating_sub(n);
        underflow
    }
}

pub struct BinTally {
    pub index: u32,
    pub size: u64,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Default)]
pub struct FreeStats {
    pub tally: SizeTally,
    pub fastbins: Vec<BinTally>,
    pub tcache_threads: BTreeSet<i32>,
    pub tcache_bins: Vec<BinTally>,
}

pub struct ArenaStats {
    pub allocated: SizeTally,
    pub free: FreeStats,
    pub overhead_count: u64,
    pub overhead_bytes: u64,
}

/// `tcache_membership` maps a user address to the `(thread_id, bin_index)` that
/// owns it, built globally before the arena loop.
pub fn accumulate(
    layout: &DetectedLayout,
    arena_index: u32,
    events: &[ChunkEvent],
    tcache_membership: &std::collections::HashMap<u64, (i32, u32)>,
    fastbin_results: &[FastbinBinResult],
) -> (ArenaStats, Vec<Problem>) {
    let header_size = u64::from(layout.header_size);
    let mut allocated = SizeTally::default();
    let mut free = SizeTally::default();
    let mut tcache_threads = BTreeSet::new();
    // bin index → chunk count; the bucket size/bytes use the bin's nominal size.
    let mut tcache_counts: BTreeMap<u32, u64> = BTreeMap::new();
    let mut problems = Vec::new();

    for ev in events {
        if ev.prev_inuse_says_in_use {
            if let Some(&(thread_id, bin_index)) = tcache_membership.get(&ev.user_addr) {
                // Source 1: parked in a tcache bin, so really free.
                free.add(ev.user_size);
                tcache_threads.insert(thread_id);
                let count = tcache_counts.entry(bin_index).or_default();
                *count = count.saturating_add(1);
            } else {
                allocated.add(ev.user_size);
            }
        } else {
            // Source 3: walk already saw this as free.
            free.add(ev.user_size);
        }
    }

    // Source 2: move fastbin chunks from allocated to free by nominal size.
    let mut fastbins = Vec::new();
    for fb in fastbin_results {
        if fb.count == 0 {
            continue;
        }
        if allocated.remove_n(fb.size, fb.count) {
            problems.push(Problem::StatsInconsistent {
                arena: arena_index,
                size: fb.size,
                reason: "fastbin count exceeds allocated count for this size".to_string(),
            });
        }
        free.add_n(fb.size, fb.count);
        fastbins.push(BinTally {
            index: fb.index,
            size: fb.size,
            count: fb.count,
            bytes: fb.size.saturating_mul(fb.count),
        });
    }

    // Bucket size/bytes use the bin's nominal size (matching the reference
    // tool's per-bin display); on a healthy heap this equals the chunks' actual
    // size, but it avoids drift when a wrong-sized chunk is parked in a bin.
    let tcache_bins = tcache_counts
        .into_iter()
        .map(|(index, count)| {
            let size = tcache_index_to_size(layout, index);
            BinTally {
                index,
                size,
                count,
                bytes: size.saturating_mul(count),
            }
        })
        .collect();

    // Every walked chunk carries one header word of overhead.
    let overhead_count = events.len() as u64;
    let overhead_bytes = overhead_count.saturating_mul(header_size);

    let stats = ArenaStats {
        allocated,
        free: FreeStats {
            tally: free,
            fastbins,
            tcache_threads,
            tcache_bins,
        },
        overhead_count,
        overhead_bytes,
    };
    (stats, problems)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::glibc::test_layout;

    fn event(user_addr: u64, user_size: u64, in_use: bool) -> ChunkEvent {
        ChunkEvent {
            size_field_addr: user_addr - 8,
            user_addr,
            user_size,
            full_size: user_size + 8,
            prev_inuse_says_in_use: in_use,
        }
    }

    #[test]
    fn splits_allocated_free_tcache_fastbin() {
        // Four walked chunks: two in use (one of them tcached), two free.
        let events = [
            event(0x100, 24, true),  // allocated
            event(0x200, 24, true),  // in tcache -> free
            event(0x300, 40, false), // free (source 3)
            event(0x400, 24, true),  // allocated, but a fastbin will claim it
        ];
        let mut membership = HashMap::new();
        membership.insert(0x200u64, (7i32, 0u32));
        // One fastbin bin, size 24, holding 1 chunk.
        let fastbins = [FastbinBinResult {
            index: 0,
            size: 24,
            count: 1,
        }];

        let layout = test_layout(8);
        let (stats, problems) = accumulate(&layout, 0, &events, &membership, &fastbins);
        assert!(problems.is_empty(), "{problems:?}");
        // allocated: started with 0x100 and 0x400 (24 each) = 2, minus 1 fastbin = 1.
        assert_eq!(stats.allocated.count, 1);
        assert_eq!(stats.allocated.bytes, 24);
        // free: tcache(1) + source3(1) + fastbin(1) = 3.
        assert_eq!(stats.free.tally.count, 3);
        assert_eq!(
            stats
                .free
                .tcache_threads
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![7]
        );
        assert_eq!(stats.free.tcache_bins.len(), 1);
        assert_eq!(stats.free.tcache_bins[0].count, 1);
        assert_eq!(stats.free.fastbins[0].count, 1);
        // overhead: 4 chunks * 8.
        assert_eq!(stats.overhead_count, 4);
        assert_eq!(stats.overhead_bytes, 32);
    }

    #[test]
    fn fastbin_exceeding_allocated_flags_inconsistency() {
        let events = [event(0x100, 24, false)]; // one free chunk, none allocated at size 24
        let membership = HashMap::new();
        let fastbins = [FastbinBinResult {
            index: 0,
            size: 24,
            count: 2,
        }];
        let layout = test_layout(8);
        let (stats, problems) = accumulate(&layout, 1, &events, &membership, &fastbins);
        assert_eq!(stats.allocated.count, 0); // clamped, not underflowed
        assert!(matches!(
            problems.as_slice(),
            [Problem::StatsInconsistent {
                arena: 1,
                size: 24,
                ..
            }]
        ));
    }
}

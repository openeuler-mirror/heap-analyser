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
//!   2. fastbins — a walked chunk whose address is in its size's fastbin is free.
//!   3. everything the walk marked free via a cleared `PREV_INUSE`.
//!
//! A partial heap walk only accounts for the chunks it reached.

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
        self.count = self.count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
        let e = self.histogram.entry(size).or_default();
        *e = e.saturating_add(1);
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
    walk_complete: bool,
) -> (ArenaStats, Vec<Problem>) {
    let header_size = u64::from(layout.header_size);
    let mut allocated = SizeTally::default();
    let mut free = SizeTally::default();
    let mut tcache_threads = BTreeSet::new();
    // bin index → chunk count; the bucket size/bytes use the bin's nominal size.
    let mut tcache_counts: BTreeMap<u32, u64> = BTreeMap::new();
    let mut fastbin_counts: BTreeMap<_, _> = fastbin_results
        .iter()
        .filter(|fb| fb.count != 0)
        .map(|fb| (fb.size, (fb, 0u64)))
        .collect();
    let mut problems = Vec::new();

    for ev in events {
        if ev.prev_inuse_says_in_use {
            if let Some(&(thread_id, bin_index)) = tcache_membership.get(&ev.user_addr) {
                // Source 1: parked in a tcache bin, so really free.
                free.add(ev.user_size);
                tcache_threads.insert(thread_id);
                let count = tcache_counts.entry(bin_index).or_default();
                *count = count.saturating_add(1);
                continue;
            }
            if let Some((fb, count)) = fastbin_counts.get_mut(&ev.user_size) {
                if ev
                    .size_field_addr
                    .checked_sub(u64::from(layout.word_size))
                    .is_some_and(|addr| fb.chunk_addrs.contains(&addr))
                {
                    free.add(ev.user_size);
                    *count += 1;
                    continue;
                }
            }
            allocated.add(ev.user_size);
        } else {
            // Source 3: walk already saw this as free.
            free.add(ev.user_size);
        }
    }

    let mut fastbins = Vec::new();
    for (fb, count) in fastbin_counts.into_values() {
        if walk_complete && count != fb.count {
            problems.push(Problem::StatsInconsistent {
                arena: arena_index,
                size: fb.size,
                reason: "fastbin nodes did not match walked chunks of this size".to_string(),
            });
        }
        if count == 0 {
            continue;
        }
        fastbins.push(BinTally {
            index: fb.index,
            size: fb.size,
            count,
            bytes: fb.size.saturating_mul(count),
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
            chunk_addrs: [0x3f0].into(),
        }];

        let layout = test_layout(8);
        let (stats, problems) = accumulate(&layout, 0, &events, &membership, &fastbins, true);
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
    fn unmatched_fastbin_on_complete_walk_flags_inconsistency() {
        let events = [event(0x100, 24, false)]; // one free chunk, none allocated at size 24
        let membership = HashMap::new();
        let fastbins = [FastbinBinResult {
            index: 0,
            size: 24,
            count: 2,
            chunk_addrs: [0xf0, 0x1f0].into(),
        }];
        let layout = test_layout(8);
        let (stats, problems) = accumulate(&layout, 1, &events, &membership, &fastbins, true);
        assert_eq!(stats.allocated.count, 0);
        assert_eq!(stats.free.tally.count, 1);
        assert!(stats.free.fastbins.is_empty());
        assert!(matches!(
            problems.as_slice(),
            [Problem::StatsInconsistent {
                arena: 1,
                size: 24,
                ..
            }]
        ));
    }

    #[test]
    fn partial_walk_counts_only_fastbin_members_in_the_walked_region() {
        // The unwalked member has the same size as both small walked chunks.
        let events = [
            event(0x100, 24, true),
            event(0x200, 24, true),
            event(0x300, 40, true),
        ];
        let fb = FastbinBinResult {
            index: 0,
            size: 24,
            count: 2,
            chunk_addrs: [0x1f0, 0x3f0].into(),
        };
        let (stats, problems) =
            accumulate(&test_layout(8), 0, &events, &HashMap::new(), &[fb], false);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!((stats.allocated.count, stats.allocated.bytes), (2, 64));
        assert_eq!(stats.allocated.histogram, [(24, 1), (40, 1)].into());
        assert_eq!((stats.free.tally.count, stats.free.tally.bytes), (1, 24));
        assert_eq!(stats.free.tally.histogram, [(24, 1)].into());
        assert_eq!(stats.free.fastbins[0].count, 1);
        assert_eq!(
            stats.allocated.count + stats.free.tally.count,
            stats.overhead_count
        );
    }
}

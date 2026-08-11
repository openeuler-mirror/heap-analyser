// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Recoverable diagnostics.
//!
//! A [`Problem`] is something that went wrong *within* an otherwise usable
//! analysis: a corrupted chunk, a fastbin that loops back on itself, a thread
//! whose TLS could not be resolved. These never abort the run — they are
//! collected into the report's `problems` array so the output still carries
//! whatever could be recovered. Hard failures (can't open the core, can't find
//! libc) are [`crate::error::Error`] instead.

use serde::Serialize;

/// One recoverable issue encountered during analysis.
///
/// Serialised with an internal `kind` tag, e.g.
/// `{"kind": "missing_symbol", "symbol": "main_arena"}`. The tag values are a
/// public part of the JSON schema (see the `problems` section of the README).
/// Existing kinds stay stable; consumers must ignore kinds added later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Problem {
    /// A required glibc symbol (`main_arena` / `mp_`) was not found.
    MissingSymbol { symbol: String },
    /// A wanted symbol was defined more than once with differing values; the
    /// first definition was used. Not fatal, but the reference libc is odd.
    DuplicateSymbol { symbol: String },
    /// The TP-offset relocation needed to reach TLS variables is absent, so
    /// tcache / thread_arena data cannot be read. Produced once, in
    /// `glibc::DetectedLayout::detect`.
    MissingRelocation,
    /// `e_machine` is not one of the architectures we implement.
    UnsupportedArch { machine: u16 },
    /// The reference libc has no GNU build-id note, so identity fell back to a
    /// content hash.
    MissingBuildId,
    /// glibc version detection failed; safe-linking was assumed on by default.
    UnknownGlibcVersion,
    /// DWARF was present, but its malloc layout was unusable. The built-in
    /// layout was kept.
    DwarfLayoutFallback { reason: String },

    /// A fastbin chain looped or exceeded the traversal cap.
    FastbinCycleDetected { arena: u32, bin_index: u32 },
    /// Reading a fastbin head or a chain node failed; the bin count is partial.
    /// The `address` disambiguates the head-slot case from a mid-chain node.
    FastbinChunkReadFailed {
        arena: u32,
        bin_index: u32,
        address: String,
    },

    /// A tcache chain looped or exceeded the traversal cap. Carries `thread_id`,
    /// not `arena`: tcache is thread-local and does not belong to any arena.
    TcacheCycleDetected { thread_id: i32, bin_index: u32 },
    /// Reading a tcache head or a chain node failed; the bin is partial.
    TcacheChunkReadFailed {
        thread_id: i32,
        bin_index: u32,
        address: String,
    },
    /// The same chunk was found in two tcache bins / threads, which indicates a
    /// double-free. The first owner is kept; this records the collision.
    DuplicateTcacheEntry {
        thread_id: i32,
        bin_index: u32,
        address: String,
    },

    /// A chunk address was not backed by file content in any loaded segment.
    ChunkReadFailed { arena: u32, address: String },
    /// A heap / list walk stopped early because of corruption, an out-of-region
    /// address, or a traversal cap. The result is partial.
    HeapWalkTruncated { arena: u32, reason: String },
    /// During accumulation a size bucket's fastbin count exceeded its allocated
    /// count — the books don't balance, usually a symptom of a truncated walk.
    StatsInconsistent {
        arena: u32,
        size: u64,
        reason: String,
    },
    /// A thread's TLS could not be resolved, so its tcache / arena binding is
    /// missing.
    ThreadTlsResolutionFailed { thread_id: i32 },
}

impl Problem {
    /// Whether this problem makes the whole analysis untrustworthy.
    ///
    /// Only missing required symbols and an unsupported architecture qualify:
    /// without `main_arena`/`mp_` there is nothing to walk, and without a known
    /// arch we can't parse threads at all. Everything else degrades gracefully
    /// (partial data + this diagnostic), so it must not flip `supported` to
    /// false. Revisit this list when adding architectures or glibc variants.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Problem::MissingSymbol { .. } | Problem::UnsupportedArch { .. }
        )
    }
}

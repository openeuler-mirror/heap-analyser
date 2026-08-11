// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! The `report` command's output model — the public JSON schema.
//!
//! Field names are the schema, so they're plain snake_case and deliberately
//! stable. The structs are built from `heap::stats` / `heap::heap_list` via the
//! constructors here, so `analyze` stays thin.

use serde::Serialize;

use crate::glibc::{DetectedLayout, VersionSource};
use crate::heap::heap_list::Heap;
use crate::heap::stats::{ArenaStats, BinTally, FreeStats, SizeTally};
use crate::locate::{Identity, LocatedLibc};
use crate::problem::Problem;

/// Bump when the schema changes in a breaking way.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool_version: String,
    pub core_path: String,
    pub libc: LibcInfo,
    pub glibc_capabilities: GlibcCapabilitiesJson,
    pub problems: Vec<Problem>,
    pub arenas: Vec<ArenaReport>,
}

#[derive(Serialize)]
pub struct LibcInfo {
    pub path: String,
    pub identity: IdentityJson,
    /// `true` when the mapping was verified against the reference identity;
    /// `false` when `--force-libc` bypassed the check.
    pub verified: bool,
}

impl LibcInfo {
    pub fn new(located: &LocatedLibc, identity: Identity) -> Self {
        LibcInfo {
            path: located.path.clone(),
            identity: identity.into(),
            verified: located.verified,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityJson {
    BuildId { value: String },
    ContentHash { value: String },
}

impl From<Identity> for IdentityJson {
    fn from(id: Identity) -> Self {
        match id {
            Identity::BuildId(bytes) => IdentityJson::BuildId {
                value: to_hex(&bytes),
            },
            Identity::ContentHash(hash) => IdentityJson::ContentHash {
                value: to_hex(&hash),
            },
        }
    }
}

#[derive(Serialize)]
pub struct GlibcCapabilitiesJson {
    /// `"dwarf"` when all required malloc offsets came from one validated
    /// DWARF layout; otherwise `"builtin"`.
    pub layout_source: String,
    pub has_tcache: bool,
    pub has_safe_linking: bool,
    /// `"gnu_version_d"` or `"assumed_default"` — a stable string, never a
    /// `Debug` rendering.
    pub version_source: String,
}

impl GlibcCapabilitiesJson {
    pub fn from_layout(layout: &DetectedLayout) -> Self {
        let caps = &layout.capabilities;
        GlibcCapabilitiesJson {
            layout_source: layout.layout_source.as_str().to_string(),
            has_tcache: caps.has_tcache,
            has_safe_linking: caps.has_safe_linking,
            version_source: caps.version_source.as_str().to_string(),
        }
    }

    /// The source string on its own, for `check`.
    pub fn version_source_str(source: VersionSource) -> String {
        source.as_str().to_string()
    }
}

#[derive(Serialize)]
pub struct ArenaReport {
    pub index: u32,
    pub is_main: bool,
    pub attached_threads: Vec<i32>,
    pub heaps: HeapsSummary,
    pub allocated: AllocatedSummary,
    pub free: FreeSummary,
    pub overhead: OverheadSummary,
}

impl ArenaReport {
    pub fn build(
        index: u32,
        is_main: bool,
        attached_threads: Vec<i32>,
        heaps: &[Heap],
        stats: &ArenaStats,
    ) -> Self {
        ArenaReport {
            index,
            is_main,
            attached_threads,
            heaps: HeapsSummary::from_heaps(heaps),
            allocated: AllocatedSummary::from_tally(&stats.allocated),
            free: FreeSummary::from_free_stats(&stats.free),
            overhead: OverheadSummary {
                count: stats.overhead_count,
                bytes: stats.overhead_bytes,
            },
        }
    }

    /// A placeholder entry for an arena that couldn't be walked, so
    /// `problems[].arena` still resolves to something in `arenas[]`.
    pub fn stub(index: u32, is_main: bool, attached_threads: Vec<i32>) -> Self {
        ArenaReport {
            index,
            is_main,
            attached_threads,
            heaps: HeapsSummary {
                count: 0,
                total_bytes: 0,
                committed_bytes: 0,
            },
            allocated: AllocatedSummary {
                count: 0,
                bytes: 0,
                size_histogram: Vec::new(),
            },
            free: FreeSummary {
                count: 0,
                bytes: 0,
                fastbins: Vec::new(),
                tcache: TcacheSummary {
                    tcache_threads: Vec::new(),
                    bins: Vec::new(),
                },
                size_histogram: Vec::new(),
            },
            overhead: OverheadSummary { count: 0, bytes: 0 },
        }
    }
}

#[derive(Serialize)]
pub struct HeapsSummary {
    pub count: u64,
    pub total_bytes: u64,
    pub committed_bytes: u64,
}

impl HeapsSummary {
    fn from_heaps(heaps: &[Heap]) -> Self {
        let mut total = 0u64;
        let mut committed = 0u64;
        for h in heaps {
            total = total.saturating_add(h.size);
            committed = committed.saturating_add(h.mprotect_size);
        }
        HeapsSummary {
            count: heaps.len() as u64,
            total_bytes: total,
            committed_bytes: committed,
        }
    }
}

#[derive(Serialize)]
pub struct SizeBucket {
    pub size: u64,
    pub count: u64,
    pub bytes: u64,
}

/// Turn a size→count histogram into ascending buckets (`BTreeMap` is ordered).
fn buckets(histogram: &std::collections::BTreeMap<u64, u64>) -> Vec<SizeBucket> {
    histogram
        .iter()
        .filter(|(_, &count)| count > 0)
        .map(|(&size, &count)| SizeBucket {
            size,
            count,
            bytes: size.saturating_mul(count),
        })
        .collect()
}

#[derive(Serialize)]
pub struct AllocatedSummary {
    pub count: u64,
    pub bytes: u64,
    pub size_histogram: Vec<SizeBucket>,
}

impl AllocatedSummary {
    fn from_tally(t: &SizeTally) -> Self {
        AllocatedSummary {
            count: t.count,
            bytes: t.bytes,
            size_histogram: buckets(&t.histogram),
        }
    }
}

#[derive(Serialize)]
pub struct BinBucket {
    pub index: u32,
    pub size: u64,
    pub count: u64,
    pub bytes: u64,
}

impl BinBucket {
    fn from_tally(b: &BinTally) -> Self {
        BinBucket {
            index: b.index,
            size: b.size,
            count: b.count,
            bytes: b.bytes,
        }
    }
}

/// Always this shape, even without tcache (empty arrays) — consumers never have
/// to check whether the key exists, only whether the arrays are empty.
#[derive(Serialize)]
pub struct TcacheSummary {
    pub tcache_threads: Vec<i32>,
    pub bins: Vec<BinBucket>,
}

#[derive(Serialize)]
pub struct FreeSummary {
    pub count: u64,
    pub bytes: u64,
    pub fastbins: Vec<BinBucket>,
    pub tcache: TcacheSummary,
    pub size_histogram: Vec<SizeBucket>,
}

impl FreeSummary {
    fn from_free_stats(f: &FreeStats) -> Self {
        FreeSummary {
            count: f.tally.count,
            bytes: f.tally.bytes,
            fastbins: f.fastbins.iter().map(BinBucket::from_tally).collect(),
            tcache: TcacheSummary {
                tcache_threads: f.tcache_threads.iter().copied().collect(),
                bins: f.tcache_bins.iter().map(BinBucket::from_tally).collect(),
            },
            size_histogram: buckets(&f.tally.histogram),
        }
    }
}

#[derive(Serialize)]
pub struct OverheadSummary {
    pub count: u64,
    pub bytes: u64,
}

/// Lowercase, unseparated hex — the build-id convention (`1b2c3d…`).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_unseparated() {
        assert_eq!(to_hex(&[0x1b, 0x2c, 0xff, 0x00]), "1b2cff00");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn identity_serializes_with_kind_tag() {
        let json = serde_json::to_string(&IdentityJson::from(Identity::BuildId(vec![0xab, 0xcd])))
            .unwrap();
        assert_eq!(json, r#"{"kind":"build_id","value":"abcd"}"#);
    }
}

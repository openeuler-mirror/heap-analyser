// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `struct tcache_perthread_struct` layout.
//!
//! ```c
//! typedef struct tcache_perthread_struct {
//!     uint16_t counts[TCACHE_MAX_BINS];
//!     tcache_entry *entries[TCACHE_MAX_BINS];
//! } tcache_perthread_struct;
//! ```

/// `TCACHE_MAX_BINS` — the length of the `entries[]` array. This is the number
/// of bins we iterate. glibc's runtime `mp_.tcache_bins` may be smaller, but
/// unused bins have a null `entries[]` slot and are skipped as empty, so walking
/// the full array gives the same result without an extra read.
pub(crate) const TCACHE_MAX_BINS: u32 = 64;

pub(crate) struct TcacheOffsets {
    /// Offset of `entries[]`, i.e. `sizeof(counts)` = `TCACHE_MAX_BINS * 2`.
    pub entries: u32,
    pub max_bins: u32,
}

impl TcacheOffsets {
    pub fn new() -> Self {
        TcacheOffsets {
            entries: TCACHE_MAX_BINS * 2,
            max_bins: TCACHE_MAX_BINS,
        }
    }
}

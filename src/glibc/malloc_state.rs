// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `struct malloc_state` field offsets.
//!
//! These assume the glibc ≥ 2.27 layout (`malloc/malloc.c`), where
//! `have_fastchunks` sits between `flags` and `fastbinsY`. On 64-bit that puts
//! `fastbinsY` at 16, `top` right after the 10-entry fastbin array at 96, and
//! `next` after `bins[254]` + `binmap[4]` at 2160.

pub(crate) struct MallocStateOffsets {
    pub top: u32,
    pub next: u32,
    pub fastbin_array: u32,
    pub fastbin_count: u32,
}

impl MallocStateOffsets {
    pub fn new(word_size: u32) -> Self {
        if word_size == 8 {
            MallocStateOffsets {
                top: 96,
                next: 2160,
                fastbin_array: 16,
                fastbin_count: 10,
            }
        } else {
            MallocStateOffsets {
                top: 56,
                next: 1096,
                fastbin_array: 12,
                fastbin_count: 11,
            }
        }
    }
}

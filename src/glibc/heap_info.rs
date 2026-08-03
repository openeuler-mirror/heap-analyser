// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `struct _heap_info` layout — the per-heap header of a non-main arena.
//!
//! ```c
//! typedef struct _heap_info {
//!     mstate ar_ptr;               // 0
//!     struct _heap_info *prev;     // 1 word
//!     size_t size;                 // 2 words
//!     size_t mprotect_size;        // 3 words
//!     // padding to MALLOC_ALIGNMENT; +1 word when THP support is compiled in
//! } heap_info;
//! ```

pub(crate) struct HeapInfoOffsets {
    pub ar_ptr: u32,
    pub prev: u32,
    pub size: u32,
    pub mprotect_size: u32,
    /// `sizeof(_heap_info)` after alignment padding — the first chunk of a heap
    /// starts this many bytes in.
    pub sizeof: u32,
    /// Alignment/size a secondary heap is reserved and masked to.
    pub heap_max_size: u64,
}

impl HeapInfoOffsets {
    pub fn new(word_size: u32, has_hugepage: bool) -> Self {
        let w = word_size;
        let malloc_alignment = if w == 8 { 16 } else { 8 };
        // THP builds carry one extra field before the tail padding.
        let base = if has_hugepage { 5 * w } else { 4 * w };
        HeapInfoOffsets {
            ar_ptr: 0,
            prev: w,
            size: 2 * w,
            mprotect_size: 3 * w,
            sizeof: align_up(base, malloc_alignment),
            heap_max_size: if w == 8 { 64u64 << 20 } else { 1u64 << 20 },
        }
    }
}

fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        value
    } else {
        (value + (align - 1)) & !(align - 1)
    }
}

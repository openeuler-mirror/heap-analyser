// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chunk header bits.
//!
//! A glibc chunk's size field packs three flags into its low bits; the size
//! itself is always a multiple of `2 * word` so those bits are free.

pub const PREV_INUSE: u64 = 1;
pub const IS_MMAPPED: u64 = 2;
pub const NON_MAIN_ARENA: u64 = 4;

const SIZE_MASK: u64 = !0x7;

/// The chunk size with the three flag bits masked off.
pub fn chunk_size(raw_size_field: u64) -> u64 {
    raw_size_field & SIZE_MASK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_flag_bits() {
        assert_eq!(chunk_size(0x21), 0x20);
        assert_eq!(chunk_size(0x20 | PREV_INUSE | NON_MAIN_ARENA), 0x20);
        assert_eq!(chunk_size(0), 0);
    }
}

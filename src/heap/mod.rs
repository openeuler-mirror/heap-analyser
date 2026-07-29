// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Heap traversal: arenas, heaps, chunks, and the free-list walkers that feed
//! the allocated/free statistics.

pub mod arena;
pub mod chunk;
pub mod fastbin;
pub mod heap_list;
pub mod stats;
pub mod tcache;
pub mod walk;

#[cfg(test)]
pub(crate) mod test_support {
    //! Synthetic memory for exercising the traversals without a real core.
    use std::collections::HashMap;

    use crate::elf::MemReader;
    use crate::error::{Error, Result};

    #[derive(Default)]
    pub(crate) struct FakeMem {
        words: HashMap<u64, u64>,
        segments: Vec<(u64, u64)>,
    }

    impl FakeMem {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Place a word at `addr`. Returns `&mut self` for chaining.
        pub(crate) fn set(&mut self, addr: u64, val: u64) -> &mut Self {
            self.words.insert(addr, val);
            self
        }

        /// Register a `[start, end)` mapped segment for `segment_start`.
        pub(crate) fn add_segment(&mut self, start: u64, end: u64) -> &mut Self {
            self.segments.push((start, end));
            self
        }
    }

    impl MemReader for FakeMem {
        fn read_u64(&self, addr: u64) -> Result<u64> {
            self.words
                .get(&addr)
                .copied()
                .ok_or(Error::AddressNotMapped { addr })
        }

        fn segment_start(&self, addr: u64) -> Option<u64> {
            self.segments
                .iter()
                .find(|(s, e)| addr >= *s && addr < *e)
                .map(|(s, _)| *s)
        }
    }
}

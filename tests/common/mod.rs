// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

#![allow(dead_code)]
//! Shared helpers for the integration tests.

use std::process::{Command, Output};

/// The freshly-built `heap-analyser` binary.
pub fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_heap-analyser"))
}

pub fn run(args: &[&str]) -> Output {
    bin()
        .args(args)
        .output()
        .expect("failed to run heap-analyser")
}

/// Path to a valid x86-64 ELF that is *not* a libc — the test binary itself.
/// Handy for exercising the "no glibc symbols" path portably.
pub fn non_libc_elf() -> &'static str {
    env!("CARGO_BIN_EXE_heap-analyser")
}

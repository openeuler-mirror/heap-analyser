// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

mod common;

use common::{non_libc_elf, run};

/// `check` on a valid ELF that isn't a libc: it parses, detects the arch, finds
/// no glibc symbols, and says so with valid JSON and a non-zero exit — without
/// needing any fixture.
#[test]
fn check_on_non_libc_elf_reports_unsupported() {
    let out = run(&["check", "--libc", non_libc_elf()]);
    assert_eq!(out.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["supported"], false);
    assert_eq!(json["symbols"]["main_arena"]["present"], false);

    let problems = json["problems"].as_array().expect("problems array");
    assert!(
        problems
            .iter()
            .any(|p| p["kind"] == "missing_symbol" && p["symbol"] == "main_arena"),
        "expected a missing_symbol problem for main_arena, got {problems:?}"
    );
}

#[test]
fn check_on_missing_file_fails_hard() {
    let out = run(&["check", "--libc", "/no/such/libc.so.6"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "no JSON on a hard failure");
    assert!(!out.stderr.is_empty());
}

#[test]
fn check_on_non_elf_fails_hard() {
    // A source file is not an ELF.
    let out = run(&["check", "--libc", file!()]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

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

use common::run;

/// A hard failure must print to stderr only and leave stdout empty — never a
/// half-written JSON document.
#[test]
fn report_on_missing_core_fails_cleanly() {
    let out = run(&["report", "/no/such/core", "--libc", "/no/such/libc"]);
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "stdout must be empty on hard failure"
    );
    assert!(!out.stderr.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("error:"));
}

#[test]
fn report_requires_a_coredump_argument() {
    let out = run(&["report"]);
    assert!(!out.status.success());
}

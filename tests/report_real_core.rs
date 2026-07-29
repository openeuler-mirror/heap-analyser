// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Opt-in end-to-end check against a real core dump.
//!
//! Committing a core + matching libc as fixtures isn't portable (they're large
//! and glibc-version specific), so this is `#[ignore]`d by default (visible as
//! "ignored" in the test output) and reads their paths from the environment:
//!
//! ```sh
//! HEAP_ANALYSER_TEST_CORE=./core.1234 \
//! HEAP_ANALYSER_TEST_LIBC=./libc.so.6.full \
//! cargo test --test report_real_core -- --include-ignored
//! ```

mod common;

use common::run;

#[test]
#[ignore = "needs HEAP_ANALYSER_TEST_CORE and HEAP_ANALYSER_TEST_LIBC fixtures"]
fn report_on_real_core_has_valid_schema() {
    let (Ok(core), Ok(libc)) = (
        std::env::var("HEAP_ANALYSER_TEST_CORE"),
        std::env::var("HEAP_ANALYSER_TEST_LIBC"),
    ) else {
        panic!("set HEAP_ANALYSER_TEST_CORE and HEAP_ANALYSER_TEST_LIBC to run this test");
    };

    let out = run(&["report", &core, "--libc", &libc]);
    assert!(
        out.status.success(),
        "report failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON");
    assert_eq!(json["schema_version"], 1);

    let arenas = json["arenas"].as_array().expect("arenas array");
    assert!(!arenas.is_empty(), "expected at least the main arena");
    let main = &arenas[0];
    assert_eq!(main["is_main"], true);

    // Totals must be self-consistent: overhead counts every walked chunk.
    let alloc = main["allocated"]["count"].as_u64().unwrap();
    let free = main["free"]["count"].as_u64().unwrap();
    let overhead = main["overhead"]["count"].as_u64().unwrap();
    assert_eq!(
        alloc + free,
        overhead,
        "overhead should equal allocated + free"
    );

    // free.tcache is always present with both arrays, even when empty.
    assert!(main["free"]["tcache"]["tcache_threads"].is_array());
    assert!(main["free"]["tcache"]["bins"].is_array());
}

/// Same fixtures, but drives the library in-process so the orchestration and
/// report-model code is exercised directly (the subprocess test above can't
/// contribute to in-process coverage).
#[test]
#[ignore = "needs HEAP_ANALYSER_TEST_CORE and HEAP_ANALYSER_TEST_LIBC fixtures"]
fn analyze_core_in_process_is_self_consistent() {
    let (Ok(core), Ok(libc)) = (
        std::env::var("HEAP_ANALYSER_TEST_CORE"),
        std::env::var("HEAP_ANALYSER_TEST_LIBC"),
    ) else {
        panic!("set HEAP_ANALYSER_TEST_CORE and HEAP_ANALYSER_TEST_LIBC to run this test");
    };

    let report = heap_analyser::analyze::analyze_core(
        std::path::Path::new(&core),
        Some(std::path::Path::new(&libc)),
        None,
    )
    .expect("analyze_core should succeed on a clean core");

    assert_eq!(report.schema_version, 1);
    let main = &report.arenas[0];
    assert!(main.is_main);
    assert_eq!(
        main.allocated.count + main.free.count,
        main.overhead.count,
        "overhead should equal allocated + free"
    );
}

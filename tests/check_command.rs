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

use common::{minimal_elf, non_libc_elf, run, ElfFixture};

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

fn check_elf_pair(runtime: &[u8], debug: &[u8]) -> std::process::Output {
    let fixture = ElfFixture::new();
    let runtime = fixture.write("libc.so.6", runtime);
    let debug = fixture.write("libc.so.6.debug", debug);
    run(&["check", "--libc", &runtime, "--libc-debug", &debug])
}

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
    assert_eq!(json["glibc_capabilities"]["layout_source"], "builtin");
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
fn matching_debug_file_is_accepted_and_reports_layout_fallback() {
    let elf = non_libc_elf();
    let out = run(&["check", "--libc", elf, "--libc-debug", elf]);
    assert_eq!(out.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON");
    assert_eq!(json["glibc_capabilities"]["layout_source"], "builtin");
    assert!(json["problems"]
        .as_array()
        .expect("problems array")
        .iter()
        .any(|problem| problem["kind"] == "dwarf_layout_fallback"));
}

#[test]
fn mismatched_debug_file_fails_before_json_output() {
    let debug = std::env::current_exe().expect("current test executable");
    let debug = debug.to_str().expect("UTF-8 test executable path");
    let out = run(&["check", "--libc", non_libc_elf(), "--libc-debug", debug]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("debuginfo build-id does not match the runtime libc"));
}

#[test]
fn matching_section_build_ids_are_accepted() {
    let build_id = b"matching build id";
    let runtime = minimal_elf(EM_X86_64, Some(build_id), &[]);
    let debug = minimal_elf(EM_X86_64, Some(build_id), &[]);
    let out = check_elf_pair(&runtime, &debug);

    // Pairing succeeded; the minimal ELF is not a libc, so `check` then emits
    // its normal unsupported report with status 1.
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("stdout should be valid JSON");
}

#[test]
fn mismatched_build_ids_are_rejected_even_when_debuglink_matches() {
    let debug = minimal_elf(EM_X86_64, Some(b"debug build id"), &[]);
    let runtime = minimal_elf(
        EM_X86_64,
        Some(b"runtime build id"),
        &[crc32fast::hash(&debug)],
    );
    let out = check_elf_pair(&runtime, &debug);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("debuginfo build-id does not match the runtime libc"));
}

#[test]
fn matching_debuglink_crc_is_accepted_without_shared_build_id() {
    let debug = minimal_elf(EM_X86_64, None, &[]);
    let runtime = minimal_elf(
        EM_X86_64,
        Some(b"runtime build id"),
        &[crc32fast::hash(&debug)],
    );
    let out = check_elf_pair(&runtime, &debug);

    // Pairing succeeded; the minimal ELF is not a libc, so `check` then emits
    // its normal unsupported report with status 1.
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty());
    serde_json::from_slice::<serde_json::Value>(&out.stdout).expect("stdout should be valid JSON");
}

#[test]
fn mismatched_debuglink_crc_is_rejected() {
    let debug = minimal_elf(EM_X86_64, None, &[]);
    let runtime = minimal_elf(EM_X86_64, None, &[crc32fast::hash(&debug) ^ 1]);
    let out = check_elf_pair(&runtime, &debug);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("debuginfo .gnu_debuglink CRC does not match the runtime libc"));
}

#[test]
fn missing_build_id_and_debuglink_are_rejected() {
    let runtime = minimal_elf(EM_X86_64, None, &[]);
    let debug = minimal_elf(EM_X86_64, None, &[]);
    let out = check_elf_pair(&runtime, &debug);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no matching build-id or .gnu_debuglink CRC")
    );
}

#[test]
fn duplicate_debuglink_sections_are_rejected() {
    let debug = minimal_elf(EM_X86_64, None, &[]);
    let crc = crc32fast::hash(&debug);
    let runtime = minimal_elf(EM_X86_64, None, &[crc, crc]);
    let out = check_elf_pair(&runtime, &debug);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("runtime libc has duplicate .gnu_debuglink sections"));
}

#[test]
fn mismatched_debug_machine_is_rejected() {
    let build_id = b"matching build id";
    let runtime = minimal_elf(EM_X86_64, Some(build_id), &[]);
    let debug = minimal_elf(EM_AARCH64, Some(build_id), &[]);
    let out = check_elf_pair(&runtime, &debug);

    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr)
        .contains("debuginfo ABI does not match the runtime libc"));
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

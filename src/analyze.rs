// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! The orchestration layer.
//!
//! [`analyze_core`] ties the whole pipeline together and returns a finished
//! [`Report`]. It takes plain values, not clap types, so it can be driven from a
//! test or a future library consumer as easily as from the CLI. The two-tier
//! rule is applied here: only "can't even start" conditions return `Err`;
//! everything degraded becomes a `Problem` in the report.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::Path;

use crate::arch::by_elf_machine;
use crate::elf::coredump::{self, Thread};
use crate::elf::{Elf, Image};
use crate::error::{Error, Result};
use crate::glibc::DetectedLayout;
use crate::heap::arena::{self, Arena};
use crate::heap::stats::accumulate;
use crate::heap::{fastbin, heap_list, tcache, walk};
use crate::locate::{
    compute_identity, looks_like_libc, strip_deleted, ForcePathLocator, Identity, LibcLocator,
    NtFileLocator,
};
use crate::problem::Problem;
use crate::report::model::{ArenaReport, GlibcCapabilitiesJson, LibcInfo, Report, SCHEMA_VERSION};

pub fn analyze_core(
    core_path: &Path,
    libc_ref_path: Option<&Path>,
    force_libc: Option<&str>,
) -> Result<Report> {
    let core_image = Image::load(core_path)?;
    let core = core_image.parse()?;

    let arch = by_elf_machine(core.machine()).ok_or(Error::UnsupportedArch(core.machine()))?;
    let notes = core.notes();
    let threads = coredump::threads(&notes, arch)?;
    let mapped = coredump::mapped_files(&notes, core.is_64bit())?;

    // The reference libc: an explicit --libc, otherwise the libc mapped in the
    // core (only useful when the local file still has symbols).
    let ref_image = match libc_ref_path {
        Some(p) => Image::load(p)?,
        None => {
            let path = mapped
                .iter()
                .find(|m| m.file_offset == 0 && looks_like_libc(&m.path))
                .map(|m| strip_deleted(&m.path).to_string())
                .ok_or_else(|| {
                    Error::LibcNotFound("no libc mapping in core; pass --libc".to_string())
                })?;
            Image::load(Path::new(&path))
                .map_err(|_| Error::LibcNotFound(format!("could not open {path}; pass --libc")))?
        }
    };
    let reference = ref_image.parse()?;

    let layout = DetectedLayout::detect(&reference, arch);
    // Start the global problem list from detection so MissingRelocation /
    // UnknownGlibcVersion / DuplicateSymbol reach the final report.
    let mut problems = layout.problems.clone();
    if let Some(fatal) = problems.iter().find(|p| p.is_fatal()) {
        return Err(Error::UnusableLibc(describe(fatal)));
    }

    let identity = compute_identity(&reference);
    if matches!(identity, Identity::ContentHash(_)) {
        problems.push(Problem::MissingBuildId);
    }

    let located = if let Some(path) = force_libc {
        ForcePathLocator(path.to_string()).locate(&core, &identity)?
    } else {
        NtFileLocator.locate(&core, &identity)?
    };
    let libc_addr = located.load_addr;

    let (arenas, arena_problems) = arena::list(&core, &layout, libc_addr)?;
    problems.extend(arena_problems);

    let TlsInfo {
        tcache_membership,
        thread_arena_map,
    } = resolve_tls(&core, &layout, libc_addr, &arenas, &threads, &mut problems);

    let mut arena_reports = Vec::new();
    for arena in &arenas {
        let attached = attached_threads(arena, &threads, &thread_arena_map);

        let (heaps, heap_problems) = match heap_list::list(&core, &layout, libc_addr, arena) {
            Ok(v) => v,
            // The main arena is core to the report; if its heap list can't start
            // the whole run fails. A secondary arena degrades to a stub.
            Err(e) if arena.is_main() => return Err(e),
            Err(_) => {
                problems.push(Problem::HeapWalkTruncated {
                    arena: arena.index,
                    reason: "heap list start unreadable".to_string(),
                });
                arena_reports.push(ArenaReport::stub(arena.index, arena.is_main(), attached));
                continue;
            }
        };
        problems.extend(heap_problems);

        // All of this arena's chunks, across every heap.
        let mut events = Vec::new();
        for h in &heaps {
            let (evs, probs) = walk::walk_region(
                &core,
                &layout,
                arena.index,
                h.region_start,
                h.region_end,
                arena.is_main(),
            );
            events.extend(evs);
            problems.extend(probs);
        }

        // Fastbins belong to the arena, so walk them once here (not per heap).
        let fastbins = walk_arena_fastbins(&core, &layout, arena, &mut problems);

        let (stats, stat_problems) =
            accumulate(&layout, arena.index, &events, &tcache_membership, &fastbins);
        problems.extend(stat_problems);

        arena_reports.push(ArenaReport::build(
            arena.index,
            arena.is_main(),
            attached,
            &heaps,
            &stats,
        ));
    }

    Ok(Report {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        core_path: core_path.display().to_string(),
        libc: LibcInfo::new(&located, identity),
        glibc_capabilities: GlibcCapabilitiesJson::from_layout(&layout),
        problems,
        arenas: arena_reports,
    })
}

struct TlsInfo {
    tcache_membership: HashMap<u64, (i32, u32)>,
    thread_arena_map: HashMap<i32, u64>,
}

/// Resolve each thread's TLS exactly once, producing the global tcache
/// membership map and the thread→arena map. Kept out of the arena loop so a
/// chain isn't re-walked, and a failing thread isn't re-reported, per arena.
fn resolve_tls(
    core: &Elf<'_>,
    layout: &DetectedLayout,
    libc_addr: u64,
    arenas: &[Arena],
    threads: &[Thread],
    problems: &mut Vec<Problem>,
) -> TlsInfo {
    let mut tcache_membership: HashMap<u64, (i32, u32)> = HashMap::new();
    let mut thread_arena_map: HashMap<i32, u64> = HashMap::new();
    if layout.tp_off_reloc_addr.is_none() {
        return TlsInfo {
            tcache_membership,
            thread_arena_map,
        };
    }
    let main_addr = arenas.first().map(|a| a.malloc_state_addr).unwrap_or(0);
    let word = u64::from(layout.word_size);
    let entries_off = u64::from(layout.tcache_entries_offset);

    for thread in threads {
        if thread.tp == 0 {
            problems.push(Problem::ThreadTlsResolutionFailed {
                thread_id: thread.thread_id,
            });
            continue;
        }
        let mut tls_failed = false;

        if layout.thread_arena.present {
            match tcache::read_thread_arena(core, layout, libc_addr, thread.tp) {
                // A null thread_arena is glibc's "this thread uses main"; map it
                // to main so attached_threads matches by address.
                Ok(addr) => {
                    let resolved = if addr == 0 { main_addr } else { addr };
                    thread_arena_map.insert(thread.thread_id, resolved);
                }
                Err(_) => tls_failed = true,
            }
        }

        if layout.capabilities.has_tcache {
            match tcache::tcache_ptr(core, layout, libc_addr, thread.tp) {
                Ok(0) => {}
                Ok(base) => collect_tcache(
                    core,
                    layout,
                    base,
                    entries_off,
                    word,
                    thread.thread_id,
                    &mut tcache_membership,
                    problems,
                ),
                Err(_) => tls_failed = true,
            }
        }

        if tls_failed {
            problems.push(Problem::ThreadTlsResolutionFailed {
                thread_id: thread.thread_id,
            });
        }
    }
    TlsInfo {
        tcache_membership,
        thread_arena_map,
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_tcache(
    core: &Elf<'_>,
    layout: &DetectedLayout,
    base: u64,
    entries_off: u64,
    word: u64,
    thread_id: i32,
    membership: &mut HashMap<u64, (i32, u32)>,
    problems: &mut Vec<Problem>,
) {
    for bin in 0..layout.tcache_max_bins {
        let head_addr = base
            .wrapping_add(entries_off)
            .wrapping_add(u64::from(bin) * word);
        let head = match core.read_u64(head_addr) {
            Ok(h) => h,
            Err(_) => {
                problems.push(Problem::TcacheChunkReadFailed {
                    thread_id,
                    bin_index: bin,
                    address: format!("{head_addr:#x}"),
                });
                continue;
            }
        };
        let (result, probs) = tcache::walk_tcache_bin(core, layout, head, thread_id, bin);
        problems.extend(probs);
        for addr in result.user_addrs {
            // First owner wins; a repeat indicates a double-free, not an overwrite.
            match membership.entry(addr) {
                Entry::Occupied(_) => problems.push(Problem::DuplicateTcacheEntry {
                    thread_id,
                    bin_index: bin,
                    address: format!("{addr:#x}"),
                }),
                Entry::Vacant(slot) => {
                    slot.insert((thread_id, bin));
                }
            }
        }
    }
}

fn walk_arena_fastbins(
    core: &Elf<'_>,
    layout: &DetectedLayout,
    arena: &Arena,
    problems: &mut Vec<Problem>,
) -> Vec<fastbin::FastbinBinResult> {
    let word = u64::from(layout.word_size);
    let array_off = u64::from(layout.fastbin_array_offset);
    let mut results = Vec::new();
    for bin in 0..layout.fastbin_count {
        let head_addr = arena
            .malloc_state_addr
            .wrapping_add(array_off)
            .wrapping_add(u64::from(bin) * word);
        let head = match core.read_u64(head_addr) {
            Ok(h) => h,
            Err(_) => {
                problems.push(Problem::FastbinChunkReadFailed {
                    arena: arena.index,
                    bin_index: bin,
                    address: format!("{head_addr:#x}"),
                });
                continue;
            }
        };
        let (result, probs) = fastbin::walk_fastbin(core, layout, head, arena.index, bin);
        problems.extend(probs);
        results.push(result);
    }
    results
}

/// Threads currently bound to this arena, via the precomputed map.
fn attached_threads(arena: &Arena, threads: &[Thread], map: &HashMap<i32, u64>) -> Vec<i32> {
    threads
        .iter()
        .filter(|t| map.get(&t.thread_id) == Some(&arena.malloc_state_addr))
        .map(|t| t.thread_id)
        .collect()
}

/// A human-readable reason for a fatal libc problem, for the stderr message.
/// Only the two fatal kinds reach here; both are spelled out rather than
/// Debug-formatted so the message stays a stable, readable string.
fn describe(problem: &Problem) -> String {
    match problem {
        Problem::MissingSymbol { symbol } => format!("missing required symbol '{symbol}'"),
        Problem::UnsupportedArch { machine } => {
            format!("unsupported architecture e_machine={machine:#x}")
        }
        _ => "reference libc unusable".to_string(),
    }
}

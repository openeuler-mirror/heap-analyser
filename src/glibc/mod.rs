// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! glibc structure layout and capability detection.
//!
//! [`DetectedLayout`] bundles the malloc structure offsets, resolved symbols,
//! TLS relocation, and version-derived capabilities needed by the analysis.

mod dwarf;
mod heap_info;
mod malloc_state;
mod tcache;
pub mod version;

use crate::arch::Arch;
use crate::elf::{notes, Elf};
use crate::problem::Problem;

use heap_info::HeapInfoOffsets;
use malloc_state::MallocStateOffsets;
use tcache::TcacheOffsets;
use version::GlibcVersion;

/// glibc gained safe-linked free lists in 2.32.
const SAFE_LINKING_SINCE: GlibcVersion = GlibcVersion {
    major: 2,
    minor: 32,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SymbolInfo {
    pub present: bool,
    pub value: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum VersionSource {
    Detected(GlibcVersion),
    AssumedDefault,
}

impl VersionSource {
    /// Stable JSON string for the `version_source` field. Never `Debug`-format
    /// this — the value is part of the public schema.
    pub fn as_str(&self) -> &'static str {
        match self {
            VersionSource::Detected(_) => "gnu_version_d",
            VersionSource::AssumedDefault => "assumed_default",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GlibcCapabilities {
    pub has_tcache: bool,
    pub has_safe_linking: bool,
    pub version_source: VersionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutSource {
    Builtin,
    Dwarf,
}

impl LayoutSource {
    pub fn as_str(self) -> &'static str {
        match self {
            LayoutSource::Builtin => "builtin",
            LayoutSource::Dwarf => "dwarf",
        }
    }
}

pub struct DetectedLayout {
    pub layout_source: LayoutSource,
    pub word_size: u32,
    pub header_size: u32,
    pub minsize: u32,
    pub malloc_alignment: u32,

    pub fastbin_array_offset: u32,
    pub fastbin_count: u32,
    pub malloc_state_top_offset: u32,
    pub malloc_state_next_offset: u32,

    pub mp_arena_max_offset: u32,
    pub mp_sbrk_base_offset: u32,
    pub mp_tcache_bins_offset: u32,

    pub heap_info_size: u32,
    pub heap_info_ar_ptr_offset: u32,
    pub heap_info_prev_offset: u32,
    pub heap_info_size_offset: u32,
    pub heap_info_mprotect_size_offset: u32,
    pub heap_max_size: u64,

    pub tcache_max_bins: u32,
    pub tcache_entries_offset: u32,

    pub main_arena: SymbolInfo,
    pub mp: SymbolInfo,
    pub narenas: SymbolInfo,
    pub narenas_limit: SymbolInfo,
    pub tcache: SymbolInfo,
    pub tcache_key: SymbolInfo,
    pub thread_arena: SymbolInfo,
    /// Address holding the libc-relative TLS block offset (the target of the
    /// first zero-addend TP-offset relocation). `None` disables all TLS reads.
    pub tp_off_reloc_addr: Option<u64>,

    pub capabilities: GlibcCapabilities,
    pub problems: Vec<Problem>,
}

/// The wanted symbols, filled in during the single symbol-table pass.
#[derive(Default)]
struct Symbols {
    main_arena: SymbolInfo,
    mp: SymbolInfo,
    narenas: SymbolInfo,
    narenas_limit: SymbolInfo,
    tcache: SymbolInfo,
    tcache_key: SymbolInfo,
    thread_arena: SymbolInfo,
    hugepage_config: SymbolInfo,
}

impl DetectedLayout {
    /// Never fails: anything wrong (missing symbol, missing relocation, unknown
    /// version) is recorded in `problems`. Callers decide whether to abort by
    /// looking for a fatal problem — `check` still wants to report a stripped
    /// libc rather than error out.
    pub fn detect(elf: &Elf<'_>, arch: &dyn Arch) -> Self {
        Self::detect_with_debug(elf, None, arch)
    }

    pub(crate) fn detect_with_debug(
        elf: &Elf<'_>,
        debug: Option<&Elf<'_>>,
        arch: &dyn Arch,
    ) -> Self {
        let word_size: u32 = if elf.is_64bit() { 8 } else { 4 };
        let mut problems = Vec::new();

        let (symbols, sym_problems) = scan_symbols(elf, debug);
        problems.extend(sym_problems);
        if !symbols.main_arena.present {
            problems.push(Problem::MissingSymbol {
                symbol: "main_arena".to_string(),
            });
        }
        if !symbols.mp.present {
            problems.push(Problem::MissingSymbol {
                symbol: "mp_".to_string(),
            });
        }

        let has_hugepage = symbols.hugepage_config.present;
        let ms = MallocStateOffsets::new(word_size);
        let hi = HeapInfoOffsets::new(word_size, has_hugepage);
        let tc = TcacheOffsets::new();

        // mp_ (malloc_par) offsets. sbrk_base shifts when the THP fields are
        // compiled in; tcache_bins immediately follows it.
        let mp_sbrk_base_offset = if word_size == 8 {
            if has_hugepage {
                96
            } else {
                72
            }
        } else if has_hugepage {
            44
        } else {
            56
        };

        let tp_off_reloc_addr = find_tp_off_reloc(elf, arch);
        if tp_off_reloc_addr.is_none() {
            problems.push(Problem::MissingRelocation);
        }

        let capabilities = detect_capabilities(elf, symbols.tcache.present, &mut problems);

        let mut layout = DetectedLayout {
            layout_source: LayoutSource::Builtin,
            word_size,
            header_size: word_size,
            minsize: if word_size == 8 { 32 } else { 16 },
            malloc_alignment: if word_size == 8 { 16 } else { 8 },
            fastbin_array_offset: ms.fastbin_array,
            fastbin_count: ms.fastbin_count,
            malloc_state_top_offset: ms.top,
            malloc_state_next_offset: ms.next,
            mp_arena_max_offset: 4 * word_size,
            mp_sbrk_base_offset,
            mp_tcache_bins_offset: mp_sbrk_base_offset + word_size,
            heap_info_size: hi.sizeof,
            heap_info_ar_ptr_offset: hi.ar_ptr,
            heap_info_prev_offset: hi.prev,
            heap_info_size_offset: hi.size,
            heap_info_mprotect_size_offset: hi.mprotect_size,
            heap_max_size: hi.heap_max_size,
            tcache_max_bins: tc.max_bins,
            tcache_entries_offset: tc.entries,
            main_arena: symbols.main_arena,
            mp: symbols.mp,
            narenas: symbols.narenas,
            narenas_limit: symbols.narenas_limit,
            tcache: symbols.tcache,
            tcache_key: symbols.tcache_key,
            thread_arena: symbols.thread_arena,
            tp_off_reloc_addr,
            capabilities,
            problems,
        };

        // Required offsets switch as one set. A failed extraction leaves the
        // built-in layout untouched.
        let dwarf_elf = debug.unwrap_or(elf);
        match dwarf::extract_layout(dwarf_elf, layout.capabilities.has_tcache) {
            Ok(dwarf) => layout.apply_dwarf(dwarf),
            Err(dwarf::DwarfLayoutError::Unavailable) if debug.is_none() => {}
            Err(error) => layout.problems.push(Problem::DwarfLayoutFallback {
                reason: error.to_string(),
            }),
        }
        layout
    }

    fn apply_dwarf(&mut self, layout: dwarf::DwarfLayout) {
        self.layout_source = LayoutSource::Dwarf;
        self.main_arena.size = u64::from(layout.malloc_state_size);
        self.fastbin_array_offset = layout.fastbin_array_offset;
        self.fastbin_count = layout.fastbin_count;
        self.malloc_state_top_offset = layout.malloc_state_top_offset;
        self.malloc_state_next_offset = layout.malloc_state_next_offset;
        self.mp_sbrk_base_offset = layout.mp_sbrk_base_offset;
        if let Some(offset) = layout.mp_arena_max_offset {
            self.mp_arena_max_offset = offset;
        }
        if let Some(offset) = layout.mp_tcache_bins_offset {
            self.mp_tcache_bins_offset = offset;
        }
        self.heap_info_size = layout.heap_info_size;
        self.heap_info_ar_ptr_offset = layout.heap_info_ar_ptr_offset;
        self.heap_info_prev_offset = layout.heap_info_prev_offset;
        self.heap_info_size_offset = layout.heap_info_size_offset;
        self.heap_info_mprotect_size_offset = layout.heap_info_mprotect_size_offset;
        if let (Some(entries), Some(bins)) = (layout.tcache_entries_offset, layout.tcache_max_bins)
        {
            self.tcache_entries_offset = entries;
            self.tcache_max_bins = bins;
        }
    }
}

/// Check that a separate debug ELF belongs to the runtime libc.
pub(crate) fn verify_debug_matches_runtime(
    runtime: &Elf<'_>,
    debug: &Elf<'_>,
) -> std::result::Result<(), String> {
    if runtime.machine() != debug.machine() || runtime.is_64bit() != debug.is_64bit() {
        return Err("debuginfo ABI does not match the runtime libc".to_string());
    }

    let runtime_build_id = elf_build_id(runtime);
    let debug_build_id = elf_build_id(debug);
    if let (Some(runtime_id), Some(debug_id)) = (&runtime_build_id, &debug_build_id) {
        return if runtime_id == debug_id {
            Ok(())
        } else {
            Err("debuginfo build-id does not match the runtime libc".to_string())
        };
    }

    let expected_crc = debuglink_crc(runtime)?.ok_or_else(|| {
        "runtime libc and debuginfo have no matching build-id or .gnu_debuglink CRC".to_string()
    })?;
    verify_debuglink_crc(expected_crc, debug.bytes())
}

fn elf_build_id(elf: &Elf<'_>) -> Option<Vec<u8>> {
    notes::build_id(&elf.notes())
        .or_else(|| notes::build_id_from_note_sections(elf.inner(), elf.bytes()))
        .filter(|id| !id.is_empty())
}

fn debuglink_crc(elf: &Elf<'_>) -> std::result::Result<Option<u32>, String> {
    let mut result = None;
    for section in &elf.inner().section_headers {
        if elf.inner().shdr_strtab.get_at(section.sh_name) != Some(".gnu_debuglink") {
            continue;
        }
        if result.is_some() {
            return Err("runtime libc has duplicate .gnu_debuglink sections".to_string());
        }
        let start = usize::try_from(section.sh_offset)
            .map_err(|_| "runtime libc has invalid .gnu_debuglink offset".to_string())?;
        let size = usize::try_from(section.sh_size)
            .map_err(|_| "runtime libc has invalid .gnu_debuglink size".to_string())?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| "runtime libc has invalid .gnu_debuglink range".to_string())?;
        let data = elf
            .bytes()
            .get(start..end)
            .ok_or_else(|| "runtime libc has truncated .gnu_debuglink data".to_string())?;
        result = Some(parse_debuglink_crc(data, elf.inner().little_endian)?);
    }
    Ok(result)
}

fn parse_debuglink_crc(data: &[u8], little_endian: bool) -> std::result::Result<u32, String> {
    let nul = data
        .iter()
        .position(|byte| *byte == 0)
        .filter(|offset| *offset > 0)
        .ok_or_else(|| "runtime libc has malformed .gnu_debuglink data".to_string())?;
    let crc_offset = nul
        .checked_add(1)
        .and_then(|offset| offset.checked_add(3))
        .map(|offset| offset & !3)
        .ok_or_else(|| "runtime libc has malformed .gnu_debuglink data".to_string())?;
    let crc_end = crc_offset
        .checked_add(4)
        .ok_or_else(|| "runtime libc has malformed .gnu_debuglink data".to_string())?;
    let bytes: [u8; 4] = data
        .get(crc_offset..crc_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "runtime libc has malformed .gnu_debuglink data".to_string())?;
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn verify_debuglink_crc(expected: u32, debug: &[u8]) -> std::result::Result<(), String> {
    if crc32fast::hash(debug) == expected {
        Ok(())
    } else {
        Err("debuginfo .gnu_debuglink CRC does not match the runtime libc".to_string())
    }
}

fn scan_symbols(runtime: &Elf<'_>, debug: Option<&Elf<'_>>) -> (Symbols, Vec<Problem>) {
    let mut syms = Symbols::default();
    let mut problems = Vec::new();
    // Prefer runtime symbols when present; debuginfo fills stripped entries.
    fill_symbols(runtime, &mut syms, &mut problems);
    if let Some(debug) = debug {
        fill_symbols(debug, &mut syms, &mut problems);
    }
    (syms, problems)
}

fn fill_symbols(elf: &Elf<'_>, syms: &mut Symbols, problems: &mut Vec<Problem>) {
    let inner = elf.inner();
    for sym in &inner.syms {
        if sym.st_shndx == 0 {
            continue;
        }
        let Some(name) = inner.strtab.get_at(sym.st_name) else {
            continue;
        };
        let slot = match name {
            "main_arena" => &mut syms.main_arena,
            "mp_" => &mut syms.mp,
            "narenas" => &mut syms.narenas,
            "tcache" | "__tcache" => &mut syms.tcache,
            "tcache_key" => &mut syms.tcache_key,
            "thread_arena" => &mut syms.thread_arena,
            "__malloc_hugepage_config" => &mut syms.hugepage_config,
            // Prefix match: LTO builds localise this as `narenas_limit.lto_priv.N`.
            _ if name.starts_with("narenas_limit") => &mut syms.narenas_limit,
            _ => continue,
        };
        if slot.present {
            // First definition wins; a differing duplicate is worth flagging but
            // not fatal.
            if slot.value != sym.st_value {
                problems.push(Problem::DuplicateSymbol {
                    symbol: name.to_string(),
                });
            }
            continue;
        }
        *slot = SymbolInfo {
            present: true,
            value: sym.st_value,
            size: sym.st_size,
        };
    }
}

/// The address the TLS block offset lives at: `r_offset` of the first
/// zero-addend TP-offset relocation.
fn find_tp_off_reloc(elf: &Elf<'_>, arch: &dyn Arch) -> Option<u64> {
    let want = arch.tp_off_reloc_type();
    elf.inner()
        .dynrelas
        .iter()
        .find(|r| r.r_type == want && r.r_addend.unwrap_or(0) == 0)
        .map(|r| r.r_offset)
}

/// Build a layout with the real offset tables but synthetic symbols, for unit
/// tests that need a `DetectedLayout` without a reference ELF.
#[cfg(test)]
pub(crate) fn test_layout(word_size: u32) -> DetectedLayout {
    let ms = MallocStateOffsets::new(word_size);
    let hi = HeapInfoOffsets::new(word_size, false);
    let tc = TcacheOffsets::new();
    let mp_sbrk_base_offset = if word_size == 8 { 72 } else { 56 };
    let present = |value| SymbolInfo {
        present: true,
        value,
        size: 0,
    };
    DetectedLayout {
        layout_source: LayoutSource::Builtin,
        word_size,
        header_size: word_size,
        minsize: if word_size == 8 { 32 } else { 16 },
        malloc_alignment: if word_size == 8 { 16 } else { 8 },
        fastbin_array_offset: ms.fastbin_array,
        fastbin_count: ms.fastbin_count,
        malloc_state_top_offset: ms.top,
        malloc_state_next_offset: ms.next,
        mp_arena_max_offset: 4 * word_size,
        mp_sbrk_base_offset,
        mp_tcache_bins_offset: mp_sbrk_base_offset + word_size,
        heap_info_size: hi.sizeof,
        heap_info_ar_ptr_offset: hi.ar_ptr,
        heap_info_prev_offset: hi.prev,
        heap_info_size_offset: hi.size,
        heap_info_mprotect_size_offset: hi.mprotect_size,
        heap_max_size: hi.heap_max_size,
        tcache_max_bins: tc.max_bins,
        tcache_entries_offset: tc.entries,
        main_arena: present(0),
        mp: present(0),
        narenas: SymbolInfo::default(),
        narenas_limit: SymbolInfo::default(),
        tcache: present(0),
        tcache_key: SymbolInfo::default(),
        thread_arena: present(0),
        tp_off_reloc_addr: Some(0),
        capabilities: GlibcCapabilities {
            has_tcache: true,
            has_safe_linking: false,
            version_source: VersionSource::AssumedDefault,
        },
        problems: Vec::new(),
    }
}

fn detect_capabilities(
    elf: &Elf<'_>,
    has_tcache: bool,
    problems: &mut Vec<Problem>,
) -> GlibcCapabilities {
    match version::detect(elf) {
        Some(v) => GlibcCapabilities {
            has_tcache,
            has_safe_linking: v >= SAFE_LINKING_SINCE,
            version_source: VersionSource::Detected(v),
        },
        None => {
            // Unknown version: assume safe-linking on. Applying the XOR to
            // already-plain pointers would corrupt them, but assuming it *off*
            // on a new glibc corrupts every read — the safer default is on.
            problems.push(Problem::UnknownGlibcVersion);
            GlibcCapabilities {
                has_tcache,
                has_safe_linking: true,
                version_source: VersionSource::AssumedDefault,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_debuglink_crc, verify_debuglink_crc};

    #[test]
    fn parses_debuglink_crc_in_target_byte_order() {
        let crc = 0x1234_5678u32;
        let mut little = b"libc.so.6.debug\0".to_vec();
        little.resize((little.len() + 3) & !3, 0);
        little.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(parse_debuglink_crc(&little, true).unwrap(), crc);

        let mut big = b"libc.so.6.debug\0".to_vec();
        big.resize((big.len() + 3) & !3, 0);
        big.extend_from_slice(&crc.to_be_bytes());
        assert_eq!(parse_debuglink_crc(&big, false).unwrap(), crc);
    }

    #[test]
    fn rejects_malformed_debuglink_data() {
        assert!(parse_debuglink_crc(b"libc.so.6.debug", true).is_err());
        assert!(parse_debuglink_crc(b"\0\0\0\0", true).is_err());
        assert!(parse_debuglink_crc(b"libc.so.6.debug\0", true).is_err());
    }

    #[test]
    fn verifies_crc_over_the_complete_debug_file() {
        let debug = b"complete debug file contents";
        let expected = crc32fast::hash(debug);
        assert!(verify_debuglink_crc(expected, debug).is_ok());

        let mut changed = debug.to_vec();
        changed[20] ^= 1;
        assert!(verify_debuglink_crc(expected, &changed).is_err());
    }
}

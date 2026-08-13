// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! ELF note parsing.
//!
//! Two callers: [`walk_all_notes`] over a fully-parsed ELF (core-dump notes,
//! reference-libc build-id), and [`build_id_from_raw_buffer`] over a bare chunk
//! of memory read out of a core at a library's load address — which is *not* a
//! complete, section-header-bearing ELF, so goblin can't parse it. Everything
//! here is truncation-tolerant: a short or malformed buffer yields fewer notes
//! (or `None`), never a panic.

use goblin::elf::program_header::PT_NOTE;
use goblin::elf::section_header::SHT_NOTE;

use super::{read_u16_le, read_u32_le};

pub const NT_GNU_BUILD_ID: u32 = 3;

pub struct Note<'a> {
    /// Note name with its trailing NUL stripped. Callers compare this directly
    /// against `"CORE"`, `"GNU"`, etc.; the raw record stores e.g. `b"CORE\0"`
    /// and a missed trim would break every one of those comparisons.
    pub name: &'a str,
    pub note_type: u32,
    pub desc: &'a [u8],
}

/// Walk one note segment: a sequence of `namesz(4) descsz(4) type(4)` headers,
/// each followed by the name (padded to 4 bytes) and descriptor (padded to 4).
pub fn walk_note_segment(data: &[u8]) -> Vec<Note<'_>> {
    let mut notes = Vec::new();
    let mut off = 0usize;
    // Each iteration consumes at least the 12-byte header, so this terminates.
    while off + 12 <= data.len() {
        let (Some(namesz), Some(descsz), Some(ntype)) = (
            read_u32_le(data, off),
            read_u32_le(data, off + 4),
            read_u32_le(data, off + 8),
        ) else {
            break;
        };
        let (namesz, descsz) = (namesz as usize, descsz as usize);

        let name_start = off + 12;
        let Some(name_end) = name_start.checked_add(namesz) else {
            break;
        };
        let Some(name_bytes) = data.get(name_start..name_end) else {
            break;
        };
        let Some(desc_start) = align4(name_end) else {
            break;
        };
        let Some(desc_end) = desc_start.checked_add(descsz) else {
            break;
        };
        let Some(desc) = data.get(desc_start..desc_end) else {
            break;
        };
        let Some(next) = align4(desc_end) else {
            break;
        };

        // Keep the note only if its name is valid UTF-8 (note names are ASCII in
        // practice); either way advance past it so a weird name doesn't desync
        // the walk.
        let trimmed = name_bytes
            .iter()
            .position(|&b| b == 0)
            .map_or(name_bytes, |nul| &name_bytes[..nul]);
        if let Ok(name) = std::str::from_utf8(trimmed) {
            notes.push(Note {
                name,
                note_type: ntype,
                desc,
            });
        }
        off = next;
    }
    notes
}

/// Collect the notes from every `PT_NOTE` segment of a parsed ELF.
pub fn walk_all_notes<'a>(elf: &goblin::elf::Elf<'_>, data: &'a [u8]) -> Vec<Note<'a>> {
    let mut notes = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != PT_NOTE {
            continue;
        }
        let (Ok(start), Ok(size)) = (usize::try_from(ph.p_offset), usize::try_from(ph.p_filesz))
        else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if let Some(segment) = data.get(start..end) {
            notes.extend(walk_note_segment(segment));
        }
    }
    notes
}

/// The GNU build-id bytes, if present.
pub fn build_id(notes: &[Note<'_>]) -> Option<Vec<u8>> {
    notes
        .iter()
        .find(|n| n.note_type == NT_GNU_BUILD_ID && n.name == "GNU")
        .map(|n| n.desc.to_vec())
}

/// Read a build-id from `SHT_NOTE` sections. Separate debug files may retain
/// the note section without a corresponding `PT_NOTE` program header.
pub fn build_id_from_note_sections(elf: &goblin::elf::Elf<'_>, data: &[u8]) -> Option<Vec<u8>> {
    for section in &elf.section_headers {
        if section.sh_type != SHT_NOTE {
            continue;
        }
        let (Ok(start), Ok(size)) = (
            usize::try_from(section.sh_offset),
            usize::try_from(section.sh_size),
        ) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Some(section_data) = data.get(start..end) else {
            continue;
        };
        let notes = walk_note_segment(section_data);
        if let Some(id) = build_id(&notes) {
            return Some(id);
        }
    }
    None
}

/// Extract a build-id straight from a raw memory buffer that starts with an ELF
/// header but isn't a full parseable file.
///
/// We read only what we need from the header — `e_phoff`, `e_phentsize`,
/// `e_phnum` — locate the `PT_NOTE` program header, and reuse
/// [`walk_note_segment`]. Assumes buffer offset 0 maps to file offset 0, which
/// holds for the `NT_FILE` mappings whose `file_offset` is 0.
pub fn build_id_from_raw_buffer(buf: &[u8]) -> Option<Vec<u8>> {
    if !buf.starts_with(b"\x7fELF") {
        return None;
    }
    let is_64 = match buf.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };

    // Program-header table location, laid out differently for the two classes.
    let (e_phoff, e_phentsize_off, e_phnum_off) = if is_64 {
        (read_u64_field(buf, 0x20)?, 0x36, 0x38)
    } else {
        (u64::from(read_u32_le(buf, 0x1c)?), 0x2a, 0x2c)
    };
    let phentsize = read_u16_le(buf, e_phentsize_off)? as usize;
    let phnum = read_u16_le(buf, e_phnum_off)? as usize;
    let phoff = usize::try_from(e_phoff).ok()?;

    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let p_type = read_u32_le(buf, ph)?;
        if p_type != PT_NOTE {
            continue;
        }
        let (p_offset, p_filesz) = if is_64 {
            (read_u64_field(buf, ph + 8)?, read_u64_field(buf, ph + 32)?)
        } else {
            (
                u64::from(read_u32_le(buf, ph + 4)?),
                u64::from(read_u32_le(buf, ph + 16)?),
            )
        };
        let start = usize::try_from(p_offset).ok()?;
        let size = usize::try_from(p_filesz).ok()?;
        let end = start.checked_add(size)?;
        let segment = buf.get(start..end)?;
        if let Some(id) = build_id(&walk_note_segment(segment)) {
            return Some(id);
        }
    }
    None
}

fn read_u64_field(buf: &[u8], off: usize) -> Option<u64> {
    super::read_u64_le(buf, off)
}

/// Round up to the next multiple of 4, or `None` on overflow.
fn align4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|x| x & !3)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one note record: namesz, descsz, type, padded name, padded desc.
    fn note_record(name: &[u8], ntype: u32, desc: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        v.extend_from_slice(&ntype.to_le_bytes());
        v.extend_from_slice(name);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v.extend_from_slice(desc);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn trims_trailing_nul_from_name() {
        let seg = note_record(b"CORE\0", 1, &[0xaa; 4]);
        let notes = walk_note_segment(&seg);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].name, "CORE", "trailing NUL must be stripped");
        assert_eq!(notes[0].note_type, 1);
        assert_eq!(notes[0].desc, &[0xaa; 4]);
    }

    #[test]
    fn walks_multiple_records() {
        let mut seg = note_record(b"CORE\0", 1, &[1, 2, 3, 4, 5, 6, 7, 8]);
        seg.extend(note_record(
            b"GNU\0",
            NT_GNU_BUILD_ID,
            &[0xde, 0xad, 0xbe, 0xef],
        ));
        let notes = walk_note_segment(&seg);
        assert_eq!(notes.len(), 2);
        assert_eq!(build_id(&notes), Some(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn truncated_record_stops_cleanly() {
        let mut seg = note_record(b"GNU\0", NT_GNU_BUILD_ID, &[0xde, 0xad, 0xbe, 0xef]);
        seg.truncate(seg.len() - 2); // chop the descriptor
                                     // No panic, and the incomplete record is dropped.
        assert!(walk_note_segment(&seg).is_empty());
    }

    #[test]
    fn no_build_id_when_absent() {
        let seg = note_record(b"CORE\0", 1, &[0; 8]);
        assert_eq!(build_id(&walk_note_segment(&seg)), None);
    }
}

// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Pull thread and mapping information out of a core dump's notes.

use crate::arch::Arch;
use crate::error::Result;

use super::notes::Note;
use super::read_word;

const NT_PRSTATUS: u32 = 1;
const NT_FILE: u32 = 0x4649_4c45;

/// Upper bound on `NT_FILE` entries, so a corrupt `count` can't spin us.
const MAX_MAPPINGS: u64 = 100_000;

#[derive(Debug, Clone)]
pub struct Thread {
    pub pc: u64,
    pub sp: u64,
    pub tp: u64,
    pub thread_id: i32,
}

#[derive(Debug, Clone)]
pub struct MappedFile {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub path: String,
}

/// Reconstruct the threads from `NT_PRSTATUS` notes (plus the arch's TLS note
/// where the thread pointer lives separately, e.g. `NT_ARM_TLS` on aarch64).
///
/// A malformed prstatus is a hard failure: it means the notes section itself is
/// damaged, and thread info underpins tcache / attached-thread analysis, so a
/// half-known thread set isn't worth pressing on with. Within a thread's note
/// group prstatus comes first, so a following TLS note fills the thread we just
/// pushed; `pending_tp` covers the rare reversed ordering.
pub fn threads(notes: &[Note<'_>], arch: &dyn Arch) -> Result<Vec<Thread>> {
    let mut threads = Vec::new();
    let mut pending_tp: Option<u64> = None;
    let tls_note = arch.tls_note_type();

    for note in notes {
        if note.note_type == NT_PRSTATUS && note.name == "CORE" {
            let mut regs = arch.parse_prstatus(note.desc)?;
            if regs.tp == 0 {
                if let Some(tp) = pending_tp.take() {
                    regs.tp = tp;
                }
            }
            threads.push(Thread {
                pc: regs.pc,
                sp: regs.sp,
                tp: regs.tp,
                thread_id: regs.thread_id,
            });
        } else if Some(note.note_type) == tls_note && (note.name == "CORE" || note.name == "LINUX")
        {
            if let Some(tp) = arch.parse_tls_note(note.desc) {
                match threads.last_mut() {
                    Some(last) if last.tp == 0 => last.tp = tp,
                    _ => pending_tp = Some(tp),
                }
            }
        }
    }
    Ok(threads)
}

/// Parse the `NT_FILE` note into the process's file-backed mappings.
///
/// Descriptor layout: `count`, `page_size`, then `count` × `(start, end,
/// file_offset)`, then `count` NUL-terminated path strings — all in target word
/// size. Missing note or truncation yields whatever parsed cleanly, never an
/// error.
pub fn mapped_files(notes: &[Note<'_>], is_64bit: bool) -> Result<Vec<MappedFile>> {
    let Some(note) = notes.iter().find(|n| n.note_type == NT_FILE) else {
        return Ok(Vec::new());
    };
    let desc = note.desc;
    let word = if is_64bit { 8 } else { 4 };

    let Some(count) = read_word(desc, 0, is_64bit) else {
        return Ok(Vec::new());
    };
    let count = count.min(MAX_MAPPINGS);

    // Fixed-size triples first, so we can then stream the variable-length paths.
    let mut ranges = Vec::new();
    let mut off = 2 * word; // skip count + page_size
    for _ in 0..count {
        let (Some(start), Some(end), Some(file_offset)) = (
            read_word(desc, off, is_64bit),
            read_word(desc, off + word, is_64bit),
            read_word(desc, off + 2 * word, is_64bit),
        ) else {
            break;
        };
        ranges.push((start, end, file_offset));
        off += 3 * word;
    }

    let mut files = Vec::with_capacity(ranges.len());
    for (start, end, file_offset) in ranges {
        let Some(path) = read_cstr(desc, &mut off) else {
            break;
        };
        files.push(MappedFile {
            start,
            end,
            file_offset,
            path,
        });
    }
    Ok(files)
}

/// Read a NUL-terminated string starting at `*off`, advancing past the NUL.
/// Returns `None` if there's no terminator before the buffer ends.
fn read_cstr(buf: &[u8], off: &mut usize) -> Option<String> {
    let rest = buf.get(*off..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    let s = String::from_utf8_lossy(&rest[..nul]).into_owned();
    *off += nul + 1;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::by_elf_machine;

    fn x86_64() -> &'static dyn Arch {
        by_elf_machine(goblin::elf::header::EM_X86_64).unwrap()
    }

    #[test]
    fn no_nt_file_yields_empty() {
        assert!(mapped_files(&[], true).unwrap().is_empty());
    }

    #[test]
    fn parses_nt_file_entries() {
        // count=2, page_size=0x1000, two ranges, two paths.
        let mut desc = Vec::new();
        desc.extend_from_slice(&2u64.to_le_bytes());
        desc.extend_from_slice(&0x1000u64.to_le_bytes());
        for (s, e, o) in [
            (0x400000u64, 0x401000u64, 0u64),
            (0x7ffff7a00000u64, 0x7ffff7c00000u64, 0u64),
        ] {
            desc.extend_from_slice(&s.to_le_bytes());
            desc.extend_from_slice(&e.to_le_bytes());
            desc.extend_from_slice(&o.to_le_bytes());
        }
        desc.extend_from_slice(b"/bin/victim\0");
        desc.extend_from_slice(b"/lib/libc.so.6\0");

        let note = Note {
            name: "CORE",
            note_type: NT_FILE,
            desc: &desc,
        };
        let files = mapped_files(&[note], true).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "/bin/victim");
        assert_eq!(files[1].start, 0x7ffff7a00000);
        assert_eq!(files[1].path, "/lib/libc.so.6");
    }

    #[test]
    fn malformed_prstatus_is_hard_failure() {
        // A too-short prstatus aborts thread extraction rather than yielding a
        // half-known thread set.
        let note = Note {
            name: "CORE",
            note_type: NT_PRSTATUS,
            desc: &[0u8; 8],
        };
        assert!(threads(&[note], x86_64()).is_err());
    }
}

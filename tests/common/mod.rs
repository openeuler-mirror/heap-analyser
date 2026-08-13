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
use std::sync::atomic::{AtomicU64, Ordering};

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

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

pub struct ElfFixture {
    dir: std::path::PathBuf,
}

impl ElfFixture {
    pub fn new() -> Self {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "heap-analyser-test-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create test fixture directory");
        ElfFixture { dir }
    }

    pub fn write(&self, name: &str, data: &[u8]) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, data).expect("write test ELF");
        path.to_str().expect("UTF-8 test path").to_string()
    }
}

impl Drop for ElfFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build a minimal ELF64 with section headers but no program headers. This
/// keeps the fixture independent of a host compiler and lets tests exercise
/// build-id discovery from `SHT_NOTE` specifically.
pub fn minimal_elf(machine: u16, build_id: Option<&[u8]>, debuglink_crcs: &[u32]) -> Vec<u8> {
    const ELF_HEADER_SIZE: usize = 64;
    const SECTION_HEADER_SIZE: usize = 64;
    const SHT_STRTAB: u32 = 3;
    const SHT_NOTE: u32 = 7;
    const SHT_PROGBITS: u32 = 1;

    struct Section {
        name: u32,
        section_type: u32,
        offset: u64,
        size: u64,
        alignment: u64,
    }

    let mut shstrtab = vec![0];
    let shstrtab_name = add_string(&mut shstrtab, b".shstrtab");
    let note_name = add_string(&mut shstrtab, b".note.gnu.build-id");
    let debuglink_name = add_string(&mut shstrtab, b".gnu_debuglink");

    let mut data = vec![0; ELF_HEADER_SIZE];
    let mut sections = Vec::new();
    append_section(
        &mut data,
        &mut sections,
        shstrtab_name,
        SHT_STRTAB,
        1,
        &shstrtab,
    );

    if let Some(build_id) = build_id {
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&(build_id.len() as u32).to_le_bytes());
        note.extend_from_slice(&3u32.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(build_id);
        align(&mut note, 4);
        append_section(&mut data, &mut sections, note_name, SHT_NOTE, 4, &note);
    }

    for crc in debuglink_crcs {
        let mut debuglink = b"fixture.debug\0".to_vec();
        align(&mut debuglink, 4);
        debuglink.extend_from_slice(&crc.to_le_bytes());
        append_section(
            &mut data,
            &mut sections,
            debuglink_name,
            SHT_PROGBITS,
            4,
            &debuglink,
        );
    }

    align(&mut data, 8);
    let section_table_offset = data.len();
    data.resize(
        section_table_offset + (sections.len() + 1) * SECTION_HEADER_SIZE,
        0,
    );
    for (index, section) in sections.iter().enumerate() {
        let offset = section_table_offset + (index + 1) * SECTION_HEADER_SIZE;
        write_u32(&mut data, offset, section.name);
        write_u32(&mut data, offset + 4, section.section_type);
        write_u64(&mut data, offset + 24, section.offset);
        write_u64(&mut data, offset + 32, section.size);
        write_u64(&mut data, offset + 48, section.alignment);
    }

    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    write_u16(&mut data, 16, 3);
    write_u16(&mut data, 18, machine);
    write_u32(&mut data, 20, 1);
    write_u64(&mut data, 40, section_table_offset as u64);
    write_u16(&mut data, 52, ELF_HEADER_SIZE as u16);
    write_u16(&mut data, 54, 56);
    write_u16(&mut data, 58, SECTION_HEADER_SIZE as u16);
    write_u16(&mut data, 60, (sections.len() + 1) as u16);
    write_u16(&mut data, 62, 1);
    fn append_section(
        data: &mut Vec<u8>,
        sections: &mut Vec<Section>,
        name: u32,
        section_type: u32,
        alignment: u64,
        contents: &[u8],
    ) {
        align(data, alignment as usize);
        let offset = data.len();
        data.extend_from_slice(contents);
        sections.push(Section {
            name,
            section_type,
            offset: offset as u64,
            size: contents.len() as u64,
            alignment,
        });
    }

    data
}

fn add_string(table: &mut Vec<u8>, value: &[u8]) -> u32 {
    let offset = table.len() as u32;
    table.extend_from_slice(value);
    table.push(0);
    offset
}

fn align(data: &mut Vec<u8>, alignment: usize) {
    while data.len() % alignment != 0 {
        data.push(0);
    }
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

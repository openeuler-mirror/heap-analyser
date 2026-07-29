// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `check`: inspect a reference libc and report whether it has the symbols and
//! layout the analyser needs. Its output schema is its own, so it lives here
//! rather than in `report/`.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::arch::{by_elf_machine, Arch};
use crate::elf::{Elf, Image};
use crate::error::Result;
use crate::glibc::{DetectedLayout, SymbolInfo};
use crate::locate::{compute_identity, Identity};
use crate::problem::Problem;
use crate::report::model::{GlibcCapabilitiesJson, IdentityJson, SCHEMA_VERSION};

#[derive(clap::Args)]
pub struct CheckArgs {
    /// Reference libc to inspect.
    #[arg(long)]
    pub libc: std::path::PathBuf,
}

#[derive(Serialize)]
pub struct CheckReport {
    pub schema_version: u32,
    pub tool_version: String,
    pub libc_path: String,
    pub arch: String,
    pub word_size: u32,
    pub identity: IdentityJson,
    /// `null` for an unsupported architecture; the field is always present so
    /// consumers only handle "maybe null", never "maybe absent".
    pub glibc_capabilities: Option<GlibcCapabilitiesJson>,
    /// Basic arena/heap/chunk analysis will work. Non-fatal problems (e.g. a
    /// missing relocation) leave this `true` while silently disabling tcache /
    /// thread data — check `problems` too.
    pub supported: bool,
    pub symbols: BTreeMap<String, SymbolJson>,
    pub problems: Vec<Problem>,
}

#[derive(Serialize)]
pub struct SymbolJson {
    pub present: bool,
    pub value: Option<u64>,
    pub size: Option<u64>,
}

impl From<&SymbolInfo> for SymbolJson {
    fn from(s: &SymbolInfo) -> Self {
        SymbolJson {
            present: s.present,
            value: s.present.then_some(s.value),
            size: s.present.then_some(s.size),
        }
    }
}

pub fn run(args: CheckArgs) -> Result<i32> {
    let image = Image::load(&args.libc)?;
    let elf = image.parse()?;
    let libc_path = args.libc.display().to_string();
    let identity = compute_identity(&elf);

    let Some(arch) = by_elf_machine(elf.machine()) else {
        // An unsupported arch still gets a full JSON diagnostic — telling the
        // user *why* it's unsupported is check's whole job — not a stderr abort.
        let report = unsupported_report(&elf, libc_path, identity);
        write_report(&report)?;
        return Ok(1);
    };

    let report = supported_report(&elf, arch, libc_path, identity);
    let code = if report.supported { 0 } else { 1 };
    write_report(&report)?;
    Ok(code)
}

fn unsupported_report(elf: &Elf<'_>, libc_path: String, identity: Identity) -> CheckReport {
    let mut problems = vec![Problem::UnsupportedArch {
        machine: elf.machine(),
    }];
    if matches!(identity, Identity::ContentHash(_)) {
        problems.push(Problem::MissingBuildId);
    }
    CheckReport {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        libc_path,
        arch: format!("unknown(0x{:x})", elf.machine()),
        word_size: if elf.is_64bit() { 8 } else { 4 },
        identity: identity.into(),
        glibc_capabilities: None,
        supported: false,
        symbols: BTreeMap::new(),
        problems,
    }
}

fn supported_report(
    elf: &Elf<'_>,
    arch: &dyn Arch,
    libc_path: String,
    identity: Identity,
) -> CheckReport {
    let layout = DetectedLayout::detect(elf, arch);
    let mut problems = layout.problems.clone();
    if matches!(identity, Identity::ContentHash(_)) {
        problems.push(Problem::MissingBuildId);
    }
    let supported = !problems.iter().any(Problem::is_fatal);

    CheckReport {
        schema_version: SCHEMA_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        libc_path,
        arch: arch.name().to_string(),
        word_size: layout.word_size,
        identity: identity.into(),
        glibc_capabilities: Some(GlibcCapabilitiesJson::from_layout(&layout)),
        supported,
        symbols: symbol_map(&layout),
        problems,
    }
}

fn symbol_map(layout: &DetectedLayout) -> BTreeMap<String, SymbolJson> {
    [
        ("main_arena", &layout.main_arena),
        ("mp_", &layout.mp),
        ("narenas", &layout.narenas),
        ("narenas_limit", &layout.narenas_limit),
        ("tcache", &layout.tcache),
        ("tcache_key", &layout.tcache_key),
        ("thread_arena", &layout.thread_arena),
    ]
    .into_iter()
    .map(|(name, info)| (name.to_string(), SymbolJson::from(info)))
    .collect()
}

fn write_report(report: &CheckReport) -> Result<()> {
    serde_json::to_writer_pretty(std::io::stdout(), report)?;
    println!();
    Ok(())
}

// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::path::PathBuf;

use crate::analyze::analyze_core;
use crate::error::Result;
use crate::report::json::JsonRenderer;
use crate::report::Renderer;

#[derive(clap::Args)]
pub struct ReportArgs {
    /// Path to the core dump to analyse.
    pub coredump: PathBuf,

    /// Reference libc (with symbols) to read glibc layout from. Defaults to the
    /// libc mapped in the core, if the local copy still has symbols.
    #[arg(long)]
    pub libc: Option<PathBuf>,

    /// Trust this mapped path as libc without verifying its identity.
    #[arg(long = "force-libc")]
    pub force_libc: Option<String>,
}

/// Thin handler: turn args into an `analyze_core` call and render the result.
/// The report is fully built in memory before anything is written, so a failure
/// never leaves half a document on stdout.
pub fn run(args: ReportArgs) -> Result<i32> {
    let report = analyze_core(
        &args.coredump,
        args.libc.as_deref(),
        args.force_libc.as_deref(),
    )?;
    JsonRenderer.render(&report, &mut std::io::stdout())?;
    println!();
    Ok(0)
}

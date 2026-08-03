// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use clap::{Parser, Subcommand};

use crate::commands::check::CheckArgs;
use crate::commands::report::ReportArgs;

#[derive(Parser)]
#[command(
    name = "heap-analyser",
    version,
    about = "Analyse the glibc malloc heap of an ELF core dump"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Analyse a core dump and print a JSON heap report.
    Report(ReportArgs),
    /// Check whether a reference libc exposes the symbols and layout we need.
    Check(CheckArgs),
}

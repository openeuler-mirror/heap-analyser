// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use clap::Parser;

use heap_analyser::cli::{Cli, Command};
use heap_analyser::commands;

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Report(args) => commands::report::run(args),
        Command::Check(args) => commands::check::run(args),
    };
    match result {
        Ok(code) => std::process::exit(code),
        // Hard failures print to stderr only; stdout stays empty (no half JSON).
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

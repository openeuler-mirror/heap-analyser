// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Hard failures.
//!
//! [`Error`] is for the "no usable result at all" cases — the core won't open,
//! the ELF won't parse, libc can't be located, a required symbol is missing.
//! These propagate with `?` up to `main`, print to stderr, and exit non-zero.
//! Recoverable issues use [`crate::problem::Problem`] instead.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} is not a valid ELF file")]
    NotElf { path: PathBuf },

    #[error("failed to parse ELF data: {0}")]
    ElfParse(#[from] goblin::error::Error),

    #[error("unsupported architecture: e_machine={0:#x}")]
    UnsupportedArch(u16),

    #[error("note data too short: expected at least {expected} bytes, got {actual}")]
    NoteTooShort { expected: usize, actual: usize },

    #[error("could not locate libc in the core dump: {0}")]
    LibcNotFound(String),

    #[error("address {addr:#x} is not backed by file content in any loaded segment")]
    AddressNotMapped { addr: u64 },

    #[error("required glibc symbol '{0}' not found in reference libc")]
    MissingSymbol(&'static str),

    #[error("reference libc is unusable: {0}")]
    UnusableLibc(String),

    #[error("failed to serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

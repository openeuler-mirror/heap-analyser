// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! The `report` command's data model and rendering.

pub mod json;
pub mod model;

pub use model::Report;

use std::io::Write;

use crate::error::Result;

/// Renders a [`Report`] to a writer. One implementation for now (`json`); the
/// trait leaves room for other formats without touching the command layer.
pub trait Renderer {
    fn render(&self, report: &Report, out: &mut dyn Write) -> Result<()>;
}

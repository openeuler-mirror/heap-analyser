// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::io::Write;

use crate::error::Result;

use super::{model::Report, Renderer};

pub struct JsonRenderer;

impl Renderer for JsonRenderer {
    fn render(&self, report: &Report, out: &mut dyn Write) -> Result<()> {
        // Pretty-printed: friendlier in a terminal, and whitespace is irrelevant
        // to `jq` or any programmatic consumer.
        serde_json::to_writer_pretty(out, report)?;
        Ok(())
    }
}

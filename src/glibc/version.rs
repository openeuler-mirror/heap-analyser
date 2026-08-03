// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! glibc version detection.
//!
//! The `.gnu.version_d` section lists the `GLIBC_x.y` symbol-version labels a
//! library *defines*. The highest one is, in practice, the version glibc was
//! built from — enough to decide whether safe-linking (≥ 2.32) is in play.

use crate::elf::Elf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlibcVersion {
    pub major: u32,
    pub minor: u32,
}

pub fn detect(elf: &Elf<'_>) -> Option<GlibcVersion> {
    let inner = elf.inner();
    let verdef = inner.verdef.as_ref()?;

    let mut best: Option<GlibcVersion> = None;
    for def in verdef {
        for aux in &def {
            if let Some(name) = inner.dynstrtab.get_at(aux.vda_name) {
                if let Some(v) = parse_glibc_version(name) {
                    best = Some(best.map_or(v, |cur| cur.max(v)));
                }
            }
        }
    }
    best
}

/// Parse `"GLIBC_2.34"` into `(2, 34)`. Non-numeric tags such as
/// `GLIBC_PRIVATE` return `None`.
fn parse_glibc_version(s: &str) -> Option<GlibcVersion> {
    let rest = s.strip_prefix("GLIBC_")?;
    let (major, minor) = rest.split_once('.')?;
    Some(GlibcVersion {
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numeric_versions() {
        assert_eq!(
            parse_glibc_version("GLIBC_2.34"),
            Some(GlibcVersion {
                major: 2,
                minor: 34
            })
        );
    }

    #[test]
    fn rejects_non_version_tags() {
        assert_eq!(parse_glibc_version("GLIBC_PRIVATE"), None);
        assert_eq!(parse_glibc_version("memcpy"), None);
        assert_eq!(parse_glibc_version("GLIBC_2"), None);
    }

    #[test]
    fn ordering_picks_higher() {
        let a = GlibcVersion {
            major: 2,
            minor: 31,
        };
        let b = GlibcVersion {
            major: 2,
            minor: 32,
        };
        assert!(b > a);
        assert_eq!(a.max(b), b);
    }
}

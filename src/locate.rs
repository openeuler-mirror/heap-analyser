// Copyright (c) 2026 KylinSoft Co., Ltd.
// heap-analyser is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Find the reference libc's load address inside the core and confirm it's the
//! same library we're reading symbols from.

use sha2::{Digest, Sha256};

use crate::elf::{coredump, notes, Elf};
use crate::error::{Error, Result};

/// How we recognise "the same libc". A GNU build-id when the library has one,
/// otherwise a hash of the first page as a weaker fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    BuildId(Vec<u8>),
    ContentHash([u8; 32]),
}

/// Bytes hashed for the content-hash fallback / compared in the core.
const IDENTITY_WINDOW: usize = 4096;

/// Compute the identity of the reference libc.
///
/// Prefers the build-id note; only falls back to a content hash when the
/// library has none. The caller checks for the fallback and records
/// `Problem::MissingBuildId` itself — this function doesn't signal it, to keep
/// the return type a plain `Identity`.
pub fn compute_identity(elf: &Elf<'_>) -> Identity {
    if let Some(id) = notes::build_id(&elf.notes()) {
        return Identity::BuildId(id);
    }
    let bytes = elf.bytes();
    let window = &bytes[..bytes.len().min(IDENTITY_WINDOW)];
    Identity::ContentHash(sha256(window))
}

pub struct LocatedLibc {
    pub load_addr: u64,
    pub path: String,
    /// `true` when the mapping was matched against the reference identity;
    /// `false` when `--force-libc` bypassed the check.
    pub verified: bool,
}

pub trait LibcLocator {
    fn locate(&self, core: &Elf<'_>, want: &Identity) -> Result<LocatedLibc>;
}

/// Locate libc via the core's `NT_FILE` mappings, verifying each candidate
/// against `want`.
pub struct NtFileLocator;

impl LibcLocator for NtFileLocator {
    fn locate(&self, core: &Elf<'_>, want: &Identity) -> Result<LocatedLibc> {
        let mapped = coredump::mapped_files(&core.notes(), core.is_64bit())?;
        let candidates = libc_candidates(&mapped);

        let mut tried = 0usize;
        for m in &candidates {
            tried += 1;
            if identity_matches(core, m.start, want) {
                return Ok(LocatedLibc {
                    load_addr: m.start,
                    path: strip_deleted(&m.path).to_string(),
                    verified: true,
                });
            }
        }
        Err(Error::LibcNotFound(format!(
            "tried {tried} libc mapping(s), none matched the reference identity"
        )))
    }
}

/// Trust an operator-supplied path: match the mapping by name, skip the identity
/// check entirely.
pub struct ForcePathLocator(pub String);

impl LibcLocator for ForcePathLocator {
    fn locate(&self, core: &Elf<'_>, _want: &Identity) -> Result<LocatedLibc> {
        let mapped = coredump::mapped_files(&core.notes(), core.is_64bit())?;
        match force_select(&mapped, &self.0) {
            Some(m) => Ok(LocatedLibc {
                load_addr: m.start,
                path: strip_deleted(&m.path).to_string(),
                verified: false,
            }),
            None => Err(Error::LibcNotFound(format!(
                "no mapping matches forced path '{}'",
                self.0
            ))),
        }
    }
}

/// Whether a mapping's path names the C library itself — matched on the basename
/// so `libcrypto.so` / `libc_malloc_debug.so` / `libcap.so` don't get picked up.
pub(crate) fn looks_like_libc(path: &str) -> bool {
    let base = strip_deleted(path).rsplit('/').next().unwrap_or(path);
    base.starts_with("libc.so") || base.starts_with("libc-")
}

/// libc-looking mappings that start at file offset 0 (so the buffer begins with
/// the ELF header), ascending by address. The order only decides the tie-break
/// when several mappings verify; the identity check is what actually chooses.
fn libc_candidates(mapped: &[coredump::MappedFile]) -> Vec<coredump::MappedFile> {
    let mut v: Vec<_> = mapped
        .iter()
        .filter(|m| m.file_offset == 0 && looks_like_libc(&m.path))
        .cloned()
        .collect();
    v.sort_by_key(|m| m.start);
    v
}

/// The lowest-address file-offset-0 mapping whose path (ignoring a " (deleted)"
/// suffix on either side) equals `wanted`.
fn force_select(mapped: &[coredump::MappedFile], wanted: &str) -> Option<coredump::MappedFile> {
    let wanted = strip_deleted(wanted);
    mapped
        .iter()
        .filter(|m| m.file_offset == 0 && strip_deleted(&m.path) == wanted)
        .min_by_key(|m| m.start)
        .cloned()
}

/// Read the first page of the mapping at `start` and check it against `want`.
fn identity_matches(core: &Elf<'_>, start: u64, want: &Identity) -> bool {
    let Some((_seg_start, seg_end)) = core.segment_bounds(start) else {
        return false;
    };
    let avail = usize::try_from(seg_end.saturating_sub(start)).unwrap_or(0);
    let len = avail.min(IDENTITY_WINDOW);
    let Ok(buf) = core.read_bytes(start, len) else {
        return false;
    };
    match want {
        Identity::BuildId(id) => notes::build_id_from_raw_buffer(buf).as_deref() == Some(id),
        Identity::ContentHash(hash) => &sha256(buf) == hash,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The kernel appends " (deleted)" to a mapping's path when the file was
/// replaced after mapping (common after a package upgrade).
pub(crate) fn strip_deleted(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::coredump::MappedFile;

    fn mapping(start: u64, offset: u64, path: &str) -> MappedFile {
        MappedFile {
            start,
            end: start + 0x1000,
            file_offset: offset,
            path: path.to_string(),
        }
    }

    #[test]
    fn strips_deleted_suffix() {
        assert_eq!(strip_deleted("/lib/libc.so.6 (deleted)"), "/lib/libc.so.6");
        assert_eq!(strip_deleted("/lib/libc.so.6"), "/lib/libc.so.6");
    }

    #[test]
    fn recognises_libc_by_basename_only() {
        assert!(looks_like_libc("/usr/lib64/libc.so.6"));
        assert!(looks_like_libc("/lib/libc-2.31.so"));
        assert!(looks_like_libc("/lib/libc.so.6 (deleted)"));
        // Look-alikes must not match.
        assert!(!looks_like_libc("/usr/lib64/libcrypto.so.3"));
        assert!(!looks_like_libc("/usr/lib64/libc_malloc_debug.so.0"));
        assert!(!looks_like_libc("/usr/lib64/libcap.so.2"));
    }

    #[test]
    fn libc_candidates_filters_and_sorts() {
        let mapped = [
            mapping(0x3000, 0, "/usr/lib64/libcrypto.so.3"), // look-alike
            mapping(0x2000, 0, "/usr/lib64/libc.so.6"),
            mapping(0x1000, 0x1000, "/usr/lib64/libc.so.6"), // wrong file_offset
            mapping(0x4000, 0, "/lib/libc-2.38.so"),
        ];
        let got = libc_candidates(&mapped);
        assert_eq!(
            got.iter().map(|m| m.start).collect::<Vec<_>>(),
            vec![0x2000, 0x4000],
            "only offset-0 real libc mappings, ascending"
        );
    }

    #[test]
    fn force_select_picks_smallest_address_ignoring_deleted() {
        let mapped = [
            mapping(0x5000, 0, "/lib/libc.so.6 (deleted)"),
            mapping(0x2000, 0, "/lib/libc.so.6"),
            mapping(0x9000, 0, "/lib/other.so"),
        ];
        let got = force_select(&mapped, "/lib/libc.so.6").expect("a match");
        assert_eq!(got.start, 0x2000);
        assert!(force_select(&mapped, "/lib/missing.so").is_none());
    }

    #[test]
    fn sha256_is_stable() {
        assert_eq!(sha256(b""), sha256(b""));
        assert_ne!(sha256(b"a"), sha256(b"b"));
    }
}

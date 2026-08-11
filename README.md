# heap-analyser

[English](README.md) | [中文](README.zh.md)

Analyse the glibc `malloc` heap of an ELF core dump and print a machine-readable
JSON report: per-arena allocated/free totals, size histograms, and the contents
of the fastbin and tcache free lists.

It reads glibc's internal structures (`malloc_state`, `_heap_info`,
`tcache_perthread_struct`) out of a core, so it needs a **reference libc with
symbols** to know where those structures and their fields are.

Currently tested on x86-64 Linux cores with glibc 2.38.

## Build

```sh
cargo build --release
```

## Usage

```
heap-analyser report <coredump> [--libc PATH] [--libc-debug PATH] [--force-libc MAPPED_PATH]
heap-analyser check  --libc PATH [--libc-debug PATH]
```

### `report`

Analyse a core and print the heap report to stdout as JSON.

```sh
heap-analyser report ./core.1234 --libc ./libc.so.6.full
```

- `--libc PATH` — the runtime libc used by the core. If omitted, the mapped
  local libc is used. Without `--libc-debug`, this file must still have symbols.
- `--libc-debug PATH` — matching debuginfo for a stripped `--libc`. Its build-id
  and ELF ABI must match the runtime libc.
- `--force-libc MAPPED_PATH` — trust the mapping whose path is `MAPPED_PATH` as
  libc without verifying its build-id/content. `verified` in the output is then
  `false`.

### `check`

Report whether a given libc exposes the symbols and layout the analyser needs —
useful for confirming you have the right reference file before analysing a core.

```sh
heap-analyser check --libc ./libc.so.6.full
```

`supported: true` means the basic arena/heap/chunk analysis will work. Non-fatal
gaps (e.g. a missing TP-offset relocation, which disables tcache/thread data)
still leave `supported: true` — always read the `problems` array too.

## Getting a usable libc

A production libc is stripped (no symbols) and its runtime relocations live in a
separate debuginfo file. Neither alone is enough:

- the stripped `libc.so.6` has the TLS relocations but no symbols;
- the `*.debug` companion has the symbols but its `.rela.dyn`/`.gnu.version_d`
  are `NOBITS`.

Pass both files directly:

```sh
heap-analyser report core.1234 \
    --libc /usr/lib64/libc.so.6 \
    --libc-debug /usr/lib/debug/.../libc.so.6-<ver>.debug
```

Alternatively, combine them with `eu-unstrip`:

```sh
eu-unstrip /usr/lib64/libc.so.6 \
           /usr/lib/debug/.../libc.so.6-<ver>.debug \
           -o libc.so.6.full
heap-analyser report core.1234 --libc libc.so.6.full
```

`heap-analyser check --libc libc.so.6.full` should then report `supported: true`
with no `missing_relocation` / `unknown_glibc_version` problems.

## Output

`report` prints one JSON document to stdout (`schema_version: 1`). Example, for a
process that kept 7 allocations and freed several chunks — some small ones into
the tcache and a fastbin, plus one larger coalesced chunk that landed in an
ordinary (unsorted/small/large) bin:

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "core_path": "./core.1234",
  "libc": {
    "path": "/usr/lib64/libc.so.6",
    "identity": { "kind": "build_id", "value": "3b82ea8fa1e83533f190fee3263379bed261884a" },
    "verified": true
  },
  "glibc_capabilities": {
    "layout_source": "dwarf",
    "has_tcache": true,
    "has_safe_linking": true,
    "version_source": "gnu_version_d"
  },
  "problems": [],
  "arenas": [
    {
      "index": 0,
      "is_main": true,
      "attached_threads": [1234],
      "heaps": { "count": 1, "total_bytes": 7248, "committed_bytes": 7248 },
      "allocated": {
        "count": 7,
        "bytes": 6584,
        "size_histogram": [
          { "size": 24,   "count": 1, "bytes": 24 },
          { "size": 104,  "count": 1, "bytes": 104 },
          { "size": 200,  "count": 1, "bytes": 200 },
          { "size": 504,  "count": 1, "bytes": 504 },
          { "size": 648,  "count": 1, "bytes": 648 },
          { "size": 1000, "count": 1, "bytes": 1000 },
          { "size": 4104, "count": 1, "bytes": 4104 }
        ]
      },
      "free": {
        "count": 14,
        "bytes": 816,
        "fastbins": [
          { "index": 0, "size": 24, "count": 3, "bytes": 72 }
        ],
        "tcache": {
          "tcache_threads": [1234],
          "bins": [
            { "index": 0, "size": 24, "count": 7, "bytes": 168 },
            { "index": 4, "size": 88, "count": 3, "bytes": 264 }
          ]
        },
        "size_histogram": [
          { "size": 24,  "count": 10, "bytes": 240 },
          { "size": 88,  "count": 3,  "bytes": 264 },
          { "size": 312, "count": 1,  "bytes": 312 }
        ]
      },
      "overhead": { "count": 21, "bytes": 168 }
    }
  ]
}
```

### Field reference

**Top level**

| Field | Meaning |
|---|---|
| `schema_version` | Output schema version; bumped only on a breaking change. |
| `tool_version` | `heap-analyser` version that produced the report. |
| `core_path` | Path of the analysed core dump. |
| `libc` | Which reference libc was used, and how it was matched. |
| `glibc_capabilities` | glibc features detected from the reference libc. |
| `problems` | Recoverable issues (see *Problem kinds*); `[]` means a clean analysis. |
| `arenas` | Per-arena results, `index` 0 first. |

**`libc`**

| Field | Meaning |
|---|---|
| `path` | The libc mapping's path as recorded in the core (`NT_FILE`). |
| `identity.kind` | `build_id` (preferred) or `content_hash` (fallback when the libc has no build-id note). |
| `identity.value` | Lowercase hex: the build-id, or the SHA-256 of the libc's first page. |
| `verified` | `true` if the mapping was matched against the reference libc's identity; `false` if `--force-libc` bypassed the check. |

**`glibc_capabilities`**

| Field | Meaning |
|---|---|
| `layout_source` | `dwarf` when the malloc structure layout came from validated DWARF; otherwise `builtin`. |
| `has_tcache` | tcache present (glibc ≥ 2.26). |
| `has_safe_linking` | free-list pointer mangling in effect (glibc ≥ 2.32); governs whether fastbin/tcache pointers are de-obfuscated. |
| `version_source` | `gnu_version_d` (version read from the libc's `.gnu.version_d`) or `assumed_default` (detection failed; safe-linking assumed on). |

**Each arena**

| Field | Meaning |
|---|---|
| `index` | `0` is the main arena; secondary (per-thread) arenas are `1`, `2`, … |
| `is_main` | Whether this is the main arena. |
| `attached_threads` | Thread IDs currently bound to this arena. |
| `heaps.count` | Number of heap segments in this arena. |
| `heaps.total_bytes` | In-use extent of the arena's heaps, in bytes. |
| `heaps.committed_bytes` | Bytes actually committed (`mprotect`ed); equals `total_bytes` for the main arena. |
| `allocated.count` / `.bytes` | In-use chunks and their **payload** bytes (payload = chunk size − the one-word header). |
| `allocated.size_histogram[]` | Buckets `{ size, count, bytes = size × count }`, ascending by payload size. |
| `free.count` / `.bytes` | Free chunks and payload bytes, across all three sources: tcache, fastbins, and ordinary free chunks (the unsorted/small/large bins and coalesced free space). |
| `free.fastbins[]` | Per fastbin `{ index, size, count, bytes }` (payload `size`); only non-empty bins. |
| `free.tcache.tcache_threads` | Thread IDs owning the tcache entries counted here. |
| `free.tcache.bins[]` | Per tcache bin `{ index, size, count, bytes }`; only non-empty bins. |
| `free.size_histogram[]` | Payload-size buckets over **all** free chunks — all three sources combined. It is *not* just `fastbins` + `tcache`: it also covers ordinary free chunks, which have no dedicated array here, so it can list sizes (like the 312-byte bucket above) that appear in neither `fastbins[]` nor `tcache.bins[]`. |
| `overhead.count` / `.bytes` | Total chunk count and total header overhead (one word per chunk). |

Conventions: all `bytes` under `allocated`/`free`/`*_histogram` are **payload
only** (they exclude the chunk header); `overhead.bytes` is the header total. As
a result `allocated.count + free.count == overhead.count`, and `free.tcache` is
always present with both arrays (empty when there is no tcache).

### Problem kinds

Each entry in `problems` is an object with a `kind` field plus context fields
(`arena`, `thread_id`, `bin_index`, `address`, `size`, `reason`, `symbol`,
`machine` — whichever apply). New non-fatal kinds may be added; consumers should
ignore kinds they do not recognise. The current kinds are:

| `kind` | Meaning | Fatal? |
|---|---|---|
| `missing_symbol` | A required glibc symbol (`main_arena` / `mp_`) is absent. | yes |
| `unsupported_arch` | The core's `e_machine` is not implemented. | yes |
| `duplicate_symbol` | A symbol was defined more than once with differing values; the first was used. | no |
| `missing_relocation` | The TP-offset relocation is absent; tcache / `thread_arena` data can't be read. | no |
| `missing_build_id` | The reference libc has no build-id; identity fell back to a content hash. | no |
| `unknown_glibc_version` | Version detection failed; safe-linking was assumed on. | no |
| `dwarf_layout_fallback` | DWARF layout extraction failed; the built-in layout was retained. | no |
| `fastbin_cycle_detected` | A fastbin chain looped or hit the traversal cap. | no |
| `fastbin_chunk_read_failed` | A fastbin head/node read failed; the bin count is partial. | no |
| `tcache_cycle_detected` | A tcache chain looped or hit the traversal cap. | no |
| `tcache_chunk_read_failed` | A tcache head/node read failed; the bin is partial. | no |
| `duplicate_tcache_entry` | The same chunk appears in two tcache bins/threads (a double-free indicator). | no |
| `chunk_read_failed` | A chunk address was not backed by file content in the core. | no |
| `heap_walk_truncated` | A heap/list walk stopped early (corruption, out-of-region, or a cap); result is partial. | no |
| `stats_inconsistent` | A size bucket's fastbin count exceeded its allocated count (usually a truncated walk). | no |
| `thread_tls_resolution_failed` | A thread's TLS couldn't be resolved; its tcache / arena binding is missing. | no |

A *fatal* problem means the analysis is untrustworthy: `report` exits non-zero
and `check` reports `supported: false`. Non-fatal problems leave a usable report
that simply flags the degraded parts.

Exit codes: `0` on success (including "recovered with non-fatal problems"),
non-zero on a hard failure (bad core, libc not located, required symbol missing).
Hard-failure messages go to stderr; stdout is either a complete JSON document or
empty.

## Development

```sh
cargo test          # unit + integration tests
cargo clippy --all-targets
cargo fmt --check
```

Unit tests drive the heap traversals against synthetic in-memory layouts;
integration tests cover command-line behavior and error handling.

## License

Licensed under the Mulan Permissive Software License, Version 2
([MulanPSL-2.0](LICENSE)).

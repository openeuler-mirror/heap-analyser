# heap-analyser

[English](README.md) | [中文](README.zh.md)

分析 ELF core dump 中的 glibc `malloc` 堆，输出一份机器可读的 JSON 报告：按 arena 汇总的
已分配/空闲统计、尺寸直方图，以及 fastbin 和 tcache 空闲链表的内容。

它从 core 里读取 glibc 的内部结构（`malloc_state`、`_heap_info`、
`tcache_perthread_struct`），因此需要一个**带符号的参考 libc** 来确定这些结构及其字段的位置。

当前验证范围：x86-64 Linux core，glibc 2.38。

## 构建

```sh
cargo build --release
```

## 用法

```
heap-analyser report <coredump> [--libc PATH] [--force-libc MAPPED_PATH]
heap-analyser check  --libc PATH
```

### `report`

分析一个 core，将堆报告以 JSON 形式打印到 stdout。

```sh
heap-analyser report ./core.1234 --libc ./libc.so.6.full
```

- `--libc PATH` —— 用于读取布局/符号的参考 libc。省略时使用 core 里映射的 libc，但这只有在
  本地那个文件仍带符号时才有用（通常不带——见下文*获取一个可用的 libc*）。
- `--force-libc MAPPED_PATH` —— 直接信任路径为 `MAPPED_PATH` 的那个映射为 libc，不校验它的
  build-id/内容。此时输出中的 `verified` 为 `false`。

### `check`

报告某个 libc 是否具备分析器所需的符号与布局——在分析 core 之前，用它确认参考文件是否正确。

```sh
heap-analyser check --libc ./libc.so.6.full
```

`supported: true` 表示基础的 arena/heap/chunk 分析可以进行。非致命的缺口（例如缺少 TP-offset
relocation，会导致 tcache/线程数据不可用）仍会保持 `supported: true`——请务必同时查看
`problems` 数组。

## 获取一个可用的 libc

生产环境的 libc 是 stripped 的（无符号），其运行期 relocation 位于单独的 debuginfo 文件里。
两者单独都不够：

- stripped 的 `libc.so.6` 有 TLS relocation，但没有符号；
- `*.debug` 伴随文件有符号，但其 `.rela.dyn`/`.gnu.version_d` 是 `NOBITS`。

用 `eu-unstrip` 合成：

```sh
eu-unstrip /usr/lib64/libc.so.6 \
           /usr/lib/debug/.../libc.so.6-<ver>.debug \
           -o libc.so.6.full
heap-analyser report core.1234 --libc libc.so.6.full
```

之后 `heap-analyser check --libc libc.so.6.full` 应报告 `supported: true`，且没有
`missing_relocation` / `unknown_glibc_version` 这类 problem。

## 输出

`report` 向 stdout 打印一份 JSON 文档（`schema_version: 1`）。示例（一个进程：保留了 7 个分配，
并释放了若干 chunk——一些小 chunk 进了 tcache 和一个 fastbin，另有一个较大的、已合并的 chunk
落在普通（unsorted/small/large）bin 里）：

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

### 字段说明

**顶层**

| 字段 | 含义 |
|---|---|
| `schema_version` | 输出 schema 版本；仅在发生破坏性变更时递增。 |
| `tool_version` | 产出该报告的 `heap-analyser` 版本。 |
| `core_path` | 被分析的 core dump 路径。 |
| `libc` | 使用了哪个参考 libc，以及是如何匹配上的。 |
| `glibc_capabilities` | 从参考 libc 探测到的 glibc 能力。 |
| `problems` | 可恢复的问题（见*Problem 类型*）；`[]` 表示一次干净的分析。 |
| `arenas` | 按 arena 的结果，`index` 0 在前。 |

**`libc`**

| 字段 | 含义 |
|---|---|
| `path` | 该 libc 映射在 core 里记录的路径（`NT_FILE`）。 |
| `identity.kind` | `build_id`（优先）或 `content_hash`（当 libc 没有 build-id note 时的兜底）。 |
| `identity.value` | 小写十六进制：build-id，或 libc 首页的 SHA-256。 |
| `verified` | 若映射经过参考 libc 身份校验则为 `true`；若被 `--force-libc` 跳过校验则为 `false`。 |

**`glibc_capabilities`**

| 字段 | 含义 |
|---|---|
| `has_tcache` | 存在 tcache（glibc ≥ 2.26）。 |
| `has_safe_linking` | 空闲链表指针混淆生效（glibc ≥ 2.32）；决定是否对 fastbin/tcache 指针做反混淆。 |
| `version_source` | `gnu_version_d`（版本读自 libc 的 `.gnu.version_d`）或 `assumed_default`（探测失败，默认按启用 safe-linking 处理）。 |

**每个 arena**

| 字段 | 含义 |
|---|---|
| `index` | `0` 为 main arena；secondary（每线程）arena 为 `1`、`2`、…… |
| `is_main` | 是否为 main arena。 |
| `attached_threads` | 当前挂靠到该 arena 的线程 ID。 |
| `heaps.count` | 该 arena 的 heap 段数量。 |
| `heaps.total_bytes` | 该 arena 各 heap 的在用字节数之和。 |
| `heaps.committed_bytes` | 实际提交（`mprotect`）的字节数；main arena 下等于 `total_bytes`。 |
| `allocated.count` / `.bytes` | 在用 chunk 数及其 **payload** 字节（payload = chunk 大小 − 一个 word 的头）。 |
| `allocated.size_histogram[]` | 桶 `{ size, count, bytes = size × count }`，按 payload 尺寸升序。 |
| `free.count` / `.bytes` | 空闲 chunk 数及 payload 字节，涵盖全部三个来源：tcache、fastbin，以及普通空闲 chunk（unsorted/small/large bin 与已合并的空闲空间）。 |
| `free.fastbins[]` | 每个 fastbin `{ index, size, count, bytes }`（`size` 为 payload）；只列非空 bin。 |
| `free.tcache.tcache_threads` | 拥有此处所计 tcache 条目的线程 ID。 |
| `free.tcache.bins[]` | 每个 tcache bin `{ index, size, count, bytes }`；只列非空 bin。 |
| `free.size_histogram[]` | 覆盖**全部**空闲 chunk 的 payload 尺寸桶——三个来源合并统计。它**不等于** `fastbins` + `tcache`：普通空闲 chunk 在这里没有单独的数组，因此该直方图可能出现既不在 `fastbins[]`、也不在 `tcache.bins[]` 里的尺寸（如上例中的 312 字节桶）。 |
| `overhead.count` / `.bytes` | chunk 总数，以及头部总开销（每个 chunk 一个 word）。 |

约定：`allocated`/`free`/`*_histogram` 下的所有 `bytes` 都是 **payload 口径**（不含 chunk
头）；`overhead.bytes` 才是头部总量。因此 `allocated.count + free.count == overhead.count`；
`free.tcache` 恒定存在且两个数组都在（没有 tcache 时为空）。

### Problem 类型

`problems` 中的每一项都是一个带 `kind` 字段的对象，外加相应的上下文字段（`arena`、
`thread_id`、`bin_index`、`address`、`size`、`reason`、`symbol`、`machine`——按适用情况）。
各类型：

| `kind` | 含义 | 致命? |
|---|---|---|
| `missing_symbol` | 缺少必需的 glibc 符号（`main_arena` / `mp_`）。 | 是 |
| `unsupported_arch` | core 的 `e_machine` 未实现。 | 是 |
| `duplicate_symbol` | 某符号被定义多次且取值不同；采用第一个。 | 否 |
| `missing_relocation` | 缺少 TP-offset relocation；无法读取 tcache / `thread_arena` 数据。 | 否 |
| `missing_build_id` | 参考 libc 无 build-id；身份退化为内容哈希。 | 否 |
| `unknown_glibc_version` | 版本探测失败；默认按启用 safe-linking 处理。 | 否 |
| `fastbin_cycle_detected` | fastbin 链成环或触及遍历上限。 | 否 |
| `fastbin_chunk_read_failed` | 读取 fastbin 头/节点失败；该 bin 计数为部分结果。 | 否 |
| `tcache_cycle_detected` | tcache 链成环或触及遍历上限。 | 否 |
| `tcache_chunk_read_failed` | 读取 tcache 头/节点失败；该 bin 为部分结果。 | 否 |
| `duplicate_tcache_entry` | 同一 chunk 出现在两个 tcache bin/线程里（double-free 迹象）。 | 否 |
| `chunk_read_failed` | 某 chunk 地址在 core 中没有文件内容支撑。 | 否 |
| `heap_walk_truncated` | 堆/链表遍历提前终止（损坏、越界或触及上限）；结果为部分数据。 | 否 |
| `stats_inconsistent` | 某尺寸桶的 fastbin 计数超过其已分配计数（通常是遍历被截断）。 | 否 |
| `thread_tls_resolution_failed` | 某线程的 TLS 无法解析；其 tcache / arena 归属缺失。 | 否 |

*致命* problem 意味着分析不可信：`report` 以非零码退出，`check` 报告 `supported: false`。
非致命 problem 则给出一份可用的报告，只是把降级的部分标注出来。

退出码：成功（含"带非致命 problem 恢复"）为 `0`；硬失败（core 坏、定位不到 libc、缺必需
符号）为非零。硬失败信息写 stderr；stdout 要么是一份完整的 JSON，要么为空。

## 开发

```sh
cargo test          # 单元测试 + 集成测试
cargo clippy --all-targets
cargo fmt --check
```

单元测试用合成的内存布局驱动堆遍历；集成测试覆盖命令行行为和错误处理。

## 许可证

采用木兰宽松许可证第 2 版（Mulan Permissive Software License, Version 2，
[MulanPSL-2.0](LICENSE)）。

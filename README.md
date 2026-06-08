# memscan

![GitHub issues](https://img.shields.io/github/issues/effjy/memscan)
![GitHub License](https://img.shields.io/github/license/effjy/memscan)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Language](https://img.shields.io/badge/language-C99-blue)

A Linux command-line tool that scans the live memory of a running process and recovers data matching a given byte pattern or magic header. It reads `/proc/<pid>/maps` to enumerate memory regions and `/proc/<pid>/mem` to extract their contents, then prints (or saves) any matching data it finds.

A companion program, `test_target`, is included to demonstrate and verify the scanner against known in-memory data.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Usage](#usage)
  - [Options](#options)
  - [Pattern Formats](#pattern-formats)
- [Examples](#examples)
  - [Scan with the test target](#scan-with-the-test-target)
  - [Search for a plain-text string](#search-for-a-plain-text-string)
  - [Search for a binary magic header](#search-for-a-binary-magic-header)
  - [Scan default file signatures](#scan-default-file-signatures)
  - [Hex dump output](#hex-dump-output)
  - [Restrict to writable memory or an address range](#restrict-to-writable-memory-or-an-address-range)
  - [Limit results and save to a file](#limit-results-and-save-to-a-file)
  - [Scan your own process](#scan-your-own-process)
- [Understanding the Output](#understanding-the-output)
- [Permissions](#permissions)
- [Limitations](#limitations)

---

## How It Works

1. `memscan` opens `/proc/<pid>/maps` to get a list of all memory-mapped regions for the target process, along with their address ranges and permissions.
2. It skips non-readable and special regions (`[vvar]`, `[vdso]`), and optionally filters to writable-only regions or a specific address range.
3. Each eligible region is read in 64 KB chunks via `pread64` on `/proc/<pid>/mem`, with a page-by-page fallback for partial reads.
4. Every chunk is scanned for the specified byte pattern using `memmem` (or a case-insensitive variant).
5. When a match is found, `memscan` re-reads `dump_len` bytes starting at the match address and prints them as either printable ASCII or a classic hex+ASCII dump.

---

## Prerequisites

- **Linux** — memscan relies on the `/proc` filesystem, which is Linux-specific.
- **GCC** (or any C99-compatible compiler).
- **make**.
- **Root / ptrace access** to read another process's memory (see [Permissions](#permissions)).

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install gcc make
```

On Fedora/RHEL:

```bash
sudo dnf install gcc make
```

On Arch Linux:

```bash
sudo pacman -S gcc make
```

---

## Building

Clone or copy the source files into a directory, then run:

```bash
make
```

This produces two binaries:

| Binary | Description |
|---|---|
| `memscan` | The memory scanner |
| `test_target` | A helper process that plants known strings in heap and stack memory |

To remove the compiled binaries:

```bash
make clean
```

---

## Usage

```
memscan -p <pid> [options]
```

`-p` is always required. All other flags are optional.

### Options

| Flag | Argument | Description |
|---|---|---|
| `-p` | `<pid>` \| `self` | PID of the target process to scan. Use `self` to scan memscan's own memory. |
| `-m` | `<pattern>` | Custom pattern to search for (text, `\xHH` escapes, or a `0x…` hex string). |
| `-s` | — | Scan for built-in file magic headers: PNG, PDF, ZIP, ELF, JPEG. |
| `-l` | `<bytes>` | Number of bytes to dump after each match (default: 256). |
| `-x` | — | Output as a hex+ASCII dump instead of plain ASCII. |
| `-w` | — | Scan writable memory regions only (skips read-only segments). |
| `-i`, `-c` | — | Case-insensitive pattern matching. |
| `-r` | `<start>-<end>` | Restrict scan to a hex address range, e.g. `0x7fff0000-0x7fff8000`. |
| `-n` | `<count>` | Stop after the first `<count>` matches. |
| `-o` | `<file>` | Write output to `<file>` instead of stdout. |
| `-v` | — | Print version and exit. |
| `-h` | — | Print help and exit. |

If neither `-m` nor `-s` is given, memscan falls back to the default file-signature patterns automatically.

### Pattern Formats

The `-m` flag accepts three formats:

| Format | Example | Matches |
|---|---|---|
| Plain text | `MY_MAGIC_SECRET` | The literal ASCII bytes of that string |
| Escape sequences | `\x89PNG\r\n\x1a\n` | Mixed binary/text bytes |
| Raw hex string | `0x89504e470d0a1a0a` | The PNG magic header as a hex blob |

---

## Examples

### Scan with the test target

`test_target` allocates a PNG magic header followed by a secret string on the heap, and a custom text marker followed by a password on the stack. It then sleeps for 300 seconds, keeping both buffers live.

**Terminal 1** — start the target:

```bash
./test_target
```

```
Test Target PID: 48271
Secret strings have been initialized in memory.
- Heap address: 0x55a3f1c2a6b0
- Stack address: 0x7ffde3b1a240

Sleeping for 300 seconds to keep memory alive...
```

**Terminal 2** — scan for the PNG header in the heap:

```bash
sudo ./memscan -p 48271 -m '\x89PNG\r\n\x1a\n'
```

**Terminal 2** — scan for the custom stack marker:

```bash
sudo ./memscan -p 48271 -m 'MY_MAGIC_SECRET_123'
```

---

### Search for a plain-text string

```bash
sudo ./memscan -p 48271 -m 'SuperSecret'
```

Add `-i` for a case-insensitive search:

```bash
sudo ./memscan -p 48271 -m 'supersecret' -i
```

---

### Search for a binary magic header

Using `\x` escape notation:

```bash
sudo ./memscan -p 48271 -m '\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
```

Using the `0x` hex blob notation:

```bash
sudo ./memscan -p 48271 -m '0x89504e470d0a1a0a'
```

---

### Scan default file signatures

Search for PNG, PDF, ZIP, ELF, and JPEG headers all at once:

```bash
sudo ./memscan -p 48271 -s
```

---

### Hex dump output

Show 512 bytes after each match in classic hex+ASCII format:

```bash
sudo ./memscan -p 48271 -m '\x89PNG\r\n\x1a\n' -x -l 512
```

---

### Restrict to writable memory or an address range

Writable regions only (heap, stack, anonymous mappings):

```bash
sudo ./memscan -p 48271 -m 'SECRET' -w
```

Specific address range (addresses printed by `test_target` can be used here):

```bash
sudo ./memscan -p 48271 -m 'SECRET' -r 0x7ffd00000000-0x7ffe00000000
```

---

### Limit results and save to a file

Stop after the first 3 matches and write results to `results.txt`:

```bash
sudo ./memscan -p 48271 -s -n 3 -o results.txt
```

---

### Scan your own process

`memscan` contains a compile-time self-test string. You can find it in its own memory without needing a second process:

```bash
./memscan -p self -m 'MEMSCAN_SELFTEST_STRING_9999_SECRET_DATA_xyz_12345!'
```

No `sudo` is required when scanning your own process.

---

## Understanding the Output

Each match is printed as a block like this:

```
[MATCH #1] Address: 0x55a3f1c2a6b8 | Region: [heap] (rw-p) | Offset: +0x6b8 | Pattern: PNG Image
--- Recovered Data (256 bytes) ---
.PNG.....HEAP_DATA: This is a secret message hidden inside a simulated PNG file in process heap memory! Recovered successfully...
----------------------------------
```

| Field | Meaning |
|---|---|
| `MATCH #N` | Sequential match counter |
| `Address` | Exact virtual address where the pattern was found |
| `Region` | The mapped file or label (`[heap]`, `[stack]`, `[anon]`, or a shared library path) |
| `(rw-p)` | Memory region permissions: read / write / execute / private or shared |
| `Offset` | Byte offset from the start of that memory region |
| `Pattern` | Which pattern triggered this match |
| Recovered Data | The raw bytes starting at the match address, rendered as ASCII or hex |

Non-printable bytes are shown as `.` in ASCII mode.

---

## Permissions

Reading another process's memory via `/proc/<pid>/mem` requires either:

- Running memscan as **root** (`sudo ./memscan …`), or
- Having `CAP_SYS_PTRACE` capability, or
- The target process being owned by the same user **and** the system's ptrace scope allowing it.

On systems with a restrictive ptrace scope (common on Ubuntu), check:

```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

A value of `1` or higher will block cross-process reads by non-root users. To temporarily allow it (until the next reboot):

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

Scanning your own process (`-p self`) never requires elevated privileges.

---

## Limitations

- **Linux only.** The `/proc` filesystem interface used here does not exist on macOS, Windows, or BSD systems.
- **64-bit address space.** Built with `-D_FILE_OFFSET_BITS=64` for large address support; 32-bit targets are not tested.
- **Kernel-managed regions skipped.** `[vvar]` and `[vdso]` regions are excluded, as they cannot be read via `/proc/mem`.
- **No write support.** memscan is read-only; it cannot modify process memory.
- **ASLR.** Address Space Layout Randomization means heap and stack addresses change on every run. Use the addresses printed by `test_target` at startup when restricting with `-r`.

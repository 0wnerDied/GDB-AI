# Linux kernel debugging

The `linux-kernel` provider is enabled by default and runs above the ordinary
GDB/MI remote target. Set `security.kernel_enabled=false` to disable it. Typed
task traversal requires a trusted, matching `vmlinux`. An x86-64 QEMU stub can
also provide the bounded symbol-free bootstrap and module views below. GDB/AI
does not auto-load target scripts or invent typed symbols.

`gdb_kernel` exposes two actions. Requesting `dmesg` may execute the exact
[`vmlinux-gdb.py` companion](https://docs.kernel.org/dev-tools/gdb-kernel-debugging.html)
generated beside the current `vmlinux`; no separate configuration is required:

- `inspect` returns bounded semantic observations;
- `monitor` runs only the first-word verbs in `security.monitor_allowlist`,
  records the raw operation, and leaves the session tainted after managed
  reconciliation.

The `inspect` views are:

| View | Result |
| --- | --- |
| `bootstrap` | Symbol-free x86-64 image; optional `names` also return exact symbols, current tasks, and loaded modules |
| `symbols` | Exact requested runtime kallsyms and per-CPU current tasks |
| `page_table` | x86-64 virtual-to-physical walk, raw entries, page size, and effective permissions |
| `capabilities` | Architecture, transport, symbol mode, task strategy, and monitor limits |
| `version` | Bounded `linux_banner` text |
| `base` | Runtime `_text` address for synchronized symbols |
| `current_task` | Current CPU task pointer |
| `init_task` | Address of the initial task |
| `tasks` | Paged `task_struct.tasks` traversal with PID, TGID, name, and current marker |
| `modules` | Paged typed or symbol-free module list with address, name, runtime base, size, and segments |
| `dmesg` | Bounded tail of the kernel log through matching Linux GDB helpers |
| `stack` | Bounded kernel stack frames |
| `panic` | Standard bounded stop snapshot with kernel provenance |

On x86-64, `current_task` is a per-CPU offset and is resolved from `$gs_base`.
On AArch64, the provider uses `$sp_el0`. Task traversal uses debug type
information from `vmlinux`. Module inspection supports both the legacy
`core_layout` and Linux 6.4-or-newer `mem[]` layouts.

When an x86-64 QEMU target is stopped without usable `vmlinux` symbols,
`bootstrap` compacts QEMU's memory map and a bounded GDB search into the runtime
kernel image range, Linux version, and possible module mappings. At a KPTI
userspace stop it reads through Linux's paired kernel page table for the
observation and restores the original CR3 before returning. The `base` and
`version` views use the same fallback automatically. When `bootstrap` includes
`names`, the same in-GDB scan also follows the kernel module list and correlates
each module's memory layout with those mappings.

`page_table` accepts one `address_expression` such as `$pc`, a symbol, or a
runtime address. On an x86-64 QEMU stub it returns every 4-level or 5-level
entry, resolves 4 KiB, 2 MiB, and 1 GiB leaves, and reports the final physical
address plus effective user, writable, and executable permissions. A missing
kernel mapping under KPTI is retried through the paired kernel PGD. QEMU's
physical-memory RSP mode is restored before the call returns.

`symbols` decodes the in-memory compressed kallsyms table inside GDB and returns
only exact names requested by the Agent. It also derives every CPU's current
task from `pcpu_hot` or `current_task`, `$gs_base`, and `init_task`'s live
`comm` offset. `bootstrap` accepts the same optional `names` array so one call
can return layout, symbols, and current tasks. No runtime address is cached
across boots. This path is verified on Linux 5.15, 6.1, 6.6, 6.12, 6.13,
6.15, and 7.2 x86-64 distribution kernels, including split text/rodata
mappings.

The symbol-free module path returns the stable module address and inline name,
then validates legacy `core_layout` or current `module_memory` bases against
QEMU's live mappings. It is verified with multiple Debian modules on Linux 6.1
and 6.12, multiple Arch modules across the Linux 6.13, 6.15, and 7.2 layout
transitions, and a randomized module layout where GEF's module commands fail.

`gdb_probe` accepts `kernel_module_offset` with a module name and text-relative
hexadecimal offset. From a stopped kernel context, one call discovers the live
module, validates the offset against its executable segment, arms the temporary
breakpoint, runs, captures the attributed stop, and removes the breakpoint.
QEMU serial or network activity is an external trigger: supply a no-shell
`trigger.command` to start it after the breakpoint is armed, or coordinate an
existing process concurrently; `input` remains inferior PTY data.

The implementation follows the useful semantic boundaries demonstrated by
[bata24/gef](https://github.com/bata24/gef): symbol-free QEMU bootstrap,
architecture-specific current-task resolution, bounded task traversal, and
explicit kernel base/version data. It cross-checks symbol/type-based traversal
against [pwndbg](https://github.com/pwndbg/pwndbg). Neither project is loaded
into GDB or linked as a runtime dependency.

[Hex-Rays rax](https://github.com/HexRaysSA/rax) is a useful future RSP
interoperability and checkpoint-safe-point test target. It is not required by
the provider; QEMU and public Debian and Arch Linux artifacts are the current
release oracles.

## Verification

The kernel integration test boots a public Debian kernel under QEMU TCG,
stops at `start_kernel`, checks the semantic views, loads a real signed module
from a generated initramfs, and captures the subsequent kernel panic. Required
runs set:

```text
GDB_AI_REQUIRE_KERNEL_INTEGRATION=1
GDB_AI_KERNEL_IMAGE=/path/to/vmlinuz
GDB_AI_KERNEL_VMLINUX=/path/to/vmlinux
GDB_AI_KERNEL_MODULE=/path/to/irqbypass.ko
```

The image, debug symbols, and module must come from the same distribution
build. The test also requires `busybox`, `cpio`, GDB or gdb-multiarch, and the
matching `qemu-system-x86_64` or `qemu-system-aarch64` executable.

To verify a separately running symbol-free x86-64 QEMU gdbstub, run:

```sh
GDB_AI_KERNEL_RSP_ENDPOINT=127.0.0.1:1234 \
  cargo test -p gdb-ai-core --test kernel \
  bootstraps_a_symbol_free_modern_kernel_over_qemu_rsp -- --exact
```

When the stub is stopped in KPTI userspace, add
`GDB_AI_KERNEL_EXPECT_PAGE_TABLE=paired-kernel`; the repeated bootstrap also
checks that the temporary kernel CR3 was restored. Set
`GDB_AI_KERNEL_COMMAND_TIMEOUT_MS=1000` to verify that the bounded kernel scan
is not cut off by a shorter generic MI deadline.

If that guest has a loaded module whose code can be triggered independently,
add `GDB_AI_KERNEL_EXPECT_MODULE=name` and
`GDB_AI_KERNEL_PROBE_OFFSET=0xTEXT_OFFSET`. Trigger the module through the QEMU
serial console or network while the test waits; the check requires a real
attributed breakpoint hit and validates cleanup.

Required CI uses `tests/kernel/fetch-debian-kernel.sh` to verify pinned,
checksum-validated Debian 6.1 and 6.12 x86-64 builds plus Debian 6.12
AArch64. These exercise both architecture-specific current-task mechanisms
and the legacy `core_layout` and current `module_memory` representations.

Kernel debugging exposes complete guest memory and register state. Bind remote
stubs only on an authorized network boundary and treat transcripts, monitor
output, snapshots, and memory artifacts as sensitive.

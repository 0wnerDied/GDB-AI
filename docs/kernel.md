# Linux kernel debugging

The conditional `linux-kernel` provider runs above the ordinary GDB/MI remote
target. Typed task and module views require a trusted, matching `vmlinux`.
An x86-64 QEMU stub can also provide the bounded symbol-free bootstrap below.
GDB/AI does not auto-load target scripts or invent typed symbols.

`gdb_kernel` exposes two actions:

- `inspect` returns bounded semantic observations;
- `monitor` runs only the first-word verbs in `security.monitor_allowlist`,
  records the raw operation, and leaves the session tainted after managed
  reconciliation.

The `inspect` views are:

| View | Result |
| --- | --- |
| `bootstrap` | Symbol-free x86-64 QEMU image segments, version, module candidates, plus optional exact `names` |
| `symbols` | Exact requested runtime kallsyms and per-CPU current tasks |
| `capabilities` | Architecture, transport, symbol mode, task strategy, and monitor limits |
| `version` | Bounded `linux_banner` text |
| `base` | Runtime `_text` address for synchronized symbols |
| `current_task` | Current CPU task pointer |
| `init_task` | Address of the initial task |
| `tasks` | Paged `task_struct.tasks` traversal with PID, TGID, name, and current marker |
| `modules` | Paged module list with address, name, runtime base, and size |
| `stack` | Bounded kernel stack frames |
| `panic` | Standard bounded stop snapshot with kernel provenance |

On x86-64, `current_task` is a per-CPU offset and is resolved from `$gs_base`.
On AArch64, the provider uses `$sp_el0`. Task traversal uses debug type
information from `vmlinux`. Module inspection supports both the legacy
`core_layout` and Linux 6.4-or-newer `mem[]` layouts.

When an x86-64 QEMU target is stopped in kernel context without usable
`vmlinux` symbols, `bootstrap` compacts QEMU's memory map and a bounded GDB
search into the runtime kernel image range, Linux version, and possible module
mappings. The `base` and `version` views use the same fallback automatically.
Candidate module mappings are intentionally unnamed until typed symbols or a
kernel module list can prove their identity.

`symbols` decodes the in-memory compressed kallsyms table inside GDB and returns
only exact names requested by the Agent. It also derives every CPU's current
task from `pcpu_hot` or `current_task`, `$gs_base`, and `init_task`'s live
`comm` offset. `bootstrap` accepts the same optional `names` array so one call
can return layout, symbols, and current tasks. No runtime address is cached
across boots. This path is verified on Linux 5.15, 6.1, 6.6, 6.12, and 7.2
x86-64 distribution kernels, including split text/rodata mappings.

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

Required CI uses `tests/kernel/fetch-debian-kernel.sh` to verify pinned,
checksum-validated Debian 6.1 and 6.12 x86-64 builds plus Debian 6.12
AArch64. These exercise both architecture-specific current-task mechanisms
and the legacy `core_layout` and current `module_memory` representations.

Kernel debugging exposes complete guest memory and register state. Bind remote
stubs only on an authorized network boundary and treat transcripts, monitor
output, snapshots, and memory artifacts as sensitive.

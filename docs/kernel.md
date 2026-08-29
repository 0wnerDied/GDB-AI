# Linux kernel debugging

The conditional `linux-kernel` provider runs above the ordinary GDB/MI remote
target. Enable it only for a QEMU GDB stub or KGDB session configured with a
trusted, matching `vmlinux`. GDB/AI does not auto-load target scripts and does
not scan arbitrary kernel memory to invent missing symbols.

`gdb_kernel` exposes two actions:

- `inspect` returns bounded semantic observations;
- `monitor` runs only the first-word verbs in `security.monitor_allowlist`,
  records the raw operation, and leaves the session tainted after managed
  reconciliation.

The `inspect` views are:

| View | Result |
| --- | --- |
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

The implementation follows the useful semantic boundaries demonstrated by
[bata24/gef](https://github.com/bata24/gef): architecture-specific current-task
resolution, bounded task traversal, explicit kernel base/version data, and an
allowlisted QEMU monitor. It cross-checks symbol/type-based traversal against
[pwndbg](https://github.com/pwndbg/pwndbg). Neither project is loaded into GDB
or linked as a runtime dependency.

[Hex-Rays rax](https://github.com/HexRaysSA/rax) is a useful future RSP
interoperability and checkpoint-safe-point test target. It is not required by
the provider; QEMU and public Debian distribution artifacts are the current
release oracle.

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

Required CI uses `tests/kernel/fetch-debian-kernel.sh` to verify pinned,
checksum-validated Debian 6.1 and 6.12 x86-64 builds plus Debian 6.12
AArch64. These exercise both architecture-specific current-task mechanisms
and the legacy `core_layout` and current `module_memory` representations.

Kernel debugging exposes complete guest memory and register state. Bind remote
stubs only on an authorized network boundary and treat transcripts, monitor
output, snapshots, and memory artifacts as sensitive.

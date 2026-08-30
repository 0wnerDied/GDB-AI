# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

## Qualification matrix

- Required CI builds checksum-pinned GDB 9.2, 10.2, 11.2, and 12.1 for MI3 and
  GDB 13.2, 14.2, 15.2, 16.3, and 17.2 for MI4. Every lane runs the same
  local-launch vertical test.
- The locked workspace suite covers native launch, attach, core, gdbserver,
  raw reconciliation, tracked state, Agent operations, public session
  lifecycle, delayed-result, disconnect, storage-failure, and noisy-PTY paths.
- AArch64 qualification includes qemu-user RSP inspection and a native Debian
  VM running launch, attach, core, and gdbserver scenarios.
- QEMU TCG jobs use checksum-pinned Debian 6.1.176 and 6.12.105 x86-64 kernels
  plus Debian 6.12.105 AArch64. They exercise architecture-specific
  current-task resolution, both module layouts, tasks, stacks, panic context,
  and allowlisted monitor commands.
- The required toolchain is Rust 1.88.0. Schema hashes, both SDKs, and bounded
  libFuzzer campaigns for the MI parser, MI framer, and state reducer are also
  required checks.
- A separate tag-only lifecycle soak exercises 10,000 session create, launch,
  stop, and close cycles. It is diagnostic evidence and does not gate release
  bundle creation.

The release bundle depends on the required workspace, compatibility,
AArch64, and kernel jobs. Whether a particular commit or tag passed those
lanes is recorded by GitHub Actions and the release attestation; results from
one source revision are not evidence for another.

Missing host facilities remain explicitly unavailable or conditional; they
are never converted to success merely because another matrix entry passed.

## Native GDB/MI compatibility

GDB/AI uses only interfaces present in the supported GDB 9 through 17 release
lines:

- GDB 9.1 through 12.1 register `mi1`, `mi2`, `mi3`, and the latest-version
  `mi` alias. GDB 13.1 and 13.2 additionally register `mi4`; GDB 14.1 removes
  the obsolete MI1 interpreter. The `mi` alias maps to MI3 before GDB 13.1
  and MI4 from GDB 13.1 onward. GDB/AI deliberately requests MI3 or MI4 and
  makes no MI1 or MI2 compatibility claim.
- MI3 changes multi-location breakpoint output from a tuple-like legacy form
  to a list. MI4 changes the breakpoint `script` field to a valid list. These
  are output-format versions over the same native command dispatcher.
- The built-in command inventory is unchanged across point releases. GDB 13.1
  adds only `-fix-breakpoint-script-output` to the 123 commands present in
  GDB 9.1 through 12.1.
- Every standard MI command emitted by GDB/AI is present throughout the
  supported release range. GDB exposes `catch exec`, `catch fork`, `catch
  vfork`, and `catch syscall` only as CLI commands, so their structured
  adapter uses controlled `-interpreter-exec console` rather than inventing
  non-existent MI commands.

Runtime qualification builds the latest supported maintenance release in each
major line. Unknown fields and future informational notifications remain
bounded and preserved rather than causing strict-version deserialization
failures.

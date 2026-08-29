# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

## Verified on 2026-08-29

- Required CI
  [run 33225096633](https://github.com/0wnerDied/GDB-AI/actions/runs/33225096633)
  passed at functional baseline `4195050`.
- The matrix built checksum-pinned GDB 9.2, 10.2, 11.2, and 12.1 for MI3 and
  GDB 13.2, 14.2, 15.2, 16.3, and 17.1 for MI4. Every version passed the same
  local-launch vertical test.
- The full locked workspace passed native launch, attach, core, gdbserver,
  raw reconciliation, tracked state, Agent operations, public session
  lifecycle, delayed-result, disconnect, storage-failure, and noisy-PTY paths.
- AArch64 passed qemu-user RSP inspection and a native Debian VM running
  launch, attach, core, and gdbserver scenarios.
- QEMU TCG tests passed checksum-pinned Debian 6.1.176 and 6.12.105 x86-64
  kernels plus Debian 6.12.105 AArch64. They exercise architecture-specific
  current-task resolution, both module layouts, tasks, stacks, panic context,
  and allowlisted monitor commands.
- Rust 1.88, stable Rust, schemas, both SDKs, and 60-second libFuzzer campaigns
  for the MI parser, MI framer, and state reducer passed required CI.
- A local 10,000-cycle session lifecycle soak completed in 777.71 seconds
  with no session, startup, parser, timeout, or consistency failure.

Repeated paired Agent A/B/C/D effect evaluation is explicitly deferred. It is
future product research, not a compatibility or correctness gate. Publishing
a release tag still requires artifact hashes and provenance for that tag.

Missing host facilities remain explicitly unavailable or conditional; they
are never converted to success merely because another matrix entry passed.

## Native GDB/MI release audit

The adjacent binutils-gdb source checkout was audited at every available GDB
9 through 17 release tag: 9.1, 9.2, 10.1, 10.2, 11.1, 11.2, 12.1, 13.1,
13.2, 14.1, 14.2, 15.1, 15.2, 16.1, 16.2, 16.3, 17.1, and 17.2.

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

Runtime qualification intentionally builds the latest maintenance release in
each supported major line instead of rebuilding interface-identical point
releases. The current matrix advances the GDB 17 lane to checksum-pinned 17.2;
the source audit above covers both 17.1 and 17.2. The official 17.2 source was
also built in the pinned Ubuntu 24.04 image and passed the same vertical test
locally with MI4.

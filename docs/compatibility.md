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

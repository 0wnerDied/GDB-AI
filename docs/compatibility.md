# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

## Verified on 2026-08-28

- Required CI run
  [33155226125](https://github.com/0wnerDied/GDB-AI/actions/runs/33155226125)
  passed at implementation baseline `9648037` with Ubuntu GDB and gdbserver
  15.1.
- Local GDB and gdbserver 17.1 passed the full locked workspace tests,
  including native launch, attach, core, gdbserver, raw reconciliation,
  tracked state, Agent operations, and public session lifecycle paths.
- The fresh-process MI3 fallback path is tested, but has not yet run against
  an actual GDB 9-12 binary.
- QEMU TCG tests passed with checksum-pinned Debian 6.1.176 and 6.12.105
  x86-64 kernels. They exercise legacy `core_layout`, current
  `module_memory`, tasks, stacks, panic context, and allowlisted monitor
  commands.
- Rust 1.88, stable Rust, schemas, Python and TypeScript SDKs, and all three
  fuzz targets compile in required CI.

## Qualification still open

- Real GDB 9-12 MI3 and GDB 13, 14, and 16 MI4 runs;
- AArch64 user-space, remote, core, register-role, and kernel paths;
- executed libFuzzer campaigns rather than target compilation alone;
- delayed-result, disconnect, storage-failure, and noisy-I/O chaos runs;
- the 10,000-cycle session lifecycle soak;
- repeated paired Agent A/B/C/D effect evaluation; and
- release artifact hashes and provenance tied to a release tag.

The architecture and capability model contain these paths, but an open item
is not reported as a verified host capability. Missing host facilities remain
explicitly unavailable or conditional; they are never converted to success.

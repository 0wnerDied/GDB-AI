# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

## Verified on 2026-08-29

- Required CI run
  [33188007777](https://github.com/0wnerDied/GDB-AI/actions/runs/33188007777)
  passed at implementation baseline `bec8b12` with Ubuntu GDB and gdbserver
  15.1.
- Local GDB and gdbserver 17.1 passed the full locked workspace tests,
  including native launch, attach, core, gdbserver, raw reconciliation,
  tracked state, Agent operations, and public session lifecycle paths.
- A local Docker matrix built checksum-pinned GDB 9.2, 10.2, 11.2, and 12.1
  for MI3 and GDB 13.2, 14.2, 15.2, 16.3, and 17.1 for MI4. Every version
  passed the same local-launch vertical test.
- AArch64 user-space debugging passed through qemu-user RSP and
  gdb-multiarch, including a function breakpoint, resume, semantic register
  roles, and disassembly.
- QEMU TCG tests passed with checksum-pinned Debian 6.1.176 and 6.12.105
  x86-64 kernels. They exercise legacy `core_layout`, current
  `module_memory`, tasks, stacks, panic context, and allowlisted monitor
  commands.
- Rust 1.88, stable Rust, schemas, and the Python and TypeScript SDKs passed
  required CI.
- Required CI ran 60-second libFuzzer campaigns under
  `nightly-2026-08-01` for the MI parser, MI framer, and state reducer. They
  completed 5,846,778, 549,776, and 2,418,486 executions respectively with
  no crash or reducer invariant failure.

## Qualification still open

- AArch64 native-host, core, gdbserver, and kernel paths;
- delayed-result, disconnect, storage-failure, and noisy-I/O chaos runs;
- the 10,000-cycle session lifecycle soak;
- repeated paired Agent A/B/C/D effect evaluation; and
- release artifact hashes and provenance tied to a release tag.

The architecture and capability model contain these paths, but an open item
is not reported as a verified host capability. Missing host facilities remain
explicitly unavailable or conditional; they are never converted to success.

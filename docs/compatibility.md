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

## Runtime coverage

Native debugging and runtime-language decoding have separate requirements.
Matching executables, libraries, symbols, and runtime helpers must be supplied
by the caller; launching an interpreter does not provide its language frames
or object model automatically.

The runtime compatibility target is the Agent debugging capability provided
by the same native GDB build. Use the structured tools for common operations.
Start the server with `--raw-admin` to expose GDB console commands such as
`source` for the runtime's own GDB helpers; new sessions then use that
authority without another profile selection. Helpers execute inside the
session's GDB process and retain its host permissions. A console tool call
returns its own `console`, `target` and `log` output, so helper output does not
require a later ring-buffer read. GDB JIT registration remains GDB's own
mechanism; GDB/AI does not replace it with a language-specific backend.

| Target | Current interface | Verification boundary |
| --- | --- | --- |
| Linux user space | Native threads, stacks, values, memory, control, attach and cores | Required native and remote integration tests; multithreaded frame and deadlock inspection |
| Linux kernel | Native remote debugging plus tasks, modules, symbols, stacks and kernel views | Pinned QEMU kernel lanes described above |
| V8 / Node.js | Native engine symbols, threads, memory and type layouts when GDB has the matching debug information | Paired native GDB/MCP V8 isolate-initialization breakpoint, stack, helper and exit checks |
| PHP / CGI | Native interpreter or CGI executable debugging through the ordinary target interface | Paired native GDB/MCP request-startup checks for CLI and CGI |
| LLVM / Clang | Native compiler debugging and GDB-compatible symbols in compiled or JIT-generated programs | Paired Clang native and LLVM MCJIT breakpoint, stack, helper and exit checks |

Thread inspection with `stack_depth` uses the same MI stack commands as
single-thread inspection and keeps all returned frames at one stop. Per-thread
unwind errors are returned on that thread; missing symbols are not inferred.

With GDB, Clang, LLVM `lli`, Node.js, PHP CLI and PHP CGI installed, reproduce
the runtime lane with:

```sh
cargo build --locked -p gdb-ai
python3 tests/runtimes/verify.py target/debug/gdb-ai
```

Use `--gdb`, `--clang`, `--lli`, `--node`, `--php`, and `--php-cgi` to select
matching installed builds. `--library-path` supplies a target library path
for unpacked runtimes. The check uses temporary targets and one MCP connection,
matches the same native breakpoint in both interfaces, reads its stack, runs
a GDB command helper, and verifies normal exit and exact target output. It
does not claim language features or JIT modes unsupported by that GDB/runtime
combination.

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

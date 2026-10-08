# Compatibility

MI4 is preferred and MI3 starts in a fresh fallback GDB process. Capability
support is probed with MI commands and refreshed after launch, attach, core,
or remote target selection. Unknown MI fields and classes are retained; an
unknown state-changing event taints consistency instead of being guessed.

## Qualification matrix

- Required CI builds checksum-pinned GDB 9.2, 10.2, 11.2, and 12.1 for MI3 and
  GDB 13.2, 14.2, 15.2, 16.3, and 17.2 for MI4. Every lane runs the same
  local-launch vertical test and a forced-MI3 breakpoint-script and journal
  replay regression, covering both native correction and legacy parsing.
  Stripped and separate-debug targets also verify start policies and missing
  frame debug information against every qualified GDB version.
- The locked workspace suite covers native launch, attach, core, gdbserver,
  raw reconciliation, tracked state, Agent operations, public session
  lifecycle, delayed-result, disconnect, storage-failure, and noisy-PTY paths.
- AArch64 qualification includes qemu-user RSP inspection, a bare-metal ELF
  under qemu-system RSP, and a native Debian VM running launch, attach, core,
  and gdbserver scenarios.
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

## Debug information

GDB separates linker symbols from debugging information. A retained function
name can support a breakpoint or disassembly while its arguments, locals,
types, and source remain unavailable. A missing name does not prevent exact
address, register, memory, or instruction reads. Stack unwinding depends on
the target's unwind information and GDB's architecture support.

Matching separate debug files restore the information through GDB's native
[build ID and `.gnu_debuglink` lookup](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Separate-Debug-Files.html).
Install the distribution's matching debug package or place the debug file in
GDB's search path. With raw administration enabled, `set debug-file-directory`
can select an unpacked local debug tree before target selection. Debuginfod
and target script auto-loading are disabled at session startup.

`stop: "main"` stops at `main` when GDB can resolve it. Otherwise launch or
restart stops at the main executable's relocated ELF entry and reports
`start_policy: "program_entry"`. This also works for stripped PIE binaries.
`first_instruction` retains GDB's `starti` behavior, which can stop in the
dynamic loader. Use `none` to observe a requested breakpoint, signal, or
exit. Explicit pending breakpoints remain available.
An empty locals result is checked at its original thread, frame, and stop:
missing debug information returns `CAPABILITY_MISSING`; a scope with debug
information and no variables returns an empty list. Composite captures retain
other facts and report the unavailable locals as incomplete evidence.

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
returns its own `console`, `target`, and `log` output plus a bounded inferior
PTY delta in `output`. Helpers that print through the inferior can therefore
return their result in the same call. `output.source` identifies the PTY;
`output.requested_offset` and `output.next_offset` identify the observed
interval. It includes any PTY writer in that interval. Follow the cursor with
`gdb_io` when `output.truncated` is true, and check `output.gap` for lost bytes.

[GDB JIT registration](https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html)
remains GDB's own mechanism. A runtime must register suitable debug objects;
launching a JIT runtime alone does not guarantee generated function names,
source, types, or unwind information.

| Target | Current interface | Verification boundary |
| --- | --- | --- |
| Linux user space | Native threads, stacks, values, memory, control, attach and cores | Required native and remote integration tests; multithreaded frame and deadlock inspection |
| Linux kernel | Native remote debugging plus tasks, modules, symbols, stacks and kernel views | Pinned QEMU kernel lanes; typed task and module pages require GDB Python |
| V8 / Node.js / d8 | Native engine symbols and types; caller-supplied V8 helpers and runtime JIT registration | Paired native GDB/MCP engine stops; optional d8 `jstc` language-stack checks with a matching helper |
| PHP / CGI | Native interpreter debugging; caller-supplied PHP helpers | Paired CLI and CGI native stops; optional PHP `zbacktrace` language-stack checks with matching debug files and helper |
| LLVM / Clang | Native compiler debugging and GDB-compatible symbols in compiled or JIT-generated programs | Paired Clang native and LLVM MCJIT breakpoint, stack, helper and exit checks |
| Remote firmware | GDB RSP control, registers, exact memory, and disassembly with a matching ELF | Bare-metal AArch64 QEMU test; host process mappings and inferior PTY are unavailable |

PHP and d8 execute as host processes, while their language frames and values
belong to their respective virtual machines. Use native observations to
establish the engine stop, then the matching
[PHP helper](https://github.com/php/php-src/blob/master/.gdbinit) or
[V8 helper](https://github.com/v8/v8/blob/main/tools/gdbinit) for that language
layer. Select the helper from the exact runtime source revision. Helpers that
call inferior functions require an explicit raw `set may-call-functions on`;
the startup default remains off. Such calls can execute target code and are
not read-only observations.

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
matching installed builds. Add `--d8 /path/to/d8` for the V8 shell,
`--d8-helper /path/to/v8/tools/gdbinit` or
`--php-helper /path/to/php-src/.gdbinit` for actual language-stack checks,
and `--debug-file-directory /path/to/usr/lib/debug` for matching separate
symbols. `--library-path` supplies a target library path for unpacked
runtimes. The check uses temporary targets and one MCP connection,
matches the same native breakpoint in both interfaces, reads its stack, runs
a GDB command helper, and verifies normal exit and exact target output. It
does not claim language features or JIT modes unsupported by that GDB/runtime
combination.

## Remote and bare-metal targets

Start with `--advanced-tools`, allowlist the remote endpoint, and use
`gdb_session` action `connect_remote` with `endpoint` and the local matching
`executable`. GDB's selected target supplies its architecture, register set,
memory access, breakpoint support, and execution control. Bare-metal targets
need no `main`, host PID, process map, or stdin; remote serial and monitor
output are not inferior PTY bytes. Select register, memory, disassembly, and
stack observations that the stub and ELF can provide.

Reproduce the bare-metal lane with the cross compiler, `gdb-multiarch`, and
`qemu-system-aarch64` installed:

```sh
GDB_AI_REQUIRE_INTEGRATION=1 cargo test --locked -p gdb-ai-core --test aarch64 \
  debugs_bare_metal_aarch64_over_rsp -- --ignored --exact
```

[RAX](https://github.com/HexRaysSA/rax) provides another GDB RSP implementation,
but has not been qualified by this suite. Its
[whole-machine checkpoints](https://github.com/HexRaysSA/rax/blob/main/docs/operations/checkpoints.md)
restore emulator state. GDB/AI observation snapshots retain debugger facts,
and journal replay reconstructs controller evidence; neither restores a
running process or machine. QEMU-specific kernel monitor and physical-memory
features require those actual stub capabilities, rather than RSP connectivity
alone.

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
- MI3 sessions enable GDB's breakpoint-script format correction when that
  command is available. On older GDBs, the parser accepts the legacy `script`
  string tuple as a command list without relaxing other tuple syntax. Live
  results and journal replay use the same normalization; the journal retains
  the original MI bytes.
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

# GDB/AI active release plan

Status: North-star implementation and release gates G1-G4 complete; release
provenance and maintainability work remain

`GDB/AI` means **GDB Agent Interface**. It runs above GNU GDB and GDB/MI to
give modern Agents a stateful interface for dynamic debugging, vulnerability
validation, and authorized vulnerability exploitation. GDB/MI is GNU GDB's
backend protocol; this project does not define it.

This file contains only unfinished work. The complete North-star design is in
the [architecture archive](docs/archive/north-star-plan-2026-08-29.md).
Completed MCP/HTTP, evidence, protocol, policy, and storage gates are in the
[G1-G4 archive](docs/archive/release-gates-g1-g4-2026-08-29.md).

The `gdb.ai/v1` namespace identifies the protocol major version. It does not
by itself claim that an unsigned development build is a production release.

## 1. Current baselines

The qualified functional baseline is `4195050`. Required CI run
`33225096633` covered the locked Rust workspace, Clippy, Rust 1.88, schemas,
both SDKs, bounded fuzz campaigns, GDB 9.2-17.1 across MI3 and MI4, x86-64,
AArch64 user and system targets, Debian kernel-provider matrices, and the
10,000-cycle local lifecycle soak.

The post-audit release-closure baseline is `eca9806`. It completes G1-G4 and
passed 88 core unit tests, 15 server unit tests, formatting checks, and
workspace Clippy with warnings denied. A signed release tag must repeat the
complete compatibility matrix; focused post-baseline verification does not
replace the `4195050` matrix evidence.

The default MCP projection is nine bounded Agent tools. Advanced targets,
mutations, values, tracking, probe, and kernel operations require
`--advanced-tools`; raw MI and controlled CLI also require `--raw-admin`.

## 2. G0: Auditable release identity

G0 is the only remaining production-release gate.

Required release artifacts:

- a signed Git tag;
- a deterministic source archive without caches or local build output;
- source and Linux binary SHA-256 checksums;
- an SBOM and fixed toolchain inventory;
- CI attestation bound to the exact tag and artifacts; and
- `gdb-ai doctor` build identity including commit, dirty state, software
  version, Rust version, GDB/MI version, and MCP version.

The release workflow must run the complete locked workspace, Clippy, MSRV,
SDK, schema, fuzz, GDB 9-17, x86-64, AArch64, kernel, chaos, and soak gates on
the tagged source.

Exit condition: a downloader can prove that the source archive, tested commit,
and distributed binary belong to one provenance chain.

Signing requires the release owner's key and remains an explicit release
operation; development automation must not create or import credentials.

## 3. G5: Behavior-preserving module split

The large `operations.rs`, `session.rs`, `main.rs`, and `gateway.rs` modules
increase review cost. Split only when a concrete change must touch that
domain; do not perform a broad rewrite solely to satisfy file-size targets.

Candidate boundaries:

```text
operations/  session, target, execution, breakpoint, inspection, value,
             memory, io, tracking, agent, kernel, raw, artifact
session/     handle, actor, scheduler, control, observation, output, snapshot
server/      stdio, unix, HTTP lifecycle, resources, tools
```

Each move is one signed commit and preserves schemas, tool catalogs, public
errors, replay output, and behavior. Protocol, security, or concurrency
changes never share a commit with a file move.

G5 is maintainability work, not a reason to delay a release whose tagged
qualification is otherwise complete.

## 4. G6: Agent-effect evaluation

Repeated paired A/B/C/D evaluation is explicitly deferred by project
direction. Existing CTF trials remain usability evidence only.

Before making comparative Agent-effect claims, use matched model versions,
prompts, permissions, budgets, environments, tasks, and multiple seeds:

```text
A  shell plus CLI GDB
B  persistent raw GDB
C  structured core GDB/AI
D  C plus typed probe/experiment
```

Measure final resolution, root-cause localization, first useful runtime
evidence, incorrect-hypothesis correction, irrelevant debugger calls, raw
fallback, tokens, turns, target resumes, and wall clock. Resume G6 before
claiming that structured tools or probe semantics generally improve success.

## 5. G7: Optional post-North-star work

Promote these only when measured demand justifies them:

- non-stop per-thread execution;
- capability-gated record/replay;
- fuller multi-inferior semantics;
- managed GDB handoff;
- an independent LLDB backend; or
- vendor JTAG providers.

None blocks the Linux all-stop GDB/MI release.

## 6. Release claims

Current acceptable claims are:

- GDB/AI is a stateful Agent Interface above GDB and GDB/MI;
- MI control and inferior PTY data are independent;
- asynchronous state, stop-scoped context, and composite observations are
  bounded and consistency checked;
- HTTP/resource integrity, evidence durability, deterministic contracts,
  default tool projection, and bounded storage have passed G1-G4; and
- exact compatibility, architecture, kernel, fuzz, chaos, and soak evidence
  exists for the named functional baseline.

Do not claim a production release until G0 binds the final tag to complete
qualification. Do not claim general Agent performance gains until G6 runs.

Documentation-only commits require link, formatting, and consistency checks;
they do not wait for the runtime CI matrix. Code and release commits retain
verification appropriate to their risk.

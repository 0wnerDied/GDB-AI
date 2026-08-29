# GDB/AI active plan

Status: North-star implementation and release gates G1-G5 are complete.
Repeated Agent-effect evaluation is deferred, and post-North-star extensions
remain optional.

`GDB/AI` means **GDB Agent Interface**. It runs above GNU GDB and GDB/MI to
give modern Agents a stateful interface for dynamic debugging, vulnerability
validation, and authorized vulnerability exploitation. GDB/MI is GNU GDB's
backend protocol; this project does not define it.

This file records qualified baselines and only unfinished or explicitly
deferred work. Completed plans and their evidence are archived in:

- [North-star architecture](docs/archive/north-star-plan-2026-08-29.md);
- [release gates G1-G4](docs/archive/release-gates-g1-g4-2026-08-29.md); and
- [behavior-preserving refactor G5](docs/archive/behavior-preserving-refactor-g5-2026-08-29.md).

The `gdb.ai/v1` namespace identifies the protocol major version. Release
signing, checksums, SBOM generation, and distribution attestations are
release-owner packaging tasks, not additional project gates.

## 1. Qualified baselines

The functional baseline is `4195050`. Required CI run `33225096633` covered
the locked Rust workspace, Clippy, Rust 1.88, schemas, both SDKs, bounded fuzz
campaigns, GDB 9.2-17.1 across MI3 and MI4, x86-64, AArch64 user and system
targets, Debian kernel-provider matrices, and the 10,000-cycle local lifecycle
soak.

The post-audit release-closure baseline is `eca9806`. It completes G1-G4 and
passed 88 core unit tests, 15 server unit tests, formatting checks, and
workspace Clippy with warnings denied.

G5 code spans `7e8fe14` through `6ac934e`. It decomposes the four large modules
into domain modules while preserving the three actual crate boundaries,
Gateway trust boundary, single session actor (`SessionWorker`) owner, protocol
schemas, public errors, and transport behavior. Its detailed review and
verification record is in the G5 archive.

The default MCP projection is nine bounded Agent tools. Advanced targets,
mutations, values, tracking, probe, and kernel operations require
`--advanced-tools`; raw MI and controlled CLI also require `--raw-admin`.

## 2. G6: Agent-effect evaluation

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
fallback, tokens, turns, target resumes, and wall clock. Resume G6 only before
claiming that structured tools or probe semantics generally improve success.

## 3. G7: Optional post-North-star work

Promote these only when measured demand justifies them:

- non-stop per-thread execution;
- capability-gated record/replay;
- fuller multi-inferior semantics;
- managed GDB handoff;
- an independent LLDB backend; or
- vendor JTAG providers.

None blocks the Linux all-stop GDB/MI release.

## 4. Current claims

Current acceptable claims are:

- GDB/AI is a stateful Agent Interface above GDB and GDB/MI;
- MI control and inferior PTY data are independent;
- asynchronous state, stop-scoped context, and composite observations are
  bounded and consistency checked;
- HTTP/resource integrity, evidence durability, deterministic contracts,
  default tool projection, and bounded storage passed G1-G4;
- G5 preserves those behaviors behind explicit ownership boundaries; and
- exact compatibility, architecture, kernel, fuzz, chaos, and soak evidence
  exists for the named functional baseline.

Do not claim general Agent performance gains until G6 runs.

Documentation-only commits require link, formatting, and consistency checks;
they do not wait for the runtime CI matrix. Code and release commits retain
verification appropriate to their risk.

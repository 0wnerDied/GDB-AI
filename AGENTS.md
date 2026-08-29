Do not overengineer, anticipate nonexistent extreme scenarios, or add
excessive fallback handling.

# Documentation Audience

Write README and public documentation for GDB/AI users and Agents. Describe
observable behavior, interfaces, supported environments, security boundaries,
and reproducible verification. Do not publish local audit snapshots, transient
commit comparisons, assistant workflow, source line counts, or internal
implementation progress there. Keep contributor roadmaps in `PLAN.md` and
release-specific provenance in release notes and CI artifacts.

# Code Comments and Bug-Fix Notes

Comment non-obvious invariants, state transitions, concurrency ordering,
trust boundaries, and security decisions. Explain why the code exists, not
what each line does. Keep obvious code uncommented and update comments when
the code changes.

Every bug fix must include a concise adjacent source comment with its ISO
date (`YYYY-MM-DD`). State the previous failure or root cause and the
invariant preserved, for example:

```rust
// 2026-08-28: Keep interrupts outside the mutation lock so a pending wait
// cannot block cancellation.
```

Put the comment at the shared root-cause fix, not at every caller. The dated
comment supplements, but does not replace, regression tests and the commit
message.

# Mandatory Commit & Pull Request Style

Use a subsystem prefix and imperative summary, for example
`subscriptions: Preserve Clash selector groups`. Use sentence case, no
period, and about 72 characters. After a blank line, explain the problem,
root cause or constraint, change, and effect; wrap prose near 72–75 columns
and include relevant evidence.

Keep one logical change per commit and sign it with `git commit -s`. Use
`Fixes:` for regressions. Reverts identify the original commit and justify
the reversal. PRs must describe the solution, exact verification, linked
issues, and UI screenshots or performance evidence when applicable. Never
commit credentials, API keys, subscription URLs, or fetched node data.

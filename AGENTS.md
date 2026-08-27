Do not overengineer, anticipate nonexistent extreme scenarios, or add
excessive fallback handling.

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

# Security Model

GDB starts with initialization, target auto-load, debuginfod, shell launch,
and inferior function calls disabled. Its environment is allowlisted. Target
paths are canonicalized beneath configured workspace roots.

Profiles separate offline observation, live observation, debug control,
laboratory mutation, and raw administration. Raw access also requires an
operator-enabled transport. Raw console uses an explicit host-safe verb
allowlist, and raw MI cannot bypass workspace, attach, remote endpoint,
inferior TTY, startup-setting, or process-lifecycle policy.

HTTP is loopback-only without a token. Unix sockets are mode `0600`. Memory,
register, input, raw, and policy mutations are audited with sensitive payloads
redacted. Never place secrets in configuration committed to this repository.

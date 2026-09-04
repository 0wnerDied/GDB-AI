# Security Model

GDB starts with initialization, target auto-load, debuginfod, shell launch,
and inferior function calls disabled. Inferiors start with a clean environment
unless `environment_mode=inherited` selects variables named by the operator's
`security.environment_allowlist`; request values may then override that
bounded set. GDB/AI rejects environment values containing whitespace or a
double quote because GDB cannot preserve them through its MI setting command.
Target paths are canonicalized beneath configured workspace roots; relative
paths resolve from those roots rather than the server process directory.
Bubblewrap hardening is disabled by default. Operators may select `auto` or
`required` when its filesystem and network namespaces are wanted.

Profiles separate offline observation, live observation, debug control,
laboratory mutation, and raw administration. Raw access also requires an
operator-enabled transport. Raw console accepts GDB's complete single-command
surface after that authorization; raw MI cannot bypass workspace, attach,
remote endpoint, inferior TTY, startup-setting, or process-lifecycle policy.

The default local profile is `lab_mutation`, which permits ordinary inferior
input and debugger mutations needed by exploit Agents. Operators may configure
`debug_control`, `live_observer`, or `offline_core` when a read/control-only
deployment is required; `raw_admin` remains explicit.

Memory reads are classified by the server. Core and proven ordinary local
mappings remain read effects. `lab_mutation` and `raw_admin` profiles accept
remote, unknown, and local device reads directly; observation profiles reject
them. The canonical API retains `acknowledge_target_effects=true` and the legacy
`volatile=true` alias for wire compatibility; admission is profile-driven and
projected Agent tools omit both.

HTTP always binds only to loopback; an optional bearer token authenticates
clients but does not permit a non-loopback listener. Unix sockets are mode
`0600`. Memory, register, input, raw, and policy mutations are audited with
sensitive payloads redacted. Never place secrets in configuration committed
to this repository.

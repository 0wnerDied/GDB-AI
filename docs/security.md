# Security Model

GDB starts with initialization, target auto-load, debuginfod, shell launch,
and inferior function calls disabled. Inferiors start with a clean environment
unless `environment_mode=inherited` selects variables named by the operator's
`security.environment_allowlist`; request values may then override that
bounded set. GDB/AI rejects environment values containing whitespace or a
double quote because GDB cannot preserve them through its MI setting command.
Target paths are canonicalized beneath configured workspace roots.

Profiles separate offline observation, live observation, debug control,
laboratory mutation, and raw administration. Raw access also requires an
operator-enabled transport. Raw console uses an explicit host-safe verb
allowlist, and raw MI cannot bypass workspace, attach, remote endpoint,
inferior TTY, startup-setting, or process-lifecycle policy.

The default local profile is `lab_mutation`, which permits ordinary inferior
input and debugger mutations needed by exploit Agents. Operators may configure
`debug_control`, `live_observer`, or `offline_core` when a read/control-only
deployment is required; `raw_admin` remains explicit.

Memory reads are classified by the server. Core and proven ordinary local
mappings remain read effects; remote, unknown, and local device mappings
require `acknowledge_target_effects=true` and the `lab_mutation` profile.
The legacy `volatile=true` field is accepted only as the same acknowledgement,
not as the source of the classification.

HTTP always binds only to loopback; an optional bearer token authenticates
clients but does not permit a non-loopback listener. Unix sockets are mode
`0600`. Memory, register, input, raw, and policy mutations are audited with
sensitive payloads redacted. Never place secrets in configuration committed
to this repository.

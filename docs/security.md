# Security Model

GDB starts with initialization, target auto-load, debuginfod, and inferior
function calls disabled. Launch uses GDB's standard shell startup with each
`argv` value quoted literally, without variable or command expansion.
`gdb_evaluate side_effects=allow`
temporarily enables calls for mutation profiles. Inferiors start with a clean
environment unless `environment_mode=inherited` selects variables named by
the operator's `security.environment_allowlist`; request values may then
override that bounded set. GDB/AI rejects environment values containing
whitespace or a double quote because GDB cannot preserve them through its MI
setting command.
Target paths are canonicalized beneath configured workspace roots; relative
paths resolve from those roots rather than the server process directory.
Remote connections that name an executable also set GDB's working directory
to its parent, so subsequent raw console file paths resolve there.
Target auto-load remains disabled. A `kernel.inspect` `dmesg` request may
explicitly execute the exact `vmlinux-gdb.py` companion beside the current
`vmlinux`; that build helper runs with the GDB process's host permissions.
Bubblewrap hardening is disabled by default. Operators may select `auto` or
`required` for filesystem isolation. Observation profiles also isolate the
network; `lab_mutation` and `raw_admin` retain it for remote GDB targets.

GDB and locally launched targets inherit the server's OS resource limits by
default. Operators may set positive `limits.process_memory_bytes`,
`process_cpu_seconds`, `process_file_bytes`, `process_open_files`, or
`process_count` values to cap GDB and its children; zero leaves that resource
unchanged. `process_count` applies to the host UID, so use a cgroup for a
per-session process quota. Artifact storage quotas only bound GDB/AI evidence;
they do not limit files written by a target. `no_new_privs` remains enabled.

Profiles separate offline observation, live observation, debug control,
laboratory mutation, and raw administration. Raw access also requires an
operator-enabled transport. Raw console accepts GDB's complete single-command
surface after that authorization; raw MI cannot bypass workspace, attach,
remote endpoint, inferior TTY, startup-setting, or process-lifecycle policy.
An administrative caller defaults to `raw_admin` when creating a session;
an explicitly requested profile still takes precedence.

The default local profile is `lab_mutation`, which permits ordinary inferior
input, debugger mutations, and remote GDB connections needed by debugging Agents.
An empty `security.remote_allowlist` accepts any parsed GDB remote endpoint; a
nonempty list restricts connections to those exact IP-address-and-port entries.
Operators may configure `debug_control`, `live_observer`, or `offline_core`
when a read/control-only deployment is required; `raw_admin` remains explicit.

Memory reads are classified by the server. Core and proven ordinary local
mappings remain read effects. `lab_mutation` and `raw_admin` profiles accept
remote, unknown, and local device reads directly; observation profiles reject
them. The canonical API retains `acknowledge_target_effects=true` and the legacy
`volatile=true` alias for wire compatibility; admission is profile-driven and
projected Agent tools omit both.

HTTP always binds only to loopback; an optional bearer token authenticates
clients but does not permit a non-loopback listener. Unix sockets are mode
`0600`. Accepted session calls are recorded in the journal. Selecting
`journal.durability = "durable"` additionally retains admission and completion
audit in SQLite, with sensitive payloads redacted. Never place secrets in
configuration committed to this repository.

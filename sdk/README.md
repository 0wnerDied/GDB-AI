# Python and TypeScript SDKs

Both SDKs are thin HTTP clients for the canonical `gdb.ai/v1` API and the
projected MCP tools and resources. Python requires 3.10 or newer and has no
runtime dependencies. The TypeScript package is ESM for Node.js 22 or newer
and uses native `fetch`. The debugger server runs in the supported
[Linux environments](../docs/compatibility.md).

## Install from this repository

```sh
python3 -m pip install ./sdk/python
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript run build
```

From your Node.js application, install the built package with
`npm install /path/to/gdb-ai/sdk/typescript`. Type declarations are included.
The SDK and server package versions follow the repository release version.

Start the server inside the target workspace:

```sh
gdb-ai serve --http 127.0.0.1:8080
```

Clients accept either the server base URL or its `/mcp` endpoint. Configure
the server's workspace roots to allow the target and source files. Raw
commands require both the SDK's `allow_raw=True` / `allowRaw: true` opt-in
and server-side administrative authority; the SDK flag grants no authority.
For authenticated servers, supply `token=` in Python or `token` in the
TypeScript options object. Load tokens from private configuration, not source
code. Remote HTTP requires a TLS reverse proxy; see the
[transport and security guide](../docs/mcp-clients.md).

## Choose an interface

| Python | TypeScript | Result |
| --- | --- | --- |
| `Client.call(method, parameters, ...)` | `Client.call(method, parameters, options)` | Canonical response envelope |
| `Client.list_tools()` | `Client.listTools()` | Tool descriptors and input schemas |
| `Client.call_tool(name, arguments)` | `Client.callTool(name, arguments)` | Projected `structuredContent` |
| `Client.list_resources()` | `Client.listResources()` | Accessible session resources |
| `Client.list_resource_templates()` | `Client.listResourceTemplates()` | Resource URI templates |
| `Client.read_resource(uri)` | `Client.readResource(uri)` | Resource contents, preserving URI and metadata |

`call` accepts every method in the [canonical schema](../schemas/gdb.ai.v1.json),
including operation status/cancellation, inspection batching, bounded I/O,
and artifact access. Parameters remain ordinary objects; the server validates
their method-specific contracts. TypeScript `call<T>` and `callTool<T>` let
applications describe their method-specific result without converting or
copying the response.

For common native debugging operations, TypeScript `Session.launch`,
`Session.control`, and `Session.inspect` provide typed parameters and delegate
to the same canonical call path. They retain revision tracking, lease renewal,
and error handling. Launch/control accept the same `idempotencyKey` option.
`inspect` covers stack, threads, frame, locals, arguments, registers, and crash
views; other operations remain available through `call`.

```typescript
await session.launch({ program: "/workspace/app", stop: "main",
  inspect: [{ view: "stack", limit: 8 }] });
await session.control({ action: "continue", wait: { until: "settled", timeout_ms: 5000 },
  inspect: [{ view: "crash", profile: "brief" }] });
```

These types reject missing executables, unknown actions/waits, an `until`
action without a location, standalone inspection without a stop selection,
and incompatible inspection/wait combinations. Launch with `inspect` chooses
a stop-producing wait by default; canonical `control` requires it explicitly.
They also exclude input on interrupt and require exactly one text/base64 input
encoding. The server still validates runtime values, limits, permissions, and
stale contexts. Results retain
`ApiResponse<T>`; the helpers do not decode unknown target-specific facts.

Use `Session` only for canonical sessions created by `Session.create`.
It manages the session ID, revision, and expiring write lease. Projected
sessions created with `gdb_session` use fixed caller control and do not return
a write lease. Keep using `call_tool` / `callTool` for those sessions; do not
wrap them in a canonical `Session` or add revision/lease arguments.

Canonical responses contain the full state when returned, with inferior
status and GDB exit-code text under `state.inferiors`. Projected responses
omit canonical coordination fields and healthy defaults, and may omit state
entirely. Their compact `state.exit_code` is numeric when recognized.
TypeScript therefore exports separate `ApiResponse<T>` and `ToolResponse<T>`
types. Neither SDK reconstructs omitted fields or duplicates structured data
as rendered MCP text.

Both SDKs export `ValueChild`, `ValueChange`, and `ValueStatus` for semantic
variable-object results. Values retain their debugger string or lossless
binary representation; availability is separate from the value text.

## Canonical Python example

This example assumes a noninteractive program with debug information at
`/workspace/app`, within a configured workspace root.

```python
from gdb_ai import Client, Session

client = Client("http://127.0.0.1:8080", timeout=30)
try:
    client.connect()
    session = Session.create(client)  # lab_mutation, subject to server policy
    try:
        launched = session.call("target.launch", {
            "program": "/workspace/app",
            "stop": "main",
            "wait": {"until": "snapshot", "timeout_ms": 5000},
        })
        stack = session.call("inspection.get", {
            "view": "stack", "stop_id": launched["state"]["stop_id"], "limit": 8,
        })
        print(stack["result"])
        session.call("execution.control", {
            "action": "continue", "wait": {"until": "exited", "timeout_ms": 5000},
        })
    finally:
        closed = session.close()
        print(closed["result"]["inferior_output_evidence"])
finally:
    client.disconnect()
```

Canonical stop-sensitive reads require a `stop_id` or
`accept_current_stop: true`. `Session.call` does not silently rebind a stale
stop. Mutations use the cached revision; close, interrupt, and interactive
input default to `accept_latest_revision: true` so asynchronous output does
not prevent cancellation or I/O. Explicit caller parameters are preserved.

## Projected TypeScript example

```typescript
import { Client } from "@gdb-ai/sdk";

const client = new Client("http://127.0.0.1:8080/mcp", {
  protocolVersion: "2026-07-28",
  timeoutMs: 30_000,
});
try {
  await client.connect();
  const created = await client.callTool<{ session_id: string }>(
    "gdb_session", { action: "create" },
  );
  const session_id = created.result!.session_id;
  try {
    await client.callTool("gdb_session", {
      action: "launch", session_id, program: "/workspace/app", stop: "main",
    });
    const stack = await client.callTool("gdb_inspect", {
      session_id, view: "stack", limit: 8,
    });
    console.log(stack.result);
    await client.callTool("gdb_run", { session_id, action: "continue" });
  } finally {
    const closed = await client.callTool("gdb_session", { session_id, action: "close" });
    console.log(closed.result);
  }
} finally {
  await client.disconnect();
}
```

The Python equivalent uses `Client(..., protocol_version="2026-07-28")`
and `call_tool`. TypeScript also provides `Session.create(client)` and
`session.call`, with the same canonical semantics as Python. The existing
TypeScript constructor `new Client(endpoint, token, allowRaw)` remains
supported.

## Transport lifetime, errors, and retries

The default protocol remains MCP `2025-11-25`: call `connect()` before
requests, and `disconnect()` to delete the HTTP transport session. The SDK
sends the negotiated version on subsequent requests. With explicit
`2026-07-28`, requests carry stateless metadata and need no initialization;
`connect()` performs discovery and `disconnect()` has no transport session
to delete. Choose the protocol when constructing the client and retain the
same endpoint and authenticated identity for the debugging session.

For cooperating workers, pass `client_name="worker-a"` in Python or
`clientName: "worker-a"` in TypeScript. Defaults remain unchanged. The option
sets the stateful initialization name or the stateless
`_meta["gdb-ai.dev/clientName"]` label; it does not grant access or change the
authenticated principal. Session create/status returns `caller_identity`
and `controller`. The current controller can call `gdb_session` action
`handoff` with `to` equal to the recipient's exact `caller_identity`.
Keep projected sessions on `call_tool` / `callTool` after handoff.

Run inspections, batches, and snapshots return `observation_id`. An authorized
worker can retrieve the same capture using `gdb_inspect` with
`view: "observation"` and `snapshot_id` set to that ID. The response is
historical, including at the same stop, and remains unchanged after resume
or close until retention removes it. Lookup does not re-read the target.

Disconnecting the client is not the same as closing the debugging session.
Close each session explicitly to release GDB and finalize retained output.
`Session.close()` and `force_abort()` / `forceAbort()` return the response,
including cleanup and output evidence metadata. Forced abort requires owner
or administrator authority and reports `clean_shutdown: false`.

`ApiError` preserves the canonical or projected response in `response`,
with `code`, `details`, and `retryable` accessors. `RpcError` preserves the
numeric JSON-RPC `code` and `data`, including an `operation_id` when the
server supplies one after a waiter timeout. Query it with `operation.get`
or `gdb_session` action `operation_status`; do not assume a timed-out request
cancelled its target effect. Transport failures remain native Python
HTTP/network exceptions or JavaScript fetch/HTTP errors.

Python's `timeout` defaults to 30 seconds for socket operations. TypeScript's
optional `timeoutMs` bounds the HTTP request and body; when omitted, the SDK
preserves native fetch timeouts without adding its own deadline.
Set the transport timeout above the requested debugger wait if the caller
needs its structured timeout result. A local timeout does not guarantee an
operation handle or cancel the server-owned operation.

`Session` tracks the highest revision from successful and rejected canonical
responses, including older cached responses. It renews and retries at most
once after `WRITE_LEASE_EXPIRED`, only when the lease is SDK-managed and no
idempotency key was supplied.
All other errors are returned without automatic replay. Calls sharing one
`Session` should be serialized; it is not a concurrent mutation scheduler.

Canonical `Client.call` accepts `idempotency_key` in Python or
`options.idempotencyKey` in TypeScript. `Session.call` forwards the same
option. The server fingerprints the parameters, revision, and lease, and
caches rejected responses too. An exact replay must preserve those fields;
renewing a lease or changing a revision under the same key is not a new
request. Use the lower-level client with explicit coordination fields when
you need to replay an exact saved envelope. The SDK never generates a new
key or retries a mutation after an ambiguous transport failure.

## Bounded output and evidence

I/O and transcript results contain exactly one lossless representation:
`text` for readable UTF-8, or `data_base64` for binary/control bytes. Resource
contents use `text` or `blob` respectively. Offsets and lengths count bytes,
not Python characters or JavaScript UTF-16 code units.

Preserve `warnings`, `truncated`, `continuation`, and `artifacts` from the
response. Missing projected metadata means the default, not a missing
canonical envelope. Read a base artifact, PTY, or transcript resource URI
to obtain its manifest, then request bounded `?offset=<n>&length=<m>` ranges.
Respect the manifest page size and verify the final SHA-256 when collecting
an artifact. The SDK returns pages as-is; it does not automatically fetch
unbounded evidence or treat a resource URI as authorization.

The server's `journal.durability` setting controls performance versus durable
history. SDK calls preserve evidence-gap warnings in either mode. Neither
SDK changes the server's retention, durability, or target security policy.

## Reproducible verification

From the repository root, with Python, Node.js, a C compiler, and GDB installed:

```sh
cargo build --locked -p gdb-ai
PYTHONPATH=sdk/python/src python3 -m unittest discover -s sdk/python/tests
npm --prefix sdk/typescript ci
npm --prefix sdk/typescript run build
npm --prefix sdk/typescript test
python3 sdk/verify.py target/debug/gdb-ai
```

`npm test` also checks accepted and rejected TypeScript helper calls at compile
time. The real-server check compiles the existing C fixture in a temporary
workspace. Both languages run canonical and projected debugging over both
HTTP versions, under performance and durable history modes. It verifies
launch, stop-bound inspection, immutable observation sharing, controller
handoff, errors, lease renewal, keyed I/O replay,
UTF-8 and binary PTY output, resource ranges, close artifacts, and complete
journal replay. It shuts down its servers and removes the temporary
workspace. The check is a required CI step, separate from the small mocked
client tests; it does not claim the complete target or deployment matrix.

// SPDX-License-Identifier: GPL-3.0-or-later

import assert from "node:assert/strict";
import { ApiError, Client, RpcError, Session } from "./dist/index.js";

const requests = [];
globalThis.fetch = async (url, init) => {
  requests.push({ url, init });
  if (requests.length === 1) {
    return new Response(JSON.stringify({ result: { protocolVersion: "2025-11-25" } }), {
      headers: { "Mcp-Session-Id": "mcp_test" },
    });
  }
  if (init.method === "DELETE") return new Response(null, { status: 204 });
  return new Response(null, { status: 202 });
};

const client = new Client("http://127.0.0.1:8080", { clientName: "analysis-agent" });
await client.connect();
await client.connect();
await client.disconnect();
await client.disconnect();

assert.equal(requests.at(-1).init.method, "DELETE");
assert.equal(JSON.parse(requests[0].init.body).params.clientInfo.name, "analysis-agent");
assert.equal(requests.at(-1).init.headers["Mcp-Session-Id"], "mcp_test");
assert.ok(requests.slice(1).every(
  ({ init }) => init.headers["Mcp-Protocol-Version"] === "2025-11-25",
));
assert.ok(requests.slice(0, -1).every(
  ({ init }) => init.headers.Accept === "application/json, text/event-stream",
));
assert.ok(requests.every(({ init }) => init.signal === undefined));
assert.equal(requests.filter(({ init }) => init.method === "DELETE").length, 1);
assert.equal(requests.filter(({ init }) => JSON.parse(init.body ?? "{}").method === "initialize").length, 1);
assert.throws(() => new Client(client.endpoint, { clientName: "" }), /1 to 128 bytes/);
assert.throws(() => new Client(client.endpoint, { clientName: "☃".repeat(43) }), /1 to 128 bytes/);

requests.length = 0;
globalThis.fetch = async (url, init) => {
  requests.push({ url, init });
  const { method } = JSON.parse(init.body);
  const key = {
    "server/discover": "supportedVersions",
    "tools/list": "tools",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
    "resources/read": "contents",
  }[method];
  const result = method === "tools/call"
    ? { content: [], structuredContent: { result: { written: 4 } } }
    : { [key]: [] };
  return Response.json({ result });
};
const stateless = new Client("http://127.0.0.1:8080/mcp/", { protocolVersion: "2026-07-28", timeoutMs: 5000 });
assert.deepEqual(await stateless.listTools(), []);
await stateless.connect();
assert.deepEqual(await stateless.listResources(), []);
assert.deepEqual(await stateless.listResourceTemplates(), []);
assert.deepEqual(await stateless.readResource("gdbai://session/sess_test/status"), []);
assert.deepEqual(await stateless.callTool("gdb_io", { action: "write", text: "test" }), {
  result: { written: 4 },
});
await stateless.disconnect();
for (const { url, init } of requests) {
  assert.equal(url, "http://127.0.0.1:8080/mcp");
  assert.equal(init.headers["Mcp-Session-Id"], undefined);
  assert.equal(init.headers["Mcp-Protocol-Version"], undefined);
  assert.ok(init.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(init.body).params._meta, {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
  });
}
const namedStateless = new Client("http://127.0.0.1:8080/mcp", {
  protocolVersion: "2026-07-28",
  clientName: "analysis-agent",
});
await namedStateless.connect();
assert.equal(
  JSON.parse(requests.at(-1).init.body).params._meta["gdb-ai.dev/clientName"],
  "analysis-agent",
);
const sent = requests.length;
await assert.rejects(stateless.call("raw.mi"), /allowRaw=true/);
await assert.rejects(stateless.call("raw.console"), /allowRaw=true/);
await assert.rejects(stateless.callTool("gdb_raw", { action: "console", command: "help" }), /allowRaw=true/);
assert.equal(requests.length, sent);

const failure = { error: { code: "STALE_CONTEXT", message: "stale", retryable: false } };
globalThis.fetch = async () => Response.json({ result: { structuredContent: failure, isError: true } });
await assert.rejects(stateless.callTool("gdb_inspect", { view: "stack" }), (error) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, "STALE_CONTEXT");
  assert.equal(error.retryable, false);
  assert.deepEqual(error.response, failure);
  return true;
});
for (const status of [200, 400]) {
  globalThis.fetch = async () => Response.json({ error: {
    code: -32001, message: "deadline", data: { operation_id: "op_wait" },
  } }, { status });
  await assert.rejects(stateless.call("session.get", {}, { sessionId: "sess_test" }), (error) => {
    assert.ok(error instanceof RpcError);
    assert.equal(error.code, -32001);
    assert.deepEqual(error.data, { operation_id: "op_wait" });
    return true;
  });
}

const calls = [];
const fakeClient = {
  async call(method, parameters, options) {
    calls.push({ method, parameters, options });
    if (method === "session.create") {
      return {
        revision: 7,
        result: {
          session_id: "sess_test",
          write_lease: { lease_id: "lease_old" },
        },
      };
    }
    return { revision: 9, result: { lease_id: "lease_new" } };
  },
};
const session = await Session.create(fakeClient);
assert.equal(calls[0].parameters.profile, "lab_mutation");
await session.renew();
assert.equal(calls.at(-1).options.expectedRevision, undefined);
await session.handoff("principal/mcp:next-agent");
assert.equal(calls.at(-1).method, "session.handoff");
assert.deepEqual(calls.at(-1).parameters, {
  to: "principal/mcp:next-agent",
  lease_id: "lease_new",
});
assert.equal(calls.at(-1).options.expectedRevision, 9);
await session.launch({ program: "/workspace/app", argv: ["a b"] }, { idempotencyKey: "launch-once" });
assert.equal(calls.at(-1).method, "target.launch");
assert.deepEqual(calls.at(-1).parameters, {
  program: "/workspace/app", argv: ["a b"], lease_id: "lease_new",
});
assert.equal(calls.at(-1).options.idempotencyKey, "launch-once");
await session.inspect({ view: "stack", stop_id: "stop_1", limit: 8 });
assert.equal(calls.at(-1).method, "inspection.get");
assert.equal(calls.at(-1).parameters.stop_id, "stop_1");
await session.control({ action: "interrupt" });
assert.equal(calls.at(-1).method, "execution.control");
assert.equal(calls.at(-1).parameters.accept_latest_revision, true);
assert.equal(calls.at(-1).options.expectedRevision, undefined);

let killAttempts = 0;
const retryCalls = [];
const retryClient = {
  async call(method, parameters, options) {
    retryCalls.push({ method, parameters: { ...parameters }, options });
    if (method === "session.create") {
      return {
        revision: 7,
        result: {
          session_id: "sess_retry",
          write_lease: { lease_id: "lease_old" },
        },
      };
    }
    if (method === "target.kill" && killAttempts++ === 0) {
      throw new ApiError({
        revision: 8,
        warnings: [],
        truncated: false,
        artifacts: [],
        evidence: [],
        error: { code: "WRITE_LEASE_EXPIRED", message: "expired", retryable: true },
      });
    }
    if (method === "session.acquire_write_lease") {
      return { revision: 9, result: { lease_id: "lease_new" } };
    }
    return { revision: 10, result: { killed: true } };
  },
};
const retrySession = await Session.create(retryClient);
const parameters = {};
await retrySession.call("target.kill", parameters);
assert.deepEqual(retryCalls.slice(1).map(({ method }) => method), [
  "target.kill",
  "session.acquire_write_lease",
  "target.kill",
]);
assert.equal(retryCalls.at(-1).parameters.lease_id, "lease_new");
assert.equal(retryCalls.at(-1).options.expectedRevision, 9);
assert.deepEqual(parameters, {});

for (const [parameters, idempotencyKey, expected] of [
  [{}, undefined, 3], [{ lease_id: "lease_explicit" }, undefined, 1], [{}, "kill-once", 1],
]) {
  const rejected = [];
  const rejectingSession = await Session.create({
    async call(method, parameters, options) {
      if (method === "session.create") return fakeClient.call(method, parameters, options);
      rejected.push({ method, options });
      if (method === "session.acquire_write_lease") {
        return { revision: 9, result: { lease_id: "lease_new" } };
      }
      throw new ApiError({ error: { code: "WRITE_LEASE_EXPIRED", message: "expired", retryable: true } });
    },
  });
  await assert.rejects(rejectingSession.call("target.kill", parameters, { idempotencyKey }), ApiError);
  assert.equal(rejected.length, expected);
  assert.equal(rejected.at(-1).options.idempotencyKey, idempotencyKey);
}

const originalCall = fakeClient.call.bind(fakeClient);
fakeClient.call = async (method, parameters, options) => {
  if (method !== "target.kill") return originalCall(method, parameters, options);
  calls.push({ method, parameters, options });
  throw new ApiError({ revision: 11, error: { code: "STALE_REVISION", message: "stale", retryable: true } });
};
await assert.rejects(session.call("target.kill"), ApiError);
await assert.rejects(session.call("target.kill"), ApiError);
assert.equal(calls.at(-1).options.expectedRevision, 11);
const closed = await session.close();
assert.equal(closed.revision, 9);
assert.equal(calls.at(-1).options.expectedRevision, undefined);
assert.equal(calls.at(-1).parameters.accept_latest_revision, true);
const cached = await session.call("session.get", {}, { idempotencyKey: "cached-status" });
assert.equal(cached.revision, 9);
assert.equal(calls.at(-1).options.expectedRevision, 11);
await assert.rejects(session.call("target.kill"), ApiError);
assert.equal(calls.at(-1).options.expectedRevision, 11);
assert.ok(await session.forceAbort());
assert.equal(calls.at(-1).method, "session.force_abort");
assert.deepEqual(calls.at(-1).parameters, {});
assert.equal(calls.at(-1).options.expectedRevision, undefined);

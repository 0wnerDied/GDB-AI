// SPDX-License-Identifier: GPL-3.0-or-later

import assert from "node:assert/strict";
import { ApiError, Client, Session } from "./dist/index.js";

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

const client = new Client("http://127.0.0.1:8080");
await client.connect();
await client.disconnect();

assert.equal(requests.at(-1).init.method, "DELETE");
assert.equal(requests.at(-1).init.headers["Mcp-Session-Id"], "mcp_test");
assert.ok(requests.slice(1).every(
  ({ init }) => init.headers["Mcp-Protocol-Version"] === "2025-11-25",
));
assert.ok(requests.slice(0, -1).every(
  ({ init }) => init.headers.Accept === "application/json, text/event-stream",
));

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
await session.renew();
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
await retrySession.call("target.kill");
assert.deepEqual(retryCalls.slice(1).map(({ method }) => method), [
  "target.kill",
  "session.acquire_write_lease",
  "target.kill",
]);
assert.equal(retryCalls.at(-1).parameters.lease_id, "lease_new");
assert.equal(retryCalls.at(-1).options.expectedRevision, 9);
await session.forceAbort();
assert.equal(calls.at(-1).method, "session.force_abort");
assert.deepEqual(calls.at(-1).parameters, {});
assert.equal(calls.at(-1).options.expectedRevision, undefined);

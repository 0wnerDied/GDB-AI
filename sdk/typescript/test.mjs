// SPDX-License-Identifier: GPL-3.0-or-later

import assert from "node:assert/strict";
import { Client } from "./dist/index.js";

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

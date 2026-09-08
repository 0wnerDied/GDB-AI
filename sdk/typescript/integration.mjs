// SPDX-License-Identifier: GPL-3.0-or-later

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { ApiError, Client, RpcError, Session } from "./dist/index.js";

async function verifyOutput(client, sessionId, result, expected) {
  assert.notEqual(Object.hasOwn(result, "text"), Object.hasOwn(result, "data_base64"));
  const actual = result.text !== undefined ? Buffer.from(result.text) : Buffer.from(result.data_base64, "base64");
  assert.deepEqual(actual, expected);
  assert.equal(result.next_offset, expected.length);
  assert.equal(result.gap, false);
  const uri = `gdbai://session/${sessionId}/output/pty`;
  const manifest = JSON.parse((await client.readResource(uri))[0].text);
  assert.equal(manifest.end_offset, expected.length);
  const rangeUri = `${uri}?offset=0&length=${expected.length}`;
  const contents = (await client.readResource(rangeUri))[0];
  assert.equal(contents.uri, rangeUri);
  assert.deepEqual(contents.text !== undefined ? Buffer.from(contents.text) : Buffer.from(contents.blob, "base64"), expected);
}

async function verifyClose(client, response, expected) {
  assert.equal(response.result.closed, true);
  assert.equal(response.result.clean_shutdown, true);
  const evidence = response.result.inferior_output_evidence;
  assert.equal(evidence.complete, true);
  assert.equal(evidence.dropped_bytes, 0);
  assert.equal(evidence.captured_bytes, expected.length);
  const digest = createHash("sha256").update(expected).digest("hex");
  assert.equal(evidence.sha256, digest);
  const uri = evidence.artifact_uri;
  const manifest = JSON.parse((await client.readResource(uri))[0].text);
  assert.equal(manifest.size, expected.length);
  assert.equal(manifest.sha256, digest);
  const page = (await client.readResource(`${uri}?offset=0&length=${expected.length}`))[0];
  assert.deepEqual(Buffer.from(page.blob, "base64"), expected);
}

async function canonical(client, program) {
  const session = await Session.create(client);
  const expected = Buffer.from("environment: sdk-世界\nmarker reached\ninput received: Q\n");
  let closed;
  try {
    await session.renew();
    const launched = await session.launch({
      program, environment: { GDB_AI_TEST_ENV: "sdk-世界" }, stop: "none",
      breakpoints: [{ function: "main" }],
      wait: { until: "snapshot", timeout_ms: 5000 },
      inspect: [{ view: "stack", limit: 4 }],
    });
    const stopId = launched.state.stop_id;
    assert.ok(launched.result.observations.stack.frames.length);
    assert.equal(launched.result.created_breakpoints.length, 1);
    assert.equal(launched.semantics.context.stop_id, stopId);
    assert.ok(launched.result.command.record && launched.result.capabilities);
    const context = await session.call("inspection.get", { view: "stop_context" });
    assert.equal(context.result.stop_id, stopId);
    const stack = await session.inspect({ view: "stack", stop_id: stopId, limit: 4 });
    assert.ok(stack.result.frames.length);
    assert.equal(stack.semantics.projection, "detailed");
    assert.equal(stack.semantics.context.stop_id, stopId);
    await assert.rejects(session.inspect({ view: "stack", stop_id: "stale" }),
      (error) => error instanceof ApiError && error.code === "STALE_CONTEXT" && error.response.revision !== undefined);
    // I/O accepts the latest revision, so this keyed replay does not change
    // the server fingerprint after Session updates its cached revision.
    const written = await session.call("inferior_io.write", { text: "Q\n" }, { idempotencyKey: "input-once" });
    const replayed = await session.call("inferior_io.write", { text: "Q\n" }, { idempotencyKey: "input-once" });
    assert.deepEqual(replayed.result, written.result);
    const exited = await session.control({
      action: "continue", wait: { until: "exited", timeout_ms: 5000 },
    });
    assert.ok(Object.values(exited.state.inferiors).some(
      (inferior) => inferior.status === "EXITED" && Number(inferior.exit_code) === 0,
    ));
    const output = await session.call("inferior_io.read", { after_offset: 0, max_bytes: 4096 });
    assert.equal(output.truncated, false);
    await verifyOutput(client, session.sessionId, output.result, expected);
  } finally {
    closed = await session.close();
  }
  await verifyClose(client, closed, expected);
}

async function projected(client, program) {
  const launched = await client.callTool("gdb_session", {
    action: "launch", program, environment: { GDB_AI_TEST_ENV: "sdk-世界" }, stop: "none",
    breakpoints: [{ function: "main" }],
    inspect: [{ view: "stack", limit: 4 }],
  });
  assert.equal(launched.api_version, undefined);
  assert.equal(launched.revision, undefined);
  const created = launched.result.session;
  assert.equal(created.write_lease, undefined);
  assert.equal(created.controller, created.caller_identity);
  const sessionId = created.session_id;
  const expected = Buffer.from("environment: sdk-世界\nmarker reached\ninput received: \0\n");
  const observer = new Client(endpoint, { protocolVersion, clientName: "typescript-observer" });
  let controller = client;
  const call = (name, arguments_) => controller.callTool(name, { session_id: sessionId, ...arguments_ });
  let closed;
  let lookup;
  let shared;
  try {
    await observer.connect();
    assert.ok(launched.state.stop_id);
    assert.equal(launched.state.backend, undefined);
    assert.ok(launched.result.observations.stack.frames.length);
    assert.equal(launched.context.stop_id, launched.state.stop_id);
    assert.ok(launched.complete && launched.evidence.length);
    assert.equal(launched.result.command, undefined);
    assert.equal(launched.result.capabilities, undefined);
    assert.equal(launched.result.observations.stack.frames[0].function, "main");
    assert.equal(launched.result.created_breakpoints.length, 1);
    await call("gdb_breakpoints", {
      action: "delete", breakpoint_id: launched.result.created_breakpoints[0],
    });
    const restarted = await call("gdb_run", {
      action: "restart", stop: "first_instruction", inspect: [{ view: "stack", limit: 4 }],
    });
    assert.ok(restarted.result.observations.stack.frames.length);
    assert.notEqual(restarted.context.stop_id, launched.context.stop_id);
    assert.equal(restarted.context.stop_id, restarted.state.stop_id);
    assert.ok(restarted.complete && restarted.evidence.length);
    assert.equal(restarted.result.command, undefined);
    assert.equal(restarted.result.capabilities, undefined);
    const statusUri = `gdbai://session/${sessionId}/status`;
    assert.ok((await client.listResources()).some((resource) => resource.uri === statusUri));
    const status = JSON.parse((await client.readResource(statusUri))[0].text);
    assert.equal(status.stop_id, restarted.state.stop_id);
    await assert.rejects(call("gdb_inspect", { view: "stack", stop_id: "stale" }),
      (error) => error instanceof ApiError && error.code === "STALE_CONTEXT" && error.response.revision === undefined);
    const captureResponse = await call("gdb_batch", { requests: [
      { view: "registers", roles: ["pc", "sp"] },
      { view: "evaluate", expression: "$pc" },
      { name: "missing", view: "evaluate", expression: "gdb_ai_missing_sdk_symbol" },
    ] });
    assert.equal(captureResponse.complete, false);
    const captured = captureResponse.result;
    assert.equal(captured.failures.missing.code, "GDB_ERROR");
    assert.equal(captured.availability.missing, "failed");
    assert.equal(captured.results.evaluate.status, "available");
    assert.equal(captured.results.evaluate.command, undefined);
    assert.equal(captured.failures.missing.details?.record, undefined);
    lookup = { session_id: sessionId, view: "observation", snapshot_id: captureResponse.context.observation_id };
    const sharedResponse = await observer.callTool("gdb_inspect", lookup);
    assert.equal(sharedResponse.historical, true);
    assert.equal(sharedResponse.context.observation_id, captureResponse.context.observation_id);
    shared = sharedResponse.result;
    assert.deepEqual(shared.results.evaluate, captured.results.evaluate);
    assert.deepEqual(shared.failures, captured.failures);
    const peerStatus = await observer.callTool("gdb_session", { action: "status", session_id: sessionId });
    const peerIdentity = peerStatus.result.caller_identity;
    assert.notEqual(peerIdentity, created.controller);
    const transferred = await call("gdb_session", { action: "handoff", to: peerIdentity });
    assert.equal(transferred.result.controller, peerIdentity);
    controller = observer;
    await assert.rejects(client.callTool("gdb_run", { action: "continue", session_id: sessionId }),
      (error) => error instanceof ApiError && error.code === "WRITE_LEASE_REQUIRED");
    const exited = await call("gdb_run", { action: "continue", input: { data_base64: "AAo=" } });
    assert.equal(exited.result.settled_by, "exited");
    assert.equal(exited.state.exit_code, 0);
    const output = await call("gdb_io", { action: "read", after_offset: 0, max_bytes: 4096 });
    assert.ok(!output.truncated);
    await verifyOutput(client, sessionId, output.result, expected);
    assert.deepEqual((await client.callTool("gdb_inspect", lookup)).result, shared);
  } finally {
    try {
      closed = await call("gdb_session", { action: "close" });
    } finally {
      await observer.disconnect();
    }
  }
  await verifyClose(client, closed, expected);
  assert.deepEqual((await client.callTool("gdb_inspect", lookup)).result, shared);
}

const [endpoint, program, protocolVersion] = process.argv.slice(2);
const client = new Client(endpoint, { protocolVersion, clientName: "typescript-controller" });
try {
  await client.connect();
  const names = (await client.listTools()).map((tool) => tool.name);
  assert.ok(["gdb_session", "gdb_run", "gdb_inspect", "gdb_io"].every((name) => names.includes(name)));
  assert.ok(!names.includes("gdb_raw"));
  assert.ok((await client.listResourceTemplates()).length);
  await assert.rejects(client.callTool("not_a_tool"), (error) => error instanceof RpcError && error.code === -32601);
  await canonical(client, program);
  await projected(client, program);
} finally {
  await client.disconnect();
}
console.log(`TypeScript ${protocolVersion}: canonical, projected, resources and output artifacts passed`);

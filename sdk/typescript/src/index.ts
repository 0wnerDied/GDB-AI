// SPDX-License-Identifier: GPL-3.0-or-later

const MCP_VERSION = "2025-11-25";
const STATELESS_MCP_VERSION = "2026-07-28";

export type ProtocolVersion = typeof MCP_VERSION | typeof STATELESS_MCP_VERSION;

export interface ClientOptions {
  token?: string;
  allowRaw?: boolean;
  protocolVersion?: ProtocolVersion;
  timeoutMs?: number;
  clientName?: string;
}

export interface CallOptions {
  sessionId?: string;
  expectedRevision?: number;
  idempotencyKey?: string;
}

export interface WaitSpec {
  until: "accepted" | "running" | "stopped" | "settled" | "snapshot" | "exited";
  timeout_ms?: number;
}

export type MutationParameters = {
  lease_id?: string;
  accept_latest_revision?: boolean;
};

export type TargetSelection = {
  inferior_id?: string;
  thread_id?: string;
  frame_id?: string;
  frame_level?: number;
};

export type StopContext =
  | { stop_id: string; accept_current_stop?: boolean }
  | { stop_id?: string; accept_current_stop: true };

export type BreakpointLocation =
  | { function: string }
  | { address: string }
  | { expression: string }
  | { source: { path: string; line: number } }
  | { module_offset: { module: string; offset: string } };

export type LaunchParameters = MutationParameters & {
  program: string;
  argv?: string[];
  cwd?: string;
  environment?: Record<string, string>;
  environment_mode?: "clean" | "inherited";
  aslr?: "preserve" | "disable";
  stop?: "first_instruction" | "main" | "none" | "entry";
  follow_fork?: "parent" | "child";
  detach_on_fork?: boolean;
  follow_exec?: "same-inferior";
  breakpoints?: BreakpointLocation[];
} & (
  | { wait?: WaitSpec; inspect?: never }
  | { wait?: WaitSpec & { until: "stopped" | "settled" | "snapshot" };
      inspect: Array<InspectionView & { name?: string }> }
);

// The typed helpers cover common native diagnosis views. Other views and
// provider-specific parameters remain available through the canonical call.
export type InspectionView = TargetSelection & (
  | { view: "stack"; limit?: number; offset?: number; include_locals?: boolean }
  | { view: "threads"; limit?: number; offset?: number; stack_depth?: number; include_locals?: boolean }
  | { view: "frame" | "locals" | "arguments" }
  | { view: "registers"; roles?: string[]; limit?: number; offset?: number }
  | { view: "crash"; profile?: "minimal" | "brief" | "standard" | "deep";
      limit?: number; roles?: string[] }
);

export type InspectionParameters = MutationParameters & StopContext & InspectionView;

export type InferiorInput =
  | { text: string; data_base64?: never }
  | { text?: never; data_base64: string };

export type ExecutionControlParameters = MutationParameters & TargetSelection & {
  stop_id?: string;
  accept_current_stop?: boolean;
} & (
  | { action: "until"; location: string; input?: InferiorInput }
  | { action: "continue" | "step" | "next" | "finish" | "step_instruction" | "next_instruction";
      location?: never; input?: InferiorInput }
  | { action: "interrupt"; location?: never; input?: never }
) & (
  | { wait?: WaitSpec; inspect?: never }
  // Canonical post-run inspection requires an explicit stop-producing wait.
  | { wait: WaitSpec & { until: "stopped" | "settled" | "snapshot" };
      inspect: Array<InspectionView & { name?: string }> }
);

export interface ApiResponse<T = unknown> {
  api_version: "gdb.ai/v1";
  request_id: string;
  session_id?: string;
  revision?: number;
  state?: unknown;
  result?: T;
  semantics?: ResultSemantics;
  warnings: Array<{ code: string; message: string }>;
  truncated: boolean;
  continuation?: unknown;
  artifacts: string[];
  evidence: Array<{ kind: string; uri: string }>;
  error?: { code: string; message: string; retryable: boolean; details?: unknown };
}

export interface ObservationContext {
  observation_id?: string;
  stop_id: string;
  captured_revision: number;
  execution_epoch: number;
  inferior_id?: string;
  thread_id?: string;
  frame_id?: string;
}

export interface ResultSemantics {
  context?: ObservationContext;
  state?: unknown;
  complete: boolean;
  historical: boolean;
  projection: "detailed" | "compact";
}

export type ValueStatus = "available" | "unavailable" | "not_collected" | "failed" | "invalid" | "unknown";

export interface ValueChild {
  path: string;
  name?: string;
  status: ValueStatus;
  type?: unknown;
  value?: unknown;
  children_count?: number;
  has_children?: boolean;
  dynamic?: boolean;
  display_hint?: string;
  has_more?: boolean;
}

export interface ValueChange {
  path: string;
  value_id?: string;
  status: ValueStatus;
  type?: unknown;
  value?: unknown;
  type_changed?: boolean;
  children_count?: number;
  has_children?: boolean;
  dynamic?: boolean;
  display_hint?: string;
  has_more?: boolean;
  new_children?: ValueChild[];
}

export interface ValueChildrenResult {
  value_id: string;
  stop_id: string;
  offset: number;
  limit: number;
  children: ValueChild[];
  children_count: number | null;
  has_more: boolean;
  result?: unknown;
  continuation: string | null;
}

export interface ValueUpdateResult {
  value_id: string;
  stop_id: string;
  changes: ValueChange[];
  result?: unknown;
}

// Projected tools omit healthy defaults and canonical coordination fields.
// Keep their optional metadata distinct from the canonical response envelope.
export type ToolResponse<T = unknown> = Partial<Pick<ApiResponse<T>,
  "state" | "result" | "warnings" | "truncated" | "continuation"
  | "artifacts" | "evidence" | "error"
>> & Partial<Pick<ResultSemantics, "context" | "complete" | "historical">>;

export interface Tool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  [key: string]: unknown;
}

export interface Resource {
  uri: string;
  name: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface ResourceTemplate {
  uriTemplate: string;
  name: string;
  mimeType?: string;
  [key: string]: unknown;
}

export type ResourceContents = {
  uri: string;
  mimeType?: string;
  _meta?: Record<string, unknown>;
} & ({ text: string; blob?: never } | { blob: string; text?: never });

export class ApiError extends Error {
  constructor(public readonly response: Partial<ApiResponse>) {
    super(`${response.error?.code ?? "INTERNAL"}: ${response.error?.message ?? "request failed"}`);
    this.name = "ApiError";
  }

  get code(): string { return this.response.error?.code ?? "INTERNAL"; }
  get details(): unknown { return this.response.error?.details; }
  get retryable(): boolean { return this.response.error?.retryable ?? false; }
}

export class RpcError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(error: { code: number; message: string; data?: unknown }) {
    super(`${error.code}: ${error.message}`);
    this.name = "RpcError";
    // 2026-09-06: Stringified faults discarded operation_id, preventing
    // recovery of a timed-out waiter without repeating the target mutation.
    this.code = error.code;
    this.data = error.data;
  }
}

export class Client {
  private nextId = 1;
  private mcpSession?: string;
  private mcpVersion?: string;
  private readonly endpoint: string;
  private readonly token?: string;
  private readonly allowRaw: boolean;
  private readonly timeoutMs?: number;
  private readonly explicitClientName: boolean;
  readonly clientName: string;
  readonly protocolVersion: ProtocolVersion;

  constructor(endpoint: string, options?: ClientOptions);
  constructor(endpoint: string, token?: string, allowRaw?: boolean);
  constructor(
    endpoint: string,
    optionsOrToken: ClientOptions | string = {},
    allowRaw = false,
  ) {
    const options = typeof optionsOrToken === "string"
      ? { token: optionsOrToken, allowRaw }
      : { allowRaw, ...optionsOrToken };
    this.protocolVersion = options.protocolVersion ?? MCP_VERSION;
    if (![MCP_VERSION, STATELESS_MCP_VERSION].includes(this.protocolVersion)) {
      throw new Error("unsupported MCP protocol version");
    }
    this.explicitClientName = options.clientName !== undefined;
    this.clientName = options.clientName ?? "gdb-ai-typescript";
    if (!this.clientName || new TextEncoder().encode(this.clientName).length > 128) {
      throw new Error("clientName must contain 1 to 128 bytes");
    }
    // 2026-09-06: Accept both the server base URL and its documented /mcp URL.
    const base = endpoint.replace(/\/+$/, "");
    this.endpoint = base.endsWith("/mcp") ? base : `${base}/mcp`;
    this.token = options.token;
    this.allowRaw = options.allowRaw ?? false;
    this.timeoutMs = options.timeoutMs;
  }

  async connect(): Promise<void> {
    if (this.protocolVersion === STATELESS_MCP_VERSION) {
      await this.rpc("server/discover", {});
      return;
    }
    if (this.mcpSession) {
      // 2026-09-06: Reuse the existing HTTP session instead of leaking it
      // on repeated connect, including a previously interrupted handshake.
      await this.notify("notifications/initialized", {});
      return;
    }
    const { result, response } = await this.rpc("initialize", {
      protocolVersion: MCP_VERSION,
      clientInfo: { name: this.clientName, version: "1.3.0" },
    }, false);
    if ((result as { protocolVersion?: string }).protocolVersion !== MCP_VERSION) {
      throw new Error("server returned an unsupported MCP protocol version");
    }
    this.mcpVersion = MCP_VERSION;
    this.mcpSession = response.headers.get("Mcp-Session-Id") ?? undefined;
    if (!this.mcpSession) throw new Error("server returned no MCP session ID");
    await this.notify("notifications/initialized", {});
  }

  // 2026-08-28: Clients could create HTTP transport sessions but had no
  // matching DELETE operation, leaving server state until idle eviction.
  async disconnect(): Promise<void> {
    if (!this.mcpSession) return;
    const response = await this.request({
      method: "DELETE",
      headers: this.headers(true),
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`HTTP ${response.status}`);
    }
    this.mcpSession = undefined;
    this.mcpVersion = undefined;
  }

  async call<T = unknown>(
    method: string,
    parameters: Record<string, unknown> = {},
    options: CallOptions = {},
  ): Promise<ApiResponse<T>> {
    if (method.startsWith("raw.") && !this.allowRaw) {
      throw new Error("raw methods require allowRaw=true");
    }
    const requestId = `ts_${this.nextId}`;
    const { result } = await this.rpc("gdb.ai/call", {
      api_version: "gdb.ai/v1",
      request_id: requestId,
      session_id: options.sessionId,
      method,
      expected_revision: options.expectedRevision,
      idempotency_key: options.idempotencyKey,
      parameters,
    });
    const response = result as ApiResponse<T>;
    if (response.error) throw new ApiError(response);
    return response;
  }

  async listTools(): Promise<Tool[]> {
    const { result } = await this.rpc("tools/list", {});
    return (result as { tools: Tool[] }).tools;
  }

  async callTool<T = unknown>(
    name: string,
    arguments_: Record<string, unknown> = {},
  ): Promise<ToolResponse<T>> {
    if (name === "gdb_raw" && !this.allowRaw) {
      throw new Error("raw tools require allowRaw=true");
    }
    const { result } = await this.rpc("tools/call", { name, arguments: arguments_ });
    const tool = result as { structuredContent?: ToolResponse<T>; isError?: boolean };
    const structured = tool.structuredContent;
    if (!structured || typeof structured !== "object" || Array.isArray(structured)) {
      throw new Error("tool returned no structuredContent");
    }
    if (structured.error) throw new ApiError(structured);
    if (tool.isError) throw new Error("tool failed without a structured error");
    return structured;
  }

  async listResources(): Promise<Resource[]> {
    const { result } = await this.rpc("resources/list", {});
    return (result as { resources: Resource[] }).resources;
  }

  async listResourceTemplates(): Promise<ResourceTemplate[]> {
    const { result } = await this.rpc("resources/templates/list", {});
    return (result as { resourceTemplates: ResourceTemplate[] }).resourceTemplates;
  }

  async readResource(uri: string): Promise<ResourceContents[]> {
    const { result } = await this.rpc("resources/read", { uri });
    return (result as { contents: ResourceContents[] }).contents;
  }

  private async rpc(
    method: string,
    params: Record<string, unknown>,
    includeSession = true,
  ): Promise<{ result: unknown; response: Response }> {
    const id = this.nextId++;
    if (this.protocolVersion === STATELESS_MCP_VERSION) {
      const metadata: Record<string, unknown> = {
        "io.modelcontextprotocol/protocolVersion": STATELESS_MCP_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
      };
      if (this.explicitClientName) metadata["gdb-ai.dev/clientName"] = this.clientName;
      params = {
        ...params,
        _meta: metadata,
      };
    }
    const response = await this.request({
      method: "POST",
      headers: this.headers(includeSession),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    if (!response.ok && !response.headers.get("Content-Type")?.includes("application/json")) {
      throw new Error(`HTTP ${response.status}`);
    }
    const message = await response.json() as {
      result?: unknown;
      error?: { code: number; message: string; data?: unknown };
    };
    if (message.error) throw new RpcError(message.error);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return { result: message.result, response };
  }

  private async notify(method: string, params: unknown): Promise<void> {
    const response = await this.request({
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify({ jsonrpc: "2.0", method, params }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
  }

  private headers(includeSession: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (includeSession && this.protocolVersion === MCP_VERSION) {
      if (!this.mcpSession) throw new Error("connect() must be called first");
      headers["Mcp-Session-Id"] = this.mcpSession;
      // 2026-08-29: Bind every HTTP request to the negotiated MCP version.
      headers["Mcp-Protocol-Version"] = this.mcpVersion ?? MCP_VERSION;
    }
    return headers;
  }

  private request(init: RequestInit): Promise<Response> {
    return fetch(this.endpoint, this.timeoutMs === undefined
      ? init
      : { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
  }
}

export class Session {
  private constructor(
    private readonly client: Client,
    readonly sessionId: string,
    private revision: number,
    private leaseId: string,
  ) {}

  static async create(client: Client, profile = "lab_mutation"): Promise<Session> {
    const response = await client.call<{
      session_id: string;
      write_lease: { lease_id: string };
    }>("session.create", { profile });
    const result = response.result!;
    return new Session(client, result.session_id, response.revision!, result.write_lease.lease_id);
  }

  launch<T = unknown>(
    parameters: LaunchParameters,
    options: { idempotencyKey?: string } = {},
  ): Promise<ApiResponse<T>> {
    return this.call<T>("target.launch", parameters, options);
  }

  control<T = unknown>(
    parameters: ExecutionControlParameters,
    options: { idempotencyKey?: string } = {},
  ): Promise<ApiResponse<T>> {
    return this.call<T>("execution.control", parameters, options);
  }

  inspect<T = unknown>(parameters: InspectionParameters): Promise<ApiResponse<T>> {
    return this.call<T>("inspection.get", parameters);
  }

  async call<T = unknown>(
    method: string,
    parameters: Record<string, unknown> = {},
    options: { idempotencyKey?: string } = {},
  ): Promise<ApiResponse<T>> {
    const managedLease = !Object.hasOwn(parameters, "lease_id");
    const request: Record<string, unknown> = {
      lease_id: this.leaseId,
      ...parameters,
    };
    if (
      [
        "session.close",
        "inferior_io.write",
        "inferior_io.close_stdin",
        "inferior_io.send_eof",
        "inferior_io.resize",
      ].includes(method)
      || method === "execution.control" && request.action === "interrupt"
    ) {
      request.accept_latest_revision ??= true;
    }

    let renewed = false;
    for (;;) {
      try {
        const response = await this.client.call<T>(method, request, {
          sessionId: this.sessionId,
          expectedRevision: request.accept_latest_revision === true
            ? undefined
            : this.revision,
          idempotencyKey: options.idempotencyKey,
        });
        this.observeRevision(response);
        return response;
      } catch (error) {
        if (error instanceof ApiError) this.observeRevision(error.response);
        // 2026-08-31: Lease expiry rejects before the target effect. Renewing
        // and retrying one managed call keeps coordination out of Agent turns.
        if (
          !(error instanceof ApiError)
          || error.response.error?.code !== "WRITE_LEASE_EXPIRED"
          || !managedLease
          // Keyed responses pin the revision and lease in their fingerprint.
          || options.idempotencyKey !== undefined
          || renewed
        ) throw error;
        await this.renew();
        request.lease_id = this.leaseId;
        renewed = true;
      }
    }
  }

  async renew(): Promise<void> {
    // 2026-08-28: Asynchronous target events can make the cached revision
    // stale. Supplying it here defeated accept_latest_revision.
    const response = await this.client.call<{ lease_id: string }>(
      "session.acquire_write_lease",
      { accept_latest_revision: true },
      { sessionId: this.sessionId },
    );
    this.observeRevision(response);
    this.leaseId = response.result!.lease_id;
  }

  handoff(to: string): Promise<ApiResponse<{ controller: string; generation: number }>> {
    return this.call("session.handoff", { to });
  }

  async close(): Promise<ApiResponse> {
    // 2026-09-06: Retain finalized output artifacts and completeness metadata
    // instead of discarding the close response needed to preserve evidence.
    return this.call("session.close");
  }

  async forceAbort(): Promise<ApiResponse> {
    const response = await this.client.call("session.force_abort", {}, { sessionId: this.sessionId });
    this.observeRevision(response);
    return response;
  }

  private observeRevision(response: Partial<ApiResponse>): void {
    // 2026-09-06: Cached idempotent responses can precede newer observations.
    // Keep the session's known revision monotonic across replies and errors.
    if (response.revision !== undefined) this.revision = Math.max(this.revision, response.revision);
  }
}

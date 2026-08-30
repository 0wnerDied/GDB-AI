use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use gdb_ai_core::{
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse, CanonicalMethod},
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use crate::tool_catalog::{discriminator_for_tool, method_for_tool, tool_exists, tools};

mod http;
mod resources;
mod stream;

pub(super) use http::serve_http;
pub(super) use stream::{serve_stdio, serve_unix};

use resources::{list_resources, read_resource, resource_templates};

pub(super) const MCP_VERSION: &str = "2025-11-25";
pub(super) const STATELESS_MCP_VERSION: &str = "2026-07-28";
pub(super) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_HTTP_PENDING_DURATION: Duration = Duration::from_secs(5 * 60);

type RpcOutput = (Option<(String, u64)>, Value);

#[derive(Clone, Copy)]
enum CanonicalPresentation {
    Tool(CanonicalMethod),
    Envelope,
}

#[derive(Clone, Copy)]
enum CancelMode {
    DetachWaiter,
    InterruptTarget,
    CloseSession,
}

#[derive(Clone)]
struct RequestCancellation {
    mode: CancelMode,
    operation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}

#[derive(Debug)]
struct RpcFault {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl RpcFault {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            data: None,
        }
    }
}

const AGENT_INSTRUCTIONS: &str = "Use tools/list schemas as authoritative. Start with \
gdb_session create, retain session_id, lease_id, and the latest revision, then launch; \
argv contains arguments only, not the program path. debug_control permits reads and \
run control; inferior PTY input and exploit experiments require a server configured \
for lab_mutation or an administrative caller selecting it. Renew an expired lease \
with acquire_write_lease and accept_latest_revision=true, omitting expected_revision. \
Read inferior output from stream=pty. Use each returned stop_id for stop-scoped \
inspection; resuming invalidates old frames and values. For stripped PIEs, set \
module-offset breakpoints with names shown by inspection mappings; a local \
explicit-loader breakpoint rebinds when its executable mapping appears. Read large evidence through \
gdbai:// resources. If HTTP returns an operation_id after waiter timeout, query \
it with gdb_session action=operation_status; use operation_cancel only when \
the record reports ACTOR_SCOPED cancellation. Close the session when finished.";

fn initialize(params: &Value, phase: &mut Phase, caller: &mut Caller) -> Result<Value, RpcFault> {
    if *phase != Phase::New {
        return Err(RpcFault::invalid("initialize may only be called once"));
    }
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("protocolVersion is required"))?;
    let client_name = params
        .get("clientInfo")
        .and_then(|info| info.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("clientInfo.name is required"))?;
    if client_name.is_empty() || client_name.len() > 128 {
        return Err(RpcFault::invalid(
            "clientInfo.name must contain 1 to 128 bytes",
        ));
    }
    caller.identity = format!("{}/mcp:{client_name}", caller.identity);
    *phase = Phase::AwaitingInitialized;
    let supported = [MCP_VERSION, "2025-06-18", "2025-03-26", "2024-11-05"];
    let version = if supported.contains(&requested) {
        requested
    } else {
        MCP_VERSION
    };
    Ok(json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": {"listChanged": false},
            "resources": {"subscribe": false, "listChanged": false}
        },
        "serverInfo": {"name": "gdb-ai", "version": env!("CARGO_PKG_VERSION")},
        "instructions": AGENT_INSTRUCTIONS
    }))
}

// 2026-08-30: MCP 2026 removed connection handshakes and carries protocol
// capabilities on every request. Keep that transport state out of Gateway.
fn stateless_request(params: &Value) -> Result<bool, RpcFault> {
    const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
    const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
    let Some(version) = params
        .get("_meta")
        .and_then(|metadata| metadata.get(VERSION_KEY))
    else {
        return Ok(false);
    };
    let requested = version
        .as_str()
        .ok_or_else(|| RpcFault::invalid(format!("_meta.{VERSION_KEY} must be a string")))?;
    if requested != STATELESS_MCP_VERSION {
        return Err(RpcFault {
            code: -32022,
            message: format!("unsupported MCP protocol version {requested}"),
            data: Some(json!({
                "requested": requested,
                "supported": [STATELESS_MCP_VERSION]
            })),
        });
    }
    if !params
        .get("_meta")
        .and_then(|metadata| metadata.get(CAPABILITIES_KEY))
        .is_some_and(Value::is_object)
    {
        return Err(RpcFault::invalid(format!(
            "_meta.{CAPABILITIES_KEY} must be an object"
        )));
    }
    Ok(true)
}

// 2026-08-30: MCP 2026 requires result discrimination and cache metadata.
// Decorate only the wire result so canonical responses remain version-neutral.
fn stateless_result(method: &str, mut result: Value) -> Value {
    let Some(object) = result.as_object_mut() else {
        return result;
    };
    object.insert("resultType".into(), Value::String("complete".into()));
    let ttl: Option<u64> = match method {
        "server/discover" | "tools/list" | "resources/templates/list" => Some(86_400_000),
        "resources/list" | "resources/read" => Some(0),
        _ => None,
    };
    if let Some(ttl) = ttl {
        object.insert("ttlMs".into(), Value::from(ttl));
        object.insert("cacheScope".into(), Value::String("private".into()));
    }
    if method == "server/discover" {
        object.insert(
            "_meta".into(),
            json!({
                "io.modelcontextprotocol/serverInfo": {
                    "name": "gdb-ai",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        );
    }
    result
}

fn apply_cancel_mode(
    gateway: Arc<Gateway>,
    caller: Caller,
    sequence: Arc<AtomicU64>,
    cancellation: RequestCancellation,
) {
    let Some(operation_id) = cancellation.operation_id else {
        return;
    };
    tokio::spawn(async move {
        let result = match cancellation.mode {
            CancelMode::DetachWaiter => gateway
                .detach_operation_waiter(&operation_id, &caller)
                .await
                .map(|_| ()),
            CancelMode::InterruptTarget | CancelMode::CloseSession => {
                let mode = match cancellation.mode {
                    CancelMode::InterruptTarget => "interrupt_target",
                    CancelMode::CloseSession => "close_session",
                    CancelMode::DetachWaiter => unreachable!(),
                };
                let response = gateway
                    .dispatch(
                        ApiRequest {
                            api_version: API_VERSION.into(),
                            request_id: format!(
                                "cancel_{}",
                                sequence.fetch_add(1, Ordering::Relaxed)
                            ),
                            session_id: None,
                            method: CanonicalMethod::OperationCancel,
                            expected_revision: None,
                            idempotency_key: None,
                            parameters: json!({
                                "operation_id": operation_id,
                                "mode": mode
                            }),
                        },
                        &caller,
                    )
                    .await;
                match response.error {
                    Some(error) => Err(gdb_ai_core::Error::new(error.code, error.message)),
                    None => Ok(()),
                }
            }
        };
        if let Err(error) = result {
            tracing::warn!(%error, %operation_id, "request cancellation action failed");
        }
    });
}

fn request_cancellation(method: &str, params: &Value) -> Result<RequestCancellation, RpcFault> {
    let parameters = match method {
        "tools/call" => params.get("arguments").unwrap_or(&Value::Null),
        "gdb.ai/call" => params,
        _ => &Value::Null,
    };
    let mode = match parameters
        .get("cancel_mode")
        .and_then(Value::as_str)
        .unwrap_or("detach_waiter")
    {
        "detach_waiter" => CancelMode::DetachWaiter,
        "interrupt_target" => CancelMode::InterruptTarget,
        "close_session" => CancelMode::CloseSession,
        _ => return Err(RpcFault::invalid("unsupported cancel_mode")),
    };
    Ok(RequestCancellation {
        mode,
        operation_id: None,
    })
}

fn progress_token(params: &Value) -> Result<Option<Value>, RpcFault> {
    let Some(token) = params
        .get("_meta")
        .and_then(|metadata| metadata.get("progressToken"))
    else {
        return Ok(None);
    };
    if token.is_string() || token.is_number() {
        Ok(Some(token.clone()))
    } else {
        Err(RpcFault::invalid(
            "_meta.progressToken must be a string or number",
        ))
    }
}

fn progress_notification(token: Value, progress: u64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": token,
            "progress": progress,
            "total": 1,
            "message": message
        }
    })
}

async fn dispatch_rpc(
    gateway: &Gateway,
    caller: &Caller,
    advanced_tools: bool,
    sequence: &AtomicU64,
    method: &str,
    mut params: Value,
) -> Result<Value, RpcFault> {
    if let Some((request, presentation)) =
        canonical_rpc_request(method, &mut params, advanced_tools, caller.admin, sequence)?
    {
        return present_canonical_response(gateway.dispatch(request, caller).await, presentation);
    }
    match method {
        "ping" => Ok(json!({})),
        "server/discover" => Ok(json!({
            "supportedVersions": [STATELESS_MCP_VERSION, MCP_VERSION],
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"listChanged": false}
            },
            "instructions": AGENT_INSTRUCTIONS
        })),
        "tools/list" => Ok(json!({"tools": tools(advanced_tools, caller.admin)})),
        "resources/list" => list_resources(gateway, caller, sequence).await,
        "resources/templates/list" => Ok(resource_templates()),
        "resources/read" => read_resource(gateway, caller, sequence, &params).await,
        _ => Err(RpcFault {
            code: -32601,
            message: format!("method not found: {method}"),
            data: None,
        }),
    }
}

// 2026-08-30: Move canonical payloads out of the outer request so large Agent
// inputs are not deep-cloned before they enter the operation service.
fn canonical_rpc_request(
    method: &str,
    params: &mut Value,
    advanced_tools: bool,
    raw_admin: bool,
    sequence: &AtomicU64,
) -> Result<Option<(ApiRequest, CanonicalPresentation)>, RpcFault> {
    match method {
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcFault::invalid("tools/call requires name"))?
                .to_owned();
            let arguments = params
                .as_object_mut()
                .and_then(|params| params.remove("arguments"))
                .unwrap_or_else(|| json!({}));
            let request = map_tool(
                &name,
                arguments,
                advanced_tools,
                raw_admin,
                sequence.fetch_add(1, Ordering::Relaxed),
            )?;
            let method = request.method;
            Ok(Some((request, CanonicalPresentation::Tool(method))))
        }
        "gdb.ai/call" => {
            // 2026-08-30: MCP 2026 metadata belongs to the transport request,
            // not the deny-unknown-fields canonical GDB/AI envelope.
            if let Some(params) = params.as_object_mut() {
                params.remove("_meta");
            }
            Ok(Some((
                serde_json::from_value(params.take())
                    .map_err(|error| RpcFault::invalid(error.to_string()))?,
                CanonicalPresentation::Envelope,
            )))
        }
        _ => Ok(None),
    }
}

fn present_canonical_response(
    response: ApiResponse,
    presentation: CanonicalPresentation,
) -> Result<Value, RpcFault> {
    match presentation {
        CanonicalPresentation::Tool(method) => Ok(tool_result(response, method)),
        CanonicalPresentation::Envelope => {
            serde_json::to_value(response).map_err(|error| RpcFault::invalid(error.to_string()))
        }
    }
}

async fn admit_canonical_operation(
    gateway: Arc<Gateway>,
    caller: Caller,
    request: ApiRequest,
    presentation: CanonicalPresentation,
    waiter_timeout: Option<Duration>,
) -> Result<(String, JoinHandle<Result<Value, RpcFault>>), RpcFault> {
    let ticket = gateway
        .admit_operation(request, caller.clone(), waiter_timeout)
        .await
        .map_err(|error| core_fault(format!("{:?}", error.code), error.message))?;
    let operation_id = ticket.operation_id.0;
    let waited_id = operation_id.clone();
    let waiter = tokio::spawn(async move {
        let record = gateway
            .wait_operation(&waited_id, &caller)
            .await
            .map_err(|error| core_fault(format!("{:?}", error.code), error.message))?;
        let response = record.result.ok_or_else(|| {
            core_fault("INTERNAL", "completed operation has no canonical response")
        })?;
        present_canonical_response(response, presentation)
    });
    Ok((operation_id, waiter))
}

#[cfg(test)]
async fn call_tool(
    gateway: &Gateway,
    caller: &Caller,
    advanced_tools: bool,
    sequence: &AtomicU64,
    mut params: Value,
) -> Result<Value, RpcFault> {
    let Some((request, presentation)) = canonical_rpc_request(
        "tools/call",
        &mut params,
        advanced_tools,
        caller.admin,
        sequence,
    )?
    else {
        unreachable!("tools/call always maps to a canonical request")
    };
    present_canonical_response(gateway.dispatch(request, caller).await, presentation)
}

fn map_tool(
    name: &str,
    arguments: Value,
    advanced_tools: bool,
    raw_admin: bool,
    sequence: u64,
) -> Result<ApiRequest, RpcFault> {
    // 2026-08-30: `arguments` is already owned after envelope extraction;
    // moving its map avoids one more deep copy of large Agent payloads.
    let Value::Object(mut parameters) = arguments else {
        return Err(RpcFault::invalid("tool arguments must be an object"));
    };
    let session_id = take_string(&mut parameters, "session_id")?;
    let expected_revision = take_u64(&mut parameters, "expected_revision")?;
    let idempotency_key = take_string(&mut parameters, "idempotency_key")?;
    let _ = take_string(&mut parameters, "cancel_mode")?;
    let discriminator = discriminator_for_tool(name);
    let action = discriminator
        .map(|field| take_required_string(&mut parameters, field))
        .transpose()?;
    let method =
        method_for_tool(name, action.as_deref(), advanced_tools, raw_admin).ok_or_else(|| {
            if tool_exists(name, advanced_tools, raw_admin) {
                RpcFault::invalid(format!(
                    "unsupported {name} action {}",
                    action.as_deref().unwrap_or_default()
                ))
            } else {
                RpcFault {
                    code: -32601,
                    message: format!("tool not found: {name}"),
                    data: None,
                }
            }
        })?;
    match (name, method, action.as_deref()) {
        ("gdb_run", CanonicalMethod::ExecutionControl, Some(action)) => {
            parameters.insert("action".into(), Value::String(action.into()));
        }
        ("gdb_breakpoints", CanonicalMethod::BreakpointUpdate, Some("enable" | "disable")) => {
            parameters.insert(
                "enabled".into(),
                Value::Bool(action.as_deref() == Some("enable")),
            );
        }
        ("gdb_inspect", CanonicalMethod::InspectionGet, Some(view)) => {
            parameters.insert("view".into(), Value::String(view.into()));
        }
        _ => {}
    }
    Ok(ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("mcp_{sequence}"),
        session_id,
        method,
        expected_revision,
        idempotency_key,
        parameters: Value::Object(parameters),
    })
}

fn tool_result(response: ApiResponse, method: CanonicalMethod) -> Value {
    let is_error = response.error.is_some();
    let summary = match &response.error {
        Some(error) => format!("{}: {}", error.code.code_name(), error.message),
        // 2026-08-30: The structured result already carries the revision.
        // Repeating it in successful text content costs tokens on every Agent
        // call without adding information.
        None => "ok".into(),
    };
    let structured = compact_tool_response(response, method);
    json!({
        "content": [{"type": "text", "text": summary}],
        "structuredContent": structured,
        "isError": is_error
    })
}

// 2026-08-30: Repeating complete thread, breakpoint, module, and signal
// registries after every tool call consumed Agent context and serialized data
// unrelated to the operation. Detailed views remain available on demand.
fn compact_tool_response(response: ApiResponse, method: CanonicalMethod) -> Value {
    let ApiResponse {
        session_id,
        revision,
        mut state,
        mut result,
        warnings,
        truncated,
        continuation,
        artifacts,
        evidence,
        error,
        ..
    } = response;
    if let Some(Value::Object(result)) = result.as_mut() {
        if result.get("state").is_some_and(|state| {
            state.get("session_id").is_some() && state.get("revision").is_some()
        }) {
            result.remove("state");
        }
        // 2026-08-30: Semantic MCP results repeated complete MI replies and
        // capability tables already available through evidence and explicit
        // discovery calls. Keep them only where they are the requested data.
        if !matches!(
            method,
            CanonicalMethod::RawMi | CanonicalMethod::RawConsole | CanonicalMethod::KernelMonitor
        ) {
            result.remove("command");
            result.remove("commands");
        }
        if !matches!(
            method,
            CanonicalMethod::InspectionGet | CanonicalMethod::KernelInspect
        ) {
            result.remove("capabilities");
        }
        match method {
            CanonicalMethod::BreakpointCreate | CanonicalMethod::BreakpointUpdate
                if result.get("breakpoint").is_some_and(Value::is_object) =>
            {
                result.remove("breakpoints");
            }
            CanonicalMethod::BreakpointDelete
                if result.get("deleted").is_some_and(Value::is_object) =>
            {
                result.remove("breakpoints");
            }
            _ => {}
        }
        if result
            .get("stop_id")
            .is_some_and(|stop_id| !stop_id.is_null())
            || matches!(
                method,
                CanonicalMethod::BreakpointCreate
                    | CanonicalMethod::BreakpointUpdate
                    | CanonicalMethod::BreakpointDelete
                    | CanonicalMethod::BreakpointList
            )
        {
            state = None;
        }
    }
    let mut compact = Map::new();
    if let Some(session_id) = session_id {
        compact.insert("session_id".into(), Value::String(session_id));
    }
    if let Some(revision) = revision {
        compact.insert("revision".into(), Value::from(revision));
    }
    if let Some(state) = state {
        let mut summary = json!({
            "lifecycle": state.lifecycle,
            "backend": state.backend,
            "consistency": state.consistency,
            "reconciliation_required": state.reconciliation_required,
            "event_seq": state.event_seq,
            "execution_epoch": state.execution_epoch,
            "target_origin": state.target_origin
        });
        let summary = summary.as_object_mut().unwrap();
        if !state.outcome_unknown_tokens.is_empty() {
            summary.insert(
                "outcome_unknown_tokens".into(),
                json!(state.outcome_unknown_tokens),
            );
        }
        if let Some(stop_id) = state.stop_id {
            summary.insert("stop_id".into(), json!(stop_id));
        }
        if let Some(reason) = state.stop_reason_detail {
            summary.insert("stop_reason".into(), json!(reason));
        } else if let Some(reason) = state.stop_reason {
            summary.insert("stop_reason".into(), Value::String(reason));
        }
        if let Some(inferior_id) = state.stopped_inferior_id {
            summary.insert("inferior_id".into(), json!(inferior_id));
        }
        if let Some(thread_id) = state.stopped_thread_id {
            summary.insert("thread_id".into(), json!(thread_id));
        }
        if let Some(snapshot) = state.snapshot {
            summary.insert("snapshot".into(), json!(snapshot));
        }
        compact.insert("state".into(), Value::Object(std::mem::take(summary)));
    }
    if let Some(result) = result {
        compact.insert("result".into(), result);
    }
    if !warnings.is_empty() {
        compact.insert("warnings".into(), json!(warnings));
    }
    if truncated {
        compact.insert("truncated".into(), Value::Bool(true));
    }
    if let Some(continuation) = continuation {
        compact.insert("continuation".into(), continuation);
    }
    if !artifacts.is_empty() {
        compact.insert("artifacts".into(), json!(artifacts));
    }
    if !evidence.is_empty() {
        compact.insert("evidence".into(), json!(evidence));
    }
    if let Some(error) = error {
        compact.insert("error".into(), json!(error));
    }
    Value::Object(compact)
}

fn canonical_request(
    sequence: &AtomicU64,
    session_id: Option<String>,
    method: CanonicalMethod,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: format!("rpc_{}", sequence.fetch_add(1, Ordering::Relaxed)),
        session_id,
        method,
        expected_revision: None,
        idempotency_key: None,
        parameters,
    }
}

fn take_required_string(object: &mut Map<String, Value>, name: &str) -> Result<String, RpcFault> {
    take_string(object, name)?.ok_or_else(|| RpcFault::invalid(format!("{name} is required")))
}

fn take_string(object: &mut Map<String, Value>, name: &str) -> Result<Option<String>, RpcFault> {
    match object.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(RpcFault::invalid(format!("{name} must be a string"))),
    }
}

fn take_u64(object: &mut Map<String, Value>, name: &str) -> Result<Option<u64>, RpcFault> {
    match object.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| RpcFault::invalid(format!("{name} must be unsigned"))),
        Some(_) => Err(RpcFault::invalid(format!("{name} must be unsigned"))),
    }
}

fn core_fault(code: impl Into<String>, message: impl Into<String>) -> RpcFault {
    RpcFault {
        code: -32001,
        message: message.into(),
        data: Some(json!({"gdb_ai_code": code.into()})),
    }
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_fault(id: Value, fault: RpcFault) -> Value {
    let mut error = json!({"code": fault.code, "message": fault.message});
    if let Some(data) = fault.data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    rpc_fault(
        id,
        RpcFault {
            code,
            message: message.into(),
            data: None,
        },
    )
}

fn valid_request_id(id: &Value) -> bool {
    id.as_str().is_some_and(|id| id.len() <= 128) || id.as_i64().is_some() || id.as_u64().is_some()
}

fn request_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

pub(super) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if line.len() + consumed > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("JSON-RPC message exceeds {maximum} bytes"),
            ));
        }
        line.extend_from_slice(&buffer[..consumed]);
        reader.consume(consumed);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

pub(super) async fn write_rpc<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: Value,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

pub(super) trait ErrorCodeName {
    fn code_name(&self) -> String;
}

impl ErrorCodeName for gdb_ai_core::ErrorCode {
    fn code_name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "INTERNAL".into())
    }
}

#[cfg(test)]
mod tests;

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use gdb_ai_core::{
    domain::{Consistency, SessionState, TargetOrigin},
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse, CanonicalMethod},
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt},
    task::JoinHandle,
};

use crate::tool_catalog::{
    DEFAULT_MCP_IO_READ_BYTES, discriminator_for_tool, method_for_tool, tool_exists, tools,
};

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
const MAX_RPC_FAULT_BYTES: usize = 4 * 1024;
const MAX_PROGRESS_TOKEN_BYTES: usize = 128;
const MAX_TOOL_SUMMARY_BYTES: usize = 512;

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

// 2026-08-31: An accepted continue can precede the running notification, so
// immediate PTY input must request a running-state fence instead of racing it.
const AGENT_INSTRUCTIONS: &str = "Use tools/list. Create once, keep session_id, then launch; \
argv excludes the program path. MCP manages leases and revisions. Returned stop_id scopes \
inspection and expires on resume. For exploit loops use stop=none, byte-exact PTY input \
(include required LF), then wait until settled; request running before PTY input after \
continue. Reuse the session with restart, batch deterministic input, and prefer gdb_batch \
or gdb_agent probe. Start crash triage with profile=brief. PTY mutation needs a server \
configured for lab_mutation. Query a returned operation_id with operation_status. Close \
the session when done.";

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
        // 2026-08-31: Echoing an unsupported near-limit version in both the
        // message and data doubled a caller-controlled MCP response.
        return Err(RpcFault {
            code: -32022,
            message: "unsupported MCP protocol version".into(),
            data: Some(json!({"supported": [STATELESS_MCP_VERSION]})),
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
    match token {
        // 2026-08-31: An unbounded string token was repeated in both progress
        // notifications. Match the existing bounded request-ID convention.
        Value::String(token) if token.len() <= MAX_PROGRESS_TOKEN_BYTES => {
            Ok(Some(Value::String(token.clone())))
        }
        Value::Number(_) => Ok(Some(token.clone())),
        Value::String(_) => Err(RpcFault::invalid(
            "_meta.progressToken must be at most 128 bytes",
        )),
        _ => Err(RpcFault::invalid(
            "_meta.progressToken must be a string or number",
        )),
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
    if let Some((mut request, presentation)) =
        canonical_rpc_request(method, &mut params, advanced_tools, caller.admin, sequence)?
    {
        prepare_canonical_request(gateway, caller, &mut request, presentation).await?;
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
        "resources/list" => list_resources(gateway, caller).await,
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
    mut request: ApiRequest,
    presentation: CanonicalPresentation,
    waiter_timeout: Option<Duration>,
) -> Result<(String, JoinHandle<Result<Value, RpcFault>>), RpcFault> {
    prepare_canonical_request(&gateway, &caller, &mut request, presentation).await?;
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
    let Some((mut request, presentation)) = canonical_rpc_request(
        "tools/call",
        &mut params,
        advanced_tools,
        caller.admin,
        sequence,
    )?
    else {
        unreachable!("tools/call always maps to a canonical request")
    };
    prepare_canonical_request(gateway, caller, &mut request, presentation).await?;
    present_canonical_response(gateway.dispatch(request, caller).await, presentation)
}

async fn prepare_canonical_request(
    gateway: &Gateway,
    caller: &Caller,
    request: &mut ApiRequest,
    presentation: CanonicalPresentation,
) -> Result<(), RpcFault> {
    if matches!(presentation, CanonicalPresentation::Tool(_)) {
        gateway
            .prepare_agent_request(request, caller)
            .await
            .map_err(|error| core_fault(format!("{:?}", error.code), error.message))?;
    }
    Ok(())
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
    // 2026-08-31: Global MCP actions advertised and accepted a session ID,
    // allowing session.create responses to be labeled with an invented ID.
    if session_id.is_some() && !method.requires_session() {
        return Err(RpcFault::invalid(
            "global action does not accept session_id",
        ));
    }
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
        ("gdb_io", CanonicalMethod::InferiorIoRead, Some("read")) => {
            // 2026-08-31: Omitted MCP reads returned up to 64 KiB and could
            // consume 88 KiB after binary encoding. Keep larger reads explicit.
            parameters
                .entry("max_bytes")
                .or_insert(Value::from(DEFAULT_MCP_IO_READ_BYTES));
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
    let mut summary = match &response.error {
        Some(error) => format!("{}: {}", error.code.code_name(), error.message),
        // 2026-08-30: The structured result already carries the revision.
        // Repeating it in successful text content costs tokens on every Agent
        // call without adding information.
        None => "ok".into(),
    };
    // 2026-08-31: MCP text duplicated potentially large structured errors.
    // Keep a short compatibility summary and preserve the full error below.
    if summary.len() > MAX_TOOL_SUMMARY_BYTES {
        let mut end = MAX_TOOL_SUMMARY_BYTES - 3;
        while !summary.is_char_boundary(end) {
            end -= 1;
        }
        summary.truncate(end);
        summary.push_str("...");
    }
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
        session_id: _,
        revision: _,
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
    let preserve_full_state = method == CanonicalMethod::EventsWait
        && result
            .as_ref()
            .and_then(|result| result.get("coalesced"))
            .and_then(Value::as_bool)
            == Some(true)
        && state.is_some();
    // 2026-08-31: Root status, list, and target states are explicitly
    // requested data. Preserve them; only nested command state duplicates the
    // compact envelope and is safe to remove below.
    if let Some(Value::Object(result)) = result.as_mut() {
        // 2026-08-31: Removing nested state by field name discarded the exact
        // state that satisfied execution.wait when the envelope had already
        // advanced. Only byte-equivalent state is redundant.
        if result.get("state").is_some_and(|result_state| {
            state.as_ref().is_some_and(|state| {
                serde_json::to_value(state).is_ok_and(|state| state == *result_state)
            })
        }) {
            result.remove("state");
        }
        // 2026-08-31: Removing these fields by name also stripped explicit
        // capability discovery. Only serialized CommandReply values duplicate
        // promoted evidence; capability maps and string inventories are data.
        if !matches!(
            method,
            CanonicalMethod::RawMi | CanonicalMethod::RawConsole | CanonicalMethod::KernelMonitor
        ) {
            if result.get("command").is_some_and(is_command_reply) {
                result.remove("command");
            }
            if result
                .get("commands")
                .and_then(Value::as_array)
                .is_some_and(|commands| {
                    !commands.is_empty() && commands.iter().all(is_command_reply)
                })
            {
                result.remove("commands");
            }
        }
        if matches!(
            method,
            CanonicalMethod::TargetLaunch
                | CanonicalMethod::TargetAttach
                | CanonicalMethod::TargetConnectRemote
                | CanonicalMethod::TargetOpenCore
                | CanonicalMethod::TargetRestart
        ) {
            // 2026-08-31: Target setup echoed the refreshed capability
            // registry even though projected tools provide explicit discovery.
            // Keep lifecycle replies focused on the resulting target state.
            result.remove("capabilities");
        }
        if matches!(
            method,
            CanonicalMethod::TargetLaunch
                | CanonicalMethod::TargetAttach
                | CanonicalMethod::TargetConnectRemote
                | CanonicalMethod::TargetOpenCore
                | CanonicalMethod::TargetDetach
                | CanonicalMethod::TargetRestart
                | CanonicalMethod::TargetKill
        ) {
            // 2026-08-31: A snapshot could advance while a lifecycle response
            // was assembled, defeating byte-equality deduplication and
            // returning both an older full state and the current compact one.
            result.remove("state");
        }
        match method {
            CanonicalMethod::SessionCreate => {
                // 2026-08-31: Session creation repeated the hidden lease,
                // complete capabilities, backend PTY, and initial state before
                // the Agent had a target. Keep only launch-relevant identity.
                result.retain(|field, _| matches!(field.as_str(), "session_id" | "profile"));
                state = None;
            }
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
        if let Some(result_state) = result.get("state")
            && let Ok(result_state) = serde_json::from_value::<SessionState>(result_state.clone())
        {
            // 2026-08-31: Execution waits retained a complete matched state
            // beside the compact current state. Preserve a real target-state
            // transition, but discard registries, coordination-only drift,
            // and superseded snapshot-building progress for the same stop.
            let matched = session_coordination_state(&result_state);
            let same_target_state = state.as_ref().is_some_and(|current| {
                let current = session_coordination_state(current);
                current == matched || {
                    let mut current = current;
                    let mut matched = matched.clone();
                    current.as_object_mut().unwrap().remove("snapshot");
                    matched.as_object_mut().unwrap().remove("snapshot");
                    current == matched
                }
            });
            if same_target_state {
                result.remove("state");
            } else {
                result.insert("state".into(), matched);
            }
        }
        if matches!(
            method,
            CanonicalMethod::InspectionGet | CanonicalMethod::InspectionBatch
        ) {
            for value in result.values_mut() {
                compact_mapping_metadata(value);
            }
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
    // 2026-08-31: MCP owns session routing and revisions. Echoing both after
    // every call consumed context without changing the next debugging action.
    if let Some(state) = state.as_ref() {
        compact.insert(
            "state".into(),
            if preserve_full_state {
                json!(state)
            } else {
                session_coordination_state(state)
            },
        );
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
    // 2026-08-31: Successful structured results already contain the debugger
    // facts an Agent requested; repeating journal URIs on every call added no
    // exploit semantics. Retain them only when diagnosing a failed operation.
    if error.is_some() && !evidence.is_empty() {
        compact.insert("evidence".into(), json!(evidence));
    }
    if let Some(error) = error {
        compact.insert("error".into(), json!(error));
    }
    Value::Object(compact)
}

fn compact_mapping_metadata(value: &mut Value) {
    match value {
        Value::Object(object) => {
            // 2026-09-01: Repeating filesystem identity and provider names on
            // every segment dominated mapping views without helping exploit
            // address decisions. Canonical results retain that metadata.
            if ["start", "end", "offset", "permissions", "path"]
                .iter()
                .all(|field| object.contains_key(*field))
            {
                object.remove("device");
                object.remove("inode");
                object.remove("source");
            }
            for child in object.values_mut() {
                compact_mapping_metadata(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                compact_mapping_metadata(child);
            }
        }
        _ => {}
    }
}

fn is_command_reply(value: &Value) -> bool {
    value.get("record").is_some_and(Value::is_object)
        && value.get("stream_records").is_some_and(Value::is_array)
        && value.get("evidence_seq").is_some_and(Value::is_u64)
}

fn session_coordination_state(state: &SessionState) -> Value {
    let mut summary = json!({
        "lifecycle": state.lifecycle,
        "backend": state.backend
    });
    let summary = summary.as_object_mut().unwrap();
    if state.consistency != Consistency::Clean {
        summary.insert("consistency".into(), json!(state.consistency));
    }
    if state.reconciliation_required {
        summary.insert("reconciliation_required".into(), Value::Bool(true));
    }
    if state.target_origin != TargetOrigin::Unknown {
        summary.insert("target_origin".into(), json!(state.target_origin));
    }
    let inferior = state
        .stopped_inferior_id
        .as_ref()
        .and_then(|id| state.inferiors.values().find(|inferior| &inferior.id == id))
        .or_else(|| {
            (state.inferiors.len() == 1)
                .then(|| state.inferiors.values().next())
                .flatten()
        });
    if let Some(inferior) = inferior {
        summary.insert("status".into(), json!(inferior.status));
        if let Some(pid) = inferior.pid {
            summary.insert("pid".into(), Value::from(pid));
        }
        if let Some(exit_code) = &inferior.exit_code {
            summary.insert("exit_code".into(), Value::String(exit_code.clone()));
        }
    }
    if !state.outcome_unknown_tokens.is_empty() {
        summary.insert(
            "outcome_unknown_tokens".into(),
            json!(state.outcome_unknown_tokens),
        );
    }
    if let Some(stop_id) = &state.stop_id {
        summary.insert("stop_id".into(), json!(stop_id));
    }
    if let Some(reason) = &state.stop_reason_detail {
        summary.insert("stop_reason".into(), json!(reason));
    } else if let Some(reason) = &state.stop_reason {
        summary.insert("stop_reason".into(), Value::String(reason.clone()));
    }
    if let Some(inferior_id) = &state.stopped_inferior_id {
        summary.insert("inferior_id".into(), json!(inferior_id));
    }
    if let Some(thread_id) = &state.stopped_thread_id {
        summary.insert("thread_id".into(), json!(thread_id));
    }
    // 2026-08-31: The compact stop state omitted an already captured frame,
    // forcing Agents to spend another tool call on stop_context.
    if let Some(frame) = state.stopped_frame() {
        summary.insert("frame".into(), json!(frame));
    }
    if let Some(snapshot) = &state.snapshot {
        summary.insert("snapshot".into(), json!(snapshot));
    }
    Value::Object(std::mem::take(summary))
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
    let code = fault.code;
    let mut error = json!({"code": code, "message": fault.message});
    if let Some(data) = fault.data {
        error["data"] = data;
    }
    // 2026-08-31: Fault messages and data could echo caller-controlled fields
    // up to the inbound limit. Replace an oversized fault as valid JSON while
    // preserving its code; successful and canonical responses stay unchanged.
    if serde_json::to_vec(&error).map_or(true, |bytes| bytes.len() > MAX_RPC_FAULT_BYTES) {
        error = json!({"code": code, "message": "error details exceeded limit"});
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

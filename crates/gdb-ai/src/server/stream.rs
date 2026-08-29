use std::{
    collections::HashMap,
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
};

use gdb_ai_core::{
    config::Config,
    gateway::{Caller, Gateway},
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    net::UnixListener,
    sync::mpsc,
    task::JoinHandle,
};

use super::{
    MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, Phase, RequestCancellation, RpcOutput,
    admit_canonical_operation, apply_cancel_mode, canonical_rpc_request, dispatch_rpc, initialize,
    progress_notification, progress_token, read_line_bounded, request_cancellation, request_key,
    rpc_error, rpc_fault, rpc_result, valid_request_id, write_rpc,
};
use crate::AnyError;

struct StreamPending {
    waiter: JoinHandle<()>,
    cancellation: RequestCancellation,
}

pub(crate) async fn serve_stdio(
    config: Config,
    raw_admin: bool,
    advanced_tools: bool,
) -> Result<(), AnyError> {
    let gateway = Arc::new(Gateway::new(config)?);
    let result = serve_stream(
        gateway.clone(),
        Caller {
            identity: "mcp-stdio".into(),
            admin: raw_admin,
        },
        advanced_tools,
        tokio::io::stdin(),
        tokio::io::stdout(),
    )
    .await;
    gateway.shutdown().await;
    result
}

async fn serve_stream<R, W>(
    gateway: Arc<Gateway>,
    mut caller: Caller,
    advanced_tools: bool,
    input: R,
    mut output: W,
) -> Result<(), AnyError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let sequence = Arc::new(AtomicU64::new(1));
    let mut phase = Phase::New;
    let mut pending: HashMap<String, StreamPending> = HashMap::new();
    let mut input_open = true;
    let (responses, mut response_rx) = mpsc::channel::<RpcOutput>(128);
    let mut input = BufReader::new(input);

    loop {
        // 2026-08-28: EOF ends input, not pending work. Drain completed RPC
        // responses so a final one-shot MCP request is not silently dropped.
        if !input_open && pending.is_empty() {
            break;
        }
        tokio::select! {
            line = read_line_bounded(&mut input, MAX_MESSAGE_BYTES), if input_open => {
                let Some(line) = line? else {
                    input_open = false;
                    continue;
                };
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                let message = match serde_json::from_slice::<Value>(&line) {
                    Ok(message) => message,
                    Err(error) => {
                        write_rpc(&mut output, rpc_error(Value::Null, -32700, error.to_string())).await?;
                        continue;
                    }
                };
                let Some(object) = message.as_object() else {
                    write_rpc(&mut output, rpc_error(Value::Null, -32600, "request must be an object")).await?;
                    continue;
                };
                let id = object.get("id").cloned();
                if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "jsonrpc must be 2.0")).await?;
                    continue;
                }
                let Some(method) = object.get("method").and_then(Value::as_str) else {
                    if id.is_some() {
                        write_rpc(&mut output, rpc_error(id.unwrap_or(Value::Null), -32600, "method is required")).await?;
                    }
                    continue;
                };
                let params = object.get("params").cloned().unwrap_or_else(|| json!({}));

                if id.is_none() {
                    handle_notification(
                        method,
                        &params,
                        &mut phase,
                        &mut pending,
                        &gateway,
                        &caller,
                        &sequence,
                    );
                    continue;
                }
                let id = id.unwrap();
                if !valid_request_id(&id) {
                    write_rpc(&mut output, rpc_error(Value::Null, -32600, "id must be a string or integer")).await?;
                    continue;
                }
                if method == "initialize" {
                    let response = initialize(&params, &mut phase, &mut caller)
                        .map_or_else(|error| rpc_fault(id.clone(), error), |result| rpc_result(id.clone(), result));
                    write_rpc(&mut output, response).await?;
                    continue;
                }
                if method != "ping" && phase != Phase::Ready {
                    write_rpc(&mut output, rpc_error(id, -32002, "server is not initialized")).await?;
                    continue;
                }

                let key = request_key(&id);
                // 2026-08-28: Duplicate IDs replaced cancellation handles and
                // unbounded pending tasks let one connection exhaust memory.
                if pending.contains_key(&key) || pending.len() >= MAX_PENDING_REQUESTS {
                    write_rpc(&mut output, rpc_error(id, -32600, "duplicate request id or too many pending requests")).await?;
                    continue;
                }
                let mut cancellation = match request_cancellation(method, &params) {
                    Ok(cancellation) => cancellation,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                let progress_token = match progress_token(&params) {
                    Ok(progress_token) => progress_token,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                if let Some(token) = &progress_token {
                    write_rpc(
                        &mut output,
                        progress_notification(token.clone(), 0, "request started"),
                    )
                    .await?;
                }
                let canonical = match canonical_rpc_request(
                    method,
                    params.clone(),
                    advanced_tools,
                    caller.admin,
                    &sequence,
                ) {
                    Ok(canonical) => canonical,
                    Err(error) => {
                        write_rpc(&mut output, rpc_fault(id, error)).await?;
                        continue;
                    }
                };
                let (operation_id, operation) = if let Some((request, presentation)) = canonical {
                    match admit_canonical_operation(
                        gateway.clone(),
                        caller.clone(),
                        request,
                        presentation,
                        None,
                    )
                    .await
                    {
                        Ok((operation_id, waiter)) => (Some(operation_id), waiter),
                        Err(error) => {
                            write_rpc(&mut output, rpc_fault(id, error)).await?;
                            continue;
                        }
                    }
                } else {
                    let dispatch_gateway = gateway.clone();
                    let dispatch_caller = caller.clone();
                    let dispatch_sequence = sequence.clone();
                    let method = method.to_owned();
                    (
                        None,
                        tokio::spawn(async move {
                            dispatch_rpc(
                                &dispatch_gateway,
                                &dispatch_caller,
                                advanced_tools,
                                &dispatch_sequence,
                                &method,
                                params,
                            )
                            .await
                        }),
                    )
                };
                cancellation.operation_id = operation_id;
                let responses = responses.clone();
                let task_key = key.clone();
                // Requests may wait for a target stop; separate tasks let
                // cancellation and inferior I/O reach the gateway meanwhile.
                // 2026-08-28: Cancelling the response task used to cancel the
                // Gateway future after a worker had accepted a mutation. Keep
                // dispatch detached so idempotency and audit still complete.
                let handle = tokio::spawn(async move {
                    let response = match operation.await {
                        Ok(result) => result.map_or_else(
                            |error| rpc_fault(id.clone(), error),
                            |result| rpc_result(id.clone(), result),
                        ),
                        Err(error) => rpc_error(id, -32603, error.to_string()),
                    };
                    if let Some(token) = progress_token {
                        let _ = responses
                            .send((
                                None,
                                progress_notification(token, 1, "request completed"),
                            ))
                            .await;
                    }
                    let _ = responses.send((Some(task_key), response)).await;
                });
                pending.insert(
                    key,
                    StreamPending {
                        waiter: handle,
                        cancellation,
                    },
                );
            }
            Some((key, response)) = response_rx.recv() => {
                if let Some(key) = key {
                    pending.remove(&key);
                }
                write_rpc(&mut output, response).await?;
            }
        }
    }

    for request in pending.into_values() {
        request.waiter.abort();
    }
    Ok(())
}

pub(crate) async fn serve_unix(
    config: Config,
    path: PathBuf,
    raw_admin: bool,
    advanced_tools: bool,
) -> Result<(), AnyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace a non-socket Unix path",
            )
            .into());
        }
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let gateway = Arc::new(Gateway::new(config)?);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                // 2026-08-28: Falling back to unix:unknown made every
                // credential lookup failure share one authorization principal.
                let identity = match stream.peer_cred() {
                    Ok(credentials) => format!("unix:uid:{}", credentials.uid()),
                    Err(error) => {
                        tracing::warn!(%error, "rejected Unix client without peer credentials");
                        continue;
                    }
                };
                let (input, output) = stream.into_split();
                let gateway = gateway.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_stream(
                        gateway,
                        Caller { identity, admin: raw_admin },
                        advanced_tools,
                        input,
                        output,
                    )
                    .await
                    {
                        tracing::warn!(%error, "Unix client disconnected with an error");
                    }
                });
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
        }
    }
    gateway.shutdown().await;
    std::fs::remove_file(&path)?;
    Ok(())
}

fn handle_notification(
    method: &str,
    params: &Value,
    phase: &mut Phase,
    pending: &mut HashMap<String, StreamPending>,
    gateway: &Arc<Gateway>,
    caller: &Caller,
    sequence: &Arc<AtomicU64>,
) {
    match method {
        "notifications/initialized" if *phase == Phase::AwaitingInitialized => {
            *phase = Phase::Ready;
        }
        "notifications/cancelled" => {
            if let Some(id) = params.get("requestId")
                && let Some(request) = pending.remove(&request_key(id))
            {
                request.waiter.abort();
                apply_cancel_mode(
                    gateway.clone(),
                    caller.clone(),
                    sequence.clone(),
                    request.cancellation,
                );
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read_json_line;
    use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    use super::super::{MCP_VERSION, call_tool};

    #[tokio::test]
    async fn bounds_stdio_messages() {
        let mut input = BufReader::new(&b"{\"ok\":true}\r\nnext\n"[..]);
        assert_eq!(
            read_line_bounded(&mut input, 32).await.unwrap().unwrap(),
            b"{\"ok\":true}"
        );
        assert_eq!(
            read_line_bounded(&mut input, 32).await.unwrap().unwrap(),
            b"next"
        );
        let mut oversized = BufReader::new(&b"12345\n"[..]);
        assert!(read_line_bounded(&mut oversized, 4).await.is_err());
    }

    #[tokio::test]
    async fn mcp_tool_gates_and_audits_raw_session() {
        let gdb_available = std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_ok();
        if !gdb_available {
            // 2026-08-29: This server test bypassed the integration helper,
            // allowing required CI to pass without exercising MCP over GDB.
            if std::env::var_os("GDB_AI_REQUIRE_INTEGRATION").is_some() {
                panic!("required GDB executable is unavailable");
            }
            eprintln!("skipped MCP GDB test; GDB is unavailable");
            return;
        }
        let directory = tempdir().unwrap();
        let config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        let gateway = Gateway::new(config).unwrap();
        let caller = Caller {
            identity: "mcp-test".into(),
            admin: true,
        };
        let sequence = AtomicU64::new(1);
        let created = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {"action": "create", "profile": "raw_admin"}
            }),
        )
        .await
        .unwrap();
        assert_eq!(created["isError"], false, "{created}");
        let response = &created["structuredContent"];
        let session_id = response["session_id"].as_str().unwrap();
        let revision = response["revision"].as_u64().unwrap();
        let lease_id = response["result"]["write_lease"]["lease_id"]
            .as_str()
            .unwrap();
        let invalid = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "console",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "show language",
                    "timeout_ms": 0
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(invalid["isError"], true);
        assert_eq!(
            invalid["structuredContent"]["state"]["consistency"],
            "CLEAN"
        );
        assert_eq!(invalid["structuredContent"]["revision"], revision);
        let raw = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "console",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "show language"
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(raw["isError"], false);
        assert_eq!(raw["structuredContent"]["state"]["consistency"], "TAINTED");
        assert_eq!(
            raw["structuredContent"]["state"]["reconciliation_required"],
            false
        );
        let console = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_io",
                "arguments": {
                    "action": "read",
                    "session_id": session_id,
                    "stream": "console",
                    "after_offset": 0
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(console["isError"], false);
        assert!(
            console["structuredContent"]["result"]["text"]
                .as_str()
                .is_some_and(|text| text.contains("source language"))
        );
        let revision = raw["structuredContent"]["revision"].as_u64().unwrap();
        let denied = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_raw",
                "arguments": {
                    "action": "mi",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id,
                    "command": "-target-select",
                    "arguments": ["remote", "203.0.113.1:1"]
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(denied["isError"], true);
        assert_eq!(
            denied["structuredContent"]["error"]["code"],
            "POLICY_DENIED"
        );
        let closed = call_tool(
            &gateway,
            &caller,
            false,
            &sequence,
            json!({
                "name": "gdb_session",
                "arguments": {
                    "action": "close",
                    "session_id": session_id,
                    "expected_revision": revision,
                    "lease_id": lease_id
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(closed["isError"], false);
    }

    #[tokio::test]
    async fn stream_protocol_runs_over_a_unix_compatible_byte_stream() {
        let directory = tempdir().unwrap();
        let config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        let gateway = Arc::new(Gateway::new(config).unwrap());
        let (client, server) = tokio::io::duplex(128 * 1024);
        let (client_input, mut client_output) = tokio::io::split(client);
        let (server_input, server_output) = tokio::io::split(server);
        let serving = tokio::spawn(serve_stream(
            gateway.clone(),
            Caller::local("stream-test"),
            false,
            server_input,
            server_output,
        ));
        let mut client_input = BufReader::new(client_input);
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "stream-test", "version": "1"}
                }
            }),
        )
        .await
        .unwrap();
        let initialized = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(initialized["result"]["protocolVersion"], MCP_VERSION);
        write_rpc(
            &mut client_output,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        )
        .await
        .unwrap();
        write_rpc(
            &mut client_output,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": {"progressToken": "list-progress"}}
            }),
        )
        .await
        .unwrap();
        let started = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(started["method"], "notifications/progress");
        assert_eq!(started["params"]["progressToken"], "list-progress");
        assert_eq!(started["params"]["progress"], 0);
        let completed = read_json_line(&mut client_input).await.unwrap();
        assert_eq!(completed["method"], "notifications/progress");
        assert_eq!(completed["params"]["progress"], 1);
        let tools = read_json_line(&mut client_input).await.unwrap();
        assert!(tools["result"]["tools"].as_array().is_some());
        client_output.shutdown().await.unwrap();
        drop(client_output);
        serving.await.unwrap().unwrap();
        gateway.shutdown().await;
    }
}

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_core::{
    config::Config,
    domain::SessionId,
    gateway::{Caller, Gateway},
};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, RwLock, Semaphore, oneshot},
    task::JoinHandle,
};

use super::{
    MAX_HTTP_PENDING_DURATION, MAX_MESSAGE_BYTES, MAX_PENDING_REQUESTS, MCP_VERSION, Phase,
    RequestCancellation, RpcFault, STATELESS_MCP_VERSION, admit_canonical_operation,
    apply_cancel_mode, canonical_rpc_request, dispatch_rpc, initialize, request_cancellation,
    request_key, rpc_error, rpc_fault, rpc_result, stateless_request, stateless_result,
    valid_request_id,
};
use crate::AnyError;

struct HttpPending {
    generation: u64,
    cancel_waiter: Option<oneshot::Sender<()>>,
    cancellation: RequestCancellation,
    deadline: Instant,
}

struct TrackedOperation {
    gateway: Arc<Gateway>,
    caller: Caller,
    operation_id: String,
}

struct HttpCompletion {
    reservation: Option<HttpReservation>,
    response_id: Value,
    deadline: Instant,
    tracked: Option<TrackedOperation>,
    stateless_method: Option<String>,
    _permit: Option<OwnedSemaphorePermit>,
    response: oneshot::Sender<Value>,
}

struct HttpReservation {
    sessions: Arc<RwLock<HashMap<String, HttpClient>>>,
    session_id: String,
    key: String,
    generation: u64,
}

#[derive(Clone)]
struct HttpState {
    gateway: Arc<Gateway>,
    sessions: Arc<RwLock<HashMap<String, HttpClient>>>,
    stateless_pending: Arc<Semaphore>,
    sequence: Arc<AtomicU64>,
    raw_admin: bool,
    advanced_tools: bool,
    auth_token: Option<Arc<str>>,
    trusted_origins: Arc<[HeaderValue]>,
    max_sessions: usize,
    idle_timeout: Duration,
}

struct HttpClient {
    phase: Phase,
    protocol_version: String,
    caller: Caller,
    pending: HashMap<String, HttpPending>,
    last_active: Instant,
}

pub(crate) async fn serve_http(
    config: Config,
    address: SocketAddr,
    raw_admin: bool,
    advanced_tools: bool,
    auth_token_file: Option<PathBuf>,
    trusted_origins: Vec<String>,
) -> Result<(), AnyError> {
    validate_http_address(address)?;
    let trusted_origins = parse_trusted_origins(&trusted_origins)?;
    let auth_token = auth_token_file
        .map(|path| -> Result<Arc<str>, AnyError> {
            let metadata = std::fs::metadata(&path)?;
            if !metadata.is_file()
                || metadata.len() == 0
                || metadata.len() > 4_096
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "token file must be regular, private, and contain 1 to 4096 bytes",
                )
                .into());
            }
            let token = std::fs::read_to_string(path)?;
            let token = token.trim();
            if token.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "authentication token is empty",
                )
                .into());
            }
            Ok(Arc::from(token))
        })
        .transpose()?;
    let max_sessions = config.server.max_http_sessions;
    let idle_timeout = Duration::from_millis(config.server.http_session_idle_ms);
    let gateway = Arc::new(Gateway::new(config)?);
    let state = HttpState {
        gateway: gateway.clone(),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
        sequence: Arc::new(AtomicU64::new(1)),
        raw_admin,
        advanced_tools,
        auth_token,
        trusted_origins,
        max_sessions,
        idle_timeout,
    };
    let router = Router::new()
        .route("/mcp", post(http_mcp).get(http_get).delete(http_delete))
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/metrics", get(http_metrics))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE_BYTES))
        .with_state(state.clone());
    let listener = TcpListener::bind(address).await?;
    let eviction_state = state.clone();
    let eviction = tokio::spawn(async move {
        loop {
            tokio::time::sleep(eviction_state.idle_timeout.min(Duration::from_secs(60))).await;
            evict_http_sessions(&eviction_state).await;
        }
    });
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    eviction.abort();
    gateway.shutdown().await;
    Ok(())
}

async fn http_mcp(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(mut message): Json<Value>,
) -> Response {
    if !allow_http_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !accepts_mcp_responses(&headers) {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let Some(object) = message.as_object_mut() else {
        return json_http_response(
            rpc_error(Value::Null, -32600, "request must be an object"),
            None,
        );
    };
    let id = object.remove("id");
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return json_http_response(
            rpc_error(id.unwrap_or(Value::Null), -32600, "jsonrpc must be 2.0"),
            None,
        );
    }
    let Some(Value::String(method)) = object.remove("method") else {
        return json_http_response(
            rpc_error(id.unwrap_or(Value::Null), -32600, "method is required"),
            None,
        );
    };
    let mut params = object.remove("params").unwrap_or_else(|| json!({}));
    if uses_stateless_http(&headers, &params) {
        return http_mcp_stateless(state, headers, id, &method, params).await;
    }
    if method == "initialize" {
        let Some(id) = id else {
            return StatusCode::ACCEPTED.into_response();
        };
        if params.get("protocolVersion").and_then(Value::as_str) != Some(MCP_VERSION) {
            let mut response = json_http_response(
                rpc_error(id, -32602, "Streamable HTTP supports only 2025-11-25"),
                None,
            );
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return response;
        }
        let mut phase = Phase::New;
        let mut caller = Caller {
            identity: "mcp-http".into(),
            admin: state.raw_admin,
        };
        let response = initialize(&params, &mut phase, &mut caller).map_or_else(
            |error| rpc_fault(id.clone(), error),
            |result| rpc_result(id.clone(), result),
        );
        if phase == Phase::New {
            return json_http_response(response, None);
        }
        let session_id = format!("mcp_{}", SessionId::new().0);
        let mut sessions = state.sessions.write().await;
        evict_expired_http_clients(&mut sessions, Instant::now(), state.idle_timeout);
        if sessions.len() >= state.max_sessions {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "MCP HTTP session limit reached",
            )
                .into_response();
        }
        sessions.insert(
            session_id.clone(),
            HttpClient {
                phase,
                protocol_version: MCP_VERSION.into(),
                caller,
                pending: HashMap::new(),
                last_active: Instant::now(),
            },
        );
        return json_http_response(response, Some(&session_id));
    }
    let Some(session_id) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "Mcp-Session-Id is required").into_response();
    };
    let (phase, caller) = {
        let mut sessions = state.sessions.write().await;
        evict_expired_http_clients(&mut sessions, Instant::now(), state.idle_timeout);
        let Some(client) = sessions.get_mut(session_id) else {
            return (StatusCode::NOT_FOUND, "MCP session not found").into_response();
        };
        if !http_protocol_version_matches(&headers, &client.protocol_version) {
            return (
                StatusCode::BAD_REQUEST,
                "Mcp-Protocol-Version is missing, repeated, or unsupported",
            )
                .into_response();
        }
        client.last_active = Instant::now();
        (client.phase, client.caller.clone())
    };
    if id.is_none() {
        let mut sessions = state.sessions.write().await;
        if let Some(client) = sessions.get_mut(session_id) {
            if method == "notifications/initialized" && client.phase == Phase::AwaitingInitialized {
                client.phase = Phase::Ready;
            } else if method == "notifications/cancelled"
                && let Some(id) = params.get("requestId")
                && let Some(pending) = client.pending.remove(&request_key(id))
            {
                cancel_http_waiter(&state, client.caller.clone(), pending);
            }
        }
        return StatusCode::ACCEPTED.into_response();
    }
    let id = id.unwrap();
    if !valid_request_id(&id) {
        return json_http_response(
            rpc_error(Value::Null, -32600, "id must be a string or integer"),
            Some(session_id),
        );
    }
    if method != "ping" && phase != Phase::Ready {
        return json_http_response(
            rpc_error(id, -32002, "server is not initialized"),
            Some(session_id),
        );
    }
    let key = request_key(&id);
    let cancellation = match request_cancellation(&method, &params) {
        Ok(cancellation) => cancellation,
        Err(error) => return json_http_response(rpc_fault(id, error), Some(session_id)),
    };
    let admitted_cancellation = cancellation.clone();
    let canonical = match canonical_rpc_request(
        &method,
        &mut params,
        state.advanced_tools,
        caller.admin,
        &state.sequence,
    ) {
        Ok(canonical) => canonical,
        Err(error) => return json_http_response(rpc_fault(id, error), Some(session_id)),
    };
    let deadline = Instant::now() + MAX_HTTP_PENDING_DURATION;
    let pending_generation = state.sequence.fetch_add(1, Ordering::Relaxed);
    let (cancel_waiter, cancelled) = oneshot::channel();
    let reserved = {
        let mut sessions = state.sessions.write().await;
        sessions.get_mut(session_id).is_some_and(|client| {
            if client.pending.contains_key(&key) || client.pending.len() >= MAX_PENDING_REQUESTS {
                false
            } else {
                client.pending.insert(
                    key.clone(),
                    HttpPending {
                        generation: pending_generation,
                        cancel_waiter: Some(cancel_waiter),
                        cancellation,
                        deadline,
                    },
                );
                true
            }
        })
    };
    if !reserved {
        return json_http_response(
            rpc_error(
                id,
                -32600,
                "duplicate request id or too many pending requests",
            ),
            Some(session_id),
        );
    }
    let response_id = id.clone();
    let (operation_id, operation) = if let Some((request, presentation)) = canonical {
        let (operation_id, waiter) = match admit_canonical_operation(
            state.gateway.clone(),
            caller.clone(),
            request,
            presentation,
            Some(deadline.saturating_duration_since(Instant::now())),
        )
        .await
        {
            Ok(operation) => operation,
            Err(error) => {
                if let Some(client) = state.sessions.write().await.get_mut(session_id) {
                    client.pending.remove(&key);
                }
                return json_http_response(rpc_fault(id, error), Some(session_id));
            }
        };
        let cancelled_during_admission = {
            let mut sessions = state.sessions.write().await;
            bind_http_operation(
                sessions
                    .get_mut(session_id)
                    .and_then(|client| client.pending.get_mut(&key)),
                &operation_id,
                admitted_cancellation,
            )
        };
        if let Some(cancellation) = cancelled_during_admission {
            // 2026-08-30: A concurrent cancellation could remove pending
            // before admission supplied its operation ID. Apply that recorded
            // policy now instead of losing cancellation of an accepted run.
            apply_cancel_mode(
                state.gateway.clone(),
                caller.clone(),
                state.sequence.clone(),
                cancellation,
            );
        }
        (Some(operation_id), waiter)
    } else {
        let gateway = state.gateway.clone();
        let sequence = state.sequence.clone();
        let advanced_tools = state.advanced_tools;
        let method = method.clone();
        let dispatch_caller = caller.clone();
        (
            None,
            tokio::spawn(async move {
                dispatch_rpc(
                    &gateway,
                    &dispatch_caller,
                    advanced_tools,
                    &sequence,
                    &method,
                    params,
                )
                .await
            }),
        )
    };
    let (response_sender, mut response_receiver) = oneshot::channel();
    tokio::spawn(complete_http_operation(
        HttpCompletion {
            reservation: Some(HttpReservation {
                sessions: state.sessions.clone(),
                session_id: session_id.to_owned(),
                key,
                generation: pending_generation,
            }),
            response_id,
            deadline,
            tracked: operation_id.map(|operation_id| TrackedOperation {
                gateway: state.gateway.clone(),
                caller,
                operation_id,
            }),
            stateless_method: None,
            _permit: None,
            response: response_sender,
        },
        operation,
    ));
    let mut cancelled = cancelled;
    // 2026-08-29: Normal completion drops the stored cancellation sender.
    // Only an explicit signal cancels the waiter; channel close awaits result.
    let response = tokio::select! {
        response = &mut response_receiver => response.unwrap_or_else(|_| {
            rpc_error(id.clone(), -32603, "request completion channel closed")
        }),
        cancellation = &mut cancelled => match cancellation {
            Ok(()) => rpc_error(id, -32800, "request waiter cancelled"),
            Err(_) => response_receiver.await.unwrap_or_else(|_| {
                rpc_error(id, -32603, "request completion channel closed")
            }),
        },
    };
    json_http_response(response, Some(session_id))
}

async fn http_mcp_stateless(
    state: HttpState,
    headers: HeaderMap,
    id: Option<Value>,
    method: &str,
    mut params: Value,
) -> Response {
    let validation = stateless_request(&params).and_then(|stateless| {
        if stateless {
            validate_stateless_headers(&headers, method, &params)
        } else {
            Err(RpcFault::invalid("2026-07-28 request metadata is required"))
        }
    });
    if let Err(error) = validation {
        let mut response = json_http_response_for(
            rpc_fault(id.unwrap_or(Value::Null), error),
            None,
            STATELESS_MCP_VERSION,
        );
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    }
    let Some(id) = id else {
        return StatusCode::ACCEPTED.into_response();
    };
    if !valid_request_id(&id) {
        return json_http_response_for(
            rpc_error(Value::Null, -32600, "id must be a string or integer"),
            None,
            STATELESS_MCP_VERSION,
        );
    }
    let permit = match state.stateless_pending.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response(),
    };
    // 2026-08-30: Releasing admission when a client drops its socket let it
    // accumulate detached work. Completion owns the permit until termination.
    let caller = Caller {
        identity: "mcp-http".into(),
        admin: state.raw_admin,
    };
    if let Err(error) = request_cancellation(method, &params) {
        return json_http_response_for(rpc_fault(id, error), None, STATELESS_MCP_VERSION);
    }
    let canonical = match canonical_rpc_request(
        method,
        &mut params,
        state.advanced_tools,
        caller.admin,
        &state.sequence,
    ) {
        Ok(canonical) => canonical,
        Err(error) => {
            return json_http_response_for(rpc_fault(id, error), None, STATELESS_MCP_VERSION);
        }
    };
    let deadline = Instant::now() + MAX_HTTP_PENDING_DURATION;
    let (operation_id, operation) = if let Some((request, presentation)) = canonical {
        match admit_canonical_operation(
            state.gateway.clone(),
            caller.clone(),
            request,
            presentation,
            Some(deadline.saturating_duration_since(Instant::now())),
        )
        .await
        {
            Ok((operation_id, waiter)) => (Some(operation_id), waiter),
            Err(error) => {
                return json_http_response_for(rpc_fault(id, error), None, STATELESS_MCP_VERSION);
            }
        }
    } else {
        let gateway = state.gateway.clone();
        let sequence = state.sequence.clone();
        let advanced_tools = state.advanced_tools;
        let method = method.to_owned();
        let dispatch_caller = caller.clone();
        (
            None,
            tokio::spawn(async move {
                dispatch_rpc(
                    &gateway,
                    &dispatch_caller,
                    advanced_tools,
                    &sequence,
                    &method,
                    params,
                )
                .await
            }),
        )
    };
    let (response_sender, response_receiver) = oneshot::channel();
    tokio::spawn(complete_http_operation(
        HttpCompletion {
            reservation: None,
            response_id: id.clone(),
            deadline,
            tracked: operation_id.map(|operation_id| TrackedOperation {
                gateway: state.gateway,
                caller,
                operation_id,
            }),
            stateless_method: Some(method.to_owned()),
            _permit: Some(permit),
            response: response_sender,
        },
        operation,
    ));
    let response = response_receiver
        .await
        .unwrap_or_else(|_| rpc_error(id, -32603, "request completion channel closed"));
    json_http_response_for(response, None, STATELESS_MCP_VERSION)
}

async fn http_get(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    // 2026-08-29: Router-generated GET rejection skipped the mandatory
    // Origin check. Validate the connection before declining optional SSE.
    if !allow_http_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

async fn complete_http_operation(
    completion: HttpCompletion,
    mut operation: JoinHandle<Result<Value, RpcFault>>,
) {
    let completed = tokio::time::timeout_at(
        tokio::time::Instant::from_std(completion.deadline),
        &mut operation,
    )
    .await;
    let value = match completed {
        Ok(Ok(result)) => result.map_or_else(
            |error| rpc_fault(completion.response_id.clone(), error),
            |result| {
                let result = if let Some(method) = completion.stateless_method.as_deref() {
                    stateless_result(method, result)
                } else {
                    result
                };
                rpc_result(completion.response_id.clone(), result)
            },
        ),
        Ok(Err(error)) => rpc_error(completion.response_id.clone(), -32603, error.to_string()),
        Err(_) => {
            operation.abort();
            if let Some(tracked) = completion.tracked {
                let operation_state = match tracked
                    .gateway
                    .detach_operation_waiter(&tracked.operation_id, &tracked.caller)
                    .await
                {
                    Ok(record) => json!(record.status),
                    Err(error) => {
                        tracing::warn!(%error, operation_id = %tracked.operation_id, "failed to detach operation waiter");
                        Value::String("UNKNOWN".into())
                    }
                };
                rpc_fault(
                    completion.response_id.clone(),
                    RpcFault {
                        code: -32001,
                        message: "HTTP request deadline exceeded".into(),
                        data: Some(json!({
                            "operation_id": tracked.operation_id,
                            "operation_state": operation_state
                        })),
                    },
                )
            } else {
                rpc_error(
                    completion.response_id.clone(),
                    -32001,
                    "HTTP request deadline exceeded",
                )
            }
        }
    };
    // 2026-08-29: A dropped HTTP handler used to skip pending cleanup while
    // its detached target operation completed. Completion now owns cleanup.
    if let Some(reservation) = completion.reservation
        && let Some(client) = reservation
            .sessions
            .write()
            .await
            .get_mut(&reservation.session_id)
    {
        remove_http_pending(client, &reservation.key, reservation.generation);
        client.last_active = Instant::now();
    }
    let _ = completion.response.send(value);
}

fn remove_http_pending(client: &mut HttpClient, key: &str, generation: u64) {
    // 2026-08-30: A cancelled request ID could be reused while its completion
    // task was still running. Match the reservation generation so the old
    // completion cannot remove the replacement request.
    if client
        .pending
        .get(key)
        .is_some_and(|pending| pending.generation == generation)
    {
        client.pending.remove(key);
    }
}

async fn evict_http_sessions(state: &HttpState) {
    let now = Instant::now();
    let expired = {
        let mut sessions = state.sessions.write().await;
        let mut expired = Vec::new();
        for client in sessions.values_mut() {
            let keys = client
                .pending
                .iter()
                .filter(|(_, pending)| pending.deadline <= now)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            for key in keys {
                if let Some(pending) = client.pending.remove(&key) {
                    expired.push((client.caller.clone(), pending));
                }
            }
        }
        evict_expired_http_clients(&mut sessions, now, state.idle_timeout);
        expired
    };
    for (caller, pending) in expired {
        cancel_http_waiter(state, caller, pending);
    }
}

fn evict_expired_http_clients(
    sessions: &mut HashMap<String, HttpClient>,
    now: Instant,
    idle_timeout: Duration,
) {
    // 2026-08-28: HTTP MCP sessions previously had no cap or idle eviction,
    // so reconnecting clients could retain transport state without bound.
    sessions.retain(|_, client| {
        !client.pending.is_empty() || now.duration_since(client.last_active) < idle_timeout
    });
}

async fn http_delete(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if !allow_http_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(session_id) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "Mcp-Session-Id is required").into_response();
    };
    let client = {
        let mut sessions = state.sessions.write().await;
        let Some(client) = sessions.get(session_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if !http_protocol_version_matches(&headers, &client.protocol_version) {
            return (
                StatusCode::BAD_REQUEST,
                "Mcp-Protocol-Version is missing, repeated, or unsupported",
            )
                .into_response();
        }
        let Some(client) = sessions.remove(session_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        client
    };
    for pending in client.pending.into_values() {
        cancel_http_waiter(&state, client.caller.clone(), pending);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn http_metrics(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // 2026-08-29: Pending work lived in transport state and was absent from
    // daemon metrics, so leaked or saturated HTTP sessions were invisible.
    let pending = state
        .sessions
        .read()
        .await
        .values()
        .map(|client| client.pending.len())
        .sum::<usize>();
    let body = format!(
        "{}gdbai_http_pending_requests {pending}\n",
        state.gateway.metrics()
    );
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    response
}

fn authorize_http(state: &HttpState, headers: &HeaderMap) -> bool {
    let Some(expected) = &state.auth_token else {
        return true;
    };
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    supplied == Some(expected.as_ref())
}

fn parse_trusted_origins(origins: &[String]) -> io::Result<Arc<[HeaderValue]>> {
    let mut parsed = Vec::with_capacity(origins.len());
    for origin in origins {
        let authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .filter(|authority| {
                !authority.is_empty()
                    && !authority
                        .bytes()
                        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b' ' | b'\t'))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "trusted origins must be HTTP(S) origins without paths",
                )
            })?;
        if authority.starts_with(':') || authority.ends_with(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted origin authority is invalid",
            ));
        }
        let value = HeaderValue::from_str(origin).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted origin is not a header value",
            )
        })?;
        if !parsed.contains(&value) {
            parsed.push(value);
        }
    }
    Ok(Arc::from(parsed))
}

fn validate_http_address(address: SocketAddr) -> io::Result<()> {
    // 2026-08-29: Bearer authentication did not encrypt non-loopback HTTP or
    // prevent direct proxy bypass. Keep plaintext listeners on loopback only.
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HTTP must bind to loopback; terminate remote TLS at a local proxy",
        ))
    }
}

fn allow_http_origin(state: &HttpState, headers: &HeaderMap) -> bool {
    let mut supplied = headers.get_all(header::ORIGIN).iter();
    let Some(origin) = supplied.next() else {
        return true;
    };
    // 2026-08-29: Accepting arbitrary browser Origin values exposed the local
    // MCP endpoint to DNS rebinding. Require one exact configured origin.
    supplied.next().is_none()
        && state
            .trusted_origins
            .iter()
            .any(|allowed| allowed == origin)
}

fn http_protocol_version_matches(headers: &HeaderMap, expected: &str) -> bool {
    let mut supplied = headers.get_all("mcp-protocol-version").iter();
    let Some(version) = supplied.next() else {
        return false;
    };
    // 2026-08-29: HTTP sessions previously forgot negotiation and accepted
    // later requests under any transport version. Bind every request to it.
    supplied.next().is_none() && version.as_bytes() == expected.as_bytes()
}

fn uses_stateless_http(headers: &HeaderMap, params: &Value) -> bool {
    // 2026-08-30: Select the transport era from this request alone; modern
    // clients do not create a protocol session that can retain negotiation.
    params
        .get("_meta")
        .and_then(|metadata| metadata.get("io.modelcontextprotocol/protocolVersion"))
        .is_some()
        || headers
            .get_all("mcp-protocol-version")
            .iter()
            .any(|version| version.as_bytes() != MCP_VERSION.as_bytes())
}

fn validate_stateless_headers(
    headers: &HeaderMap,
    method: &str,
    params: &Value,
) -> Result<(), RpcFault> {
    if !http_protocol_version_matches(headers, STATELESS_MCP_VERSION) {
        return Err(header_mismatch(
            "MCP-Protocol-Version must match 2026-07-28 request metadata",
        ));
    }
    let mirrored_method = single_header(headers, "mcp-method")?
        .ok_or_else(|| header_mismatch("Mcp-Method is required"))?;
    if mirrored_method != method {
        return Err(header_mismatch("Mcp-Method does not match the request"));
    }
    let name = match method {
        "tools/call" => params.get("name").and_then(Value::as_str),
        "resources/read" => params.get("uri").and_then(Value::as_str),
        _ => None,
    };
    if matches!(method, "tools/call" | "resources/read") {
        let name = name.ok_or_else(|| header_mismatch("request name is missing"))?;
        let mirrored_name = decoded_header(headers, "mcp-name")?
            .ok_or_else(|| header_mismatch("Mcp-Name is required"))?;
        if mirrored_name != name {
            return Err(header_mismatch("Mcp-Name does not match the request"));
        }
    }
    Ok(())
}

fn single_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, RpcFault> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(header_mismatch(format!("{name} must not be repeated")));
    }
    value
        .to_str()
        .map(str::to_owned)
        .map(Some)
        .map_err(|_| header_mismatch(format!("{name} is not valid ASCII")))
}

fn decoded_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, RpcFault> {
    let Some(value) = single_header(headers, name)? else {
        return Ok(None);
    };
    let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    else {
        return Ok(Some(value));
    };
    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| header_mismatch(format!("{name} contains invalid base64")))?;
    String::from_utf8(decoded)
        .map(Some)
        .map_err(|_| header_mismatch(format!("{name} contains invalid UTF-8")))
}

fn header_mismatch(message: impl Into<String>) -> RpcFault {
    RpcFault {
        code: -32020,
        message: message.into(),
        data: None,
    }
}

fn accepts_mcp_responses(headers: &HeaderMap) -> bool {
    let mut json = false;
    let mut event_stream = false;
    for value in headers.get_all(header::ACCEPT).iter() {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for media_type in value.split(',') {
            match media_type.split(';').next().map(str::trim) {
                Some("application/json") => json = true,
                Some("text/event-stream") => event_stream = true,
                _ => {}
            }
        }
    }
    // 2026-08-29: Accepting JSON-only clients contradicted the declared MCP
    // Streamable HTTP revision, whose POST contract requires both media types.
    json && event_stream
}

fn json_http_response(value: Value, session_id: Option<&str>) -> Response {
    json_http_response_for(value, session_id, MCP_VERSION)
}

fn json_http_response_for(
    value: Value,
    session_id: Option<&str>,
    protocol_version: &'static str,
) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"null".to_vec());
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static(protocol_version),
    );
    if let Some(session_id) = session_id
        && let Ok(value) = HeaderValue::from_str(session_id)
    {
        response.headers_mut().insert("mcp-session-id", value);
    }
    response
}

fn cancel_http_waiter(state: &HttpState, caller: Caller, pending: HttpPending) {
    if let Some(waiter) = pending.cancel_waiter {
        let _ = waiter.send(());
    }
    apply_cancel_mode(
        state.gateway.clone(),
        caller,
        state.sequence.clone(),
        pending.cancellation,
    );
}

fn bind_http_operation(
    pending: Option<&mut HttpPending>,
    operation_id: &str,
    mut cancellation: RequestCancellation,
) -> Option<RequestCancellation> {
    if let Some(pending) = pending {
        pending.cancellation.operation_id = Some(operation_id.to_owned());
        None
    } else {
        cancellation.operation_id = Some(operation_id.to_owned());
        Some(cancellation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
    use tempfile::tempdir;

    use super::super::CancelMode;

    fn detached_http_pending(
        generation: u64,
        waiter: oneshot::Sender<()>,
        deadline: Instant,
    ) -> HttpPending {
        HttpPending {
            generation,
            cancel_waiter: Some(waiter),
            cancellation: RequestCancellation {
                mode: CancelMode::DetachWaiter,
                operation_id: None,
            },
            deadline,
        }
    }

    #[test]
    fn cancellation_during_admission_targets_the_accepted_operation() {
        let cancellation = RequestCancellation {
            mode: CancelMode::InterruptTarget,
            operation_id: None,
        };
        let late = bind_http_operation(None, "op_late", cancellation.clone()).unwrap();
        assert!(matches!(late.mode, CancelMode::InterruptTarget));
        assert_eq!(late.operation_id.as_deref(), Some("op_late"));

        let (waiter, _cancelled) = oneshot::channel();
        let mut pending = detached_http_pending(1, waiter, Instant::now());
        assert!(bind_http_operation(Some(&mut pending), "op_pending", cancellation).is_none());
        assert_eq!(
            pending.cancellation.operation_id.as_deref(),
            Some("op_pending")
        );

        let mut client = HttpClient {
            phase: Phase::Ready,
            protocol_version: MCP_VERSION.into(),
            caller: Caller::local("pending-generation-test"),
            pending: HashMap::from([("same-id".into(), pending)]),
            last_active: Instant::now(),
        };
        remove_http_pending(&mut client, "same-id", 0);
        assert!(client.pending.contains_key("same-id"));
        remove_http_pending(&mut client, "same-id", 1);
        assert!(client.pending.is_empty());
    }

    #[tokio::test]
    async fn streamable_http_authenticates_and_tracks_mcp_sessions() {
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
        let state = HttpState {
            gateway: gateway.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            advanced_tools: false,
            auth_token: Some(Arc::from("test-token")),
            trusted_origins: parse_trusted_origins(&["https://agent.example".into()]).unwrap(),
            max_sessions: 1,
            idle_timeout: Duration::from_secs(1),
        };
        let unauthorized = http_mcp(
            State(state.clone()),
            HeaderMap::new(),
            Json(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token"),
        );
        let mut forbidden_headers = headers.clone();
        forbidden_headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        let forbidden = http_mcp(
            State(state.clone()),
            forbidden_headers,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "http-evil", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        let mut incomplete_accept = headers.clone();
        incomplete_accept.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let unacceptable = http_mcp(
            State(state.clone()),
            incomplete_accept,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "http-json-only", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(unacceptable.status(), StatusCode::NOT_ACCEPTABLE);
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let unsupported = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "clientInfo": {"name": "http-old", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        assert!(state.sessions.read().await.is_empty());
        let initialized = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "http-test", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(initialized.status(), StatusCode::OK);
        assert_eq!(
            initialized.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let session = initialized.headers().get("mcp-session-id").unwrap().clone();
        headers.insert("mcp-session-id", session);
        let missing_version = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            })),
        )
        .await;
        assert_eq!(missing_version.status(), StatusCode::BAD_REQUEST);
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(MCP_VERSION),
        );
        let ready = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            })),
        )
        .await;
        assert_eq!(ready.status(), StatusCode::ACCEPTED);
        let mut wrong_version = headers.clone();
        wrong_version.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2025-06-18"),
        );
        let rejected = http_mcp(
            State(state.clone()),
            wrong_version,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            })),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let listed = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            })),
        )
        .await;
        let bytes = axum::body::to_bytes(listed.into_body(), MAX_MESSAGE_BYTES)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&bytes).unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 9);
        assert!(!tools.iter().any(|tool| tool["name"] == "gdb_values"));
        let limited = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "http-test-2", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        for client in state.sessions.write().await.values_mut() {
            client.last_active = Instant::now() - Duration::from_secs(2);
        }
        let replaced = http_mcp(
            State(state.clone()),
            headers,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "http-test-3", "version": "1"}
                }
            })),
        )
        .await;
        assert_eq!(replaced.status(), StatusCode::OK);
        assert_eq!(state.sessions.read().await.len(), 1);
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn streamable_http_accepts_stateless_mcp_requests() {
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
        let state = HttpState {
            gateway: gateway.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            advanced_tools: false,
            auth_token: None,
            trusted_origins: Arc::from([]),
            max_sessions: 1,
            idle_timeout: Duration::from_secs(1),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(STATELESS_MCP_VERSION),
        );
        headers.insert("mcp-method", HeaderValue::from_static("server/discover"));
        let metadata = json!({
            "io.modelcontextprotocol/protocolVersion": STATELESS_MCP_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}
        });
        let discovered = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": metadata}
            })),
        )
        .await;
        assert_eq!(discovered.status(), StatusCode::OK);
        assert!(discovered.headers().get("mcp-session-id").is_none());
        assert_eq!(
            discovered.headers().get("mcp-protocol-version").unwrap(),
            STATELESS_MCP_VERSION
        );
        let body = axum::body::to_bytes(discovered.into_body(), MAX_MESSAGE_BYTES)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(response["result"]["ttlMs"], 86_400_000_u64);

        headers.insert("mcp-method", HeaderValue::from_static("tools/list"));
        let listed = http_mcp(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": metadata}
            })),
        )
        .await;
        assert_eq!(listed.status(), StatusCode::OK);
        let body = axum::body::to_bytes(listed.into_body(), MAX_MESSAGE_BYTES)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 9);

        headers.insert("mcp-method", HeaderValue::from_static("ping"));
        let mismatch = http_mcp(
            State(state),
            headers,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": {"_meta": metadata}
            })),
        )
        .await;
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(mismatch.into_body(), MAX_MESSAGE_BYTES)
            .await
            .unwrap();
        let response: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(response["error"]["code"], -32020);
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn http_completion_cleans_pending_after_disconnect_and_panic() {
        async fn panic_operation() -> Result<Value, RpcFault> {
            panic!("operation panic")
        }

        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let caller = Caller::local("http-cleanup-test");
        let deadline = Instant::now() + Duration::from_secs(1);
        let (cancel_waiter, _cancelled) = oneshot::channel();
        sessions.write().await.insert(
            "mcp_test".into(),
            HttpClient {
                phase: Phase::Ready,
                protocol_version: MCP_VERSION.into(),
                caller: caller.clone(),
                pending: HashMap::from([(
                    "1".into(),
                    detached_http_pending(1, cancel_waiter, deadline),
                )]),
                last_active: Instant::now(),
            },
        );

        let (release, released) = oneshot::channel();
        let operation = tokio::spawn(async move {
            released.await.unwrap();
            Ok(json!({"ok": true}))
        });
        let (response, disconnected) = oneshot::channel();
        drop(disconnected);
        let completion = tokio::spawn(complete_http_operation(
            HttpCompletion {
                reservation: Some(HttpReservation {
                    sessions: sessions.clone(),
                    session_id: "mcp_test".into(),
                    key: "1".into(),
                    generation: 1,
                }),
                response_id: json!(1),
                deadline,
                tracked: None,
                stateless_method: None,
                _permit: None,
                response,
            },
            operation,
        ));
        release.send(()).unwrap();
        completion.await.unwrap();
        assert!(sessions.read().await["mcp_test"].pending.is_empty());

        let (cancel_waiter, _cancelled) = oneshot::channel();
        sessions
            .write()
            .await
            .get_mut("mcp_test")
            .unwrap()
            .pending
            .insert(
                "2".into(),
                detached_http_pending(2, cancel_waiter, deadline),
            );
        let (response, received) = oneshot::channel();
        complete_http_operation(
            HttpCompletion {
                reservation: Some(HttpReservation {
                    sessions: sessions.clone(),
                    session_id: "mcp_test".into(),
                    key: "2".into(),
                    generation: 2,
                }),
                response_id: json!(2),
                deadline,
                tracked: None,
                stateless_method: None,
                _permit: None,
                response,
            },
            tokio::spawn(panic_operation()),
        )
        .await;
        assert_eq!(received.await.unwrap()["error"]["code"], -32603);
        assert!(sessions.read().await["mcp_test"].pending.is_empty());

        let deadline = Instant::now() - Duration::from_millis(1);
        let (cancel_waiter, _cancelled) = oneshot::channel();
        sessions
            .write()
            .await
            .get_mut("mcp_test")
            .unwrap()
            .pending
            .insert(
                "3".into(),
                detached_http_pending(3, cancel_waiter, deadline),
            );
        let operation = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(json!({"unreachable": true}))
        });
        let abort = operation.abort_handle();
        let (response, received) = oneshot::channel();
        complete_http_operation(
            HttpCompletion {
                reservation: Some(HttpReservation {
                    sessions: sessions.clone(),
                    session_id: "mcp_test".into(),
                    key: "3".into(),
                    generation: 3,
                }),
                response_id: json!(3),
                deadline,
                tracked: None,
                stateless_method: None,
                _permit: None,
                response,
            },
            operation,
        )
        .await;
        assert_eq!(received.await.unwrap()["error"]["code"], -32001);
        assert!(sessions.read().await["mcp_test"].pending.is_empty());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn http_deadlines_and_delete_release_pending_waiters() {
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
        let state = HttpState {
            gateway: gateway.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            advanced_tools: false,
            auth_token: None,
            trusted_origins: Arc::from([]),
            max_sessions: 1,
            idle_timeout: Duration::from_secs(60),
        };
        let (expired_waiter, expired) = oneshot::channel();
        state.sessions.write().await.insert(
            "mcp_test".into(),
            HttpClient {
                phase: Phase::Ready,
                protocol_version: MCP_VERSION.into(),
                caller: Caller::local("http-deadline-test"),
                pending: HashMap::from([(
                    "expired".into(),
                    detached_http_pending(
                        1,
                        expired_waiter,
                        Instant::now() - Duration::from_millis(1),
                    ),
                )]),
                last_active: Instant::now(),
            },
        );
        evict_http_sessions(&state).await;
        expired.await.unwrap();
        assert!(state.sessions.read().await["mcp_test"].pending.is_empty());

        let (delete_waiter, deleted) = oneshot::channel();
        state
            .sessions
            .write()
            .await
            .get_mut("mcp_test")
            .unwrap()
            .pending
            .insert(
                "delete".into(),
                detached_http_pending(2, delete_waiter, Instant::now() + Duration::from_secs(60)),
            );
        let mut headers = HeaderMap::new();
        headers.insert("mcp-session-id", HeaderValue::from_static("mcp_test"));
        let rejected = http_delete(State(state.clone()), headers.clone()).await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert!(state.sessions.read().await.contains_key("mcp_test"));
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(MCP_VERSION),
        );
        let response = http_delete(State(state.clone()), headers).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        deleted.await.unwrap();
        assert!(state.sessions.read().await.is_empty());
        gateway.shutdown().await;
    }

    #[test]
    fn http_origin_and_binding_policy_fail_closed() {
        assert!(validate_http_address("127.0.0.1:8080".parse().unwrap()).is_ok());
        assert!(validate_http_address("[::1]:8080".parse().unwrap()).is_ok());
        assert!(validate_http_address("0.0.0.0:8080".parse().unwrap()).is_err());
        assert!(parse_trusted_origins(&["https://agent.example/path".into()]).is_err());

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
        let state = HttpState {
            gateway: Arc::new(Gateway::new(config).unwrap()),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            advanced_tools: false,
            auth_token: None,
            trusted_origins: parse_trusted_origins(&["https://agent.example".into()]).unwrap(),
            max_sessions: 1,
            idle_timeout: Duration::from_secs(60),
        };
        assert!(allow_http_origin(&state, &HeaderMap::new()));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://agent.example"),
        );
        assert!(allow_http_origin(&state, &headers));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!allow_http_origin(&state, &headers));
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://agent.example"),
        );
        assert!(!allow_http_origin(&state, &headers));
    }

    #[tokio::test]
    async fn http_get_declines_sse_after_origin_validation() {
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
        let state = HttpState {
            gateway: Arc::new(Gateway::new(config).unwrap()),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stateless_pending: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            advanced_tools: false,
            auth_token: None,
            trusted_origins: parse_trusted_origins(&["https://agent.example".into()]).unwrap(),
            max_sessions: 1,
            idle_timeout: Duration::from_secs(60),
        };
        assert_eq!(
            http_get(State(state.clone()), HeaderMap::new())
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            http_get(State(state), headers).await.status(),
            StatusCode::FORBIDDEN
        );
    }
}

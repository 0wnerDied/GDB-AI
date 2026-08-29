use super::*;

pub(super) const MCP_VERSION: &str = "2025-11-25";
pub(super) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_HTTP_PENDING_DURATION: Duration = Duration::from_secs(5 * 60);

type RpcOutput = (Option<String>, Value);

#[derive(Clone, Copy)]
enum CancelMode {
    DetachWaiter,
    InterruptTarget,
    CloseSession,
}

#[derive(Clone)]
struct RequestCancellation {
    mode: CancelMode,
    session_id: Option<String>,
    lease_id: Option<String>,
}

struct StreamPending {
    waiter: JoinHandle<()>,
    cancellation: RequestCancellation,
}

struct HttpPending {
    cancel_waiter: Option<oneshot::Sender<()>>,
    cancellation: RequestCancellation,
    deadline: Instant,
}

pub(super) async fn serve_stdio(
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
                let cancellation = match request_cancellation(method, &params) {
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
                let gateway = gateway.clone();
                let caller = caller.clone();
                let responses = responses.clone();
                let sequence = sequence.clone();
                let method = method.to_owned();
                let task_key = key.clone();
                // Requests may wait for a target stop; separate tasks let
                // cancellation and inferior I/O reach the gateway meanwhile.
                // 2026-08-28: Cancelling the response task used to cancel the
                // Gateway future after a worker had accepted a mutation. Keep
                // dispatch detached so idempotency and audit still complete.
                let operation = tokio::spawn(async move {
                    dispatch_rpc(
                        &gateway,
                        &caller,
                        advanced_tools,
                        &sequence,
                        &method,
                        params,
                    )
                    .await
                });
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

pub(super) async fn serve_unix(
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

#[derive(Clone)]
struct HttpState {
    gateway: Arc<Gateway>,
    sessions: Arc<RwLock<HashMap<String, HttpClient>>>,
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

pub(super) async fn serve_http(
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
        sequence: Arc::new(AtomicU64::new(1)),
        raw_admin,
        advanced_tools,
        auth_token,
        trusted_origins,
        max_sessions,
        idle_timeout,
    };
    let router = Router::new()
        .route("/mcp", post(http_mcp).delete(http_delete))
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
    Json(message): Json<Value>,
) -> Response {
    if !allow_http_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(object) = message.as_object() else {
        return json_http_response(
            rpc_error(Value::Null, -32600, "request must be an object"),
            None,
        );
    };
    let id = object.get("id").cloned();
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return json_http_response(
            rpc_error(id.unwrap_or(Value::Null), -32600, "jsonrpc must be 2.0"),
            None,
        );
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return json_http_response(
            rpc_error(id.unwrap_or(Value::Null), -32600, "method is required"),
            None,
        );
    };
    let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
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
    let cancellation = match request_cancellation(method, &params) {
        Ok(cancellation) => cancellation,
        Err(error) => return json_http_response(rpc_fault(id, error), Some(session_id)),
    };
    let deadline = Instant::now() + MAX_HTTP_PENDING_DURATION;
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
    let gateway = state.gateway.clone();
    let sequence = state.sequence.clone();
    let advanced_tools = state.advanced_tools;
    let method = method.to_owned();
    let response_id = id.clone();
    let operation = tokio::spawn(async move {
        dispatch_rpc(
            &gateway,
            &caller,
            advanced_tools,
            &sequence,
            &method,
            params,
        )
        .await
    });
    let (response_sender, mut response_receiver) = oneshot::channel();
    tokio::spawn(complete_http_operation(
        state.sessions.clone(),
        session_id.to_owned(),
        key,
        response_id,
        deadline,
        operation,
        response_sender,
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

async fn complete_http_operation(
    sessions: Arc<RwLock<HashMap<String, HttpClient>>>,
    session_id: String,
    key: String,
    response_id: Value,
    deadline: Instant,
    operation: JoinHandle<Result<Value, RpcFault>>,
    response: oneshot::Sender<Value>,
) {
    let completed =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), operation).await;
    let value = match completed {
        Ok(Ok(result)) => result.map_or_else(
            |error| rpc_fault(response_id.clone(), error),
            |result| rpc_result(response_id.clone(), result),
        ),
        Ok(Err(error)) => rpc_error(response_id, -32603, error.to_string()),
        Err(_) => rpc_error(response_id, -32001, "HTTP request deadline exceeded"),
    };
    // 2026-08-29: A dropped HTTP handler used to skip pending cleanup while
    // its detached target operation completed. Completion now owns cleanup.
    if let Some(client) = sessions.write().await.get_mut(&session_id) {
        client.pending.remove(&key);
    }
    let _ = response.send(value);
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

fn json_http_response(value: Value, session_id: Option<&str>) -> Response {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"null".to_vec());
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_static(MCP_VERSION),
    );
    if let Some(session_id) = session_id
        && let Ok(value) = HeaderValue::from_str(session_id)
    {
        response.headers_mut().insert("mcp-session-id", value);
    }
    response
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
gdbai:// resources and close the session when finished.";

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

fn apply_cancel_mode(
    gateway: Arc<Gateway>,
    caller: Caller,
    sequence: Arc<AtomicU64>,
    cancellation: RequestCancellation,
) {
    // 2026-08-28: MCP cancellation only aborted the response waiter while
    // presenting no explicit way to interrupt or close the target operation.
    let Some(session_id) = cancellation.session_id else {
        return;
    };
    let Some(lease_id) = cancellation.lease_id else {
        return;
    };
    let (method, parameters) = match cancellation.mode {
        CancelMode::DetachWaiter => return,
        CancelMode::InterruptTarget => (
            CanonicalMethod::ExecutionControl,
            json!({
                "action": "interrupt",
                "lease_id": lease_id,
                "accept_latest_revision": true
            }),
        ),
        CancelMode::CloseSession => (
            CanonicalMethod::SessionClose,
            json!({"lease_id": lease_id, "accept_latest_revision": true}),
        ),
    };
    tokio::spawn(async move {
        let response = gateway
            .dispatch(
                ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: format!("cancel_{}", sequence.fetch_add(1, Ordering::Relaxed)),
                    session_id: Some(session_id),
                    method,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters,
                },
                &caller,
            )
            .await;
        if let Some(error) = response.error {
            tracing::warn!(code = ?error.code, message = %error.message, "request cancellation action failed");
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
    let session_id = parameters
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let lease_id = parameters
        .get("lease_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if !matches!(mode, CancelMode::DetachWaiter) && (session_id.is_none() || lease_id.is_none()) {
        return Err(RpcFault::invalid(
            "interrupt_target and close_session require session_id and lease_id",
        ));
    }
    Ok(RequestCancellation {
        mode,
        session_id,
        lease_id,
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
    params: Value,
) -> Result<Value, RpcFault> {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools(advanced_tools, caller.admin)})),
        "tools/call" => call_tool(gateway, caller, advanced_tools, sequence, params).await,
        "resources/list" => list_resources(gateway, caller, sequence).await,
        "resources/templates/list" => Ok(resource_templates()),
        "resources/read" => read_resource(gateway, caller, sequence, &params).await,
        "gdb.ai/call" => {
            let request: ApiRequest = serde_json::from_value(params)
                .map_err(|error| RpcFault::invalid(error.to_string()))?;
            Ok(
                serde_json::to_value(gateway.dispatch(request, caller).await)
                    .map_err(|error| RpcFault::invalid(error.to_string()))?,
            )
        }
        _ => Err(RpcFault {
            code: -32601,
            message: format!("method not found: {method}"),
            data: None,
        }),
    }
}

async fn call_tool(
    gateway: &Gateway,
    caller: &Caller,
    advanced_tools: bool,
    sequence: &AtomicU64,
    params: Value,
) -> Result<Value, RpcFault> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("tools/call requires name"))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let request = map_tool(
        name,
        arguments,
        advanced_tools,
        caller.admin,
        sequence.fetch_add(1, Ordering::Relaxed),
    )?;
    let response = gateway.dispatch(request, caller).await;
    Ok(tool_result(response))
}

fn map_tool(
    name: &str,
    arguments: Value,
    advanced_tools: bool,
    raw_admin: bool,
    sequence: u64,
) -> Result<ApiRequest, RpcFault> {
    let mut parameters = arguments
        .as_object()
        .cloned()
        .ok_or_else(|| RpcFault::invalid("tool arguments must be an object"))?;
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

fn tool_result(response: ApiResponse) -> Value {
    let is_error = response.error.is_some();
    let summary = match &response.error {
        Some(error) => format!("{}: {}", error.code.code_name(), error.message),
        None => match response.revision {
            Some(revision) => format!("request completed at revision {revision}"),
            None => "request completed".into(),
        },
    };
    let structured = serde_json::to_value(response).unwrap_or_else(
        |error| json!({"error": {"code": "INTERNAL", "message": error.to_string()}}),
    );
    json!({
        "content": [{"type": "text", "text": summary}],
        "structuredContent": structured,
        "isError": is_error
    })
}

async fn list_resources(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
) -> Result<Value, RpcFault> {
    let response = gateway
        .dispatch(
            canonical_request(sequence, None, CanonicalMethod::SessionList, json!({})),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let resources = response
        .result
        .and_then(|result| result.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|state| {
            let id = state.get("session_id")?.as_str()?;
            Some(json!({
                "uri": format!("gdbai://session/{id}/status"),
                "name": format!("Session {id} status"),
                "mimeType": "application/json"
            }))
        })
        .collect::<Vec<_>>();
    Ok(json!({"resources": resources}))
}

fn resource_templates() -> Value {
    json!({"resourceTemplates": [
        {
            "uriTemplate": "gdbai://session/{session_id}/status",
            "name": "Session status",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/capabilities",
            "name": "Session capabilities",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/events",
            "name": "Current event state",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/transcript",
            "name": "Paged MI transcript",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/event/{event_seq}",
            "name": "Journal evidence entry",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/snapshot/{snapshot_id}",
            "name": "Stop snapshot",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/output/pty",
            "name": "Paged session PTY output",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/breakpoints",
            "name": "Session breakpoints",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}",
            "name": "Content-addressed artifact manifest",
            "mimeType": "application/vnd.gdb-ai.artifact-manifest+json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}?offset={offset}&length={length}",
            "name": "Content-addressed artifact range",
            "mimeType": "application/octet-stream"
        }
    ]})
}

#[derive(Debug, PartialEq)]
enum ArtifactResource {
    Manifest {
        uri: String,
        digest: String,
    },
    Range {
        uri: String,
        artifact_uri: String,
        digest: String,
        offset: u64,
        length: u64,
    },
}

fn parse_artifact_resource(uri: &str) -> Result<ArtifactResource, RpcFault> {
    let (artifact_uri, query) = match uri.split_once('?') {
        Some(parts) => (parts.0, Some(parts.1)),
        None => (uri, None),
    };
    let digest = artifact_uri
        .strip_prefix("gdbai://artifact/sha256:")
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| RpcFault::invalid("invalid artifact resource URI"))?
        .to_owned();
    let Some(query) = query else {
        return Ok(ArtifactResource::Manifest {
            uri: artifact_uri.to_owned(),
            digest,
        });
    };
    let (offset, length) = query
        .strip_prefix("offset=")
        .and_then(|query| query.split_once("&length="))
        .ok_or_else(|| RpcFault::invalid("artifact range requires offset and length"))?;
    let offset = offset
        .parse::<u64>()
        .ok()
        .filter(|value| value.to_string() == offset)
        .ok_or_else(|| RpcFault::invalid("artifact range offset is invalid"))?;
    let length = length
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0 && value.to_string() == length)
        .ok_or_else(|| RpcFault::invalid("artifact range length is invalid"))?;
    Ok(ArtifactResource::Range {
        uri: uri.to_owned(),
        artifact_uri: artifact_uri.to_owned(),
        digest,
        offset,
        length,
    })
}

fn artifact_resource_contents(
    resource: ArtifactResource,
    result: Value,
) -> Result<Value, RpcFault> {
    let size = result
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcFault::invalid("artifact response contained no size"))?;
    let page_size = result
        .get("max_page_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcFault::invalid("artifact response contained no page limit"))?;
    match resource {
        ArtifactResource::Manifest { uri, digest } => {
            let manifest = json!({
                "uri": uri,
                "sha256": digest,
                "size": size,
                "mime_type": "application/octet-stream",
                "sensitivity": result.get("sensitivity").cloned().unwrap_or(Value::Null),
                "page_size": page_size,
                "range_uri_template": format!(
                    "gdbai://artifact/sha256:{digest}?offset={{offset}}&length={{length}}"
                )
            });
            let text = serde_json::to_string(&manifest)
                .map_err(|error| RpcFault::invalid(error.to_string()))?;
            Ok(json!({"contents": [{
                "uri": uri,
                "mimeType": "application/vnd.gdb-ai.artifact-manifest+json",
                "text": text
            }]}))
        }
        ArtifactResource::Range {
            uri,
            digest,
            offset,
            length,
            ..
        } => {
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= size)
                .ok_or_else(|| RpcFault::invalid("artifact range is outside the artifact"))?;
            if length > page_size {
                return Err(RpcFault::invalid("artifact range exceeds the page limit"));
            }
            let returned_offset = result.get("offset").and_then(Value::as_u64);
            let returned_end = result.get("next_offset").and_then(Value::as_u64);
            if returned_offset != Some(offset) || returned_end != Some(end) {
                return Err(RpcFault::invalid(
                    "artifact response did not contain the exact range",
                ));
            }
            let blob = result
                .get("data_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcFault::invalid("artifact response contained no data"))?;
            Ok(json!({"contents": [{
                "uri": uri,
                "mimeType": "application/octet-stream",
                "blob": blob,
                "_meta": {
                    "sha256": digest,
                    "artifactSize": size,
                    "offset": offset,
                    "length": length
                }
            }]}))
        }
    }
}

async fn read_resource(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
    params: &Value,
) -> Result<Value, RpcFault> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcFault::invalid("resources/read requires uri"))?;
    if uri.starts_with("gdbai://artifact/sha256:") {
        let resource = parse_artifact_resource(uri)?;
        let parameters = match &resource {
            ArtifactResource::Manifest { uri, .. } => json!({"uri": uri, "max_bytes": 1}),
            ArtifactResource::Range {
                artifact_uri,
                offset,
                length,
                ..
            } => json!({"uri": artifact_uri, "offset": offset, "max_bytes": length}),
        };
        let response = gateway
            .dispatch(
                canonical_request(sequence, None, CanonicalMethod::ArtifactGet, parameters),
                caller,
            )
            .await;
        if let Some(error) = response.error {
            return Err(core_fault(error.code.code_name(), error.message));
        }
        let result = response
            .result
            .ok_or_else(|| RpcFault::invalid("artifact response contained no result"))?;
        // 2026-08-29: resources/read previously discarded artifact paging
        // metadata and mislabeled the first page as the complete digest URI.
        // Return a manifest or an exact URI-bound range so evidence is whole.
        return artifact_resource_contents(resource, result);
    }
    let path = uri
        .strip_prefix("gdbai://session/")
        .ok_or_else(|| RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": uri})),
        })?;
    let parts = path.split('/').collect::<Vec<_>>();
    let session = parts
        .first()
        .copied()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| RpcFault {
            code: -32002,
            message: "resource not found".into(),
            data: Some(json!({"uri": uri})),
        })?;
    let (method, parameters) = match parts.as_slice() {
        [_, "status"] | [_, "events"] => (CanonicalMethod::SessionGet, json!({})),
        [_, "capabilities"] => (CanonicalMethod::SessionCapabilities, json!({})),
        [_, "transcript"] => (CanonicalMethod::SessionTranscript, json!({})),
        [_, "event", event_seq] => (
            CanonicalMethod::SessionEvent,
            json!({"event_seq": event_seq.parse::<u64>().map_err(|_| RpcFault::invalid("invalid event sequence"))?}),
        ),
        [_, "breakpoints"] => (CanonicalMethod::BreakpointList, json!({})),
        [_, "snapshot", snapshot_id] => (
            CanonicalMethod::InspectionSnapshotGet,
            json!({"snapshot_id": snapshot_id}),
        ),
        // 2026-08-29: The PTY ring is session-scoped. The old per-inferior
        // resource URI ignored its inferior ID and promised false isolation.
        [_, "output", "pty"] => (
            CanonicalMethod::InferiorIoRead,
            json!({"stream": "pty", "after_offset": 0, "max_bytes": 65536}),
        ),
        _ => {
            return Err(RpcFault {
                code: -32002,
                message: "resource not found".into(),
                data: Some(json!({"uri": uri})),
            });
        }
    };
    let response = gateway
        .dispatch(
            canonical_request(sequence, Some(session.into()), method, parameters),
            caller,
        )
        .await;
    if let Some(error) = response.error {
        return Err(core_fault(error.code.code_name(), error.message));
    }
    let text = serde_json::to_string(&response.result.unwrap_or(Value::Null))
        .map_err(|error| RpcFault::invalid(error.to_string()))?;
    Ok(json!({"contents": [{
        "uri": uri,
        "mimeType": "application/json",
        "text": text
    }]}))
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

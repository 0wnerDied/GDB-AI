use super::*;

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

pub(super) async fn serve_stream<R, W>(
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

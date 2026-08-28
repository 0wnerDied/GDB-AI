use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::{
    collections::HashMap,
    error::Error as StdError,
    io,
    net::SocketAddr,
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
use clap::{ArgGroup, Parser, Subcommand};
use gdb_ai_core::{
    config::Config,
    domain::SessionId,
    gateway::{Caller, Gateway},
    protocol::{API_VERSION, ApiRequest, ApiResponse, CanonicalMethod, canonical_request_schema},
};
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixListener},
    sync::{RwLock, mpsc},
    task::JoinHandle,
};

mod tool_catalog;

use tool_catalog::{discriminator_for_tool, method_for_tool, tool_exists, tool_names, tools};

const MCP_VERSION: &str = "2025-11-25";
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_REQUESTS: usize = 128;

type AnyError = Box<dyn StdError + Send + Sync>;
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

#[derive(Clone)]
struct HttpPending {
    waiter: Option<tokio::task::AbortHandle>,
    cancellation: RequestCancellation,
}

#[derive(Parser)]
#[command(name = "gdb-ai", version, about)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(group(
        ArgGroup::new("transport")
            .required(true)
            .args(["stdio", "unix", "http"])
    ))]
    Serve {
        #[arg(long)]
        stdio: bool,
        #[arg(long)]
        unix: Option<PathBuf>,
        #[arg(long)]
        http: Option<SocketAddr>,
        #[arg(long)]
        raw_admin: bool,
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
    },
    Doctor,
    Replay {
        journal: PathBuf,
        #[arg(long, default_value = "sess_replay")]
        session_id: String,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Transcript {
        #[command(subcommand)]
        command: TranscriptCommand,
    },
    Schema {
        #[command(subcommand)]
        command: SchemaCommand,
    },
    Capabilities,
}

#[derive(Subcommand)]
enum SchemaCommand {
    Export,
}

#[derive(Subcommand)]
enum SessionCommand {
    List,
    Inspect { session_id: String },
    Close { session_id: String },
}

#[derive(Subcommand)]
enum TranscriptCommand {
    Export { session_id: String },
    Inspect { journal: PathBuf },
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("gdb_ai=info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    if let Err(error) = run().await {
        eprintln!("gdb-ai: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AnyError> {
    let cli = Cli::parse();
    let config = Config::load(cli.config)?;
    match cli.command {
        Command::Serve {
            stdio: true,
            raw_admin,
            ..
        } => serve_stdio(config, raw_admin).await,
        Command::Serve {
            unix: Some(path),
            raw_admin,
            ..
        } => serve_unix(config, path, raw_admin).await,
        Command::Serve {
            http: Some(address),
            raw_admin,
            auth_token_file,
            ..
        } => serve_http(config, address, raw_admin, auth_token_file).await,
        Command::Serve { .. } => unreachable!("clap requires one transport"),
        Command::Doctor => doctor(config).await,
        Command::Replay {
            journal,
            session_id,
        } => {
            let report = gdb_ai_core::replay::replay(journal, SessionId::parse(session_id)?)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Command::Session { command } => session_cli(config, command).await,
        Command::Transcript { command } => transcript_cli(config, command),
        Command::Schema {
            command: SchemaCommand::Export,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "canonical": canonical_request_schema(),
                    "events": serde_json::from_str::<Value>(include_str!("../../../schemas/events.v1.json"))?,
                    "resources": serde_json::from_str::<Value>(include_str!("../../../schemas/resources.v1.json"))?,
                    "sha256": include_str!("../../../schemas/SHA256SUMS")
                }))?
            );
            Ok(())
        }
        Command::Capabilities => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "api_version": API_VERSION,
                    "mcp_protocol_version": MCP_VERSION,
                    "transports": ["stdio", "unix", "streamable_http", "json_rpc"],
                    "tools": tool_names(false),
                    "raw_admin_tool": "gdb_raw",
                    "schemas": [
                        "schemas/gdb.ai.v1.json",
                        "schemas/events.v1.json",
                        "schemas/resources.v1.json"
                    ],
                }))?
            );
            Ok(())
        }
    }
}

async fn session_cli(config: Config, command: SessionCommand) -> Result<(), AnyError> {
    let socket = config.server.unix_socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.unix_socket is required for session commands",
        )
    })?;
    let mut client = UnixClient::connect(socket).await?;
    let response = match command {
        SessionCommand::List => {
            client
                .call(ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "cli-list".into(),
                    session_id: None,
                    method: CanonicalMethod::SessionList,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                })
                .await?
        }
        SessionCommand::Inspect { session_id } => {
            client
                .call(ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "cli-inspect".into(),
                    session_id: Some(session_id),
                    method: CanonicalMethod::SessionGet,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                })
                .await?
        }
        SessionCommand::Close { session_id } => {
            let inspected = client
                .call(ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "cli-close-inspect".into(),
                    session_id: Some(session_id.clone()),
                    method: CanonicalMethod::SessionGet,
                    expected_revision: None,
                    idempotency_key: None,
                    parameters: json!({}),
                })
                .await?;
            require_api_success(&inspected)?;
            let acquired = client
                .call(ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "cli-close-lease".into(),
                    session_id: Some(session_id.clone()),
                    method: CanonicalMethod::SessionAcquireWriteLease,
                    expected_revision: inspected.revision,
                    idempotency_key: None,
                    parameters: json!({"force": true}),
                })
                .await?;
            require_api_success(&acquired)?;
            let lease_id = acquired
                .result
                .as_ref()
                .and_then(|value| value.get("lease_id"))
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other("lease response has no lease_id"))?;
            client
                .call(ApiRequest {
                    api_version: API_VERSION.into(),
                    request_id: "cli-close".into(),
                    session_id: Some(session_id),
                    method: CanonicalMethod::SessionClose,
                    expected_revision: acquired.revision,
                    idempotency_key: None,
                    parameters: json!({"lease_id": lease_id}),
                })
                .await?
        }
    };
    require_api_success(&response)?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn transcript_cli(config: Config, command: TranscriptCommand) -> Result<(), AnyError> {
    match command {
        TranscriptCommand::Export { session_id } => {
            let session_id = SessionId::parse(session_id)?;
            let path = config
                .persistence
                .sessions
                .join(session_id.0)
                .join("journal.jsonl");
            let mut file = std::fs::File::open(path)?;
            let mut output = std::io::stdout().lock();
            std::io::copy(&mut file, &mut output)?;
        }
        TranscriptCommand::Inspect { journal } => {
            use std::io::BufRead as _;
            let file = std::fs::File::open(journal)?;
            let mut kinds = std::collections::BTreeMap::<String, u64>::new();
            let mut entries = 0u64;
            let mut last_seq = 0u64;
            for line in std::io::BufReader::new(file).lines() {
                let entry: gdb_ai_core::journal::JournalEntry = serde_json::from_str(&line?)?;
                gdb_ai_core::journal::require_next_sequence(last_seq, entry.seq)?;
                last_seq = entry.seq;
                entries += 1;
                *kinds.entry(entry.kind).or_default() += 1;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "entries": entries,
                    "last_seq": last_seq,
                    "kinds": kinds
                }))?
            );
        }
    }
    Ok(())
}

struct UnixClient {
    input: BufReader<tokio::net::unix::OwnedReadHalf>,
    output: tokio::net::unix::OwnedWriteHalf,
    next_id: u64,
}

impl UnixClient {
    async fn connect(path: PathBuf) -> Result<Self, AnyError> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        let (input, output) = stream.into_split();
        let mut client = Self {
            input: BufReader::new(input),
            output,
            next_id: 1,
        };
        let initialize_id = Value::from(client.next_id);
        client.next_id += 1;
        write_rpc(
            &mut client.output,
            json!({
                "jsonrpc": "2.0",
                "id": initialize_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_VERSION,
                    "clientInfo": {"name": "gdb-ai-cli", "version": env!("CARGO_PKG_VERSION")}
                }
            }),
        )
        .await?;
        let response = read_json_line(&mut client.input).await?;
        if response.get("error").is_some() {
            return Err(io::Error::other(response.to_string()).into());
        }
        write_rpc(
            &mut client.output,
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }),
        )
        .await?;
        Ok(client)
    }

    async fn call(&mut self, request: ApiRequest) -> Result<ApiResponse, AnyError> {
        let id = Value::from(self.next_id);
        self.next_id += 1;
        write_rpc(
            &mut self.output,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "gdb.ai/call",
                "params": request
            }),
        )
        .await?;
        let response = read_json_line(&mut self.input).await?;
        if let Some(error) = response.get("error") {
            return Err(io::Error::other(error.to_string()).into());
        }
        Ok(serde_json::from_value(
            response.get("result").cloned().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "JSON-RPC response has no result",
                )
            })?,
        )?)
    }
}

async fn read_json_line<R>(input: &mut R) -> Result<Value, AnyError>
where
    R: AsyncBufRead + Unpin,
{
    let line = read_line_bounded(input, MAX_MESSAGE_BYTES)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed connection"))?;
    Ok(serde_json::from_slice(&line)?)
}

fn require_api_success(response: &ApiResponse) -> Result<(), AnyError> {
    if let Some(error) = &response.error {
        Err(io::Error::other(format!("{:?}: {}", error.code, error.message)).into())
    } else {
        Ok(())
    }
}

async fn doctor(config: Config) -> Result<(), AnyError> {
    let checks = json!({
        "gdb": {
            "path": config.gdb.path,
            "available": std::process::Command::new(&config.gdb.path)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success())
        },
        "gdbserver": {"available": program_available("gdbserver")},
        "bubblewrap": {"available": std::path::Path::new("/usr/bin/bwrap").is_file()},
        "host_architecture": std::env::consts::ARCH,
        "ptrace_scope": std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .map(|value| value.trim().to_owned()),
        "workspace_roots": config.security.workspace_roots.iter().map(|root| json!({
            "path": root,
            "accessible": std::fs::canonicalize(root).is_ok()
        })).collect::<Vec<_>>(),
        "remote_allowlist_entries": config.security.remote_allowlist.len(),
        "attach_allowlist_entries": config.security.attach_allowlist.len(),
        "python_extension_configured": config.gdb.python_extension.is_some(),
    });
    let gateway = Gateway::new(config)?;
    let caller = Caller::local("doctor");
    let created = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "doctor-create".into(),
                session_id: None,
                method: CanonicalMethod::SessionCreate,
                expected_revision: None,
                idempotency_key: None,
                parameters: json!({}),
            },
            &caller,
        )
        .await;
    if let Some(error) = &created.error {
        return Err(
            io::Error::other(format!("{}: {}", error.code.code_name(), error.message)).into(),
        );
    }
    let session_id = created
        .session_id
        .clone()
        .ok_or_else(|| io::Error::other("session.create returned no session_id"))?;
    let lease_id = created
        .result
        .as_ref()
        .and_then(|result| result.get("write_lease"))
        .and_then(|lease| lease.get("lease_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("session.create returned no write lease"))?
        .to_owned();
    let report = json!({
        "status": "ok",
        "session_id": session_id,
        "revision": created.revision,
        "backend": created.result.as_ref().and_then(|value| value.get("backend")),
        "capabilities": created.result.as_ref().and_then(|value| value.get("capabilities")),
        "checks": checks,
    });
    let _ = gateway
        .dispatch(
            ApiRequest {
                api_version: API_VERSION.into(),
                request_id: "doctor-close".into(),
                session_id: Some(session_id),
                method: CanonicalMethod::SessionClose,
                expected_revision: created.revision,
                idempotency_key: None,
                parameters: json!({"lease_id": lease_id}),
            },
            &caller,
        )
        .await;
    gateway.shutdown().await;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn program_available(program: &str) -> bool {
    std::process::Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

async fn serve_stdio(config: Config, raw_admin: bool) -> Result<(), AnyError> {
    let gateway = Arc::new(Gateway::new(config)?);
    let result = serve_stream(
        gateway.clone(),
        Caller {
            identity: "mcp-stdio".into(),
            admin: raw_admin,
        },
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
                    dispatch_rpc(&gateway, &caller, &sequence, &method, params).await
                });
                let handle = tokio::spawn(async move {
                    let response = match operation.await {
                        Ok(result) => result.map_or_else(
                            |error| rpc_fault(id.clone(), error),
                            |result| rpc_result(id.clone(), result),
                        ),
                        Err(error) => rpc_error(id, -32603, error.to_string()),
                    };
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

async fn serve_unix(config: Config, path: PathBuf, raw_admin: bool) -> Result<(), AnyError> {
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
    auth_token: Option<Arc<str>>,
    max_sessions: usize,
    idle_timeout: Duration,
}

#[derive(Clone)]
struct HttpClient {
    phase: Phase,
    caller: Caller,
    pending: HashMap<String, HttpPending>,
    last_active: Instant,
}

async fn serve_http(
    config: Config,
    address: SocketAddr,
    raw_admin: bool,
    auth_token_file: Option<PathBuf>,
) -> Result<(), AnyError> {
    if !address.ip().is_loopback() && auth_token_file.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "non-loopback HTTP requires --auth-token-file",
        )
        .into());
    }
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
        auth_token,
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
    let client = {
        let mut sessions = state.sessions.write().await;
        evict_expired_http_clients(&mut sessions, Instant::now(), state.idle_timeout);
        let Some(client) = sessions.get_mut(session_id) else {
            return (StatusCode::NOT_FOUND, "MCP session not found").into_response();
        };
        client.last_active = Instant::now();
        client.clone()
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
    if method != "ping" && client.phase != Phase::Ready {
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
    let reserved = {
        let mut sessions = state.sessions.write().await;
        sessions.get_mut(session_id).is_some_and(|client| {
            if client.pending.contains_key(&key) || client.pending.len() >= MAX_PENDING_REQUESTS {
                false
            } else {
                client.pending.insert(
                    key.clone(),
                    HttpPending {
                        waiter: None,
                        cancellation,
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
    let caller = client.caller;
    let method = method.to_owned();
    let response_id = id.clone();
    let operation =
        tokio::spawn(
            async move { dispatch_rpc(&gateway, &caller, &sequence, &method, params).await },
        );
    let task = tokio::spawn(async move {
        match operation.await {
            Ok(result) => result.map_or_else(
                |error| rpc_fault(response_id.clone(), error),
                |result| rpc_result(response_id.clone(), result),
            ),
            Err(error) => rpc_error(response_id, -32603, error.to_string()),
        }
    });
    let registered = {
        let mut sessions = state.sessions.write().await;
        sessions
            .get_mut(session_id)
            .and_then(|client| client.pending.get_mut(&key))
            .is_some_and(|pending| {
                pending.waiter = Some(task.abort_handle());
                true
            })
    };
    if !registered {
        task.abort();
        return json_http_response(
            rpc_error(
                id,
                -32600,
                "duplicate request id or too many pending requests",
            ),
            Some(session_id),
        );
    }
    let response = match task.await {
        Ok(response) => response,
        Err(error) if error.is_cancelled() => rpc_error(id, -32800, "request waiter cancelled"),
        Err(error) => rpc_error(id, -32603, error.to_string()),
    };
    if let Some(client) = state.sessions.write().await.get_mut(session_id) {
        client.pending.remove(&key);
    }
    json_http_response(response, Some(session_id))
}

async fn evict_http_sessions(state: &HttpState) {
    let mut sessions = state.sessions.write().await;
    evict_expired_http_clients(&mut sessions, Instant::now(), state.idle_timeout);
}

fn evict_expired_http_clients(
    sessions: &mut HashMap<String, HttpClient>,
    now: Instant,
    idle_timeout: Duration,
) {
    // 2026-08-28: HTTP MCP sessions previously had no cap or idle eviction,
    // so reconnecting clients could retain transport state without bound.
    sessions.retain(|_, client| {
        let active =
            !client.pending.is_empty() || now.duration_since(client.last_active) < idle_timeout;
        if !active {
            for pending in client.pending.values() {
                if let Some(waiter) = &pending.waiter {
                    waiter.abort();
                }
            }
        }
        active
    });
}

async fn http_delete(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(session_id) = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
    else {
        return (StatusCode::BAD_REQUEST, "Mcp-Session-Id is required").into_response();
    };
    let Some(client) = state.sessions.write().await.remove(session_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    for pending in client.pending.into_values() {
        if let Some(waiter) = pending.waiter {
            waiter.abort();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn http_metrics(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if !authorize_http(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut response = Response::new(Body::from(state.gateway.metrics()));
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
module-offset breakpoints only after inspection mappings shows the executable; \
an earlier explicit-loader breakpoint stays pending. Read large evidence through \
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
    if let Some(waiter) = pending.waiter {
        waiter.abort();
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

async fn dispatch_rpc(
    gateway: &Gateway,
    caller: &Caller,
    sequence: &AtomicU64,
    method: &str,
    params: Value,
) -> Result<Value, RpcFault> {
    match method {
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools(caller.admin)})),
        "tools/call" => call_tool(gateway, caller, sequence, params).await,
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
    let request = map_tool(name, arguments, sequence.fetch_add(1, Ordering::Relaxed))?;
    let response = gateway.dispatch(request, caller).await;
    Ok(tool_result(response))
}

fn map_tool(name: &str, arguments: Value, sequence: u64) -> Result<ApiRequest, RpcFault> {
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
    let method = method_for_tool(name, action.as_deref()).ok_or_else(|| {
        if tool_exists(name) {
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
            "uriTemplate": "gdbai://session/{session_id}/inferior/{inferior_id}/output",
            "name": "Paged inferior output",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://session/{session_id}/breakpoints",
            "name": "Session breakpoints",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "gdbai://artifact/sha256:{digest}",
            "name": "Content-addressed artifact",
            "mimeType": "application/octet-stream"
        }
    ]})
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
        let response = gateway
            .dispatch(
                canonical_request(
                    sequence,
                    None,
                    CanonicalMethod::ArtifactGet,
                    json!({"uri": uri}),
                ),
                caller,
            )
            .await;
        if let Some(error) = response.error {
            return Err(core_fault(error.code.code_name(), error.message));
        }
        let blob = response
            .result
            .and_then(|result| result.get("data_base64").cloned())
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| RpcFault::invalid("artifact response contained no data"))?;
        return Ok(json!({"contents": [{
            "uri": uri,
            "mimeType": "application/octet-stream",
            "blob": blob
        }]}));
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
        [_, "inferior", _, "output"] => (
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

async fn read_line_bounded<R: AsyncBufRead + Unpin>(
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

async fn write_rpc<W: AsyncWriteExt + Unpin>(writer: &mut W, response: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

trait ErrorCodeName {
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
mod tests {
    use super::*;
    use gdb_ai_core::config::{ArtifactConfig, PersistenceConfig};
    use tempfile::tempdir;

    #[test]
    fn initialize_teaches_agents_the_stateful_workflow() {
        let mut phase = Phase::New;
        let mut caller = Caller::local("test");
        let result = initialize(
            &json!({
                "protocolVersion": MCP_VERSION,
                "clientInfo": {"name": "test-agent"}
            }),
            &mut phase,
            &mut caller,
        )
        .unwrap();
        let instructions = result["instructions"].as_str().unwrap();
        for required in [
            "tools/list",
            "argv",
            "lab_mutation",
            "accept_latest_revision",
            "stream=pty",
            "stop_id",
            "inspection mappings",
        ] {
            assert!(instructions.contains(required), "missing {required}");
        }
    }

    #[test]
    fn maps_tool_metadata_outside_canonical_parameters() {
        let request = map_tool(
            "gdb_run",
            json!({
                "action": "continue",
                "session_id": "sess_test",
                "expected_revision": 7,
                "cancel_mode": "interrupt_target",
                "stop_id": "stop_test",
                "wait": {"until": "snapshot", "timeout_ms": 1000}
            }),
            3,
        )
        .unwrap();
        assert_eq!(request.method, "execution.control");
        assert_eq!(request.session_id.as_deref(), Some("sess_test"));
        assert_eq!(request.expected_revision, Some(7));
        assert_eq!(request.parameters["action"], "continue");
        assert!(request.parameters.get("session_id").is_none());
        assert!(request.parameters.get("cancel_mode").is_none());
        let cancellation = request_cancellation(
            "tools/call",
            &json!({
                "arguments": {
                    "session_id": "sess_test",
                    "lease_id": "lease_test",
                    "cancel_mode": "interrupt_target"
                }
            }),
        )
        .unwrap();
        assert!(matches!(cancellation.mode, CancelMode::InterruptTarget));
        assert_eq!(cancellation.session_id.as_deref(), Some("sess_test"));
        assert!(!tool_names(false).contains(&"gdb_raw"));
        assert!(tool_names(true).contains(&"gdb_raw"));
        assert!(!valid_request_id(&Value::String("x".repeat(129))));
    }

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
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
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
            sequence: Arc::new(AtomicU64::new(1)),
            raw_admin: false,
            auth_token: Some(Arc::from("test-token")),
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
        let session = initialized.headers().get("mcp-session-id").unwrap().clone();
        headers.insert("mcp-session-id", session);
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
        assert!(
            response["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == "gdb_values")
        );
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
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        )
        .await
        .unwrap();
        let tools = read_json_line(&mut client_input).await.unwrap();
        assert!(tools["result"]["tools"].as_array().is_some());
        client_output.shutdown().await.unwrap();
        drop(client_output);
        serving.await.unwrap().unwrap();
        gateway.shutdown().await;
    }
}

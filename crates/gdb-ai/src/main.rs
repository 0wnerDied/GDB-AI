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
    sync::{RwLock, mpsc, oneshot},
    task::JoinHandle,
};

mod server;
mod storage_cli;
mod tool_catalog;

use server::{
    ErrorCodeName, MAX_MESSAGE_BYTES, MCP_VERSION, read_line_bounded, serve_http, serve_stdio,
    serve_unix, write_rpc,
};
use tool_catalog::{discriminator_for_tool, method_for_tool, tool_exists, tool_names, tools};

type AnyError = Box<dyn StdError + Send + Sync>;

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
        advanced_tools: bool,
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        #[arg(long, requires = "http")]
        trusted_origin: Vec<String>,
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
    Storage {
        #[command(subcommand)]
        command: storage_cli::StorageCommand,
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
            advanced_tools,
            ..
        } => serve_stdio(config, raw_admin, advanced_tools).await,
        Command::Serve {
            unix: Some(path),
            raw_admin,
            advanced_tools,
            ..
        } => serve_unix(config, path, raw_admin, advanced_tools).await,
        Command::Serve {
            http: Some(address),
            raw_admin,
            advanced_tools,
            auth_token_file,
            trusted_origin,
            ..
        } => {
            serve_http(
                config,
                address,
                raw_admin,
                advanced_tools,
                auth_token_file,
                trusted_origin,
            )
            .await
        }
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
        Command::Storage { command } => storage_cli::run(config, command).map_err(Into::into),
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
                    "tools": tool_names(false, false),
                    "raw_admin_tool": "gdb_raw",
                    "advanced_tools_flag": "--advanced-tools",
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

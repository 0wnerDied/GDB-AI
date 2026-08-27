use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use gdb_ai_mi::{MiLimits, MiRecord, MiResult, MiValue};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::{
    Error, ErrorCode, Result,
    backend::{BackendDescriptor, BackendInput, GdbBackend, MiCommand, session_directory},
    config::Config,
    domain::{
        DomainEvent, InferiorStatus, JournaledEvent, OutputSource, SessionId, SessionState,
        SnapshotStatus,
    },
    journal::Journal,
    normalize::normalize,
    persistence::Store,
    policy::Profile,
    reducer::StateReducer,
    ring::{ByteRing, RingRead},
};

#[derive(Clone, Debug, Serialize)]
pub struct SessionCapabilities {
    pub backend: BackendDescriptor,
    pub features: BTreeSet<String>,
    pub commands: BTreeSet<String>,
    pub capabilities: BTreeMap<String, Capability>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Supported,
    Unsupported,
    Conditional,
    Limited,
    Unknown,
    TemporarilyUnavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct Capability {
    pub status: CapabilityStatus,
    pub scope: &'static str,
    pub constraints: Vec<String>,
    pub source: &'static str,
    pub last_checked_revision: u64,
}

impl SessionCapabilities {
    pub fn status(&self, name: &str) -> Option<CapabilityStatus> {
        self.capabilities
            .get(name)
            .map(|capability| capability.status)
    }

    pub fn supports(&self, name: &str) -> bool {
        matches!(
            self.status(name),
            Some(CapabilityStatus::Supported | CapabilityStatus::Conditional)
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CommandReply {
    pub token: u64,
    pub class: String,
    pub record: MiRecord,
    pub stream_records: Vec<MiRecord>,
    pub stream_truncated: bool,
    pub evidence_seq: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublishedEvent {
    pub event_seq: u64,
    pub revision: u64,
    pub event: DomainEvent,
}

#[derive(Clone, Copy, Debug)]
pub enum WaitUntil {
    Running,
    Stopped,
    Snapshot,
    Exited,
}

#[derive(Clone, Copy, Debug)]
pub enum OutputRing {
    Inferior,
    Console,
    Log,
}

#[derive(Clone)]
pub struct SessionHandle {
    id: SessionId,
    profile: Profile,
    capabilities: Arc<SessionCapabilities>,
    requests: mpsc::Sender<WorkerRequest>,
    state: watch::Receiver<SessionState>,
    events: broadcast::Sender<PublishedEvent>,
    command_timeout: Duration,
    journal_path: PathBuf,
}

impl SessionHandle {
    pub async fn start(config: Arc<Config>, profile: Profile, store: Arc<Store>) -> Result<Self> {
        let id = SessionId::new();
        let session_dir = session_directory(&config.persistence.sessions, &id.0);
        std::fs::create_dir_all(&session_dir)?;
        let journal_path = session_dir.join("journal.jsonl");
        let journal = Journal::create(&journal_path)?;
        let initial_state = SessionState::creating(id.clone());
        let (state_sender, state) = watch::channel(initial_state.clone());
        let (events, _) = broadcast::channel(512);
        let (requests, receiver) = mpsc::channel(128);

        let worker = SessionWorker::bootstrap(
            config.clone(),
            profile,
            store,
            session_dir,
            journal,
            initial_state,
            state_sender,
            events.clone(),
            receiver,
        )
        .await?;
        let capabilities = Arc::new(worker.capabilities.clone());
        tokio::spawn(worker.run());

        Ok(Self {
            id,
            profile,
            capabilities,
            requests,
            state,
            events,
            command_timeout: config.server.command_timeout(),
            journal_path,
        })
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn capabilities(&self) -> &SessionCapabilities {
        &self.capabilities
    }

    pub fn state(&self) -> SessionState {
        self.state.borrow().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PublishedEvent> {
        self.events.subscribe()
    }

    pub fn journal_path(&self) -> &PathBuf {
        &self.journal_path
    }

    pub async fn command(&self, command: MiCommand) -> Result<CommandReply> {
        self.command_with_timeout(command, self.command_timeout)
            .await
    }

    pub async fn command_with_timeout(
        &self,
        command: MiCommand,
        timeout: Duration,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Command {
                command,
                timeout: timeout.max(Duration::from_millis(1)),
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn transaction(
        &self,
        before: Vec<MiCommand>,
        command: MiCommand,
        after: Vec<MiCommand>,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Transaction {
                before,
                command,
                after,
                timeout: self.command_timeout,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn record_event(&self, event: DomainEvent) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RecordEvent {
                event,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn wait(&self, until: WaitUntil, timeout: Duration) -> Result<SessionState> {
        self.wait_from(until, timeout, None).await
    }

    pub async fn wait_after(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: &SessionState,
    ) -> Result<SessionState> {
        self.wait_from(until, timeout, Some(baseline)).await
    }

    async fn wait_from(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: Option<&SessionState>,
    ) -> Result<SessionState> {
        let mut state = self.state.clone();
        let baseline = baseline.cloned();
        let wait = async {
            loop {
                let current = state.borrow().clone();
                if wait_satisfied(&current, until, baseline.as_ref()) {
                    return Ok(current);
                }
                state.changed().await.map_err(|_| {
                    Error::new(ErrorCode::GdbExited, "session state channel closed")
                })?;
            }
        };
        tokio::time::timeout(timeout.max(Duration::from_millis(1)), wait)
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout, "state wait timed out").retryable())?
    }

    pub async fn read_output(
        &self,
        ring: OutputRing,
        after_offset: u64,
        max_bytes: usize,
    ) -> Result<RingRead> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::ReadOutput {
                ring,
                after_offset,
                max_bytes: max_bytes.min(64 * 1024),
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))
    }

    pub async fn write_inferior(&self, bytes: Vec<u8>) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::WriteInferior {
                bytes,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn resize_inferior(&self, rows: u16, columns: u16) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::ResizeInferior {
                rows,
                columns,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn close(&self) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Close { response: sender })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }
}

// 2026-08-28: Compare waits with pre-command state; otherwise an existing
// stop or snapshot can satisfy a new resume request before a new async event.
fn wait_satisfied(state: &SessionState, until: WaitUntil, baseline: Option<&SessionState>) -> bool {
    let after_baseline = baseline.is_none_or(|baseline| state.event_seq > baseline.event_seq);
    match until {
        WaitUntil::Running => baseline.map_or_else(
            || {
                state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Running)
            },
            |baseline| state.execution_epoch > baseline.execution_epoch,
        ),
        WaitUntil::Stopped => {
            after_baseline
                && state.stop_id.is_some()
                && baseline.is_none_or(|baseline| state.stop_id != baseline.stop_id)
                && state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Stopped)
        }
        WaitUntil::Snapshot => state.snapshot.as_ref().is_some_and(|snapshot| {
            after_baseline
                && snapshot.status == SnapshotStatus::Ready
                && baseline
                    .is_none_or(|baseline| Some(&snapshot.stop_id) != baseline.stop_id.as_ref())
        }),
        WaitUntil::Exited => state.inferiors.values().any(|inferior| {
            matches!(
                inferior.status,
                InferiorStatus::Exited | InferiorStatus::Detached | InferiorStatus::Disconnected
            )
        }),
    }
}

enum WorkerRequest {
    Command {
        command: MiCommand,
        timeout: Duration,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    Transaction {
        before: Vec<MiCommand>,
        command: MiCommand,
        after: Vec<MiCommand>,
        timeout: Duration,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    RecordEvent {
        event: DomainEvent,
        response: oneshot::Sender<Result<()>>,
    },
    ReadOutput {
        ring: OutputRing,
        after_offset: u64,
        max_bytes: usize,
        response: oneshot::Sender<RingRead>,
    },
    WriteInferior {
        bytes: Vec<u8>,
        response: oneshot::Sender<Result<()>>,
    },
    ResizeInferior {
        rows: u16,
        columns: u16,
        response: oneshot::Sender<Result<()>>,
    },
    Close {
        response: oneshot::Sender<Result<()>>,
    },
}

// Owns both GDB input and reducer state. Callers cross the request channel so
// only one MI command can be in flight and no other task can mutate state.
struct SessionWorker {
    backend: GdbBackend,
    journal: Journal,
    reducer: StateReducer,
    store: Arc<Store>,
    profile: Profile,
    capabilities: SessionCapabilities,
    state_sender: watch::Sender<SessionState>,
    events: broadcast::Sender<PublishedEvent>,
    requests: mpsc::Receiver<WorkerRequest>,
    inferior_output: ByteRing,
    console_output: ByteRing,
    log_output: ByteRing,
    next_token: u64,
    timed_out_tokens: HashSet<u64>,
    stream_limit: usize,
}

#[allow(clippy::too_many_arguments)]
impl SessionWorker {
    async fn bootstrap(
        config: Arc<Config>,
        profile: Profile,
        store: Arc<Store>,
        session_dir: PathBuf,
        journal: Journal,
        initial_state: SessionState,
        state_sender: watch::Sender<SessionState>,
        events: broadcast::Sender<PublishedEvent>,
        requests: mpsc::Receiver<WorkerRequest>,
    ) -> Result<Self> {
        let limits = MiLimits {
            max_record_bytes: config.limits.mi_record_bytes,
            max_depth: config.limits.mi_depth,
            max_decoded_string_bytes: config.limits.mi_record_bytes,
        };
        let mut last_error = None;
        let mut selected = None;
        let mut journal = journal;
        let mut reducer = StateReducer::new(initial_state);
        let mut inferior_output = ByteRing::new(config.limits.inferior_output_ring_bytes);
        let mut console_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut log_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut versions = vec![config.gdb.preferred_mi.clone()];
        if config.gdb.fallback_mi != config.gdb.preferred_mi {
            versions.push(config.gdb.fallback_mi.clone());
        }

        for version in versions {
            let mut backend =
                GdbBackend::spawn(&config.gdb, &version, &session_dir, limits).await?;
            match wait_for_prompt(
                &mut backend,
                &mut journal,
                &mut reducer,
                &mut inferior_output,
                &mut console_output,
                &mut log_output,
            )
            .await
            {
                Ok(()) => {
                    selected = Some(backend);
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    let _ = backend.shutdown().await;
                }
            }
        }
        let backend = selected.ok_or_else(|| {
            last_error.unwrap_or_else(|| Error::new(ErrorCode::GdbExited, "GDB startup failed"))
        })?;
        let mut worker = Self {
            capabilities: SessionCapabilities {
                backend: backend.descriptor().clone(),
                features: BTreeSet::new(),
                commands: BTreeSet::new(),
                capabilities: BTreeMap::from([
                    ("async_execution".into(), capability(CapabilityStatus::Unknown, "backend", vec![], "handshake", 0)),
                    ("non_stop".into(), capability(CapabilityStatus::Unsupported, "session", vec!["version 1 is all-stop".into()], "configuration", 0)),
                    ("inferior_tty".into(), capability(CapabilityStatus::Supported, "session", vec![], "pty", 0)),
                    ("memory_read".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["target must be stopped; volatile ranges may have target-defined effects".into()], "probe", 0)),
                    ("memory_write".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["requires lab_mutation policy and stopped target".into()], "probe", 0)),
                    ("watchpoints".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["hardware resources are target-dependent".into()], "probe", 0)),
                    ("thread_scoped_commands".into(), capability(CapabilityStatus::Supported, "backend", vec![], "mi", 0)),
                    ("sandbox.namespaces".into(), capability(CapabilityStatus::Unsupported, "deployment", vec!["requires a deployment supervisor".into()], "runtime", 0)),
                    ("sandbox.seccomp".into(), capability(CapabilityStatus::Unsupported, "deployment", vec!["requires a deployment supervisor".into()], "runtime", 0)),
                ]),
                limitations: vec![
                    "namespace, cgroup, and seccomp isolation require a deployment supervisor"
                        .into(),
                ],
            },
            backend,
            journal,
            reducer,
            store,
            profile,
            state_sender,
            events,
            requests,
            inferior_output,
            console_output,
            log_output,
            next_token: 1,
            timed_out_tokens: HashSet::new(),
            stream_limit: config.limits.tool_response_bytes,
        };
        worker.apply_event(DomainEvent::BackendStarted)?;
        worker.handshake().await?;
        worker.persist()?;
        Ok(worker)
    }

    async fn handshake(&mut self) -> Result<()> {
        for command in [
            MiCommand::new("-gdb-set")?.bare("mi-async")?.bare("on")?,
            MiCommand::new("-gdb-set")?.bare("non-stop")?.bare("off")?,
            MiCommand::new("-gdb-set")?
                .bare("pagination")?
                .bare("off")?,
            MiCommand::new("-gdb-set")?
                .bare("style")?
                .bare("enabled")?
                .bare("off")?,
            MiCommand::new("-gdb-set")?
                .bare("print")?
                .bare("elements")?
                .bare("200")?,
            MiCommand::new("-gdb-set")?
                .bare("may-call-functions")?
                .bare("off")?,
        ] {
            self.execute(command, Duration::from_secs(5)).await?;
        }
        let features = self
            .execute(MiCommand::new("-list-features")?, Duration::from_secs(5))
            .await?;
        self.capabilities.features = extract_string_list(&features.record, "features");
        // The successful -gdb-set above is the capability probe. Modern GDB
        // does not include async execution in -list-features.
        self.set_capability("async_execution", CapabilityStatus::Supported);
        self.set_capability("thread_scoped_commands", CapabilityStatus::Supported);

        for command in [
            "-data-read-memory-bytes",
            "-data-write-memory-bytes",
            "-data-disassemble",
            "-break-watch",
            "-thread-info",
        ] {
            let probe = MiCommand::new("-info-gdb-mi-command")?.string(command);
            let reply = self.execute(probe, Duration::from_secs(5)).await?;
            if mi_command_exists(&reply.record) {
                self.capabilities.commands.insert(command.into());
            }
        }
        self.set_capability(
            "memory_read",
            command_status(&self.capabilities.commands, "-data-read-memory-bytes"),
        );
        self.set_capability(
            "memory_write",
            command_status(&self.capabilities.commands, "-data-write-memory-bytes"),
        );
        self.set_capability(
            "watchpoints",
            command_status(&self.capabilities.commands, "-break-watch"),
        );

        let pty = self.backend.pty_path().as_bytes().to_vec();
        self.execute(
            MiCommand::new("-inferior-tty-set")?.string(pty),
            Duration::from_secs(5),
        )
        .await?;
        Ok(())
    }

    fn set_capability(&mut self, name: &str, status: CapabilityStatus) {
        if let Some(capability) = self.capabilities.capabilities.get_mut(name) {
            capability.status = status;
            capability.last_checked_revision = self.reducer.state().revision;
        }
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                request = self.requests.recv() => {
                    let Some(request) = request else {
                        let _ = self.close().await;
                        break;
                    };
                    if self.handle_request(request).await {
                        break;
                    }
                }
                input = self.backend.next_input() => {
                    let Some(input) = input else {
                        let _ = self.apply_event(DomainEvent::BackendExited { status: None });
                        break;
                    };
                    if let Ok(Some(MiRecord::Result { token: Some(token), .. })) = self.process_input(input)
                        && self.timed_out_tokens.remove(&token)
                    {
                        let _ = self.apply_event(DomainEvent::ConsistencyDirty {
                            reason: format!("delayed result for timed out MI token {token}"),
                        });
                    }
                }
            }
        }
    }

    async fn handle_request(&mut self, request: WorkerRequest) -> bool {
        match request {
            WorkerRequest::Command {
                command,
                timeout,
                response,
            } => {
                let _ = response.send(self.execute(command, timeout).await);
            }
            WorkerRequest::Transaction {
                before,
                command,
                after,
                timeout,
                response,
            } => {
                let mut setup = Ok(());
                for command in before {
                    if let Err(error) = self.execute(command, timeout).await {
                        setup = Err(error);
                        break;
                    }
                }
                let result = match setup {
                    Ok(()) => self.execute(command, timeout).await,
                    Err(error) => Err(error),
                };
                let mut restoration_error = None;
                for command in after {
                    if let Err(error) = self.execute(command, timeout).await {
                        restoration_error = Some(error);
                        break;
                    }
                }
                if let Some(error) = restoration_error {
                    let _ = self.apply_event(DomainEvent::ConsistencyDirty {
                        reason: format!("failed to restore temporary GDB settings: {error}"),
                    });
                    let _ = response.send(Err(Error::new(
                        ErrorCode::ConsistencyDirty,
                        "temporary GDB settings could not be restored",
                    )));
                } else {
                    let _ = response.send(result);
                }
            }
            WorkerRequest::RecordEvent { event, response } => {
                let _ = response.send(self.apply_event(event));
            }
            WorkerRequest::ReadOutput {
                ring,
                after_offset,
                max_bytes,
                response,
            } => {
                let ring = match ring {
                    OutputRing::Inferior => &self.inferior_output,
                    OutputRing::Console => &self.console_output,
                    OutputRing::Log => &self.log_output,
                };
                let _ = response.send(ring.read(after_offset, max_bytes));
            }
            WorkerRequest::WriteInferior { bytes, response } => {
                let result = match self.journal.append_inferior_input(&bytes) {
                    Ok(_) => self.backend.write_inferior(&bytes).await,
                    Err(error) => Err(error),
                };
                let _ = response.send(result);
            }
            WorkerRequest::ResizeInferior {
                rows,
                columns,
                response,
            } => {
                let _ = response.send(self.backend.resize_inferior(rows, columns).await);
            }
            WorkerRequest::Close { response } => {
                let result = self.close().await;
                let _ = response.send(result);
                return true;
            }
        }
        false
    }

    async fn close(&mut self) -> Result<()> {
        self.apply_event(DomainEvent::SessionClosing)?;
        self.backend.shutdown().await?;
        self.apply_event(DomainEvent::SessionClosed)?;
        Ok(())
    }

    async fn execute(&mut self, command: MiCommand, timeout: Duration) -> Result<CommandReply> {
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "MI token counter exhausted"))?;
        let raw = command.encoded(token);
        self.journal.append_mi_input(token, &raw)?;
        self.backend.send(token, &command).await?;

        let deadline = tokio::time::Instant::now() + timeout;
        let mut streams = Vec::new();
        let mut stream_bytes: usize = 0;
        let mut stream_truncated = false;
        loop {
            let input = tokio::time::timeout_at(deadline, self.backend.next_input())
                .await
                .map_err(|_| {
                    self.timed_out_tokens.insert(token);
                    Error::new(
                        ErrorCode::Timeout,
                        format!("MI token {token} timed out; target state is unchanged"),
                    )
                    .retryable()
                })?
                .ok_or_else(|| Error::new(ErrorCode::GdbExited, "GDB input channel closed"))?;
            let Some(record) = self.process_input(input)? else {
                continue;
            };
            if let MiRecord::Result {
                token: Some(result_token),
                class,
                results,
            } = &record
                && *result_token == token
            {
                let evidence_seq = self.reducer.state().event_seq;
                if class == "error" {
                    let message =
                        MiResult::find_str(results, "msg").unwrap_or("GDB command failed");
                    return Err(Error::new(ErrorCode::GdbError, message)
                        .with_details(serde_json::json!({ "token": token, "record": record })));
                }
                return Ok(CommandReply {
                    token,
                    class: class.clone(),
                    record,
                    stream_records: streams,
                    stream_truncated,
                    evidence_seq,
                });
            }
            if matches!(
                record,
                MiRecord::ConsoleStream(_) | MiRecord::TargetStream(_) | MiRecord::LogStream(_)
            ) {
                let length = stream_len(&record);
                if stream_bytes.saturating_add(length) <= self.stream_limit {
                    stream_bytes += length;
                    streams.push(record);
                } else {
                    stream_truncated = true;
                }
            }
        }
    }

    fn process_input(&mut self, input: BackendInput) -> Result<Option<MiRecord>> {
        match input {
            BackendInput::Mi { raw, record } => {
                self.journal.append_mi_output(&raw)?;
                if let Some(event) = normalize(&record) {
                    let stopped = matches!(event, DomainEvent::TargetStopped { .. });
                    self.apply_event(event)?;
                    if stopped {
                        // ponytail: publish the bounded stop record immediately;
                        // inspection.snapshot enriches it when callers need more.
                        let stop_id = self.reducer.state().stop_id.clone().unwrap();
                        self.apply_event(DomainEvent::SnapshotReady {
                            stop_id,
                            partial: true,
                        })?;
                    }
                }
                Ok(Some(record))
            }
            BackendInput::GdbStderr(bytes) => {
                self.journal.append_gdb_stderr(&bytes)?;
                self.log_output.append(&bytes);
                Ok(None)
            }
            BackendInput::InferiorPty(bytes) => {
                self.journal.append_inferior_output(&bytes)?;
                self.inferior_output.append(&bytes);
                self.apply_event(DomainEvent::Output {
                    source: OutputSource::InferiorPty,
                    bytes,
                })?;
                Ok(None)
            }
            BackendInput::ProtocolError(error) => {
                self.apply_event(DomainEvent::ConsistencyLost {
                    reason: error.to_string(),
                })?;
                Err(error)
            }
            BackendInput::GdbEof => {
                let status = self.backend.try_wait()?.and_then(|status| status.code());
                self.apply_event(DomainEvent::BackendExited { status })?;
                Err(Error::new(ErrorCode::GdbExited, "GDB stdout closed"))
            }
            BackendInput::PtyEof => Ok(None),
        }
    }

    fn apply_event(&mut self, event: DomainEvent) -> Result<()> {
        let journaled: JournaledEvent = self.journal.append_domain(event.clone())?;
        let changed = self.reducer.apply(&journaled)?;
        if changed {
            self.persist()?;
            self.state_sender.send_replace(self.reducer.state().clone());
        }
        let _ = self.events.send(PublishedEvent {
            event_seq: journaled.seq(),
            revision: self.reducer.state().revision,
            event,
        });
        Ok(())
    }

    fn persist(&mut self) -> Result<()> {
        self.store
            .upsert_session(self.reducer.state(), self.profile)
    }
}

async fn wait_for_prompt(
    backend: &mut GdbBackend,
    journal: &mut Journal,
    reducer: &mut StateReducer,
    inferior_output: &mut ByteRing,
    console_output: &mut ByteRing,
    log_output: &mut ByteRing,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let input = tokio::time::timeout_at(deadline, backend.next_input())
            .await
            .map_err(|_| Error::new(ErrorCode::GdbUnresponsive, "GDB startup timed out"))?
            .ok_or_else(|| Error::new(ErrorCode::GdbExited, "GDB startup channel closed"))?;
        match input {
            BackendInput::Mi { raw, record } => {
                journal.append_mi_output(&raw)?;
                if let Some(event) = normalize(&record) {
                    if let DomainEvent::Output { source, bytes } = &event {
                        match source {
                            OutputSource::GdbConsoleStream => {
                                console_output.append(bytes);
                            }
                            OutputSource::GdbLogStream => {
                                log_output.append(bytes);
                            }
                            OutputSource::MiTargetStream => {
                                inferior_output.append(bytes);
                            }
                            _ => {}
                        }
                    }
                    let journaled = journal.append_domain(event)?;
                    reducer.apply(&journaled)?;
                }
                if record == MiRecord::Prompt {
                    return Ok(());
                }
            }
            BackendInput::GdbStderr(bytes) => {
                journal.append_gdb_stderr(&bytes)?;
                log_output.append(&bytes);
            }
            BackendInput::ProtocolError(error) => return Err(error),
            BackendInput::GdbEof => return Err(Error::new(ErrorCode::GdbExited, "GDB exited")),
            BackendInput::InferiorPty(_) | BackendInput::PtyEof => {}
        }
    }
}

fn extract_string_list(record: &MiRecord, name: &str) -> BTreeSet<String> {
    let Some(MiValue::ValueList(values)) = MiResult::find(record.results(), name) else {
        return BTreeSet::new();
    };
    values
        .iter()
        .filter_map(MiValue::as_str)
        .map(str::to_owned)
        .collect()
}

// 2026-08-28: Unsupported commands still return ^done; capability detection
// must inspect command.exists instead of treating probe success as support.
fn mi_command_exists(record: &MiRecord) -> bool {
    MiResult::find(record.results(), "command")
        .and_then(MiValue::results)
        .and_then(|results| MiResult::find_str(results, "exists"))
        == Some("true")
}

fn capability(
    status: CapabilityStatus,
    scope: &'static str,
    constraints: Vec<String>,
    source: &'static str,
    last_checked_revision: u64,
) -> Capability {
    Capability {
        status,
        scope,
        constraints,
        source,
        last_checked_revision,
    }
}

fn command_status(commands: &BTreeSet<String>, command: &str) -> CapabilityStatus {
    if commands.contains(command) {
        CapabilityStatus::Conditional
    } else {
        CapabilityStatus::Unsupported
    }
}

fn stream_len(record: &MiRecord) -> usize {
    match record {
        MiRecord::ConsoleStream(bytes)
        | MiRecord::TargetStream(bytes)
        | MiRecord::LogStream(bytes) => bytes.len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::config::{ArtifactConfig, PersistenceConfig};

    #[test]
    fn reads_mi_command_probe_value() {
        let exists =
            gdb_ai_mi::parse_record(b"1^done,command={exists=\"true\"}", MiLimits::default())
                .unwrap();
        let missing =
            gdb_ai_mi::parse_record(b"2^done,command={exists=\"false\"}", MiLimits::default())
                .unwrap();
        assert!(mi_command_exists(&exists));
        assert!(!mi_command_exists(&missing));
    }

    #[tokio::test]
    async fn starts_secure_gdb_and_closes_cleanly() {
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
        let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
        let session = SessionHandle::start(Arc::new(config), Profile::DebugControl, store)
            .await
            .unwrap();
        assert_eq!(
            session.state().lifecycle,
            crate::domain::SessionLifecycle::Ready
        );
        assert!(session.capabilities().supports("async_execution"));
        assert!(session.capabilities().supports("inferior_tty"));
        session.close().await.unwrap();
        assert_eq!(
            session.state().lifecycle,
            crate::domain::SessionLifecycle::Closed
        );
    }
}

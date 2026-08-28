use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    future::Future,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, RwLock as StdRwLock},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiLimits, MiRecord, MiResult, MiValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};

use crate::{
    Error, ErrorCode, Result,
    backend::{
        BackendDescriptor, BackendInput, DebugBackend, GdbBackend, MiCommand, PtyOutput,
        SandboxOptions, session_directory,
    },
    config::Config,
    domain::{
        DomainEvent, InferiorStatus, JournaledEvent, OutputSource, SessionId, SessionState,
        SnapshotStatus, StopId, TrackingDefinition, ValueBinding, WaitBaseline,
    },
    journal::Journal,
    metrics::Metrics,
    normalize::normalize,
    persistence::Store,
    policy::Profile,
    reducer::StateReducer,
    ring::{ByteRing, RingRead},
};

tokio::task_local! {
    static ACTIVE_OBSERVATION_SESSION: String;
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionCapabilities {
    pub backend: BackendDescriptor,
    pub features: BTreeSet<String>,
    pub target_features: BTreeSet<String>,
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
    Target,
    Console,
    Log,
}

#[derive(Clone)]
pub struct SessionHandle {
    id: SessionId,
    profile: Profile,
    capabilities: Arc<StdRwLock<SessionCapabilities>>,
    requests: mpsc::Sender<WorkerRequest>,
    controls: mpsc::Sender<ControlRequest>,
    command_sequence: Arc<Mutex<()>>,
    inferior_output: Arc<PtyOutput>,
    state: watch::Receiver<SessionState>,
    events: broadcast::Sender<PublishedEvent>,
    command_timeout: Duration,
    session_dir: PathBuf,
    journal_path: PathBuf,
}

impl SessionHandle {
    pub async fn start(
        config: Arc<Config>,
        profile: Profile,
        store: Arc<Store>,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let id = SessionId::new();
        let session_dir = session_directory(&config.persistence.sessions, &id.0);
        std::fs::create_dir_all(&session_dir)?;
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700))?;
        // 2026-08-28: Bubblewrap bind destinations require absolute paths;
        // relative persistence configuration previously made startup fail.
        let session_dir = std::fs::canonicalize(session_dir)?;
        let journal_path = session_dir.join("journal.jsonl");
        let mut journal = Journal::create(&journal_path, config.limits.journal_bytes)?;
        journal.append_session_created(&id.0)?;
        let initial_state = SessionState::creating(id.clone());
        let (state_sender, state) = watch::channel(initial_state.clone());
        let (events, _) = broadcast::channel(512);
        let (requests, receiver) = mpsc::channel(128);
        // 2026-08-28: Interrupt and close previously waited behind the command
        // they needed to preempt. Keep a dedicated bounded control lane.
        let (controls, control_receiver) = mpsc::channel(16);

        let mut worker = SessionWorker::bootstrap(
            config.clone(),
            profile,
            store,
            metrics.clone(),
            session_dir.clone(),
            journal,
            initial_state,
            state_sender,
            events.clone(),
            receiver,
            control_receiver,
        )
        .await?;
        let capabilities = worker.capabilities.clone();
        let inferior_output = worker.inferior_output.clone();
        metrics.session_started();
        worker.metric_active = true;
        tokio::spawn(worker.run());

        Ok(Self {
            id,
            profile,
            capabilities,
            requests,
            controls,
            command_sequence: Arc::new(Mutex::new(())),
            inferior_output,
            state,
            events,
            command_timeout: config.server.command_timeout(),
            session_dir,
            journal_path,
        })
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub(crate) fn session_directory(&self) -> &Path {
        &self.session_dir
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn capabilities(&self) -> SessionCapabilities {
        self.capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
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
        let deadline = command_deadline(timeout);
        if self.observation_active() {
            return self.send_command(command, deadline).await;
        }
        let _sequence = self.command_sequence.lock().await;
        self.send_command(command, deadline).await
    }

    async fn send_command(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Command {
                command,
                deadline,
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
        let deadline = command_deadline(self.command_timeout);
        if self.observation_active() {
            return self
                .send_transaction(before, command, after, deadline)
                .await;
        }
        let _sequence = self.command_sequence.lock().await;
        self.send_transaction(before, command, after, deadline)
            .await
    }

    async fn send_transaction(
        &self,
        before: Vec<MiCommand>,
        command: MiCommand,
        after: Vec<MiCommand>,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::Transaction {
                before,
                command,
                after,
                deadline,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn safe_evaluate(&self, command: MiCommand) -> Result<CommandReply> {
        let deadline = command_deadline(self.command_timeout);
        if self.observation_active() {
            return self.send_safe_evaluate(command, deadline).await;
        }
        let _sequence = self.command_sequence.lock().await;
        self.send_safe_evaluate(command, deadline).await
    }

    async fn send_safe_evaluate(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::SafeEvaluate {
                command,
                deadline,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn stable_observation<'a, T>(
        &'a self,
        expected: &'a SessionState,
        operation: Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>,
    ) -> Result<T> {
        if self.observation_active() {
            self.require_observation_context(expected)?;
            let result = operation.await?;
            self.require_observation_context(expected)?;
            return Ok(result);
        }

        // 2026-08-28: Gateway locks did not protect direct SessionHandle users,
        // so composite reads could still interleave ordinary MI commands. Hold
        // the shared command sequence for the complete stop-scoped operation.
        // ponytail: Keep composite builders in this task; use actor transaction
        // IDs before allowing them to spawn command-producing subtasks.
        let _sequence = self.command_sequence.lock().await;
        self.require_observation_context(expected)?;
        ACTIVE_OBSERVATION_SESSION
            .scope(self.id.0.clone(), async {
                let result = operation.await?;
                self.require_observation_context(expected)?;
                Ok(result)
            })
            .await
    }

    fn observation_active(&self) -> bool {
        ACTIVE_OBSERVATION_SESSION
            .try_with(|session_id| session_id == &self.id.0)
            .unwrap_or(false)
    }

    fn require_observation_context(&self, expected: &SessionState) -> Result<()> {
        let current = self.state();
        if current.stop_id == expected.stop_id
            && current.execution_epoch == expected.execution_epoch
        {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::StaleContext,
                "target stop changed during composite operation",
            ))
        }
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

    pub async fn record_api(&self, request: Value) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RecordApi {
                request,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn flush_journal(&self) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::FlushJournal { response: sender })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn refresh_target_capabilities(&self) -> Result<SessionCapabilities> {
        if self.observation_active() {
            return self.send_refresh_target_capabilities().await;
        }
        let _sequence = self.command_sequence.lock().await;
        self.send_refresh_target_capabilities().await
    }

    async fn send_refresh_target_capabilities(&self) -> Result<SessionCapabilities> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RefreshTargetCapabilities { response: sender })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn register_value(&self, binding: ValueBinding) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RegisterValue {
                binding,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn value_binding(&self, value_id: String) -> Result<ValueBinding> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::GetValue {
                value_id,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn remove_value(&self, value_id: String) -> Result<ValueBinding> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RemoveValue {
                value_id,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn add_tracking(&self, definition: TrackingDefinition) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::AddTracking {
                definition,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn remove_tracking(&self, tracking_id: String) -> Result<TrackingDefinition> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RemoveTracking {
                tracking_id,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn tracking(&self) -> Result<Vec<TrackingDefinition>> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::ListTracking { response: sender })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))
    }

    pub async fn record_tracking(
        &self,
        observations: BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RecordTracking {
                observations,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn commit_snapshot(
        &self,
        snapshot_id: String,
        snapshot: Value,
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
        partial: bool,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::CommitSnapshot {
                snapshot_id,
                snapshot,
                expected_stop_id,
                expected_execution_epoch,
                partial,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn snapshot(&self, snapshot_id: String) -> Result<Value> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::GetSnapshot {
                snapshot_id,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn wait(&self, until: WaitUntil, timeout: Duration) -> Result<SessionState> {
        self.wait_from(until, timeout, None, None).await
    }

    pub async fn wait_after(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: &SessionState,
    ) -> Result<SessionState> {
        self.wait_after_baseline(until, timeout, &WaitBaseline::from(baseline))
            .await
    }

    pub async fn wait_after_baseline(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: &WaitBaseline,
    ) -> Result<SessionState> {
        self.wait_from(until, timeout, Some(baseline), None).await
    }

    pub async fn wait_for_operation(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: &WaitBaseline,
        expected_execution_epoch: u64,
    ) -> Result<SessionState> {
        self.wait_from(
            until,
            timeout,
            Some(baseline),
            Some(expected_execution_epoch),
        )
        .await
    }

    async fn wait_from(
        &self,
        until: WaitUntil,
        timeout: Duration,
        baseline: Option<&WaitBaseline>,
        expected_execution_epoch: Option<u64>,
    ) -> Result<SessionState> {
        let mut state = self.state.clone();
        let baseline = baseline.cloned();
        let wait = async {
            loop {
                let current = state.borrow().clone();
                // 2026-08-28: A later execution epoch belongs to another
                // operation and must not satisfy this operation's waiter.
                if expected_execution_epoch
                    .is_some_and(|expected| current.execution_epoch > expected)
                {
                    return Err(Error::new(
                        ErrorCode::StaleContext,
                        "operation state was superseded by a later execution",
                    ));
                }
                if expected_execution_epoch
                    .is_none_or(|expected| current.execution_epoch == expected)
                    && wait_satisfied(&current, until, baseline.as_ref())
                {
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
        if matches!(ring, OutputRing::Inferior) {
            // 2026-08-28: GDB can publish inferior exit before the PTY reader
            // observes hangup. Drain that bounded tail before returning exit output.
            if self
                .state()
                .inferiors
                .values()
                .any(|inferior| inferior.status == InferiorStatus::Exited)
            {
                self.inferior_output
                    .wait_closed(Duration::from_secs(1))
                    .await;
            }
            return Ok(self
                .inferior_output
                .read(after_offset, max_bytes.min(64 * 1024)));
        }
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

    pub async fn interrupt(&self, command: MiCommand) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.controls
            .send(ControlRequest::Interrupt {
                command,
                deadline: command_deadline(self.command_timeout),
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
        self.controls
            .send(ControlRequest::Close { response: sender })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }
}

// 2026-08-28: Compare waits with pre-command state; otherwise an existing
// stop or snapshot can satisfy a new resume request before a new async event.
fn wait_satisfied(state: &SessionState, until: WaitUntil, baseline: Option<&WaitBaseline>) -> bool {
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
        // 2026-08-28: An inferior that was already terminal at the baseline
        // must not satisfy a new run-and-wait operation for another inferior.
        WaitUntil::Exited => state.inferiors.iter().any(|(backend_id, inferior)| {
            terminal(inferior.status)
                && baseline.is_none_or(|baseline| !baseline.terminal_inferiors.contains(backend_id))
        }),
    }
}

fn terminal(status: InferiorStatus) -> bool {
    matches!(
        status,
        InferiorStatus::Exited | InferiorStatus::Detached | InferiorStatus::Disconnected
    )
}

fn command_deadline(timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + timeout.max(Duration::from_millis(1))
}

enum WorkerRequest {
    Command {
        command: MiCommand,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    Transaction {
        before: Vec<MiCommand>,
        command: MiCommand,
        after: Vec<MiCommand>,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    SafeEvaluate {
        command: MiCommand,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    RecordEvent {
        event: DomainEvent,
        response: oneshot::Sender<Result<()>>,
    },
    RecordApi {
        request: Value,
        response: oneshot::Sender<Result<()>>,
    },
    FlushJournal {
        response: oneshot::Sender<Result<()>>,
    },
    RefreshTargetCapabilities {
        response: oneshot::Sender<Result<SessionCapabilities>>,
    },
    RegisterValue {
        binding: ValueBinding,
        response: oneshot::Sender<Result<()>>,
    },
    GetValue {
        value_id: String,
        response: oneshot::Sender<Result<ValueBinding>>,
    },
    RemoveValue {
        value_id: String,
        response: oneshot::Sender<Result<ValueBinding>>,
    },
    AddTracking {
        definition: TrackingDefinition,
        response: oneshot::Sender<Result<()>>,
    },
    RemoveTracking {
        tracking_id: String,
        response: oneshot::Sender<Result<TrackingDefinition>>,
    },
    ListTracking {
        response: oneshot::Sender<Vec<TrackingDefinition>>,
    },
    RecordTracking {
        observations: BTreeMap<String, Value>,
        response: oneshot::Sender<Result<BTreeMap<String, Value>>>,
    },
    CommitSnapshot {
        snapshot_id: String,
        snapshot: Value,
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
        partial: bool,
        response: oneshot::Sender<Result<()>>,
    },
    GetSnapshot {
        snapshot_id: String,
        response: oneshot::Sender<Result<Value>>,
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
}

enum ControlRequest {
    Interrupt {
        command: MiCommand,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    Close {
        response: oneshot::Sender<Result<()>>,
    },
}

struct PendingControl {
    token: u64,
    deadline: tokio::time::Instant,
    escalate_at: tokio::time::Instant,
    escalated: bool,
    started: std::time::Instant,
    response: oneshot::Sender<Result<CommandReply>>,
}

// Owns both GDB input and reducer state. One ordinary MI command may be in
// flight; the separate control lane admits only interrupt or close.
struct SessionWorker {
    backend: Box<dyn DebugBackend>,
    journal: Journal,
    reducer: StateReducer,
    store: Arc<Store>,
    metrics: Arc<Metrics>,
    profile: Profile,
    capabilities: Arc<StdRwLock<SessionCapabilities>>,
    state_sender: watch::Sender<SessionState>,
    events: broadcast::Sender<PublishedEvent>,
    requests: mpsc::Receiver<WorkerRequest>,
    controls: mpsc::Receiver<ControlRequest>,
    controls_open: bool,
    inferior_output: Arc<PtyOutput>,
    inferior_output_dropped: u64,
    target_output: ByteRing,
    console_output: ByteRing,
    log_output: ByteRing,
    next_token: u64,
    timed_out_tokens: HashSet<u64>,
    stream_limit: usize,
    values: BTreeMap<String, ValueBinding>,
    tracking: BTreeMap<String, TrackingDefinition>,
    tracking_history: BTreeMap<String, VecDeque<Value>>,
    snapshots: BTreeMap<String, Value>,
    stale_backend_values: Vec<String>,
    tracking_memory_limit: usize,
    fatal: bool,
    metric_active: bool,
}

#[allow(clippy::too_many_arguments)]
impl SessionWorker {
    async fn bootstrap(
        config: Arc<Config>,
        profile: Profile,
        store: Arc<Store>,
        metrics: Arc<Metrics>,
        session_dir: PathBuf,
        journal: Journal,
        initial_state: SessionState,
        state_sender: watch::Sender<SessionState>,
        events: broadcast::Sender<PublishedEvent>,
        requests: mpsc::Receiver<WorkerRequest>,
        controls: mpsc::Receiver<ControlRequest>,
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
        let mut target_output = ByteRing::new(config.limits.inferior_output_ring_bytes);
        let mut console_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut log_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut versions = vec![config.gdb.preferred_mi.clone()];
        if config.gdb.fallback_mi != config.gdb.preferred_mi {
            versions.push(config.gdb.fallback_mi.clone());
        }

        for version in versions {
            let mut backend: Box<dyn DebugBackend> = Box::new(
                GdbBackend::spawn(
                    &config.gdb,
                    &version,
                    &session_dir,
                    limits,
                    &config.limits,
                    SandboxOptions {
                        mode: config.security.sandbox,
                        allow_network: profile == Profile::RawAdmin
                            && !config.security.remote_allowlist.is_empty(),
                    },
                )
                .await?,
            );
            match wait_for_prompt(
                backend.as_mut(),
                &mut journal,
                &mut reducer,
                &mut target_output,
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
                    metrics.gdb_start_failed();
                    last_error = Some(error);
                    let _ = backend.shutdown().await;
                }
            }
        }
        let backend = selected.ok_or_else(|| {
            last_error.unwrap_or_else(|| Error::new(ErrorCode::GdbExited, "GDB startup failed"))
        })?;
        let inferior_output = backend.inferior_output();
        let mut worker = Self {
            capabilities: Arc::new(StdRwLock::new(SessionCapabilities {
                backend: backend.descriptor().clone(),
                features: BTreeSet::new(),
                target_features: BTreeSet::new(),
                commands: BTreeSet::new(),
                capabilities: BTreeMap::from([
                    ("async_execution".into(), capability(CapabilityStatus::Unknown, "backend", vec![], "handshake", 0)),
                    ("non_stop".into(), capability(CapabilityStatus::Unsupported, "session", vec!["version 1 is all-stop".into()], "configuration", 0)),
                    ("inferior_tty".into(), capability(CapabilityStatus::Supported, "session", vec![], "pty", 0)),
                    ("memory_read".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["target must be stopped; volatile ranges may have target-defined effects".into()], "probe", 0)),
                    ("memory_write".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["requires lab_mutation policy and stopped target".into()], "probe", 0)),
                    ("watchpoints".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["hardware resources are target-dependent".into()], "probe", 0)),
                    ("reverse".into(), capability(CapabilityStatus::Unknown, "current_target", vec!["target must advertise reverse execution".into()], "target-features", 0)),
                    ("execution".into(), capability(if matches!(profile, Profile::DebugControl | Profile::LabMutation | Profile::RawAdmin) { CapabilityStatus::Conditional } else { CapabilityStatus::Unsupported }, "current_target", vec!["requires a live target".into()], "policy", 0)),
                    ("target_mutation".into(), capability(if matches!(profile, Profile::LabMutation | Profile::RawAdmin) { CapabilityStatus::Conditional } else { CapabilityStatus::Unsupported }, "current_target", vec!["requires lab_mutation or raw_admin".into()], "policy", 0)),
                    ("custom_extension".into(), capability(CapabilityStatus::Unsupported, "backend", vec!["optional trusted extension is not configured".into()], "configuration", 0)),
                    ("thread_scoped_commands".into(), capability(CapabilityStatus::Supported, "backend", vec![], "mi", 0)),
                    ("hardening.filesystem".into(), capability(if backend.descriptor().filesystem_hardened { CapabilityStatus::Supported } else { CapabilityStatus::Unsupported }, "session", vec!["does not provide PID, user, cgroup, or seccomp isolation".into()], "bubblewrap", 0)),
                    ("hardening.network_namespace".into(), capability(if backend.descriptor().network_isolated { CapabilityStatus::Supported } else { CapabilityStatus::Unsupported }, "session", vec![], "bubblewrap", 0)),
                    ("sandbox.seccomp".into(), capability(CapabilityStatus::Unsupported, "deployment", vec!["no portable GDB seccomp profile is enabled".into()], "runtime", 0)),
                ]),
                limitations: vec![
                    "untrusted targets require an external container or VM supervisor for PID, user, cgroup, and seccomp isolation".into(),
                ],
            })),
            backend,
            journal,
            reducer,
            store,
            metrics,
            profile,
            state_sender,
            events,
            requests,
            controls,
            controls_open: true,
            inferior_output,
            inferior_output_dropped: 0,
            target_output,
            console_output,
            log_output,
            next_token: 1,
            timed_out_tokens: HashSet::new(),
            stream_limit: config.limits.tool_response_bytes,
            values: BTreeMap::new(),
            tracking: BTreeMap::new(),
            tracking_history: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            stale_backend_values: Vec::new(),
            tracking_memory_limit: config.limits.memory_read_bytes,
            fatal: false,
            metric_active: false,
        };
        worker.apply_event(DomainEvent::BackendStarted)?;
        worker.handshake().await?;
        worker.load_extension(&config.gdb).await?;
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
            MiCommand::new("-gdb-set")?.bare("confirm")?.bare("off")?,
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
        let target_writes = matches!(self.profile, Profile::LabMutation | Profile::RawAdmin);
        let target_control = matches!(
            self.profile,
            Profile::DebugControl | Profile::LabMutation | Profile::RawAdmin
        );
        for (setting, enabled) in [
            ("may-write-memory", target_writes),
            // 2026-08-28: starti and some stepping paths update internal
            // registers. Service policy still denies register.write outside
            // lab_mutation, while safe evaluation temporarily disables writes.
            ("may-write-registers", target_control),
            ("may-insert-breakpoints", target_control),
            ("may-interrupt", target_control),
        ] {
            self.execute(
                MiCommand::new("-gdb-set")?
                    .bare(setting)?
                    .bare(if enabled { "on" } else { "off" })?,
                Duration::from_secs(5),
            )
            .await?;
        }
        let features = self
            .execute(MiCommand::new("-list-features")?, Duration::from_secs(5))
            .await?;
        self.capabilities
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .features = extract_string_list(&features.record, "features");
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
                self.capabilities
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .commands
                    .insert(command.into());
            }
        }
        let commands = self
            .capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .commands
            .clone();
        self.set_capability(
            "memory_read",
            command_status(&commands, "-data-read-memory-bytes"),
        );
        self.set_capability(
            "memory_write",
            if matches!(self.profile, Profile::LabMutation | Profile::RawAdmin) {
                command_status(&commands, "-data-write-memory-bytes")
            } else {
                CapabilityStatus::Unsupported
            },
        );
        self.set_capability("watchpoints", command_status(&commands, "-break-watch"));

        let pty = self.backend.pty_path().as_bytes().to_vec();
        self.execute(
            MiCommand::new("-inferior-tty-set")?.string(pty),
            Duration::from_secs(5),
        )
        .await?;
        Ok(())
    }

    async fn load_extension(&mut self, config: &crate::config::GdbConfig) -> Result<()> {
        let Some(configured_path) = &config.python_extension else {
            return Ok(());
        };
        if !configured_path.is_absolute() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "gdb.python_extension must be an absolute path",
            ));
        }
        let path = std::fs::canonicalize(configured_path)?;
        let bytes = std::fs::read(&path)?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        let expected = config.python_extension_sha256.as_deref().ok_or_else(|| {
            Error::new(
                ErrorCode::PolicyDenied,
                "configured Python extension requires python_extension_sha256",
            )
        })?;
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "configured Python extension hash does not match",
            ));
        }
        let source = format!("source {}", path.display());
        let loaded = self
            .execute(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(source),
                Duration::from_secs(5),
            )
            .await;
        if let Err(error) = loaded {
            self.capabilities
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .limitations
                .push(format!("trusted Python extension failed to load: {error}"));
            return Ok(());
        }
        match self
            .execute(
                MiCommand::new("-gdb-ai-capabilities")?,
                Duration::from_secs(5),
            )
            .await
        {
            Ok(reply) if MiResult::find_str(reply.record.results(), "protocol") == Some("1") => {
                self.set_capability("custom_extension", CapabilityStatus::Supported);
            }
            Ok(_) => {
                self.capabilities
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .limitations
                    .push("trusted Python extension protocol mismatch".into());
            }
            Err(error) => {
                self.capabilities
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .limitations
                    .push(format!("trusted Python extension probe failed: {error}"));
            }
        }
        Ok(())
    }

    fn set_capability(&self, name: &str, status: CapabilityStatus) {
        let mut capabilities = self
            .capabilities
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(capability) = capabilities.capabilities.get_mut(name) {
            capability.status = status;
            capability.last_checked_revision = self.reducer.state().revision;
        }
    }

    async fn refresh_target_capabilities(&mut self) -> Result<SessionCapabilities> {
        let reply = self
            .execute(
                MiCommand::new("-list-target-features")?,
                Duration::from_secs(5),
            )
            .await?;
        let features = extract_string_list(&reply.record, "features");
        let reverse = if features.contains("reverse") {
            CapabilityStatus::Conditional
        } else {
            CapabilityStatus::Unsupported
        };
        {
            let mut capabilities = self
                .capabilities
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            capabilities.target_features = features;
        }
        self.set_capability("reverse", reverse);
        Ok(self
            .capabilities
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone())
    }

    async fn run(mut self) {
        let mut journal_flush = tokio::time::interval(Duration::from_millis(250));
        journal_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = journal_flush.tick() => {
                    if let Err(error) = self.journal.flush() {
                        tracing::error!(%error, "session journal flush failed");
                        self.mark_failed();
                        let _ = self.backend.shutdown().await;
                        break;
                    }
                }
                control = self.controls.recv(), if self.controls_open => {
                    match control {
                        Some(control) => {
                            if self.handle_control(control).await {
                                break;
                            }
                        }
                        None => self.controls_open = false,
                    }
                }
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
                        self.mark_failed();
                        let _ = self.backend.shutdown().await;
                        break;
                    };
                    if let Ok(Some((record, _))) = self.process_input(input)
                        && let Some(token) = take_delayed_token(&mut self.timed_out_tokens, &record)
                    {
                        let _ = self.apply_event(DomainEvent::CommandOutcomeResolved { token });
                    }
                    if self.fatal {
                        let _ = self.backend.shutdown().await;
                        break;
                    }
                }
            }
        }
        let _ = self.journal.flush();
    }

    async fn handle_request(&mut self, request: WorkerRequest) -> bool {
        match request {
            WorkerRequest::Command {
                command,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                self.cleanup_stale_values(deadline).await;
                let _ = response.send(self.execute_until(command, deadline).await);
            }
            WorkerRequest::Transaction {
                before,
                command,
                after,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                self.cleanup_stale_values(deadline).await;
                let mut setup = Ok(());
                for command in before {
                    if let Err(error) = self.execute_until(command, deadline).await {
                        setup = Err(error);
                        break;
                    }
                }
                let result = match setup {
                    Ok(()) => self.execute_until(command, deadline).await,
                    Err(error) => Err(error),
                };
                let mut restoration_error = None;
                for command in after {
                    if let Err(error) = self.execute_until(command, deadline).await {
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
            WorkerRequest::SafeEvaluate {
                command,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                self.cleanup_stale_values(deadline).await;
                let _ = response.send(self.execute_safe(command, deadline).await);
            }
            WorkerRequest::RecordEvent { event, response } => {
                let _ = response.send(self.apply_event(event));
            }
            WorkerRequest::RecordApi { request, response } => {
                let appended = self.journal.append_api(&request).map(|_| ());
                let result = self.journal_result(appended);
                let _ = response.send(result);
            }
            WorkerRequest::FlushJournal { response } => {
                let flushed = self.journal.flush();
                let result = self.journal_result(flushed);
                let _ = response.send(result);
            }
            WorkerRequest::RefreshTargetCapabilities { response } => {
                let result = match self.require_known_outcome_name("-list-target-features") {
                    Ok(()) => self.refresh_target_capabilities().await,
                    Err(error) => Err(error),
                };
                let _ = response.send(result);
            }
            WorkerRequest::RegisterValue { binding, response } => {
                let result = if self.values.len() >= 1_024 {
                    Err(Error::new(
                        ErrorCode::OutputLimit,
                        "session value-object limit reached",
                    ))
                } else if self.values.contains_key(&binding.value_id.0) {
                    Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "value object already exists",
                    ))
                } else {
                    self.values.insert(binding.value_id.0.clone(), binding);
                    Ok(())
                };
                let _ = response.send(result);
            }
            WorkerRequest::GetValue { value_id, response } => {
                let result = self.values.get(&value_id).cloned().ok_or_else(|| {
                    let current = self.reducer.state().stop_id.as_ref();
                    if value_id.starts_with("val_stop_")
                        && current.is_none_or(|stop| !value_id.contains(&stop.0))
                    {
                        Error::new(
                            ErrorCode::StaleContext,
                            "value object belongs to an earlier stop",
                        )
                    } else {
                        Error::new(ErrorCode::NotFound, "value object not found")
                    }
                });
                let _ = response.send(result);
            }
            WorkerRequest::RemoveValue { value_id, response } => {
                let result = self
                    .values
                    .remove(&value_id)
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "value object not found"));
                let _ = response.send(result);
            }
            WorkerRequest::AddTracking {
                definition,
                response,
            } => {
                let requested_memory = match &definition {
                    TrackingDefinition::Memory { length, .. } => *length,
                    TrackingDefinition::Expression { .. } => 0,
                };
                let tracked_memory = self
                    .tracking
                    .values()
                    .filter_map(|definition| match definition {
                        TrackingDefinition::Memory { length, .. } => Some(*length),
                        TrackingDefinition::Expression { .. } => None,
                    })
                    .sum::<usize>();
                // 2026-08-28: Per-definition limits still allowed 128 ranges
                // to reserve multiple gigabytes. Share one session memory budget.
                let result = if tracked_memory.saturating_add(requested_memory)
                    > self.tracking_memory_limit
                {
                    Err(Error::new(
                        ErrorCode::OutputLimit,
                        "tracked memory exceeds the session memory budget",
                    ))
                } else if self.tracking.len() >= 128 {
                    Err(Error::new(
                        ErrorCode::OutputLimit,
                        "session tracking-definition limit reached",
                    ))
                } else if self.tracking.contains_key(&definition.id().0) {
                    Err(Error::new(
                        ErrorCode::AlreadyExists,
                        "tracking definition already exists",
                    ))
                } else {
                    self.store
                        .upsert_tracking(&self.reducer.state().session_id, &definition)
                        .map(|()| {
                            self.tracking.insert(definition.id().0.clone(), definition);
                        })
                };
                let _ = response.send(result);
            }
            WorkerRequest::RemoveTracking {
                tracking_id,
                response,
            } => {
                let result = self
                    .tracking
                    .get(&tracking_id)
                    .cloned()
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "tracking definition not found"))
                    .and_then(|definition| {
                        self.store
                            .delete_tracking(&self.reducer.state().session_id, &tracking_id)?;
                        self.tracking.remove(&tracking_id);
                        self.tracking_history.remove(&tracking_id);
                        Ok(definition)
                    });
                let _ = response.send(result);
            }
            WorkerRequest::ListTracking { response } => {
                let _ = response.send(self.tracking.values().cloned().collect());
            }
            WorkerRequest::RecordTracking {
                observations,
                response,
            } => {
                let mut changes = BTreeMap::new();
                for (tracking_id, current) in observations {
                    let Some(definition) = self.tracking.get(&tracking_id) else {
                        continue;
                    };
                    let maximum = match definition {
                        TrackingDefinition::Expression { .. } => 32,
                        TrackingDefinition::Memory { max_history, .. } => *max_history,
                    }
                    .clamp(1, 256);
                    let history = self
                        .tracking_history
                        .entry(tracking_id.clone())
                        .or_default();
                    if let Some(previous) = history.back()
                        && previous != &current
                    {
                        changes.insert(tracking_id, tracking_change(previous, &current));
                    }
                    let bytes = serde_json::to_vec(&current).map_or(1, |bytes| bytes.len().max(1));
                    let bounded_maximum = maximum.min((1024 * 1024 / bytes).max(1));
                    history.push_back(current);
                    while history.len() > bounded_maximum {
                        history.pop_front();
                    }
                }
                let _ = response.send(Ok(changes));
            }
            WorkerRequest::CommitSnapshot {
                snapshot_id,
                snapshot,
                expected_stop_id,
                expected_execution_epoch,
                partial,
                response,
            } => {
                // 2026-08-28: Snapshot data was persisted before the Gateway's
                // final context check. Validate and publish it atomically in
                // the state-owning worker so stale builds leave no evidence.
                let state = self.reducer.state();
                let result = if state.stop_id.as_ref() != Some(&expected_stop_id)
                    || state.execution_epoch != expected_execution_epoch
                {
                    Err(Error::new(
                        ErrorCode::StaleContext,
                        "target stop changed before snapshot commit",
                    ))
                } else {
                    self.store_snapshot_value(snapshot_id, snapshot)
                        .and_then(|()| {
                            self.apply_event(DomainEvent::SnapshotReady {
                                stop_id: expected_stop_id,
                                partial,
                            })
                        })
                };
                let _ = response.send(result);
            }
            WorkerRequest::GetSnapshot {
                snapshot_id,
                response,
            } => {
                let result = self
                    .snapshots
                    .get(&snapshot_id)
                    .cloned()
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot not found"));
                let _ = response.send(result);
            }
            WorkerRequest::ReadOutput {
                ring,
                after_offset,
                max_bytes,
                response,
            } => {
                let read = match ring {
                    OutputRing::Inferior => self.inferior_output.read(after_offset, max_bytes),
                    OutputRing::Target => self.target_output.read(after_offset, max_bytes),
                    OutputRing::Console => self.console_output.read(after_offset, max_bytes),
                    OutputRing::Log => self.log_output.read(after_offset, max_bytes),
                };
                let _ = response.send(read);
            }
            WorkerRequest::WriteInferior { bytes, response } => {
                let appended = self.journal.append_inferior_input(&bytes);
                let result = match self.journal_result(appended) {
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
        }
        if self.fatal {
            let _ = self.backend.shutdown().await;
        }
        self.fatal
    }

    async fn handle_control(&mut self, control: ControlRequest) -> bool {
        match control {
            ControlRequest::Interrupt {
                command,
                deadline,
                response,
            } => {
                let result = self.require_known_outcome(&command).and_then(|()| {
                    (deadline > tokio::time::Instant::now())
                        .then_some(())
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Timeout,
                                "interrupt deadline expired while queued",
                            )
                            .retryable()
                        })
                });
                let result = match result {
                    Ok(()) => self.execute_until(command, deadline).await,
                    Err(error) => Err(error),
                };
                let _ = response.send(result);
                self.fatal
            }
            ControlRequest::Close { response } => {
                let result = self.close().await;
                let _ = response.send(result);
                true
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        let closing = self.apply_event(DomainEvent::SessionClosing);
        let shutdown = self.backend.shutdown().await;
        closing?;
        shutdown?;
        self.apply_event(DomainEvent::SessionClosed)?;
        if self.metric_active {
            self.metrics.session_closed();
            self.metric_active = false;
        }
        Ok(())
    }

    async fn cleanup_stale_values(&mut self, deadline: tokio::time::Instant) {
        if !self.reducer.state().inferiors.values().any(|inferior| {
            matches!(
                inferior.status,
                InferiorStatus::Stopped | InferiorStatus::Core
            )
        }) {
            return;
        }
        for backend_name in std::mem::take(&mut self.stale_backend_values) {
            let Ok(command) =
                MiCommand::new("-var-delete").and_then(|command| command.bare(backend_name))
            else {
                continue;
            };
            let _ = self.execute_until(command, deadline).await;
        }
    }

    fn require_known_outcome(&self, command: &MiCommand) -> Result<()> {
        self.require_known_outcome_name(&command.name)
    }

    fn require_known_outcome_name(&self, command: &str) -> Result<()> {
        // 2026-08-28: Starting another ordinary command after a timeout could
        // overlap a late mutation result. Only interruption may cross this fence.
        if !self.timed_out_tokens.is_empty() && command != "-exec-interrupt" {
            return Err(Error::new(
                ErrorCode::GdbUnresponsive,
                format!(
                    "MI command outcome is unknown for token(s) {:?}; interrupt or close the session",
                    self.timed_out_tokens
                ),
            ));
        }
        Ok(())
    }

    async fn execute_safe(
        &mut self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        const SETTINGS: [&str; 3] = [
            "may-call-functions",
            "may-write-memory",
            "may-write-registers",
        ];
        let mut originals = Vec::new();
        for setting in SETTINGS {
            let reply = self
                .execute_until(MiCommand::new("-gdb-show")?.bare(setting)?, deadline)
                .await?;
            let value = MiResult::find_str(reply.record.results(), "value")
                .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB setting has no value"))?;
            originals.push((setting, value.to_owned()));
        }
        // 2026-08-28: Hard-coded restoration to "on" could weaken observer
        // policy after evaluation. Restore the exact values read in this worker.
        let mut setup_error = None;
        for setting in SETTINGS {
            if let Err(error) = self
                .execute_until(
                    MiCommand::new("-gdb-set")?.bare(setting)?.bare("off")?,
                    deadline,
                )
                .await
            {
                setup_error = Some(error);
                break;
            }
        }
        let result = match setup_error {
            Some(error) => Err(error),
            None => self.execute_until(command, deadline).await,
        };
        let mut restoration_error = None;
        for (setting, value) in originals {
            if let Err(error) = self
                .execute_until(
                    MiCommand::new("-gdb-set")?.bare(setting)?.bare(value)?,
                    deadline,
                )
                .await
            {
                restoration_error = Some(error);
                break;
            }
        }
        if let Some(error) = restoration_error {
            self.apply_event(DomainEvent::ConsistencyDirty {
                reason: format!("failed to restore safe-evaluation settings: {error}"),
            })?;
            Err(Error::new(
                ErrorCode::ConsistencyDirty,
                "safe-evaluation settings could not be restored",
            ))
        } else {
            result
        }
    }

    async fn execute(&mut self, command: MiCommand, timeout: Duration) -> Result<CommandReply> {
        self.execute_until(command, command_deadline(timeout)).await
    }

    async fn execute_until(
        &mut self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let started = std::time::Instant::now();
        // 2026-08-28: Starting the timeout inside the worker let requests sit
        // past their API deadline and then execute. Expired work never reaches GDB.
        if deadline <= tokio::time::Instant::now() {
            self.metrics.command(0, true);
            return Err(Error::new(
                ErrorCode::Timeout,
                "MI command deadline expired while queued",
            )
            .retryable());
        }
        let token = self.begin_command(&command).await?;

        let mut streams = Vec::new();
        let mut stream_bytes: usize = 0;
        let mut stream_truncated = false;
        let mut normal_result = None;
        let mut pending_control: Option<PendingControl> = None;
        loop {
            if pending_control.is_none()
                && let Some(result) = normal_result.take()
            {
                return result;
            }
            let mut wake = if normal_result.is_none() {
                deadline
            } else {
                pending_control.as_ref().unwrap().deadline
            };
            if let Some(control) = &pending_control {
                wake = wake.min(control.deadline);
                if !control.escalated {
                    wake = wake.min(control.escalate_at);
                }
            }

            enum ExecutionInput {
                Control(Option<ControlRequest>),
                Backend(Option<BackendInput>),
                Deadline,
            }
            let input = tokio::select! {
                biased;
                control = self.controls.recv(), if self.controls_open => {
                    ExecutionInput::Control(control)
                }
                input = self.backend.next_input() => ExecutionInput::Backend(input),
                _ = tokio::time::sleep_until(wake) => ExecutionInput::Deadline,
            };

            match input {
                ExecutionInput::Control(None) => self.controls_open = false,
                ExecutionInput::Control(Some(ControlRequest::Close { response })) => {
                    let result = self.close().await;
                    let _ = response.send(result);
                    self.fatal = true;
                    return Err(Error::new(ErrorCode::GdbExited, "session closed"));
                }
                ExecutionInput::Control(Some(ControlRequest::Interrupt {
                    command,
                    deadline,
                    response,
                })) => {
                    if pending_control.is_some() {
                        let _ = response.send(Err(Error::new(
                            ErrorCode::Conflict,
                            "an interrupt is already pending",
                        )));
                    } else if deadline <= tokio::time::Instant::now() {
                        let _ = response.send(Err(Error::new(
                            ErrorCode::Timeout,
                            "interrupt deadline expired while queued",
                        )
                        .retryable()));
                    } else {
                        match self.begin_command(&command).await {
                            Ok(control_token) => {
                                let now = tokio::time::Instant::now();
                                pending_control = Some(PendingControl {
                                    token: control_token,
                                    deadline,
                                    escalate_at: now + Duration::from_millis(250),
                                    escalated: false,
                                    started: std::time::Instant::now(),
                                    response,
                                });
                            }
                            Err(error) => {
                                let _ = response.send(Err(error));
                            }
                        }
                    }
                }
                ExecutionInput::Deadline => {
                    let now = tokio::time::Instant::now();
                    let should_escalate = pending_control
                        .as_ref()
                        .is_some_and(|control| !control.escalated && control.escalate_at <= now);
                    if should_escalate {
                        // 2026-08-28: A blocked GDB cannot consume the queued
                        // -exec-interrupt. Escalate only after its MI grace period.
                        if let Err(error) = self.backend.signal_interrupt() {
                            let control = pending_control.take().unwrap();
                            let _ = control.response.send(Err(error));
                        } else if let Some(control) = &mut pending_control {
                            control.escalated = true;
                        }
                    }
                    let control_timed_out = pending_control
                        .as_ref()
                        .is_some_and(|control| control.deadline <= now);
                    if control_timed_out {
                        let control = pending_control.take().unwrap();
                        self.timed_out_tokens.insert(control.token);
                        self.apply_event(DomainEvent::CommandOutcomeUnknown {
                            token: control.token,
                        })?;
                        self.metrics.command(
                            control.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                            true,
                        );
                        let _ = control.response.send(Err(command_timeout(control.token)));
                    }
                    if normal_result.is_none() && deadline <= now {
                        self.timed_out_tokens.insert(token);
                        self.apply_event(DomainEvent::CommandOutcomeUnknown { token })?;
                        self.metrics.command(
                            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                            true,
                        );
                        normal_result = Some(Err(command_timeout(token)));
                    }
                }
                ExecutionInput::Backend(None) => {
                    return Err(Error::new(ErrorCode::GdbExited, "GDB input channel closed"));
                }
                ExecutionInput::Backend(Some(input)) => {
                    let Some((record, evidence_seq)) = self.process_input(input)? else {
                        continue;
                    };
                    if let Some(delayed) = take_delayed_token(&mut self.timed_out_tokens, &record) {
                        self.apply_event(DomainEvent::CommandOutcomeResolved { token: delayed })?;
                    }
                    let result_token = match &record {
                        MiRecord::Result {
                            token: Some(result_token),
                            ..
                        } => Some(*result_token),
                        _ => None,
                    };
                    if pending_control
                        .as_ref()
                        .is_some_and(|control| Some(control.token) == result_token)
                    {
                        let control = pending_control.take().unwrap();
                        self.metrics.command(
                            control.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                            false,
                        );
                        let _ = control.response.send(command_reply(
                            control.token,
                            record,
                            evidence_seq,
                            Vec::new(),
                            false,
                        ));
                        continue;
                    }
                    if Some(token) == result_token {
                        self.metrics.command(
                            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
                            false,
                        );
                        normal_result = Some(command_reply(
                            token,
                            record,
                            evidence_seq,
                            std::mem::take(&mut streams),
                            stream_truncated,
                        ));
                        continue;
                    }
                    if normal_result.is_none()
                        && matches!(
                            record,
                            MiRecord::ConsoleStream(_)
                                | MiRecord::TargetStream(_)
                                | MiRecord::LogStream(_)
                        )
                    {
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
        }
    }

    async fn begin_command(&mut self, command: &MiCommand) -> Result<u64> {
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::Internal, "MI token counter exhausted"))?;
        let raw = command.encoded(token);
        let appended = self.journal.append_mi_input(token, &raw);
        self.journal_result(appended)?;
        self.backend.send(token, command).await?;
        Ok(token)
    }

    fn process_input(&mut self, input: BackendInput) -> Result<Option<(MiRecord, u64)>> {
        match input {
            BackendInput::Mi { raw, record } => {
                self.metrics.mi_record();
                let appended = self.journal.append_mi_output(&raw);
                let evidence_seq = self.journal_result(appended)?;
                if let Some(event) = normalize(&record) {
                    // 2026-08-28: Normal MI stream records were returned only
                    // with the in-flight command and never reached incremental
                    // output readers. Route each source before state reduction.
                    if let DomainEvent::Output { source, bytes } = &event {
                        match source {
                            OutputSource::GdbConsoleStream => {
                                self.console_output.append(bytes);
                            }
                            OutputSource::MiTargetStream => {
                                self.target_output.append(bytes);
                            }
                            OutputSource::GdbLogStream => {
                                self.log_output.append(bytes);
                            }
                            OutputSource::InferiorPty | OutputSource::ServerDiagnostic => {}
                        }
                    }
                    if matches!(
                        event,
                        DomainEvent::UnknownBackendEvent { .. }
                            | DomainEvent::UnknownBackendNotification { .. }
                    ) {
                        self.metrics.mi_unknown_class();
                    }
                    if matches!(event, DomainEvent::TargetStopped { .. }) {
                        self.metrics.target_stop();
                    }
                    self.apply_event(event)?;
                }
                Ok(Some((record, evidence_seq)))
            }
            BackendInput::GdbStderr(bytes) => {
                let appended = self.journal.append_gdb_stderr(&bytes);
                self.journal_result(appended)?;
                self.log_output.append(&bytes);
                Ok(None)
            }
            BackendInput::InferiorPty {
                offset,
                length,
                dropped_bytes,
            } => {
                let appended = self
                    .journal
                    .append_inferior_output(offset, length, dropped_bytes);
                self.journal_result(appended)?;
                self.metrics.inferior_output_dropped(
                    dropped_bytes.saturating_sub(self.inferior_output_dropped),
                );
                self.inferior_output_dropped = dropped_bytes;
                self.apply_event(DomainEvent::OutputAdvanced {
                    source: OutputSource::InferiorPty,
                    offset,
                    length,
                    dropped_bytes,
                })?;
                Ok(None)
            }
            BackendInput::ProtocolError(error) => {
                self.metrics.mi_parse_error();
                self.metrics.consistency_lost();
                // 2026-08-28: Continuing after the MI reader lost framing left
                // an unreachable GDB alive and made every later command time out.
                self.fatal = true;
                let lost = self.apply_event(DomainEvent::ConsistencyLost {
                    reason: error.to_string(),
                });
                let exited = self.apply_event(DomainEvent::BackendExited { status: None });
                self.mark_failed();
                lost?;
                exited?;
                Err(error)
            }
            BackendInput::GdbEof => {
                let status = self.backend.try_wait()?.and_then(|status| status.code());
                self.fatal = true;
                let exited = self.apply_event(DomainEvent::BackendExited { status });
                self.mark_failed();
                exited?;
                Err(Error::new(ErrorCode::GdbExited, "GDB stdout closed"))
            }
            BackendInput::PtyEof => Ok(None),
        }
    }

    fn apply_event(&mut self, event: DomainEvent) -> Result<()> {
        let stopped = matches!(&event, DomainEvent::TargetStopped { .. });
        if matches!(&event, DomainEvent::TargetRunning { .. }) {
            self.inferior_output.reset();
        }
        let invalidates_values = matches!(
            &event,
            DomainEvent::TargetRunning { .. }
                | DomainEvent::InferiorExited { .. }
                | DomainEvent::TargetDisconnected
                | DomainEvent::TargetDetached
        );
        let appended = self.journal.append_domain(event.clone());
        let journaled: JournaledEvent = self.journal_result(appended)?;
        let changed = self.reducer.apply(&journaled)?;
        match &event {
            DomainEvent::CoreOpened { .. } => {
                self.set_capability("execution", CapabilityStatus::Unsupported);
                self.set_capability("target_mutation", CapabilityStatus::Unsupported);
                self.set_capability("memory_write", CapabilityStatus::Unsupported);
            }
            DomainEvent::TargetRunning { .. } | DomainEvent::TargetStopped { .. } => {
                self.set_capability(
                    "execution",
                    if matches!(
                        self.profile,
                        Profile::DebugControl | Profile::LabMutation | Profile::RawAdmin
                    ) {
                        CapabilityStatus::Conditional
                    } else {
                        CapabilityStatus::Unsupported
                    },
                );
            }
            DomainEvent::TargetDetached | DomainEvent::TargetDisconnected => {
                self.set_capability("execution", CapabilityStatus::TemporarilyUnavailable);
            }
            _ => {}
        }
        if invalidates_values {
            // 2026-08-28: Clearing public bindings alone leaked MI variable
            // objects across stops. Delete them at the next stopped command,
            // when GDB permits var-object cleanup.
            self.stale_backend_values.extend(
                std::mem::take(&mut self.values)
                    .into_values()
                    .map(|binding| binding.backend_name),
            );
        }
        // 2026-08-28: Even non-revision events advance public event_seq. The
        // watch state must publish every journaled event or waits see stale evidence.
        if changed {
            // 2026-08-28: State revisions were persisted to SQLite but absent
            // from the append-only replay evidence.
            let appended = self.journal.append_state(
                self.reducer.state().revision,
                &serde_json::to_value(self.reducer.state())?,
            );
            self.journal_result(appended)?;
            self.persist()?;
        }
        self.state_sender.send_replace(self.reducer.state().clone());
        let _ = self.events.send(PublishedEvent {
            event_seq: journaled.seq(),
            revision: self.reducer.state().revision,
            event,
        });
        if stopped {
            // 2026-08-28: SnapshotReady was published without a stored object.
            // Persist the bounded stop context before advertising readiness.
            let stop_id = self.reducer.state().stop_id.clone().unwrap();
            let snapshot_id = format!("snap_{stop_id}");
            let frame = self
                .reducer
                .state()
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find_map(|thread| thread.frame.clone());
            let snapshot = serde_json::json!({
                "snapshot_id": snapshot_id,
                "stop_id": stop_id,
                "revision": self.reducer.state().revision,
                "profile": "minimal",
                "reason": self.reducer.state().stop_reason,
                "frame": frame,
                "partial": frame.is_none(),
                "warnings": if frame.is_none() {
                    vec![serde_json::json!({
                        "code": "FRAME_UNAVAILABLE",
                        "message": "GDB stop event did not include a frame"
                    })]
                } else {
                    Vec::new()
                },
                "evidence": [{
                    "kind": "mi-event",
                    "uri": format!(
                        "gdbai://session/{}/event/{}",
                        self.reducer.state().session_id,
                        journaled.seq()
                    )
                }]
            });
            if let Err(error) = self.store_snapshot_value(snapshot_id, snapshot) {
                self.apply_event(DomainEvent::SnapshotFailed {
                    stop_id: stop_id.clone(),
                })?;
                return Err(error);
            }
            self.apply_event(DomainEvent::SnapshotReady {
                stop_id,
                partial: frame.is_none(),
            })?;
        }
        Ok(())
    }

    fn store_snapshot_value(&mut self, snapshot_id: String, snapshot: Value) -> Result<()> {
        let appended = self.journal.append_snapshot(&snapshot_id, &snapshot);
        self.journal_result(appended)?;
        self.store
            .upsert_snapshot(&self.reducer.state().session_id, &snapshot_id, &snapshot)?;
        if self.snapshots.len() >= 128 {
            self.snapshots.pop_first();
        }
        self.snapshots.insert(snapshot_id, snapshot);
        Ok(())
    }

    fn journal_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.fatal = true;
            self.mark_failed();
        }
        result
    }

    fn persist(&mut self) -> Result<()> {
        self.store
            .upsert_session(self.reducer.state(), self.profile)
    }

    fn mark_failed(&mut self) {
        if self.metric_active {
            self.metrics.session_failed();
            self.metrics.session_closed();
            self.metric_active = false;
        }
    }
}

async fn wait_for_prompt(
    backend: &mut dyn DebugBackend,
    journal: &mut Journal,
    reducer: &mut StateReducer,
    target_output: &mut ByteRing,
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
                                target_output.append(bytes);
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
            BackendInput::InferiorPty {
                offset,
                length,
                dropped_bytes,
            } => {
                journal.append_inferior_output(offset, length, dropped_bytes)?;
            }
            BackendInput::PtyEof => {}
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

fn command_timeout(token: u64) -> Error {
    Error::new(
        ErrorCode::Timeout,
        // 2026-08-28: A timeout does not prove that GDB ignored the command or
        // that target state remained unchanged.
        format!("MI token {token} timed out; command completion is unknown"),
    )
    .retryable()
}

fn command_reply(
    token: u64,
    record: MiRecord,
    evidence_seq: u64,
    stream_records: Vec<MiRecord>,
    stream_truncated: bool,
) -> Result<CommandReply> {
    let MiRecord::Result {
        token: Some(result_token),
        class,
        results,
    } = &record
    else {
        return Err(Error::new(
            ErrorCode::Internal,
            "matched MI command record is not a result",
        ));
    };
    if *result_token != token {
        return Err(Error::new(
            ErrorCode::Internal,
            "matched MI command token changed",
        ));
    }
    if class == "error" {
        let message = MiResult::find_str(results, "msg")
            .unwrap_or("GDB command failed")
            .to_owned();
        return Err(
            Error::new(ErrorCode::GdbError, message).with_details(serde_json::json!({
                "token": token,
                "record": record,
                "evidence_seq": evidence_seq
            })),
        );
    }
    let class = class.clone();
    Ok(CommandReply {
        token,
        class,
        record,
        stream_records,
        stream_truncated,
        evidence_seq,
    })
}

// 2026-08-28: Delayed results were detected only while the worker was idle;
// another command could consume them without scheduling reconciliation.
fn take_delayed_token(timed_out: &mut HashSet<u64>, record: &MiRecord) -> Option<u64> {
    let token = match record {
        MiRecord::Result {
            token: Some(token), ..
        } => *token,
        _ => return None,
    };
    timed_out.remove(&token).then_some(token)
}

fn tracking_change(before: &Value, after: &Value) -> Value {
    let decoded = |value: &Value| {
        value
            .get("data_base64")
            .and_then(Value::as_str)
            .and_then(|encoded| BASE64.decode(encoded).ok())
    };
    let (Some(before_bytes), Some(after_bytes)) = (decoded(before), decoded(after)) else {
        return serde_json::json!({ "before": before, "after": after });
    };
    let mut ranges = Vec::new();
    let mut offset = 0usize;
    let mut emitted = 0usize;
    let mut truncated = false;
    let maximum = before_bytes.len().max(after_bytes.len());
    // 2026-08-28: One fully changed tracked range embedded both complete
    // buffers in a diff. Bound raw range evidence independently of history.
    while offset < maximum && ranges.len() < 128 && emitted < 4 * 1024 {
        if before_bytes.get(offset) == after_bytes.get(offset) {
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < maximum && before_bytes.get(offset) != after_bytes.get(offset) {
            offset += 1;
        }
        let visible_end = offset.min(start + (4 * 1024 - emitted));
        ranges.push(serde_json::json!({
            "offset": start,
            "before_base64": BASE64.encode(&before_bytes[start.min(before_bytes.len())..visible_end.min(before_bytes.len())]),
            "after_base64": BASE64.encode(&after_bytes[start.min(after_bytes.len())..visible_end.min(after_bytes.len())])
        }));
        emitted += visible_end - start;
        if visible_end < offset {
            truncated = true;
            break;
        }
    }
    serde_json::json!({
        "before_sha256": before.get("sha256"),
        "after_sha256": after.get("sha256"),
        "changed_ranges": ranges,
        "truncated": truncated || offset < maximum
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::config::{ArtifactConfig, PersistenceConfig};

    async fn control_test_session() -> Option<SessionHandle> {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
            return None;
        }
        let directory = tempdir().unwrap();
        let path = directory.keep();
        let config = Config {
            artifacts: ArtifactConfig {
                path: path.join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: path.join("state.sqlite"),
                sessions: path.join("sessions"),
            },
            ..Config::default()
        };
        let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
        Some(
            SessionHandle::start(
                Arc::new(config),
                Profile::RawAdmin,
                store,
                Arc::new(Metrics::default()),
            )
            .await
            .unwrap(),
        )
    }

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

        let delayed = gdb_ai_mi::parse_record(b"7^done", MiLimits::default()).unwrap();
        let mut timed_out = HashSet::from([7]);
        assert_eq!(take_delayed_token(&mut timed_out, &delayed), Some(7));
        assert!(timed_out.is_empty());
    }

    #[test]
    fn reports_bounded_tracked_memory_ranges() {
        let before = serde_json::json!({
            "sha256": "before",
            "data_base64": BASE64.encode([0, 0, 0, 0, 9])
        });
        let after = serde_json::json!({
            "sha256": "after",
            "data_base64": BASE64.encode([0, 1, 2, 0, 9])
        });
        let change = tracking_change(&before, &after);
        assert_eq!(change["changed_ranges"][0]["offset"], 1);
        assert_eq!(change["changed_ranges"].as_array().unwrap().len(), 1);

        let large = tracking_change(
            &serde_json::json!({"data_base64": BASE64.encode(vec![0; 8192])}),
            &serde_json::json!({"data_base64": BASE64.encode(vec![1; 8192])}),
        );
        assert_eq!(large["truncated"], true);
        assert_eq!(
            BASE64
                .decode(large["changed_ranges"][0]["after_base64"].as_str().unwrap())
                .unwrap()
                .len(),
            4096
        );
    }

    #[test]
    fn exit_wait_ignores_an_already_terminal_inferior() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_wait".into())));
        for (seq, event) in [
            (1, DomainEvent::BackendStarted),
            (
                2,
                DomainEvent::InferiorAdded {
                    backend_id: "i1".into(),
                    pid: Some(1),
                },
            ),
            (
                3,
                DomainEvent::InferiorExited {
                    backend_id: "i1".into(),
                    exit_code: Some("0".into()),
                },
            ),
        ] {
            reducer
                .apply(&JournaledEvent::for_replay(seq, event))
                .unwrap();
        }
        let baseline = WaitBaseline::from(reducer.state());
        reducer
            .apply(&JournaledEvent::for_replay(
                4,
                DomainEvent::InferiorAdded {
                    backend_id: "i2".into(),
                    pid: Some(2),
                },
            ))
            .unwrap();
        assert!(!wait_satisfied(
            reducer.state(),
            WaitUntil::Exited,
            Some(&baseline)
        ));
        reducer
            .apply(&JournaledEvent::for_replay(
                5,
                DomainEvent::InferiorExited {
                    backend_id: "i2".into(),
                    exit_code: Some("0".into()),
                },
            ))
            .unwrap();
        assert!(wait_satisfied(
            reducer.state(),
            WaitUntil::Exited,
            Some(&baseline)
        ));
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
        let session = SessionHandle::start(
            Arc::new(config),
            Profile::DebugControl,
            store,
            Arc::new(Metrics::default()),
        )
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

    #[tokio::test]
    async fn timeout_fences_late_result() {
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
        let session = SessionHandle::start(
            Arc::new(config),
            Profile::RawAdmin,
            store,
            Arc::new(Metrics::default()),
        )
        .await
        .unwrap();
        let slow = MiCommand::new("-interpreter-exec")
            .unwrap()
            .bare("console")
            .unwrap()
            .string("shell sleep 0.5");
        let timeout = session
            .command_with_timeout(slow, Duration::from_millis(10))
            .await
            .unwrap_err();
        assert_eq!(timeout.code, ErrorCode::Timeout);
        assert!(!session.state().outcome_unknown_tokens.is_empty());

        let fenced = session
            .command(MiCommand::new("-gdb-version").unwrap())
            .await
            .unwrap_err();
        assert_eq!(fenced.code, ErrorCode::GdbUnresponsive);

        tokio::time::timeout(Duration::from_secs(2), async {
            while !session.state().outcome_unknown_tokens.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(session.state().reconciliation_required);
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn queue_wait_counts_toward_command_deadline() {
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
        let session = SessionHandle::start(
            Arc::new(config),
            Profile::RawAdmin,
            store,
            Arc::new(Metrics::default()),
        )
        .await
        .unwrap();
        let slow_session = session.clone();
        let slow = tokio::spawn(async move {
            slow_session
                .command_with_timeout(
                    MiCommand::new("-interpreter-exec")
                        .unwrap()
                        .bare("console")
                        .unwrap()
                        .string("shell sleep 0.3"),
                    Duration::from_secs(1),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let expired = session
            .command_with_timeout(
                MiCommand::new("-gdb-version").unwrap(),
                Duration::from_millis(20),
            )
            .await
            .unwrap_err();
        assert_eq!(expired.code, ErrorCode::Timeout);
        assert!(session.state().outcome_unknown_tokens.is_empty());
        slow.await.unwrap().unwrap();
        session
            .command(MiCommand::new("-gdb-version").unwrap())
            .await
            .unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn stable_observation_serializes_ordinary_commands() {
        let Some(session) = control_test_session().await else {
            return;
        };
        let expected = session.state();
        let observing_session = session.clone();
        let (entered_sender, entered) = oneshot::channel();
        let (release_sender, release) = oneshot::channel();
        let observation = tokio::spawn(async move {
            observing_session
                .stable_observation(
                    &expected,
                    Box::pin(async {
                        observing_session
                            .command(MiCommand::new("-gdb-version").unwrap())
                            .await?;
                        let _ = entered_sender.send(());
                        let _ = release.await;
                        Ok(())
                    }),
                )
                .await
        });
        entered.await.unwrap();

        let competing_session = session.clone();
        let competing = tokio::spawn(async move {
            competing_session
                .command(MiCommand::new("-gdb-version").unwrap())
                .await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!competing.is_finished());

        release_sender.send(()).unwrap();
        observation.await.unwrap().unwrap();
        competing.await.unwrap().unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn stale_snapshot_commit_leaves_no_snapshot() {
        let Some(session) = control_test_session().await else {
            return;
        };
        let error = session
            .commit_snapshot(
                "snap_invalid".into(),
                serde_json::json!({"snapshot_id": "snap_invalid"}),
                StopId("stop_missing".into()),
                session.state().execution_epoch,
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::StaleContext);
        assert_eq!(
            session
                .snapshot("snap_invalid".into())
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn stable_observation_rejects_a_preempting_state_change() {
        let Some(session) = control_test_session().await else {
            return;
        };
        let expected = session.state();
        let observing_session = session.clone();
        let (entered_sender, entered) = oneshot::channel();
        let (release_sender, release) = oneshot::channel();
        let observation = tokio::spawn(async move {
            observing_session
                .stable_observation(
                    &expected,
                    Box::pin(async {
                        let _ = entered_sender.send(());
                        let _ = release.await;
                        Ok(())
                    }),
                )
                .await
        });
        entered.await.unwrap();
        session
            .record_event(DomainEvent::TargetRunning {
                backend_inferiors: vec![],
            })
            .await
            .unwrap();
        release_sender.send(()).unwrap();

        assert_eq!(
            observation.await.unwrap().unwrap_err().code,
            ErrorCode::StaleContext
        );
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn interrupt_preempts_blocked_command() {
        let Some(session) = control_test_session().await else {
            return;
        };
        let slow_session = session.clone();
        let slow = tokio::spawn(async move {
            slow_session
                .command_with_timeout(
                    MiCommand::new("-interpreter-exec")
                        .unwrap()
                        .bare("console")
                        .unwrap()
                        .string("shell sleep 5"),
                    Duration::from_secs(10),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        let interrupt = session
            .interrupt(MiCommand::new("-exec-interrupt").unwrap())
            .await;
        assert!(started.elapsed() < Duration::from_secs(2));
        if let Err(error) = interrupt {
            assert_eq!(error.code, ErrorCode::GdbError);
        }
        tokio::time::timeout(Duration::from_secs(2), slow)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn close_preempts_blocked_command() {
        let Some(session) = control_test_session().await else {
            return;
        };
        let slow_session = session.clone();
        let slow = tokio::spawn(async move {
            slow_session
                .command_with_timeout(
                    MiCommand::new("-interpreter-exec")
                        .unwrap()
                        .bare("console")
                        .unwrap()
                        .string("shell sleep 10"),
                    Duration::from_secs(20),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        session.close().await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(
            session.state().lifecycle,
            crate::domain::SessionLifecycle::Closed
        );
        let error = tokio::time::timeout(Duration::from_secs(1), slow)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::GdbExited);
    }

    #[tokio::test]
    async fn loads_hash_pinned_python_extension() {
        if std::process::Command::new("gdb")
            .arg("--configuration")
            .output()
            .ok()
            .is_none_or(|output| !String::from_utf8_lossy(&output.stdout).contains("--with-python"))
        {
            return;
        }
        let directory = tempdir().unwrap();
        let extension = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../gdb-extension/gdb_ai.py")
            .canonicalize()
            .unwrap();
        let digest = format!("{:x}", Sha256::digest(std::fs::read(&extension).unwrap()));
        let mut config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        config.gdb.python_extension = Some(extension);
        config.gdb.python_extension_sha256 = Some(digest);
        let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
        let session = SessionHandle::start(
            Arc::new(config),
            Profile::DebugControl,
            store,
            Arc::new(Metrics::default()),
        )
        .await
        .unwrap();
        assert!(session.capabilities().supports("custom_extension"));
        session.close().await.unwrap();
    }

    #[tokio::test]
    async fn starts_compatible_mi3_backend() {
        if std::process::Command::new("gdb")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let directory = tempdir().unwrap();
        let mut config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        config.gdb.preferred_mi = "mi99".into();
        config.gdb.fallback_mi = "mi3".into();
        let store = Arc::new(Store::open(&config.persistence.sqlite).unwrap());
        let session = SessionHandle::start(
            Arc::new(config),
            Profile::DebugControl,
            store,
            Arc::new(Metrics::default()),
        )
        .await
        .unwrap();
        assert_eq!(session.capabilities().backend.mi_version, "mi3");
        session.close().await.unwrap();
    }
}

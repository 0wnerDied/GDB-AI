use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use gdb_ai_mi::MiRecord;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, OnceCell, broadcast, mpsc, oneshot, watch};

mod actor;
mod state;

use actor::{ControlRequest, SessionWorker, WorkerRequest};

use crate::{
    Error, ErrorCode, Result,
    backend::{BackendDescriptor, MiCommand, OutputEvidenceStatus, PtyOutput, session_directory},
    config::Config,
    domain::{
        BreakpointId, DomainEvent, InferiorStatus, OperationId, OperationRecord, SessionId,
        SessionState, SnapshotStatus, StopId, TrackingDefinition, ValueBinding, WaitBaseline,
    },
    journal::Journal,
    metrics::Metrics,
    persistence::Store,
    policy::Profile,
    protocol::ObservationContext,
    ring::RingRead,
};

tokio::task_local! {
    static ACTIVE_OBSERVATION: ObservationScope;
    static ACTIVE_OPERATION: ActiveOperation;
}

#[derive(Clone)]
struct ObservationScope {
    session_id: String,
    register_names: Arc<OnceCell<CommandReply>>,
    contexts: Arc<StdRwLock<BTreeMap<ContextKey, CommandContext>>>,
}

#[derive(Clone)]
pub(crate) struct CommandContext {
    pub backend_thread: Option<String>,
    pub default_thread: Option<String>,
    pub frame_level: Option<u64>,
    pub observation: Option<ObservationContext>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ContextKey {
    revision: u64,
    stop_id: Option<StopId>,
    epoch: u64,
    selectors: [Option<String>; 3],
    frame_level: Option<u64>,
}

pub(crate) fn cached_command_context(
    state: &SessionState,
    parameters: &Value,
    resolve: impl FnOnce() -> Result<CommandContext>,
) -> Result<CommandContext> {
    let scope = ACTIVE_OBSERVATION
        .try_with(|scope| (scope.session_id == state.session_id.0).then(|| scope.contexts.clone()))
        .ok()
        .flatten();
    let Some(scope) = scope else {
        return resolve();
    };
    let key = ContextKey {
        revision: state.revision,
        stop_id: state.stop_id.clone(),
        epoch: state.execution_epoch,
        selectors: ["inferior_id", "thread_id", "frame_id"].map(|field| {
            parameters
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_owned)
        }),
        frame_level: parameters.get("frame_level").and_then(Value::as_u64),
    };
    // 2026-09-08: Every view rescanned thread/frame handles at the same
    // fence. Reuse only successful selection resolution in this task's
    // bounded observation scope, never across state changes or sessions.
    let mut contexts = scope
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(context) = contexts.get(&key) {
        return Ok(context.clone());
    }
    let context = resolve()?;
    if contexts.len() < 16 {
        contexts.insert(key, context.clone());
    }
    Ok(context)
}

#[derive(Clone)]
pub(crate) struct ActiveOperation {
    id: OperationId,
    cancelled: Arc<AtomicBool>,
}

impl ActiveOperation {
    pub(crate) fn new(id: OperationId, cancelled: Arc<AtomicBool>) -> Self {
        Self { id, cancelled }
    }

    pub(super) fn id(&self) -> &OperationId {
        &self.id
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn require_active(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::new(ErrorCode::Cancelled, "operation was cancelled"))
        } else {
            Ok(())
        }
    }
}

pub(crate) async fn scope_operation<T>(
    operation: ActiveOperation,
    future: impl Future<Output = T>,
) -> T {
    ACTIVE_OPERATION.scope(operation, future).await
}

pub(crate) fn active_operation() -> Option<ActiveOperation> {
    ACTIVE_OPERATION.try_with(Clone::clone).ok()
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
        // 2026-08-28: Treating conditional capabilities as unconditionally
        // supported discarded target constraints at every boolean call site.
        self.status(name) == Some(CapabilityStatus::Supported)
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

#[derive(Clone)]
pub(crate) struct PendingModuleBreakpoint {
    pub id: BreakpointId,
    pub backend_number: String,
    pub module: String,
    pub offset: u64,
    pub enabled: bool,
    pub command: MiCommand,
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
    Settled,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationCancelMode {
    InterruptTarget,
    CloseSession,
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
    snapshots: Arc<StdRwLock<VecDeque<(String, Value)>>>,
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
        let mut journal = Journal::create_with_durability(
            &journal_path,
            config.limits.journal_bytes,
            config.journal.durability,
        )?;
        journal.append_session_created(&id.0)?;
        let initial_state = SessionState::creating(id.clone());
        let (state_sender, state) = watch::channel(initial_state);
        let (events, _) = broadcast::channel(512);
        let (requests, receiver) = mpsc::channel(128);
        let snapshots = Arc::new(StdRwLock::new(VecDeque::new()));
        // 2026-08-28: Interrupt and close previously waited behind the command
        // they needed to preempt. Keep a dedicated bounded control lane.
        let (controls, control_receiver) = mpsc::channel(16);

        // 2026-08-29: Bootstrap, handshake, MI journaling, and the caller's
        // Gateway future shared one poll stack. A normal session create could
        // exhaust Tokio's 2 MiB worker stack as the request surface grew.
        let mut worker = tokio::spawn(SessionWorker::bootstrap(
            config.clone(),
            profile,
            store,
            metrics.clone(),
            session_dir.clone(),
            journal,
            state_sender,
            events.clone(),
            snapshots.clone(),
            receiver,
            control_receiver,
        ))
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("bootstrap task failed: {error}"),
            )
        })??;
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
            snapshots,
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

    // 2026-08-30: Reading one coordination scalar used to clone growing
    // breakpoint, thread, module, and signal registries. Keep the watch borrow
    // inside a synchronous closure so callers cannot hold it across an await.
    pub(crate) fn with_state<T>(&self, inspect: impl FnOnce(&SessionState) -> T) -> T {
        let state = self.state.borrow();
        inspect(&state)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PublishedEvent> {
        self.events.subscribe()
    }

    pub fn journal_path(&self) -> &PathBuf {
        &self.journal_path
    }

    pub fn inferior_output_evidence(&self) -> OutputEvidenceStatus {
        self.inferior_output.evidence_status()
    }

    pub(crate) fn inferior_output_position(&self) -> u64 {
        self.inferior_output.position().0
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
        let _sequence = self.command_sequence_until(deadline).await?;
        self.send_command(command, deadline).await
    }

    async fn send_command(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let operation = active_operation();
        if let Some(operation) = &operation {
            operation.require_active()?;
        }
        self.enqueue_command(command, deadline, operation).await
    }

    pub(crate) async fn cleanup_command(&self, command: MiCommand) -> Result<CommandReply> {
        let deadline = command_deadline(self.command_timeout);
        let _sequence = if self.observation_active() {
            None
        } else {
            Some(self.command_sequence_until(deadline).await?)
        };
        // 2026-08-30: A cancelled operation rejected its own compensating GDB
        // command, leaving cleanup to race later requests in a detached task.
        self.enqueue_command(command, deadline, None).await
    }

    async fn enqueue_command(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
        operation: Option<ActiveOperation>,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.enqueue_until(
            WorkerRequest::Command {
                command,
                operation,
                deadline,
                response: sender,
            },
            deadline,
        )
        .await?;
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
        let _sequence = self.command_sequence_until(deadline).await?;
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
        let operation = active_operation();
        if let Some(operation) = &operation {
            operation.require_active()?;
        }
        let (sender, receiver) = oneshot::channel();
        self.enqueue_until(
            WorkerRequest::Transaction {
                before,
                command,
                after,
                operation,
                deadline,
                response: sender,
            },
            deadline,
        )
        .await?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn safe_evaluate(&self, command: MiCommand) -> Result<CommandReply> {
        let deadline = command_deadline(self.command_timeout);
        if self.observation_active() {
            return self.send_safe_evaluate(command, deadline).await;
        }
        let _sequence = self.command_sequence_until(deadline).await?;
        self.send_safe_evaluate(command, deadline).await
    }

    pub(crate) async fn register_names(&self) -> Result<CommandReply> {
        self.require_active_operation()?;
        let Some(scope) = self.observation_scope() else {
            return self
                .command(MiCommand::new("-data-list-register-names")?)
                .await;
        };
        // 2026-09-08: Turn views independently queried invariant register
        // metadata, multiplying MI traffic. Reuse it only inside this fenced
        // stop/epoch observation; live values and later turns remain uncached.
        let reply = scope
            .register_names
            .get_or_try_init(|| async {
                self.send_command(
                    MiCommand::new("-data-list-register-names")?,
                    command_deadline(self.command_timeout),
                )
                .await
            })
            .await?;
        Ok(reply.clone())
    }

    pub(crate) fn require_active_operation(&self) -> Result<()> {
        // 2026-09-08: Cached observation results skipped the cancellation
        // check normally enforced before enqueueing MI. A cancelled turn must
        // stop even when its next result needs no backend command.
        if let Some(operation) = active_operation() {
            operation.require_active()?;
        }
        Ok(())
    }

    async fn send_safe_evaluate(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        // 2026-08-30: Command-producing observation helpers previously lost
        // their canonical operation while queued behind another MI command.
        let operation = active_operation();
        if let Some(operation) = &operation {
            operation.require_active()?;
        }
        let (sender, receiver) = oneshot::channel();
        self.enqueue_until(
            WorkerRequest::SafeEvaluate {
                command,
                operation,
                deadline,
                response: sender,
            },
            deadline,
        )
        .await?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    async fn command_sequence_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>> {
        // 2026-08-30: Expired commands were rejected inside the actor, but a
        // caller could first wait behind a long composite operation past its
        // own deadline. Bound admission to the shared command sequence.
        tokio::time::timeout_at(deadline, self.command_sequence.lock())
            .await
            .map_err(|_| command_queue_timeout())
    }

    async fn enqueue_until(
        &self,
        request: WorkerRequest,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        tokio::time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| command_queue_timeout())?
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))
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
        // 2026-08-30: Waiting for that sequence was unbounded even though each
        // contained command had a deadline. Bound composite admission too.
        // ponytail: Keep composite builders in this task; use actor transaction
        // IDs before allowing them to spawn command-producing subtasks.
        let deadline = command_deadline(self.command_timeout);
        let _sequence = self.command_sequence_until(deadline).await?;
        self.require_observation_context(expected)?;
        ACTIVE_OBSERVATION
            .scope(
                ObservationScope {
                    session_id: self.id.0.clone(),
                    register_names: Arc::new(OnceCell::new()),
                    contexts: Arc::new(StdRwLock::new(BTreeMap::new())),
                },
                async {
                    let result = operation.await?;
                    self.require_observation_context(expected)?;
                    Ok(result)
                },
            )
            .await
    }

    fn observation_active(&self) -> bool {
        self.observation_scope().is_some()
    }

    fn observation_scope(&self) -> Option<ObservationScope> {
        ACTIVE_OBSERVATION
            .try_with(|scope| (scope.session_id == self.id.0).then(|| scope.clone()))
            .ok()
            .flatten()
    }

    fn require_observation_context(&self, expected: &SessionState) -> Result<()> {
        let matches = self.with_state(|current| {
            current.stop_id == expected.stop_id
                && current.execution_epoch == expected.execution_epoch
        });
        if matches {
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

    pub(crate) async fn register_pending_module_breakpoint(
        &self,
        breakpoint: PendingModuleBreakpoint,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RegisterPendingModuleBreakpoint {
                breakpoint,
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
        self.controls
            .send(ControlRequest::RecordApi {
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
        let deadline = command_deadline(self.command_timeout);
        if self.observation_active() {
            return self.send_refresh_target_capabilities(deadline).await;
        }
        let _sequence = self.command_sequence_until(deadline).await?;
        self.send_refresh_target_capabilities(deadline).await
    }

    async fn send_refresh_target_capabilities(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SessionCapabilities> {
        // 2026-08-30: Preserve cancellation at both admission and actor
        // execution so a cancelled probe cannot continue refreshing GDB.
        let operation = active_operation();
        if let Some(operation) = &operation {
            operation.require_active()?;
        }
        let (sender, receiver) = oneshot::channel();
        // 2026-08-30: Refresh requests previously waited without a deadline
        // and restarted their timeout in the actor. Expired work could still
        // reach GDB after queue congestion.
        self.enqueue_until(
            WorkerRequest::RefreshTargetCapabilities {
                operation,
                deadline,
                response: sender,
            },
            deadline,
        )
        .await?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub(crate) async fn record_operation(&self, operation: &OperationRecord) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.controls
            .send(ControlRequest::RecordOperation {
                operation: operation.clone(),
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub(crate) async fn operation(&self, operation_id: &str) -> Result<OperationRecord> {
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::GetOperation {
                operation_id: operation_id.into(),
                response: sender,
            })
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
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
    ) -> Result<BTreeMap<String, Value>> {
        self.require_active_operation()?;
        if !self.with_state(|state| {
            state.stop_id.as_ref() == Some(&expected_stop_id)
                && state.execution_epoch == expected_execution_epoch
        }) {
            return Err(Error::new(
                ErrorCode::StaleContext,
                "target stop changed before tracking commit",
            ));
        }
        let operation = active_operation();
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::RecordTracking {
                observations,
                expected_stop_id,
                expected_execution_epoch,
                operation,
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
        snapshot: Value,
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
        partial: bool,
    ) -> Result<Value> {
        self.commit_observation_inner(
            snapshot,
            expected_stop_id,
            expected_execution_epoch,
            partial,
            true,
        )
        .await
    }

    pub async fn commit_observation(
        &self,
        observation: Value,
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
        partial: bool,
    ) -> Result<Value> {
        self.commit_observation_inner(
            observation,
            expected_stop_id,
            expected_execution_epoch,
            partial,
            false,
        )
        .await
    }

    async fn commit_observation_inner(
        &self,
        snapshot: Value,
        expected_stop_id: StopId,
        expected_execution_epoch: u64,
        partial: bool,
        publish_snapshot: bool,
    ) -> Result<Value> {
        self.require_active_operation()?;
        let operation = active_operation();
        let (sender, receiver) = oneshot::channel();
        self.requests
            .send(WorkerRequest::CommitSnapshot {
                snapshot,
                expected_stop_id,
                expected_execution_epoch,
                partial,
                publish_snapshot,
                operation,
                response: sender,
            })
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn snapshot(&self, snapshot_id: String) -> Result<Value> {
        self.snapshot_cached(&snapshot_id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot not found"))
    }

    pub(crate) fn snapshot_cached(&self, snapshot_id: &str) -> Option<Value> {
        // 2026-09-08: Immutable snapshots were readable only through the actor
        // queue, and a store-only fast path lost performance-mode observations
        // after SQLite failed. Share the actor's one bounded in-memory history.
        self.snapshots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .find(|(id, _)| id == snapshot_id)
            .map(|(_, snapshot)| snapshot.clone())
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
                {
                    let current = state.borrow();
                    if inspect_wait_state(
                        &current,
                        until,
                        baseline.as_ref(),
                        expected_execution_epoch,
                    )? {
                        return Ok(current.clone());
                    }
                }
                state.changed().await.map_err(|_| {
                    Error::new(ErrorCode::GdbExited, "session state channel closed")
                })?;
            }
        };
        match tokio::time::timeout(timeout.max(Duration::from_millis(1)), wait).await {
            Ok(result) => result,
            // 2026-09-04: A stop and the timer can become ready in the same
            // scheduler turn. Recheck the published state before reporting a
            // timeout so an already-ready snapshot is never hidden from Agents.
            Err(_) => {
                let current = state.borrow();
                wait_timeout_result(&current, until, baseline.as_ref(), expected_execution_epoch)
            }
        }
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
            if self.with_state(|state| {
                state
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Exited)
            }) {
                self.inferior_output.drain(Duration::from_secs(1)).await;
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

    pub async fn write_inferior(&self, bytes: Vec<u8>, eof: bool) -> Result<usize> {
        self.write_inferior_with_timeout(bytes, eof, self.command_timeout)
            .await
    }

    pub async fn write_inferior_with_timeout(
        &self,
        bytes: Vec<u8>,
        eof: bool,
        timeout: Duration,
    ) -> Result<usize> {
        let total = bytes.len();
        let deadline = command_deadline(timeout);
        let (sender, receiver) = oneshot::channel();
        // 2026-09-01: A PTY request that expired in the actor queue omitted
        // byte progress while an in-flight timeout reported it. Zero accepted
        // bytes is still exact and lets an Agent resume without guessing.
        self.enqueue_until(
            WorkerRequest::WriteInferior {
                bytes,
                eof,
                deadline,
                response: sender,
            },
            deadline,
        )
        .await
        .map_err(|error| input_write_progress(error, total))?;
        let result = receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        result.map_err(|error| input_write_progress(error, total))
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
        let deadline = command_deadline(self.command_timeout);
        let (sender, receiver) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.controls.send(ControlRequest::Interrupt {
                command,
                deadline,
                response: sender,
            }),
        )
        .await
        .map_err(|_| command_queue_timeout())?
        .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?;
        receiver
            .await
            .map_err(|_| Error::new(ErrorCode::GdbExited, "session worker stopped"))?
    }

    pub async fn cancel_operation(
        &self,
        operation_id: OperationId,
        mode: OperationCancelMode,
    ) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.controls
            .send(ControlRequest::CancelOperation {
                operation_id,
                mode,
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
        WaitUntil::Stopped => stopped_after(state, baseline),
        WaitUntil::Settled => settled_by(state, baseline).is_some(),
        WaitUntil::Snapshot => state.snapshot.as_ref().is_some_and(|snapshot| {
            after_baseline
                && snapshot.status == SnapshotStatus::Ready
                && baseline
                    .is_none_or(|baseline| Some(&snapshot.stop_id) != baseline.stop_id.as_ref())
        }),
        WaitUntil::Exited => exited_after(state, baseline),
    }
}

fn wait_timeout_result(
    state: &SessionState,
    until: WaitUntil,
    baseline: Option<&WaitBaseline>,
    expected_execution_epoch: Option<u64>,
) -> Result<SessionState> {
    if expected_execution_epoch.is_none_or(|expected| state.execution_epoch == expected)
        && wait_satisfied(state, until, baseline)
    {
        Ok(state.clone())
    } else {
        Err(Error::new(ErrorCode::Timeout, "state wait timed out").retryable())
    }
}

fn inspect_wait_state(
    state: &SessionState,
    until: WaitUntil,
    baseline: Option<&WaitBaseline>,
    expected_execution_epoch: Option<u64>,
) -> Result<bool> {
    // 2026-08-28: A later execution epoch belongs to another operation and
    // must not satisfy this operation's waiter.
    if expected_execution_epoch.is_some_and(|expected| state.execution_epoch > expected) {
        return Err(Error::new(
            ErrorCode::StaleContext,
            "operation state was superseded by a later execution",
        ));
    }
    let expected_epoch =
        expected_execution_epoch.is_none_or(|expected| state.execution_epoch == expected);
    if expected_epoch && wait_satisfied(state, until, baseline) {
        return Ok(true);
    }
    // 2026-09-01: Report impossible waits immediately, but only after the
    // requested execution epoch starts. A restart first exits the old
    // inferior; that transition cannot fail the new run.
    if expected_epoch
        && !matches!(until, WaitUntil::Settled | WaitUntil::Exited)
        && let Some(inferior) = terminal_after(state, baseline)
    {
        let code = if inferior.status == InferiorStatus::Exited {
            ErrorCode::TargetExited
        } else {
            ErrorCode::TargetDisconnected
        };
        return Err(Error::new(
            code,
            format!("target became {:?} before {until:?}", inferior.status),
        )
        .with_details(serde_json::json!({
            "inferior_id": inferior.id,
            "status": inferior.status,
            "exit_code": inferior.exit_code
        })));
    }
    // 2026-08-28: State waiters kept sleeping after GDB death or an unmatched
    // result made the controller unreliable, turning a known failure into an
    // unrelated timeout.
    if matches!(
        state.lifecycle,
        crate::domain::SessionLifecycle::Closed | crate::domain::SessionLifecycle::Failed
    ) || state.backend == crate::domain::BackendHealth::Dead
    {
        return Err(Error::new(ErrorCode::GdbExited, "GDB session ended"));
    }
    if state.consistency == crate::domain::Consistency::Lost {
        return Err(Error::new(
            ErrorCode::ConsistencyLost,
            "session consistency was lost while waiting",
        ));
    }
    if state.reconciliation_required
        && baseline.is_none_or(|baseline| state.event_seq > baseline.event_seq)
    {
        return Err(Error::new(
            ErrorCode::ConsistencyDirty,
            "session requires reconciliation after an unexpected backend result",
        ));
    }
    Ok(false)
}

fn stopped_after(state: &SessionState, baseline: Option<&WaitBaseline>) -> bool {
    baseline.is_none_or(|baseline| state.event_seq > baseline.event_seq)
        && state.stop_id.is_some()
        && baseline.is_none_or(|baseline| state.stop_id != baseline.stop_id)
        && state
            .inferiors
            .values()
            .any(|inferior| inferior.status == InferiorStatus::Stopped)
}

fn exited_after(state: &SessionState, baseline: Option<&WaitBaseline>) -> bool {
    terminal_after(state, baseline).is_some()
}

fn terminal_after<'a>(
    state: &'a SessionState,
    baseline: Option<&WaitBaseline>,
) -> Option<&'a crate::domain::InferiorState> {
    // 2026-08-28: An inferior that was already terminal at the baseline
    // must not satisfy a new run-and-wait operation for another inferior.
    // 2026-09-05: Backend IDs are reused across launches, so ID-only baselines
    // made a replacement process time out after it had exited. Match generations.
    state
        .inferiors
        .iter()
        .find(|(backend_id, inferior)| {
            terminal(inferior.status)
                && baseline.is_none_or(|baseline| {
                    baseline
                        .terminal_inferior_generations
                        .get(*backend_id)
                        .map_or_else(
                            || !baseline.terminal_inferiors.contains(*backend_id),
                            |generation| *generation != inferior.generation,
                        )
                })
        })
        .map(|(_, inferior)| inferior)
}

pub(crate) fn settled_by(
    state: &SessionState,
    baseline: Option<&WaitBaseline>,
) -> Option<&'static str> {
    // 2026-08-31: A settled response exposed no indication of whether a stop
    // or exit satisfied it, forcing Agents to fetch status after normal exit.
    stopped_after(state, baseline)
        .then_some("stopped")
        .or_else(|| exited_after(state, baseline).then_some("exited"))
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

fn command_queue_timeout() -> Error {
    Error::new(
        ErrorCode::Timeout,
        "MI command deadline expired while queued",
    )
    .retryable()
}

fn input_write_progress(mut error: Error, total: usize) -> Error {
    if error.code == ErrorCode::Timeout && error.details.is_none() {
        error.details = Some(serde_json::json!({"written": 0, "remaining": total}));
    }
    error
}

#[cfg(test)]
mod tests;

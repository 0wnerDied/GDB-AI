use std::{
    collections::{BTreeMap, BTreeSet},
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
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};

mod actor;

use actor::{ControlRequest, SessionWorker, WorkerRequest};

use crate::{
    Error, ErrorCode, Result,
    backend::{BackendDescriptor, MiCommand, OutputEvidenceStatus, PtyOutput, session_directory},
    config::Config,
    domain::{
        BreakpointId, DomainEvent, InferiorStatus, OperationId, SessionId, SessionState,
        SnapshotStatus, StopId, TrackingDefinition, ValueBinding, WaitBaseline,
    },
    journal::Journal,
    metrics::Metrics,
    persistence::Store,
    policy::Profile,
    ring::RingRead,
};

tokio::task_local! {
    static ACTIVE_OBSERVATION_SESSION: String;
    static ACTIVE_OPERATION: ActiveOperation;
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

    fn require_active(&self) -> Result<()> {
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

fn active_operation() -> Option<ActiveOperation> {
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
        let (state_sender, state) = watch::channel(initial_state.clone());
        let (events, _) = broadcast::channel(512);
        let (requests, receiver) = mpsc::channel(128);
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
            initial_state,
            state_sender,
            events.clone(),
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

    pub fn inferior_output_evidence(&self) -> OutputEvidenceStatus {
        self.inferior_output.evidence_status()
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

    async fn send_safe_evaluate(
        &self,
        command: MiCommand,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        let (sender, receiver) = oneshot::channel();
        self.enqueue_until(
            WorkerRequest::SafeEvaluate {
                command,
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
        let deadline = command_deadline(self.command_timeout);
        let _sequence = self.command_sequence_until(deadline).await?;
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
                // 2026-08-28: State waiters kept sleeping after GDB death or
                // an unmatched result made the controller unreliable, turning
                // a known failure into an unrelated timeout.
                if matches!(
                    current.lifecycle,
                    crate::domain::SessionLifecycle::Closed
                        | crate::domain::SessionLifecycle::Failed
                ) || current.backend == crate::domain::BackendHealth::Dead
                {
                    return Err(Error::new(ErrorCode::GdbExited, "GDB session ended"));
                }
                if current.consistency == crate::domain::Consistency::Lost {
                    return Err(Error::new(
                        ErrorCode::ConsistencyLost,
                        "session consistency was lost while waiting",
                    ));
                }
                if current.reconciliation_required
                    && baseline
                        .as_ref()
                        .is_none_or(|baseline| current.event_seq > baseline.event_seq)
                {
                    return Err(Error::new(
                        ErrorCode::ConsistencyDirty,
                        "session requires reconciliation after an unexpected backend result",
                    ));
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

fn command_queue_timeout() -> Error {
    Error::new(
        ErrorCode::Timeout,
        "MI command deadline expired while queued",
    )
    .retryable()
}

#[cfg(test)]
mod tests;

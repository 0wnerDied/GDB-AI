use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiLimits, MiRecord, MiResult, MiValue};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::{
    ActiveOperation, Capability, CapabilityStatus, CommandReply, OperationCancelMode, OutputRing,
    PendingModuleBreakpoint, PublishedEvent, SessionCapabilities, command_deadline,
};
use crate::{
    Error, ErrorCode, Result,
    artifact::ArtifactStore,
    backend::{
        BackendInput, GdbBackend, MiArgument, MiCommand, OutputEvidenceStatus, PtyOutput,
        SandboxOptions,
    },
    config::{Config, OutputEvidenceMode},
    domain::{
        DomainEvent, InferiorStatus, JournaledEvent, OperationId, OutputSource, SessionState,
        StopId, TrackingDefinition, ValueBinding,
    },
    journal::Journal,
    metrics::Metrics,
    normalize::{breakpoint_number, command_output, normalize},
    persistence::{ArtifactLimits, Store},
    policy::Profile,
    providers::live_module_offset,
    reducer::StateReducer,
    ring::{ByteRing, RingRead},
};

pub(super) enum WorkerRequest {
    Command {
        command: MiCommand,
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    Transaction {
        before: Vec<MiCommand>,
        command: MiCommand,
        after: Vec<MiCommand>,
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    SafeEvaluate {
        command: MiCommand,
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    RecordEvent {
        event: DomainEvent,
        response: oneshot::Sender<Result<()>>,
    },
    RegisterPendingModuleBreakpoint {
        breakpoint: PendingModuleBreakpoint,
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
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
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
        eof: bool,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<usize>>,
    },
    ResizeInferior {
        rows: u16,
        columns: u16,
        response: oneshot::Sender<Result<()>>,
    },
}

pub(super) enum ControlRequest {
    Interrupt {
        command: MiCommand,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<CommandReply>>,
    },
    CancelOperation {
        operation_id: OperationId,
        mode: OperationCancelMode,
        response: oneshot::Sender<Result<()>>,
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
    response: PendingControlResponse,
}

enum PendingControlResponse {
    Interrupt(oneshot::Sender<Result<CommandReply>>),
    Cancel(oneshot::Sender<Result<()>>),
}

impl PendingControlResponse {
    fn send(self, result: Result<CommandReply>) {
        match self {
            Self::Interrupt(response) => {
                let _ = response.send(result);
            }
            Self::Cancel(response) => {
                let _ = response.send(result.map(drop));
            }
        }
    }
}

// Owns both GDB input and reducer state. One ordinary MI command may be in
// flight; the separate control lane admits only interrupt or close.
pub(super) struct SessionWorker {
    backend: GdbBackend,
    journal: Journal,
    artifacts: ArtifactStore,
    reducer: StateReducer,
    store: Arc<Store>,
    metrics: Arc<Metrics>,
    profile: Profile,
    pub(super) capabilities: Arc<StdRwLock<SessionCapabilities>>,
    state_sender: watch::Sender<SessionState>,
    events: broadcast::Sender<PublishedEvent>,
    requests: mpsc::Receiver<WorkerRequest>,
    controls: mpsc::Receiver<ControlRequest>,
    controls_open: bool,
    pub(super) inferior_output: Arc<PtyOutput>,
    inferior_output_offset: u64,
    inferior_output_dropped: u64,
    output_evidence_mode: OutputEvidenceMode,
    output_evidence_finalized: bool,
    target_output: ByteRing,
    console_output: ByteRing,
    log_output: ByteRing,
    next_token: u64,
    timed_out_tokens: HashSet<u64>,
    interrupt_fallback_at: Option<tokio::time::Instant>,
    stream_limit: usize,
    command_timeout: Duration,
    values: BTreeMap<String, ValueBinding>,
    tracking: BTreeMap<String, TrackingDefinition>,
    tracking_history: BTreeMap<String, VecDeque<Value>>,
    snapshots: BTreeMap<String, Value>,
    stale_backend_values: Vec<String>,
    deferred_restoration: Vec<MiCommand>,
    pending_module_breakpoints: BTreeMap<String, PendingModuleBreakpoint>,
    active_resume_operation: Option<OperationId>,
    module_rebind_needed: bool,
    tracking_memory_limit: usize,
    artifact_limit: usize,
    owner_artifact_limit: usize,
    total_artifact_limit: usize,
    fatal: bool,
    pub(super) metric_active: bool,
}

#[allow(clippy::too_many_arguments)]
impl SessionWorker {
    pub(super) async fn bootstrap(
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
        let artifacts = ArtifactStore::new(&config.artifacts.path)?;
        let mut reducer = StateReducer::new(initial_state);
        let mut target_output = ByteRing::new(config.limits.inferior_output_ring_bytes);
        let mut console_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut log_output = ByteRing::new(config.limits.console_output_ring_bytes);
        let mut versions = vec![config.gdb.preferred_mi.clone()];
        if config.gdb.fallback_mi != config.gdb.preferred_mi {
            versions.push(config.gdb.fallback_mi.clone());
        }

        for version in versions {
            let mut backend = GdbBackend::spawn(
                &config.gdb,
                &version,
                &session_dir,
                limits,
                &config.limits,
                &config.output,
                SandboxOptions {
                    mode: config.security.sandbox,
                    // 2026-09-04: Lab sessions may connect GDB remote
                    // targets, so optional sandboxing must preserve their
                    // network rather than silently isolating the stub.
                    allow_network: matches!(profile, Profile::LabMutation | Profile::RawAdmin),
                },
            )
            .await?;
            match wait_for_prompt(
                &mut backend,
                &mut journal,
                &mut reducer,
                &mut target_output,
                &mut console_output,
                &mut log_output,
                config.server.command_timeout(),
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
            artifacts,
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
            inferior_output_offset: 0,
            inferior_output_dropped: 0,
            output_evidence_mode: config.output.evidence,
            output_evidence_finalized: false,
            target_output,
            console_output,
            log_output,
            next_token: 1,
            timed_out_tokens: HashSet::new(),
            interrupt_fallback_at: None,
            stream_limit: config.limits.tool_response_bytes,
            command_timeout: config.server.command_timeout(),
            values: BTreeMap::new(),
            tracking: BTreeMap::new(),
            tracking_history: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            stale_backend_values: Vec::new(),
            deferred_restoration: Vec::new(),
            pending_module_breakpoints: BTreeMap::new(),
            active_resume_operation: None,
            module_rebind_needed: false,
            tracking_memory_limit: config.limits.memory_read_bytes,
            artifact_limit: config.limits.session_artifact_bytes,
            owner_artifact_limit: config.limits.owner_artifact_bytes,
            total_artifact_limit: config.limits.total_artifact_bytes,
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
            self.execute(command, self.command_timeout).await?;
        }
        let target_control = matches!(
            self.profile,
            Profile::DebugControl | Profile::LabMutation | Profile::RawAdmin
        );
        for (setting, enabled) in [
            // 2026-08-28: GDB implements software breakpoints by writing the
            // target instruction. DebugControl permits breakpoints, so this
            // GDB guard must follow control permission; policy still denies
            // the public memory.write method outside mutation profiles.
            ("may-write-memory", target_control),
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
                self.command_timeout,
            )
            .await?;
        }
        let features = self
            .execute(MiCommand::new("-list-features")?, self.command_timeout)
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
            let reply = self.execute(probe, self.command_timeout).await?;
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
            self.command_timeout,
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
                self.command_timeout,
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
                self.command_timeout,
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

    async fn refresh_target_capabilities(
        &mut self,
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
    ) -> Result<SessionCapabilities> {
        let reply = self
            .execute_operation_until(
                MiCommand::new("-list-target-features")?,
                operation,
                deadline,
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

    pub(super) async fn run(mut self) {
        let mut journal_flush = tokio::time::interval(Duration::from_millis(250));
        journal_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if self.module_rebind_needed {
                self.module_rebind_needed = false;
                if let Err(error) = self.rebind_pending_module_breakpoints().await {
                    tracing::warn!(%error, "failed to rebind a pending module breakpoint");
                }
            }
            let interrupt_fallback = self
                .interrupt_fallback_at
                .unwrap_or_else(tokio::time::Instant::now);
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
                    if let Ok(Some((record, _))) = self.process_input(input) {
                        if let Some(token) =
                            take_delayed_token(&mut self.timed_out_tokens, &record)
                        {
                            let _ = self.apply_event(DomainEvent::CommandOutcomeResolved { token });
                        } else {
                            let _ = self.handle_unmatched_result(&record);
                        }
                    }
                    if self.fatal {
                        let _ = self.backend.shutdown().await;
                        break;
                    }
                }
                _ = tokio::time::sleep_until(interrupt_fallback), if self.interrupt_fallback_at.is_some() => {
                    if let Err(error) = self.escalate_acknowledged_interrupt() {
                        tracing::error!(%error, "failed to complete acknowledged interrupt");
                        self.mark_failed();
                    }
                }
            }
        }
        if !self.output_evidence_finalized {
            let _ = self.backend.shutdown().await;
            if !self
                .inferior_output
                .wait_closed(Duration::from_secs(1))
                .await
            {
                // 2026-08-30: Finalizing after a PTY close timeout could
                // publish complete=true before trailing output was dropped.
                self.inferior_output.set_evidence_error(
                    "inferior output did not close before evidence finalization".into(),
                );
            }
            if let Err(error) = self.finalize_output_evidence().await {
                tracing::error!(%error, "inferior output evidence finalization failed");
                self.mark_failed();
            }
        }
        let _ = self.journal.flush();
    }

    async fn handle_request(&mut self, request: WorkerRequest) -> bool {
        match request {
            WorkerRequest::Command {
                command,
                operation,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                if let Err(error) = self.restore_deferred_commands(deadline).await {
                    let _ = response.send(Err(error));
                    return false;
                }
                if command_starts_fresh_inferior(&command)
                    && let Err(error) = self.park_module_breakpoints(deadline).await
                {
                    let _ = response.send(Err(error));
                    return false;
                }
                let _ = response.send(
                    self.execute_operation_until(command, operation, deadline)
                        .await,
                );
                self.cleanup_one_stale_value().await;
            }
            WorkerRequest::Transaction {
                before,
                command,
                after,
                operation,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                if let Err(error) = self.restore_deferred_commands(deadline).await {
                    let _ = response.send(Err(error));
                    return false;
                }
                if command_starts_fresh_inferior(&command)
                    && let Err(error) = self.park_module_breakpoints(deadline).await
                {
                    let _ = response.send(Err(error));
                    return false;
                }
                let mut setup = Ok(());
                for command in before {
                    if let Some(operation) = &operation
                        && let Err(error) = operation.require_active()
                    {
                        setup = Err(error);
                        break;
                    }
                    if let Err(error) = self.execute_until(command, deadline).await {
                        setup = Err(error);
                        break;
                    }
                }
                let result = match setup {
                    // 2026-08-30: Launch and restart advertised actor-scoped
                    // cancellation, but their transaction dropped operation
                    // identity before the resume reached the SessionActor.
                    Ok(()) => {
                        self.execute_operation_until(command, operation, deadline)
                            .await
                    }
                    Err(error) => Err(error),
                };
                // 2026-08-28: A timed-out transaction previously sent its
                // restoration commands while the original outcome was unknown.
                // Defer them until the late token is consumed by the worker.
                if !after.is_empty() && !self.timed_out_tokens.is_empty() {
                    self.deferred_restoration = after;
                    match self.apply_event(DomainEvent::ConsistencyDirty {
                        reason: "temporary GDB settings await a known command outcome".into(),
                    }) {
                        Ok(()) => {
                            let _ = response.send(result);
                        }
                        Err(error) => {
                            let _ = response.send(Err(error));
                        }
                    }
                } else if let Err(error) = self.run_restoration(&after, deadline).await {
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
                self.cleanup_one_stale_value().await;
            }
            WorkerRequest::SafeEvaluate {
                command,
                operation,
                deadline,
                response,
            } => {
                if let Err(error) = self.require_known_outcome(&command) {
                    let _ = response.send(Err(error));
                    return false;
                }
                if let Err(error) = self.restore_deferred_commands(deadline).await {
                    let _ = response.send(Err(error));
                    return false;
                }
                let _ = response.send(
                    self.execute_safe(command, operation.as_ref(), deadline)
                        .await,
                );
                self.cleanup_one_stale_value().await;
            }
            WorkerRequest::RecordEvent { event, response } => {
                let _ = response.send(self.apply_event(event));
            }
            WorkerRequest::RegisterPendingModuleBreakpoint {
                breakpoint,
                response,
            } => {
                self.pending_module_breakpoints
                    .insert(breakpoint.backend_number.clone(), breakpoint);
                self.module_rebind_needed = true;
                let _ = response.send(Ok(()));
            }
            WorkerRequest::RecordApi { request, response } => {
                let appended = self.journal.append_api(request).map(|_| ());
                let result = self.journal_result(appended);
                let _ = response.send(result);
            }
            WorkerRequest::FlushJournal { response } => {
                let flushed = self.journal.flush();
                let result = self.journal_result(flushed);
                let _ = response.send(result);
            }
            WorkerRequest::RefreshTargetCapabilities {
                operation,
                deadline,
                response,
            } => {
                let result = match self.require_known_outcome_name("-list-target-features") {
                    Ok(()) => match self.restore_deferred_commands(deadline).await {
                        Ok(()) => self.refresh_target_capabilities(operation, deadline).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                };
                let _ = response.send(result);
                self.cleanup_one_stale_value().await;
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
                    if value_id.starts_with('v')
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
            WorkerRequest::WriteInferior {
                bytes,
                eof,
                deadline,
                response,
            } => {
                let appended = self.journal.append_inferior_input(&bytes);
                let result = match self.journal_result(appended) {
                    Ok(_) => self.backend.write_inferior(&bytes, eof, deadline).await,
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
                // 2026-09-04: Some remote stubs acknowledge -exec-interrupt
                // before stopping (or without stopping at all). If the target
                // is still running after the MI reply, deliver the existing
                // process-group fallback so a later state wait can complete.
                let result = self.finish_interrupt(result);
                let _ = response.send(result);
                self.fatal
            }
            ControlRequest::CancelOperation {
                operation_id,
                mode,
                response,
            } => {
                let result = match mode {
                    // 2026-09-01: Signalling immediately after ^running could
                    // abort GDB's startup command before *running, leaving the
                    // inferior reported as running without a stop event. Once
                    // the actor is idle, use MI's ordered interrupt path.
                    OperationCancelMode::InterruptTarget => {
                        match self.owned_interrupt_command(&operation_id) {
                            Ok(command) => {
                                self.execute(command, self.command_timeout).await.map(drop)
                            }
                            Err(error) => Err(error),
                        }
                    }
                    OperationCancelMode::CloseSession => {
                        match self.require_active_resume(&operation_id) {
                            Ok(()) => self.close().await,
                            Err(error) => Err(error),
                        }
                    }
                };
                let closed = result.is_ok() && mode == OperationCancelMode::CloseSession;
                let _ = response.send(result);
                closed
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
        if !self
            .inferior_output
            .wait_closed(Duration::from_secs(1))
            .await
        {
            // 2026-08-30: A retained PTY slave can outlive GDB. Preserve the
            // bounded prefix, but do not certify it as complete evidence.
            self.inferior_output.set_evidence_error(
                "inferior output did not close before evidence finalization".into(),
            );
        }
        self.finalize_output_evidence().await?;
        self.apply_event(DomainEvent::SessionClosed)?;
        if self.metric_active {
            self.metrics.session_closed();
            self.metric_active = false;
        }
        Ok(())
    }

    fn owned_interrupt_command(&self, operation_id: &OperationId) -> Result<MiCommand> {
        // 2026-08-29: A delayed cancellation used a generic interrupt and
        // could stop a later resume. Only the actor can atomically verify
        // which operation still owns the target before applying control.
        self.require_active_resume(operation_id)?;
        MiCommand::new("-exec-interrupt")
    }

    fn require_active_resume(&self, operation_id: &OperationId) -> Result<()> {
        if operation_owns_resume(self.active_resume_operation.as_ref(), operation_id) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Conflict,
                "operation no longer owns the active target resume",
            ))
        }
    }

    async fn finalize_output_evidence(&mut self) -> Result<OutputEvidenceStatus> {
        if self.output_evidence_finalized {
            return Ok(self.inferior_output.evidence_status());
        }
        let output = Arc::clone(&self.inferior_output);
        let store = Arc::clone(&self.store);
        let artifacts = self.artifacts.clone();
        let session_id = self.reducer.state().session_id.clone();
        let evidence_mode = self.output_evidence_mode;
        let artifact_limits = ArtifactLimits {
            session_bytes: self.artifact_limit,
            owner_bytes: self.owner_artifact_limit,
            total_bytes: self.total_artifact_limit,
        };
        // 2026-08-29: Joining the spool writer and reading, hashing, and
        // publishing its file synchronously blocked the SessionActor.
        let (status, artifact_bytes, stored_bytes) = tokio::task::spawn_blocking(move || {
            let mut status = output.finish_evidence();
            let mut artifact_bytes = 0;
            let mut stored_bytes = None;
            if evidence_mode == OutputEvidenceMode::Artifact && status.error.is_none() {
                let result = (|| {
                    let size = usize::try_from(status.spooled_bytes).map_err(|_| {
                        Error::new(ErrorCode::OutputLimit, "inferior output spool is too large")
                    })?;
                    // ponytail: Output spools are operator-bounded and default
                    // to 8 MiB. Add streaming ingestion only if that bound grows.
                    let path = output
                        .evidence_path()
                        .map(|path| path.to_path_buf())
                        .ok_or_else(|| {
                            Error::new(ErrorCode::Internal, "inferior output spool path is missing")
                        })?;
                    let bytes = std::fs::read(&path)?;
                    if bytes.len() != size {
                        return Err(Error::new(
                            ErrorCode::Internal,
                            "inferior output spool size changed during finalization",
                        ));
                    }
                    let uri = store.put_artifact(
                        &artifacts,
                        &bytes,
                        Some(&session_id),
                        "target-io",
                        artifact_limits,
                    )?;
                    artifact_bytes = bytes.len();
                    stored_bytes = store.total_artifact_bytes().ok();
                    Ok((uri, path))
                })();
                match result {
                    Ok((uri, path)) => {
                        output.set_artifact_uri(uri.clone());
                        status.artifact_uri = Some(uri);
                        status.durability = "artifact";
                        let _ = std::fs::remove_file(path);
                    }
                    Err(error) => {
                        // 2026-08-29: Keeping an artifact failure only in this
                        // local result made the later close response claim complete
                        // evidence. Persist the failure in the shared PTY status.
                        status.complete = false;
                        status.error = Some(error.to_string());
                        output.set_evidence_error(error.to_string());
                    }
                }
            }
            (status, artifact_bytes, stored_bytes)
        })
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("output evidence finalization task failed: {error}"),
            )
        })?;
        // 2026-08-29: Drop metrics alone hid successfully preserved PTY
        // evidence, so count each finalized spool exactly once.
        self.metrics.inferior_output_spooled(status.spooled_bytes);
        if artifact_bytes > 0 {
            self.metrics.artifact_written(artifact_bytes);
        }
        if let Some(stored) = stored_bytes {
            self.metrics
                .artifact_storage(stored, self.total_artifact_limit);
        }
        self.output_evidence_finalized = true;
        let evidence = serde_json::to_value(&status)?;
        let appended = self.journal.append_inferior_output_evidence(evidence);
        self.journal_result(appended)?;
        Ok(status)
    }

    async fn cleanup_one_stale_value(&mut self) {
        // 2026-08-28: Deleting every stale variable object before a business
        // command consumed that request's deadline. Clean one object only
        // after responding, so maintenance cannot delay the current result.
        if !self.timed_out_tokens.is_empty()
            || !self.reducer.state().inferiors.values().any(|inferior| {
                matches!(
                    inferior.status,
                    InferiorStatus::Stopped | InferiorStatus::Core
                )
            })
        {
            return;
        }
        let Some(backend_name) = self.stale_backend_values.pop() else {
            return;
        };
        let Ok(command) =
            MiCommand::new("-var-delete").and_then(|command| command.bare(backend_name.clone()))
        else {
            return;
        };
        let deadline = command_deadline(Duration::from_millis(250));
        if let Err(error) = self.execute_until(command, deadline).await
            && matches!(error.code, ErrorCode::Timeout | ErrorCode::GdbUnresponsive)
        {
            self.stale_backend_values.push(backend_name);
        }
    }

    async fn run_restoration(
        &mut self,
        commands: &[MiCommand],
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        for command in commands {
            self.execute_until(command.clone(), deadline).await?;
        }
        Ok(())
    }

    async fn restore_deferred_commands(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        if self.deferred_restoration.is_empty() {
            return Ok(());
        }
        let commands = self.deferred_restoration.clone();
        self.run_restoration(&commands, deadline)
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::ConsistencyDirty,
                    format!("deferred GDB setting restoration failed: {error}"),
                )
            })?;
        self.deferred_restoration.clear();
        Ok(())
    }

    async fn rebind_pending_module_breakpoints(&mut self) -> Result<()> {
        let pending = self
            .pending_module_breakpoints
            .values()
            .filter(|breakpoint| {
                self.reducer
                    .state()
                    .breakpoints
                    .get(&breakpoint.backend_number)
                    .is_some_and(|state| state.pending)
            })
            .cloned()
            .collect::<Vec<_>>();
        for breakpoint in pending {
            let Some(address) =
                live_module_offset(self.reducer.state(), &breakpoint.module, breakpoint.offset)?
            else {
                continue;
            };
            // 2026-08-28: A module-offset breakpoint created at an explicit
            // loader entry stayed pending after exec because GDB interpreted
            // the module name as a symbol. Materialize it once /proc exposes
            // the load bias while preserving the public breakpoint handle.
            let enabled = breakpoint.enabled;
            let command = breakpoint.command.clone().string(format!("*{address}"));
            self.replace_module_breakpoint(
                breakpoint,
                enabled,
                command,
                Some(address),
                command_deadline(self.command_timeout),
            )
            .await?;
        }
        Ok(())
    }

    async fn park_module_breakpoints(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        let materialized = self
            .pending_module_breakpoints
            .values()
            .filter_map(|breakpoint| {
                self.reducer
                    .state()
                    .breakpoints
                    .get(&breakpoint.backend_number)
                    .filter(|state| !state.pending)
                    .map(|state| (breakpoint.clone(), state.enabled))
            })
            .collect::<Vec<_>>();
        // 2026-09-01: Rebinding discarded module metadata and left a PIE's
        // absolute address enabled across the next ASLR generation, so GDB
        // rejected the fresh run before its mappings existed. Replace it with
        // a software pending placeholder while retaining the logical identity;
        // GDB has no pending watchpoints, and rebind restores the saved kind.
        for (breakpoint, enabled) in materialized {
            let pending = format!("__gdb_ai_pending_{}", breakpoint.id.0);
            let command = MiCommand::new("-break-insert")?.bare("-f")?.string(pending);
            self.replace_module_breakpoint(breakpoint, enabled, command, None, deadline)
                .await?;
        }
        if !self.pending_module_breakpoints.is_empty() {
            self.module_rebind_needed = true;
        }
        Ok(())
    }

    async fn replace_module_breakpoint(
        &mut self,
        mut breakpoint: PendingModuleBreakpoint,
        enabled: bool,
        command: MiCommand,
        address: Option<String>,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let old_backend_number = breakpoint.backend_number.clone();
        let reply = self.execute_until(command, deadline).await?;
        let new_backend_number = breakpoint_number(&reply.record)?;
        if !enabled {
            self.execute_until(
                MiCommand::new("-break-disable")?.bare(new_backend_number.clone())?,
                deadline,
            )
            .await?;
        }
        self.apply_event(DomainEvent::BreakpointRebound {
            id: breakpoint.id.clone(),
            old_backend_number: old_backend_number.clone(),
            new_backend_number: new_backend_number.clone(),
            enabled,
            address,
        })?;
        self.pending_module_breakpoints.remove(&old_backend_number);
        breakpoint.backend_number.clone_from(&new_backend_number);
        breakpoint.enabled = enabled;
        self.pending_module_breakpoints
            .insert(new_backend_number.clone(), breakpoint);
        if let Err(error) = self
            .execute_until(
                MiCommand::new("-break-delete")?.bare(old_backend_number.clone())?,
                deadline,
            )
            .await
        {
            self.apply_event(DomainEvent::ConsistencyDirty {
                reason: format!(
                    "module breakpoint moved to {new_backend_number}, but old breakpoint {old_backend_number} could not be deleted: {error}"
                ),
            })?;
            return Err(error);
        }
        Ok(())
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
        operation: Option<&ActiveOperation>,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        const SETTINGS: [&str; 3] = [
            "may-call-functions",
            "may-write-memory",
            "may-write-registers",
        ];
        let (settings, inspect_originals) = safe_evaluation_settings(self.profile, &SETTINGS);
        let mut originals = Vec::new();
        if inspect_originals {
            for &setting in settings {
                if let Some(operation) = operation {
                    operation.require_active()?;
                }
                let reply = self
                    .execute_until(MiCommand::new("-gdb-show")?.bare(setting)?, deadline)
                    .await?;
                let value = MiResult::find_str(reply.record.results(), "value")
                    .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB setting has no value"))?;
                originals.push((setting, value.to_owned()));
            }
        } else {
            // 2026-08-30: Handshake fixes these values and non-raw profiles
            // cannot alter them. Avoid three redundant queries per evaluation;
            // only settings enabled for target control need temporary guards.
            originals.extend(settings.iter().map(|&setting| (setting, "on".into())));
        }
        // 2026-08-28: Hard-coded restoration to "on" could weaken observer
        // policy after evaluation. Restore the exact values read in this worker.
        let mut setup_error = None;
        let mut guarded = Vec::new();
        for &setting in settings {
            // 2026-08-30: Safe evaluation and capability refresh used to drop
            // operation identity, so cancelled probes could keep issuing MI
            // reads. Stop at command boundaries but still restore any setting
            // already changed below.
            if let Some(operation) = operation
                && let Err(error) = operation.require_active()
            {
                setup_error = Some(error);
                break;
            }
            match self
                .execute_until(
                    MiCommand::new("-gdb-set")?.bare(setting)?.bare("off")?,
                    deadline,
                )
                .await
            {
                Ok(_) => guarded.push(setting),
                // 2026-08-29: GDB 9-13 cannot change this setting after a
                // live inferior exists. The expression validator is the
                // primary register-mutation guard on those versions.
                Err(error)
                    if setting == "may-write-registers" && error.code == ErrorCode::GdbError => {}
                Err(error) => {
                    setup_error = Some(error);
                    break;
                }
            }
        }
        let result = match setup_error {
            Some(error) => Err(error),
            None => match operation.map(ActiveOperation::require_active) {
                Some(Err(error)) => Err(error),
                _ => self.execute_until(command, deadline).await,
            },
        };
        let restoration = originals
            .into_iter()
            .filter(|(setting, _)| guarded.contains(setting))
            .map(|(setting, value)| MiCommand::new("-gdb-set")?.bare(setting)?.bare(value))
            .collect::<Result<Vec<_>>>()?;
        // 2026-08-28: Restoring safety settings before a timed-out evaluate
        // resolved could overlap its late result. Keep the restrictive values
        // and restore them only after the unknown-outcome fence clears.
        if !self.timed_out_tokens.is_empty() {
            self.deferred_restoration = restoration;
            self.apply_event(DomainEvent::ConsistencyDirty {
                reason: "safe-evaluation settings await a known command outcome".into(),
            })?;
            return result;
        }
        if let Err(error) = self.run_restoration(&restoration, deadline).await {
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
            if let Some(interrupt_fallback) = self.interrupt_fallback_at {
                wake = wake.min(interrupt_fallback);
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
                ExecutionInput::Control(Some(ControlRequest::CancelOperation {
                    operation_id,
                    mode,
                    response,
                })) => {
                    match mode {
                        OperationCancelMode::CloseSession => {
                            let result = match self.require_active_resume(&operation_id) {
                                Ok(()) => self.close().await,
                                Err(error) => Err(error),
                            };
                            let closed = result.is_ok();
                            let _ = response.send(result);
                            if closed {
                                self.fatal = true;
                                return Err(Error::new(
                                    ErrorCode::Cancelled,
                                    "operation closed session",
                                ));
                            }
                        }
                        OperationCancelMode::InterruptTarget => {
                            if pending_control.is_some() {
                                let _ = response.send(Err(Error::new(
                                    ErrorCode::Conflict,
                                    "an interrupt is already pending",
                                )));
                                continue;
                            }
                            let command = match self.owned_interrupt_command(&operation_id) {
                                Ok(command) => command,
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                    continue;
                                }
                            };
                            match self.begin_command(&command).await {
                                Ok(control_token) => {
                                    // 2026-09-01: Process-group SIGINT during
                                    // inferior startup could abort the accepted
                                    // resume and leave no stop event. Queue MI
                                    // first; this timer retains the bounded
                                    // signal fallback for an unresponsive GDB.
                                    let now = tokio::time::Instant::now();
                                    pending_control = Some(PendingControl {
                                        token: control_token,
                                        deadline: command_deadline(self.command_timeout),
                                        escalate_at: now + Duration::from_millis(250),
                                        escalated: false,
                                        started: std::time::Instant::now(),
                                        response: PendingControlResponse::Cancel(response),
                                    });
                                }
                                Err(error) => {
                                    let _ = response.send(Err(error));
                                }
                            }
                        }
                    }
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
                                    response: PendingControlResponse::Interrupt(response),
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
                    self.escalate_acknowledged_interrupt()?;
                    let should_escalate = pending_control
                        .as_ref()
                        .is_some_and(|control| !control.escalated && control.escalate_at <= now);
                    if should_escalate {
                        // 2026-08-28: A blocked GDB cannot consume the queued
                        // -exec-interrupt. Escalate only after its MI grace period.
                        if let Err(error) = self.backend.signal_interrupt() {
                            let control = pending_control.take().unwrap();
                            control.response.send(Err(error));
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
                        control.response.send(Err(command_timeout(control.token)));
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
                    let delayed = take_delayed_token(&mut self.timed_out_tokens, &record);
                    if let Some(delayed) = delayed {
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
                        let result =
                            command_reply(control.token, record, evidence_seq, Vec::new(), false);
                        control.response.send(self.finish_interrupt(result));
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
                    if delayed.is_none() {
                        self.handle_unmatched_result(&record)?;
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

    fn finish_interrupt(&mut self, result: Result<CommandReply>) -> Result<CommandReply> {
        if result.is_ok() && self.target_running() {
            // 2026-09-04: Escalating as soon as GDB acknowledged an interrupt
            // raced its queued stop notification, leaving a second SIGINT to
            // poison the next resume. Give the ordered MI stop a bounded grace
            // period and cancel the fallback as soon as state settles.
            self.interrupt_fallback_at =
                Some(tokio::time::Instant::now() + Duration::from_millis(250));
        }
        result
    }

    fn escalate_acknowledged_interrupt(&mut self) -> Result<()> {
        let Some(deadline) = self.interrupt_fallback_at else {
            return Ok(());
        };
        if deadline > tokio::time::Instant::now() {
            return Ok(());
        }
        self.interrupt_fallback_at = None;
        if self.target_running() {
            self.backend.signal_interrupt()?;
        }
        Ok(())
    }

    fn target_running(&self) -> bool {
        self.reducer
            .state()
            .inferiors
            .values()
            .any(|inferior| inferior.status == InferiorStatus::Running)
    }

    async fn execute_operation_until(
        &mut self,
        command: MiCommand,
        operation: Option<ActiveOperation>,
        deadline: tokio::time::Instant,
    ) -> Result<CommandReply> {
        if let Some(operation) = &operation {
            operation.require_active()?;
        }
        if command_starts_fresh_inferior(&command) {
            // 2026-09-01: Unconsumed PTY input survived an aborted inferior and
            // was executed by its replacement. Input never crosses a fresh-run
            // generation boundary; Agents send new input after GDB accepts run.
            self.backend.flush_inferior_input()?;
        }
        let resumes_target = command_resumes_target(&command);
        let operation_id = operation.as_ref().map(|operation| operation.id().clone());
        if resumes_target {
            self.active_resume_operation = operation_id.clone();
        }
        let result = self.execute_until(command, deadline).await;
        // 2026-08-30: A rejected or queue-expired resume remained active. A
        // late cancel could then interrupt an unrelated following command.
        // Keep ownership only when a sent command has an unresolved outcome.
        if resumes_target
            && resume_failed_definitively(&result, !self.timed_out_tokens.is_empty())
            && self.active_resume_operation == operation_id
        {
            self.active_resume_operation = None;
        }
        result
    }

    fn handle_unmatched_result(&mut self, record: &MiRecord) -> Result<()> {
        let MiRecord::Result { token, class, .. } = record else {
            return Ok(());
        };
        // 2026-08-28: GDB can accept async execution with ^running and later
        // emit ^error for the same token when startup fails. Silently dropping
        // that second result left canonical state running until a wait timed out.
        self.apply_event(DomainEvent::ConsistencyDirty {
            reason: format!("unmatched MI result token {token:?} class {class}"),
        })
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
        // 2026-08-30: The backend used to encode the same command again after
        // the scheduler journaled it. Send these exact recorded bytes once.
        self.backend.send(&raw).await?;
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
                    if !self.target_running() {
                        self.interrupt_fallback_at = None;
                    }
                }
                Ok(Some((record, evidence_seq)))
            }
            BackendInput::GdbStderr(bytes) => {
                let appended = self.journal.append_gdb_stderr(&bytes);
                self.journal_result(appended)?;
                self.log_output.append(&bytes);
                Ok(None)
            }
            BackendInput::InferiorPty => {
                // 2026-08-29: PTY notifications are coalesced high-water
                // signals. Read the authoritative ring position here instead
                // of trusting stale per-chunk metadata.
                let (next_offset, dropped_bytes) = self.inferior_output.position();
                let offset = self.inferior_output_offset.min(next_offset);
                let length = next_offset.saturating_sub(offset) as usize;
                if length == 0 && dropped_bytes == self.inferior_output_dropped {
                    return Ok(None);
                }
                let appended = self
                    .journal
                    .append_inferior_output(offset, length, dropped_bytes);
                self.journal_result(appended)?;
                self.metrics.inferior_output_dropped(
                    dropped_bytes.saturating_sub(self.inferior_output_dropped),
                );
                self.inferior_output_offset = next_offset;
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
        }
    }

    fn apply_event(&mut self, event: DomainEvent) -> Result<()> {
        let result = self.apply_event_inner(event);
        if result.is_err() {
            // 2026-08-30: Reducer or state persistence failures returned to
            // one caller while the worker stayed live and watch clients kept
            // an older healthy state. Authoritative event failure is fatal.
            self.fatal = true;
            self.mark_failed();
        }
        result
    }

    fn apply_event_inner(&mut self, event: DomainEvent) -> Result<()> {
        let stopped = matches!(&event, DomainEvent::TargetStopped { .. });
        let attributed_exit = self.reducer.state().attributed_exit(&event);
        if attributed_exit
            || matches!(
                &event,
                DomainEvent::TargetStopped { .. }
                    | DomainEvent::TargetDisconnected
                    | DomainEvent::TargetDetached
                    | DomainEvent::BackendExited { .. }
            )
        {
            self.active_resume_operation = None;
        }
        if let DomainEvent::BreakpointDeleted { backend_number } = &event {
            self.pending_module_breakpoints.remove(backend_number);
        }
        if let DomainEvent::BreakpointModified {
            backend_number,
            enabled,
            ..
        } = &event
            && let Some(breakpoint) = self.pending_module_breakpoints.get_mut(backend_number)
        {
            breakpoint.enabled = *enabled;
        }
        if !self.pending_module_breakpoints.is_empty()
            && matches!(
                &event,
                DomainEvent::LibraryLoaded { .. } | DomainEvent::TargetStopped { .. }
            )
        {
            self.module_rebind_needed = true;
        }
        if matches!(&event, DomainEvent::TargetRunning { .. }) {
            self.inferior_output.reset();
        }
        let invalidates_values = attributed_exit
            || matches!(
                &event,
                DomainEvent::TargetRunning { .. }
                    | DomainEvent::TargetDisconnected
                    | DomainEvent::TargetDetached
                    | DomainEvent::BackendExited { .. }
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
            DomainEvent::TargetDetached
            | DomainEvent::TargetDisconnected
            | DomainEvent::BackendExited { .. } => {
                self.set_capability("execution", CapabilityStatus::TemporarilyUnavailable);
            }
            DomainEvent::InferiorExited { .. }
                if self
                    .reducer
                    .state()
                    .inferiors
                    .values()
                    .any(|inferior| inferior.status == InferiorStatus::Disconnected) =>
            {
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
            let appended = self
                .journal
                .append_state(self.reducer.state().revision, self.reducer.state());
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
            let snapshot_started = Instant::now();
            // 2026-08-28: SnapshotReady was published without a stored object.
            // Persist the bounded stop context before advertising readiness.
            let stop_id = self.reducer.state().stop_id.clone().unwrap();
            let snapshot_id = format!("snap_{stop_id}");
            let frame = self.reducer.state().stopped_frame().cloned();
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
            self.metrics.snapshot(
                snapshot_started.elapsed().as_micros() as u64,
                frame.is_none(),
            );
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
        // 2026-08-29: Evidence-storage failures stopped the worker before a
        // BackendExited event could be journaled, leaving live clients with a
        // stale READY/ACTIVE state. The reducer still owns this emergency
        // terminal transition even though the failed journal cannot record it.
        if self.reducer.fail_closed() {
            self.state_sender.send_replace(self.reducer.state().clone());
        }
        if self.metric_active {
            self.metrics.session_failed();
            self.metrics.session_closed();
            self.metric_active = false;
        }
    }
}

async fn wait_for_prompt(
    backend: &mut GdbBackend,
    journal: &mut Journal,
    reducer: &mut StateReducer,
    target_output: &mut ByteRing,
    console_output: &mut ByteRing,
    log_output: &mut ByteRing,
    timeout: Duration,
) -> Result<()> {
    // 2026-08-29: A fixed three-second prompt deadline rejected valid GDB
    // startup on AArch64 TCG before the configured command timeout elapsed.
    let deadline = tokio::time::Instant::now() + timeout;
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
            BackendInput::InferiorPty => {}
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

fn command_resumes_target(command: &MiCommand) -> bool {
    matches!(
        command.name.as_str(),
        "-exec-run"
            | "-exec-continue"
            | "-exec-step"
            | "-exec-next"
            | "-exec-finish"
            | "-exec-step-instruction"
            | "-exec-next-instruction"
            | "-exec-until"
            | "-exec-jump"
            | "-exec-return"
    )
}

fn command_starts_fresh_inferior(command: &MiCommand) -> bool {
    command.name == "-exec-run"
        || matches!(
            command.arguments.as_slice(),
            [MiArgument::Bare(interpreter), MiArgument::String(console_command)]
                if command.name == "-interpreter-exec"
                    && interpreter == "console"
                    && console_command == b"starti"
        )
}

fn resume_failed_definitively(result: &Result<CommandReply>, outcome_unknown: bool) -> bool {
    result.is_err() && !outcome_unknown
}

fn operation_owns_resume(active: Option<&OperationId>, requested: &OperationId) -> bool {
    active == Some(requested)
}

fn command_timeout(token: u64) -> Error {
    Error::new(
        ErrorCode::Timeout,
        // 2026-08-28: A timeout does not prove that GDB ignored the command or
        // that target state remained unchanged.
        format!("MI token {token} timed out; command completion is unknown"),
    )
    .with_details(serde_json::json!({
        "outcome_unknown": true,
        "token": token,
    }))
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
        let mut details = serde_json::json!({
            "token": token,
            "record": record,
            "evidence_seq": evidence_seq
        });
        // 2026-09-05: A failing helper discarded diagnostics emitted before
        // its error. Preserve this command's bounded streams in the same reply.
        details
            .as_object_mut()
            .unwrap()
            .extend(command_output(&stream_records, stream_truncated));
        return Err(Error::new(ErrorCode::GdbError, message).with_details(details));
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

fn safe_evaluation_settings<'a>(
    profile: Profile,
    settings: &'a [&'a str; 3],
) -> (&'a [&'a str], bool) {
    match profile {
        Profile::RawAdmin => (&settings[..], true),
        Profile::DebugControl | Profile::LabMutation => (&settings[1..], false),
        Profile::OfflineCore | Profile::LiveObserver => (&settings[..0], false),
    }
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
    use super::*;

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
    fn stale_operation_does_not_own_a_later_resume() {
        let earlier = OperationId::new();
        let later = OperationId::new();
        assert!(!operation_owns_resume(Some(&later), &earlier));
        assert!(operation_owns_resume(Some(&later), &later));
        assert!(command_resumes_target(
            &MiCommand::new("-exec-continue").unwrap()
        ));
        assert!(resume_failed_definitively(
            &Err(Error::new(ErrorCode::GdbError, "cannot execute")),
            false
        ));
        assert!(resume_failed_definitively(
            &Err(Error::new(ErrorCode::Timeout, "expired before send")),
            false
        ));
        assert!(!resume_failed_definitively(
            &Err(Error::new(ErrorCode::Timeout, "unknown outcome")),
            true
        ));
        assert_eq!(command_timeout(42).details.unwrap()["token"], 42);
    }

    #[test]
    fn safe_evaluation_reuses_non_raw_handshake_settings() {
        let settings = [
            "may-call-functions",
            "may-write-memory",
            "may-write-registers",
        ];
        assert_eq!(
            safe_evaluation_settings(Profile::DebugControl, &settings),
            (&settings[1..], false)
        );
        assert_eq!(
            safe_evaluation_settings(Profile::LiveObserver, &settings),
            (&settings[..0], false)
        );
        assert_eq!(
            safe_evaluation_settings(Profile::RawAdmin, &settings),
            (&settings[..], true)
        );
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
}

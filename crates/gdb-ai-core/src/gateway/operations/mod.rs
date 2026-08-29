use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiRecord, MiResult, MiValue};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{
        BreakpointLocationState, DomainEvent, FrameId, FrameSummary, LeaseId, OperationId,
        OperationRecord, OperationStatus, SessionId, SignalPolicyState, StopId, StopReason,
        TargetOrigin, TrackingDefinition, TrackingId, ValueBinding, ValueId, WaitBaseline,
        WriteLease,
    },
    gateway::{Caller, Gateway, SessionEntry, now_unix_ms, same_principal},
    normalize::breakpoint_number as inserted_breakpoint_number,
    persistence::Store,
    policy::{Profile, validate_console_command},
    protocol::{ApiRequest, CanonicalMethod},
    providers::{LINUX_KERNEL_PROVIDER_VERSION, live_module_offset, mappings},
    session::{CommandReply, OutputRing, PendingModuleBreakpoint, SessionHandle, WaitUntil},
};

mod agent;
mod execution;
mod inspection;
mod io;
mod kernel;
mod lifecycle;
mod memory;
mod values;

impl Gateway {
    pub(crate) async fn execute_method(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        match request.method {
            CanonicalMethod::SessionCreate => self.session_create(request, caller).await,
            CanonicalMethod::SessionGet => self.session_get(request).await,
            CanonicalMethod::SessionList => self.session_list(caller).await,
            CanonicalMethod::SessionClose => self.session_close(request).await,
            CanonicalMethod::SessionAcquireWriteLease => {
                self.session_acquire_write_lease(request, caller).await
            }
            CanonicalMethod::SessionReleaseWriteLease => {
                self.session_release_write_lease(request).await
            }
            CanonicalMethod::SessionAttemptRecovery => self.session_attempt_recovery(request).await,
            CanonicalMethod::SessionCapabilities => Ok(serde_json::to_value(
                self.entry(required_session(request)?)
                    .await?
                    .handle
                    .capabilities(),
            )?),
            CanonicalMethod::SessionProviders => self.session_providers(request).await,
            CanonicalMethod::SessionTranscript => self.session_transcript(request).await,
            CanonicalMethod::SessionEvent => self.session_event(request).await,
            CanonicalMethod::TargetLaunch => self.target_launch(request).await,
            CanonicalMethod::TargetAttach => self.target_attach(request).await,
            CanonicalMethod::TargetConnectRemote => self.target_connect_remote(request).await,
            CanonicalMethod::TargetOpenCore => self.target_open_core(request).await,
            CanonicalMethod::TargetDetach => self.target_detach(request).await,
            CanonicalMethod::TargetRestart => self.target_restart(request).await,
            CanonicalMethod::TargetKill => self.target_kill(request).await,
            CanonicalMethod::ExecutionControl => self.execution_control(request).await,
            CanonicalMethod::ExecutionWait => self.execution_wait(request).await,
            CanonicalMethod::BreakpointCreate => self.breakpoint_create(request).await,
            CanonicalMethod::BreakpointUpdate => self.breakpoint_update(request).await,
            CanonicalMethod::BreakpointDelete => self.breakpoint_delete(request).await,
            CanonicalMethod::BreakpointList => self.breakpoint_list(request).await,
            CanonicalMethod::InspectionGet => self.inspection_get(request).await,
            CanonicalMethod::InspectionSnapshot => self.inspection_snapshot(request).await,
            CanonicalMethod::InspectionDiff => self.inspection_diff(request).await,
            CanonicalMethod::InspectionBatch => self.inspection_batch(request).await,
            CanonicalMethod::InspectionSnapshotGet => self.inspection_snapshot_get(request).await,
            CanonicalMethod::ValueEvaluate => self.value_evaluate(request).await,
            CanonicalMethod::ValueCreate => self.value_create(request).await,
            CanonicalMethod::ValueChildren => self.value_children(request).await,
            CanonicalMethod::ValueUpdate => self.value_update(request).await,
            CanonicalMethod::ValueRelease => self.value_release(request).await,
            CanonicalMethod::MemoryRead => self.memory_read(request).await,
            CanonicalMethod::MemoryWrite => self.memory_write(request).await,
            CanonicalMethod::MemorySearch => self.memory_search(request).await,
            CanonicalMethod::MemoryCompare => self.memory_compare(request).await,
            CanonicalMethod::RegisterRead => self.register_read(request).await,
            CanonicalMethod::RegisterWrite => self.register_write(request).await,
            CanonicalMethod::DisassemblyRead => self.disassembly_read(request).await,
            CanonicalMethod::InferiorIoRead => self.io_read(request).await,
            CanonicalMethod::InferiorIoWrite => self.io_write(request).await,
            CanonicalMethod::InferiorIoCloseStdin | CanonicalMethod::InferiorIoSendEof => {
                self.io_send_eof(request).await
            }
            CanonicalMethod::InferiorIoResize => self.io_resize(request).await,
            CanonicalMethod::TrackingAddExpression => self.tracking_add_expression(request).await,
            CanonicalMethod::TrackingAddMemory => self.tracking_add_memory(request).await,
            CanonicalMethod::TrackingRemove => self.tracking_remove(request).await,
            CanonicalMethod::TrackingList => self.tracking_list(request).await,
            CanonicalMethod::SignalGet => self.signal_get(request).await,
            CanonicalMethod::SignalUpdate => self.signal_update(request).await,
            CanonicalMethod::AgentHypothesisCheck => self.agent_hypothesis_check(request).await,
            CanonicalMethod::AgentProbe | CanonicalMethod::AgentExperiment => {
                self.agent_probe(request).await
            }
            CanonicalMethod::KernelInspect => self.kernel_inspect(request).await,
            CanonicalMethod::KernelMonitor => self.kernel_monitor(request).await,
            CanonicalMethod::ArtifactGet => self.artifact_get(request, caller).await,
            CanonicalMethod::EventsWait => self.events_wait(request).await,
            CanonicalMethod::RawMi => self.raw_mi(request).await,
            CanonicalMethod::RawConsole => self.raw_console(request).await,
        }
    }

    async fn artifact_get(&self, request: &ApiRequest, caller: &Caller) -> Result<Value> {
        let uri = string(&request.parameters, "uri")?;
        // 2026-08-28: Content-addressed URIs are identifiers, not bearer
        // credentials. Enforce the creating session's ownership on every read.
        let metadata = self
            .store
            .artifact(&uri)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "artifact not found"))?;
        let sessions = self.store.artifact_sessions(&uri)?;
        let mut owned = false;
        for session_id in &sessions {
            let session_id = SessionId::parse(session_id)?;
            if self
                .store
                .session_owner(&session_id)?
                .is_some_and(|owner| same_principal(&owner, &caller.identity))
            {
                owned = true;
                break;
            }
        }
        if !caller.admin && !owned {
            let message = if sessions.is_empty() {
                "global artifacts require administrative access"
            } else {
                "artifact belongs to another session owner"
            };
            return Err(Error::new(ErrorCode::PolicyDenied, message));
        }
        let offset = request
            .parameters
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let inline_maximum = (self.config.limits.tool_response_bytes / 4).clamp(1, 64 * 1024);
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(inline_maximum as u64)
            .min(inline_maximum as u64) as usize;
        if max_bytes == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "artifact max_bytes must be positive",
            ));
        }
        // 2026-08-28: Inlining a complete large artifact caused the outer
        // response limiter to replace it with another artifact. Page raw bytes
        // below the envelope budget instead.
        let (bytes, total_bytes) = self.artifacts.get_range(&uri, offset, max_bytes)?;
        let next_offset = offset + bytes.len() as u64;
        Ok(json!({
            "uri": uri,
            "size": total_bytes,
            "sensitivity": metadata.sensitivity,
            "max_page_bytes": inline_maximum,
            "offset": offset,
            "next_offset": next_offset,
            "data_base64": BASE64.encode(bytes),
            "truncated": next_offset < total_bytes
        }))
    }

    async fn events_wait(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let after = request
            .parameters
            .get("after_event_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // 2026-08-28: Reading state before subscribing lost an event emitted
        // in the gap and left a waiter blocked until timeout. Subscribe first,
        // then use state as the coalescing check for that race window.
        let mut events = entry.handle.subscribe();
        let current = entry.handle.state();
        if current.event_seq > after {
            return Ok(json!({ "state": current, "coalesced": true }));
        }
        let timeout_ms = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5_000);
        if timeout_ms == 0 || timeout_ms > 300_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "event timeout must be between 1 and 300000 ms",
            ));
        }
        let event = tokio::time::timeout(Duration::from_millis(timeout_ms), events.recv())
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout, "event wait timed out").retryable())?
            .map_err(|error| {
                let current = entry.handle.state();
                // 2026-08-29: Typed EVENT_GAP errors were visible to callers
                // but absent from operational metrics, hiding resync pressure.
                if matches!(&error, tokio::sync::broadcast::error::RecvError::Lagged(_)) {
                    self.metrics.event_gap();
                }
                event_receive_error(error, &current.session_id.0, after, current.event_seq)
            })?;
        Ok(serde_json::to_value(event)?)
    }

    async fn raw_console(&self, request: &ApiRequest) -> Result<Value> {
        self.metrics.raw_command();
        let command_text = string(&request.parameters, "command")?;
        validate_console_command(&command_text)?;
        let entry = self.entry(required_session(request)?).await?;
        let timeout = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(2_000);
        if timeout == 0 || timeout > 60_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw command timeout must be between 1 and 60000 ms",
            ));
        }
        // 2026-08-28: Invalid raw arguments used to taint state before any
        // command was sent. Record the effect only after validation succeeds.
        entry
            .handle
            .record_event(DomainEvent::ConsistencyTainted {
                reason: format!(
                    "raw console command executed: {}",
                    first_word(&command_text)
                ),
            })
            .await?;
        let reply = entry
            .handle
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(command_text),
                Duration::from_millis(timeout),
            )
            .await?;
        let reconciliation = self.reconcile_session(&entry, false).await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        }))
    }

    async fn raw_mi(&self, request: &ApiRequest) -> Result<Value> {
        self.metrics.raw_command();
        let name = string(&request.parameters, "command")?;
        if raw_mi_is_denied(&name) {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "raw MI command bypasses a protected host or target boundary",
            ));
        }
        let managed = raw_mi_is_managed(&name);
        let entry = self.entry(required_session(request)?).await?;
        let mut command = MiCommand::new(name.clone())?;
        let arguments = request
            .parameters
            .get("arguments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if arguments.len() > 64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw MI accepts at most 64 arguments",
            ));
        }
        let mut argument_bytes = 0usize;
        for argument in arguments {
            let (kind, value) = if let Some(value) = argument.as_str() {
                ("string", value.to_owned())
            } else {
                (
                    argument
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("string"),
                    string(&argument, "value")?,
                )
            };
            argument_bytes = argument_bytes.saturating_add(value.len());
            if argument_bytes > 16 * 1024 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "raw MI arguments exceed 16384 bytes",
                ));
            }
            command = match kind {
                "bare" => command.bare(value)?,
                "string" => command.string(value),
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "raw MI argument kind must be bare or string",
                    ));
                }
            };
        }
        let timeout = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(2_000);
        if timeout == 0 || timeout > 60_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw command timeout must be between 1 and 60000 ms",
            ));
        }
        entry
            .handle
            .record_event(if managed {
                DomainEvent::ConsistencyDirty {
                    reason: format!("managed raw MI command executed: {name}"),
                }
            } else {
                DomainEvent::ConsistencyTainted {
                    reason: format!("unknown raw MI command executed: {name}"),
                }
            })
            .await?;
        let reply = entry
            .handle
            .command_with_timeout(command, Duration::from_millis(timeout))
            .await?;
        let reconciliation = self.reconcile_session(&entry, managed).await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        }))
    }

    pub(crate) async fn reconcile_session(
        &self,
        entry: &SessionEntry,
        restore_clean: bool,
    ) -> Result<Value> {
        self.metrics.reconciliation();
        let can_restore = restore_clean
            && entry.handle.state().consistency != crate::domain::Consistency::Tainted;
        if can_restore {
            entry
                .handle
                .record_event(DomainEvent::ConsistencyReconciling)
                .await?;
        }
        let mut warnings = Vec::new();
        let groups = reconciliation_command(
            &entry.handle,
            MiCommand::new("-list-thread-groups")?
                .bare("--recurse")?
                .bare("1")?,
            "thread groups",
            &mut warnings,
        )
        .await;
        let threads = reconciliation_command(
            &entry.handle,
            MiCommand::new("-thread-info")?,
            "threads",
            &mut warnings,
        )
        .await;
        let breakpoints = reconciliation_command(
            &entry.handle,
            MiCommand::new("-break-list")?,
            "breakpoints",
            &mut warnings,
        )
        .await;
        let libraries = reconciliation_command(
            &entry.handle,
            MiCommand::new("-file-list-shared-libraries")?,
            "shared libraries",
            &mut warnings,
        )
        .await;

        if let Some(reply) = &groups {
            reconcile_inferiors(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &threads {
            reconcile_threads(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &breakpoints {
            reconcile_breakpoints(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &libraries {
            reconcile_libraries(&entry.handle, &reply.record).await?;
        }
        let capabilities = match entry.handle.refresh_target_capabilities().await {
            Ok(capabilities) => Some(capabilities),
            Err(error) => {
                warnings.push(format!("target features: {error}"));
                None
            }
        };
        if can_restore && (groups.is_none() || threads.is_none() || breakpoints.is_none()) {
            entry
                .handle
                .record_event(DomainEvent::ConsistencyLost {
                    reason: "reconciliation could not recover required registries".into(),
                })
                .await?;
            return Err(Error::new(
                ErrorCode::ConsistencyLost,
                "reconciliation could not recover required registries",
            ));
        }
        entry
            .handle
            .record_event(DomainEvent::ConsistencyRestored {
                warnings: warnings.clone(),
            })
            .await?;
        Ok(json!({
            "status": if can_restore { "clean" } else { "tainted" },
            "warnings": warnings,
            "capabilities": capabilities,
            "managed_surface": ["inferiors", "threads", "breakpoints", "libraries", "target_features"]
        }))
    }

    pub(crate) fn workspace_path(
        &self,
        value: &str,
        directory: bool,
    ) -> Result<std::path::PathBuf> {
        let path = std::fs::canonicalize(value).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("cannot canonicalize path {value:?}: {error}"),
            )
        })?;
        if directory != path.is_dir() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                if directory {
                    "path is not a directory"
                } else {
                    "path is not a file"
                },
            ));
        }
        let allowed = self
            .config
            .security
            .workspace_roots
            .iter()
            .any(|root| std::fs::canonicalize(root).is_ok_and(|root| path.starts_with(root)));
        if !allowed {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "path escapes configured workspace roots",
            ));
        }
        Ok(path)
    }

    fn breakpoint_location(
        &self,
        parameters: &Value,
        state: &crate::domain::SessionState,
    ) -> Result<(String, Option<(String, u64)>)> {
        let location = parameters.get("location").unwrap_or(parameters);
        if let Some(source) = location.get("source") {
            // 2026-08-28: Source breakpoints previously bypassed workspace
            // canonicalization even though every other target path was checked.
            let path = self.workspace_path(&string(source, "path")?, false)?;
            return Ok((
                format!("{}:{}", path.to_string_lossy(), unsigned(source, "line")?),
                None,
            ));
        }
        if let Some(module_offset) = location.get("module_offset") {
            let module = string(module_offset, "module")?;
            let offset = crate::domain::Address::parse(&string(module_offset, "offset")?)?;
            let offset = u64::from_str_radix(&offset.as_str()[2..], 16)
                .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid module offset"))?;
            // 2026-08-28: GDB does not report a loader-launched stripped PIE
            // as a shared library, so `module+offset` remained pending. The
            // existing local mapping provider supplies the actual load bias.
            if let Some(address) = live_module_offset(state, &module, offset)? {
                return Ok((format!("*{address}"), None));
            }
            return Ok((breakpoint_location(parameters)?, Some((module, offset))));
        }
        Ok((breakpoint_location(parameters)?, None))
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StartPolicy {
    // 2026-08-28: The old "entry" name mapped to GDB starti, which can stop
    // in the dynamic loader. Retain it only as an input alias for the precise
    // first-instruction policy.
    #[serde(alias = "entry")]
    FirstInstruction,
    Main,
    None,
}

impl StartPolicy {
    fn command(self) -> Result<MiCommand> {
        match self {
            Self::FirstInstruction => MiCommand::new("-interpreter-exec")?
                .bare("console")
                .map(|command| command.string("starti")),
            Self::Main => MiCommand::new("-exec-run")?.bare("--start"),
            Self::None => MiCommand::new("-exec-run"),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::FirstInstruction => "first_instruction",
            Self::Main => "main",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitSpec {
    until: String,
    #[serde(default = "default_wait_ms")]
    timeout_ms: u64,
}

impl WaitSpec {
    fn validate(&self) -> Result<()> {
        // 2026-08-28: Wait validation once ran after the associated control
        // command, so invalid input could resume or kill a target before erroring.
        if !matches!(
            self.until.as_str(),
            "accepted" | "running" | "stopped" | "snapshot" | "exited"
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unknown wait condition",
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "wait timeout must be between 1 and 300000 ms",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
struct ObservationBudget {
    max_calls: usize,
    max_frames: usize,
    max_values: usize,
    max_memory_bytes: usize,
    max_instructions: usize,
    max_context_bytes: usize,
    wall_time_ms: u64,
}

impl Default for ObservationBudget {
    fn default() -> Self {
        Self {
            max_calls: 32,
            max_frames: 16,
            max_values: 16,
            max_memory_bytes: 64 * 1024,
            max_instructions: 64,
            max_context_bytes: 64 * 1024,
            wall_time_ms: 10_000,
        }
    }
}

impl ObservationBudget {
    fn validate(&self, config: &crate::config::Config) -> Result<()> {
        if self.max_calls == 0
            || self.max_calls > 256
            || self.max_frames == 0
            || self.max_frames > config.limits.stack_frames
            || self.max_values == 0
            || self.max_values > 1_000
            || self.max_memory_bytes == 0
            || self.max_memory_bytes > config.limits.memory_read_bytes
            || self.max_instructions == 0
            || self.max_instructions > 1_024
            || self.max_context_bytes == 0
            || self.max_context_bytes > config.limits.tool_response_bytes
            || self.wall_time_ms == 0
            || self.wall_time_ms > 60_000
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "observation budget is outside configured limits",
            ));
        }
        Ok(())
    }
}

fn event_receive_error(
    error: tokio::sync::broadcast::error::RecvError,
    session_id: &str,
    requested_after: u64,
    current_event_seq: u64,
) -> Error {
    // 2026-08-29: Collapsing lag and closure into INTERNAL gave clients no
    // way to distinguish a recoverable cursor gap from a terminal stream.
    match error {
        tokio::sync::broadcast::error::RecvError::Lagged(skipped) => Error::new(
            ErrorCode::EventGap,
            format!("event subscriber missed {skipped} events"),
        )
        .retryable()
        .with_details(json!({
            "requested_after": requested_after,
            "dropped_events": skipped,
            "available_after": current_event_seq,
            "current_event_seq": current_event_seq,
            "resync": format!("gdbai://session/{session_id}/status")
        })),
        tokio::sync::broadcast::error::RecvError::Closed => {
            Error::new(ErrorCode::StreamClosed, "session event stream closed").with_details(json!({
                "current_event_seq": current_event_seq,
                "session": format!("gdbai://session/{session_id}/status")
            }))
        }
    }
}

fn default_wait_ms() -> u64 {
    5_000
}

fn wait_spec(parameters: &Value) -> Result<Option<WaitSpec>> {
    let wait: Option<WaitSpec> = parameters
        .get("wait")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
    if let Some(wait) = &wait {
        wait.validate()?;
    }
    Ok(wait)
}

async fn wait_if_requested(
    handle: &SessionHandle,
    wait: Option<WaitSpec>,
    baseline: Option<&crate::domain::SessionState>,
) -> Result<crate::domain::SessionState> {
    match wait {
        Some(wait) => apply_wait(handle, wait, baseline).await,
        None => Ok(handle.state()),
    }
}

async fn apply_wait(
    handle: &SessionHandle,
    wait: WaitSpec,
    baseline: Option<&crate::domain::SessionState>,
) -> Result<crate::domain::SessionState> {
    let baseline = baseline.map(WaitBaseline::from);
    apply_wait_baseline(handle, wait, baseline.as_ref(), None).await
}

async fn apply_wait_baseline(
    handle: &SessionHandle,
    wait: WaitSpec,
    baseline: Option<&WaitBaseline>,
    expected_execution_epoch: Option<u64>,
) -> Result<crate::domain::SessionState> {
    wait.validate()?;
    let until = match wait.until.as_str() {
        "accepted" => return Ok(handle.state()),
        "running" => WaitUntil::Running,
        "stopped" => WaitUntil::Stopped,
        "snapshot" => WaitUntil::Snapshot,
        "exited" => WaitUntil::Exited,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unknown wait condition",
            ));
        }
    };
    let timeout = Duration::from_millis(wait.timeout_ms);
    match (baseline, expected_execution_epoch) {
        (Some(baseline), Some(expected_execution_epoch)) => {
            handle
                .wait_for_operation(until, timeout, baseline, expected_execution_epoch)
                .await
        }
        (Some(baseline), None) => handle.wait_after_baseline(until, timeout, baseline).await,
        (None, _) => handle.wait(until, timeout).await,
    }
}

fn required_session(request: &ApiRequest) -> Result<&str> {
    request
        .session_id
        .as_deref()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "method requires session_id"))
}

fn parameters<T: for<'de> Deserialize<'de>>(request: &ApiRequest) -> Result<T> {
    let mut parameters = request.parameters.clone();
    // 2026-08-28: Strict operation structs rejected the lease and revision
    // controls that the shared Gateway contract adds to every parameter map.
    // Consume those transport controls before decoding operation-owned fields.
    if let Some(parameters) = parameters.as_object_mut() {
        parameters.remove("lease_id");
        parameters.remove("accept_latest_revision");
    }
    serde_json::from_value(parameters)
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn string(value: &Value, name: &str) -> Result<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("{name} is required")))
}

fn unsigned(value: &Value, name: &str) -> Result<u64> {
    value.get(name).and_then(Value::as_u64).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("{name} must be unsigned"),
        )
    })
}

fn bool_value(value: &Value, name: &str, default: bool) -> bool {
    value.get(name).and_then(Value::as_bool).unwrap_or(default)
}

fn bounded_limit(value: &Value, default: usize, maximum: usize) -> Result<usize> {
    let limit = value
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    if limit == 0 || limit > maximum as u64 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("limit must be between 1 and {maximum}"),
        ));
    }
    Ok(limit as usize)
}

fn bounded_offset(value: &Value, maximum: usize, subject: &str) -> Result<usize> {
    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
    if offset > maximum as u64 {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            format!("{subject} offset must not exceed {maximum}"),
        ));
    }
    Ok(offset as usize)
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<()> {
    if environment.len() > 256 {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            "too many environment variables",
        ));
    }
    for (name, value) in environment {
        let mut bytes = name.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || value.len() > 64 * 1024
            || value.contains('\0')
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid environment entry {name:?}"),
            ));
        }
    }
    Ok(())
}

fn inherited_environment(allowlist: &[String]) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    for name in allowlist {
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        let value = value.into_string().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("inherited environment variable {name:?} is not UTF-8"),
            )
        })?;
        environment.insert(name.clone(), value);
    }
    Ok(environment)
}

fn validate_argv(arguments: &[String]) -> Result<()> {
    if arguments.len() > 256
        || arguments
            .iter()
            .any(|argument| argument.len() > 64 * 1024 || argument.contains('\0'))
    {
        Err(Error::new(
            ErrorCode::OutputLimit,
            "argv exceeds 256 entries or 64 KiB per argument",
        ))
    } else {
        Ok(())
    }
}

fn context_options(
    mut command: MiCommand,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<MiCommand> {
    if let Some(stop) = parameters.get("stop_id").and_then(Value::as_str) {
        state.require_stop(&StopId(stop.to_owned()))?;
    }
    let requested_thread = parameters
        .get("thread_id")
        .and_then(Value::as_str)
        .map(|public_thread| current_backend_thread(state, public_thread))
        .transpose()?;
    let mut frame_level = parameters.get("frame_level").and_then(Value::as_u64);
    let frame_thread = if let Some(frame) = parameters.get("frame_id").and_then(Value::as_str) {
        let stop = state.stop_id.as_ref().ok_or_else(|| {
            Error::new(ErrorCode::TargetRunning, "frame requires a stopped target")
        })?;
        let (backend_thread, level) = state
            .inferiors
            .values()
            .flat_map(|inferior| inferior.threads.values())
            .find_map(|thread| {
                frame
                    .strip_prefix(&format!("frm_{}_{}_", thread.id.0, stop.0))
                    .and_then(|level| level.parse::<u64>().ok())
                    .map(|level| (thread.backend_id.clone(), level))
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::StaleContext,
                    "frame handle is not current for this stop",
                )
            })?;
        frame_level = Some(level);
        Some(backend_thread)
    } else {
        None
    };
    if let (Some(requested), Some(frame)) = (&requested_thread, &frame_thread)
        && requested != frame
    {
        return Err(Error::new(
            ErrorCode::StaleContext,
            "thread and frame handles refer to different threads",
        ));
    }
    // 2026-08-28: Frame handles supplied only a frame level to GDB, leaving
    // their owning thread implicit. On a multi-thread stop this could inspect
    // a different selected thread. Encode the frame's thread and stop focus.
    let backend_thread = requested_thread.or(frame_thread).or_else(|| {
        command_uses_stop_focus(&command.name)
            .then_some(state.stopped_thread_id.as_ref())
            .flatten()
            .and_then(|thread| current_backend_thread(state, &thread.0).ok())
    });
    let mut contextual = MiCommand::new(command.name.clone())?;
    if let Some(backend_thread) = backend_thread {
        contextual = contextual.bare("--thread")?.bare(backend_thread)?;
    }
    if frame_level.is_none() && command_uses_top_frame(&command.name) {
        frame_level = Some(0);
    }
    if let Some(level) = frame_level {
        contextual = contextual.bare("--frame")?.bare(level.to_string())?;
    }
    // 2026-08-28: Context options belong before positional MI arguments.
    // Several callers build expressions first, so appending options made
    // explicit context syntactically ineffective or invalid.
    contextual.arguments.append(&mut command.arguments);
    Ok(contextual)
}

fn current_backend_thread(
    state: &crate::domain::SessionState,
    public_thread: &str,
) -> Result<String> {
    state
        .inferiors
        .values()
        .flat_map(|inferior| inferior.threads.values())
        .find(|thread| thread.id.0 == public_thread)
        .map(|thread| thread.backend_id.clone())
        .ok_or_else(|| Error::new(ErrorCode::StaleContext, "thread handle is not current"))
}

fn command_uses_stop_focus(command: &str) -> bool {
    matches!(
        command,
        "-exec-step"
            | "-exec-next"
            | "-exec-finish"
            | "-exec-step-instruction"
            | "-exec-next-instruction"
            | "-exec-until"
            | "-stack-info-frame"
            | "-stack-list-frames"
            | "-stack-list-variables"
            | "-stack-list-arguments"
            | "-data-evaluate-expression"
            | "-data-list-register-values"
            | "-var-create"
    )
}

fn command_uses_top_frame(command: &str) -> bool {
    matches!(
        command,
        "-stack-info-frame"
            | "-stack-list-variables"
            | "-data-evaluate-expression"
            | "-data-list-register-values"
            | "-var-create"
    )
}

fn require_stopped_context(parameters: &Value, state: &crate::domain::SessionState) -> Result<()> {
    let stop = state.stop_id.as_ref().ok_or_else(|| {
        Error::new(
            ErrorCode::TargetRunning,
            "inspection requires stopped target",
        )
    })?;
    if let Some(expected) = parameters.get("stop_id").and_then(Value::as_str) {
        state.require_stop(&StopId(expected.to_owned()))?;
    } else if parameters
        .get("accept_current_stop")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(Error::new(
            ErrorCode::StaleContext,
            format!("inspection requires stop_id (current is {stop})"),
        ));
    }
    Ok(())
}

fn breakpoint_location(parameters: &Value) -> Result<String> {
    let location = parameters.get("location").unwrap_or(parameters);
    if let Some(function) = location.get("function").and_then(Value::as_str) {
        return Ok(function.to_owned());
    }
    if let Some(address) = location.get("address").and_then(Value::as_str) {
        crate::domain::Address::parse(address)?;
        return Ok(format!("*{address}"));
    }
    if let Some(expression) = location.get("expression").and_then(Value::as_str) {
        return Ok(expression.to_owned());
    }
    if let Some(module) = location.get("module_offset") {
        return Ok(format!(
            "{}+{}",
            string(module, "module")?,
            string(module, "offset")?
        ));
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "breakpoint location is required",
    ))
}

fn breakpoint_scope(
    mut command: MiCommand,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<MiCommand> {
    let thread = parameters.get("thread_id").and_then(Value::as_str);
    let inferior = parameters.get("inferior_id").and_then(Value::as_str);
    if (thread.is_some() || inferior.is_some()) && command.name != "-break-insert" {
        return Err(Error::new(
            ErrorCode::CapabilityMissing,
            "this GDB target only supports scoped software or hardware breakpoints",
        ));
    }
    if let Some(thread_id) = thread {
        let backend_thread = state
            .inferiors
            .values()
            .flat_map(|inferior| inferior.threads.values())
            .find(|thread| thread.id.0 == thread_id)
            .map(|thread| thread.backend_id.clone())
            .ok_or_else(|| Error::new(ErrorCode::StaleContext, "thread handle is not current"))?;
        command = command.bare("-p")?.bare(backend_thread)?;
    }
    if let Some(inferior_id) = inferior {
        let backend_inferior = state
            .inferiors
            .values()
            .find(|inferior| inferior.id.0 == inferior_id)
            .map(|inferior| inferior.backend_id.clone())
            .ok_or_else(|| Error::new(ErrorCode::StaleContext, "inferior handle is not current"))?;
        command = command.bare("--thread-group")?.bare(backend_inferior)?;
    }
    Ok(command)
}

fn breakpoint_number(entry: &SessionEntry, parameters: &Value) -> Result<String> {
    if let Some(number) = parameters.get("backend_number").and_then(Value::as_str) {
        return Ok(number.to_owned());
    }
    let public = string(parameters, "breakpoint_id")?;
    entry
        .handle
        .state()
        .breakpoints
        .values()
        .find(|breakpoint| breakpoint.id.0 == public)
        .map(|breakpoint| breakpoint.backend_number.clone())
        .ok_or_else(|| Error::new(ErrorCode::NotFound, "breakpoint not found"))
}

async fn optional_command(
    handle: &SessionHandle,
    command: MiCommand,
    name: &str,
    warnings: &mut Vec<Value>,
) -> Option<CommandReply> {
    match handle.command(command).await {
        Ok(reply) => Some(reply),
        Err(error) => {
            warnings.push(json!({ "code": format!("{}_UNAVAILABLE", name.to_uppercase()), "message": error.to_string() }));
            None
        }
    }
}

async fn reconciliation_command(
    handle: &SessionHandle,
    command: MiCommand,
    name: &str,
    warnings: &mut Vec<String>,
) -> Option<CommandReply> {
    match handle.command(command).await {
        Ok(reply) => Some(reply),
        Err(error) => {
            warnings.push(format!("{name}: {error}"));
            None
        }
    }
}

async fn reconcile_inferiors(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(groups) = MiResult::find(record.results(), "groups") else {
        return Ok(());
    };
    let observed = aggregate_items(groups, "group")
        .into_iter()
        .filter_map(|fields| {
            Some((
                MiResult::find_str(fields, "id")?.to_owned(),
                MiResult::find_str(fields, "pid").and_then(|pid| pid.parse().ok()),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle.state().inferiors.keys().cloned().collect::<Vec<_>>();
    for (backend_id, pid) in &observed {
        handle
            .record_event(DomainEvent::InferiorAdded {
                backend_id: backend_id.clone(),
                pid: *pid,
            })
            .await?;
    }
    for backend_id in existing {
        if !observed.contains_key(&backend_id) {
            handle
                .record_event(DomainEvent::InferiorRemoved { backend_id })
                .await?;
        }
    }
    Ok(())
}

async fn reconcile_threads(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(threads) = MiResult::find(record.results(), "threads") else {
        return Ok(());
    };
    let fallback_group = handle
        .state()
        .inferiors
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "i1".into());
    let observed = aggregate_items(threads, "thread")
        .into_iter()
        .filter_map(|fields| {
            Some((
                MiResult::find_str(fields, "id")?.to_owned(),
                MiResult::find_str(fields, "group-id")
                    .unwrap_or(&fallback_group)
                    .to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle
        .state()
        .inferiors
        .values()
        .flat_map(|inferior| {
            inferior
                .threads
                .keys()
                .cloned()
                .map(|thread| (thread, inferior.backend_id.clone()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for (backend_thread, backend_inferior) in &observed {
        handle
            .record_event(DomainEvent::ThreadCreated {
                backend_inferior: backend_inferior.clone(),
                backend_thread: backend_thread.clone(),
            })
            .await?;
    }
    for (backend_thread, backend_inferior) in existing {
        if !observed.contains_key(&backend_thread) {
            handle
                .record_event(DomainEvent::ThreadExited {
                    backend_inferior: Some(backend_inferior),
                    backend_thread,
                })
                .await?;
        }
    }
    Ok(())
}

async fn reconcile_breakpoints(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(table) =
        MiResult::find(record.results(), "BreakpointTable").and_then(MiValue::results)
    else {
        return Ok(());
    };
    let Some(body) = MiResult::find(table, "body") else {
        return Ok(());
    };
    let observed = aggregate_items(body, "bkpt")
        .into_iter()
        .filter_map(|fields| {
            let number = MiResult::find_str(fields, "number")?.to_owned();
            let enabled = MiResult::find_str(fields, "enabled").is_none_or(|value| value == "y");
            let pending = MiResult::find_str(fields, "pending").is_some_and(|value| value == "y")
                || MiResult::find_str(fields, "addr") == Some("<PENDING>");
            Some((number, (enabled, pending)))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle
        .state()
        .breakpoints
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for fields in aggregate_items(body, "bkpt") {
        synchronize_breakpoint(handle, fields).await?;
    }
    for backend_number in existing {
        if !observed.contains_key(&backend_number) {
            handle
                .record_event(DomainEvent::BreakpointDeleted { backend_number })
                .await?;
        }
    }
    Ok(())
}

async fn synchronize_breakpoint(handle: &SessionHandle, fields: &[MiResult]) -> Result<()> {
    let Some(backend_number) = MiResult::find_str(fields, "number").map(str::to_owned) else {
        return Ok(());
    };
    let enabled = MiResult::find_str(fields, "enabled").is_none_or(|value| value == "y");
    let pending = MiResult::find_str(fields, "pending").is_some_and(|value| value == "y")
        || MiResult::find_str(fields, "addr") == Some("<PENDING>");
    let previous = handle.state().breakpoints.get(&backend_number).cloned();
    // 2026-08-28: Breakpoint reads relied on optional notifications and then
    // emitted unconditional modifications, leaving stale registries or
    // advancing revisions on every list. Synchronize only observed changes.
    if previous
        .as_ref()
        .is_none_or(|breakpoint| breakpoint.enabled != enabled || breakpoint.pending != pending)
    {
        let event = if previous.is_some() {
            DomainEvent::BreakpointModified {
                backend_number: backend_number.clone(),
                enabled,
                pending,
            }
        } else {
            DomainEvent::BreakpointCreated {
                backend_number: backend_number.clone(),
                enabled,
                pending,
            }
        };
        handle.record_event(event).await?;
    }
    let state = handle.state();
    let existing = state
        .breakpoints
        .get(&backend_number)
        .map(|breakpoint| breakpoint.locations.clone())
        .unwrap_or_default();
    let public_id = state
        .breakpoints
        .get(&backend_number)
        .map(|breakpoint| breakpoint.id.0.clone())
        .unwrap_or_else(|| format!("bp_{}", backend_number.replace('.', "_")));
    let location_fields = MiResult::find(fields, "locations")
        .map(|locations| aggregate_items(locations, "location"))
        .unwrap_or_default();
    let location_fields = if location_fields.is_empty() && !pending {
        vec![fields]
    } else {
        location_fields
    };
    let locations = location_fields
        .into_iter()
        .enumerate()
        .map(|(index, location)| {
            let number = MiResult::find_str(location, "number")
                .unwrap_or(&backend_number)
                .to_owned();
            BreakpointLocationState {
                id: existing
                    .iter()
                    .find(|existing| existing.backend_number == number)
                    .map(|existing| existing.id.clone())
                    .unwrap_or_else(|| {
                        format!("bpl_{public_id}_{}_{}", state.event_seq, index + 1)
                    }),
                backend_number: number,
                address: MiResult::find_str(location, "addr")
                    .filter(|address| *address != "<PENDING>")
                    .map(str::to_owned),
                function: MiResult::find_str(location, "func").map(str::to_owned),
            }
        })
        .collect();
    if existing != locations {
        handle
            .record_event(DomainEvent::BreakpointLocations {
                backend_number,
                locations,
            })
            .await
    } else {
        Ok(())
    }
}

async fn reconcile_libraries(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(libraries) = MiResult::find(record.results(), "shared-libraries") else {
        return Ok(());
    };
    let observed = aggregate_items(libraries, "library")
        .into_iter()
        .filter_map(|fields| {
            let id = MiResult::find_str(fields, "id")
                .or_else(|| MiResult::find_str(fields, "target-name"))?
                .to_owned();
            Some((id, fields))
        })
        .collect::<Vec<_>>();
    let observed_ids = observed
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let existing = handle.state().modules.keys().cloned().collect::<Vec<_>>();
    for (id, fields) in observed {
        handle
            .record_event(DomainEvent::LibraryLoaded {
                id,
                target_name: MiResult::find_str(fields, "target-name").map(str::to_owned),
                host_name: MiResult::find_str(fields, "host-name").map(str::to_owned),
                symbols_loaded: MiResult::find_str(fields, "symbols-loaded")
                    .map(|value| value == "1"),
            })
            .await?;
    }
    for id in existing {
        if !observed_ids.contains(&id) {
            handle
                .record_event(DomainEvent::LibraryUnloaded { id })
                .await?;
        }
    }
    Ok(())
}

async fn safe_evaluate_command(handle: &SessionHandle, command: MiCommand) -> Result<CommandReply> {
    handle.safe_evaluate(command).await
}

async fn kernel_current_text(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<(String, u64)> {
    let reply = entry
        .handle
        .command(MiCommand::new("-data-list-register-names")?)
        .await?;
    let names = result_string_list(&reply.record, "register-names");
    if find_register_name(&names, "gs_base").is_some() {
        // 2026-08-28: Newer x86 kernels moved current_task into pcpu_hot,
        // while older distribution symbols expose the standalone per-CPU
        // variable. Try only the two documented layouts and preserve any
        // timeout or transport failure from the first evaluation.
        let modern = "*(struct task_struct **)((unsigned long)$gs_base+(unsigned long)&pcpu_hot.current_task)";
        match kernel_text(entry, parameters, state, modern).await {
            Ok(value) => Ok(value),
            Err(error) if error.code == ErrorCode::GdbError => kernel_text(
                entry,
                parameters,
                state,
                "*(struct task_struct **)((unsigned long)$gs_base+(unsigned long)&current_task)",
            )
            .await,
            Err(error) => Err(error),
        }
    } else if let Some(sp_el0) = find_register_name(&names, "sp_el0") {
        kernel_text(
            entry,
            parameters,
            state,
            &format!("(struct task_struct *)${sp_el0}"),
        )
        .await
    } else {
        Err(Error::new(
            ErrorCode::CapabilityMissing,
            "current task requires x86-64 gs_base or AArch64 sp_el0",
        ))
    }
}

async fn kernel_text(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
    expression: &str,
) -> Result<(String, u64)> {
    let command = context_options(
        MiCommand::new("-data-evaluate-expression")?.string(expression),
        parameters,
        state,
    )?;
    let reply = safe_evaluate_command(&entry.handle, command).await?;
    let value = result_text(&reply.record, "value")
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB omitted expression value"))?;
    Ok((value, reply.evidence_seq))
}

async fn kernel_address(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
    expression: &str,
) -> Result<(u64, u64)> {
    let (value, evidence_seq) = kernel_text(entry, parameters, state, expression).await?;
    Ok((parse_gdb_u64(&value)?, evidence_seq))
}

fn validate_expression(expression: &str) -> Result<()> {
    if expression.is_empty() || expression.len() > 4_096 || expression.contains('\0') {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "expression must contain 1 to 4096 bytes and no NUL",
        ));
    }

    // 2026-08-29: Legacy GDB cannot disable register writes after a live
    // inferior exists. Reject mutation and call syntax before GDB sees it;
    // backend guards still independently block inferior calls and memory.
    let bytes = expression.as_bytes();
    let mut quote = None;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            continue;
        }

        let next = bytes.get(index + 1).copied();
        if byte == b'/' && matches!(next, Some(b'/' | b'*')) {
            return unsafe_expression();
        }
        if matches!((byte, next), (b'+', Some(b'+')) | (b'-', Some(b'-'))) {
            return unsafe_expression();
        }
        if byte == b'=' {
            let previous = index.checked_sub(1).and_then(|i| bytes.get(i)).copied();
            let before_previous = index.checked_sub(2).and_then(|i| bytes.get(i)).copied();
            let comparison = next == Some(b'=')
                || matches!(previous, Some(b'=' | b'!'))
                || matches!(previous, Some(b'<' | b'>')) && before_previous != previous;
            if !comparison {
                return unsafe_expression();
            }
        }
        if byte == b'(' {
            let prefix = expression[..index].trim_end();
            let Some(previous) = prefix.as_bytes().last().copied() else {
                continue;
            };
            if matches!(previous, b')' | b']') {
                return unsafe_expression();
            }
            if previous.is_ascii_alphanumeric() || previous == b'_' {
                let start = prefix
                    .rfind(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '_')
                    })
                    .map_or(0, |offset| offset + 1);
                if !matches!(
                    &prefix[start..],
                    "sizeof"
                        | "alignof"
                        | "_Alignof"
                        | "__alignof__"
                        | "typeof"
                        | "__typeof__"
                        | "decltype"
                ) {
                    return unsafe_expression();
                }
            }
        }
    }
    Ok(())
}

fn unsafe_expression() -> Result<()> {
    Err(Error::new(
        ErrorCode::PolicyDenied,
        "safe evaluation forbids calls and mutation operators",
    ))
}

async fn current_value_binding(
    entry: &SessionEntry,
    request: &ApiRequest,
    state: &crate::domain::SessionState,
) -> Result<ValueBinding> {
    require_stopped_context(&request.parameters, state)?;
    let binding = entry
        .handle
        .value_binding(string(&request.parameters, "value_id")?)
        .await?;
    state.require_stop(&binding.stop_id)?;
    Ok(binding)
}

fn result_text(record: &MiRecord, name: &str) -> Option<String> {
    MiResult::find_str(record.results(), name).map(str::to_owned)
}

fn frame_summary(record: &MiRecord) -> Option<FrameSummary> {
    let fields = MiResult::find(record.results(), "frame")?.results()?;
    Some(frame_summary_fields(fields))
}

fn frame_summary_fields(fields: &[MiResult]) -> FrameSummary {
    FrameSummary {
        level: MiResult::find_str(fields, "level")
            .and_then(|level| level.parse().ok())
            .unwrap_or(0),
        address: MiResult::find_str(fields, "addr").map(str::to_owned),
        function: MiResult::find_str(fields, "func").map(str::to_owned),
        source: MiResult::find_str(fields, "fullname")
            .or_else(|| MiResult::find_str(fields, "file"))
            .map(str::to_owned),
        line: MiResult::find_str(fields, "line").and_then(|line| line.parse().ok()),
    }
}

fn normalized_threads(record: &MiRecord, state: &crate::domain::SessionState) -> Vec<Value> {
    let Some(threads) = MiResult::find(record.results(), "threads") else {
        return Vec::new();
    };
    aggregate_items(threads, "thread")
        .into_iter()
        .filter_map(|fields| {
            let backend_id = MiResult::find_str(fields, "id")?;
            let thread = state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| thread.backend_id == backend_id);
            Some(json!({
                "thread_id": thread.map(|thread| &thread.id),
                "backend_id": backend_id,
                "inferior_id": state.inferiors.values()
                    .find(|inferior| inferior.threads.contains_key(backend_id))
                    .map(|inferior| &inferior.id),
                "state": MiResult::find_str(fields, "state"),
                "name": MiResult::find_str(fields, "name"),
                "frame": MiResult::find(fields, "frame")
                    .and_then(MiValue::results)
                    .map(frame_summary_fields)
            }))
        })
        .collect()
}

fn normalized_frames(
    record: &MiRecord,
    state: &crate::domain::SessionState,
    parameters: &Value,
) -> Vec<Value> {
    let Some(stack) = MiResult::find(record.results(), "stack") else {
        return Vec::new();
    };
    // 2026-08-28: Assigning frames to the first non-running thread could
    // mint handles for a different thread than the explicit MI stop focus.
    let thread = parameters
        .get("thread_id")
        .and_then(Value::as_str)
        .and_then(|thread_id| {
            state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| thread.id.0 == thread_id)
        })
        .or_else(|| {
            let stopped = state.stopped_thread_id.as_ref()?;
            state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| &thread.id == stopped)
        });
    aggregate_items(stack, "frame")
        .into_iter()
        .map(|fields| {
            let frame = frame_summary_fields(fields);
            let frame_id = thread.and_then(|thread| {
                state
                    .stop_id
                    .as_ref()
                    .map(|stop| FrameId::new(&thread.id, stop, frame.level))
            });
            json!({
                "frame_id": frame_id,
                "level": frame.level,
                "address": frame.address,
                "function": frame.function,
                "source": frame.source.map(|path| json!({"path": path, "line": frame.line}))
            })
        })
        .collect()
}

fn normalized_variables(record: &MiRecord, name: &str) -> Vec<Value> {
    let Some(variables) = MiResult::find(record.results(), name) else {
        return Vec::new();
    };
    aggregate_items(variables, "variable")
        .into_iter()
        .map(|fields| {
            json!({
                "name": MiResult::find_str(fields, "name"),
                "type": MiResult::find_str(fields, "type"),
                "value": MiResult::find_str(fields, "value")
                    .map(|value| value.chars().take(16 * 1024).collect::<String>()),
                "dynamic": MiResult::find_str(fields, "dynamic") == Some("1")
            })
        })
        .collect()
}

fn normalized_arguments(record: &MiRecord) -> Vec<Value> {
    let Some(frames) = MiResult::find(record.results(), "stack-args") else {
        return Vec::new();
    };
    aggregate_items(frames, "frame")
        .into_iter()
        .map(|fields| {
            let arguments = MiResult::find(fields, "args")
                .map(|args| {
                    aggregate_items(args, "arg")
                        .into_iter()
                        .map(|fields| {
                            json!({
                                "name": MiResult::find_str(fields, "name"),
                                "type": MiResult::find_str(fields, "type"),
                                "value": MiResult::find_str(fields, "value")
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({
                "level": MiResult::find_str(fields, "level")
                    .and_then(|level| level.parse::<u64>().ok()),
                "arguments": arguments
            })
        })
        .collect()
}

fn normalized_modules(record: &MiRecord) -> Vec<Value> {
    let Some(modules) = MiResult::find(record.results(), "shared-libraries") else {
        return Vec::new();
    };
    aggregate_items(modules, "library")
        .into_iter()
        .map(|fields| {
            json!({
                "module_id": MiResult::find_str(fields, "id")
                    .or_else(|| MiResult::find_str(fields, "target-name")),
                "target_name": MiResult::find_str(fields, "target-name"),
                "host_name": MiResult::find_str(fields, "host-name"),
                "from": MiResult::find_str(fields, "from"),
                "to": MiResult::find_str(fields, "to"),
                "symbols_loaded": MiResult::find_str(fields, "symbols-loaded")
                    .map(|loaded| loaded == "1")
            })
        })
        .collect()
}

fn normalized_source_files(record: &MiRecord) -> Vec<Value> {
    let Some(files) = MiResult::find(record.results(), "files") else {
        return Vec::new();
    };
    aggregate_items(files, "file")
        .into_iter()
        .map(|fields| {
            json!({
                "file": MiResult::find_str(fields, "file"),
                "fullname": MiResult::find_str(fields, "fullname"),
                "debug_fully_read": MiResult::find_str(fields, "debug-fully-read")
                    .map(|read| read == "true")
            })
        })
        .collect()
}

fn disassembly_instructions(record: &MiRecord, current: Option<u64>) -> Vec<Value> {
    let mut instructions = Vec::new();
    for result in record.results() {
        collect_instructions(&result.value, None, None, current, &mut instructions);
    }
    instructions
}

fn collect_instructions(
    value: &MiValue,
    inherited_file: Option<&str>,
    inherited_line: Option<u64>,
    current: Option<u64>,
    output: &mut Vec<Value>,
) {
    match value {
        MiValue::Tuple(results) | MiValue::ResultList(results) => {
            let file = MiResult::find_str(results, "fullname")
                .or_else(|| MiResult::find_str(results, "file"))
                .or(inherited_file);
            let line = MiResult::find_str(results, "line")
                .and_then(|line| line.parse().ok())
                .or(inherited_line);
            if let (Some(address), Some(instruction)) = (
                MiResult::find_str(results, "address"),
                MiResult::find_str(results, "inst"),
            ) {
                let address_number = parse_address(address).ok();
                let (mnemonic, operands) = instruction
                    .split_once(char::is_whitespace)
                    .map_or((instruction, ""), |(mnemonic, operands)| {
                        (mnemonic, operands.trim())
                    });
                output.push(json!({
                    "address": address,
                    "offset": MiResult::find_str(results, "offset")
                        .and_then(|offset| offset.parse::<i64>().ok()),
                    "bytes": MiResult::find_str(results, "opcodes"),
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "function": MiResult::find_str(results, "func-name"),
                    "source": file.map(|file| json!({"path": file, "line": line})),
                    "current": address_number.is_some() && address_number == current
                }));
            }
            for result in results {
                collect_instructions(&result.value, file, line, current, output);
            }
        }
        MiValue::ValueList(values) => {
            for value in values {
                collect_instructions(value, inherited_file, inherited_line, current, output);
            }
        }
        MiValue::Const(_) => {}
    }
}

fn result_string_list(record: &MiRecord, name: &str) -> Vec<String> {
    let Some(MiValue::ValueList(values)) = MiResult::find(record.results(), name) else {
        return Vec::new();
    };
    values
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .collect()
}

fn aggregate_items<'a>(value: &'a MiValue, result_name: &str) -> Vec<&'a [MiResult]> {
    match value {
        MiValue::ValueList(values) => values.iter().filter_map(|value| value.results()).collect(),
        MiValue::ResultList(results) => results
            .iter()
            .filter(|result| result.name == result_name)
            .filter_map(|result| result.value.results())
            .collect(),
        MiValue::Tuple(results) => vec![results],
        MiValue::Const(_) => Vec::new(),
    }
}

fn memory_contents(record: &MiRecord) -> Result<Vec<u8>> {
    let memory = MiResult::find(record.results(), "memory").ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            "GDB memory response has no memory field",
        )
    })?;
    let mut bytes = Vec::new();
    for item in aggregate_items(memory, "memory") {
        if let Some(contents) = MiResult::find_str(item, "contents") {
            bytes.extend(hex_decode(contents)?);
        }
    }
    Ok(bytes)
}

// 2026-08-28: A single 16 MiB read expands beyond the MI record limit as
// hexadecimal text. Keep backend records bounded while preserving one API read.
async fn read_memory_bytes(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
    start: u64,
    length: usize,
    allow_partial: bool,
) -> Result<(Vec<u8>, u64)> {
    handle
        .stable_observation(
            expected,
            Box::pin(read_memory_bytes_in_observation(
                handle,
                expected,
                start,
                length,
                allow_partial,
            )),
        )
        .await
}

async fn read_memory_bytes_in_observation(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
    start: u64,
    length: usize,
    allow_partial: bool,
) -> Result<(Vec<u8>, u64)> {
    const CHUNK_BYTES: usize = 64 * 1024;

    let mut bytes = Vec::with_capacity(length);
    let mut evidence_seq = handle.state().event_seq;
    while bytes.len() < length {
        // 2026-08-28: Chunked reads could resume after an interrupt at a new
        // stop and concatenate bytes from different execution epochs.
        require_same_execution_context(handle, expected)?;
        let chunk = (length - bytes.len()).min(CHUNK_BYTES);
        let address = start.checked_add(bytes.len() as u64).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "memory range overflows address space",
            )
        })?;
        let reply = match handle
            .command(
                MiCommand::new("-data-read-memory-bytes")?
                    .bare(format!("0x{address:x}"))?
                    .bare(chunk.to_string())?,
            )
            .await
        {
            Ok(reply) => reply,
            Err(error)
                if allow_partial && !bytes.is_empty() && error.code != ErrorCode::StaleContext =>
            {
                break;
            }
            Err(error) => return Err(error),
        };
        require_same_execution_context(handle, expected)?;
        evidence_seq = reply.evidence_seq;
        let part = memory_contents(&reply.record)?;
        let part_len = part.len();
        bytes.extend(part);
        if part_len < chunk {
            break;
        }
    }
    Ok((bytes, evidence_seq))
}

fn require_same_execution_context(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
) -> Result<()> {
    let current = handle.state();
    if current.stop_id == expected.stop_id && current.execution_epoch == expected.execution_epoch {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::StaleContext,
            "target stop changed during composite operation",
        ))
    }
}

fn require_expected_bytes(parameters: &Value, actual: &[u8]) -> Result<()> {
    if expected_bytes_match(parameters, actual)? {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::MemoryPreconditionFailed,
            "memory no longer matches the expected value",
        ))
    }
}

fn expected_bytes_match(parameters: &Value, actual: &[u8]) -> Result<bool> {
    let expected = parameters.get("expected").ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "expected bytes or sha256 are required",
        )
    })?;
    if let Some(encoded) = expected.get("bytes_base64").and_then(Value::as_str) {
        let bytes = BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid expected bytes_base64: {error}"),
            )
        })?;
        return Ok(bytes == actual);
    }
    if let Some(expected_hash) = expected.get("sha256").and_then(Value::as_str) {
        if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expected sha256 must contain 64 hexadecimal digits",
            ));
        }
        return Ok(format!("{:x}", Sha256::digest(actual)).eq_ignore_ascii_case(expected_hash));
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "expected must contain bytes_base64 or sha256",
    ))
}

fn search_pattern(parameters: &Value) -> Result<Vec<u8>> {
    let pattern = parameters.get("pattern").ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "memory search pattern is required",
        )
    })?;
    let bytes = if let Some(hex) = pattern.get("hex").and_then(Value::as_str) {
        hex_decode(hex).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "memory search hex pattern is invalid",
            )
        })?
    } else if let Some(encoded) = pattern.get("data_base64").and_then(Value::as_str) {
        BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid memory search data_base64: {error}"),
            )
        })?
    } else if let Some(text) = pattern.get("text").and_then(Value::as_str) {
        text.as_bytes().to_vec()
    } else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "pattern must contain hex, data_base64, or text",
        ));
    };
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "memory search pattern must contain 1 to 65536 bytes",
        ));
    }
    Ok(bytes)
}

fn register_values(record: &MiRecord) -> BTreeMap<usize, Value> {
    let Some(values) = MiResult::find(record.results(), "register-values") else {
        return BTreeMap::new();
    };
    aggregate_items(values, "register-values")
        .into_iter()
        .filter_map(|fields| {
            let number = MiResult::find_str(fields, "number")?.parse().ok()?;
            let value = MiResult::find_str(fields, "value")?;
            Some((number, Value::String(value.to_owned())))
        })
        .collect()
}

fn register_role_candidates(role: &str) -> Option<&'static [&'static str]> {
    Some(match role {
        "pc" => &["rip", "pc"],
        "sp" => &["rsp", "sp"],
        "fp" => &["rbp", "x29", "fp"],
        "return" => &["rax", "x0"],
        "flags" => &["eflags", "cpsr"],
        "syscall_number" => &["orig_rax", "x8"],
        "syscall_return" => &["rax", "x0"],
        "tls" => &["fs_base", "tpidr_el0"],
        "argument_0" => &["rdi", "x0"],
        "argument_1" => &["rsi", "x1"],
        "argument_2" => &["rdx", "x2"],
        "argument_3" => &["rcx", "x3"],
        "argument_4" => &["r8", "x4"],
        "argument_5" => &["r9", "x5"],
        "argument_6" => &["x6"],
        "argument_7" => &["x7"],
        _ => return None,
    })
}

fn target_architecture(register_names: &[String]) -> &'static str {
    // 2026-08-29: `-gdb-show architecture` reports the configured selector
    // `auto`, not the architecture selected from a live remote target.
    if find_register_name(register_names, "rip").is_some() {
        "i386:x86-64"
    } else if find_register_name(register_names, "x29").is_some() {
        "aarch64"
    } else {
        "unknown"
    }
}

fn resolve_register_name(requested: &str, names: &[String]) -> Result<String> {
    if let Some(name) = find_register_name(names, requested) {
        return Ok(name.to_owned());
    }
    let candidates = register_role_candidates(requested).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown register or role {requested}"),
        )
    })?;
    candidates
        .iter()
        .find_map(|candidate| find_register_name(names, candidate))
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                format!("target has no register for role {requested}"),
            )
        })
}

fn find_register_name<'a>(names: &'a [String], requested: &str) -> Option<&'a str> {
    // 2026-08-29: QEMU preserves uppercase AArch64 system-register names in
    // its target description; a lowercase exact lookup made `$sp_el0` void.
    names
        .iter()
        .find(|name| name.eq_ignore_ascii_case(requested))
        .map(String::as_str)
}

fn valid_integer_literal(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if let Some(hex) = unsigned.strip_prefix("0x") {
        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        !unsigned.is_empty() && unsigned.bytes().all(|byte| byte.is_ascii_digit())
    }
}

fn valid_signal_name(signal: &str) -> bool {
    signal.strip_prefix("SIG").is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn compare_observation(actual: &str, operator: &str, expected: &str) -> Result<bool> {
    match operator {
        "equals" => Ok(actual == expected),
        "not_equals" => Ok(actual != expected),
        "contains" => Ok(actual.contains(expected)),
        "greater_than" | "less_than" => {
            let actual = parse_observed_integer(actual)?;
            let expected = parse_observed_integer(expected)?;
            Ok(if operator == "greater_than" {
                actual > expected
            } else {
                actual < expected
            })
        }
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "operator must be equals, not_equals, contains, greater_than, or less_than",
        )),
    }
}

// 2026-08-28: Probes previously counted every new stop as their own hit,
// turning signals, interrupts, and unrelated breakpoints into false evidence.
fn require_probe_hit(
    parameters: &Value,
    baseline: &crate::domain::SessionState,
    stopped: &crate::domain::SessionState,
    expected_breakpoint: &str,
) -> Result<()> {
    let new_stop = stopped.stop_id.is_some()
        && stopped.stop_id != baseline.stop_id
        && stopped.execution_epoch > baseline.execution_epoch;
    let breakpoint_matches = matches!(
        &stopped.stop_reason_detail,
        Some(StopReason::Breakpoint {
            backend_number: Some(actual),
            ..
        }) if same_breakpoint_number(expected_breakpoint, actual)
    );
    let inferior_matches = parameters
        .get("inferior_id")
        .and_then(Value::as_str)
        .is_none_or(|expected| {
            stopped
                .stopped_inferior_id
                .as_ref()
                .is_some_and(|actual| actual.0 == expected)
        });
    let thread_matches = parameters
        .get("thread_id")
        .and_then(Value::as_str)
        .is_none_or(|expected| {
            stopped
                .stopped_thread_id
                .as_ref()
                .is_some_and(|actual| actual.0 == expected)
        });
    if new_stop && breakpoint_matches && inferior_matches && thread_matches {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidState,
        "target stopped somewhere other than the probe breakpoint",
    )
    .with_details(json!({
        "expected_breakpoint": expected_breakpoint,
        "actual_reason": stopped.stop_reason_detail,
        "raw_reason": stopped.stop_reason,
        "stop_id": stopped.stop_id,
        "stopped_inferior_id": stopped.stopped_inferior_id,
        "stopped_thread_id": stopped.stopped_thread_id
    })))
}

fn same_breakpoint_number(expected: &str, actual: &str) -> bool {
    actual == expected
        || actual
            .strip_prefix(expected)
            .and_then(|suffix| suffix.strip_prefix('.'))
            .is_some_and(|location| {
                !location.is_empty() && location.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn parse_observed_integer(value: &str) -> Result<i128> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        i128::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("observation is not an integer: {value}"),
        )
    })
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(
            ErrorCode::GdbError,
            "GDB returned malformed hexadecimal bytes",
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16)
                .map_err(|_| Error::new(ErrorCode::GdbError, "invalid hexadecimal byte"))
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn parse_gdb_u64(value: &str) -> Result<u64> {
    if let Some(start) = value.find("0x") {
        let digits: String = value[start + 2..]
            .chars()
            .take_while(|character| character.is_ascii_hexdigit())
            .collect();
        if !digits.is_empty() {
            return u64::from_str_radix(&digits, 16)
                .map_err(|_| Error::new(ErrorCode::GdbError, "invalid GDB hexadecimal value"));
        }
    }
    value
        .split_whitespace()
        .find_map(|word| {
            word.trim_matches(|character: char| !character.is_ascii_digit())
                .parse()
                .ok()
        })
        .ok_or_else(|| {
            Error::new(
                ErrorCode::GdbError,
                format!("GDB value is not an unsigned integer: {value}"),
            )
        })
}

fn gdb_c_string(value: &str) -> String {
    // 2026-08-28: GDB prefixes pointer-to-char values with an address and
    // symbol, while fixed arrays begin at the quote. Normalize both forms.
    let value = value
        .find('"')
        .map_or(value, |quote| &value[quote.saturating_add(1)..]);
    let end = [value.find("\\000"), value.find('"')]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(value.len());
    value[..end].trim_end_matches('"').to_owned()
}

fn parse_address(value: &str) -> Result<u64> {
    let value = value
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .trim_matches(|character: char| matches!(character, '(' | ')' | ','));
    let value = value.strip_prefix("0x").ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            format!("GDB value is not a hexadecimal address: {value}"),
        )
    })?;
    u64::from_str_radix(value, 16)
        .map_err(|_| Error::new(ErrorCode::GdbError, "invalid hexadecimal address"))
}

fn input_bytes(parameters: &Value) -> Result<Vec<u8>> {
    if let Some(encoded) = parameters.get("data_base64").and_then(Value::as_str) {
        return BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid data_base64: {error}"),
            )
        });
    }
    if let Some(text) = parameters.get("text").and_then(Value::as_str) {
        return Ok(text.as_bytes().to_vec());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "text or data_base64 is required",
    ))
}

fn remote_endpoint(parameters: &Value) -> Result<String> {
    let endpoint = parameters
        .get("endpoint")
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "endpoint is required"))?;
    let text = if let Some(endpoint) = endpoint.as_str() {
        endpoint.to_owned()
    } else {
        let host = string(endpoint, "host")?;
        let port = unsigned(endpoint, "port")?;
        if port == 0 || port > u16::MAX as u64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "remote port must be between 1 and 65535",
            ));
        }
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    };
    text.parse::<std::net::SocketAddr>()
        .map(|endpoint| endpoint.to_string())
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "remote endpoint must use a pinned IP address and port",
            )
        })
}

#[derive(Clone, Copy)]
struct AttachIdentity {
    start_time_ticks: u64,
}

impl AttachIdentity {
    fn revalidate(self, pid: u64) -> Result<()> {
        if process_start_time(pid)? == self.start_time_ticks {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Conflict,
                "attach target identity changed before attach completed",
            ))
        }
    }
}

fn validate_attach_target(pid: u64) -> Result<AttachIdentity> {
    use std::os::unix::fs::MetadataExt;

    let process = std::fs::metadata(format!("/proc/{pid}")).map_err(|error| {
        Error::new(
            ErrorCode::TargetUnavailable,
            format!("cannot inspect attach target: {error}"),
        )
    })?;
    // SAFETY: geteuid has no preconditions and reads process credentials.
    let current_uid = unsafe { libc::geteuid() };
    if process.uid() != current_uid {
        return Err(Error::new(
            ErrorCode::PolicyDenied,
            "attach target belongs to another Unix user",
        ));
    }
    let current_namespace = std::fs::metadata("/proc/self/ns/pid")?;
    let target_namespace = std::fs::metadata(format!("/proc/{pid}/ns/pid"))?;
    if current_namespace.dev() != target_namespace.dev()
        || current_namespace.ino() != target_namespace.ino()
    {
        return Err(Error::new(
            ErrorCode::PolicyDenied,
            "attach target belongs to another PID namespace",
        ));
    }
    Ok(AttachIdentity {
        start_time_ticks: process_start_time(pid)?,
    })
}

fn process_start_time(pid: u64) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        Error::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read attach target identity: {error}"),
        )
    })?;
    parse_process_start_time(&stat)
}

fn parse_process_start_time(stat: &str) -> Result<u64> {
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::TargetUnavailable,
                "attach target stat record is malformed",
            )
        })?;
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::TargetUnavailable,
                "attach target stat record has no start time",
            )
        })
}

fn first_word(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or("unknown")
}

fn raw_mi_is_managed(command: &str) -> bool {
    [
        "-break-",
        "-exec-",
        "-gdb-show",
        "-list-thread-groups",
        "-list-target-features",
        "-file-list-shared-libraries",
        "-stack-list-",
        "-stack-select-frame",
        "-thread-info",
        "-thread-select",
    ]
    .iter()
    .any(|prefix| command.starts_with(prefix))
}

// 2026-08-28: Raw MI previously bypassed workspace, attach, remote endpoint,
// and safe-startup policy. Protected setup operations use their semantic APIs.
fn raw_mi_is_denied(command: &str) -> bool {
    matches!(
        command,
        "-interpreter-exec"
            | "-gdb-exit"
            | "-gdb-set"
            | "-target-select"
            | "-target-attach"
            | "-target-file-get"
            | "-target-file-put"
            | "-target-file-delete"
            | "-file-exec-and-symbols"
            | "-file-exec-file"
            | "-file-symbol-file"
            | "-environment-cd"
            | "-inferior-tty-set"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{FrameId, InferiorId, JournaledEvent, SessionState, StopId, ThreadId},
        reducer::StateReducer,
    };

    #[test]
    fn event_receive_errors_preserve_resynchronization_semantics() {
        let gap = event_receive_error(
            tokio::sync::broadcast::error::RecvError::Lagged(7),
            "sess_test",
            10,
            30,
        );
        assert_eq!(gap.code, ErrorCode::EventGap);
        assert!(gap.retryable);
        assert_eq!(gap.details.as_ref().unwrap()["dropped_events"], 7);
        assert_eq!(gap.details.as_ref().unwrap()["available_after"], 30);
        assert_eq!(
            gap.details.as_ref().unwrap()["resync"],
            "gdbai://session/sess_test/status"
        );

        let closed = event_receive_error(
            tokio::sync::broadcast::error::RecvError::Closed,
            "sess_test",
            10,
            30,
        );
        assert_eq!(closed.code, ErrorCode::StreamClosed);
        assert!(!closed.retryable);
    }

    #[test]
    fn safe_expression_rejects_calls_and_mutations() {
        for expression in [
            "global_value",
            "&large_buffer",
            "$pc == 0",
            "(struct pair *)global",
            "sizeof(global_value)",
        ] {
            validate_expression(expression).unwrap();
        }
        for expression in [
            "global_value = 1",
            "++global_value",
            "$rax += 1",
            "marker()",
            "$_shell(\"id\")",
            "marker/**/()",
        ] {
            assert_eq!(
                validate_expression(expression).unwrap_err().code,
                ErrorCode::PolicyDenied,
                "accepted unsafe expression: {expression}"
            );
        }
    }

    #[test]
    fn probe_accepts_only_its_breakpoint_and_scope() {
        let mut baseline = SessionState::creating(SessionId("sess_probe".into()));
        baseline.stop_id = Some(StopId("stop_before".into()));
        baseline.execution_epoch = 4;
        let mut stopped = baseline.clone();
        stopped.stop_id = Some(StopId("stop_after".into()));
        stopped.execution_epoch = 5;
        stopped.stop_reason = Some("breakpoint-hit".into());
        stopped.stop_reason_detail = Some(StopReason::Breakpoint {
            backend_number: Some("7.2".into()),
            disposition: Some("keep".into()),
        });
        stopped.stopped_inferior_id = Some(InferiorId("inf_expected".into()));
        stopped.stopped_thread_id = Some(ThreadId("thr_expected".into()));
        let scope = json!({
            "inferior_id": "inf_expected",
            "thread_id": "thr_expected"
        });

        require_probe_hit(&scope, &baseline, &stopped, "7").unwrap();

        stopped.stop_reason = Some("signal-received".into());
        stopped.stop_reason_detail = Some(StopReason::Signal {
            name: Some("SIGSEGV".into()),
            meaning: Some("Segmentation fault".into()),
        });
        assert_eq!(
            require_probe_hit(&scope, &baseline, &stopped, "7")
                .unwrap_err()
                .code,
            ErrorCode::InvalidState
        );
    }

    #[test]
    fn probe_rejects_an_unrelated_breakpoint() {
        let mut baseline = SessionState::creating(SessionId("sess_probe".into()));
        baseline.stop_id = Some(StopId("stop_before".into()));
        let mut stopped = baseline.clone();
        stopped.stop_id = Some(StopId("stop_after".into()));
        stopped.execution_epoch = 1;
        stopped.stop_reason = Some("breakpoint-hit".into());
        stopped.stop_reason_detail = Some(StopReason::Breakpoint {
            backend_number: Some("8".into()),
            disposition: None,
        });

        assert!(require_probe_hit(&json!({}), &baseline, &stopped, "7").is_err());
    }

    #[test]
    fn parses_and_revalidates_attach_identity() {
        let stat = "123 (worker name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242";
        assert_eq!(parse_process_start_time(stat).unwrap(), 4242);

        let pid = u64::from(std::process::id());
        let identity = validate_attach_target(pid).unwrap();
        identity.revalidate(pid).unwrap();
        let changed = AttachIdentity {
            start_time_ticks: identity.start_time_ticks.saturating_add(1),
        };
        assert_eq!(
            changed.revalidate(pid).unwrap_err().code,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn start_policies_map_to_explicit_gdb_stops() {
        let first: StartPolicy = serde_json::from_value(json!("entry")).unwrap();
        assert_eq!(first.as_str(), "first_instruction");
        assert_eq!(
            first.command().unwrap().encoded(1),
            b"1-interpreter-exec console \"starti\"\n"
        );
        assert_eq!(
            StartPolicy::Main.command().unwrap().encoded(2),
            b"2-exec-run --start\n"
        );
        assert_eq!(
            StartPolicy::None.command().unwrap().encoded(3),
            b"3-exec-run\n"
        );
    }

    #[test]
    fn inherits_only_allowlisted_environment_variables() {
        let path = std::env::var("PATH").unwrap();
        let environment = inherited_environment(&[
            "PATH".into(),
            "GDB_AI_TEST_VARIABLE_THAT_DOES_NOT_EXIST".into(),
        ])
        .unwrap();

        assert_eq!(environment.len(), 1);
        assert_eq!(environment.get("PATH"), Some(&path));
    }

    #[test]
    fn frame_context_encodes_its_thread_before_positional_arguments() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_ctx".into())));
        for (seq, event) in [
            (
                1,
                DomainEvent::InferiorAdded {
                    backend_id: "i1".into(),
                    pid: Some(7),
                },
            ),
            (
                2,
                DomainEvent::ThreadCreated {
                    backend_inferior: "i1".into(),
                    backend_thread: "1".into(),
                },
            ),
            (
                3,
                DomainEvent::ThreadCreated {
                    backend_inferior: "i1".into(),
                    backend_thread: "2".into(),
                },
            ),
            (
                4,
                DomainEvent::TargetStopped {
                    backend_inferior: Some("i1".into()),
                    backend_thread: Some("2".into()),
                    reason: "breakpoint-hit".into(),
                    reason_detail: Some(StopReason::Breakpoint {
                        backend_number: Some("1".into()),
                        disposition: Some("keep".into()),
                    }),
                    frame: None,
                },
            ),
        ] {
            reducer
                .apply(&JournaledEvent::for_replay(seq, event))
                .unwrap();
        }
        let state = reducer.state();
        let stop = state.stop_id.as_ref().unwrap();
        let stopped_thread = state.stopped_thread_id.as_ref().unwrap();
        let frame = FrameId::new(stopped_thread, stop, 3);
        let command = context_options(
            MiCommand::new("-data-evaluate-expression")
                .unwrap()
                .string("$pc"),
            &json!({"stop_id": stop, "frame_id": frame}),
            state,
        )
        .unwrap();
        assert_eq!(
            command.encoded(1),
            b"1-data-evaluate-expression --thread 2 --frame 3 \"$pc\"\n"
        );

        let other_thread = &state.inferiors["i1"].threads["1"].id;
        let error = context_options(
            MiCommand::new("-stack-info-frame").unwrap(),
            &json!({
                "stop_id": stop,
                "thread_id": other_thread,
                "frame_id": frame
            }),
            state,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::StaleContext);

        let focused = context_options(
            MiCommand::new("-data-evaluate-expression")
                .unwrap()
                .string("$pc"),
            &json!({"stop_id": stop}),
            state,
        )
        .unwrap();
        assert_eq!(
            focused.encoded(2),
            b"2-data-evaluate-expression --thread 2 --frame 0 \"$pc\"\n"
        );
    }

    #[test]
    fn strict_operation_parameters_ignore_gateway_controls() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StrictParameters {
            stop: StartPolicy,
        }

        let request = ApiRequest {
            api_version: crate::protocol::API_VERSION.into(),
            request_id: "strict-parameters".into(),
            session_id: Some("sess_test".into()),
            method: CanonicalMethod::TargetRestart,
            expected_revision: Some(1),
            idempotency_key: None,
            parameters: json!({
                "stop": "main",
                "lease_id": "lease_test",
                "accept_latest_revision": true
            }),
        };
        let decoded: StrictParameters = parameters(&request).unwrap();
        assert_eq!(decoded.stop.as_str(), "main");
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::Duration,
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
    persistence::Store,
    policy::{Profile, validate_console_command},
    protocol::{ApiRequest, CanonicalMethod},
    providers::LINUX_KERNEL_PROVIDER_VERSION,
    session::{CommandReply, OutputRing, SessionHandle, WaitUntil},
};

struct ProbeBreakpoint {
    handle: SessionHandle,
    store: Arc<Store>,
    operation_id: OperationId,
    backend_number: Option<String>,
}

impl ProbeBreakpoint {
    async fn remove(&mut self) -> Result<()> {
        let Some(backend_number) = self.backend_number.clone() else {
            return Ok(());
        };
        self.handle
            .command(MiCommand::new("-break-delete")?.bare(backend_number)?)
            .await?;
        // 2026-08-28: Taking the number before GDB confirmed deletion made a
        // failed cleanup impossible to retry from Drop.
        self.backend_number = None;
        Ok(())
    }
}

impl Drop for ProbeBreakpoint {
    fn drop(&mut self) {
        let Some(backend_number) = self.backend_number.take() else {
            return;
        };
        let handle = self.handle.clone();
        let store = self.store.clone();
        let operation_id = self.operation_id.clone();
        // 2026-08-28: Dropping a cancelled probe skipped its trailing delete
        // and leaked a temporary breakpoint into later Agent operations.
        tokio::spawn(async move {
            let cleanup = async {
                handle
                    .command(MiCommand::new("-break-delete")?.bare(backend_number)?)
                    .await?;
                Result::<()>::Ok(())
            }
            .await;
            if let Ok(Some(mut operation)) = store.get_operation(&operation_id.0) {
                // 2026-08-28: Drop also retries failed explicit cleanup. Only
                // an in-flight operation represents cancellation; preserve any
                // completed, timed-out, or failed terminal result.
                if operation.status == OperationStatus::WaitingForState {
                    operation.status = if cleanup.is_ok() {
                        OperationStatus::Cancelled
                    } else {
                        OperationStatus::Failed
                    };
                    operation.error = cleanup.as_ref().err().map(ToString::to_string);
                    operation.completed_event_seq = Some(handle.state().event_seq);
                    let _ = store.upsert_operation(&operation);
                }
            }
            if let Err(error) = cleanup {
                tracing::warn!(%error, %operation_id, "failed to clean up cancelled probe");
            }
        });
    }
}

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

    async fn session_create(&self, request: &ApiRequest, caller: &Caller) -> Result<Value> {
        // 2026-08-28: Concurrent creates checked the registry before either
        // inserted its worker, allowing both to exceed max_sessions. Session
        // startup is rare, so serialize its reservation and insertion.
        // ponytail: shard reservations only if startup throughput matters.
        let _creation = self.session_creation.lock().await;
        if self.sessions.read().await.len() >= self.config.server.max_sessions {
            return Err(Error::new(ErrorCode::Conflict, "maximum sessions reached"));
        }
        #[derive(Deserialize)]
        struct Parameters {
            #[serde(default)]
            profile: Option<Profile>,
        }
        let parameters: Parameters = parameters(request)?;
        let profile = parameters
            .profile
            .unwrap_or(self.config.security.default_profile);
        if profile != self.config.security.default_profile && !caller.admin {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "selecting a non-default profile requires an administrative caller",
            ));
        }
        let handle = SessionHandle::start(
            self.config.clone(),
            profile,
            self.store.clone(),
            self.metrics.clone(),
        )
        .await?;
        let id = handle.id().clone();
        let lease = WriteLease {
            lease_id: LeaseId::new(),
            session_id: id.clone(),
            owner: caller.identity.clone(),
            expires_at_unix_ms: now_unix_ms()
                .saturating_add(self.config.server.write_lease_ms.max(1)),
            generation: 1,
        };
        if let Err(error) = self
            .store
            .set_session_owner(&id, &caller.identity)
            .and_then(|()| self.store.upsert_lease(&lease))
        {
            let _ = handle.close().await;
            return Err(error);
        }
        let entry = Arc::new(SessionEntry {
            handle,
            owner: caller.identity.clone(),
            target_state: tokio::sync::RwLock::new(()),
            mutation: tokio::sync::Mutex::new(()),
            out_of_band_mutation: tokio::sync::Mutex::new(()),
            lease: tokio::sync::Mutex::new(Some(lease.clone())),
            lease_generation: std::sync::atomic::AtomicU64::new(1),
        });
        self.sessions
            .write()
            .await
            .insert(id.0.clone(), entry.clone());
        entry
            .handle
            .record_api(serde_json::to_value(request)?)
            .await?;
        Ok(json!({
            "session_id": id,
            "resource": format!("gdbai://session/{}/status", id.0),
            "state": entry.handle.state(),
            "backend": entry.handle.capabilities().backend,
            "profile": profile,
            "write_lease": lease,
            "capabilities": entry.handle.capabilities(),
        }))
    }

    async fn session_acquire_write_lease(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let now = now_unix_ms();
        let mut current = entry.lease.lock().await;
        let force =
            request.parameters.get("force").and_then(Value::as_bool) == Some(true) && caller.admin;
        if current
            .as_ref()
            .is_some_and(|lease| !lease.is_expired(now) && lease.owner != caller.identity && !force)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "another caller holds the write lease",
            ));
        }
        let generation = entry.lease_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let lease = WriteLease {
            lease_id: LeaseId::new(),
            session_id: entry.handle.id().clone(),
            owner: caller.identity.clone(),
            expires_at_unix_ms: now.saturating_add(self.config.server.write_lease_ms.max(1)),
            generation,
        };
        self.store.upsert_lease(&lease)?;
        current.replace(lease.clone());
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "write_lease_acquired".into(),
            })
            .await?;
        Ok(serde_json::to_value(lease)?)
    }

    async fn session_release_write_lease(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let released = entry
            .lease
            .lock()
            .await
            .take()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "write lease not found"))?;
        self.store.delete_lease(entry.handle.id())?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "write_lease_released".into(),
            })
            .await?;
        Ok(json!({ "released": released.lease_id }))
    }

    async fn session_attempt_recovery(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        self.reconcile_session(&entry, true).await
    }

    async fn session_list(&self, caller: &Caller) -> Result<Value> {
        let entries = self
            .sessions
            .read()
            .await
            .values()
            .filter(|entry| caller.admin || same_principal(&entry.owner, &caller.identity))
            .cloned()
            .collect::<Vec<_>>();
        let mut states = self
            .store
            .list_session_owners()?
            .into_iter()
            .filter(|(_, owner)| {
                caller.admin
                    || owner
                        .as_deref()
                        .is_some_and(|owner| same_principal(owner, &caller.identity))
            })
            .map(|(state, _)| (state.session_id.0.clone(), state))
            .collect::<BTreeMap<_, _>>();
        for entry in entries {
            let state = entry.handle.state();
            states.insert(state.session_id.0.clone(), state);
        }
        Ok(serde_json::to_value(
            states.into_values().collect::<Vec<_>>(),
        )?)
    }

    async fn session_get(&self, request: &ApiRequest) -> Result<Value> {
        let session_id = SessionId::parse(required_session(request)?)?;
        if let Ok(entry) = self.entry(&session_id.0).await {
            return Ok(serde_json::to_value(entry.handle.state())?);
        }
        self.store
            .get_session(&session_id)?
            .map(serde_json::to_value)
            .transpose()?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "session not found"))
    }

    async fn session_providers(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(crate::providers::descriptors(
            &entry.handle.state(),
            &entry.handle.capabilities(),
            self.config.security.kernel_enabled,
        ))?)
    }

    async fn session_transcript(&self, request: &ApiRequest) -> Result<Value> {
        use std::io::{Read as _, Seek as _};

        let session_id = SessionId::parse(required_session(request)?)?;
        let journal_path = self.session_journal_path(&session_id).await?;
        let offset = request
            .parameters
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(64 * 1024)
            .clamp(1, 64 * 1024) as usize;
        let mut file = std::fs::File::open(journal_path)?;
        let length = file.metadata()?.len();
        let offset = offset.min(length);
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut bytes = vec![0; max_bytes.min((length - offset) as usize)];
        file.read_exact(&mut bytes)?;
        let text = std::str::from_utf8(&bytes).ok();
        Ok(json!({
            "offset": offset,
            "next_offset": offset + bytes.len() as u64,
            "total_bytes": length,
            "text": text,
            "data_base64": BASE64.encode(&bytes),
            "truncated": offset + (bytes.len() as u64) < length
        }))
    }

    async fn session_event(&self, request: &ApiRequest) -> Result<Value> {
        use std::io::BufRead as _;

        let session_id = SessionId::parse(required_session(request)?)?;
        let wanted = unsigned(&request.parameters, "event_seq")?;
        if wanted == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "event_seq must be positive",
            ));
        }
        let path = self.session_journal_path(&session_id).await?;
        for line in std::io::BufReader::new(std::fs::File::open(path)?).lines() {
            let entry: crate::journal::JournalEntry = serde_json::from_str(&line?)?;
            if entry.seq == wanted {
                return Ok(serde_json::to_value(entry)?);
            }
            if entry.seq > wanted {
                break;
            }
        }
        Err(Error::new(ErrorCode::NotFound, "journal event not found"))
    }

    async fn session_journal_path(&self, session_id: &SessionId) -> Result<std::path::PathBuf> {
        // 2026-08-28: Transcript and event reads previously required a live
        // worker, making retained failure evidence inaccessible after close.
        match self.entry(&session_id.0).await {
            Ok(entry) => {
                // 2026-08-28: Batched journal writes were not flushed before
                // live transcript reads, so recently advertised evidence was missing.
                entry.handle.flush_journal().await?;
                Ok(entry.handle.journal_path().clone())
            }
            Err(_) if self.store.get_session(session_id)?.is_some() => Ok(self
                .config
                .persistence
                .sessions
                .join(&session_id.0)
                .join("journal.jsonl")),
            Err(error) => Err(error),
        }
    }

    async fn session_close(&self, request: &ApiRequest) -> Result<Value> {
        let id = required_session(request)?.to_owned();
        let entry = self.entry(&id).await?;
        if let Err(error) = entry.handle.close().await {
            // 2026-08-28: A failed worker closes its request channel, so close
            // must still release registry and lease state after GDB death.
            if entry.handle.state().lifecycle != crate::domain::SessionLifecycle::Failed {
                return Err(error);
            }
        }
        let state = entry.handle.state();
        self.store.delete_lease(entry.handle.id())?;
        self.sessions.write().await.remove(&id);
        Ok(json!({ "closed": true, "state": state }))
    }

    async fn target_launch(&self, request: &ApiRequest) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Parameters {
            program: String,
            argv: Vec<String>,
            cwd: Option<String>,
            environment: BTreeMap<String, String>,
            environment_mode: String,
            aslr: String,
            stop: StartPolicy,
            follow_fork: String,
            detach_on_fork: bool,
            follow_exec: String,
            wait: Option<WaitSpec>,
        }
        impl Default for Parameters {
            fn default() -> Self {
                Self {
                    program: String::new(),
                    argv: Vec::new(),
                    cwd: None,
                    environment: BTreeMap::new(),
                    environment_mode: "clean".into(),
                    aslr: "preserve".into(),
                    stop: StartPolicy::FirstInstruction,
                    follow_fork: "parent".into(),
                    detach_on_fork: true,
                    follow_exec: "same-inferior".into(),
                    wait: None,
                }
            }
        }
        let parameters: Parameters = parameters(request)?;
        if parameters.program.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "program is required",
            ));
        }
        if parameters.environment_mode != "clean" {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "only environment_mode=clean is supported securely",
            ));
        }
        validate_environment(&parameters.environment)?;
        validate_argv(&parameters.argv)?;
        let program = self.workspace_path(&parameters.program, false)?;
        let default_cwd = program
            .parent()
            .unwrap_or(Path::new("/"))
            .to_string_lossy()
            .into_owned();
        let cwd = self.workspace_path(parameters.cwd.as_deref().unwrap_or(&default_cwd), true)?;
        if !matches!(parameters.follow_fork.as_str(), "parent" | "child") {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "follow_fork must be parent or child",
            ));
        }
        if parameters.follow_exec != "same-inferior" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "follow_exec must be same-inferior",
            ));
        }
        if let Some(wait) = &parameters.wait {
            wait.validate()?;
        }
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let mut setup = vec![
            MiCommand::new("-file-exec-and-symbols")?
                .string(program.as_os_str().as_encoded_bytes()),
            MiCommand::new("-environment-cd")?.string(cwd.as_os_str().as_encoded_bytes()),
            // 2026-08-28: Clearing GDB's own environment did not clear the
            // inferior environment. Enforce environment_mode=clean explicitly.
            MiCommand::new("-interpreter-exec")?
                .bare("console")?
                .string("unset environment"),
        ];
        let mut arguments = MiCommand::new("-exec-arguments")?;
        for argument in parameters.argv {
            arguments = arguments.string(argument);
        }
        setup.push(arguments);
        for (name, value) in parameters.environment {
            setup.push(
                MiCommand::new("-gdb-set")?
                    .bare("environment")?
                    .string(format!("{name}={value}")),
            );
        }
        setup.push(
            MiCommand::new("-gdb-set")?
                .bare("disable-randomization")?
                .bare(match parameters.aslr.as_str() {
                    "preserve" => "off",
                    "disable" => "on",
                    _ => {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "aslr must be preserve or disable",
                        ));
                    }
                })?,
        );
        setup.push(
            MiCommand::new("-gdb-set")?
                .bare("follow-fork-mode")?
                .bare(parameters.follow_fork)?,
        );
        setup.push(MiCommand::new("-gdb-set")?.bare("detach-on-fork")?.bare(
            if parameters.detach_on_fork {
                "on"
            } else {
                "off"
            },
        )?);
        setup.push(
            MiCommand::new("-gdb-set")?
                .bare("follow-exec-mode")?
                .bare("same")?,
        );
        let start_policy = parameters.stop;
        let run = start_policy.command()?;
        let reply = entry.handle.transaction(setup, run, Vec::new()).await?;
        entry
            .handle
            .record_event(DomainEvent::TargetConfigured {
                origin: TargetOrigin::Local,
            })
            .await?;
        let state = wait_if_requested(&entry.handle, parameters.wait, Some(&baseline)).await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({
            "command": reply,
            "state": state,
            "capabilities": capabilities,
            "start_policy": start_policy.as_str()
        }))
    }

    async fn target_attach(&self, request: &ApiRequest) -> Result<Value> {
        let pid = unsigned(&request.parameters, "pid")?;
        let wait = wait_spec(&request.parameters)?.unwrap_or(WaitSpec {
            until: "snapshot".into(),
            timeout_ms: self.config.server.wait_timeout_ms,
        });
        if !self.config.security.attach_allowlist.contains(&pid) {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "PID is not in security.attach_allowlist",
            ));
        }
        let target_identity = validate_attach_target(pid)?;
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        if let Some(executable) = request.parameters.get("executable").and_then(Value::as_str) {
            let executable = self.workspace_path(executable, false)?;
            entry
                .handle
                .command(
                    MiCommand::new("-file-exec-and-symbols")?
                        .string(executable.as_os_str().as_encoded_bytes()),
                )
                .await?;
        }
        // 2026-08-28: PID ownership was checked before optional setup, leaving
        // time for exit and PID reuse before GDB attached. Revalidate the
        // process identity immediately before and after the numeric attach.
        target_identity.revalidate(pid)?;
        let reply = entry
            .handle
            .command(MiCommand::new("-target-attach")?.bare(pid.to_string())?)
            .await?;
        if let Err(error) = target_identity.revalidate(pid) {
            let _ = entry
                .handle
                .command(MiCommand::new("-target-detach")?)
                .await;
            return Err(error);
        }
        entry
            .handle
            .record_event(DomainEvent::TargetConfigured {
                origin: TargetOrigin::Attach,
            })
            .await?;
        let state = apply_wait(&entry.handle, wait, Some(&baseline)).await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({ "command": reply, "state": state, "capabilities": capabilities }))
    }

    async fn target_connect_remote(&self, request: &ApiRequest) -> Result<Value> {
        let mode = request
            .parameters
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or("remote");
        if !matches!(mode, "remote" | "extended-remote") {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "remote mode must be remote or extended-remote",
            ));
        }
        let endpoint = remote_endpoint(&request.parameters)?;
        let wait = wait_spec(&request.parameters)?;
        if !self.config.security.remote_allowlist.contains(&endpoint) {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "endpoint is not in security.remote_allowlist",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        if let Some(executable) = request.parameters.get("executable").and_then(Value::as_str) {
            let executable = self.workspace_path(executable, false)?;
            entry
                .handle
                .command(
                    MiCommand::new("-file-exec-and-symbols")?
                        .string(executable.as_os_str().as_encoded_bytes()),
                )
                .await?;
        }
        let reply = entry
            .handle
            .command(
                MiCommand::new("-target-select")?
                    .bare(mode)?
                    // 2026-08-28: GDB retained MI string quotes in remote
                    // endpoint parsing. SocketAddr normalization makes bare
                    // encoding safe and avoids a quoted service name.
                    .bare(&endpoint)?,
            )
            .await?;
        entry
            .handle
            .record_event(DomainEvent::TargetConfigured {
                origin: TargetOrigin::Remote,
            })
            .await?;
        let state = wait_if_requested(&entry.handle, wait, Some(&baseline)).await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({ "command": reply, "state": state, "capabilities": capabilities }))
    }

    async fn target_open_core(&self, request: &ApiRequest) -> Result<Value> {
        let executable = self.workspace_path(&string(&request.parameters, "executable")?, false)?;
        let core = self.workspace_path(&string(&request.parameters, "core")?, false)?;
        let entry = self.entry(required_session(request)?).await?;
        let core_link = entry.handle.session_directory().join("target.core");
        if let Err(error) = std::fs::remove_file(&core_link)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
        std::os::unix::fs::symlink(core, core_link)?;
        let reply = entry
            .handle
            .transaction(
                vec![
                    MiCommand::new("-file-exec-and-symbols")?
                        .string(executable.as_os_str().as_encoded_bytes()),
                ],
                // 2026-08-28: GDB 15 treats filename quotes literally while
                // GDB 17 requires them for spaces. A session-local safe name
                // gives both versions the same unquoted target argument.
                MiCommand::new("-target-select")?
                    .bare("core")?
                    .bare("target.core")?,
                Vec::new(),
            )
            .await?;
        // 2026-08-28: Loading a core does not reliably emit *stopped. Build
        // the immutable stop context explicitly so core inspection is usable.
        let frame_reply = entry
            .handle
            .command(MiCommand::new("-stack-info-frame")?)
            .await?;
        let backend_id = entry
            .handle
            .state()
            .inferiors
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "i1".into());
        entry
            .handle
            .record_event(DomainEvent::TargetStopped {
                backend_inferior: Some(backend_id.clone()),
                backend_thread: None,
                reason: "core".into(),
                reason_detail: Some(StopReason::Core),
                frame: frame_summary(&frame_reply.record),
            })
            .await?;
        entry
            .handle
            .record_event(DomainEvent::CoreOpened { backend_id })
            .await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({
            "command": reply,
            "state": entry.handle.state(),
            "capabilities": capabilities
        }))
    }

    async fn target_detach(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let reply = entry
            .handle
            .command(MiCommand::new("-target-detach")?)
            .await?;
        entry
            .handle
            .record_event(DomainEvent::TargetDetached)
            .await?;
        Ok(json!({ "command": reply, "state": entry.handle.state() }))
    }

    async fn target_restart(&self, request: &ApiRequest) -> Result<Value> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Parameters {
            stop: Option<StartPolicy>,
            stop_at_entry: Option<bool>,
            wait: Option<WaitSpec>,
        }
        let parameters: Parameters = parameters(request)?;
        if let Some(wait) = &parameters.wait {
            wait.validate()?;
        }
        let start_policy = parameters.stop.unwrap_or_else(|| {
            parameters.stop_at_entry.map_or(StartPolicy::Main, |stop| {
                if stop {
                    StartPolicy::Main
                } else {
                    StartPolicy::None
                }
            })
        });
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let reply = entry.handle.command(start_policy.command()?).await?;
        let state = wait_if_requested(&entry.handle, parameters.wait, Some(&baseline)).await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({
            "command": reply,
            "state": state,
            "capabilities": capabilities,
            "start_policy": start_policy.as_str()
        }))
    }

    async fn target_kill(&self, request: &ApiRequest) -> Result<Value> {
        let wait = wait_spec(&request.parameters)?;
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        // 2026-08-28: GDB 17 has no -exec-abort MI command. Use console kill
        // after the handshake disables confirmation so exit events stay MI.
        let reply = entry
            .handle
            .command(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string("kill"),
            )
            .await?;
        let state = wait_if_requested(&entry.handle, wait, Some(&baseline)).await?;
        Ok(json!({ "command": reply, "state": state }))
    }

    async fn execution_control(&self, request: &ApiRequest) -> Result<Value> {
        let action = string(&request.parameters, "action")?;
        let wait = wait_spec(&request.parameters)?;
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let mut operation = OperationRecord {
            operation_id: OperationId::new(),
            session_id: entry.handle.id().clone(),
            kind: format!("execution.{action}"),
            status: OperationStatus::Accepted,
            created_revision: state.revision,
            wait_baseline: Some(WaitBaseline::from(&state)),
            expected_execution_epoch: Some(
                state.execution_epoch + u64::from(action != "interrupt"),
            ),
            accepted_event_seq: None,
            completed_event_seq: None,
            error: None,
        };
        self.store.upsert_operation(&operation)?;
        let mut command = match action.as_str() {
            "continue" => MiCommand::new("-exec-continue")?,
            "interrupt" => MiCommand::new("-exec-interrupt")?,
            "step" => MiCommand::new("-exec-step")?,
            "next" => MiCommand::new("-exec-next")?,
            "finish" => MiCommand::new("-exec-finish")?,
            "step_instruction" => MiCommand::new("-exec-step-instruction")?,
            "next_instruction" => MiCommand::new("-exec-next-instruction")?,
            "until" => {
                MiCommand::new("-exec-until")?.string(string(&request.parameters, "location")?)
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unsupported execution action",
                ));
            }
        };
        command = context_options(command, &request.parameters, &state)?;
        let reply = match if action == "interrupt" {
            entry.handle.interrupt(command).await
        } else {
            entry.handle.command(command).await
        } {
            Ok(reply) => reply,
            Err(error) => {
                operation.status = OperationStatus::Failed;
                operation.error = Some(error.to_string());
                operation.completed_event_seq = Some(entry.handle.state().event_seq);
                self.store.upsert_operation(&operation)?;
                return Err(error);
            }
        };
        operation.accepted_event_seq = Some(reply.evidence_seq);
        if let Some(wait) = wait {
            operation.status = OperationStatus::WaitingForState;
            self.store.upsert_operation(&operation)?;
            match apply_wait(&entry.handle, wait, Some(&state)).await {
                Ok(state) => {
                    operation.status = OperationStatus::Completed;
                    operation.completed_event_seq = Some(state.event_seq);
                    self.store.upsert_operation(&operation)?;
                    Ok(json!({
                        "operation_id": operation.operation_id,
                        "wait_status": "COMPLETED",
                        "command": reply,
                        "state": state
                    }))
                }
                Err(error) if error.code == ErrorCode::Timeout => {
                    let state = entry.handle.state();
                    operation.status = OperationStatus::TimedOut;
                    operation.completed_event_seq = Some(state.event_seq);
                    self.store.upsert_operation(&operation)?;
                    Ok(json!({
                        "operation_id": operation.operation_id,
                        "wait_status": "TIMEOUT",
                        "target_state": state,
                        "can_interrupt": true,
                        "command": reply
                    }))
                }
                Err(error) => {
                    operation.status = OperationStatus::Failed;
                    operation.error = Some(error.to_string());
                    operation.completed_event_seq = Some(entry.handle.state().event_seq);
                    self.store.upsert_operation(&operation)?;
                    Err(error)
                }
            }
        } else {
            operation.status = OperationStatus::Completed;
            operation.completed_event_seq = Some(entry.handle.state().event_seq);
            self.store.upsert_operation(&operation)?;
            Ok(json!({
                "operation_id": operation.operation_id,
                "wait_status": "ACCEPTED",
                "command": reply,
                "state": entry.handle.state()
            }))
        }
    }

    async fn execution_wait(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let mut operation = request
            .parameters
            .get("operation_id")
            .and_then(Value::as_str)
            .map(|operation_id| {
                self.store
                    .get_operation(operation_id)?
                    .ok_or_else(|| Error::new(ErrorCode::NotFound, "operation not found"))
            })
            .transpose()?;
        if operation
            .as_ref()
            .is_some_and(|operation| operation.session_id != *entry.handle.id())
        {
            return Err(Error::new(
                ErrorCode::NotFound,
                "operation does not belong to this session",
            ));
        }
        let wait = wait_spec(&request.parameters)?.ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "wait parameters are required")
        })?;
        // 2026-08-28: Waiting without the operation's creation baseline let
        // an unrelated current or future state complete the wrong operation.
        let baseline = operation
            .as_ref()
            .map(|operation| {
                operation.wait_baseline.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidState,
                        "operation predates attributable wait state",
                    )
                })
            })
            .transpose()?;
        let expected_execution_epoch = operation
            .as_ref()
            .map(|operation| {
                operation.expected_execution_epoch.ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidState,
                        "operation predates attributable execution state",
                    )
                })
            })
            .transpose()?;
        let state =
            apply_wait_baseline(&entry.handle, wait, baseline, expected_execution_epoch).await?;
        if let Some(operation) = &mut operation {
            operation.status = OperationStatus::Completed;
            operation.completed_event_seq = Some(state.event_seq);
            self.store.upsert_operation(operation)?;
        }
        Ok(json!({ "operation": operation, "state": state }))
    }

    async fn breakpoint_create(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let kind = request
            .parameters
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("software");
        let mut needs_location = true;
        let mut command = if matches!(kind, "watchpoint" | "read_watchpoint" | "access_watchpoint")
        {
            let mut command = MiCommand::new("-break-watch")?;
            if kind == "read_watchpoint" {
                command = command.bare("-r")?;
            } else if kind == "access_watchpoint" {
                command = command.bare("-a")?;
            }
            command
        } else if kind == "catchpoint" {
            needs_location = false;
            let catch = string(&request.parameters, "catch")?;
            MiCommand::new(match catch.as_str() {
                "throw" => "-catch-throw",
                "catch" => "-catch-catch",
                "exec" => "-catch-exec",
                "fork" => "-catch-fork",
                "vfork" => "-catch-vfork",
                "syscall" => "-catch-syscall",
                "load" => "-catch-load",
                "unload" => "-catch-unload",
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "unsupported catchpoint kind",
                    ));
                }
            })?
        } else {
            if !matches!(kind, "software" | "hardware" | "temporary" | "instruction") {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unsupported breakpoint kind",
                ));
            }
            let mut command = MiCommand::new("-break-insert")?;
            if kind == "temporary" || bool_value(&request.parameters, "temporary", false) {
                command = command.bare("-t")?;
            }
            let hardware = request.parameters.get("hardware");
            if kind == "hardware"
                || hardware.and_then(Value::as_bool) == Some(true)
                || hardware.and_then(Value::as_str) == Some("required")
            {
                command = command.bare("-h")?;
            }
            if bool_value(&request.parameters, "pending", true) {
                command = command.bare("-f")?;
            }
            if let Some(condition) = request.parameters.get("condition").and_then(Value::as_str) {
                command = command.bare("-c")?.string(condition);
            }
            if let Some(ignore) = request
                .parameters
                .get("ignore_count")
                .and_then(Value::as_u64)
            {
                command = command.bare("-i")?.bare(ignore.to_string())?;
            }
            command
        };
        command = breakpoint_scope(command, &request.parameters, &entry.handle.state())?;
        if needs_location {
            command = command.string(self.breakpoint_location(&request.parameters)?);
        }
        let reply = entry.handle.command(command).await?;
        if let Some(fields) =
            MiResult::find(reply.record.results(), "bkpt").and_then(MiValue::results)
        {
            synchronize_breakpoint(&entry.handle, fields).await?;
        }
        Ok(json!({ "command": reply, "breakpoints": entry.handle.state().breakpoints }))
    }

    async fn breakpoint_update(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let number = breakpoint_number(&entry, &request.parameters)?;
        if !["enabled", "condition", "ignore_count"]
            .iter()
            .any(|field| request.parameters.get(*field).is_some())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "breakpoint.update requires enabled, condition, or ignore_count",
            ));
        }
        // 2026-08-28: An else-if chain silently ignored every update field
        // after the first. Apply the complete validated patch and refresh the
        // managed registry even when GDB rejects a later command.
        let update: Result<Vec<CommandReply>> = async {
            let mut replies = Vec::new();
            if let Some(enabled) = request.parameters.get("enabled").and_then(Value::as_bool) {
                replies.push(
                    entry
                        .handle
                        .command(
                            MiCommand::new(if enabled {
                                "-break-enable"
                            } else {
                                "-break-disable"
                            })?
                            .bare(number.clone())?,
                        )
                        .await?,
                );
            }
            if let Some(condition) = request.parameters.get("condition").and_then(Value::as_str) {
                replies.push(
                    entry
                        .handle
                        .command(
                            MiCommand::new("-break-condition")?
                                .bare(number.clone())?
                                .string(condition),
                        )
                        .await?,
                );
            }
            if let Some(ignore) = request
                .parameters
                .get("ignore_count")
                .and_then(Value::as_u64)
            {
                replies.push(
                    entry
                        .handle
                        .command(
                            MiCommand::new("-break-after")?
                                .bare(number)?
                                .bare(ignore.to_string())?,
                        )
                        .await?,
                );
            }
            Ok(replies)
        }
        .await;
        let list = entry.handle.command(MiCommand::new("-break-list")?).await;
        if let Ok(list) = &list {
            reconcile_breakpoints(&entry.handle, &list.record).await?;
        }
        let replies = update?;
        let list = list?;
        Ok(json!({
            "command": replies.last(),
            "commands": replies,
            "breakpoints": entry.handle.state().breakpoints,
            "evidence_seq": list.evidence_seq
        }))
    }

    async fn breakpoint_delete(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let number = breakpoint_number(&entry, &request.parameters)?;
        let reply = entry
            .handle
            .command(MiCommand::new("-break-delete")?.bare(number)?)
            .await?;
        let list = entry.handle.command(MiCommand::new("-break-list")?).await?;
        reconcile_breakpoints(&entry.handle, &list.record).await?;
        Ok(json!({
            "command": reply,
            "breakpoints": entry.handle.state().breakpoints,
            "evidence_seq": list.evidence_seq
        }))
    }

    async fn breakpoint_list(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let reply = entry.handle.command(MiCommand::new("-break-list")?).await?;
        reconcile_breakpoints(&entry.handle, &reply.record).await?;
        Ok(json!({
            "breakpoints": entry.handle.state().breakpoints,
            "evidence_seq": reply.evidence_seq
        }))
    }

    async fn inspection_get(&self, request: &ApiRequest) -> Result<Value> {
        let view = string(&request.parameters, "view")?;
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        match view.as_str() {
            "stop_context" | "target" => Ok(serde_json::to_value(state)?),
            "capabilities" => Ok(serde_json::to_value(entry.handle.capabilities())?),
            "providers" => self.session_providers(request).await,
            "crash" => {
                let mut snapshot = self.inspection_snapshot(request).await?;
                snapshot["crash_signature"] =
                    Value::String(crate::providers::crash_signature(&entry.handle.state()));
                snapshot["source"] = json!({
                    "provider": "userland-security",
                    "version": "1.0.0",
                    "mechanism": "bounded-stop-snapshot"
                });
                Ok(snapshot)
            }
            "threads" => {
                let reply = self
                    .inspection_command(&entry, request, "-thread-info", vec![])
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "threads": normalized_threads(&reply.record, &state),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "stack" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                let offset = request
                    .parameters
                    .get("offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as usize;
                let end = offset.saturating_add(limit - 1);
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-frames",
                        vec![("bare", offset.to_string()), ("bare", end.to_string())],
                    )
                    .await?;
                let frames = normalized_frames(&reply.record, &state, &request.parameters);
                let continuation = (frames.len() == limit).then(|| {
                    format!(
                        "stack:{}:{}",
                        state.stop_id.as_ref().unwrap(),
                        offset + frames.len()
                    )
                });
                Ok(json!({
                    "stop_id": state.stop_id,
                    "offset": offset,
                    "limit": limit,
                    "frames": frames,
                    "continuation": continuation,
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "frame" => {
                let reply = self
                    .inspection_command(&entry, request, "-stack-info-frame", vec![])
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "frame": frame_summary(&reply.record),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "locals" => {
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-variables",
                        vec![("bare", "--simple-values".into())],
                    )
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "variables": normalized_variables(&reply.record, "variables"),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "arguments" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                let offset = request
                    .parameters
                    .get("offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as usize;
                let end = offset.saturating_add(limit - 1);
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-arguments",
                        vec![
                            ("bare", "--simple-values".into()),
                            ("bare", offset.to_string()),
                            ("bare", end.to_string()),
                        ],
                    )
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "offset": offset,
                    "limit": limit,
                    "arguments": normalized_arguments(&reply.record),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "registers" => self.register_read(request).await,
            "modules" => {
                let reply = self
                    .inspection_command(&entry, request, "-file-list-shared-libraries", vec![])
                    .await?;
                Ok(json!({
                    "modules": normalized_modules(&reply.record),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "breakpoints" => {
                let reply = entry.handle.command(MiCommand::new("-break-list")?).await?;
                reconcile_breakpoints(&entry.handle, &reply.record).await?;
                Ok(json!({
                    "breakpoints": entry.handle.state().breakpoints,
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "source" => {
                if request.parameters.get("path").is_some() {
                    self.source_excerpt(request)
                } else {
                    let reply = self
                        .inspection_command(&entry, request, "-file-list-exec-source-files", vec![])
                        .await?;
                    Ok(json!({
                        "files": normalized_source_files(&reply.record),
                        "evidence_seq": reply.evidence_seq
                    }))
                }
            }
            "mappings" => mappings(&state),
            "signals" => Ok(serde_json::to_value(state.signal_policies)?),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "unsupported inspection view",
            )),
        }
    }

    async fn inspection_command(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        name: &str,
        arguments: Vec<(&str, String)>,
    ) -> Result<CommandReply> {
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let mut command = MiCommand::new(name)?;
        command = context_options(command, &request.parameters, &state)?;
        for (kind, argument) in arguments {
            command = if kind == "bare" {
                command.bare(argument)?
            } else {
                command.string(argument)
            };
        }
        entry.handle.command(command).await
    }

    async fn inspection_snapshot(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let profile = request
            .parameters
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or("standard");
        let frames = match profile {
            "minimal" => 1,
            "brief" => 3,
            "standard" => 8,
            "deep" => bounded_limit(&request.parameters, 8, self.config.limits.stack_frames)?,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unknown snapshot profile",
                ));
            }
        };
        // 2026-08-28: Publishing SnapshotStarted before profile validation
        // left the current snapshot permanently BUILDING on invalid input.
        entry
            .handle
            .record_event(DomainEvent::SnapshotStarted {
                stop_id: state.stop_id.clone().unwrap(),
            })
            .await?;
        let built = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(self.build_and_commit_snapshot(&entry, request, &state, profile, frames)),
            )
            .await;
        if built.is_err() {
            entry
                .handle
                .record_event(DomainEvent::SnapshotFailed {
                    stop_id: state.stop_id.clone().unwrap(),
                })
                .await?;
        }
        built
    }

    async fn build_and_commit_snapshot(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        state: &crate::domain::SessionState,
        profile: &str,
        frames: usize,
    ) -> Result<Value> {
        let mut warnings = Vec::new();
        let stack = optional_command(
            &entry.handle,
            context_options(
                MiCommand::new("-stack-list-frames")?,
                &request.parameters,
                state,
            )?
            .bare("0")?
            .bare((frames - 1).to_string())?,
            "stack",
            &mut warnings,
        )
        .await
        .map(|reply| normalized_frames(&reply.record, state, &request.parameters))
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
        let locals = if profile == "minimal" {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-stack-list-variables")?,
                    &request.parameters,
                    state,
                )?
                .bare("--simple-values")?,
                "locals",
                &mut warnings,
            )
            .await
            .map(|reply| normalized_variables(&reply.record, "variables"))
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null)
        };
        let arguments = if profile == "minimal" {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-stack-list-arguments")?,
                    &request.parameters,
                    state,
                )?
                .bare("--simple-values")?
                .bare("0")?
                .bare((frames - 1).to_string())?,
                "arguments",
                &mut warnings,
            )
            .await
            .map(|reply| normalized_arguments(&reply.record))
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null)
        };
        let registers = if profile == "minimal" {
            Value::Null
        } else {
            match self.register_read(request).await {
                Ok(registers) => registers,
                Err(error) => {
                    warnings.push(json!({
                        "code": "REGISTERS_UNAVAILABLE",
                        "message": error.to_string()
                    }));
                    Value::Null
                }
            }
        };
        let disassembly = if matches!(profile, "brief" | "standard" | "deep") {
            match self.disassembly_read(request).await {
                Ok(disassembly) => disassembly,
                Err(error) => {
                    warnings.push(json!({
                        "code": "DISASSEMBLY_UNAVAILABLE",
                        "message": error.to_string()
                    }));
                    Value::Null
                }
            }
        } else {
            Value::Null
        };
        let (tracked, changes) = match self
            .capture_tracking(entry, request, state, &mut warnings)
            .await
        {
            Ok(tracking) => tracking,
            Err(error) => {
                warnings.push(json!({
                    "code": "TRACKING_UNAVAILABLE",
                    "message": error.to_string()
                }));
                (BTreeMap::new(), BTreeMap::new())
            }
        };
        let partial = !warnings.is_empty();
        let stop_id = state.stop_id.clone().unwrap();
        self.metrics.snapshot(partial);
        let current = entry.handle.state();
        let snapshot_id = format!("snap_{stop_id}");
        let snapshot = json!({
            "snapshot_id": &snapshot_id,
            "stop_id": &stop_id,
            "revision": current.revision,
            "profile": profile,
            "reason": state.stop_reason,
            "reason_detail": state.stop_reason_detail,
            "stack": stack,
            "locals": locals,
            "arguments": arguments,
            "registers": registers,
            "disassembly": disassembly,
            "tracked": tracked,
            "changes": changes,
            "warnings": warnings,
            "partial": partial,
            "evidence": [{"kind": "mi-event", "uri": format!("gdbai://session/{}/event/{}", entry.handle.id(), current.event_seq)}]
        });
        entry
            .handle
            .commit_snapshot(
                snapshot_id,
                snapshot.clone(),
                stop_id,
                state.execution_epoch,
                partial,
            )
            .await?;
        Ok(snapshot)
    }

    async fn inspection_diff(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let before_id = string(&request.parameters, "before_snapshot_id")?;
        let after_id = string(&request.parameters, "after_snapshot_id")?;
        let before = entry.handle.snapshot(before_id.clone()).await?;
        let after = entry.handle.snapshot(after_id.clone()).await?;
        let mut changes = BTreeMap::new();
        for field in ["reason", "stack", "locals", "registers", "tracked"] {
            let old = before.get(field).cloned().unwrap_or(Value::Null);
            let new = after.get(field).cloned().unwrap_or(Value::Null);
            if old != new {
                changes.insert(field, json!({ "before": old, "after": new }));
            }
        }
        Ok(json!({
            "before_snapshot_id": before_id,
            "after_snapshot_id": after_id,
            "changes": changes,
            "partial": before.get("partial") == Some(&Value::Bool(true))
                || after.get("partial") == Some(&Value::Bool(true))
        }))
    }

    async fn inspection_snapshot_get(&self, request: &ApiRequest) -> Result<Value> {
        let session_id = SessionId::parse(required_session(request)?)?;
        let snapshot_id = string(&request.parameters, "snapshot_id")?;
        if let Ok(entry) = self.entry(&session_id.0).await {
            return entry.handle.snapshot(snapshot_id).await;
        }
        // 2026-08-28: Historical snapshots remain authoritative SQLite
        // evidence after the live worker has been removed from the registry.
        self.store
            .get_snapshot(&session_id, &snapshot_id)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot not found"))
    }

    async fn inspection_batch(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        require_stopped_context(&request.parameters, &baseline)?;
        let requests = request
            .parameters
            .get("requests")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "batch requests are required"))?;
        if requests.is_empty() || requests.len() > 16 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "batch accepts 1 to 16 reads",
            ));
        }
        entry
            .handle
            .stable_observation(
                &baseline,
                Box::pin(async {
                    let mut results = BTreeMap::new();
                    for item in requests {
                        let name = string(item, "name")?;
                        if results.contains_key(&name) {
                            return Err(Error::new(
                                ErrorCode::Conflict,
                                "batch request names must be unique",
                            ));
                        }
                        let mut parameters = item.clone();
                        parameters["stop_id"] =
                            Value::String(baseline.stop_id.as_ref().unwrap().0.clone());
                        let subrequest = ApiRequest {
                            api_version: request.api_version.clone(),
                            request_id: format!("{}:{name}", request.request_id),
                            session_id: request.session_id.clone(),
                            method: CanonicalMethod::InspectionGet,
                            expected_revision: None,
                            idempotency_key: None,
                            parameters,
                        };
                        results.insert(name, self.inspection_get(&subrequest).await?);
                    }
                    Ok(json!({
                        "stop_id": baseline.stop_id,
                        "revision": entry.handle.state().revision,
                        "results": results
                    }))
                }),
            )
            .await
    }

    async fn capture_tracking(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        state: &crate::domain::SessionState,
        warnings: &mut Vec<Value>,
    ) -> Result<(BTreeMap<String, Value>, BTreeMap<String, Value>)> {
        let mut observations = BTreeMap::new();
        let mut presented = BTreeMap::new();
        for definition in entry.handle.tracking().await? {
            let tracking_id = definition.id().0.clone();
            let observation = match definition {
                TrackingDefinition::Expression {
                    expression,
                    max_value_bytes,
                    ..
                } => {
                    let command = context_options(
                        MiCommand::new("-data-evaluate-expression")?.string(&expression),
                        &request.parameters,
                        state,
                    )?;
                    match safe_evaluate_command(&entry.handle, command).await {
                        Ok(reply) => {
                            let value = result_text(&reply.record, "value").unwrap_or_default();
                            if value.len() > max_value_bytes {
                                let uri = self.put_artifact(
                                    Some(entry.handle.id()),
                                    value.as_bytes(),
                                    "target-value",
                                )?;
                                json!({
                                    "expression": expression,
                                    "sha256": format!("{:x}", Sha256::digest(value.as_bytes())),
                                    "preview": value.chars().take(max_value_bytes.min(256)).collect::<String>(),
                                    "artifact": uri,
                                    "truncated": true
                                })
                            } else {
                                json!({ "expression": expression, "value": value })
                            }
                        }
                        Err(error) => {
                            warnings.push(json!({
                                "code": "TRACKED_EXPRESSION_UNAVAILABLE",
                                "tracking_id": tracking_id,
                                "message": error.to_string()
                            }));
                            continue;
                        }
                    }
                }
                TrackingDefinition::Memory {
                    address_expression,
                    length,
                    ..
                } => {
                    let command = context_options(
                        MiCommand::new("-data-evaluate-expression")?.string(&address_expression),
                        &request.parameters,
                        state,
                    )?;
                    let address = match safe_evaluate_command(&entry.handle, command).await {
                        Ok(reply) => result_text(&reply.record, "value")
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorCode::GdbError,
                                    "tracked address expression returned no value",
                                )
                            })
                            .and_then(|value| parse_address(&value)),
                        Err(error) => Err(error),
                    };
                    let bytes = match address {
                        Ok(address) => {
                            read_memory_bytes(&entry.handle, state, address, length, true).await
                        }
                        Err(error) => Err(error),
                    };
                    match bytes {
                        Ok((bytes, evidence_seq)) => json!({
                            "address_expression": address_expression,
                            "length": bytes.len(),
                            "sha256": format!("{:x}", Sha256::digest(&bytes)),
                            "data_base64": BASE64.encode(&bytes),
                            "evidence_seq": evidence_seq
                        }),
                        Err(error) => {
                            warnings.push(json!({
                                "code": "TRACKED_MEMORY_UNAVAILABLE",
                                "tracking_id": tracking_id,
                                "message": error.to_string()
                            }));
                            continue;
                        }
                    }
                }
            };
            // 2026-08-28: Tracked memory was copied into snapshots and SQLite
            // as base64. Keep bytes only in bounded worker history and artifacts.
            let presentation = match observation
                .get("data_base64")
                .and_then(Value::as_str)
                .and_then(|encoded| BASE64.decode(encoded).ok())
            {
                Some(bytes) if bytes.len() > self.config.limits.inline_memory_bytes => {
                    let uri =
                        self.put_artifact(Some(entry.handle.id()), &bytes, "tracked-memory")?;
                    json!({
                        "address_expression": observation.get("address_expression"),
                        "length": observation.get("length"),
                        "sha256": observation.get("sha256"),
                        "preview_hex": hex_encode(&bytes[..bytes.len().min(64)]),
                        "artifact": uri,
                        "truncated": true,
                        "evidence_seq": observation.get("evidence_seq")
                    })
                }
                _ => observation.clone(),
            };
            observations.insert(tracking_id.clone(), observation);
            presented.insert(tracking_id, presentation);
        }
        let changes = entry.handle.record_tracking(observations).await?;
        Ok((presented, changes))
    }

    async fn value_evaluate(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        if request
            .parameters
            .get("side_effects")
            .and_then(Value::as_str)
            .unwrap_or("deny")
            != "deny"
        {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "the vertical slice only supports side_effects=deny",
            ));
        }
        let evaluate = context_options(
            MiCommand::new("-data-evaluate-expression")?.string(expression),
            &request.parameters,
            &state,
        )?;
        let reply = safe_evaluate_command(&entry.handle, evaluate).await?;
        Ok(json!({
            "stop_id": state.stop_id,
            "value": result_text(&reply.record, "value"),
            "command": reply,
            "side_effects": "denied"
        }))
    }

    async fn value_create(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        let stop_id = state.stop_id.clone().unwrap();
        let value_id = ValueId::for_stop(&stop_id);
        let backend_name = format!("gdbai_{}", Ulid::new());
        let command = context_options(MiCommand::new("-var-create")?, &request.parameters, &state)?
            .bare(&backend_name)?
            .bare("*")?
            .string(&expression);
        let reply = safe_evaluate_command(&entry.handle, command).await?;
        let binding = ValueBinding {
            value_id: value_id.clone(),
            backend_name: backend_name.clone(),
            stop_id: stop_id.clone(),
            expression: expression.clone(),
        };
        if let Err(error) = entry.handle.register_value(binding).await {
            let _ = entry
                .handle
                .command(MiCommand::new("-var-delete")?.bare(backend_name)?)
                .await;
            return Err(error);
        }
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "value_created".into(),
            })
            .await?;
        Ok(json!({
            "value_id": value_id,
            "stop_id": stop_id,
            "expression": expression,
            "value": result_text(&reply.record, "value"),
            "type": result_text(&reply.record, "type"),
            "children_count": result_text(&reply.record, "numchild")
                .and_then(|value| value.parse::<u64>().ok()),
            "has_children": result_text(&reply.record, "numchild")
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|count| count > 0),
            "command": reply
        }))
    }

    async fn value_children(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let offset = request
            .parameters
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let limit = bounded_limit(&request.parameters, 100, self.config.limits.value_children)?;
        let end = offset.saturating_add(limit);
        let reply = entry
            .handle
            .command(
                MiCommand::new("-var-list-children")?
                    .bare("--simple-values")?
                    .bare(&binding.backend_name)?
                    .bare(offset.to_string())?
                    .bare(end.to_string())?,
            )
            .await?;
        let has_more = result_text(&reply.record, "has_more") == Some("1".into());
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "offset": offset,
            "limit": limit,
            "result": reply,
            "continuation": has_more.then(|| format!("{}:{}", binding.value_id, end))
        }))
    }

    async fn value_update(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let reply = entry
            .handle
            .command(
                MiCommand::new("-var-update")?
                    .bare("--simple-values")?
                    .bare(&binding.backend_name)?,
            )
            .await?;
        Ok(json!({
            "value_id": binding.value_id,
            "stop_id": binding.stop_id,
            "result": reply
        }))
    }

    async fn value_release(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        let binding = current_value_binding(&entry, request, &state).await?;
        let reply = entry
            .handle
            .command(MiCommand::new("-var-delete")?.bare(&binding.backend_name)?)
            .await?;
        entry
            .handle
            .remove_value(binding.value_id.0.clone())
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "value_released".into(),
            })
            .await?;
        Ok(json!({ "released": binding.value_id, "command": reply }))
    }

    async fn memory_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address_text = string(&request.parameters, "address")?;
        let address = crate::domain::Address::parse(&address_text)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        // 2026-08-28: The public read limit was accidentally capped to one
        // backend chunk, making the configured 16 MiB logical limit unusable.
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "memory length must be between 1 and {}",
                    self.config.limits.memory_read_bytes
                ),
            ));
        }
        let (bytes, evidence_seq) = read_memory_bytes(
            &entry.handle,
            &state,
            parse_address(address.as_str())?,
            length,
            bool_value(&request.parameters, "allow_partial", false),
        )
        .await?;
        let partial = bytes.len() != length;
        if partial && !bool_value(&request.parameters, "allow_partial", false) {
            return Err(Error::new(
                ErrorCode::PartialRead,
                format!("requested {length} bytes, read {}", bytes.len()),
            ));
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if bytes.len() > self.config.limits.inline_memory_bytes {
            let uri = self.put_artifact(Some(entry.handle.id()), &bytes, "target-memory")?;
            Ok(json!({
                "address": address,
                "requested_length": length,
                "read_length": bytes.len(),
                "sha256": sha256,
                "preview_hex": hex_encode(&bytes[..bytes.len().min(64)]),
                "artifact": uri,
                "partial": partial,
                "truncated": true,
                "evidence_seq": evidence_seq
            }))
        } else {
            Ok(json!({
                "address": address,
                "requested_length": length,
                "read_length": bytes.len(),
                "data_base64": BASE64.encode(&bytes),
                "sha256": sha256,
                "partial": partial,
                "truncated": false,
                "evidence_seq": evidence_seq
            }))
        }
    }

    async fn memory_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address = crate::domain::Address::parse(&string(&request.parameters, "address")?)?;
        let bytes = input_bytes(&request.parameters)?;
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory writes must contain 1 to 65536 bytes",
            ));
        }
        // 2026-08-28: Releasing the composite read before compare-and-write
        // allowed another direct SessionHandle command to invalidate the
        // precondition. Keep the read, check, write, and state event together.
        let (before, reply) = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let (before, _) = read_memory_bytes(
                        &entry.handle,
                        &state,
                        parse_address(address.as_str())?,
                        bytes.len(),
                        false,
                    )
                    .await?;
                    require_expected_bytes(&request.parameters, &before)?;
                    let reply = entry
                        .handle
                        .command(
                            MiCommand::new("-data-write-memory-bytes")?
                                .bare(address.as_str())?
                                .bare(hex_encode(&bytes))?,
                        )
                        .await?;
                    entry
                        .handle
                        .record_event(DomainEvent::MemoryChanged)
                        .await?;
                    Ok((before, reply))
                }),
            )
            .await?;
        Ok(json!({
            "address": address,
            "length": bytes.len(),
            "before_sha256": format!("{:x}", Sha256::digest(&before)),
            "after_sha256": format!("{:x}", Sha256::digest(&bytes)),
            "snapshot_invalidated": true,
            "command": reply
        }))
    }

    async fn memory_compare(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address = crate::domain::Address::parse(&string(&request.parameters, "address")?)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory comparison length is outside configured limits",
            ));
        }
        let (bytes, evidence_seq) = read_memory_bytes(
            &entry.handle,
            &state,
            parse_address(address.as_str())?,
            length,
            false,
        )
        .await?;
        let matches = expected_bytes_match(&request.parameters, &bytes)?;
        Ok(json!({
            "address": address,
            "length": length,
            "matches": matches,
            "sha256": format!("{:x}", Sha256::digest(&bytes)),
            "evidence_seq": evidence_seq
        }))
    }

    async fn memory_search(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let start = crate::domain::Address::parse(&string(&request.parameters, "start")?)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory search length is outside configured limits",
            ));
        }
        let pattern = search_pattern(&request.parameters)?;
        let max_results = request
            .parameters
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 1_000) as usize;
        let start_number = parse_address(start.as_str())?;
        let (bytes, evidence_seq) =
            read_memory_bytes(&entry.handle, &state, start_number, length, true).await?;
        let mut matches = bytes
            .windows(pattern.len())
            .enumerate()
            .filter(|(_, window)| *window == pattern.as_slice())
            .take(max_results + 1)
            .map(|(offset, _)| format!("0x{:016x}", start_number + offset as u64))
            .collect::<Vec<_>>();
        // 2026-08-28: Exactly max_results matches was incorrectly reported as
        // truncated. Read one sentinel match before setting the flag.
        let truncated = matches.len() > max_results;
        matches.truncate(max_results);
        // 2026-08-28: Search permits a bounded short read, but callers could
        // only infer it from two lengths. Mark partial evidence explicitly.
        let partial = bytes.len() < length;
        Ok(json!({
            "start": start,
            "requested_length": length,
            "searched_length": bytes.len(),
            "matches": matches,
            "partial": partial,
            "truncated": truncated,
            "evidence_seq": evidence_seq
        }))
    }

    async fn register_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let names_reply = entry
            .handle
            .command(MiCommand::new("-data-list-register-names")?)
            .await?;
        let names = result_string_list(&names_reply.record, "register-names");
        let requested_roles = request
            .parameters
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["pc".into(), "sp".into(), "fp".into(), "return".into()]);
        let mut role_numbers = BTreeMap::new();
        for role in requested_roles {
            let candidates = register_role_candidates(&role).ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown register role {role}"),
                )
            })?;
            if let Some((number, _)) = names
                .iter()
                .enumerate()
                .find(|(_, name)| candidates.contains(&name.as_str()))
            {
                role_numbers.insert(role, number);
            }
        }
        let architecture = if names.iter().any(|name| name == "rip") {
            "i386:x86-64"
        } else if names.iter().any(|name| name == "x29") {
            "aarch64"
        } else {
            "unknown"
        };
        // 2026-08-28: GDB interprets an empty register-number list as all
        // registers. Return an explicit empty role map instead of expanding a
        // missing semantic role into an unbounded backend observation.
        if role_numbers.is_empty() {
            return Ok(json!({
                "stop_id": state.stop_id,
                "roles": {},
                "architecture": architecture,
                "limitations": ["requested register roles are unavailable"],
                "evidence_seq": names_reply.evidence_seq
            }));
        }
        let mut command = context_options(
            MiCommand::new("-data-list-register-values")?.bare("x")?,
            &request.parameters,
            &state,
        )?;
        for number in role_numbers.values() {
            command = command.bare(number.to_string())?;
        }
        let values_reply = entry.handle.command(command).await?;
        let values = register_values(&values_reply.record);
        let roles: BTreeMap<String, Value> = role_numbers
            .into_iter()
            .map(|(role, number)| {
                let value = values.get(&number).cloned().unwrap_or(Value::Null);
                (role, value)
            })
            .collect();
        Ok(json!({
            "stop_id": state.stop_id,
            "roles": roles,
            "architecture": architecture,
            "evidence_seq": values_reply.evidence_seq
        }))
    }

    async fn register_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let requested = string(&request.parameters, "register")?;
        let value = string(&request.parameters, "value")?;
        let reason = string(&request.parameters, "reason")?;
        if !valid_integer_literal(&value) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "register value must be a decimal or hexadecimal integer",
            ));
        }
        // 2026-08-28: Register compare/write evidence previously released the
        // command sequence between MI requests, so another command could alter
        // the register before the recorded after-value. Keep it one observation.
        let (register, before, write, after) = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let names_reply = entry
                        .handle
                        .command(MiCommand::new("-data-list-register-names")?)
                        .await?;
                    let names = result_string_list(&names_reply.record, "register-names");
                    let register = resolve_register_name(&requested, &names)?;
                    let read = |expression: String| {
                        context_options(
                            MiCommand::new("-data-evaluate-expression")?.string(expression),
                            &request.parameters,
                            &state,
                        )
                    };
                    let before = entry.handle.command(read(format!("${register}"))?).await?;
                    let write = entry
                        .handle
                        .command(read(format!("${register}={value}"))?)
                        .await?;
                    let after = entry.handle.command(read(format!("${register}"))?).await?;
                    entry
                        .handle
                        .record_event(DomainEvent::RegisterChanged {
                            register: register.clone(),
                        })
                        .await?;
                    Ok((register, before, write, after))
                }),
            )
            .await?;
        Ok(json!({
            "register": register,
            "before": result_text(&before.record, "value"),
            "after": result_text(&after.record, "value"),
            "reason": reason,
            "snapshot_invalidated": true,
            "command": write
        }))
    }

    async fn disassembly_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let (start, end, current) = if let Some(range) = request.parameters.get("range") {
            let start = crate::domain::Address::parse(&string(range, "start")?)?;
            let end = crate::domain::Address::parse(&string(range, "end")?)?;
            let start_number = parse_address(start.as_str())?;
            let end_number = parse_address(end.as_str())?;
            if end_number <= start_number || end_number - start_number > 64 * 1024 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "disassembly range must be positive and at most 64 KiB",
                ));
            }
            (start_number, end_number, None)
        } else {
            let around = request
                .parameters
                .get("around")
                .unwrap_or(&request.parameters);
            let expression = around
                .get("expression")
                .and_then(Value::as_str)
                .unwrap_or("$pc");
            let reply = entry
                .handle
                .command(context_options(
                    MiCommand::new("-data-evaluate-expression")?.string(expression),
                    &request.parameters,
                    &state,
                )?)
                .await?;
            let address = result_text(&reply.record, "value")
                .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB did not return an address"))?;
            let address = parse_address(&address)?;
            let before = around
                .get("before_instructions")
                .and_then(Value::as_u64)
                .unwrap_or(8)
                .min(64);
            let after = around
                .get("after_instructions")
                .and_then(Value::as_u64)
                .unwrap_or(16)
                .min(64);
            (
                address.saturating_sub(before * 16),
                address.saturating_add(after * 16 + 16),
                Some(address),
            )
        };
        let include_source = bool_value(&request.parameters, "include_source", true);
        let include_bytes = bool_value(&request.parameters, "include_bytes", true);
        let mode = match (include_source, include_bytes) {
            (false, false) => "0",
            (true, false) => "1",
            (false, true) => "2",
            (true, true) => "3",
        };
        let reply = entry
            .handle
            .command(
                MiCommand::new("-data-disassemble")?
                    .bare("-s")?
                    .bare(format!("0x{start:x}"))?
                    .bare("-e")?
                    .bare(format!("0x{end:x}"))?
                    .bare("--")?
                    .bare(mode)?,
            )
            .await?;
        let architecture = entry
            .handle
            .command(MiCommand::new("-gdb-show")?.bare("architecture")?)
            .await
            .ok()
            .and_then(|reply| result_text(&reply.record, "value"));
        let instructions = disassembly_instructions(&reply.record, current);
        Ok(json!({
            "architecture": architecture,
            "syntax": "target-default",
            "range": {"start": format!("0x{start:016x}"), "end": format!("0x{end:016x}")},
            "instructions": instructions,
            "evidence_seq": reply.evidence_seq,
            "bounded": true
        }))
    }

    async fn io_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let offset = request
            .parameters
            .get("after_offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(64 * 1024)
            .min(64 * 1024) as usize;
        let ring = match request
            .parameters
            .get("stream")
            .and_then(Value::as_str)
            .unwrap_or("pty")
        {
            "pty" => OutputRing::Inferior,
            "target" => OutputRing::Target,
            "console" => OutputRing::Console,
            "log" => OutputRing::Log,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unknown output stream",
                ));
            }
        };
        let read = entry.handle.read_output(ring, offset, max_bytes).await?;
        let text = std::str::from_utf8(&read.bytes).ok().map(str::to_owned);
        Ok(json!({
            "requested_offset": read.requested_offset,
            "available_from": read.available_from,
            "next_offset": read.next_offset,
            "gap": read.gap,
            "encoding": if text.is_some() { "utf-8" } else { "binary" },
            "text": text,
            "data_base64": BASE64.encode(read.bytes)
        }))
    }

    async fn io_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let bytes = input_bytes(&request.parameters)?;
        if bytes.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "inferior input is limited to 64 KiB per call",
            ));
        }
        entry.handle.write_inferior(bytes.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_input".into(),
            })
            .await?;
        Ok(json!({ "written": bytes.len() }))
    }

    async fn io_send_eof(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        // 2026-08-28: Writing VEOF to a PTY never closes its file descriptor;
        // the old close_stdin result falsely claimed an OS-level half-close.
        entry.handle.write_inferior(vec![0x04]).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_veof_sent".into(),
            })
            .await?;
        Ok(json!({
            "sent": true,
            "closed": false,
            "mechanism": "pty_veof"
        }))
    }

    async fn io_resize(&self, request: &ApiRequest) -> Result<Value> {
        let rows = unsigned(&request.parameters, "rows")?;
        let columns = unsigned(&request.parameters, "columns")?;
        if rows == 0 || columns == 0 || rows > u16::MAX as u64 || columns > u16::MAX as u64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid PTY dimensions",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        entry
            .handle
            .resize_inferior(rows as u16, columns as u16)
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_terminal_resized".into(),
            })
            .await?;
        Ok(json!({ "rows": rows, "columns": columns }))
    }

    async fn tracking_add_expression(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        let max_value_bytes = request
            .parameters
            .get("max_value_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4_096) as usize;
        if max_value_bytes == 0 || max_value_bytes > 1024 * 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "max_value_bytes must be between 1 and 1048576",
            ));
        }
        let definition = TrackingDefinition::Expression {
            tracking_id: TrackingId::new(),
            expression,
            max_value_bytes,
        };
        entry.handle.add_tracking(definition.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_added".into(),
            })
            .await?;
        Ok(serde_json::to_value(definition)?)
    }

    async fn tracking_add_memory(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let address_expression = string(&request.parameters, "address_expression")?;
        validate_expression(&address_expression)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "tracked memory length is outside configured limits",
            ));
        }
        let max_history = request
            .parameters
            .get("max_history")
            .and_then(Value::as_u64)
            .unwrap_or(32)
            .clamp(1, 256) as usize;
        let definition = TrackingDefinition::Memory {
            tracking_id: TrackingId::new(),
            address_expression,
            length,
            max_history,
        };
        entry.handle.add_tracking(definition.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_added".into(),
            })
            .await?;
        Ok(serde_json::to_value(definition)?)
    }

    async fn tracking_remove(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let tracking_id = string(&request.parameters, "tracking_id")?;
        let removed = entry.handle.remove_tracking(tracking_id).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_removed".into(),
            })
            .await?;
        Ok(json!({ "removed": removed }))
    }

    async fn tracking_list(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(entry.handle.tracking().await?)?)
    }

    async fn signal_get(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(entry.handle.state().signal_policies)?)
    }

    async fn signal_update(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let policies = request
            .parameters
            .get("signals")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "signals object is required"))?;
        if policies.is_empty() || policies.len() > 64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "signals must contain 1 to 64 entries",
            ));
        }
        // 2026-08-28: Validating while executing allowed a malformed later
        // entry to return INVALID_ARGUMENT after earlier policies had changed.
        let policies = policies
            .iter()
            .map(|(signal, value)| {
                if !valid_signal_name(signal) {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid signal name {signal}"),
                    ));
                }
                let policy = serde_json::from_value(value.clone())
                    .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
                Ok((signal.clone(), policy))
            })
            .collect::<Result<BTreeMap<String, SignalPolicyState>>>()?;
        let extension = entry.handle.capabilities().supports("custom_extension");
        let mut applied = BTreeMap::new();
        for (signal, policy) in policies {
            let command = if extension {
                MiCommand::new("-gdb-ai-signal-policy")?
                    .bare(signal.clone())?
                    .bare(policy.stop.to_string())?
                    .bare(policy.print.to_string())?
                    .bare(policy.pass.to_string())?
            } else {
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(format!(
                        "handle {signal} {} {} {}",
                        if policy.stop { "stop" } else { "nostop" },
                        if policy.print { "print" } else { "noprint" },
                        if policy.pass { "pass" } else { "nopass" }
                    ))
            };
            if let Err(error) = entry.handle.command(command).await {
                return Err(error.with_details(json!({
                    "partial": !applied.is_empty(),
                    "applied": applied
                })));
            }
            entry
                .handle
                .record_event(DomainEvent::SignalPolicyChanged {
                    signal: signal.clone(),
                    policy: policy.clone(),
                })
                .await?;
            applied.insert(signal, policy);
        }
        Ok(
            json!({ "signals": applied, "mechanism": if extension { "gdb-python-mi" } else { "controlled-console" } }),
        )
    }

    async fn agent_hypothesis_check(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        let expected = string(&request.parameters, "expected")?;
        let operator = request
            .parameters
            .get("operator")
            .and_then(Value::as_str)
            .unwrap_or("equals");
        let command = context_options(
            MiCommand::new("-data-evaluate-expression")?.string(&expression),
            &request.parameters,
            &state,
        )?;
        let reply = safe_evaluate_command(&entry.handle, command).await?;
        let actual = result_text(&reply.record, "value").unwrap_or_default();
        let confirmed = compare_observation(&actual, operator, &expected)?;
        Ok(json!({
            "claim": request.parameters.get("claim"),
            "expression": expression,
            "operator": operator,
            "expected": expected,
            "actual": actual,
            "verdict": if confirmed { "confirmed" } else { "refuted" },
            "stop_id": state.stop_id,
            "evidence": [{
                "kind": "mi-result",
                "uri": format!("gdbai://session/{}/event/{}", entry.handle.id(), reply.evidence_seq)
            }]
        }))
    }

    async fn agent_probe(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let initial = entry.handle.state();
        require_stopped_context(&request.parameters, &initial)?;
        let budget: ObservationBudget = request
            .parameters
            .get("budget")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?
            .unwrap_or_default();
        budget.validate(&self.config)?;
        let max_hits = request
            .parameters
            .get("max_hits")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, 100) as usize;
        let stop_policy = request
            .parameters
            .get("stop_policy")
            .and_then(Value::as_str)
            .unwrap_or("on_condition");
        if !matches!(stop_policy, "on_condition" | "continue_after_capture") {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "stop_policy must be on_condition or continue_after_capture",
            ));
        }
        let mut insert = MiCommand::new("-break-insert")?.bare("-f")?;
        if let Some(condition) = request.parameters.get("condition").and_then(Value::as_str) {
            validate_expression(condition)?;
            insert = insert.bare("-c")?.string(condition);
        }
        insert = insert.string(self.breakpoint_location(&request.parameters)?);
        let inserted = entry.handle.command(insert).await?;
        let backend_number = breakpoint_number_from_record(&inserted.record)?;
        let mut operation = OperationRecord {
            operation_id: OperationId::new(),
            session_id: entry.handle.id().clone(),
            kind: request.method.to_string(),
            status: OperationStatus::WaitingForState,
            created_revision: initial.revision,
            wait_baseline: Some(WaitBaseline::from(&initial)),
            expected_execution_epoch: None,
            accepted_event_seq: Some(inserted.evidence_seq),
            completed_event_seq: None,
            error: None,
        };
        self.store.upsert_operation(&operation)?;
        let mut breakpoint = ProbeBreakpoint {
            handle: entry.handle.clone(),
            store: self.store.clone(),
            operation_id: operation.operation_id.clone(),
            backend_number: Some(backend_number.clone()),
        };
        let started = tokio::time::Instant::now();
        let mut captures = Vec::new();
        let mut calls = 1usize;
        // 2026-08-28: Applying the wall budget only to stop waits let capture
        // commands exceed it repeatedly. Bound the complete experiment body.
        let run_result: Result<Value> =
            match tokio::time::timeout(Duration::from_millis(budget.wall_time_ms), async {
                for hit in 1..=max_hits {
                    if calls >= budget.max_calls {
                        return Err(Error::new(
                            ErrorCode::OutputLimit,
                            "probe exhausted its debugger-call budget",
                        ));
                    }
                    let baseline = entry.handle.state();
                    entry
                        .handle
                        .command(MiCommand::new("-exec-continue")?)
                        .await?;
                    calls += 1;
                    let elapsed = started.elapsed();
                    let remaining = Duration::from_millis(budget.wall_time_ms)
                        .checked_sub(elapsed)
                        .ok_or_else(|| Error::new(ErrorCode::Timeout, "probe timed out"))?;
                    let stopped = entry
                        .handle
                        .wait_after(WaitUntil::Snapshot, remaining, &baseline)
                        .await?;
                    require_probe_hit(&request.parameters, &baseline, &stopped, &backend_number)?;
                    let capture = self
                        .capture_probe_observation(request, &entry, &stopped, &budget, &mut calls)
                        .await?;
                    captures.push(json!({ "hit": hit, "observation": capture }));
                    if stop_policy == "on_condition" || hit == max_hits {
                        break;
                    }
                }
                let serialized = serde_json::to_vec(&captures)?;
                if serialized.len() > budget.max_context_bytes {
                    let uri = self.put_artifact(
                        Some(entry.handle.id()),
                        &serialized,
                        "probe-observations",
                    )?;
                    Ok(json!({
                        "captures": [],
                        "artifact": uri,
                        "capture_count": captures.len(),
                        "truncated": true
                    }))
                } else {
                    Ok(json!({
                        "captures": captures,
                        "capture_count": captures.len(),
                        "truncated": false
                    }))
                }
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(Error::new(ErrorCode::Timeout, "probe timed out")),
            };
        let cleanup = breakpoint.remove().await;
        match run_result {
            Ok(mut result) => {
                let cleanup_error = cleanup.err();
                // 2026-08-28: continue_after_capture stopped after the final
                // hit. Resume only after the temporary breakpoint is removed.
                if stop_policy == "continue_after_capture" && cleanup_error.is_none() {
                    match entry
                        .handle
                        .command(MiCommand::new("-exec-continue")?)
                        .await
                    {
                        Ok(resume) => {
                            result["continued"] = Value::Bool(true);
                            result["resume_evidence_seq"] = Value::from(resume.evidence_seq);
                        }
                        Err(error) => {
                            operation.status = OperationStatus::Failed;
                            operation.error = Some(error.to_string());
                            operation.completed_event_seq = Some(entry.handle.state().event_seq);
                            self.store.upsert_operation(&operation)?;
                            return Err(error);
                        }
                    }
                } else {
                    result["continued"] = Value::Bool(false);
                }
                operation.status = OperationStatus::Completed;
                operation.error = cleanup_error.as_ref().map(ToString::to_string);
                operation.completed_event_seq = Some(entry.handle.state().event_seq);
                self.store.upsert_operation(&operation)?;
                result["operation"] = serde_json::to_value(operation)?;
                result["breakpoint"] = Value::String(backend_number);
                if let Some(error) = cleanup_error {
                    result["cleanup_warning"] = Value::String(error.to_string());
                    result["partial"] = Value::Bool(true);
                }
                Ok(result)
            }
            Err(error) => {
                let cleanup_error = cleanup.err();
                operation.status = if error.code == ErrorCode::Timeout {
                    OperationStatus::TimedOut
                } else {
                    OperationStatus::Failed
                };
                operation.error = Some(match cleanup_error {
                    Some(cleanup_error) => {
                        format!("{error}; cleanup failed: {cleanup_error}")
                    }
                    None => error.to_string(),
                });
                operation.completed_event_seq = Some(entry.handle.state().event_seq);
                self.store.upsert_operation(&operation)?;
                Err(error)
            }
        }
    }

    async fn capture_probe_observation(
        &self,
        request: &ApiRequest,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
        budget: &ObservationBudget,
        calls: &mut usize,
    ) -> Result<Value> {
        let capture = request
            .parameters
            .get("capture")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![json!({"stack": {"limit": 4}})]);
        if capture.len() > budget.max_values {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "probe capture plan exceeds max_values",
            ));
        }
        let mut observations = Vec::new();
        for item in capture {
            if *calls >= budget.max_calls {
                return Err(Error::new(
                    ErrorCode::OutputLimit,
                    "probe exhausted its debugger-call budget",
                ));
            }
            if let Some(expression) = item.get("expression").and_then(Value::as_str) {
                validate_expression(expression)?;
                let command = context_options(
                    MiCommand::new("-data-evaluate-expression")?.string(expression),
                    &json!({"stop_id": state.stop_id}),
                    state,
                )?;
                let reply = safe_evaluate_command(&entry.handle, command).await?;
                *calls += 1;
                observations.push(json!({
                    "expression": expression,
                    "value": result_text(&reply.record, "value"),
                    "evidence_seq": reply.evidence_seq
                }));
            } else if let Some(stack) = item.get("stack") {
                let limit = stack
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(4)
                    .clamp(1, budget.max_frames as u64) as usize;
                let context = json!({"stop_id": state.stop_id});
                // 2026-08-28: Probe stack capture bypassed explicit context
                // and returned the raw MI reply, so a multi-thread hit could
                // inspect GDB's selected thread instead of the stopped thread.
                let command =
                    context_options(MiCommand::new("-stack-list-frames")?, &context, state)?
                        .bare("0")?
                        .bare((limit - 1).to_string())?;
                let reply = entry.handle.command(command).await?;
                *calls += 1;
                observations.push(json!({
                    "stack": normalized_frames(&reply.record, state, &context),
                    "evidence_seq": reply.evidence_seq
                }));
            } else {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "capture items require expression or stack",
                ));
            }
        }
        Ok(json!({
            "stop_id": state.stop_id,
            "reason": state.stop_reason,
            "observations": observations
        }))
    }

    async fn kernel_inspect(&self, request: &ApiRequest) -> Result<Value> {
        if !self.config.security.kernel_enabled {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "Linux kernel provider is disabled",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let view = string(&request.parameters, "view")?;
        match view.as_str() {
            "current_task" | "init_task" => {
                // 2026-08-28: Linux current is a C macro, while current_task
                // is an unrelocated per-CPU offset. Resolve the live pointer
                // from the architecture register and keep task output bounded.
                let (value, evidence_seq) = if view == "current_task" {
                    kernel_current_text(&entry, &request.parameters, &state).await?
                } else {
                    kernel_text(&entry, &request.parameters, &state, "&init_task").await?
                };
                Ok(json!({
                    "view": view,
                    "value": value,
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "gdb-expression"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "version" => {
                let (value, evidence_seq) =
                    kernel_text(&entry, &request.parameters, &state, "(char *)linux_banner")
                        .await?;
                Ok(json!({
                    "view": view,
                    "version": gdb_c_string(&value),
                    "rendered": value,
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "vmlinux-symbol"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "base" => {
                let (address, evidence_seq) =
                    kernel_address(&entry, &request.parameters, &state, "&_text").await?;
                Ok(json!({
                    "view": view,
                    "address": format!("0x{address:016x}"),
                    "symbol": "_text",
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "vmlinux-symbol"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "tasks" => self.kernel_tasks(request, &entry, &state).await,
            "modules" => self.kernel_modules(request, &entry, &state).await,
            "capabilities" => {
                let names_reply = entry
                    .handle
                    .command(MiCommand::new("-data-list-register-names")?)
                    .await?;
                let names = result_string_list(&names_reply.record, "register-names");
                let (architecture, current_task) = if names.iter().any(|name| name == "gs_base") {
                    ("x86-64", "gs_base + current_task per-CPU offset")
                } else if names.iter().any(|name| name == "sp_el0") {
                    ("aarch64", "sp_el0")
                } else {
                    ("unknown", "unavailable")
                };
                let symbols =
                    match kernel_address(&entry, &request.parameters, &state, "&init_task").await {
                        Ok(symbols) => Some(symbols),
                        Err(error) if error.code == ErrorCode::GdbError => None,
                        Err(error) => return Err(error),
                    };
                Ok(json!({
                    "view": view,
                    "architecture": architecture,
                    "transport": match state.target_origin {
                        TargetOrigin::Remote => "gdb-remote",
                        TargetOrigin::Core => "core",
                        _ => "native",
                    },
                    "symbols": {
                        "status": if symbols.is_some() { "supported" } else { "unsupported" },
                        "mode": "trusted-vmlinux"
                    },
                    "current_task": {
                        "status": if current_task == "unavailable" {
                            "unsupported"
                        } else if symbols.is_some() {
                            "supported"
                        } else {
                            "conditional"
                        },
                        "mechanism": current_task
                    },
                    "monitor": {
                        "status": if self.config.security.monitor_allowlist.is_empty() {
                            "unsupported"
                        } else {
                            "conditional"
                        },
                        "allowlist": self.config.security.monitor_allowlist.clone()
                    },
                    "limitations": [
                        "symbol-free heuristic discovery is not enabled",
                        "QEMU monitor support is confirmed only by an allowlisted command"
                    ],
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "target-probe"
                    },
                    "evidence_seq": symbols
                        .map(|(_, evidence_seq)| evidence_seq)
                        .unwrap_or(names_reply.evidence_seq)
                }))
            }
            "stack" => {
                let mut subrequest = request.clone();
                subrequest.method = CanonicalMethod::InspectionGet;
                subrequest.parameters["view"] = Value::String("stack".into());
                let mut result = self.inspection_get(&subrequest).await?;
                result["view"] = Value::String("stack".into());
                result["source"] = json!({
                    "provider": "linux-kernel",
                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                    "mechanism": "gdb-stack"
                });
                Ok(result)
            }
            "panic" => {
                let mut subrequest = request.clone();
                subrequest.method = CanonicalMethod::InspectionSnapshot;
                subrequest.parameters["profile"] = Value::String("standard".into());
                let mut result = self.inspection_snapshot(&subrequest).await?;
                result["view"] = Value::String("panic".into());
                result["source"] = json!({
                    "provider": "linux-kernel",
                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                    "mechanism": "bounded-stop-snapshot"
                });
                Ok(result)
            }
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "unsupported kernel inspection view",
            )),
        }
    }

    async fn kernel_tasks(
        &self,
        request: &ApiRequest,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<Value> {
        let limit = bounded_limit(&request.parameters, 32, self.config.limits.value_children)?;
        let offset = bounded_offset(
            &request.parameters,
            self.config.limits.value_children,
            "kernel task",
        )?;
        let (init_task, mut evidence_seq) =
            kernel_address(entry, &request.parameters, state, "&init_task").await?;
        let (head, seq) =
            kernel_address(entry, &request.parameters, state, "&init_task.tasks").await?;
        evidence_seq = evidence_seq.max(seq);
        let (mut cursor, seq) =
            kernel_address(entry, &request.parameters, state, "init_task.tasks.next").await?;
        evidence_seq = evidence_seq.max(seq);
        // 2026-08-28: Optional current-task metadata previously swallowed
        // timeouts and could send more MI commands after an unknown outcome.
        let current = match kernel_current_text(entry, &request.parameters, state).await {
            Ok((value, _)) => Some(parse_gdb_u64(&value)?),
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::CapabilityMissing | ErrorCode::GdbError
                ) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let mut task_addresses = vec![init_task];
        let mut seen = BTreeSet::new();
        while cursor != head && task_addresses.len() < offset.saturating_add(limit + 1) {
            if !seen.insert(cursor) {
                return Err(Error::new(
                    ErrorCode::GdbError,
                    "kernel task list contains a cycle outside init_task",
                ));
            }
            let expression = format!(
                "(struct task_struct *)((char *)0x{cursor:x} - (unsigned long)&((struct task_struct *)0)->tasks)"
            );
            let (task, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            task_addresses.push(task);
            let expression = format!("((struct list_head *)0x{cursor:x})->next");
            let (next, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            cursor = next;
        }
        let truncated = cursor != head || task_addresses.len() > offset.saturating_add(limit);
        let mut tasks = Vec::new();
        for task in task_addresses.into_iter().skip(offset).take(limit) {
            let (pid, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->pid"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let (tgid, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->tgid"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let (name, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->comm"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            tasks.push(json!({
                "address": format!("0x{task:016x}"),
                "pid": parse_gdb_u64(&pid)?,
                "tgid": parse_gdb_u64(&tgid)?,
                "name": gdb_c_string(&name),
                "current": current.map(|current| current == task)
            }));
        }
        let next_offset = offset + tasks.len();
        Ok(json!({
            "view": "tasks",
            "tasks": tasks,
            "offset": offset,
            "limit": limit,
            "truncated": truncated,
            "continuation": truncated.then(|| json!({"offset": next_offset})),
            "partial": current.is_none(),
            "warnings": if current.is_none() {
                vec!["current task could not be resolved"]
            } else {
                Vec::new()
            },
            "stop_id": state.stop_id,
            "source": {
                "provider": "linux-kernel",
                "version": LINUX_KERNEL_PROVIDER_VERSION,
                "mechanism": "task_struct.tasks"
            },
            "evidence_seq": evidence_seq
        }))
    }

    async fn kernel_modules(
        &self,
        request: &ApiRequest,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<Value> {
        let limit = bounded_limit(&request.parameters, 32, self.config.limits.value_children)?;
        let offset = bounded_offset(
            &request.parameters,
            self.config.limits.value_children,
            "kernel module",
        )?;
        let (head, mut evidence_seq) =
            kernel_address(entry, &request.parameters, state, "&modules").await?;
        let (mut cursor, seq) =
            kernel_address(entry, &request.parameters, state, "modules.next").await?;
        evidence_seq = evidence_seq.max(seq);
        let mut module_addresses = Vec::new();
        let mut seen = BTreeSet::new();
        while cursor != head && module_addresses.len() < offset.saturating_add(limit + 1) {
            if !seen.insert(cursor) {
                return Err(Error::new(
                    ErrorCode::GdbError,
                    "kernel module list contains a cycle outside modules",
                ));
            }
            let expression = format!(
                "(struct module *)((char *)0x{cursor:x} - (unsigned long)&((struct module *)0)->list)"
            );
            let (module, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            module_addresses.push(module);
            let expression = format!("((struct list_head *)0x{cursor:x})->next");
            let (next, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            cursor = next;
        }
        let truncated = cursor != head || module_addresses.len() > offset.saturating_add(limit);
        let mut modules = Vec::new();
        for module in module_addresses.into_iter().skip(offset).take(limit) {
            let (name, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct module *)0x{module:x})->name"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let modern_base = format!("((struct module *)0x{module:x})->mem[0].base");
            let legacy_base = format!("((struct module *)0x{module:x})->core_layout.base");
            let legacy_size = format!("((struct module *)0x{module:x})->core_layout.size");
            let (base, size, layout, seq) = match kernel_text(
                entry,
                &request.parameters,
                state,
                &modern_base,
            )
            .await
            {
                Ok((base, base_seq)) => {
                    let count_expression =
                        "sizeof(((struct module *)0)->mem) / sizeof(((struct module *)0)->mem[0])";
                    let (count, mut size_seq) =
                        kernel_text(entry, &request.parameters, state, count_expression).await?;
                    let count = parse_gdb_u64(&count)?;
                    if count == 0 || count > 32 {
                        return Err(Error::new(
                            ErrorCode::OutputLimit,
                            "kernel module memory layout count is invalid",
                        ));
                    }
                    let mut size = 0_u64;
                    for index in 0..count {
                        let expression =
                            format!("((struct module *)0x{module:x})->mem[{index}].size");
                        let (part, seq) =
                            kernel_text(entry, &request.parameters, state, &expression).await?;
                        size = size.checked_add(parse_gdb_u64(&part)?).ok_or_else(|| {
                            Error::new(ErrorCode::OutputLimit, "kernel module size exceeds 64 bits")
                        })?;
                        size_seq = size_seq.max(seq);
                    }
                    (
                        base,
                        size.to_string(),
                        "module_memory",
                        base_seq.max(size_seq),
                    )
                }
                // 2026-08-28: Only an absent legacy field justifies trying
                // the alternate layout. Preserve timeout and transport errors
                // so an unknown command outcome remains fenced.
                Err(error) if error.code == ErrorCode::GdbError => {
                    let (base, base_seq) =
                        kernel_text(entry, &request.parameters, state, &legacy_base).await?;
                    let (size, size_seq) =
                        kernel_text(entry, &request.parameters, state, &legacy_size).await?;
                    (base, size, "core_layout", base_seq.max(size_seq))
                }
                Err(error) => return Err(error),
            };
            evidence_seq = evidence_seq.max(seq);
            modules.push(json!({
                "address": format!("0x{module:016x}"),
                "name": gdb_c_string(&name),
                "base": format!("0x{:016x}", parse_gdb_u64(&base)?),
                "size": parse_gdb_u64(&size)?,
                "layout": layout
            }));
        }
        let next_offset = offset + modules.len();
        Ok(json!({
            "view": "modules",
            "modules": modules,
            "offset": offset,
            "limit": limit,
            "truncated": truncated,
            "continuation": truncated.then(|| json!({"offset": next_offset})),
            "stop_id": state.stop_id,
            "source": {
                "provider": "linux-kernel",
                "version": LINUX_KERNEL_PROVIDER_VERSION,
                "mechanism": "modules-list"
            },
            "evidence_seq": evidence_seq
        }))
    }

    async fn kernel_monitor(&self, request: &ApiRequest) -> Result<Value> {
        if !self.config.security.kernel_enabled {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "Linux kernel provider is disabled",
            ));
        }
        let monitor = string(&request.parameters, "command")?;
        if monitor.len() > 4_096
            || monitor
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "monitor command is empty, oversized, or multiline",
            ));
        }
        let verb = first_word(&monitor);
        if !self
            .config
            .security
            .monitor_allowlist
            .iter()
            .any(|allowed| allowed == verb)
        {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "monitor command is not allowlisted",
            ));
        }
        self.metrics.raw_command();
        let entry = self.entry(required_session(request)?).await?;
        entry
            .handle
            .record_event(DomainEvent::ConsistencyTainted {
                reason: format!("target monitor command executed: {verb}"),
            })
            .await?;
        let reply = entry
            .handle
            .command(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(format!("monitor {monitor}")),
            )
            .await?;
        let reconciliation = self.reconcile_session(&entry, false).await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        }))
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
            .map_err(|_| Error::new(ErrorCode::Internal, "event stream lagged or closed"))?;
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

    fn source_excerpt(&self, request: &ApiRequest) -> Result<Value> {
        let requested = std::path::PathBuf::from(string(&request.parameters, "path")?);
        let mapped = self
            .config
            .security
            .source_map
            .iter()
            .find_map(|mapping| {
                requested
                    .strip_prefix(&mapping.from)
                    .ok()
                    .map(|suffix| mapping.to.join(suffix))
            })
            .unwrap_or(requested);
        let path = self.workspace_path(&mapped.to_string_lossy(), false)?;
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > 1024 * 1024 {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "source file exceeds 1 MiB",
            ));
        }
        let source = std::fs::read_to_string(&path).map_err(|_| {
            Error::new(ErrorCode::InvalidArgument, "source file is not valid UTF-8")
        })?;
        let lines = source.lines().collect::<Vec<_>>();
        let center = request
            .parameters
            .get("line")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, lines.len().max(1) as u64) as usize;
        let before = request
            .parameters
            .get("before_lines")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .min(100) as usize;
        let after = request
            .parameters
            .get("after_lines")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .min(100) as usize;
        let start = center.saturating_sub(before + 1);
        let end = center.saturating_add(after).min(lines.len());
        let excerpt = lines[start..end]
            .iter()
            .enumerate()
            .map(|(offset, text)| json!({ "line": start + offset + 1, "text": text }))
            .collect::<Vec<_>>();
        Ok(json!({
            "path": path,
            "start_line": start + 1,
            "end_line": end,
            "lines": excerpt,
            "partial": start > 0 || end < lines.len(),
            "source": {"provider": "linux-userland", "mechanism": "workspace-file"}
        }))
    }

    fn breakpoint_location(&self, parameters: &Value) -> Result<String> {
        let location = parameters.get("location").unwrap_or(parameters);
        if let Some(source) = location.get("source") {
            // 2026-08-28: Source breakpoints previously bypassed workspace
            // canonicalization even though every other target path was checked.
            let path = self.workspace_path(&string(source, "path")?, false)?;
            return Ok(format!(
                "{}:{}",
                path.to_string_lossy(),
                unsigned(source, "line")?
            ));
        }
        breakpoint_location(parameters)
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

fn breakpoint_number_from_record(record: &MiRecord) -> Result<String> {
    MiResult::find(record.results(), "bkpt")
        .and_then(MiValue::results)
        .and_then(|fields| MiResult::find_str(fields, "number"))
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB returned no breakpoint number"))
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
    if names.iter().any(|name| name == "gs_base") {
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
    } else if names.iter().any(|name| name == "sp_el0") {
        kernel_text(entry, parameters, state, "(struct task_struct *)$sp_el0").await
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
        Err(Error::new(
            ErrorCode::InvalidArgument,
            "expression must contain 1 to 4096 bytes and no NUL",
        ))
    } else {
        Ok(())
    }
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

fn mappings(state: &crate::domain::SessionState) -> Result<Value> {
    // 2026-08-28: A remote PID can collide with an unrelated host PID. Never
    // consult host /proc unless the reducer recorded a local target origin.
    if !matches!(
        state.target_origin,
        TargetOrigin::Local | TargetOrigin::Attach
    ) {
        return Ok(json!({
            "mappings": [],
            "partial": true,
            "limitations": ["target origin does not permit host /proc access"],
            "source": {"provider": "remote", "mechanism": "unavailable"}
        }));
    }
    let Some(pid) = state.inferiors.values().find_map(|inferior| inferior.pid) else {
        return Ok(json!({
            "mappings": [],
            "partial": true,
            "limitations": ["target does not expose a local /proc memory map"],
            "source": {"provider": "remote", "mechanism": "unavailable"}
        }));
    };
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let ranges: Vec<Value> = maps.lines().filter_map(parse_proc_map).collect();
    Ok(json!({
        "mappings": ranges,
        "partial": false,
        "source": {"provider": "linux-userland", "mechanism": "proc-maps"}
    }))
}

fn parse_proc_map(line: &str) -> Option<Value> {
    let mut fields = line
        .splitn(6, char::is_whitespace)
        .filter(|field| !field.is_empty());
    let (start, end) = fields.next()?.split_once('-')?;
    let permissions = fields.next()?;
    let offset = fields.next()?;
    let device = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    let path = fields.next().unwrap_or("");
    Some(json!({
        "start": format!("0x{start}"), "end": format!("0x{end}"),
        "permissions": permissions, "offset": format!("0x{offset}"),
        "device": device, "inode": inode, "path": path, "source": "linux-proc"
    }))
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

fn resolve_register_name(requested: &str, names: &[String]) -> Result<String> {
    if names.iter().any(|name| name == requested) {
        return Ok(requested.to_owned());
    }
    let candidates = register_role_candidates(requested).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown register or role {requested}"),
        )
    })?;
    names
        .iter()
        .find(|name| candidates.contains(&name.as_str()))
        .cloned()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                format!("target has no register for role {requested}"),
            )
        })
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

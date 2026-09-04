use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::process::Command;

use super::{
    context::{WaitSpec, apply_wait, apply_wait_baseline, wait_if_requested, wait_spec},
    encoding::byte_content,
    mi::frame_summary,
    request::{parameters, required_session, string, unsigned},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, LeaseId, SessionId, StopReason, TargetOrigin, WaitBaseline, WriteLease},
    gateway::{Caller, Gateway, SessionEntry, now_unix_ms, same_principal},
    policy::Profile,
    protocol::ApiRequest,
    session::SessionHandle,
};

impl Gateway {
    pub(super) async fn session_create(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        // 2026-08-30: A global mutex covered the complete GDB handshake and
        // serialized independent Agent sessions. A read gate only coordinates
        // shutdown; the owned permit reserves capacity through session close.
        let _creation = self.session_creation.read().await;
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorCode::InvalidState,
                "gateway is shutting down",
            ));
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
        let slot = self
            .session_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::new(ErrorCode::Conflict, "maximum sessions reached"))?;
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
            slot: tokio::sync::Mutex::new(Some(slot)),
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

    pub(super) async fn session_acquire_write_lease(
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
        drop(current);
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "write_lease_acquired".into(),
            })
            .await?;
        Ok(serde_json::to_value(lease)?)
    }

    pub(super) async fn session_release_write_lease(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        // 2026-08-30: Removing memory state before durable state let a
        // concurrent acquire persist a new lease that this old release then
        // deleted. Keep both changes under the one lease serialization point.
        let released = {
            let mut current = entry.lease.lock().await;
            let released = current
                .as_ref()
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "write lease not found"))?;
            self.store.delete_lease(entry.handle.id())?;
            current.take();
            released
        };
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "write_lease_released".into(),
            })
            .await?;
        Ok(json!({ "released": released.lease_id }))
    }

    pub(super) async fn session_attempt_recovery(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        self.reconcile_session(&entry, true).await
    }

    pub(super) async fn session_list(&self, caller: &Caller) -> Result<Value> {
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

    pub(super) async fn session_get(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn session_providers(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(crate::providers::descriptors(
            &entry.handle.state(),
            &entry.handle.capabilities(),
            self.config.security.kernel_enabled,
        ))?)
    }

    pub(super) async fn session_transcript(&self, request: &ApiRequest) -> Result<Value> {
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
        // 2026-08-29: Transcript reads and seeks ran synchronously on the
        // async request worker, so a retained large journal stalled sessions.
        let (offset, bytes, length) =
            tokio::task::spawn_blocking(move || -> Result<(u64, Vec<u8>, u64)> {
                use std::io::{Read as _, Seek as _};

                let mut file = std::fs::File::open(journal_path)?;
                let length = file.metadata()?.len();
                let offset = offset.min(length);
                file.seek(std::io::SeekFrom::Start(offset))?;
                let mut bytes = vec![0; max_bytes.min((length - offset) as usize)];
                file.read_exact(&mut bytes)?;
                Ok((offset, bytes, length))
            })
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!("transcript read task failed: {error}"),
                )
            })??;
        let mut result = json!({
            "offset": offset,
            "next_offset": offset + bytes.len() as u64,
            "total_bytes": length,
            "truncated": offset + (bytes.len() as u64) < length
        });
        result.as_object_mut().unwrap().extend(byte_content(bytes));
        Ok(result)
    }

    pub(super) async fn session_event(&self, request: &ApiRequest) -> Result<Value> {
        let session_id = SessionId::parse(required_session(request)?)?;
        let wanted = unsigned(&request.parameters, "event_seq")?;
        if wanted == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "event_seq must be positive",
            ));
        }
        let path = self.session_journal_path(&session_id).await?;
        let entry = tokio::task::spawn_blocking(move || -> Result<_> {
            use std::io::BufRead as _;

            for line in std::io::BufReader::new(std::fs::File::open(path)?).lines() {
                let entry: crate::journal::JournalEntry = serde_json::from_str(&line?)?;
                if entry.seq == wanted {
                    return Ok(Some(entry));
                }
                if entry.seq > wanted {
                    break;
                }
            }
            Ok(None)
        })
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("journal scan task failed: {error}"),
            )
        })??;
        entry
            .map(serde_json::to_value)
            .transpose()?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "journal event not found"))
    }

    pub(super) async fn session_journal_path(
        &self,
        session_id: &SessionId,
    ) -> Result<std::path::PathBuf> {
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

    pub(super) async fn session_close(&self, request: &ApiRequest) -> Result<Value> {
        self.finish_session(request, false).await
    }

    pub(super) async fn session_force_abort(&self, request: &ApiRequest) -> Result<Value> {
        self.finish_session(request, true).await
    }

    async fn finish_session(&self, request: &ApiRequest, forced: bool) -> Result<Value> {
        let id = required_session(request)?.to_owned();
        let entry = self.entry(&id).await?;
        let close_error = match entry.handle.close().await {
            Ok(()) => None,
            Err(error) => {
                // 2026-08-28: A failed worker closes its request channel, so close
                // must still release registry and lease state after GDB death.
                if !forced
                    && entry.handle.with_state(|state| state.lifecycle)
                        != crate::domain::SessionLifecycle::Failed
                {
                    return Err(error);
                }
                Some(error.to_string())
            }
        };
        // 2026-08-29: An expired business lease could strand a failed worker.
        // Forced termination always drops live registry and lease ownership
        // after the control lane has attempted GDB process-group shutdown.
        let state = entry.handle.state();
        let output_evidence = entry.handle.inferior_output_evidence();
        let lease_warning = self.retire_session(&id, &entry).await.map(|message| {
            json!({
                "code": "LEASE_CLEANUP_FAILED",
                "message": message
            })
        });
        Ok(json!({
            "closed": true,
            "clean_shutdown": !forced && close_error.is_none(),
            "termination_warning": close_error,
            "warnings": lease_warning.into_iter().collect::<Vec<_>>(),
            "state": state,
            "inferior_output_evidence": output_evidence
        }))
    }

    pub(super) async fn target_launch(&self, request: &ApiRequest) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(default)]
        struct Parameters {
            program: String,
            argv: Vec<String>,
            cwd: Option<String>,
            environment: BTreeMap<String, String>,
            environment_mode: String,
            runtime: String,
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
                    runtime: "auto".into(),
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
        let mut environment = match parameters.environment_mode.as_str() {
            "clean" => BTreeMap::new(),
            "inherited" => inherited_environment(&self.config.security.environment_allowlist)?,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "environment_mode must be clean or inherited",
                ));
            }
        };
        environment.extend(parameters.environment);
        validate_environment(&environment)?;
        validate_argv(&parameters.argv)?;
        if !matches!(parameters.runtime.as_str(), "auto" | "system") {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "runtime must be auto or system",
            ));
        }
        // 2026-08-28: Launch canonicalized program before applying the
        // requested cwd, so an otherwise valid relative executable failed.
        let requested_cwd = parameters
            .cwd
            .as_deref()
            .map(|cwd| self.workspace_path(cwd, true))
            .transpose()?;
        let requested_program = Path::new(&parameters.program);
        let program_path = if requested_program.is_relative() {
            requested_cwd.as_ref().map_or_else(
                || requested_program.to_owned(),
                |cwd| cwd.join(requested_program),
            )
        } else {
            requested_program.to_owned()
        };
        let program = self.workspace_path(&program_path.to_string_lossy(), false)?;
        validate_launch_program(&program)?;
        let cwd = if let Some(cwd) = requested_cwd {
            cwd
        } else {
            self.workspace_path(
                &program.parent().unwrap_or(Path::new("/")).to_string_lossy(),
                true,
            )?
        };
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
        let wait = parameters.wait.unwrap_or_else(|| {
            parameters
                .stop
                .default_wait(self.config.server.wait_timeout_ms)
        });
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let bundled_runtime = if parameters.runtime == "auto" {
            prepare_bundled_runtime(
                &program,
                entry.handle.session_directory(),
                baseline.revision,
            )
            .await?
        } else {
            None
        };
        let debug_program = bundled_runtime
            .as_ref()
            .map_or(program.as_path(), |runtime| runtime.program.as_path());
        let aslr = parameters.aslr.clone();
        let disable_randomization = match aslr.as_str() {
            "preserve" => "off",
            "disable" => "on",
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "aslr must be preserve or disable",
                ));
            }
        };
        // 2026-08-29: GDB 9-10 evaluates ASLR support against the active
        // target. Select native first, and accept its explicit unsupported
        // result only when preserving the operating system's existing ASLR.
        entry
            .handle
            .command(MiCommand::new("-target-select")?.bare("native")?)
            .await?;
        let aslr_managed = match entry
            .handle
            .command(
                MiCommand::new("-gdb-set")?
                    .bare("disable-randomization")?
                    .bare(disable_randomization)?,
            )
            .await
        {
            Ok(_) => true,
            Err(error)
                if aslr == "preserve"
                    && error.code == ErrorCode::GdbError
                    && error.message.contains("randomization")
                    && error.message.contains("unsupported") =>
            {
                false
            }
            Err(error) => return Err(error),
        };
        let mut setup = vec![
            MiCommand::new("-file-exec-and-symbols")?
                .string(debug_program.as_os_str().as_encoded_bytes()),
            MiCommand::new("-environment-cd")?.string(cwd.as_os_str().as_encoded_bytes()),
            // 2026-08-28: Clearing GDB's own environment did not clear the
            // inferior environment. Enforce environment_mode=clean explicitly.
            MiCommand::new("-interpreter-exec")?
                .bare("console")?
                .string("unset environment"),
        ];
        let mut arguments = MiCommand::new("-exec-arguments")?;
        for argument in parameters.argv {
            // 2026-08-28: GDB 15 retains MI C-string quotes in argv when
            // startup-with-shell is disabled. Keep simple arguments bare;
            // newer GDB accepts that encoding and older GDB gets the exact
            // path instead of a quoted, nonexistent one.
            arguments = if !argument.is_empty()
                && !argument
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"'))
            {
                arguments.bare(argument)?
            } else {
                arguments.string(argument)
            };
        }
        setup.push(arguments);
        for (name, value) in environment {
            // 2026-09-01: GDB accepts quoted environment arguments but keeps
            // the quotes or silently leaves NAME undefined. Send one validated
            // bare assignment so successful launch means the value was applied.
            setup.push(
                MiCommand::new("-gdb-set")?
                    .bare("environment")?
                    .bare(format!("{name}={value}"))?,
            );
        }
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
        let state = apply_wait(&entry.handle, wait, Some(&baseline)).await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        let mut result = json!({
            "command": reply,
            "state": state,
            "capabilities": capabilities,
            "start_policy": start_policy.as_str(),
            "aslr": {"requested": aslr, "backend_managed": aslr_managed}
        });
        if let Some(runtime) = bundled_runtime {
            result["runtime"] = runtime.summary;
        }
        Ok(result)
    }

    pub(super) async fn target_attach(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn target_connect_remote(&self, request: &ApiRequest) -> Result<Value> {
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
        // 2026-09-04: An empty allowlist made the default remote-debugging
        // interface unusable. Empty now means unrestricted; entries opt in to
        // exact endpoint restriction.
        if !self.config.security.remote_allowlist.is_empty()
            && !self.config.security.remote_allowlist.contains(&endpoint)
        {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "endpoint is not in security.remote_allowlist",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let workspace_cwd = if let Some(executable) =
            request.parameters.get("executable").and_then(Value::as_str)
        {
            let executable = self.workspace_path(executable, false)?;
            entry
                .handle
                .command(
                    MiCommand::new("-file-exec-and-symbols")?
                        .string(executable.as_os_str().as_encoded_bytes()),
                )
                .await?;
            executable.parent().map(Path::to_owned)
        } else {
            None
        };
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
        // 2026-09-04: The remote handshake retained the service process
        // directory, so raw commands could not reuse workspace-relative
        // module paths. Set the executable directory after connecting.
        if let Some(cwd) = workspace_cwd {
            entry
                .handle
                .command(
                    MiCommand::new("-environment-cd")?.string(cwd.as_os_str().as_encoded_bytes()),
                )
                .await?;
        }
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

    pub(super) async fn target_open_core(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn target_detach(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn target_restart(&self, request: &ApiRequest) -> Result<Value> {
        #[derive(Default, Deserialize)]
        #[serde(default)]
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
        let wait = parameters
            .wait
            .unwrap_or_else(|| start_policy.default_wait(self.config.server.wait_timeout_ms));
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let wait_baseline = WaitBaseline::from(&baseline);
        let reply = entry.handle.command(start_policy.command()?).await?;
        let state = apply_wait_baseline(
            &entry.handle,
            wait,
            Some(&wait_baseline),
            Some(baseline.execution_epoch + 1),
        )
        .await?;
        let capabilities = entry.handle.refresh_target_capabilities().await?;
        Ok(json!({
            "command": reply,
            "state": state,
            "capabilities": capabilities,
            "start_policy": start_policy.as_str()
        }))
    }

    pub(super) async fn target_kill(&self, request: &ApiRequest) -> Result<Value> {
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
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum StartPolicy {
    // 2026-08-28: The old "entry" name mapped to GDB starti, which can stop
    // in the dynamic loader. Retain it only as an input alias for the precise
    // first-instruction policy.
    #[serde(alias = "entry")]
    FirstInstruction,
    Main,
    None,
}

impl StartPolicy {
    pub(super) fn command(self) -> Result<MiCommand> {
        match self {
            Self::FirstInstruction => MiCommand::new("-interpreter-exec")?
                .bare("console")
                .map(|command| command.string("starti")),
            Self::Main => MiCommand::new("-exec-run")?.bare("--start"),
            Self::None => MiCommand::new("-exec-run"),
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::FirstInstruction => "first_instruction",
            Self::Main => "main",
            Self::None => "none",
        }
    }

    fn default_wait(self, timeout_ms: u64) -> WaitSpec {
        // 2026-08-31: Omitted launch and restart waits raced their async state
        // updates. Return an observed run or complete stop; `accepted` remains
        // the explicit non-blocking policy.
        WaitSpec {
            until: if matches!(self, Self::None) {
                "running"
            } else {
                "snapshot"
            }
            .into(),
            timeout_ms,
        }
    }
}

pub(super) fn validate_environment(environment: &BTreeMap<String, String>) -> Result<()> {
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
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'"')
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid environment entry {name:?}"),
            ));
        }
    }
    Ok(())
}

pub(super) fn inherited_environment(allowlist: &[String]) -> Result<BTreeMap<String, String>> {
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

pub(super) fn validate_argv(arguments: &[String]) -> Result<()> {
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

fn validate_launch_program(program: &Path) -> Result<()> {
    // 2026-08-31: Non-executable files previously reached GDB and collapsed
    // exec permission failures into an opaque startup exit code 127.
    if program.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("program is not executable: {}", program.display()),
        ));
    }
    Ok(())
}

struct BundledRuntime {
    program: PathBuf,
    summary: Value,
}

async fn prepare_bundled_runtime(
    program: &Path,
    session_directory: &Path,
    revision: u64,
) -> Result<Option<BundledRuntime>> {
    // 2026-09-05: Launch ignored complete challenge runtimes beside the
    // executable, making Agents patch the target before every debug session.
    // Patch only a session-local copy so GDB retains normal PIE symbol and
    // breakpoint relocation while the supplied loader and libraries are used.
    let parent = program.parent().unwrap_or(Path::new("/"));
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    let runtime_files = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(runtime_candidate_name)
        })
        .collect::<Vec<_>>();
    let has_loader = runtime_files.iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(loader_candidate_name)
    });
    let has_library = runtime_files.iter().any(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(".so") && !loader_candidate_name(name))
    });
    if !has_loader || !has_library {
        return Ok(None);
    }
    let interpreter = match Command::new("patchelf")
        .arg("--print-interpreter")
        .arg(program)
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::new(
                ErrorCode::TargetUnavailable,
                "bundled loader detected but patchelf is unavailable",
            )
            .with_details(json!({"candidates": runtime_files})));
        }
        Err(error) => {
            return Err(Error::new(
                ErrorCode::TargetUnavailable,
                format!("cannot inspect launch runtime: {error}"),
            ));
        }
    };
    let Some(interpreter_soname) = Path::new(&interpreter)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return Ok(None);
    };
    let needed = Command::new("patchelf")
        .arg("--print-needed")
        .arg(program)
        .output()
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::TargetUnavailable,
                format!("cannot inspect launch dependencies: {error}"),
            )
        })?;
    if !needed.status.success() {
        return Ok(None);
    }
    let needed = String::from_utf8_lossy(&needed.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut candidates = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for path in runtime_files {
        let Ok(path) = std::fs::canonicalize(path) else {
            continue;
        };
        if path == program || !path.is_file() {
            continue;
        }
        let Ok(output) = Command::new("patchelf")
            .arg("--print-soname")
            .arg(&path)
            .output()
            .await
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let soname = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !soname.is_empty() {
            candidates.entry(soname).or_default().insert(path);
        }
    }
    let loader = unique_soname_candidate(&candidates, interpreter_soname, "loader")?;
    let Some(loader) = loader else {
        return Ok(None);
    };
    for name in &needed {
        if unique_soname_candidate(&candidates, name, "library")?.is_none() {
            return Ok(None);
        }
    }

    let runtime_directory = session_directory.join(format!("runtime-{revision}"));
    let library_directory = runtime_directory.join("lib");
    std::fs::create_dir_all(&library_directory)?;
    // 2026-09-05: A SONAME match still failed at launch when the versioned
    // attachment lacked the DT_NEEDED filename. Stage aliases for every
    // unambiguous sibling without changing the supplied files.
    for (soname, matches) in &candidates {
        if matches.len() != 1 || Path::new(soname).components().count() != 1 {
            continue;
        }
        let link = library_directory.join(soname);
        if let Err(error) = std::fs::remove_file(&link)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
        std::os::unix::fs::symlink(matches.first().unwrap(), link)?;
    }
    let file_name = program.file_name().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "launch program has no file name",
        )
    })?;
    let prepared = runtime_directory.join(file_name);
    let patched = Command::new("patchelf")
        .arg("--no-sort")
        .arg("--output")
        .arg(&prepared)
        .arg("--set-interpreter")
        .arg(&loader)
        .arg("--force-rpath")
        .arg("--set-rpath")
        .arg(&library_directory)
        .arg(program)
        .output()
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::TargetUnavailable,
                format!("cannot prepare bundled launch runtime: {error}"),
            )
        })?;
    if !patched.status.success() {
        let message = String::from_utf8_lossy(&patched.stderr);
        return Err(Error::new(
            ErrorCode::TargetUnavailable,
            format!(
                "patchelf could not prepare bundled runtime: {}",
                message.trim()
            ),
        ));
    }
    std::fs::set_permissions(&prepared, program.metadata()?.permissions())?;
    Ok(Some(BundledRuntime {
        program: prepared.clone(),
        summary: json!({
            "mode": "bundled",
            "prepared_program": prepared,
            "loader": loader,
            "library_path": library_directory,
            "libraries": needed,
        }),
    }))
}

fn unique_soname_candidate(
    candidates: &BTreeMap<String, BTreeSet<PathBuf>>,
    soname: &str,
    kind: &str,
) -> Result<Option<PathBuf>> {
    let Some(matches) = candidates.get(soname) else {
        return Ok(None);
    };
    if matches.len() != 1 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("bundled runtime has ambiguous {kind} for {soname:?}"),
        )
        .with_details(json!({"soname": soname, "candidates": matches})));
    }
    Ok(matches.first().cloned())
}

fn runtime_candidate_name(name: &str) -> bool {
    name.contains(".so") || loader_candidate_name(name)
}

fn loader_candidate_name(name: &str) -> bool {
    name.starts_with("ld-")
        || name.starts_with("ld-linux")
        || name.starts_with("ld-musl")
        || name.starts_with("ld.so")
}

pub(super) fn remote_endpoint(parameters: &Value) -> Result<String> {
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
pub(super) struct AttachIdentity {
    pub(super) start_time_ticks: u64,
}

impl AttachIdentity {
    pub(super) fn revalidate(self, pid: u64) -> Result<()> {
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

pub(super) fn validate_attach_target(pid: u64) -> Result<AttachIdentity> {
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

pub(super) fn process_start_time(pid: u64) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
        Error::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read attach target identity: {error}"),
        )
    })?;
    parse_process_start_time(&stat)
}

pub(super) fn parse_process_start_time(stat: &str) -> Result<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(first.default_wait(123).until, "snapshot");
        assert_eq!(StartPolicy::None.default_wait(123).until, "running");
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
    fn rejects_environment_values_gdb_cannot_preserve() {
        for value in ["two words", "\"quoted\""] {
            let environment = BTreeMap::from([("VALUE".into(), value.into())]);
            assert_eq!(
                validate_environment(&environment).unwrap_err().code,
                ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn rejects_a_program_without_execute_permission() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("program");
        std::fs::File::create(&program).unwrap();

        let error = validate_launch_program(&program).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains(program.to_str().unwrap()));

        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        validate_launch_program(&program).unwrap();
    }
}

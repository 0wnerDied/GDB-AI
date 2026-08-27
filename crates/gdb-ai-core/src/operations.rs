use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiRecord, MiResult, MiValue};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, StopId},
    gateway::{Caller, Gateway, SessionEntry},
    policy::{Profile, validate_console_command},
    protocol::ApiRequest,
    session::{CommandReply, OutputRing, SessionHandle, WaitUntil},
};

impl Gateway {
    pub(crate) async fn execute_method(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        match request.method.as_str() {
            "session.create" => self.session_create(request, caller).await,
            "session.get" => Ok(serde_json::to_value(
                self.entry(required_session(request)?).await?.handle.state(),
            )?),
            "session.list" => self.session_list().await,
            "session.close" => self.session_close(request).await,
            "session.acquire_write_lease" | "session.release_write_lease" => {
                deferred("multi-user write leases")
            }
            "session.capabilities" => Ok(serde_json::to_value(
                self.entry(required_session(request)?)
                    .await?
                    .handle
                    .capabilities(),
            )?),
            "target.launch" => self.target_launch(request).await,
            "target.attach"
            | "target.connect_remote"
            | "target.open_core"
            | "target.detach"
            | "target.restart"
            | "target.kill" => deferred("non-local-launch target lifecycle"),
            "execution.control" => self.execution_control(request).await,
            "execution.wait" => self.execution_wait(request).await,
            "breakpoint.create" => self.breakpoint_create(request).await,
            "breakpoint.update" => self.breakpoint_update(request).await,
            "breakpoint.delete" => self.breakpoint_delete(request).await,
            "breakpoint.list" => self.simple_command(request, "-break-list").await,
            "inspection.get" => self.inspection_get(request).await,
            "inspection.snapshot" => self.inspection_snapshot(request).await,
            "inspection.diff" => deferred("tracked snapshot diff"),
            "value.evaluate" => self.value_evaluate(request).await,
            "value.create" | "value.children" | "value.update" | "value.release" => {
                deferred("persistent MI variable objects")
            }
            "memory.read" => self.memory_read(request).await,
            "memory.write" | "memory.search" | "memory.compare" => {
                deferred("memory mutation and search")
            }
            "register.read" => self.register_read(request).await,
            "register.write" => deferred("register mutation"),
            "disassembly.read" => self.disassembly_read(request).await,
            "inferior_io.read" => self.io_read(request).await,
            "inferior_io.write" => self.io_write(request).await,
            "inferior_io.close_stdin" => self.io_close_stdin(request).await,
            "inferior_io.resize" => self.io_resize(request).await,
            "tracking.add_expression"
            | "tracking.add_memory"
            | "tracking.remove"
            | "tracking.list" => deferred("tracked state"),
            "artifact.get" => self.artifact_get(request).await,
            "events.wait" => self.events_wait(request).await,
            "raw.mi" => deferred("raw MI exposure"),
            "raw.console" => self.raw_console(request).await,
            _ => Err(Error::new(ErrorCode::NotFound, "unknown canonical method")),
        }
    }

    async fn session_create(&self, request: &ApiRequest, caller: &Caller) -> Result<Value> {
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
        let handle = SessionHandle::start(self.config.clone(), profile, self.store.clone()).await?;
        let id = handle.id().clone();
        let entry = Arc::new(SessionEntry {
            handle,
            owner: caller.identity.clone(),
            mutation: tokio::sync::Mutex::new(()),
        });
        self.sessions
            .write()
            .await
            .insert(id.0.clone(), entry.clone());
        Ok(json!({
            "session_id": id,
            "resource": format!("gdbai://session/{}/status", id.0),
            "state": entry.handle.state(),
            "backend": entry.handle.capabilities().backend,
            "profile": profile,
            "capabilities": entry.handle.capabilities(),
        }))
    }

    async fn session_list(&self) -> Result<Value> {
        let entries = self
            .sessions
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        Ok(Value::Array(
            entries
                .into_iter()
                .map(|entry| serde_json::to_value(entry.handle.state()))
                .collect::<std::result::Result<_, _>>()?,
        ))
    }

    async fn session_close(&self, request: &ApiRequest) -> Result<Value> {
        let id = required_session(request)?.to_owned();
        let entry = self.entry(&id).await?;
        entry.handle.close().await?;
        let state = entry.handle.state();
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
            stop: String,
            follow_fork: String,
            detach_on_fork: bool,
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
                    stop: "entry".into(),
                    follow_fork: "parent".into(),
                    detach_on_fork: true,
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
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        let mut setup = vec![
            MiCommand::new("-file-exec-and-symbols")?
                .string(program.as_os_str().as_encoded_bytes()),
            MiCommand::new("-environment-cd")?.string(cwd.as_os_str().as_encoded_bytes()),
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
        let mut run = MiCommand::new("-exec-run")?;
        if parameters.stop == "entry" {
            run = run.bare("--start")?;
        } else if parameters.stop != "none" {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "stop must be entry or none",
            ));
        }
        let reply = entry.handle.transaction(setup, run, Vec::new()).await?;
        let state = wait_if_requested(&entry.handle, parameters.wait, Some(&baseline)).await?;
        Ok(json!({ "command": reply, "state": state }))
    }

    async fn execution_control(&self, request: &ApiRequest) -> Result<Value> {
        let action = string(&request.parameters, "action")?;
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
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
        let reply = entry.handle.command(command).await?;
        let state =
            wait_if_requested(&entry.handle, wait_spec(&request.parameters)?, Some(&state)).await?;
        Ok(
            json!({ "operation_id": format!("op_{}", Ulid::new()), "command": reply, "state": state }),
        )
    }

    async fn execution_wait(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let wait = wait_spec(&request.parameters)?.ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "wait parameters are required")
        })?;
        Ok(serde_json::to_value(
            apply_wait(&entry.handle, wait, None).await?,
        )?)
    }

    async fn breakpoint_create(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let kind = request
            .parameters
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("software");
        let location = breakpoint_location(&request.parameters)?;
        let mut command = if matches!(kind, "watchpoint" | "read_watchpoint" | "access_watchpoint")
        {
            let mut command = MiCommand::new("-break-watch")?;
            if kind == "read_watchpoint" {
                command = command.bare("-r")?;
            } else if kind == "access_watchpoint" {
                command = command.bare("-a")?;
            }
            command
        } else {
            let mut command = MiCommand::new("-break-insert")?;
            if bool_value(&request.parameters, "temporary", false) {
                command = command.bare("-t")?;
            }
            if kind == "hardware" || bool_value(&request.parameters, "hardware", false) {
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
        command = command.string(location);
        let reply = entry.handle.command(command).await?;
        Ok(json!({ "command": reply, "breakpoints": entry.handle.state().breakpoints }))
    }

    async fn breakpoint_update(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let number = breakpoint_number(&entry, &request.parameters)?;
        let reply = if let Some(enabled) =
            request.parameters.get("enabled").and_then(Value::as_bool)
        {
            entry
                .handle
                .command(
                    MiCommand::new(if enabled {
                        "-break-enable"
                    } else {
                        "-break-disable"
                    })?
                    .bare(number)?,
                )
                .await?
        } else if let Some(condition) = request.parameters.get("condition").and_then(Value::as_str)
        {
            entry
                .handle
                .command(
                    MiCommand::new("-break-condition")?
                        .bare(number)?
                        .string(condition),
                )
                .await?
        } else if let Some(ignore) = request
            .parameters
            .get("ignore_count")
            .and_then(Value::as_u64)
        {
            entry
                .handle
                .command(
                    MiCommand::new("-break-after")?
                        .bare(number)?
                        .bare(ignore.to_string())?,
                )
                .await?
        } else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "breakpoint.update requires enabled, condition, or ignore_count",
            ));
        };
        Ok(json!({ "command": reply }))
    }

    async fn breakpoint_delete(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let number = breakpoint_number(&entry, &request.parameters)?;
        command_value(
            entry
                .handle
                .command(MiCommand::new("-break-delete")?.bare(number)?)
                .await?,
        )
    }

    async fn inspection_get(&self, request: &ApiRequest) -> Result<Value> {
        let view = string(&request.parameters, "view")?;
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        match view.as_str() {
            "stop_context" | "target" => Ok(serde_json::to_value(state)?),
            "capabilities" => Ok(serde_json::to_value(entry.handle.capabilities())?),
            "threads" => {
                self.inspection_command(&entry, request, "-thread-info", vec![])
                    .await
            }
            "stack" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                self.inspection_command(
                    &entry,
                    request,
                    "-stack-list-frames",
                    vec![("bare", "0".into()), ("bare", (limit - 1).to_string())],
                )
                .await
            }
            "frame" => {
                self.inspection_command(&entry, request, "-stack-info-frame", vec![])
                    .await
            }
            "locals" => {
                self.inspection_command(
                    &entry,
                    request,
                    "-stack-list-variables",
                    vec![("bare", "--simple-values".into())],
                )
                .await
            }
            "arguments" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                self.inspection_command(
                    &entry,
                    request,
                    "-stack-list-arguments",
                    vec![
                        ("bare", "--simple-values".into()),
                        ("bare", "0".into()),
                        ("bare", (limit - 1).to_string()),
                    ],
                )
                .await
            }
            "registers" => self.register_read(request).await,
            "modules" => {
                self.inspection_command(&entry, request, "-file-list-shared-libraries", vec![])
                    .await
            }
            "breakpoints" => self.simple_command(request, "-break-list").await,
            "source" => {
                self.inspection_command(&entry, request, "-file-list-exec-source-files", vec![])
                    .await
            }
            "mappings" => mappings(&state),
            "signals" => Err(Error::new(
                ErrorCode::CapabilityMissing,
                "structured signal inspection requires the trusted GDB extension",
            )),
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
    ) -> Result<Value> {
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
        command_value(entry.handle.command(command).await?)
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
        let mut warnings = Vec::new();
        let stack = optional_command(
            &entry.handle,
            context_options(
                MiCommand::new("-stack-list-frames")?,
                &request.parameters,
                &state,
            )?
            .bare("0")?
            .bare((frames - 1).to_string())?,
            "stack",
            &mut warnings,
        )
        .await;
        let locals = if profile == "minimal" {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-stack-list-variables")?,
                    &request.parameters,
                    &state,
                )?
                .bare("--simple-values")?,
                "locals",
                &mut warnings,
            )
            .await
        };
        let registers = if profile == "minimal" {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-data-list-register-values")?,
                    &request.parameters,
                    &state,
                )?
                .bare("x")?,
                "registers",
                &mut warnings,
            )
            .await
        };
        let disassembly = if matches!(profile, "brief" | "standard" | "deep") {
            optional_command(
                &entry.handle,
                MiCommand::new("-data-disassemble")?
                    .bare("-a")?
                    .string("$pc")
                    .bare("--")?
                    .bare("5")?,
                "disassembly",
                &mut warnings,
            )
            .await
        } else {
            Value::Null
        };
        let partial = !warnings.is_empty();
        if let Some(stop_id) = &state.stop_id {
            entry
                .handle
                .record_event(DomainEvent::SnapshotReady {
                    stop_id: stop_id.clone(),
                    partial,
                })
                .await?;
        }
        Ok(json!({
            "snapshot_id": state.snapshot.as_ref().map(|snapshot| &snapshot.snapshot_id),
            "stop_id": state.stop_id,
            "revision": state.revision,
            "profile": profile,
            "reason": state.stop_reason,
            "stack": stack,
            "locals": locals,
            "registers": registers,
            "disassembly": disassembly,
            "warnings": warnings,
            "partial": partial,
            "evidence": [{"kind": "mi-event", "uri": format!("gdbai://session/{}/event/{}", entry.handle.id(), entry.handle.state().event_seq)}]
        }))
    }

    async fn value_evaluate(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let expression = string(&request.parameters, "expression")?;
        if expression.len() > 4_096 || expression.contains('\0') {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expression exceeds 4096 bytes or contains NUL",
            ));
        }
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
        let off = |setting: &str| -> Result<MiCommand> {
            MiCommand::new("-gdb-set")?.bare(setting)?.bare("off")
        };
        let on = |setting: &str| -> Result<MiCommand> {
            MiCommand::new("-gdb-set")?.bare(setting)?.bare("on")
        };
        // Keep policy changes and evaluation in one worker transaction so no
        // unrelated command can observe or weaken the temporary restrictions.
        let reply = entry
            .handle
            .transaction(
                vec![
                    off("may-call-functions")?,
                    off("may-write-memory")?,
                    off("may-write-registers")?,
                ],
                evaluate,
                vec![
                    on("may-write-registers")?,
                    on("may-write-memory")?,
                    off("may-call-functions")?,
                ],
            )
            .await?;
        Ok(json!({
            "stop_id": state.stop_id,
            "value": result_text(&reply.record, "value"),
            "command": reply,
            "side_effects": "denied"
        }))
    }

    async fn memory_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address_text = string(&request.parameters, "address")?;
        let address = crate::domain::Address::parse(&address_text)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "memory length must be between 1 and {}",
                    self.config.limits.memory_read_bytes
                ),
            ));
        }
        let reply = entry
            .handle
            .command(
                MiCommand::new("-data-read-memory-bytes")?
                    .bare(address.as_str())?
                    .bare(length.to_string())?,
            )
            .await?;
        let bytes = memory_contents(&reply.record)?;
        let partial = bytes.len() != length;
        if partial && !bool_value(&request.parameters, "allow_partial", false) {
            return Err(Error::new(
                ErrorCode::PartialRead,
                format!("requested {length} bytes, read {}", bytes.len()),
            ));
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if bytes.len() > self.config.limits.inline_memory_bytes {
            let uri = self.artifacts.put(&bytes)?;
            Ok(json!({
                "address": address,
                "requested_length": length,
                "read_length": bytes.len(),
                "sha256": sha256,
                "preview_hex": hex_encode(&bytes[..bytes.len().min(64)]),
                "artifact": uri,
                "partial": partial,
                "truncated": true,
                "evidence_seq": reply.evidence_seq
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
                "evidence_seq": reply.evidence_seq
            }))
        }
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
            let candidates: &[&str] = match role.as_str() {
                "pc" => &["rip", "pc"],
                "sp" => &["rsp", "sp"],
                "fp" => &["rbp", "x29", "fp"],
                "return" => &["rax", "x0"],
                "flags" => &["eflags", "cpsr"],
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("unknown register role {role}"),
                    ));
                }
            };
            if let Some((number, _)) = names
                .iter()
                .enumerate()
                .find(|(_, name)| candidates.contains(&name.as_str()))
            {
                role_numbers.insert(role, number);
            }
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
            "architecture": if names.iter().any(|name| name == "rip") { "i386:x86-64" } else if names.iter().any(|name| name == "x29") { "aarch64" } else { "unknown" },
            "evidence_seq": values_reply.evidence_seq
        }))
    }

    async fn disassembly_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let (start, end) = if let Some(range) = request.parameters.get("range") {
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
            (start_number, end_number)
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
            )
        };
        let include_source = bool_value(&request.parameters, "include_source", true);
        let mode = if include_source { "3" } else { "2" };
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
        Ok(json!({
            "range": {"start": format!("0x{start:016x}"), "end": format!("0x{end:016x}")},
            "result": reply,
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
        Ok(json!({ "written": bytes.len() }))
    }

    async fn io_close_stdin(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        // A PTY is a terminal, not a pipe. VEOF is the portable terminal EOF
        // signal while retaining the master for output reads.
        entry.handle.write_inferior(vec![0x04]).await?;
        Ok(json!({ "closed": true, "mechanism": "pty-veof" }))
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
        Ok(json!({ "rows": rows, "columns": columns }))
    }

    async fn artifact_get(&self, request: &ApiRequest) -> Result<Value> {
        let uri = string(&request.parameters, "uri")?;
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(self.config.limits.tool_response_bytes as u64)
            .min(self.config.limits.tool_response_bytes as u64) as usize;
        let bytes = self.artifacts.get(&uri, max_bytes)?;
        Ok(json!({
            "uri": uri,
            "size": bytes.len(),
            "data_base64": BASE64.encode(bytes)
        }))
    }

    async fn events_wait(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let after = request
            .parameters
            .get("after_event_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let current = entry.handle.state();
        if current.event_seq > after {
            return Ok(json!({ "state": current, "coalesced": true }));
        }
        let timeout_ms = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5_000)
            .max(1);
        let mut events = entry.handle.subscribe();
        let event = tokio::time::timeout(Duration::from_millis(timeout_ms), events.recv())
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout, "event wait timed out").retryable())?
            .map_err(|_| Error::new(ErrorCode::Internal, "event stream lagged or closed"))?;
        Ok(serde_json::to_value(event)?)
    }

    async fn raw_console(&self, request: &ApiRequest) -> Result<Value> {
        let command_text = string(&request.parameters, "command")?;
        validate_console_command(&command_text)?;
        let entry = self.entry(required_session(request)?).await?;
        entry
            .handle
            .record_event(DomainEvent::ConsistencyTainted {
                reason: format!(
                    "raw console command executed: {}",
                    first_word(&command_text)
                ),
            })
            .await?;
        let timeout = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(2_000)
            .max(1);
        let reply = entry
            .handle
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(command_text),
                Duration::from_millis(timeout),
            )
            .await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": {
                "status": "tainted",
                "message": "unknown CLI effects cannot be proven fully reconciled"
            }
        }))
    }

    async fn simple_command(&self, request: &ApiRequest, name: &str) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        command_value(entry.handle.command(MiCommand::new(name)?).await?)
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
}

#[derive(Clone, Deserialize)]
struct WaitSpec {
    until: String,
    #[serde(default = "default_wait_ms")]
    timeout_ms: u64,
}

fn default_wait_ms() -> u64 {
    5_000
}

fn wait_spec(parameters: &Value) -> Result<Option<WaitSpec>> {
    parameters
        .get("wait")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))
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
    let timeout = Duration::from_millis(wait.timeout_ms.max(1));
    match baseline {
        Some(baseline) => handle.wait_after(until, timeout, baseline).await,
        None => handle.wait(until, timeout).await,
    }
}

fn required_session(request: &ApiRequest) -> Result<&str> {
    request
        .session_id
        .as_deref()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "method requires session_id"))
}

fn parameters<T: for<'de> Deserialize<'de>>(request: &ApiRequest) -> Result<T> {
    serde_json::from_value(request.parameters.clone())
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

fn context_options(
    mut command: MiCommand,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<MiCommand> {
    if let Some(stop) = parameters.get("stop_id").and_then(Value::as_str) {
        state.require_stop(&StopId(stop.to_owned()))?;
    }
    if let Some(public_thread) = parameters.get("thread_id").and_then(Value::as_str) {
        let backend_thread = state
            .inferiors
            .values()
            .flat_map(|inferior| inferior.threads.values())
            .find(|thread| thread.id.0 == public_thread)
            .map(|thread| thread.backend_id.clone())
            .ok_or_else(|| Error::new(ErrorCode::StaleContext, "thread handle is not current"))?;
        command = command.bare("--thread")?.bare(backend_thread)?;
    }
    if let Some(frame) = parameters.get("frame_id").and_then(Value::as_str) {
        let stop = state.stop_id.as_ref().ok_or_else(|| {
            Error::new(ErrorCode::TargetRunning, "frame requires a stopped target")
        })?;
        if !frame.contains(&stop.0) {
            return Err(Error::new(
                ErrorCode::StaleContext,
                "frame belongs to another stop",
            ));
        }
        let level = frame
            .rsplit('_')
            .next()
            .and_then(|level| level.parse::<u32>().ok())
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "invalid frame identifier"))?;
        command = command.bare("--frame")?.bare(level.to_string())?;
    } else if let Some(level) = parameters.get("frame_level").and_then(Value::as_u64) {
        command = command.bare("--frame")?.bare(level.to_string())?;
    }
    Ok(command)
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
    if let Some(source) = location.get("source") {
        return Ok(format!(
            "{}:{}",
            string(source, "path")?,
            unsigned(source, "line")?
        ));
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

fn command_value(reply: CommandReply) -> Result<Value> {
    Ok(serde_json::to_value(reply)?)
}

async fn optional_command(
    handle: &SessionHandle,
    command: MiCommand,
    name: &str,
    warnings: &mut Vec<Value>,
) -> Value {
    match handle.command(command).await {
        Ok(reply) => serde_json::to_value(reply).unwrap_or(Value::Null),
        Err(error) => {
            warnings.push(json!({ "code": format!("{}_UNAVAILABLE", name.to_uppercase()), "message": error.to_string() }));
            Value::Null
        }
    }
}

fn mappings(state: &crate::domain::SessionState) -> Result<Value> {
    let pid = state
        .inferiors
        .values()
        .find_map(|inferior| inferior.pid)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                "current target does not expose a local PID",
            )
        })?;
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let ranges: Vec<Value> = maps.lines().filter_map(parse_proc_map).collect();
    Ok(json!({ "mappings": ranges, "partial": false, "source": "linux-proc" }))
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

fn first_word(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or("unknown")
}

fn deferred(feature: &str) -> Result<Value> {
    Err(Error::new(
        ErrorCode::Unsupported,
        format!("{feature} is a North-star feature, not part of the Rust vertical slice"),
    ))
}

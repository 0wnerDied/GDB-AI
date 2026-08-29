use super::*;

pub(super) fn breakpoint_location(parameters: &Value) -> Result<String> {
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

pub(super) fn breakpoint_scope(
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

pub(super) fn breakpoint_number(entry: &SessionEntry, parameters: &Value) -> Result<String> {
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

impl Gateway {
    pub(super) async fn execution_control(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn execution_wait(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn breakpoint_create(&self, request: &ApiRequest) -> Result<Value> {
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
        let state = entry.handle.state();
        command = breakpoint_scope(command, &request.parameters, &state)?;
        let mut pending_module = None;
        let mut rebind_command = None;
        if needs_location {
            let (location, unresolved_module) =
                self.breakpoint_location(&request.parameters, &state)?;
            rebind_command = unresolved_module.as_ref().map(|_| command.clone());
            pending_module = unresolved_module;
            command = command.string(location);
        }
        let reply = entry.handle.command(command).await?;
        if let Some(fields) =
            MiResult::find(reply.record.results(), "bkpt").and_then(MiValue::results)
        {
            synchronize_breakpoint(&entry.handle, fields).await?;
        }
        if let (Some((module, offset)), Some(command)) = (pending_module, rebind_command) {
            let backend_number = inserted_breakpoint_number(&reply.record)?;
            let state = entry.handle.state();
            if let Some(breakpoint) = state.breakpoints.get(&backend_number)
                && breakpoint.pending
            {
                entry
                    .handle
                    .register_pending_module_breakpoint(PendingModuleBreakpoint {
                        id: breakpoint.id.clone(),
                        backend_number,
                        module,
                        offset,
                        enabled: breakpoint.enabled,
                        command,
                    })
                    .await?;
            }
        }
        Ok(json!({ "command": reply, "breakpoints": entry.handle.state().breakpoints }))
    }

    pub(super) async fn breakpoint_update(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn breakpoint_delete(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn breakpoint_list(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let reply = entry.handle.command(MiCommand::new("-break-list")?).await?;
        reconcile_breakpoints(&entry.handle, &reply.record).await?;
        Ok(json!({
            "breakpoints": entry.handle.state().breakpoints,
            "evidence_seq": reply.evidence_seq
        }))
    }

    pub(super) async fn signal_get(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(entry.handle.state().signal_policies)?)
    }

    pub(super) async fn signal_update(&self, request: &ApiRequest) -> Result<Value> {
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
}

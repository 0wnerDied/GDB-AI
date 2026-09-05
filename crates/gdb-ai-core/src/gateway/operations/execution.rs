use std::{collections::BTreeMap, time::Duration};

use gdb_ai_mi::{MiResult, MiValue};
use serde_json::{Value, json};

use super::{
    context::{WaitSpec, apply_wait, apply_wait_baseline, context_options, wait_spec},
    encoding::{MAX_INFERIOR_INPUT_BYTES, byte_content, input_bytes},
    reconciliation::{reconcile_breakpoints, synchronize_breakpoint},
    request::{bool_value, required_session, string},
};

pub(super) fn turn_input(parameters: &Value) -> Result<Option<Vec<u8>>> {
    let Some(input) = parameters.get("input") else {
        return Ok(None);
    };
    let bytes = input_bytes(input)?;
    if bytes.len() > MAX_INFERIOR_INPUT_BYTES {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            "inferior input is limited to 64 KiB per call",
        ));
    }
    Ok(Some(bytes))
}

pub(super) async fn feed_inferior(
    entry: &SessionEntry,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<Option<Value>> {
    let Some(bytes) = input else {
        return Ok(None);
    };
    let requested = bytes.len();
    let (written, result) = match entry
        .handle
        .write_inferior_with_timeout(bytes, false, timeout)
        .await
    {
        Ok(written) => (written, None),
        Err(error) => {
            let written = error
                .details
                .as_ref()
                .and_then(|details| details["written"].as_u64())
                .unwrap_or(0);
            let remaining = error
                .details
                .as_ref()
                .and_then(|details| details["remaining"].as_u64())
                .unwrap_or(requested.saturating_sub(written as usize) as u64);
            (
                written as usize,
                Some(json!({
                    "written": written,
                    "remaining": remaining,
                    "error": {
                        "code": error.code,
                        "message": error.message,
                        "retryable": error.retryable
                    }
                })),
            )
        }
    };
    if written > 0 {
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_input".into(),
            })
            .await?;
    }
    Ok(result)
}

fn append_input(result: &mut Value, input: Option<&Value>) {
    if let Some(input) = input {
        result["input"] = input.clone();
    }
}

// 2026-09-01: Synchronous execution discarded PTY bytes produced in the same
// turn, forcing Agents into a second schema lookup and read. Return only bytes
// after the pre-execution cursor, bounded to the ordinary inline read limit.
pub(super) async fn append_turn_output(
    entry: &SessionEntry,
    offset: u64,
    result: &mut Value,
) -> Result<()> {
    let read = entry
        .handle
        .read_output(OutputRing::Inferior, offset, 4 * 1024)
        .await?;
    if read.bytes.is_empty() {
        return Ok(());
    }
    let end = entry.handle.inferior_output_position();
    let mut output = Value::Object(byte_content(read.bytes));
    if read.gap {
        output["gap"] = Value::Bool(true);
        output["available_from"] = Value::from(read.available_from);
    }
    if read.next_offset < end {
        output["truncated"] = Value::Bool(true);
        output["next_offset"] = Value::from(read.next_offset);
    }
    result["output"] = output;
    Ok(())
}
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{
        DomainEvent, OperationId, OperationRecord, OperationStatus, SignalPolicyState, WaitBaseline,
    },
    gateway::{Gateway, SessionEntry},
    normalize::breakpoint_number as inserted_breakpoint_number,
    protocol::{ApiRequest, CanonicalMethod},
    session::{CommandReply, OutputRing, PendingModuleBreakpoint, settled_by},
};

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

fn validate_inspection_wait(parameters: &Value, wait: Option<&WaitSpec>) -> Result<()> {
    if parameters.get("inspect").is_some()
        && wait
            .is_none_or(|wait| !matches!(wait.until.as_str(), "stopped" | "settled" | "snapshot"))
    {
        // 2026-09-01: Observing after an accepted/running fence raced the
        // inferior and could not describe the stop caused by this action.
        // Reject before execution; stop-producing waits remain one turn.
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "inspect requires a stopped, settled, or snapshot wait",
        ));
    }
    Ok(())
}

fn catchpoint_command(kind: &str) -> Result<MiCommand> {
    match kind {
        "throw" => MiCommand::new("-catch-throw"),
        "catch" => MiCommand::new("-catch-catch"),
        "load" => MiCommand::new("-catch-load"),
        "unload" => MiCommand::new("-catch-unload"),
        // 2026-08-29: GDB 9.1 through 17.2 expose these catch commands only
        // through the CLI. Sending invented MI commands made every release
        // reject otherwise valid structured catchpoint requests.
        "exec" | "fork" | "vfork" | "syscall" => MiCommand::new("-interpreter-exec")?
            .bare("console")
            .map(|command| command.string(format!("catch {kind}"))),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            "unsupported catchpoint kind",
        )),
    }
}

pub(super) fn breakpoint_number(entry: &SessionEntry, parameters: &Value) -> Result<String> {
    if let Some(number) = parameters.get("backend_number").and_then(Value::as_str) {
        return Ok(number.to_owned());
    }
    let public = string(parameters, "breakpoint_id")?;
    entry.handle.with_state(|state| {
        state
            .breakpoints
            .values()
            .find(|breakpoint| breakpoint.id.0 == public)
            .map(|breakpoint| breakpoint.backend_number.clone())
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "breakpoint not found"))
    })
}

impl Gateway {
    pub(super) async fn execution_control(&self, request: &ApiRequest) -> Result<Value> {
        let action = string(&request.parameters, "action")?;
        let wait = wait_spec(&request.parameters)?;
        validate_inspection_wait(&request.parameters, wait.as_ref())?;
        let input = turn_input(&request.parameters)?;
        if action == "interrupt" && input.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "interrupt does not accept inferior input",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        let output_offset = entry.handle.inferior_output_position();
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
        entry.handle.record_operation(&operation).await?;
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
                operation.completed_event_seq =
                    Some(entry.handle.with_state(|state| state.event_seq));
                entry.handle.record_operation(&operation).await?;
                return Err(error);
            }
        };
        operation.accepted_event_seq = Some(reply.evidence_seq);
        // 2026-09-01: Agents previously needed one call per input fragment
        // between resume and stop waits. Feed the bounded byte stream after
        // GDB accepts execution, then observe the resulting stop in this turn.
        let input = feed_inferior(
            &entry,
            input,
            Duration::from_millis(
                wait.as_ref()
                    .map_or(self.config.server.wait_timeout_ms, |wait| wait.timeout_ms),
            ),
        )
        .await?;
        if let Some(wait) = wait {
            let report_settled_by = wait.until == "settled";
            operation.status = OperationStatus::WaitingForState;
            entry.handle.record_operation(&operation).await?;
            match apply_wait(&entry.handle, wait, Some(&state)).await {
                Ok(state) => {
                    operation.status = OperationStatus::Completed;
                    operation.completed_event_seq = Some(state.event_seq);
                    entry.handle.record_operation(&operation).await?;
                    let mut result = json!({
                        "operation_id": operation.operation_id,
                        "wait_status": "COMPLETED",
                        "command": reply,
                        "state": state
                    });
                    if report_settled_by {
                        result["settled_by"] = Value::String(
                            settled_by(&state, operation.wait_baseline.as_ref())
                                .ok_or_else(|| {
                                    Error::new(
                                        ErrorCode::Internal,
                                        "settled wait completed without a stop or exit",
                                    )
                                })?
                                .into(),
                        );
                    }
                    append_input(&mut result, input.as_ref());
                    append_turn_output(&entry, output_offset, &mut result).await?;
                    self.append_stop_observations(request, &state, &mut result)
                        .await;
                    Ok(result)
                }
                Err(error) if error.code == ErrorCode::Timeout => {
                    let state = entry.handle.state();
                    operation.status = OperationStatus::TimedOut;
                    operation.completed_event_seq = Some(state.event_seq);
                    entry.handle.record_operation(&operation).await?;
                    let mut result = json!({
                        "operation_id": operation.operation_id,
                        "wait_status": "TIMEOUT",
                        "target_state": state,
                        "can_interrupt": true,
                        "command": reply
                    });
                    append_input(&mut result, input.as_ref());
                    append_turn_output(&entry, output_offset, &mut result).await?;
                    Ok(result)
                }
                Err(error) => {
                    operation.status = OperationStatus::Failed;
                    operation.error = Some(error.to_string());
                    operation.completed_event_seq =
                        Some(entry.handle.with_state(|state| state.event_seq));
                    entry.handle.record_operation(&operation).await?;
                    Err(error)
                }
            }
        } else {
            operation.status = OperationStatus::Completed;
            operation.completed_event_seq = Some(entry.handle.with_state(|state| state.event_seq));
            entry.handle.record_operation(&operation).await?;
            let mut result = json!({
                "operation_id": operation.operation_id,
                "wait_status": "ACCEPTED",
                "command": reply,
                "state": entry.handle.state()
            });
            append_input(&mut result, input.as_ref());
            Ok(result)
        }
    }

    pub(super) async fn execution_wait(&self, request: &ApiRequest) -> Result<Value> {
        let input = turn_input(&request.parameters)?;
        let entry = self.entry(required_session(request)?).await?;
        let output_offset = entry.handle.inferior_output_position();
        let mut operation = match request
            .parameters
            .get("operation_id")
            .and_then(Value::as_str)
        {
            Some(id) => Some(entry.handle.operation(id).await?),
            None => None,
        };
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
        validate_inspection_wait(&request.parameters, Some(&wait))?;
        let report_settled_by = wait.until == "settled";
        let input = feed_inferior(&entry, input, Duration::from_millis(wait.timeout_ms)).await?;
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
        let settled_by = if report_settled_by {
            Some(settled_by(&state, baseline).ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "settled wait completed without a stop or exit",
                )
            })?)
        } else {
            None
        };
        if let Some(operation) = &mut operation {
            operation.status = OperationStatus::Completed;
            operation.completed_event_seq = Some(state.event_seq);
            entry.handle.record_operation(operation).await?;
        }
        let mut result = json!({ "operation": operation, "state": state });
        append_input(&mut result, input.as_ref());
        append_turn_output(&entry, output_offset, &mut result).await?;
        if let Some(settled_by) = settled_by {
            result["settled_by"] = Value::String(settled_by.into());
        }
        self.append_stop_observations(request, &state, &mut result)
            .await;
        Ok(result)
    }

    pub(super) async fn append_stop_observations(
        &self,
        request: &ApiRequest,
        state: &crate::domain::SessionState,
        result: &mut Value,
    ) {
        let Some(requests) = request.parameters.get("inspect") else {
            return;
        };
        if state.stop_id.is_none() {
            return;
        }
        let observation_request = ApiRequest {
            api_version: request.api_version.clone(),
            request_id: format!("{}:inspect", request.request_id),
            session_id: request.session_id.clone(),
            method: CanonicalMethod::InspectionBatch,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({
                "stop_id": state.stop_id,
                "requests": requests
            }),
        };
        result["stop_id"] = json!(state.stop_id);
        match self.inspection_batch(&observation_request).await {
            Ok(batch) => result["observations"] = batch["results"].clone(),
            Err(error) => {
                // 2026-09-01: A post-stop observation failure must not
                // disguise successful execution and invite a second resume.
                result["observation_error"] = json!({
                    "code": error.code,
                    "message": error.message,
                    "retryable": error.retryable,
                    "details": error.details
                });
            }
        }
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
            catchpoint_command(&string(&request.parameters, "catch")?)?
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
        let inserted_number = inserted_breakpoint_number(&reply.record).ok();
        if let Some(fields) =
            MiResult::find(reply.record.results(), "bkpt").and_then(MiValue::results)
        {
            synchronize_breakpoint(&entry.handle, fields).await?;
        }
        if let (Some((module, offset)), Some(command)) = (pending_module, rebind_command) {
            let backend_number = inserted_breakpoint_number(&reply.record)?;
            let breakpoint = entry.handle.with_state(|state| {
                state
                    .breakpoints
                    .get(&backend_number)
                    .map(|breakpoint| (breakpoint.id.clone(), breakpoint.enabled))
            });
            if let Some((id, enabled)) = breakpoint {
                entry
                    .handle
                    .register_pending_module_breakpoint(PendingModuleBreakpoint {
                        id,
                        backend_number,
                        module,
                        offset,
                        enabled,
                        command,
                    })
                    .await?;
            }
        }
        let breakpoints = entry.handle.with_state(|state| state.breakpoints.clone());
        // 2026-08-30: Returning the complete registry after every insert made
        // repeated Agent breakpoint creation produce quadratic MCP output.
        let breakpoint = inserted_number
            .as_ref()
            .and_then(|number| breakpoints.get(number));
        Ok(json!({
            "command": reply,
            "breakpoint": breakpoint,
            "breakpoints": breakpoints
        }))
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
                                .bare(number.clone())?
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
        let breakpoints = entry.handle.with_state(|state| state.breakpoints.clone());
        Ok(json!({
            "command": replies.last(),
            "commands": replies,
            "breakpoint": breakpoints.get(&number),
            "breakpoints": breakpoints,
            "evidence_seq": list.evidence_seq
        }))
    }

    pub(super) async fn breakpoint_delete(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let number = breakpoint_number(&entry, &request.parameters)?;
        let deleted = entry.handle.with_state(|state| {
            state
                .breakpoints
                .get(&number)
                .map(|breakpoint| breakpoint.id.clone())
        });
        let reply = entry
            .handle
            .command(MiCommand::new("-break-delete")?.bare(number.clone())?)
            .await?;
        let list = entry.handle.command(MiCommand::new("-break-list")?).await?;
        reconcile_breakpoints(&entry.handle, &list.record).await?;
        let breakpoints = entry.handle.with_state(|state| state.breakpoints.clone());
        Ok(json!({
            "command": reply,
            "deleted": {"breakpoint_id": deleted, "backend_number": number},
            "breakpoints": breakpoints,
            "evidence_seq": list.evidence_seq
        }))
    }

    pub(super) async fn breakpoint_list(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let reply = entry.handle.command(MiCommand::new("-break-list")?).await?;
        reconcile_breakpoints(&entry.handle, &reply.record).await?;
        let breakpoints = entry.handle.with_state(|state| state.breakpoints.clone());
        Ok(json!({
            "breakpoints": breakpoints,
            "evidence_seq": reply.evidence_seq
        }))
    }

    pub(super) async fn signal_get(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let policies = entry
            .handle
            .with_state(|state| state.signal_policies.clone());
        Ok(serde_json::to_value(policies)?)
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

fn valid_signal_name(signal: &str) -> bool {
    signal.strip_prefix("SIG").is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::catchpoint_command;

    #[test]
    fn uses_native_mi_only_for_native_catchpoint_commands() {
        assert_eq!(
            catchpoint_command("throw").unwrap().encoded(1),
            b"1-catch-throw\n"
        );
        for kind in ["exec", "fork", "vfork", "syscall"] {
            assert_eq!(
                catchpoint_command(kind).unwrap().encoded(2),
                format!("2-interpreter-exec console \"catch {kind}\"\n").as_bytes()
            );
        }
    }
}

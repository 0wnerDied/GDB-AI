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
mod context;
mod evidence;
mod execution;
mod inspection;
mod io;
mod kernel;
mod lifecycle;
mod memory;
mod raw;
mod request;
mod values;

use context::*;
use request::*;

#[cfg(test)]
use lifecycle::{
    AttachIdentity, StartPolicy, inherited_environment, parse_process_start_time,
    validate_attach_target,
};

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
mod tests;

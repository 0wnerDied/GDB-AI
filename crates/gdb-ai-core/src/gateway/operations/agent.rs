use std::{sync::Arc, time::Duration};

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    context::{context_options, require_stopped_context},
    evaluation::{safe_evaluate_command, validate_expression},
    mi::{normalized_frames, result_text},
    request::{required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{OperationId, OperationRecord, OperationStatus, StopReason, WaitBaseline},
    gateway::{Gateway, SessionEntry},
    normalize::breakpoint_number as inserted_breakpoint_number,
    persistence::Store,
    protocol::ApiRequest,
    session::{SessionHandle, WaitUntil},
};

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
    pub(super) async fn agent_hypothesis_check(&self, request: &ApiRequest) -> Result<Value> {
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

    pub(super) async fn agent_probe(&self, request: &ApiRequest) -> Result<Value> {
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
        let (location, unresolved_module) =
            self.breakpoint_location(&request.parameters, &initial)?;
        // 2026-08-28: Probe hit attribution is bound to one backend number,
        // so an unresolved module breakpoint cannot be transparently rebound.
        // Require the existing mappings precondition instead of misreporting a
        // later replacement breakpoint as an unrelated stop.
        if unresolved_module.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidState,
                "agent.probe module_offset requires the module to be mapped",
            ));
        }
        insert = insert.string(location);
        let inserted = entry.handle.command(insert).await?;
        let backend_number = inserted_breakpoint_number(&inserted.record)?;
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
        // 2026-08-30: Persisting the probe operation before constructing its
        // cleanup guard leaked the already-inserted breakpoint on SQLite errors.
        let mut breakpoint = ProbeBreakpoint {
            handle: entry.handle.clone(),
            store: self.store.clone(),
            operation_id: operation.operation_id.clone(),
            backend_number: Some(backend_number.clone()),
        };
        self.store.upsert_operation(&operation)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{InferiorId, SessionId, SessionState, StopId, ThreadId};

    #[test]
    fn accepts_only_the_probe_breakpoint_and_scope() {
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
    fn rejects_an_unrelated_breakpoint() {
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
}

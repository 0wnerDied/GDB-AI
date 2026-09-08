use crate::{
    Result,
    gateway::{Caller, Gateway, RequestMode},
    protocol::{ApiRequest, CanonicalMethod, ObservationContext, OperationResult, SemanticResult},
};

mod agent;
mod context;
mod encoding;
mod evaluation;
mod evidence;
mod execution;
mod inspection;
mod io;
mod kernel;
mod lifecycle;
mod memory;
mod mi;
mod observation;
mod raw;
mod reconciliation;
mod request;
mod values;

use request::required_session;

impl Gateway {
    pub(super) async fn execute_method(
        &self,
        request: &ApiRequest,
        caller: &Caller,
        mode: RequestMode,
    ) -> Result<OperationResult> {
        let result = match request.method {
            CanonicalMethod::SessionCreate => self
                .session_create(request, caller, mode)
                .await
                .map(|(_, result)| result),
            CanonicalMethod::SessionGet => self.session_get(request, caller).await,
            CanonicalMethod::SessionList => self.session_list(caller).await,
            CanonicalMethod::SessionClose => self.session_close(request).await,
            CanonicalMethod::SessionForceAbort => self.session_force_abort(request).await,
            CanonicalMethod::SessionAcquireWriteLease => {
                self.session_acquire_write_lease(request, caller).await
            }
            CanonicalMethod::SessionReleaseWriteLease => {
                self.session_release_write_lease(request, caller).await
            }
            CanonicalMethod::SessionHandoff => self.session_handoff(request, caller).await,
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
            CanonicalMethod::OperationGet => self.operation_get(request, caller).await,
            CanonicalMethod::OperationCancel => self.operation_cancel(request, caller).await,
            CanonicalMethod::TargetLaunch => {
                return self.target_launch(request).await.map(Into::into);
            }
            CanonicalMethod::TargetAttach => self.target_attach(request).await,
            CanonicalMethod::TargetConnectRemote => self.target_connect_remote(request).await,
            CanonicalMethod::TargetOpenCore => self.target_open_core(request).await,
            CanonicalMethod::TargetDetach => self.target_detach(request).await,
            CanonicalMethod::TargetRestart => {
                return self.target_restart(request).await.map(Into::into);
            }
            CanonicalMethod::TargetKill => self.target_kill(request).await,
            CanonicalMethod::ExecutionControl => {
                return self.execution_control(request).await.map(Into::into);
            }
            CanonicalMethod::ExecutionWait => {
                return self.execution_wait(request).await.map(Into::into);
            }
            CanonicalMethod::BreakpointCreate => self.breakpoint_create(request).await,
            CanonicalMethod::BreakpointUpdate => self.breakpoint_update(request).await,
            CanonicalMethod::BreakpointDelete => self.breakpoint_delete(request).await,
            CanonicalMethod::BreakpointList => self.breakpoint_list(request).await,
            CanonicalMethod::InspectionGet => {
                return self.inspection_result(request).await.map(Into::into);
            }
            CanonicalMethod::InspectionSnapshot => {
                return self.inspection_snapshot(request).await.map(Into::into);
            }
            CanonicalMethod::InspectionDiff => self.inspection_diff(request).await,
            CanonicalMethod::InspectionBatch => {
                return self.inspection_batch(request).await.map(Into::into);
            }
            CanonicalMethod::InspectionSnapshotGet => self.inspection_snapshot_get(request).await,
            CanonicalMethod::ValueEvaluate => {
                return self.value_evaluate(request).await.map(Into::into);
            }
            CanonicalMethod::ValueCreate => {
                return self.value_create(request).await.map(Into::into);
            }
            CanonicalMethod::ValueChildren => {
                return self.value_children(request).await.map(Into::into);
            }
            CanonicalMethod::ValueUpdate => {
                return self.value_update(request).await.map(Into::into);
            }
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
        }?;
        if !matches!(
            request.method,
            CanonicalMethod::InspectionDiff
                | CanonicalMethod::InspectionSnapshotGet
                | CanonicalMethod::MemoryRead
                | CanonicalMethod::MemorySearch
                | CanonicalMethod::MemoryCompare
                | CanonicalMethod::RegisterRead
                | CanonicalMethod::DisassemblyRead
                | CanonicalMethod::InferiorIoRead
        ) {
            return Ok(OperationResult::Legacy(result));
        }
        let session_id = required_session(request)?;
        let historical = result.get("historical") == Some(&serde_json::Value::Bool(true));
        let context = if historical {
            ObservationContext::from_observation(&result)?
        } else {
            self.entry(session_id)
                .await?
                .handle
                .with_state(|state| context::observation_context(&request.parameters, state))?
        };
        let mut result = SemanticResult::read(result, context, session_id);
        if request.method == CanonicalMethod::InspectionSnapshotGet {
            for field in ["failures", "observation_failures"] {
                if let Some(failures) = result.facts.get(field) {
                    result.failures(field, serde_json::from_value(failures.clone())?);
                }
            }
            result = result.observation_details();
        }
        Ok(result.into())
    }
}

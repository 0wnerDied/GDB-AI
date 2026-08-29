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
mod raw;
mod reconciliation;
mod request;
mod values;

use context::*;
use encoding::*;
use evaluation::{safe_evaluate_command, validate_expression};
use execution::breakpoint_location;
use memory::read_memory_bytes;
use mi::*;
use reconciliation::*;
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

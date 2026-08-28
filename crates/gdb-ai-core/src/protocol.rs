use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fmt, ops::Deref};

use crate::{Error, domain::SessionState};

pub const API_VERSION: &str = "gdb.ai/v1";

// 2026-08-28: Free-form method strings let routing, policy, MCP projection,
// and the published schema drift into four different canonical method sets.
macro_rules! canonical_methods {
    ($( $variant:ident => $name:literal ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum CanonicalMethod {
            $(#[serde(rename = $name)] $variant,)+
        }

        impl CanonicalMethod {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        }
    };
}

canonical_methods! {
    SessionCreate => "session.create",
    SessionGet => "session.get",
    SessionList => "session.list",
    SessionClose => "session.close",
    SessionAcquireWriteLease => "session.acquire_write_lease",
    SessionReleaseWriteLease => "session.release_write_lease",
    SessionAttemptRecovery => "session.attempt_recovery",
    SessionCapabilities => "session.capabilities",
    SessionProviders => "session.providers",
    SessionTranscript => "session.transcript",
    SessionEvent => "session.event",
    TargetLaunch => "target.launch",
    TargetAttach => "target.attach",
    TargetConnectRemote => "target.connect_remote",
    TargetOpenCore => "target.open_core",
    TargetDetach => "target.detach",
    TargetRestart => "target.restart",
    TargetKill => "target.kill",
    ExecutionControl => "execution.control",
    ExecutionWait => "execution.wait",
    BreakpointCreate => "breakpoint.create",
    BreakpointUpdate => "breakpoint.update",
    BreakpointDelete => "breakpoint.delete",
    BreakpointList => "breakpoint.list",
    InspectionGet => "inspection.get",
    InspectionSnapshot => "inspection.snapshot",
    InspectionDiff => "inspection.diff",
    InspectionBatch => "inspection.batch",
    InspectionSnapshotGet => "inspection.snapshot_get",
    ValueEvaluate => "value.evaluate",
    ValueCreate => "value.create",
    ValueChildren => "value.children",
    ValueUpdate => "value.update",
    ValueRelease => "value.release",
    MemoryRead => "memory.read",
    MemoryWrite => "memory.write",
    MemorySearch => "memory.search",
    MemoryCompare => "memory.compare",
    RegisterRead => "register.read",
    RegisterWrite => "register.write",
    DisassemblyRead => "disassembly.read",
    InferiorIoRead => "inferior_io.read",
    InferiorIoWrite => "inferior_io.write",
    InferiorIoCloseStdin => "inferior_io.close_stdin",
    InferiorIoResize => "inferior_io.resize",
    TrackingAddExpression => "tracking.add_expression",
    TrackingAddMemory => "tracking.add_memory",
    TrackingRemove => "tracking.remove",
    TrackingList => "tracking.list",
    SignalGet => "signal.get",
    SignalUpdate => "signal.update",
    AgentHypothesisCheck => "agent.hypothesis_check",
    AgentProbe => "agent.probe",
    AgentExperiment => "agent.experiment",
    KernelInspect => "kernel.inspect",
    KernelMonitor => "kernel.monitor",
    ArtifactGet => "artifact.get",
    EventsWait => "events.wait",
    RawMi => "raw.mi",
    RawConsole => "raw.console",
}

impl fmt::Display for CanonicalMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Deref for CanonicalMethod {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<&str> for CanonicalMethod {
    fn from(value: &str) -> Self {
        Self::ALL
            .iter()
            .copied()
            .find(|method| method.as_str() == value)
            .unwrap_or_else(|| panic!("unknown internal canonical method {value}"))
    }
}

impl From<String> for CanonicalMethod {
    fn from(value: String) -> Self {
        Self::from(value.as_str())
    }
}

impl PartialEq<&str> for CanonicalMethod {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiRequest {
    pub api_version: String,
    pub request_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub method: CanonicalMethod,
    #[serde(default)]
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub api_version: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SessionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub warnings: Vec<Warning>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<String>,
    pub artifacts: Vec<String>,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: crate::ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ApiResponse {
    pub fn success(request: &ApiRequest, state: Option<SessionState>, result: Value) -> Self {
        // 2026-08-28: session.create has no request session ID, so derive it
        // from returned state to keep the creation response routable.
        let session_id = request
            .session_id
            .clone()
            .or_else(|| state.as_ref().map(|state| state.session_id.0.clone()));
        // 2026-08-28: Command evidence stayed buried in result objects and the
        // envelope often pointed at no raw MI record. Promote bounded journal
        // sequence references without traversing large byte arrays.
        let evidence = response_evidence(session_id.as_deref(), state.as_ref(), Some(&result));
        Self {
            api_version: API_VERSION.into(),
            request_id: request.request_id.clone(),
            session_id,
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: Some(result),
            warnings: Vec::new(),
            truncated: false,
            continuation: None,
            artifacts: Vec::new(),
            evidence,
            error: None,
        }
    }

    pub fn failure(request: &ApiRequest, error: Error, state: Option<SessionState>) -> Self {
        let evidence = response_evidence(
            request.session_id.as_deref(),
            state.as_ref(),
            error.details.as_ref(),
        );
        Self {
            api_version: API_VERSION.into(),
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: None,
            warnings: Vec::new(),
            truncated: false,
            continuation: None,
            artifacts: Vec::new(),
            evidence,
            error: Some(ApiError {
                code: error.code,
                message: error.message,
                retryable: error.retryable,
                details: error.details,
            }),
        }
    }
}

fn response_evidence(
    session_id: Option<&str>,
    state: Option<&SessionState>,
    source: Option<&Value>,
) -> Vec<Evidence> {
    let mut sequences = BTreeSet::new();
    if let Some(source) = source {
        collect_evidence_sequences(source, 0, &mut sequences);
    }
    if sequences.is_empty()
        && let Some(event_seq) = state.map(|state| state.event_seq).filter(|seq| *seq > 0)
    {
        sequences.insert(event_seq);
    }
    session_id
        .map(|session_id| {
            sequences
                .into_iter()
                .map(|sequence| Evidence {
                    kind: "journal-entry".into(),
                    uri: format!("gdbai://session/{session_id}/event/{sequence}"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn collect_evidence_sequences(value: &Value, depth: usize, output: &mut BTreeSet<u64>) {
    if depth >= 8 || output.len() >= 64 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "evidence_seq" {
                    if let Some(sequence) = child.as_u64() {
                        output.insert(sequence);
                    }
                } else {
                    collect_evidence_sequences(child, depth + 1, output);
                }
            }
        }
        Value::Array(array) if array.len() <= 128 => {
            for child in array {
                collect_evidence_sequences(child, depth + 1, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_schema_uses_the_canonical_method_set() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/gdb.ai.v1.json")).unwrap();
        let published: BTreeSet<&str> = schema["properties"]["method"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|method| method.as_str().unwrap())
            .collect();
        let typed: BTreeSet<&str> = CanonicalMethod::ALL
            .iter()
            .map(|method| method.as_str())
            .collect();
        assert_eq!(published, typed);
        assert!(
            serde_json::from_value::<CanonicalMethod>(Value::String("unknown".into())).is_err()
        );
    }
}

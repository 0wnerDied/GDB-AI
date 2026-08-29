use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fmt, ops::Deref, str::FromStr};

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
    OperationGet => "operation.get",
    OperationCancel => "operation.cancel",
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
    InferiorIoSendEof => "inferior_io.send_eof",
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

impl TryFrom<&str> for CanonicalMethod {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // 2026-08-28: Infallible conversion panicked on an unknown internal
        // method string. Keep every routing boundary on the typed error path.
        Self::ALL
            .iter()
            .copied()
            .find(|method| method.as_str() == value)
            .ok_or_else(|| {
                Error::new(
                    crate::ErrorCode::InvalidArgument,
                    format!("unknown canonical method {value}"),
                )
            })
    }
}

impl TryFrom<String> for CanonicalMethod {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for CanonicalMethod {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl PartialEq<&str> for CanonicalMethod {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

// 2026-08-28: The published envelope described parameters as an arbitrary
// object. Generate each method branch from the runtime contract instead.
// 2026-08-28: GDB/AI is the Agent Interface; GNU GDB supplies the GDB/MI
// backend protocol.
pub fn canonical_request_schema() -> Value {
    let methods = CanonicalMethod::ALL
        .iter()
        .map(|method| method.as_str())
        .collect::<Vec<_>>();
    let contracts = CanonicalMethod::ALL
        .iter()
        .map(|method| {
            json!({
                "if": {
                    "properties": {"method": {"const": method.as_str()}},
                    "required": ["method"]
                },
                "then": {
                    "properties": {"parameters": method.parameter_schema()}
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.gdb-ai.dev/gdb.ai.v1.json",
        "title": "GDB/AI canonical request",
        "type": "object",
        "additionalProperties": false,
        "required": ["api_version", "request_id", "method", "parameters"],
        "properties": {
            "api_version": {"const": API_VERSION},
            "request_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "session_id": {
                "type": ["string", "null"],
                "pattern": "^sess_[A-Za-z0-9_-]{1,256}$"
            },
            "method": {"type": "string", "enum": methods},
            "expected_revision": {"type": ["integer", "null"], "minimum": 0},
            "idempotency_key": {"type": ["string", "null"], "maxLength": 256},
            "parameters": {"type": "object"}
        },
        "allOf": contracts
    })
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
    pub continuation: Option<Value>,
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
        let evidence = response_evidence(session_id.as_deref(), Some(&result));
        // 2026-08-29: Result-level pagination and artifact metadata never
        // reached the canonical envelope, so clients saw false completeness.
        let warnings = result_warnings(&result);
        let continuation = result
            .get("continuation")
            .filter(|value| !value.is_null())
            .cloned();
        let mut artifacts = BTreeSet::new();
        let mut truncated = false;
        collect_result_metadata(&result, 0, &mut truncated, &mut artifacts);
        Self {
            api_version: API_VERSION.into(),
            request_id: request.request_id.clone(),
            session_id,
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: Some(result),
            warnings,
            truncated,
            continuation,
            artifacts: artifacts.into_iter().collect(),
            evidence,
            error: None,
        }
    }

    pub fn failure(request: &ApiRequest, error: Error, state: Option<SessionState>) -> Self {
        let evidence = response_evidence(request.session_id.as_deref(), error.details.as_ref());
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

fn result_warnings(result: &Value) -> Vec<Warning> {
    result
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|warning| match warning {
            Value::String(message) => Some(Warning {
                code: "PARTIAL_RESULT".into(),
                message: message.clone(),
            }),
            Value::Object(object) => Some(Warning {
                code: object.get("code")?.as_str()?.into(),
                message: object.get("message")?.as_str()?.into(),
            }),
            _ => None,
        })
        .collect()
}

fn collect_result_metadata(
    value: &Value,
    depth: usize,
    truncated: &mut bool,
    artifacts: &mut BTreeSet<String>,
) {
    if depth >= 8 || artifacts.len() >= 64 {
        return;
    }
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if key == "truncated" && child == true {
                    *truncated = true;
                } else if matches!(key.as_str(), "artifact" | "raw_artifact") {
                    if let Some(uri) = child.as_str() {
                        artifacts.insert(uri.into());
                    }
                } else {
                    collect_result_metadata(child, depth + 1, truncated, artifacts);
                }
            }
        }
        Value::Array(array) if array.len() <= 128 => {
            for child in array {
                collect_result_metadata(child, depth + 1, truncated, artifacts);
            }
        }
        _ => {}
    }
}

fn response_evidence(session_id: Option<&str>, source: Option<&Value>) -> Vec<Evidence> {
    let mut sequences = BTreeSet::new();
    if let Some(source) = source {
        collect_evidence_sequences(source, 0, &mut sequences);
    }
    // 2026-08-28: Falling back to the session's latest event attributed an
    // unrelated record to results that had no evidence. Empty is truthful.
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
        assert!(CanonicalMethod::try_from("unknown").is_err());
    }

    #[test]
    fn generated_schema_contains_method_parameter_contracts() {
        let schema = canonical_request_schema();
        let published: Value =
            serde_json::from_str(include_str!("../../../schemas/gdb.ai.v1.json")).unwrap();
        assert_eq!(published, schema);
        assert_eq!(
            schema["allOf"].as_array().unwrap().len(),
            CanonicalMethod::ALL.len()
        );
        let memory = schema["allOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["if"]["properties"]["method"]["const"] == "memory.read")
            .unwrap();
        assert_eq!(
            memory["then"]["properties"]["parameters"]["additionalProperties"],
            false
        );
        assert!(
            memory["then"]["properties"]["parameters"]["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("address".into()))
        );
    }

    #[test]
    fn response_without_explicit_evidence_has_no_evidence_link() {
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "evidence".into(),
            session_id: Some("sess_test".into()),
            method: CanonicalMethod::SessionGet,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let mut state = SessionState::creating(crate::domain::SessionId("sess_test".into()));
        state.event_seq = 42;

        let response = ApiResponse::success(&request, Some(state), json!({"status": "ready"}));

        assert!(response.evidence.is_empty());
    }

    #[test]
    fn promotes_result_metadata_to_the_response_envelope() {
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "metadata".into(),
            session_id: Some("sess_test".into()),
            method: CanonicalMethod::ArtifactGet,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let response = ApiResponse::success(
            &request,
            None,
            json!({
                "warnings": [
                    {"code": "PARTIAL_READ", "message": "one page was unavailable"},
                    "current task could not be resolved"
                ],
                "continuation": {"offset": 16},
                "items": [{
                    "artifact": "gdbai://artifact/sha256:test",
                    "truncated": true
                }]
            }),
        );

        assert!(response.truncated);
        assert_eq!(response.continuation, Some(json!({"offset": 16})));
        assert_eq!(response.artifacts, ["gdbai://artifact/sha256:test"]);
        assert_eq!(response.warnings.len(), 2);
    }
}

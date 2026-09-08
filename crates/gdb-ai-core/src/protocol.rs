use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    ops::Deref,
    str::FromStr,
};

use crate::{
    Error,
    domain::{
        BackendHealth, Consistency, FrameId, InferiorId, SessionLifecycle, SessionState,
        SnapshotStatus, StopId, TargetOrigin, ThreadId, ValueId,
    },
    session::{CommandReply, SessionCapabilities},
};

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
    SessionForceAbort => "session.force_abort",
    SessionAcquireWriteLease => "session.acquire_write_lease",
    SessionReleaseWriteLease => "session.release_write_lease",
    SessionHandoff => "session.handoff",
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<ResultSemantics>,
    pub warnings: Vec<Warning>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<Value>,
    pub artifacts: Vec<String>,
    pub evidence: Vec<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResultSemantics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ObservationContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    pub complete: bool,
    pub historical: bool,
    #[serde(default)]
    pub projection: ResultProjection,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    #[default]
    Detailed,
    Compact,
}

#[derive(Clone, Debug)]
pub(crate) struct ResultMetadata {
    pub semantics: ResultSemantics,
    pub warnings: Vec<Warning>,
    pub truncated: bool,
    pub continuation: Option<Value>,
    pub artifacts: Vec<String>,
    pub evidence: Vec<Evidence>,
}

impl ResultMetadata {
    pub(crate) fn new(context: Option<ObservationContext>) -> Self {
        Self {
            semantics: ResultSemantics {
                context,
                state: None,
                complete: true,
                historical: false,
                projection: ResultProjection::Detailed,
            },
            warnings: Vec::new(),
            truncated: false,
            continuation: None,
            artifacts: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SemanticResult {
    pub facts: Value,
    pub metadata: ResultMetadata,
    diagnostics: BTreeMap<&'static str, Diagnostic>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
enum Diagnostic {
    Command(CommandReply),
    Commands(Vec<CommandReply>),
    State(Box<SessionState>),
    Capabilities(SessionCapabilities),
    Value(Value),
    Failures(BTreeMap<String, ApiError>),
    Error(ApiError),
}

impl SemanticResult {
    pub(crate) fn new(facts: Value, context: Option<ObservationContext>) -> Self {
        Self {
            facts,
            metadata: ResultMetadata::new(context),
            diagnostics: BTreeMap::new(),
        }
    }

    pub(crate) fn command(
        mut self,
        session_id: &str,
        key: &'static str,
        reply: CommandReply,
    ) -> Self {
        self.metadata
            .evidence
            .push(Evidence::journal(session_id, reply.evidence_seq));
        self.diagnostics.insert(key, Diagnostic::Command(reply));
        self
    }

    pub(crate) fn read(
        facts: Value,
        context: Option<ObservationContext>,
        session_id: &str,
    ) -> Self {
        // Dynamic provider facts enter the semantic boundary once, before
        // composition. Envelopes and transports do not rediscover metadata.
        let mut metadata = ResultMetadata::new(context);
        metadata.warnings = result_warnings(&facts);
        let mut evidence = result_evidence(session_id, &facts)
            .into_iter()
            .map(|item| (item.uri.clone(), item))
            .collect::<BTreeMap<_, _>>();
        for field in ["evidence", "observation_evidence"] {
            if let Some(items) = facts.get(field).and_then(Value::as_array) {
                for item in items.iter().take(64) {
                    if let Ok(item) = serde_json::from_value::<Evidence>(item.clone()) {
                        evidence.insert(item.uri.clone(), item);
                    }
                }
            }
        }
        metadata.evidence = evidence.into_values().take(64).collect();
        metadata.continuation = facts
            .get("continuation")
            .filter(|value| !value.is_null())
            .cloned();
        let mut artifacts = BTreeSet::new();
        collect_result_metadata(&facts, 0, &mut metadata.truncated, &mut artifacts);
        metadata.artifacts = artifacts.into_iter().collect();
        // 2026-09-08: Exact bytes after a ring gap do not constitute a
        // complete sample of the requested range, even on a successful read.
        metadata.semantics.complete = facts.get("gap") != Some(&Value::Bool(true))
            && facts.get("partial") != Some(&Value::Bool(true))
            && facts.get("complete") != Some(&Value::Bool(false));
        metadata.semantics.historical = facts.get("historical") == Some(&Value::Bool(true));
        let mut result = Self {
            facts,
            metadata,
            diagnostics: BTreeMap::new(),
        };
        // 2026-09-08: Per-command sequence numbers made identical captures
        // compare unequal. Keep the root transport marker in detailed output
        // and promoted evidence, never in the facts shared by observations.
        if let Some(sequence) = result.facts.get("evidence_seq").and_then(Value::as_u64) {
            result.facts.as_object_mut().unwrap().remove("evidence_seq");
            result = result.detail("evidence_seq", Value::from(sequence));
        }
        result
    }

    pub(crate) fn commands(mut self, session_id: &str, replies: Vec<CommandReply>) -> Self {
        self.metadata.evidence.extend(
            replies
                .iter()
                .map(|reply| Evidence::journal(session_id, reply.evidence_seq)),
        );
        self.diagnostics
            .insert("commands", Diagnostic::Commands(replies));
        self
    }

    pub(crate) fn state(mut self, key: &'static str, state: SessionState) -> Self {
        // 2026-09-08: Native execution projection must retain the public
        // top-level stop/exit state without reconstructing full registries.
        self.metadata.semantics.state = Some(session_coordination_state(&state));
        self.diagnostics
            .insert(key, Diagnostic::State(Box::new(state)));
        self
    }

    pub(crate) fn detail(mut self, key: &'static str, value: Value) -> Self {
        self.diagnostics.insert(key, Diagnostic::Value(value));
        self
    }

    pub(crate) fn capabilities(mut self, capabilities: SessionCapabilities) -> Self {
        self.diagnostics
            .insert("capabilities", Diagnostic::Capabilities(capabilities));
        self
    }

    pub(crate) fn failures(&mut self, key: &'static str, failures: BTreeMap<String, ApiError>) {
        self.facts[key] = Value::Object(
            failures
                .iter()
                .map(|(name, error)| (name.clone(), json!(error.compact())))
                .collect(),
        );
        self.diagnostics.insert(key, Diagnostic::Failures(failures));
    }

    pub(crate) fn error(&mut self, key: &'static str, error: ApiError) {
        self.facts[key] = json!(error.compact());
        self.diagnostics.insert(key, Diagnostic::Error(error));
    }

    pub(crate) fn into_value(mut self, detailed: bool) -> Value {
        if detailed {
            // 2026-09-08: Agent values built and then discarded complete MI
            // trees. Only the detailed projection serializes diagnostics;
            // both projections use the facts and evidence captured above.
            project_diagnostics(&mut self.facts, &self.diagnostics);
        }
        self.facts
    }
}

fn project_diagnostics(facts: &mut Value, diagnostics: &BTreeMap<&'static str, Diagnostic>) {
    for (key, diagnostic) in diagnostics {
        facts[*key] = serde_json::to_value(diagnostic)
            .expect("diagnostics contain only JSON-serializable fields");
    }
}

#[derive(Clone, Debug)]
pub(crate) enum OperationResult {
    Semantic(Box<SemanticResult>),
    Legacy(Value),
}

impl OperationResult {
    pub(crate) fn facts(&self) -> &Value {
        match self {
            Self::Semantic(result) => &result.facts,
            Self::Legacy(result) => result,
        }
    }

    pub(crate) fn detailed_value(&self) -> Value {
        let mut facts = self.facts().clone();
        if let Self::Semantic(result) = self {
            project_diagnostics(&mut facts, &result.diagnostics);
        }
        facts
    }
}

impl From<SemanticResult> for OperationResult {
    fn from(result: SemanticResult) -> Self {
        Self::Semantic(Box::new(result))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_id: Option<String>,
    pub stop_id: StopId,
    pub captured_revision: u64,
    pub execution_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferior_id: Option<InferiorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<ThreadId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_id: Option<FrameId>,
}

impl ObservationContext {
    pub(crate) fn from_observation(value: &Value) -> crate::Result<Option<Self>> {
        if let Some(context) = value
            .get("observation_context")
            .or_else(|| value.get("context"))
        {
            return Ok(Some(serde_json::from_value(context.clone())?));
        }
        // Older automatic stop snapshots have the same capture identity at
        // the root. Historical lookup never substitutes the live context.
        let Some(stop_id) = value.get("stop_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Some(captured_revision) = value
            .get("captured_revision")
            .or_else(|| value.get("revision"))
            .and_then(Value::as_u64)
        else {
            return Ok(None);
        };
        let Some(execution_epoch) = value.get("execution_epoch").and_then(Value::as_u64) else {
            return Ok(None);
        };
        Ok(Some(Self {
            observation_id: value
                .get("observation_id")
                .or_else(|| value.get("snapshot_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            stop_id: StopId(stop_id.into()),
            captured_revision,
            execution_epoch,
            inferior_id: None,
            thread_id: None,
            frame_id: None,
        }))
    }

    pub(crate) fn from_state(state: &SessionState) -> Option<Self> {
        let stop_id = state.stop_id.clone()?;
        let frame_id = state
            .stopped_thread_id
            .as_ref()
            .zip(state.stopped_frame())
            .map(|(thread, frame)| FrameId::new(thread, &stop_id, frame.level));
        Some(Self {
            observation_id: None,
            stop_id,
            captured_revision: state.revision,
            execution_epoch: state.execution_epoch,
            inferior_id: state.stopped_inferior_id.clone(),
            thread_id: state.stopped_thread_id.clone(),
            frame_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationResult {
    pub context: ObservationContext,
    pub results: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, ApiError>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub availability: BTreeMap<String, FactAvailability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<Warning>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactAvailability {
    Captured,
    NotCollected,
    Unavailable,
    Failed,
}

impl ObservationResult {
    pub(crate) fn into_batch_result(self) -> SemanticResult {
        let mut facts = json!({
            "observation_context": self.context,
            "observation_id": self.context.observation_id,
            "stop_id": self.context.stop_id,
            "revision": self.context.captured_revision,
            "execution_epoch": self.context.execution_epoch,
            "availability": self.availability,
            "evidence": self.evidence,
            "complete": self.complete,
            "partial": !self.complete
        });
        facts["results"] = Value::Object(self.results.into_iter().collect());
        let mut result = SemanticResult {
            facts,
            metadata: ResultMetadata {
                semantics: ResultSemantics {
                    context: Some(self.context),
                    state: None,
                    complete: self.complete,
                    historical: false,
                    projection: ResultProjection::Detailed,
                },
                warnings: self.warnings,
                truncated: self.truncated,
                continuation: None,
                artifacts: self.artifacts,
                evidence: self.evidence,
            },
            diagnostics: BTreeMap::new(),
        };
        result.failures("failures", self.failures);
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueStatus {
    Available,
    Unavailable,
    NotCollected,
    Failed,
    Invalid,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValueChild {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: ValueStatus,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_name: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_children: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValueChange {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_id: Option<ValueId>,
    pub status: ValueStatus,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_name: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_children: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_children: Vec<ValueChild>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub uri: String,
}

impl Evidence {
    pub(crate) fn journal(session_id: &str, sequence: u64) -> Self {
        Self {
            kind: "journal-entry".into(),
            uri: format!("gdbai://session/{session_id}/event/{sequence}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: crate::ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        Self {
            code: error.code,
            message: error.message,
            retryable: error.retryable,
            details: error.details,
        }
    }
}

impl ApiError {
    pub(crate) fn compact(&self) -> Self {
        let mut error = self.clone();
        // The typed GDB error owns these transport diagnostics. Preserve its
        // message and semantic details; exact MI remains in detailed output
        // and the evidence journal, never inferred from arbitrary fact keys.
        if self.code == crate::ErrorCode::GdbError
            && let Some(details) = error.details.as_mut().and_then(Value::as_object_mut)
        {
            for field in ["record", "token", "evidence_seq"] {
                details.remove(field);
            }
            if details.is_empty() {
                error.details = None;
            }
        }
        error
    }
}

impl ApiResponse {
    pub fn success(request: &ApiRequest, mut state: Option<SessionState>, result: Value) -> Self {
        // 2026-08-28: session.create has no request session ID, so derive it
        // from returned state to keep the creation response routable.
        // 2026-08-31: A caller-supplied ID on a global method could otherwise
        // mislabel the real session returned by typed state.
        // 2026-09-05: Polling an operation without a session ID spilled its
        // result into an unreadable global artifact. Its authorized record,
        // including a newly created session, owns the result and its evidence.
        let session_id = if matches!(
            request.method,
            CanonicalMethod::OperationGet | CanonicalMethod::OperationCancel
        ) {
            let session_id = result
                .pointer("/operation/result/session_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    result
                        .pointer("/operation/session_id")
                        .and_then(Value::as_str)
                });
            state = state.filter(|state| Some(state.session_id.0.as_str()) == session_id);
            session_id.map(str::to_owned)
        } else {
            state
                .as_ref()
                .map(|state| state.session_id.0.clone())
                .or_else(|| request.session_id.clone())
        };
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
            semantics: None,
            warnings,
            truncated,
            continuation,
            artifacts: artifacts.into_iter().collect(),
            evidence,
            error: None,
        }
    }

    pub(crate) fn semantic_success(
        request: &ApiRequest,
        state: Option<SessionState>,
        result: SemanticResult,
        detailed: bool,
    ) -> Self {
        let SemanticResult {
            facts,
            mut metadata,
            diagnostics,
        } = result;
        let mut facts = facts;
        metadata.semantics.projection = if detailed {
            ResultProjection::Detailed
        } else {
            ResultProjection::Compact
        };
        if detailed {
            project_diagnostics(&mut facts, &diagnostics);
        }
        Self {
            api_version: API_VERSION.into(),
            request_id: request.request_id.clone(),
            session_id: request.session_id.clone(),
            revision: state.as_ref().map(|state| state.revision),
            state,
            result: Some(facts),
            semantics: Some(metadata.semantics),
            warnings: metadata.warnings,
            truncated: metadata.truncated,
            continuation: metadata.continuation,
            artifacts: metadata.artifacts,
            evidence: metadata.evidence,
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
            semantics: None,
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

pub fn session_coordination_state(state: &SessionState) -> Value {
    let mut summary = json!({});
    let summary = summary.as_object_mut().unwrap();
    // 2026-09-01: Healthy active state repeated on every successful stopped
    // turn in the blind trace. Absence means the ordinary case; exceptional
    // lifecycle and backend values remain explicit.
    if state.lifecycle != SessionLifecycle::Active {
        summary.insert("lifecycle".into(), json!(state.lifecycle));
    }
    if state.backend != BackendHealth::Healthy {
        summary.insert("backend".into(), json!(state.backend));
    }
    if state.consistency != Consistency::Clean {
        summary.insert("consistency".into(), json!(state.consistency));
    }
    if state.reconciliation_required {
        summary.insert("reconciliation_required".into(), Value::Bool(true));
    }
    if state.target_origin != TargetOrigin::Unknown {
        summary.insert("target_origin".into(), json!(state.target_origin));
    }
    let inferior = state
        .stopped_inferior_id
        .as_ref()
        .and_then(|id| state.inferiors.values().find(|inferior| &inferior.id == id))
        .or_else(|| {
            (state.inferiors.len() == 1)
                .then(|| state.inferiors.values().next())
                .flatten()
        });
    if let Some(inferior) = inferior {
        summary.insert("status".into(), json!(inferior.status));
        if let Some(pid) = inferior.pid {
            summary.insert("pid".into(), Value::from(pid));
        }
        if let Some(exit_code) = &inferior.exit_code {
            summary.insert("exit_code".into(), projected_exit_code(exit_code));
        }
    }
    if !state.outcome_unknown_tokens.is_empty() {
        summary.insert(
            "outcome_unknown_tokens".into(),
            json!(state.outcome_unknown_tokens),
        );
    }
    if let Some(stop_id) = &state.stop_id {
        summary.insert("stop_id".into(), json!(stop_id));
    }
    if let Some(reason) = &state.stop_reason_detail {
        summary.insert("stop_reason".into(), json!(reason));
    } else if let Some(reason) = &state.stop_reason {
        summary.insert("stop_reason".into(), Value::String(reason.clone()));
    }
    if let Some(inferior_id) = &state.stopped_inferior_id {
        summary.insert("inferior_id".into(), json!(inferior_id));
    }
    if let Some(thread_id) = &state.stopped_thread_id {
        summary.insert("thread_id".into(), json!(thread_id));
    }
    // 2026-08-31: The compact stop state omitted an already captured frame,
    // forcing Agents to spend another tool call on stop_context.
    if let Some(frame) = state.stopped_frame() {
        let mut frame = json!(frame);
        if let Some(frame) = frame.as_object_mut() {
            frame.retain(|_, value| !value.is_null());
            if frame.get("function").and_then(Value::as_str) == Some("??") {
                frame.remove("function");
            }
        }
        summary.insert("frame".into(), frame);
    }
    if let Some(snapshot) = &state.snapshot
        && (snapshot.partial
            || snapshot.status != SnapshotStatus::Ready
            || state.stop_id.as_ref() != Some(&snapshot.stop_id))
    {
        // A ready, complete snapshot for this stop repeats stop_id and adds no
        // next-action semantics. Preserve every incomplete or mismatched case.
        summary.insert("snapshot".into(), json!(snapshot));
    }
    if let Some(reason) = summary
        .get_mut("stop_reason")
        .and_then(Value::as_object_mut)
    {
        reason.retain(|_, value| !value.is_null());
        if reason.get("disposition").and_then(Value::as_str) == Some("keep") {
            reason.remove("disposition");
        }
    }
    Value::Object(std::mem::take(summary))
}

// 2026-09-04: Projected state exposed GDB/MI's octal exit-code text, making
// Agents translate values such as 0170 before checking process results.
// Preserve unknown backend forms, but report recognized process codes as
// decimal.
fn projected_exit_code(exit_code: &str) -> Value {
    let parsed = if exit_code == "0" {
        Some(0)
    } else if let Some(octal) = exit_code.strip_prefix('0') {
        u32::from_str_radix(octal, 8).ok()
    } else {
        exit_code.parse().ok()
    };
    parsed.map(Value::from).unwrap_or_else(|| exit_code.into())
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
    // 2026-08-28: Falling back to the session's latest event attributed an
    // unrelated record to results that had no evidence. Empty is truthful.
    session_id
        .zip(source)
        .map(|(session_id, source)| result_evidence(session_id, source))
        .unwrap_or_default()
}

pub fn result_evidence(session_id: &str, source: &Value) -> Vec<Evidence> {
    let mut sequences = BTreeSet::new();
    collect_evidence_sequences(source, 0, &mut sequences);
    sequences
        .into_iter()
        .map(|sequence| Evidence {
            kind: "journal-entry".into(),
            uri: format!("gdbai://session/{session_id}/event/{sequence}"),
        })
        .collect()
}

pub fn is_command_reply(value: &Value) -> bool {
    value.get("record").is_some_and(Value::is_object)
        && value.get("stream_records").is_some_and(Value::is_array)
        && value.get("evidence_seq").is_some_and(Value::is_u64)
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
    fn semantic_projections_share_facts_without_scanning_business_fields() {
        let gap = SemanticResult::read(json!({"gap": true, "text": "tail"}), None, "sess_native");
        assert!(!gap.metadata.semantics.complete);
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "native".into(),
            session_id: Some("sess_native".into()),
            method: CanonicalMethod::ValueEvaluate,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let facts = json!({"value": "18446744073709551615", "user": {
            "evidence_seq": 999, "truncated": true, "artifact": "ordinary text"
        }});
        let result = SemanticResult::new(facts.clone(), None).command(
            "sess_native",
            "command",
            CommandReply {
                token: 1,
                class: "done".into(),
                record: gdb_ai_mi::parse_record(b"1^done", gdb_ai_mi::MiLimits::default()).unwrap(),
                stream_records: Vec::new(),
                stream_truncated: false,
                evidence_seq: 42,
            },
        );
        let audit = OperationResult::from(result.clone()).detailed_value();
        let detailed = ApiResponse::semantic_success(&request, None, result.clone(), true);
        let compact = ApiResponse::semantic_success(&request, None, result, false);
        assert_eq!(detailed.result.as_ref(), Some(&audit));
        assert!(detailed.result.unwrap()["command"]["record"].is_object());
        assert_eq!(compact.result.as_ref(), Some(&facts));
        assert!(!compact.truncated);
        assert!(compact.artifacts.is_empty());
        assert_eq!(compact.evidence, vec![Evidence::journal("sess_native", 42)]);
        assert_eq!(compact.evidence, detailed.evidence);
        let restored: ApiResponse = serde_json::from_value(json!(compact)).unwrap();
        assert_eq!(restored.result, compact.result);
        assert_eq!(restored.semantics, compact.semantics);
    }

    #[test]
    fn read_evidence_is_diagnostic_without_pruning_target_fields() {
        let facts = json!({
            "evidence_seq": 42,
            "variables": [{"name": "evidence_seq", "value": "99"}],
            "value": {"evidence_seq": "target text"}
        });
        let result = SemanticResult::read(facts.clone(), None, "sess_native");
        assert_eq!(
            result.metadata.evidence,
            vec![Evidence::journal("sess_native", 42)]
        );
        assert_eq!(result.clone().into_value(true), facts);
        let compact = result.into_value(false);
        assert!(compact.get("evidence_seq").is_none());
        assert_eq!(compact["variables"], facts["variables"]);
        assert_eq!(compact["value"], facts["value"]);
    }

    #[test]
    fn projected_exit_codes_are_decimal_integers() {
        assert_eq!(projected_exit_code("0170"), json!(120));
        assert_eq!(projected_exit_code("0"), json!(0));
        assert_eq!(projected_exit_code("unknown"), json!("unknown"));
    }

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
        let parameters = &memory["then"]["properties"]["parameters"];
        // 2026-09-04: Requiring a literal address here rejected the generated
        // one-call expression form. Preserve exactly one address selector.
        assert_eq!(parameters["required"], json!(["length"]));
        assert_eq!(
            parameters["allOf"][0]["oneOf"],
            json!([
                {"required": ["address"]},
                {"required": ["address_expression"]}
            ])
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
    fn response_session_identity_follows_returned_state() {
        let request = ApiRequest {
            api_version: API_VERSION.into(),
            request_id: "create".into(),
            session_id: Some("sess_caller".into()),
            method: CanonicalMethod::SessionCreate,
            expected_revision: None,
            idempotency_key: None,
            parameters: json!({}),
        };
        let state = SessionState::creating(crate::domain::SessionId("sess_created".into()));

        let response = ApiResponse::success(&request, Some(state), json!({}));

        assert_eq!(response.session_id.as_deref(), Some("sess_created"));
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

    #[test]
    fn observation_context_records_capture_identity_without_mutable_freshness() {
        let observation = ObservationResult {
            context: ObservationContext {
                observation_id: Some("obs_test".into()),
                stop_id: StopId("stop_test".into()),
                captured_revision: 7,
                execution_epoch: 3,
                inferior_id: Some(InferiorId("inf_test".into())),
                thread_id: None,
                frame_id: None,
            },
            results: BTreeMap::from([("stack".into(), json!({"frames": []}))]),
            failures: BTreeMap::new(),
            complete: true,
            availability: BTreeMap::new(),
            warnings: Vec::new(),
            evidence: vec![Evidence {
                kind: "journal-entry".into(),
                uri: "gdbai://session/sess_test/event/9".into(),
            }],
            artifacts: Vec::new(),
            truncated: false,
        };

        let serialized = serde_json::to_value(&observation).unwrap();
        assert_eq!(serialized["context"]["captured_revision"], 7);
        assert!(serialized["context"].get("historical").is_none());
        assert_eq!(
            serde_json::from_value::<ObservationResult>(serialized).unwrap(),
            observation
        );
    }
}

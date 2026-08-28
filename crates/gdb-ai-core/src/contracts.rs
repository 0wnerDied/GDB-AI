use serde_json::{Map, Value, json};

use crate::{Error, ErrorCode, Result, protocol::CanonicalMethod};

#[derive(Clone, Copy)]
enum ParameterKind {
    String,
    Boolean,
    Unsigned,
    Positive,
    Object,
    Array,
    StringArray,
    Shape(&'static ObjectContract),
    ArrayOf(&'static ParameterKind),
    MapOf(&'static ParameterKind),
    OneOf(&'static [ParameterKind]),
    BooleanOrEnum(&'static [&'static str]),
    Enum(&'static [&'static str]),
}

impl ParameterKind {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Boolean => value.is_boolean(),
            Self::Unsigned => value.as_u64().is_some(),
            Self::Positive => value.as_u64().is_some_and(|value| value > 0),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::StringArray => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            Self::Shape(contract) => contract.accepts(value),
            Self::ArrayOf(kind) => value
                .as_array()
                .is_some_and(|items| items.iter().all(|item| kind.accepts(item))),
            Self::MapOf(kind) => value
                .as_object()
                .is_some_and(|object| object.values().all(|value| kind.accepts(value))),
            Self::OneOf(kinds) => kinds.iter().filter(|kind| kind.accepts(value)).count() == 1,
            Self::BooleanOrEnum(values) => {
                value.is_boolean() || value.as_str().is_some_and(|value| values.contains(&value))
            }
            Self::Enum(values) => value.as_str().is_some_and(|value| values.contains(&value)),
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::String => "a string",
            Self::Boolean => "a boolean",
            Self::Unsigned => "an unsigned integer",
            Self::Positive => "a positive integer",
            Self::Object => "an object",
            Self::Array => "an array",
            Self::StringArray => "an array of strings",
            Self::Shape(_) => "a supported object",
            Self::ArrayOf(_) => "an array of supported values",
            Self::MapOf(_) => "an object with supported values",
            Self::OneOf(_) => "one supported shape",
            Self::BooleanOrEnum(_) => "a boolean or supported string",
            Self::Enum(_) => "a supported string",
        }
    }

    fn schema(self) -> Value {
        match self {
            Self::String => json!({"type": "string"}),
            Self::Boolean => json!({"type": "boolean"}),
            Self::Unsigned => json!({"type": "integer", "minimum": 0}),
            Self::Positive => json!({"type": "integer", "minimum": 1}),
            Self::Object => json!({"type": "object"}),
            Self::Array => json!({"type": "array"}),
            Self::StringArray => json!({"type": "array", "items": {"type": "string"}}),
            Self::Shape(contract) => contract.schema(),
            Self::ArrayOf(kind) => json!({"type": "array", "items": kind.schema()}),
            Self::MapOf(kind) => {
                json!({"type": "object", "additionalProperties": kind.schema()})
            }
            Self::OneOf(kinds) => {
                json!({"oneOf": kinds.iter().map(|kind| kind.schema()).collect::<Vec<_>>()})
            }
            Self::BooleanOrEnum(values) => json!({
                "oneOf": [
                    {"type": "boolean"},
                    {"type": "string", "enum": values}
                ]
            }),
            Self::Enum(values) => json!({"type": "string", "enum": values}),
        }
    }
}

#[derive(Clone, Copy)]
struct ParameterField {
    name: &'static str,
    kind: ParameterKind,
    required: bool,
}

const fn optional(name: &'static str, kind: ParameterKind) -> ParameterField {
    ParameterField {
        name,
        kind,
        required: false,
    }
}

const fn required(name: &'static str, kind: ParameterKind) -> ParameterField {
    ParameterField {
        name,
        kind,
        required: true,
    }
}

// 2026-08-28: Object and array contracts checked only their top level, so
// malformed nested requests reached stateful handlers. One recursive shape
// now drives both runtime validation and the published JSON Schema.
struct ObjectContract {
    fields: &'static [ParameterField],
    min_properties: usize,
    any_of: &'static [&'static str],
}

impl ObjectContract {
    const fn new(
        fields: &'static [ParameterField],
        min_properties: usize,
        any_of: &'static [&'static str],
    ) -> Self {
        Self {
            fields,
            min_properties,
            any_of,
        }
    }

    fn accepts(&self, value: &Value) -> bool {
        let Some(object) = value.as_object() else {
            return false;
        };
        if object.len() < self.min_properties
            || self
                .fields
                .iter()
                .filter(|field| field.required)
                .any(|field| !object.contains_key(field.name))
            || (!self.any_of.is_empty()
                && !self.any_of.iter().any(|field| object.contains_key(*field)))
        {
            return false;
        }
        object.iter().all(|(name, value)| {
            self.fields
                .iter()
                .find(|field| field.name == name)
                .is_some_and(|field| field.kind.accepts(value))
        })
    }

    fn schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for field in self.fields {
            properties.insert(field.name.into(), field.kind.schema());
            if field.required {
                required.push(field.name);
            }
        }
        let mut schema = json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        });
        if self.min_properties > 0 {
            schema["minProperties"] = Value::from(self.min_properties);
        }
        if !self.any_of.is_empty() {
            schema["anyOf"] = Value::Array(
                self.any_of
                    .iter()
                    .map(|field| json!({"required": [field]}))
                    .collect(),
            );
        }
        schema
    }
}

const STRING_KIND: ParameterKind = ParameterKind::String;

const WAIT_FIELDS: &[ParameterField] = &[
    required(
        "until",
        ParameterKind::Enum(&["accepted", "running", "stopped", "snapshot", "exited"]),
    ),
    optional("timeout_ms", ParameterKind::Positive),
];
const WAIT_OBJECT: ObjectContract = ObjectContract::new(WAIT_FIELDS, 0, &[]);
const WAIT_KIND: ParameterKind = ParameterKind::Shape(&WAIT_OBJECT);

const ENDPOINT_FIELDS: &[ParameterField] = &[
    required("host", ParameterKind::String),
    required("port", ParameterKind::Positive),
];
const ENDPOINT_OBJECT: ObjectContract = ObjectContract::new(ENDPOINT_FIELDS, 0, &[]);
const ENDPOINT_KINDS: &[ParameterKind] = &[
    ParameterKind::String,
    ParameterKind::Shape(&ENDPOINT_OBJECT),
];
const ENDPOINT_KIND: ParameterKind = ParameterKind::OneOf(ENDPOINT_KINDS);

const SOURCE_FIELDS: &[ParameterField] = &[
    required("path", ParameterKind::String),
    required("line", ParameterKind::Unsigned),
];
const SOURCE_OBJECT: ObjectContract = ObjectContract::new(SOURCE_FIELDS, 0, &[]);
const SOURCE_KIND: ParameterKind = ParameterKind::Shape(&SOURCE_OBJECT);

const MODULE_OFFSET_FIELDS: &[ParameterField] = &[
    required("module", ParameterKind::String),
    required("offset", ParameterKind::String),
];
const MODULE_OFFSET_OBJECT: ObjectContract = ObjectContract::new(MODULE_OFFSET_FIELDS, 0, &[]);
const MODULE_OFFSET_KIND: ParameterKind = ParameterKind::Shape(&MODULE_OFFSET_OBJECT);

const LOCATION_FIELDS: &[ParameterField] = &[
    optional("function", ParameterKind::String),
    optional("address", ParameterKind::String),
    optional("expression", ParameterKind::String),
    optional("source", SOURCE_KIND),
    optional("module_offset", MODULE_OFFSET_KIND),
];
const LOCATION_OBJECT: ObjectContract = ObjectContract::new(LOCATION_FIELDS, 1, &[]);
const LOCATION_KIND: ParameterKind = ParameterKind::Shape(&LOCATION_OBJECT);

const AROUND_FIELDS: &[ParameterField] = &[
    optional("expression", ParameterKind::String),
    optional("before_instructions", ParameterKind::Unsigned),
    optional("after_instructions", ParameterKind::Unsigned),
];
const AROUND_OBJECT: ObjectContract = ObjectContract::new(AROUND_FIELDS, 0, &[]);
const AROUND_KIND: ParameterKind = ParameterKind::Shape(&AROUND_OBJECT);

const RANGE_FIELDS: &[ParameterField] = &[
    required("start", ParameterKind::String),
    required("end", ParameterKind::String),
];
const RANGE_OBJECT: ObjectContract = ObjectContract::new(RANGE_FIELDS, 0, &[]);
const RANGE_KIND: ParameterKind = ParameterKind::Shape(&RANGE_OBJECT);

const EXPECTED_FIELDS: &[ParameterField] = &[
    optional("bytes_base64", ParameterKind::String),
    optional("sha256", ParameterKind::String),
];
const EXPECTED_OBJECT: ObjectContract =
    ObjectContract::new(EXPECTED_FIELDS, 1, &["bytes_base64", "sha256"]);
const EXPECTED_KIND: ParameterKind = ParameterKind::Shape(&EXPECTED_OBJECT);

const PATTERN_FIELDS: &[ParameterField] = &[
    optional("kind", ParameterKind::Enum(&["bytes", "text"])),
    optional("hex", ParameterKind::String),
    optional("data_base64", ParameterKind::String),
    optional("text", ParameterKind::String),
];
const PATTERN_OBJECT: ObjectContract =
    ObjectContract::new(PATTERN_FIELDS, 1, &["hex", "data_base64", "text"]);
const PATTERN_KIND: ParameterKind = ParameterKind::Shape(&PATTERN_OBJECT);

const BUDGET_FIELDS: &[ParameterField] = &[
    optional("max_calls", ParameterKind::Positive),
    optional("max_frames", ParameterKind::Positive),
    optional("max_values", ParameterKind::Positive),
    optional("max_memory_bytes", ParameterKind::Positive),
    optional("max_instructions", ParameterKind::Positive),
    optional("max_context_bytes", ParameterKind::Positive),
    optional("wall_time_ms", ParameterKind::Positive),
];
const BUDGET_OBJECT: ObjectContract = ObjectContract::new(BUDGET_FIELDS, 0, &[]);
const BUDGET_KIND: ParameterKind = ParameterKind::Shape(&BUDGET_OBJECT);

const CAPTURE_STACK_FIELDS: &[ParameterField] = &[optional("limit", ParameterKind::Positive)];
const CAPTURE_STACK_OBJECT: ObjectContract = ObjectContract::new(CAPTURE_STACK_FIELDS, 0, &[]);
const CAPTURE_EXPRESSION_FIELDS: &[ParameterField] =
    &[required("expression", ParameterKind::String)];
const CAPTURE_EXPRESSION_OBJECT: ObjectContract =
    ObjectContract::new(CAPTURE_EXPRESSION_FIELDS, 0, &[]);
const CAPTURE_STACK_ITEM_FIELDS: &[ParameterField] = &[required(
    "stack",
    ParameterKind::Shape(&CAPTURE_STACK_OBJECT),
)];
const CAPTURE_STACK_ITEM_OBJECT: ObjectContract =
    ObjectContract::new(CAPTURE_STACK_ITEM_FIELDS, 0, &[]);
const CAPTURE_ITEM_KINDS: &[ParameterKind] = &[
    ParameterKind::Shape(&CAPTURE_EXPRESSION_OBJECT),
    ParameterKind::Shape(&CAPTURE_STACK_ITEM_OBJECT),
];
const CAPTURE_ITEM_KIND: ParameterKind = ParameterKind::OneOf(CAPTURE_ITEM_KINDS);
const CAPTURE_KIND: ParameterKind = ParameterKind::ArrayOf(&CAPTURE_ITEM_KIND);

const ENVIRONMENT_KIND: ParameterKind = ParameterKind::MapOf(&STRING_KIND);

const COMMON_FIELDS: &[ParameterField] = &[
    optional("accept_latest_revision", ParameterKind::Boolean),
    optional("lease_id", ParameterKind::String),
];

const CONTEXT_FIELDS: &[ParameterField] = &[
    optional("stop_id", ParameterKind::String),
    optional("accept_current_stop", ParameterKind::Boolean),
    optional("inferior_id", ParameterKind::String),
    optional("thread_id", ParameterKind::String),
    optional("frame_id", ParameterKind::String),
    optional("frame_level", ParameterKind::Unsigned),
];

struct MethodContract {
    fields: Vec<ParameterField>,
    context: bool,
}

impl MethodContract {
    fn plain(fields: Vec<ParameterField>) -> Self {
        Self {
            fields,
            context: false,
        }
    }

    fn contextual(fields: Vec<ParameterField>) -> Self {
        Self {
            fields,
            context: true,
        }
    }

    fn fields(&self) -> impl Iterator<Item = &ParameterField> {
        COMMON_FIELDS
            .iter()
            .chain(self.context.then_some(CONTEXT_FIELDS).into_iter().flatten())
            .chain(self.fields.iter())
    }

    fn schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for field in self.fields() {
            properties.insert(field.name.into(), field.kind.schema());
            if field.required {
                required.push(field.name);
            }
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        })
    }

    fn validate(&self, parameters: &Value) -> Result<()> {
        let object = parameters.as_object().ok_or_else(|| {
            Error::new(ErrorCode::InvalidArgument, "parameters must be an object")
        })?;
        for (name, value) in object {
            let field = self
                .fields()
                .find(|field| field.name == name)
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("unknown parameter {name}"),
                    )
                })?;
            if !field.kind.accepts(value) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("parameter {name} must be {}", field.kind.description()),
                ));
            }
        }
        for field in self.fields().filter(|field| field.required) {
            if !object.contains_key(field.name) {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("{} is required", field.name),
                ));
            }
        }
        Ok(())
    }
}

impl CanonicalMethod {
    fn contract(self) -> MethodContract {
        use CanonicalMethod::*;
        use ParameterKind::*;

        match self {
            SessionCreate => MethodContract::plain(vec![optional(
                "profile",
                Enum(&[
                    "offline_core",
                    "live_observer",
                    "debug_control",
                    "lab_mutation",
                    "raw_admin",
                ]),
            )]),
            SessionGet
            | SessionList
            | SessionClose
            | SessionReleaseWriteLease
            | SessionAttemptRecovery
            | SessionCapabilities
            | SessionProviders
            | TargetDetach
            | BreakpointList
            | InferiorIoCloseStdin
            | InferiorIoSendEof
            | TrackingList
            | SignalGet => MethodContract::plain(vec![]),
            SessionAcquireWriteLease => MethodContract::plain(vec![optional("force", Boolean)]),
            SessionTranscript => MethodContract::plain(vec![
                optional("offset", Unsigned),
                optional("max_bytes", Unsigned),
            ]),
            SessionEvent => MethodContract::plain(vec![required("event_seq", Unsigned)]),
            TargetLaunch => MethodContract::plain(vec![
                required("program", String),
                optional("argv", StringArray),
                optional("cwd", String),
                optional("environment", ENVIRONMENT_KIND),
                optional("environment_mode", Enum(&["clean"])),
                optional("aslr", Enum(&["preserve", "disable"])),
                optional(
                    "stop",
                    Enum(&["first_instruction", "main", "none", "entry"]),
                ),
                optional("follow_fork", Enum(&["parent", "child"])),
                optional("detach_on_fork", Boolean),
                optional("follow_exec", Enum(&["same-inferior"])),
                optional("wait", WAIT_KIND),
            ]),
            TargetAttach => MethodContract::plain(vec![
                required("pid", Unsigned),
                optional("executable", String),
                optional("wait", WAIT_KIND),
            ]),
            TargetConnectRemote => MethodContract::plain(vec![
                optional("mode", Enum(&["remote", "extended-remote"])),
                required("endpoint", ENDPOINT_KIND),
                optional("executable", String),
                optional("wait", WAIT_KIND),
            ]),
            TargetOpenCore => MethodContract::plain(vec![
                required("executable", String),
                required("core", String),
            ]),
            TargetRestart => MethodContract::plain(vec![
                optional(
                    "stop",
                    Enum(&["first_instruction", "main", "none", "entry"]),
                ),
                optional("stop_at_entry", Boolean),
                optional("wait", WAIT_KIND),
            ]),
            TargetKill => MethodContract::plain(vec![optional("wait", WAIT_KIND)]),
            ExecutionControl => MethodContract::contextual(vec![
                required(
                    "action",
                    Enum(&[
                        "continue",
                        "interrupt",
                        "step",
                        "next",
                        "finish",
                        "step_instruction",
                        "next_instruction",
                        "until",
                    ]),
                ),
                optional("location", String),
                optional("wait", WAIT_KIND),
            ]),
            ExecutionWait => MethodContract::plain(vec![
                optional("operation_id", String),
                required("wait", WAIT_KIND),
            ]),
            BreakpointCreate => MethodContract::plain(vec![
                optional(
                    "kind",
                    Enum(&[
                        "software",
                        "hardware",
                        "temporary",
                        "instruction",
                        "watchpoint",
                        "read_watchpoint",
                        "access_watchpoint",
                        "catchpoint",
                    ]),
                ),
                optional("location", LOCATION_KIND),
                optional("function", String),
                optional("address", String),
                optional("expression", String),
                optional("source", SOURCE_KIND),
                optional("module_offset", MODULE_OFFSET_KIND),
                optional("catch", String),
                optional("temporary", Boolean),
                optional("hardware", BooleanOrEnum(&["auto", "required"])),
                optional("pending", Boolean),
                optional("condition", String),
                optional("ignore_count", Unsigned),
                optional("thread_id", String),
                optional("inferior_id", String),
            ]),
            BreakpointUpdate => MethodContract::plain(vec![
                optional("breakpoint_id", String),
                optional("backend_number", String),
                optional("enabled", Boolean),
                optional("condition", String),
                optional("ignore_count", Unsigned),
            ]),
            BreakpointDelete => MethodContract::plain(vec![
                optional("breakpoint_id", String),
                optional("backend_number", String),
            ]),
            InspectionGet => MethodContract::contextual(vec![
                required(
                    "view",
                    Enum(&[
                        "stop_context",
                        "target",
                        "capabilities",
                        "providers",
                        "crash",
                        "threads",
                        "stack",
                        "frame",
                        "locals",
                        "arguments",
                        "registers",
                        "modules",
                        "breakpoints",
                        "source",
                        "mappings",
                        "signals",
                    ]),
                ),
                optional("limit", Unsigned),
                optional("offset", Unsigned),
                optional("roles", StringArray),
                optional("path", String),
                optional("line", Unsigned),
                optional("before_lines", Unsigned),
                optional("after_lines", Unsigned),
                optional("profile", Enum(&["minimal", "brief", "standard", "deep"])),
                optional("around", AROUND_KIND),
                optional("range", RANGE_KIND),
                optional("include_bytes", Boolean),
                optional("include_source", Boolean),
            ]),
            InspectionSnapshot => MethodContract::contextual(vec![
                optional("profile", Enum(&["minimal", "brief", "standard", "deep"])),
                optional("limit", Unsigned),
                optional("roles", StringArray),
                optional("around", AROUND_KIND),
                optional("range", RANGE_KIND),
                optional("include_bytes", Boolean),
                optional("include_source", Boolean),
            ]),
            InspectionDiff => MethodContract::plain(vec![
                required("before_snapshot_id", String),
                required("after_snapshot_id", String),
            ]),
            InspectionBatch => MethodContract::contextual(vec![required("requests", Array)]),
            InspectionSnapshotGet => MethodContract::plain(vec![required("snapshot_id", String)]),
            ValueEvaluate => MethodContract::contextual(vec![
                required("expression", String),
                optional("side_effects", Enum(&["deny"])),
            ]),
            ValueCreate => MethodContract::contextual(vec![required("expression", String)]),
            ValueChildren => MethodContract::contextual(vec![
                required("value_id", String),
                optional("offset", Unsigned),
                optional("limit", Unsigned),
            ]),
            ValueUpdate | ValueRelease => {
                MethodContract::contextual(vec![required("value_id", String)])
            }
            MemoryRead => MethodContract::contextual(vec![
                required("address", String),
                required("length", Unsigned),
                optional("allow_partial", Boolean),
                optional("volatile", Boolean),
            ]),
            MemoryWrite => MethodContract::contextual(vec![
                required("address", String),
                optional("text", String),
                optional("data_base64", String),
                required("expected", EXPECTED_KIND),
            ]),
            MemorySearch => MethodContract::contextual(vec![
                required("start", String),
                required("length", Unsigned),
                required("pattern", PATTERN_KIND),
                optional("max_results", Unsigned),
                optional("volatile", Boolean),
            ]),
            MemoryCompare => MethodContract::contextual(vec![
                required("address", String),
                required("length", Unsigned),
                required("expected", EXPECTED_KIND),
                optional("volatile", Boolean),
            ]),
            RegisterRead => MethodContract::contextual(vec![optional("roles", StringArray)]),
            RegisterWrite => MethodContract::contextual(vec![
                required("register", String),
                required("value", String),
                required("reason", String),
            ]),
            DisassemblyRead => MethodContract::contextual(vec![
                optional("around", AROUND_KIND),
                optional("range", RANGE_KIND),
                optional("include_bytes", Boolean),
                optional("include_source", Boolean),
            ]),
            InferiorIoRead => MethodContract::plain(vec![
                optional("stream", Enum(&["pty", "target", "console", "log"])),
                optional("after_offset", Unsigned),
                optional("max_bytes", Unsigned),
            ]),
            InferiorIoWrite => MethodContract::plain(vec![
                optional("text", String),
                optional("data_base64", String),
            ]),
            InferiorIoResize => MethodContract::plain(vec![
                required("rows", Unsigned),
                required("columns", Unsigned),
            ]),
            TrackingAddExpression => MethodContract::plain(vec![
                required("expression", String),
                optional("max_value_bytes", Unsigned),
            ]),
            TrackingAddMemory => MethodContract::plain(vec![
                required("address_expression", String),
                required("length", Unsigned),
                optional("max_history", Unsigned),
            ]),
            TrackingRemove => MethodContract::plain(vec![required("tracking_id", String)]),
            SignalUpdate => MethodContract::plain(vec![required("signals", Object)]),
            AgentHypothesisCheck => MethodContract::contextual(vec![
                optional("claim", String),
                required("expression", String),
                optional(
                    "operator",
                    Enum(&[
                        "equals",
                        "not_equals",
                        "contains",
                        "greater_than",
                        "less_than",
                    ]),
                ),
                required("expected", String),
            ]),
            AgentProbe | AgentExperiment => MethodContract::contextual(vec![
                optional("location", LOCATION_KIND),
                optional("function", String),
                optional("address", String),
                optional("expression", String),
                optional("source", SOURCE_KIND),
                optional("module_offset", MODULE_OFFSET_KIND),
                optional("condition", String),
                optional("capture", CAPTURE_KIND),
                optional("max_hits", Unsigned),
                optional(
                    "stop_policy",
                    Enum(&["on_condition", "continue_after_capture"]),
                ),
                optional("budget", BUDGET_KIND),
            ]),
            KernelInspect => MethodContract::contextual(vec![
                required(
                    "view",
                    Enum(&["current_task", "init_task", "stack", "panic"]),
                ),
                optional("limit", Unsigned),
                optional("offset", Unsigned),
                optional("roles", StringArray),
                optional("around", AROUND_KIND),
                optional("range", RANGE_KIND),
                optional("include_bytes", Boolean),
                optional("include_source", Boolean),
            ]),
            KernelMonitor => MethodContract::plain(vec![required("command", String)]),
            ArtifactGet => MethodContract::plain(vec![
                required("uri", String),
                optional("offset", Unsigned),
                optional("max_bytes", Unsigned),
            ]),
            EventsWait => MethodContract::plain(vec![
                optional("after_event_seq", Unsigned),
                optional("timeout_ms", Unsigned),
            ]),
            RawMi => MethodContract::plain(vec![
                required("command", String),
                optional("arguments", Array),
                optional("timeout_ms", Unsigned),
            ]),
            RawConsole => MethodContract::plain(vec![
                required("command", String),
                optional("timeout_ms", Unsigned),
            ]),
        }
    }

    pub fn validate_parameters(self, parameters: &Value) -> Result<()> {
        self.contract().validate(parameters)
    }

    pub fn parameter_schema(self) -> Value {
        self.contract().schema()
    }

    pub const fn requires_session(self) -> bool {
        !matches!(
            self,
            Self::SessionCreate | Self::SessionList | Self::ArtifactGet
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_method_specific_parameters() {
        CanonicalMethod::MemoryRead
            .validate_parameters(&json!({
                "address": "0x1000",
                "length": 16,
                "stop_id": "stop_test"
            }))
            .unwrap();
        assert!(
            CanonicalMethod::MemoryRead
                .validate_parameters(&json!({"address": "0x1000"}))
                .is_err()
        );
        assert!(
            CanonicalMethod::MemoryRead
                .validate_parameters(&json!({
                    "address": "0x1000",
                    "length": "16",
                    "unknown": true
                }))
                .is_err()
        );
    }

    #[test]
    fn validates_nested_parameter_contracts() {
        for (method, parameters) in [
            (
                CanonicalMethod::TargetLaunch,
                json!({"program": "/tmp/a", "wait": {"until": "stopped", "extra": true}}),
            ),
            (
                CanonicalMethod::TargetConnectRemote,
                json!({"endpoint": {"host": "127.0.0.1"}}),
            ),
            (
                CanonicalMethod::BreakpointCreate,
                json!({"source": {"path": "/tmp/a.c"}}),
            ),
            (
                CanonicalMethod::MemoryWrite,
                json!({"address": "0x1000", "text": "A", "expected": {"unknown": "x"}}),
            ),
            (
                CanonicalMethod::MemorySearch,
                json!({"start": "0x1000", "length": 16, "pattern": {"kind": "bytes"}}),
            ),
            (
                CanonicalMethod::AgentProbe,
                json!({"capture": [{"expression": "x", "stack": {}}]}),
            ),
            (
                CanonicalMethod::AgentProbe,
                json!({"budget": {"max_calls": 0}}),
            ),
        ] {
            assert!(method.validate_parameters(&parameters).is_err());
        }

        CanonicalMethod::AgentProbe
            .validate_parameters(&json!({
                "location": {"source": {"path": "/tmp/a.c", "line": 7}},
                "capture": [{"expression": "length"}, {"stack": {"limit": 4}}],
                "budget": {"max_calls": 8, "wall_time_ms": 1000}
            }))
            .unwrap();
        assert_eq!(
            CanonicalMethod::TargetLaunch.parameter_schema()["properties"]["wait"]["additionalProperties"],
            false
        );
    }
}

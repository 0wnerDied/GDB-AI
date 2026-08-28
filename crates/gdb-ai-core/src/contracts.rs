use serde_json::{Map, Value, json};

use crate::{Error, ErrorCode, Result, protocol::CanonicalMethod};

#[derive(Clone, Copy)]
enum ParameterKind {
    String,
    Boolean,
    Unsigned,
    Object,
    Array,
    StringArray,
    StringOrObject,
    BooleanOrEnum(&'static [&'static str]),
    Enum(&'static [&'static str]),
}

impl ParameterKind {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Boolean => value.is_boolean(),
            Self::Unsigned => value.as_u64().is_some(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::StringArray => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            Self::StringOrObject => value.is_string() || value.is_object(),
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
            Self::Object => "an object",
            Self::Array => "an array",
            Self::StringArray => "an array of strings",
            Self::StringOrObject => "a string or object",
            Self::BooleanOrEnum(_) => "a boolean or supported string",
            Self::Enum(_) => "a supported string",
        }
    }

    fn schema(self) -> Value {
        match self {
            Self::String => json!({"type": "string"}),
            Self::Boolean => json!({"type": "boolean"}),
            Self::Unsigned => json!({"type": "integer", "minimum": 0}),
            Self::Object => json!({"type": "object"}),
            Self::Array => json!({"type": "array"}),
            Self::StringArray => json!({"type": "array", "items": {"type": "string"}}),
            Self::StringOrObject => json!({
                "oneOf": [{"type": "string"}, {"type": "object"}]
            }),
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
                optional("environment", Object),
                optional("environment_mode", Enum(&["clean"])),
                optional("aslr", Enum(&["preserve", "disable"])),
                optional("stop", Enum(&["entry", "none"])),
                optional("follow_fork", Enum(&["parent", "child"])),
                optional("detach_on_fork", Boolean),
                optional("follow_exec", Enum(&["same-inferior"])),
                optional("wait", Object),
            ]),
            TargetAttach => MethodContract::plain(vec![
                required("pid", Unsigned),
                optional("executable", String),
                optional("wait", Object),
            ]),
            TargetConnectRemote => MethodContract::plain(vec![
                optional("mode", Enum(&["remote", "extended-remote"])),
                required("endpoint", StringOrObject),
                optional("executable", String),
                optional("wait", Object),
            ]),
            TargetOpenCore => MethodContract::plain(vec![
                required("executable", String),
                required("core", String),
            ]),
            TargetRestart => MethodContract::plain(vec![
                optional("stop_at_entry", Boolean),
                optional("wait", Object),
            ]),
            TargetKill => MethodContract::plain(vec![optional("wait", Object)]),
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
                optional("wait", Object),
            ]),
            ExecutionWait => MethodContract::plain(vec![
                optional("operation_id", String),
                required("wait", Object),
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
                optional("location", Object),
                optional("function", String),
                optional("address", String),
                optional("expression", String),
                optional("source", Object),
                optional("module_offset", Object),
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
                optional("around", Object),
                optional("range", Object),
                optional("include_bytes", Boolean),
                optional("include_source", Boolean),
            ]),
            InspectionSnapshot => MethodContract::contextual(vec![
                optional("profile", Enum(&["minimal", "brief", "standard", "deep"])),
                optional("limit", Unsigned),
                optional("roles", StringArray),
                optional("around", Object),
                optional("range", Object),
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
                required("expected", Object),
            ]),
            MemorySearch => MethodContract::contextual(vec![
                required("start", String),
                required("length", Unsigned),
                required("pattern", Object),
                optional("max_results", Unsigned),
                optional("volatile", Boolean),
            ]),
            MemoryCompare => MethodContract::contextual(vec![
                required("address", String),
                required("length", Unsigned),
                required("expected", Object),
                optional("volatile", Boolean),
            ]),
            RegisterRead => MethodContract::contextual(vec![optional("roles", StringArray)]),
            RegisterWrite => MethodContract::contextual(vec![
                required("register", String),
                required("value", String),
                required("reason", String),
            ]),
            DisassemblyRead => MethodContract::contextual(vec![
                optional("around", Object),
                optional("range", Object),
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
                optional("location", Object),
                optional("function", String),
                optional("address", String),
                optional("expression", String),
                optional("source", Object),
                optional("module_offset", Object),
                optional("condition", String),
                optional("capture", Array),
                optional("max_hits", Unsigned),
                optional(
                    "stop_policy",
                    Enum(&["on_condition", "continue_after_capture"]),
                ),
                optional("budget", Object),
            ]),
            KernelInspect => MethodContract::contextual(vec![
                required(
                    "view",
                    Enum(&["current_task", "init_task", "stack", "panic"]),
                ),
                optional("limit", Unsigned),
                optional("offset", Unsigned),
                optional("roles", StringArray),
                optional("around", Object),
                optional("range", Object),
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
}

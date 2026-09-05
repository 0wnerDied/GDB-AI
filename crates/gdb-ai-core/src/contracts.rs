use serde_json::{Map, Value, json};

use crate::{Error, ErrorCode, Result, protocol::CanonicalMethod};

#[derive(Clone, Copy)]
enum ParameterKind {
    String,
    Boolean,
    Unsigned,
    Positive,
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

    fn description(self) -> String {
        match self {
            Self::String => "a string".into(),
            Self::Boolean => "a boolean".into(),
            Self::Unsigned => "an unsigned integer".into(),
            Self::Positive => "a positive integer".into(),
            Self::StringArray => "an array of strings".into(),
            Self::Shape(_) => "a supported object".into(),
            Self::ArrayOf(_) => "an array of supported values".into(),
            Self::MapOf(_) => "an object with supported values".into(),
            Self::OneOf(_) => "one supported shape".into(),
            // 2026-08-28: Generic enum errors forced Agents to guess values
            // already known by the canonical contract.
            Self::BooleanOrEnum(values) => {
                format!("a boolean or one of {}", values.join(", "))
            }
            Self::Enum(values) => format!("one of {}", values.join(", ")),
        }
    }

    fn schema(self) -> Value {
        match self {
            Self::String => json!({"type": "string"}),
            Self::Boolean => json!({"type": "boolean"}),
            Self::Unsigned => json!({"type": "integer", "minimum": 0}),
            Self::Positive => json!({"type": "integer", "minimum": 1}),
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
    exactly_one_of: &'static [&'static str],
}

impl ObjectContract {
    const fn new(
        fields: &'static [ParameterField],
        min_properties: usize,
        exactly_one_of: &'static [&'static str],
    ) -> Self {
        Self {
            fields,
            min_properties,
            exactly_one_of,
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
            || (!self.exactly_one_of.is_empty()
                && self
                    .exactly_one_of
                    .iter()
                    .filter(|field| object.contains_key(**field))
                    .count()
                    != 1)
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
        if !self.exactly_one_of.is_empty() {
            // 2026-08-29: anyOf accepted multiple selectors and let handlers
            // silently choose one by implementation order. oneOf makes the
            // runtime and published contract reject ambiguous evidence input.
            schema["oneOf"] = Value::Array(
                self.exactly_one_of
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
        ParameterKind::Enum(&[
            "accepted", "running", "stopped", "settled", "snapshot", "exited",
        ]),
    ),
    optional("timeout_ms", ParameterKind::Positive),
];
const WAIT_OBJECT: ObjectContract = ObjectContract::new(WAIT_FIELDS, 0, &[]);
const WAIT_KIND: ParameterKind = ParameterKind::Shape(&WAIT_OBJECT);

const INFERIOR_INPUT_FIELDS: &[ParameterField] = &[
    optional("text", ParameterKind::String),
    optional("data_base64", ParameterKind::String),
];
const INFERIOR_INPUT_OBJECT: ObjectContract =
    ObjectContract::new(INFERIOR_INPUT_FIELDS, 0, &["text", "data_base64"]);
const INFERIOR_INPUT_KIND: ParameterKind = ParameterKind::Shape(&INFERIOR_INPUT_OBJECT);

const PROBE_TRIGGER_FIELDS: &[ParameterField] = &[
    required("command", ParameterKind::StringArray),
    optional("cwd", ParameterKind::String),
];
const PROBE_TRIGGER_OBJECT: ObjectContract = ObjectContract::new(PROBE_TRIGGER_FIELDS, 0, &[]);
const PROBE_TRIGGER_KIND: ParameterKind = ParameterKind::Shape(&PROBE_TRIGGER_OBJECT);

const IO_WRITE_STEP_FIELDS: &[ParameterField] = &[
    optional("wait_for", ParameterKind::String),
    optional("text", ParameterKind::String),
    optional("data_base64", ParameterKind::String),
];
const IO_WRITE_STEP_OBJECT: ObjectContract =
    ObjectContract::new(IO_WRITE_STEP_FIELDS, 0, &["text", "data_base64"]);
const IO_WRITE_STEP_KIND: ParameterKind = ParameterKind::Shape(&IO_WRITE_STEP_OBJECT);
const IO_WRITE_STEPS_KIND: ParameterKind = ParameterKind::ArrayOf(&IO_WRITE_STEP_KIND);

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
    required("line", ParameterKind::Positive),
];
const SOURCE_OBJECT: ObjectContract = ObjectContract::new(SOURCE_FIELDS, 0, &[]);
const SOURCE_KIND: ParameterKind = ParameterKind::Shape(&SOURCE_OBJECT);

const MODULE_OFFSET_FIELDS: &[ParameterField] = &[
    required("module", ParameterKind::String),
    required("offset", ParameterKind::String),
];
const MODULE_OFFSET_OBJECT: ObjectContract = ObjectContract::new(MODULE_OFFSET_FIELDS, 0, &[]);
const MODULE_OFFSET_KIND: ParameterKind = ParameterKind::Shape(&MODULE_OFFSET_OBJECT);

const KERNEL_MODULE_OFFSET_FIELDS: &[ParameterField] = &[
    required("module", ParameterKind::String),
    required("offset", ParameterKind::String),
];
const KERNEL_MODULE_OFFSET_OBJECT: ObjectContract =
    ObjectContract::new(KERNEL_MODULE_OFFSET_FIELDS, 0, &[]);
const KERNEL_MODULE_OFFSET_KIND: ParameterKind = ParameterKind::Shape(&KERNEL_MODULE_OFFSET_OBJECT);

const LOCATION_FIELDS: &[ParameterField] = &[
    optional("function", ParameterKind::String),
    optional("address", ParameterKind::String),
    optional("expression", ParameterKind::String),
    optional("source", SOURCE_KIND),
    optional("module_offset", MODULE_OFFSET_KIND),
];
const LOCATION_OBJECT: ObjectContract = ObjectContract::new(
    LOCATION_FIELDS,
    1,
    &[
        "function",
        "address",
        "expression",
        "source",
        "module_offset",
    ],
);
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
const CAPTURE_MEMORY_FIELDS: &[ParameterField] = &[
    required("address_expression", ParameterKind::String),
    required("length", ParameterKind::Positive),
];
const CAPTURE_MEMORY_OBJECT: ObjectContract = ObjectContract::new(CAPTURE_MEMORY_FIELDS, 0, &[]);
const CAPTURE_MEMORY_ITEM_FIELDS: &[ParameterField] = &[required(
    "memory",
    ParameterKind::Shape(&CAPTURE_MEMORY_OBJECT),
)];
const CAPTURE_MEMORY_ITEM_OBJECT: ObjectContract =
    ObjectContract::new(CAPTURE_MEMORY_ITEM_FIELDS, 0, &[]);
const CAPTURE_ITEM_KINDS: &[ParameterKind] = &[
    ParameterKind::Shape(&CAPTURE_EXPRESSION_OBJECT),
    ParameterKind::Shape(&CAPTURE_STACK_ITEM_OBJECT),
    ParameterKind::Shape(&CAPTURE_MEMORY_ITEM_OBJECT),
];
const CAPTURE_ITEM_KIND: ParameterKind = ParameterKind::OneOf(CAPTURE_ITEM_KINDS);
const CAPTURE_KIND: ParameterKind = ParameterKind::ArrayOf(&CAPTURE_ITEM_KIND);

const ENVIRONMENT_KIND: ParameterKind = ParameterKind::MapOf(&STRING_KIND);

const INSPECTION_VIEWS: &[&str] = &[
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
    "symbols",
    "source",
    "mappings",
    "signals",
];

// 2026-08-29: The last generic object and array contracts let malformed
// batch, signal, and raw MI children pass the shared protocol boundary.
const INSPECTION_BATCH_ITEM_FIELDS: &[ParameterField] = &[
    optional("name", ParameterKind::String),
    required("view", ParameterKind::Enum(INSPECTION_VIEWS)),
    optional("inferior_id", ParameterKind::String),
    optional("thread_id", ParameterKind::String),
    optional("frame_id", ParameterKind::String),
    optional("frame_level", ParameterKind::Unsigned),
    optional("limit", ParameterKind::Unsigned),
    optional("stack_depth", ParameterKind::Positive),
    optional("offset", ParameterKind::Unsigned),
    optional("roles", ParameterKind::StringArray),
    optional("query", ParameterKind::String),
    optional(
        "kind",
        ParameterKind::Enum(&["functions", "types", "variables"]),
    ),
    optional("type_layout", ParameterKind::String),
    optional("path", ParameterKind::String),
    optional("line", ParameterKind::Positive),
    optional("before_lines", ParameterKind::Unsigned),
    optional("after_lines", ParameterKind::Unsigned),
    optional(
        "profile",
        ParameterKind::Enum(&["minimal", "brief", "standard", "deep"]),
    ),
    optional("around", AROUND_KIND),
    optional("range", RANGE_KIND),
    optional("include_bytes", ParameterKind::Boolean),
    optional("include_source", ParameterKind::Boolean),
];
const INSPECTION_BATCH_ITEM_OBJECT: ObjectContract =
    ObjectContract::new(INSPECTION_BATCH_ITEM_FIELDS, 0, &[]);
const INSPECTION_BATCH_ITEM_KIND: ParameterKind =
    ParameterKind::Shape(&INSPECTION_BATCH_ITEM_OBJECT);
const INSPECTION_BATCH_KIND: ParameterKind = ParameterKind::ArrayOf(&INSPECTION_BATCH_ITEM_KIND);

// 2026-09-01: Repeating the complete batch-item contract in both run branches
// charged every Agent turn for rarely used cross-thread and source selectors.
// Keep the high-value stop-turn controls here; gdb_batch retains the full set.
const TURN_INSPECTION_ITEM_FIELDS: &[ParameterField] = &[
    required("view", ParameterKind::Enum(INSPECTION_VIEWS)),
    optional("limit", ParameterKind::Unsigned),
    optional("stack_depth", ParameterKind::Positive),
    optional("roles", ParameterKind::StringArray),
    optional("query", ParameterKind::String),
    optional(
        "kind",
        ParameterKind::Enum(&["functions", "types", "variables"]),
    ),
    optional("type_layout", ParameterKind::String),
    optional(
        "profile",
        ParameterKind::Enum(&["minimal", "brief", "standard", "deep"]),
    ),
];
const TURN_INSPECTION_ITEM_OBJECT: ObjectContract =
    ObjectContract::new(TURN_INSPECTION_ITEM_FIELDS, 0, &[]);
const TURN_INSPECTION_ITEM_KIND: ParameterKind = ParameterKind::Shape(&TURN_INSPECTION_ITEM_OBJECT);
const TURN_INSPECTION_KIND: ParameterKind = ParameterKind::ArrayOf(&TURN_INSPECTION_ITEM_KIND);

const SIGNAL_POLICY_FIELDS: &[ParameterField] = &[
    required("stop", ParameterKind::Boolean),
    required("print", ParameterKind::Boolean),
    required("pass", ParameterKind::Boolean),
];
const SIGNAL_POLICY_OBJECT: ObjectContract = ObjectContract::new(SIGNAL_POLICY_FIELDS, 0, &[]);
const SIGNAL_POLICY_KIND: ParameterKind = ParameterKind::Shape(&SIGNAL_POLICY_OBJECT);
const SIGNALS_KIND: ParameterKind = ParameterKind::MapOf(&SIGNAL_POLICY_KIND);

const RAW_MI_ARGUMENT_FIELDS: &[ParameterField] = &[
    optional("kind", ParameterKind::Enum(&["bare", "string"])),
    required("value", ParameterKind::String),
];
const RAW_MI_ARGUMENT_OBJECT: ObjectContract = ObjectContract::new(RAW_MI_ARGUMENT_FIELDS, 0, &[]);
const RAW_MI_ARGUMENT_KINDS: &[ParameterKind] = &[
    ParameterKind::String,
    ParameterKind::Shape(&RAW_MI_ARGUMENT_OBJECT),
];
const RAW_MI_ARGUMENT_KIND: ParameterKind = ParameterKind::OneOf(RAW_MI_ARGUMENT_KINDS);
const RAW_MI_ARGUMENTS_KIND: ParameterKind = ParameterKind::ArrayOf(&RAW_MI_ARGUMENT_KIND);

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
    exactly_one_of: Vec<Vec<&'static str>>,
}

impl MethodContract {
    fn plain(fields: Vec<ParameterField>) -> Self {
        Self {
            fields,
            context: false,
            exactly_one_of: Vec::new(),
        }
    }

    fn contextual(fields: Vec<ParameterField>) -> Self {
        Self {
            fields,
            context: true,
            exactly_one_of: Vec::new(),
        }
    }

    fn exactly_one(mut self, fields: &[&'static str]) -> Self {
        self.exactly_one_of.push(fields.to_vec());
        self
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
        let mut schema = json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false
        });
        if !self.exactly_one_of.is_empty() {
            schema["allOf"] = Value::Array(
                self.exactly_one_of
                    .iter()
                    .map(|fields| {
                        json!({
                            "oneOf": fields
                                .iter()
                                .map(|field| json!({"required": [field]}))
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect(),
            );
        }
        schema
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
        for fields in &self.exactly_one_of {
            if fields
                .iter()
                .filter(|field| object.contains_key(**field))
                .count()
                != 1
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("exactly one of {} is required", fields.join(", ")),
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
            | SessionForceAbort
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
            OperationGet => MethodContract::plain(vec![required("operation_id", String)]),
            OperationCancel => MethodContract::plain(vec![
                required("operation_id", String),
                required("mode", Enum(&["interrupt_target", "close_session"])),
            ]),
            TargetLaunch => MethodContract::plain(vec![
                required("program", String),
                optional("argv", StringArray),
                optional("cwd", String),
                optional("environment", ENVIRONMENT_KIND),
                optional("environment_mode", Enum(&["clean", "inherited"])),
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
                optional("input", INFERIOR_INPUT_KIND),
                optional("inspect", TURN_INSPECTION_KIND),
            ]),
            ExecutionWait => MethodContract::plain(vec![
                optional("operation_id", String),
                required("wait", WAIT_KIND),
                optional("input", INFERIOR_INPUT_KIND),
                optional("inspect", TURN_INSPECTION_KIND),
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
            ])
            .exactly_one(&[
                "location",
                "function",
                "address",
                "expression",
                "source",
                "module_offset",
                "catch",
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
                required("view", Enum(INSPECTION_VIEWS)),
                optional("limit", Unsigned),
                optional("stack_depth", Positive),
                optional("offset", Unsigned),
                optional("roles", StringArray),
                optional("query", String),
                optional("kind", Enum(&["functions", "types", "variables"])),
                optional("type_layout", String),
                optional("path", String),
                optional("line", Positive),
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
            InspectionBatch => {
                MethodContract::contextual(vec![required("requests", INSPECTION_BATCH_KIND)])
            }
            InspectionSnapshotGet => MethodContract::plain(vec![required("snapshot_id", String)]),
            ValueEvaluate => MethodContract::contextual(vec![
                optional("expression", String),
                optional("expressions", StringArray),
                optional("side_effects", Enum(&["deny", "allow"])),
            ])
            .exactly_one(&["expression", "expressions"]),
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
                optional("address", String),
                optional("address_expression", String),
                required("length", Unsigned),
                optional("allow_partial", Boolean),
                optional("acknowledge_target_effects", Boolean),
                optional("volatile", Boolean),
            ])
            .exactly_one(&["address", "address_expression"]),
            MemoryWrite => MethodContract::contextual(vec![
                required("address", String),
                optional("text", String),
                optional("data_base64", String),
                required("expected", EXPECTED_KIND),
            ])
            .exactly_one(&["text", "data_base64"]),
            MemorySearch => MethodContract::contextual(vec![
                required("start", String),
                required("length", Unsigned),
                required("pattern", PATTERN_KIND),
                optional("max_results", Unsigned),
                optional("acknowledge_target_effects", Boolean),
                optional("volatile", Boolean),
            ]),
            MemoryCompare => MethodContract::contextual(vec![
                required("address", String),
                required("length", Unsigned),
                required("expected", EXPECTED_KIND),
                optional("acknowledge_target_effects", Boolean),
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
                optional("steps", IO_WRITE_STEPS_KIND),
                optional("timeout_ms", Positive),
            ])
            .exactly_one(&["text", "data_base64", "steps"]),
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
            SignalUpdate => MethodContract::plain(vec![required("signals", SIGNALS_KIND)]),
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
                optional("kernel_module_offset", KERNEL_MODULE_OFFSET_KIND),
                optional("condition", String),
                optional("ignore_count", Unsigned),
                optional("restart", Boolean),
                optional("input", INFERIOR_INPUT_KIND),
                optional("trigger", PROBE_TRIGGER_KIND),
                optional("capture", CAPTURE_KIND),
                optional("max_hits", Unsigned),
                optional(
                    "stop_policy",
                    Enum(&["on_condition", "continue_after_capture", "continue_to_stop"]),
                ),
                optional("inspect", TURN_INSPECTION_KIND),
                optional("budget", BUDGET_KIND),
            ])
            .exactly_one(&[
                "location",
                "function",
                "address",
                "expression",
                "source",
                "module_offset",
                "kernel_module_offset",
            ]),
            KernelInspect => MethodContract::contextual(vec![
                required(
                    "view",
                    Enum(&[
                        "bootstrap",
                        "capabilities",
                        "version",
                        "base",
                        "page_table",
                        "symbols",
                        "current_task",
                        "init_task",
                        "tasks",
                        "modules",
                        "dmesg",
                        "stack",
                        "panic",
                    ]),
                ),
                optional("limit", Unsigned),
                optional("offset", Unsigned),
                optional("address_expression", String),
                optional("names", StringArray),
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
                optional("arguments", RAW_MI_ARGUMENTS_KIND),
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
            Self::SessionCreate
                | Self::SessionList
                | Self::OperationGet
                | Self::OperationCancel
                | Self::ArtifactGet
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
            (
                CanonicalMethod::InspectionBatch,
                json!({"requests": ["stack"]}),
            ),
            (
                CanonicalMethod::InspectionBatch,
                json!({"requests": [{"name": "stack", "view": "stack", "extra": true}]}),
            ),
            (
                CanonicalMethod::ExecutionControl,
                json!({"action": "continue", "inspect": [{"view": "stack", "extra": true}]}),
            ),
            (
                CanonicalMethod::InferiorIoWrite,
                json!({"steps": [{"wait_for": "name: ", "text": "A", "data_base64": "QQ=="}]}),
            ),
            (
                CanonicalMethod::SignalUpdate,
                json!({"signals": {"SIGUSR1": {"stop": true, "print": true}}}),
            ),
            (
                CanonicalMethod::RawMi,
                json!({"command": "-list-features", "arguments": [{"kind": "quoted", "value": "x"}]}),
            ),
        ] {
            assert!(method.validate_parameters(&parameters).is_err());
        }

        CanonicalMethod::AgentProbe
            .validate_parameters(&json!({
                "location": {"source": {"path": "/tmp/a.c", "line": 7}},
                "capture": [
                    {"expression": "length"},
                    {"stack": {"limit": 4}},
                    {"memory": {"address_expression": "$sp", "length": 16}}
                ],
                "budget": {"max_calls": 8, "wall_time_ms": 1000}
            }))
            .unwrap();
        CanonicalMethod::AgentProbe
            .validate_parameters(&json!({
                "kernel_module_offset": {"module": "sample", "offset": "0x123"}
            }))
            .unwrap();
        CanonicalMethod::InspectionBatch
            .validate_parameters(&json!({
                "requests": [
                    {"view": "stack", "limit": 4},
                    {"view": "registers", "roles": ["pc", "sp"]}
                ]
            }))
            .unwrap();
        CanonicalMethod::ValueEvaluate
            .validate_parameters(&json!({"expressions": ["$pc", "$sp"]}))
            .unwrap();
        CanonicalMethod::ExecutionControl
            .validate_parameters(&json!({
                "action": "continue",
                "wait": {"until": "settled"},
                "input": {"data_base64": "QQ=="},
                "inspect": [{"view": "registers", "roles": ["pc", "sp"]}]
            }))
            .unwrap();
        CanonicalMethod::ExecutionWait
            .validate_parameters(&json!({
                "wait": {"until": "settled"},
                "inspect": [{"view": "stack", "limit": 4}]
            }))
            .unwrap();
        CanonicalMethod::InferiorIoWrite
            .validate_parameters(&json!({
                "steps": [
                    {"text": "1\n"},
                    {"wait_for": "index: ", "data_base64": "MAo="}
                ],
                "timeout_ms": 1000
            }))
            .unwrap();
        CanonicalMethod::SignalUpdate
            .validate_parameters(&json!({
                "signals": {"SIGUSR1": {"stop": true, "print": true, "pass": false}}
            }))
            .unwrap();
        CanonicalMethod::RawMi
            .validate_parameters(&json!({
                "command": "-symbol-info-functions",
                "arguments": ["--name", {"kind": "string", "value": "parse"}]
            }))
            .unwrap();
        assert_eq!(
            CanonicalMethod::TargetLaunch.parameter_schema()["properties"]["wait"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn enum_errors_list_allowed_values() {
        let stream = CanonicalMethod::InferiorIoRead
            .validate_parameters(&json!({"stream": "combined"}))
            .unwrap_err();
        assert!(stream.message.contains("pty, target, console, log"));

        let side_effects = CanonicalMethod::ValueEvaluate
            .validate_parameters(&json!({"expression": "$rax", "side_effects": "forbid"}))
            .unwrap_err();
        assert!(side_effects.message.contains("one of deny, allow"));
    }

    #[test]
    fn rejects_ambiguous_selector_and_binary_shapes() {
        for (method, parameters) in [
            (
                CanonicalMethod::BreakpointCreate,
                json!({"location": {"function": "main", "address": "0x1"}}),
            ),
            (
                CanonicalMethod::BreakpointCreate,
                json!({"location": {"function": "main"}, "address": "0x1"}),
            ),
            (
                CanonicalMethod::MemoryWrite,
                json!({
                    "address": "0x1000",
                    "text": "A",
                    "data_base64": "QQ==",
                    "expected": {"sha256": "0"}
                }),
            ),
            (
                CanonicalMethod::ValueEvaluate,
                json!({"expression": "$pc", "expressions": ["$sp"]}),
            ),
            (
                CanonicalMethod::MemoryCompare,
                json!({
                    "address": "0x1000",
                    "length": 1,
                    "expected": {"bytes_base64": "QQ==", "sha256": "0"}
                }),
            ),
            (
                CanonicalMethod::MemorySearch,
                json!({
                    "start": "0x1000",
                    "length": 16,
                    "pattern": {"hex": "41", "text": "A"}
                }),
            ),
            (
                CanonicalMethod::InferiorIoWrite,
                json!({"text": "A", "data_base64": "QQ=="}),
            ),
            (
                CanonicalMethod::InferiorIoWrite,
                json!({"text": "A", "steps": [{"text": "B"}]}),
            ),
            (
                CanonicalMethod::ExecutionControl,
                json!({
                    "action": "continue",
                    "input": {"text": "A", "data_base64": "QQ=="}
                }),
            ),
            (
                CanonicalMethod::BreakpointCreate,
                json!({"source": {"path": "/tmp/a.c", "line": 0}}),
            ),
        ] {
            assert!(
                method.validate_parameters(&parameters).is_err(),
                "accepted ambiguous {method}: {parameters}"
            );
        }

        CanonicalMethod::MemoryWrite
            .validate_parameters(&json!({
                "address": "0x1000",
                "data_base64": "QQ==",
                "expected": {"bytes_base64": "AA=="}
            }))
            .unwrap();
        assert!(CanonicalMethod::MemoryWrite.parameter_schema()["allOf"][0]["oneOf"].is_array());
    }
}

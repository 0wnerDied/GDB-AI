use std::collections::BTreeSet;

use gdb_ai_core::protocol::CanonicalMethod;
use serde_json::{Map, Value, json};

pub(crate) const DEFAULT_MCP_IO_READ_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy)]
struct ToolAction {
    name: &'static str,
    method: CanonicalMethod,
    advanced: bool,
}

struct ToolProjection {
    name: &'static str,
    description: &'static str,
    discriminator: Option<&'static str>,
    actions: &'static [ToolAction],
    read_only: bool,
    advanced: bool,
    raw: bool,
}

macro_rules! action {
    ($name:literal, $method:ident) => {
        ToolAction {
            name: $name,
            method: CanonicalMethod::$method,
            advanced: false,
        }
    };
}

macro_rules! advanced_action {
    ($name:literal, $method:ident) => {
        ToolAction {
            name: $name,
            method: CanonicalMethod::$method,
            advanced: true,
        }
    };
}

const SESSION_ACTIONS: &[ToolAction] = &[
    action!("create", SessionCreate),
    action!("launch", TargetLaunch),
    advanced_action!("attach", TargetAttach),
    advanced_action!("connect_remote", TargetConnectRemote),
    advanced_action!("open_core", TargetOpenCore),
    action!("detach", TargetDetach),
    action!("restart", TargetRestart),
    action!("kill", TargetKill),
    action!("status", SessionGet),
    action!("list", SessionList),
    action!("capabilities", SessionCapabilities),
    action!("providers", SessionProviders),
    action!("attempt_recovery", SessionAttemptRecovery),
    action!("operation_status", OperationGet),
    action!("operation_cancel", OperationCancel),
    action!("close", SessionClose),
    action!("force_abort", SessionForceAbort),
];
const RUN_ACTIONS: &[ToolAction] = &[
    action!("continue", ExecutionControl),
    action!("interrupt", ExecutionControl),
    action!("step", ExecutionControl),
    action!("next", ExecutionControl),
    action!("finish", ExecutionControl),
    action!("step_instruction", ExecutionControl),
    action!("next_instruction", ExecutionControl),
    action!("until", ExecutionControl),
    action!("wait", ExecutionWait),
    // 2026-09-01: Keeping the existing stop-and-capture operation behind the
    // advanced catalog forced Agents to recreate it with several core calls.
    action!("probe", AgentProbe),
];
const BREAKPOINT_ACTIONS: &[ToolAction] = &[
    action!("create", BreakpointCreate),
    action!("update", BreakpointUpdate),
    action!("enable", BreakpointUpdate),
    action!("disable", BreakpointUpdate),
    action!("delete", BreakpointDelete),
    action!("list", BreakpointList),
];
const INSPECTION_ACTIONS: &[ToolAction] = &[
    action!("stop_context", InspectionGet),
    action!("threads", InspectionGet),
    action!("stack", InspectionGet),
    action!("frame", InspectionGet),
    action!("locals", InspectionGet),
    action!("arguments", InspectionGet),
    action!("registers", InspectionGet),
    action!("modules", InspectionGet),
    action!("mappings", InspectionGet),
    action!("source", InspectionGet),
    action!("breakpoints", InspectionGet),
    action!("capabilities", InspectionGet),
    action!("target", InspectionGet),
    action!("signals", InspectionGet),
    action!("providers", InspectionGet),
    action!("crash", InspectionGet),
    action!("snapshot", InspectionSnapshot),
    advanced_action!("diff", InspectionDiff),
];
const EVALUATE_ACTIONS: &[ToolAction] = &[action!("", ValueEvaluate)];
const VALUE_ACTIONS: &[ToolAction] = &[
    action!("create", ValueCreate),
    action!("children", ValueChildren),
    action!("update", ValueUpdate),
    action!("release", ValueRelease),
];
const MEMORY_ACTIONS: &[ToolAction] = &[
    action!("read", MemoryRead),
    // 2026-09-01: Large reads returned an artifact URI that default MCP
    // tools could not resolve, forcing Agents to repeat the read in windows.
    action!("artifact", ArtifactGet),
    advanced_action!("write", MemoryWrite),
    advanced_action!("search", MemorySearch),
    advanced_action!("compare", MemoryCompare),
];
const REGISTER_ACTIONS: &[ToolAction] = &[
    action!("read", RegisterRead),
    action!("write", RegisterWrite),
];
const DISASSEMBLY_ACTIONS: &[ToolAction] = &[action!("", DisassemblyRead)];
const IO_ACTIONS: &[ToolAction] = &[
    action!("read", InferiorIoRead),
    action!("write", InferiorIoWrite),
    action!("send_eof", InferiorIoSendEof),
    action!("resize", InferiorIoResize),
];
const TRACKING_ACTIONS: &[ToolAction] = &[
    action!("add_expression", TrackingAddExpression),
    action!("add_memory", TrackingAddMemory),
    action!("remove", TrackingRemove),
    action!("list", TrackingList),
];
const SIGNAL_ACTIONS: &[ToolAction] = &[action!("get", SignalGet), action!("update", SignalUpdate)];
const BATCH_ACTIONS: &[ToolAction] = &[action!("", InspectionBatch)];
const PROBE_ACTIONS: &[ToolAction] = &[action!("", AgentProbe)];
const AGENT_ACTIONS: &[ToolAction] = &[action!("probe", AgentProbe)];
const EVENT_ACTIONS: &[ToolAction] = &[action!("", EventsWait)];
const KERNEL_ACTIONS: &[ToolAction] = &[
    action!("inspect", KernelInspect),
    action!("monitor", KernelMonitor),
];
const RAW_ACTIONS: &[ToolAction] = &[action!("mi", RawMi), action!("console", RawConsole)];

const TOOLS: &[ToolProjection] = &[
    ToolProjection {
        name: "gdb_session",
        // 2026-09-04: An Agent repeated the executable in argv because the
        // launch convention appeared only in initialization instructions.
        description: "Manage sessions and targets; launch program names the executable and argv contains only its arguments; use first_instruction for stripped executables.",
        discriminator: Some("action"),
        actions: SESSION_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_run",
        // 2026-09-01: Blind Agents rebuilt probe workflows or selected an
        // exit-only wait even though one default turn already handles both.
        description: "Run with exact input/output; omit wait for stop-or-exit. Probe skips hits and captures expressions, stack, or memory.",
        discriminator: Some("action"),
        actions: RUN_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_probe",
        // 2026-09-04: Repeated blind Agents overlooked the probe action nested
        // under gdb_run and rebuilt it from several debugger turns. Surface
        // the existing one-call workflow under the operation they search for.
        description: "Arm a temporary breakpoint on a stopped or running target, send exact input, skip hits, capture expressions, stack, memory, and output, then clean up in one call.",
        discriminator: None,
        actions: PROBE_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_breakpoints",
        // 2026-09-01: Agents mistook the executable mapping start for the PIE
        // base. State the load-bias invariant once instead of in every branch.
        description: "Breakpoints/watchpoints; module_offset = load bias + ELF vaddr.",
        discriminator: Some("action"),
        actions: BREAKPOINT_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_inspect",
        description: "Read one bounded view at a stop.",
        discriminator: Some("view"),
        actions: INSPECTION_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_evaluate",
        description: "Evaluate without calls or writes.",
        discriminator: None,
        actions: EVALUATE_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_values",
        description: "Create and page stop-scoped GDB variable objects.",
        discriminator: Some("action"),
        actions: VALUE_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_memory",
        description: "Read memory or page a returned artifact; advanced: write/search/compare.",
        discriminator: Some("action"),
        actions: MEMORY_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_registers",
        description: "Read semantic register roles or write one authorized register.",
        discriminator: Some("action"),
        actions: REGISTER_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_disassemble",
        description: "Read instructions around an address.",
        discriminator: None,
        actions: DISASSEMBLY_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_io",
        description: "Open-ended PTY I/O, EOF, or resize.",
        discriminator: Some("action"),
        actions: IO_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_tracking",
        description: "Manage bounded tracked expressions and memory ranges.",
        discriminator: Some("action"),
        actions: TRACKING_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_signals",
        description: "Read or update structured signal handling policy.",
        discriminator: Some("action"),
        actions: SIGNAL_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    // 2026-08-31: Initialization recommended same-stop batching while default
    // discovery hid it behind the much larger advanced catalog. Keep the
    // token-saving primitive available without exposing unrelated tools.
    ToolProjection {
        name: "gdb_batch",
        description: "Read bounded views at one stop.",
        discriminator: None,
        actions: BATCH_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_agent",
        description: "Run a bounded probe with explicit stop attribution.",
        discriminator: Some("action"),
        actions: AGENT_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_events",
        description: "Wait for a session event.",
        discriminator: None,
        actions: EVENT_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_kernel",
        description: "Inspect kernel targets or run allowlisted monitor commands.",
        discriminator: Some("action"),
        actions: KERNEL_ACTIONS,
        read_only: false,
        advanced: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_raw",
        description: "Run audited raw MI or console commands with reconciliation.",
        discriminator: Some("action"),
        actions: RAW_ACTIONS,
        read_only: false,
        advanced: false,
        raw: true,
    },
];

pub fn method_for_tool(
    tool_name: &str,
    action_name: Option<&str>,
    include_advanced: bool,
    include_raw: bool,
) -> Option<CanonicalMethod> {
    let tool =
        available_tools(include_advanced, include_raw).find(|tool| tool.name == tool_name)?;
    let action_name = action_name.unwrap_or_default();
    tool.actions
        .iter()
        .find(|action| action.name == action_name && (include_advanced || !action.advanced))
        .map(|action| action.method)
}

pub fn discriminator_for_tool(tool_name: &str) -> Option<&'static str> {
    TOOLS
        .iter()
        .find(|tool| tool.name == tool_name)
        .and_then(|tool| tool.discriminator)
}

pub fn tool_exists(tool_name: &str, include_advanced: bool, include_raw: bool) -> bool {
    available_tools(include_advanced, include_raw).any(|tool| tool.name == tool_name)
}

pub fn tools(include_advanced: bool, include_raw: bool) -> Vec<Value> {
    available_tools(include_advanced, include_raw)
        .map(|tool| {
            let mut projected = json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": projected_schema(tool, include_advanced, include_raw)
            });
            // 2026-09-01: Repeating false optional MCP hints on every tool
            // consumed discovery context and implied certainty where none was
            // needed. Preserve only positive scheduling and mutation signals.
            let mut annotations = Map::new();
            if tool.read_only || (!include_advanced && tool.name == "gdb_memory") {
                annotations.insert("readOnlyHint".into(), Value::Bool(true));
            }
            if tool.raw {
                annotations.insert("destructiveHint".into(), Value::Bool(true));
            }
            if !annotations.is_empty() {
                projected["annotations"] = Value::Object(annotations);
            }
            projected
        })
        .collect()
}

pub fn tool_names(include_advanced: bool, include_raw: bool) -> Vec<&'static str> {
    available_tools(include_advanced, include_raw)
        .map(|tool| tool.name)
        .collect()
}

fn available_tools(
    include_advanced: bool,
    include_raw: bool,
) -> impl Iterator<Item = &'static ToolProjection> {
    TOOLS
        .iter()
        .filter(move |tool| (include_advanced || !tool.advanced) && (include_raw || !tool.raw))
}

fn projected_schema(tool: &ToolProjection, include_advanced: bool, admin: bool) -> Value {
    // 2026-08-30: Expanding equivalent canonical parameter contracts once
    // per MCP action repeated schema. Group them before adding the action.
    let mut groups: Vec<(Value, Vec<&str>)> = Vec::new();
    for action in tool
        .actions
        .iter()
        .filter(|action| include_advanced || !action.advanced)
    {
        let schema = projected_method_schema(action.method, admin);
        if let Some((_, names)) = groups
            .iter_mut()
            .find(|(candidate, _)| *candidate == schema)
        {
            names.push(action.name);
        } else {
            groups.push((schema, vec![action.name]));
        }
    }
    let branches = groups
        .into_iter()
        .map(|(mut schema, action_names)| {
            if let Some(discriminator) = tool.discriminator {
                add_discriminator(&mut schema, discriminator, &action_names);
            }
            compact_schema_defaults(&mut schema);
            schema
        })
        .collect::<Vec<_>>();
    if branches.len() == 1 {
        branches.into_iter().next().unwrap()
    } else {
        json!({"oneOf": branches})
    }
}

// 2026-08-28: Handwritten MCP fields drifted from canonical validation.
// Project transport metadata around the same per-method parameter schema.
fn projected_method_schema(method: CanonicalMethod, admin: bool) -> Value {
    let mut schema = method.parameter_schema();
    let mut required = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let properties = schema["properties"].as_object_mut().unwrap();
    // 2026-08-31: Lease, revision, retry, and cancellation bookkeeping made
    // Agents parse and repeat transport state on every debugging turn. MCP
    // owns those fields; stop_id remains visible because it carries target
    // semantics and prevents inspection of the wrong stop.
    for field in [
        "accept_latest_revision",
        "lease_id",
        "expected_revision",
        "idempotency_key",
        "cancel_mode",
    ] {
        properties.remove(field);
    }
    // 2026-09-01: Ordinary MCP callers cannot select a non-default session
    // profile. Do not advertise an argument that can only produce a denial.
    if method == CanonicalMethod::SessionCreate && !admin {
        properties.remove("profile");
    }
    if matches!(
        method,
        CanonicalMethod::ExecutionControl
            | CanonicalMethod::ExecutionWait
            | CanonicalMethod::AgentProbe
    ) && let Some(input) = properties.get_mut("input").and_then(Value::as_object_mut)
    {
        // 2026-09-01: Repeating required-field branches for inline input
        // inflated each projected tool. A closed two-field object with
        // min/max one preserves the same exactly-one input contract.
        input.remove("oneOf");
        input.insert("minProperties".into(), Value::from(1));
        input.insert("maxProperties".into(), Value::from(1));
    }
    if method == CanonicalMethod::AgentProbe {
        // 2026-09-01: The projected probe exposed backend budget knobs with
        // useful defaults. Keep the shorter GDB selectors Agent-facing.
        for field in ["budget", "frame_id", "frame_level"] {
            properties.remove(field);
        }
    }
    if matches!(
        method,
        CanonicalMethod::AgentProbe | CanonicalMethod::BreakpointCreate
    ) {
        // 2026-09-01: Canonical compatibility accepts both top-level location
        // selectors and an equivalent wrapper. Project only the shorter form.
        properties.remove("location");
    }
    if matches!(
        method,
        CanonicalMethod::MemoryRead
            | CanonicalMethod::MemorySearch
            | CanonicalMethod::MemoryCompare
    ) {
        // 2026-09-01: Mutation profiles now acknowledge target-effect reads
        // by policy; other profiles cannot elevate them with a request flag.
        // Keep the legacy fields canonical without spending Agent tokens.
        properties.remove("acknowledge_target_effects");
        properties.remove("volatile");
    }
    // 2026-09-01: Requiring an Agent to fetch and echo the current stop split
    // one inspection into two calls. MCP binds an omitted stop_id internally;
    // an explicit stop_id remains available for cross-call attribution.
    properties.remove("accept_current_stop");
    if method.requires_session() {
        properties.insert("session_id".into(), json!({"type": "string"}));
        required.insert("session_id".into());
    }
    if method == CanonicalMethod::InferiorIoRead {
        schema["properties"]["max_bytes"]["default"] = Value::from(DEFAULT_MCP_IO_READ_BYTES);
    }
    if matches!(
        method,
        CanonicalMethod::TargetLaunch | CanonicalMethod::TargetRestart
    ) && let Some(values) = schema["properties"]["stop"]["enum"].as_array_mut()
    {
        // 2026-08-31: Advertising the legacy `entry` alias made an Agent
        // mistake the loader's first instruction for the target entry point.
        // Keep compatibility in the canonical API, but expose one precise
        // name for that policy in projected tools.
        values.retain(|value| value != "entry");
    }
    schema["required"] = Value::Array(required.into_iter().map(Value::String).collect());
    if matches!(
        method,
        CanonicalMethod::AgentProbe | CanonicalMethod::BreakpointCreate
    ) {
        schema["allOf"][0]["oneOf"]
            .as_array_mut()
            .unwrap()
            .retain(|branch| branch["required"][0] != "location");
    }
    schema
}

fn compact_schema_defaults(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            // 2026-09-01: Generated empty required arrays repeated a JSON
            // Schema default throughout tools/list without constraining input.
            if object
                .get("required")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
            {
                object.remove("required");
            }
            object.values_mut().for_each(compact_schema_defaults);
        }
        Value::Array(values) => values.iter_mut().for_each(compact_schema_defaults),
        _ => {}
    }
}

fn add_discriminator(schema: &mut Value, discriminator: &str, action_names: &[&str]) {
    let discriminator_schema = match action_names {
        [action] => json!({"const": action}),
        actions => json!({"type": "string", "enum": actions}),
    };
    schema["properties"]
        .as_object_mut()
        .unwrap()
        .insert(discriminator.into(), discriminator_schema);
    let required = schema["required"].as_array_mut().unwrap();
    required.push(Value::String(discriminator.into()));
    required.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    // 2026-08-31: Canonical schemas may already require their MCP
    // discriminator. Keep `required` unique so strict clients accept it.
    required.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_canonical_parameter_contracts() {
        let tools = tools(true, true);
        let memory = tools
            .iter()
            .find(|tool| tool["name"] == "gdb_memory")
            .unwrap();
        let read = memory["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == "read")
            .unwrap();
        assert_eq!(read["additionalProperties"], false);
        assert!(
            read["required"]
                .as_array()
                .unwrap()
                .contains(&Value::String("address".into()))
        );
        let artifact = memory["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == "artifact")
            .unwrap();
        assert!(
            artifact["required"]
                .as_array()
                .unwrap()
                .contains(&json!("uri"))
        );
        assert_eq!(
            method_for_tool("gdb_memory", Some("read"), false, false),
            Some(CanonicalMethod::MemoryRead)
        );
        assert_eq!(
            method_for_tool("gdb_memory", Some("artifact"), false, false),
            Some(CanonicalMethod::ArtifactGet)
        );
        assert_eq!(
            method_for_tool("gdb_run", Some("probe"), false, false),
            Some(CanonicalMethod::AgentProbe)
        );
        assert_eq!(
            method_for_tool("gdb_probe", None, false, false),
            Some(CanonicalMethod::AgentProbe)
        );
        assert_eq!(
            method_for_tool("gdb_io", Some("send_eof"), false, false),
            Some(CanonicalMethod::InferiorIoSendEof)
        );
        let io = tools.iter().find(|tool| tool["name"] == "gdb_io").unwrap();
        let read = io["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == "read")
            .unwrap();
        assert_eq!(
            read["properties"]["max_bytes"]["default"],
            DEFAULT_MCP_IO_READ_BYTES
        );
        let session = tools
            .iter()
            .find(|tool| tool["name"] == "gdb_session")
            .unwrap();
        for action in ["launch", "restart"] {
            let lifecycle = session["inputSchema"]["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .find(|branch| branch["properties"]["action"]["const"] == action)
                .unwrap();
            let policies = lifecycle["properties"]["stop"]["enum"].as_array().unwrap();
            assert!(policies.contains(&json!("first_instruction")));
            assert!(!policies.contains(&json!("entry")));
        }
        let create = session["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == "create")
            .unwrap();
        assert!(create["properties"].get("session_id").is_none());
    }

    #[test]
    fn defaults_to_the_bounded_agent_surface() {
        assert_eq!(
            tool_names(false, false),
            [
                "gdb_session",
                "gdb_run",
                "gdb_probe",
                "gdb_breakpoints",
                "gdb_inspect",
                "gdb_evaluate",
                "gdb_memory",
                "gdb_disassemble",
                "gdb_io",
                "gdb_batch",
                "gdb_events",
            ]
        );
        assert!(!tool_exists("gdb_values", false, false));
        assert!(tool_exists("gdb_values", true, false));
        assert!(tool_exists("gdb_batch", false, false));
        assert!(method_for_tool("gdb_memory", Some("write"), false, false).is_none());
        assert!(method_for_tool("gdb_memory", Some("write"), true, false).is_some());
        assert_eq!(
            tools(false, false)
                .into_iter()
                .find(|tool| tool["name"] == "gdb_memory")
                .unwrap()["annotations"]["readOnlyHint"],
            true
        );
        assert!(
            tools(false, false)
                .into_iter()
                .find(|tool| tool["name"] == "gdb_run")
                .unwrap()
                .get("annotations")
                .is_none()
        );
        assert_eq!(
            tools(true, true)
                .into_iter()
                .find(|tool| tool["name"] == "gdb_raw")
                .unwrap()["annotations"]["destructiveHint"],
            true
        );
        assert!(method_for_tool("gdb_io", Some("close_stdin"), true, false).is_none());
        assert!(method_for_tool("gdb_agent", Some("experiment"), true, false).is_none());
        assert!(method_for_tool("gdb_session", Some("acquire_write_lease"), true, false).is_none());
    }

    #[test]
    fn projects_current_stop_as_an_optional_pin() {
        assert!(
            projected_method_schema(CanonicalMethod::SessionCreate, false)["properties"]
                .get("profile")
                .is_none()
        );
        assert!(
            projected_method_schema(CanonicalMethod::SessionCreate, true)["properties"]
                .get("profile")
                .is_some()
        );

        for method in [
            CanonicalMethod::InspectionBatch,
            CanonicalMethod::ValueEvaluate,
            CanonicalMethod::MemoryRead,
            CanonicalMethod::DisassemblyRead,
        ] {
            let schema = projected_method_schema(method, false);
            assert!(schema["properties"].get("stop_id").is_some());
            assert!(
                !schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("stop_id"))
            );
            assert!(schema["properties"].get("accept_current_stop").is_none());
        }
        let inspection = projected_method_schema(CanonicalMethod::InspectionGet, false);
        assert!(inspection.get("allOf").is_none());
        assert!(inspection["properties"].get("stop_id").is_some());
        assert!(
            !inspection["required"]
                .as_array()
                .unwrap()
                .contains(&json!("stop_id"))
        );
        let canonical = CanonicalMethod::MemoryRead.parameter_schema();
        assert!(canonical["properties"].get("accept_current_stop").is_some());
        let projected = projected_method_schema(CanonicalMethod::MemoryRead, false);
        assert!(
            projected["properties"]
                .get("acknowledge_target_effects")
                .is_none()
        );
        assert!(projected["properties"].get("volatile").is_none());
        let breakpoint = projected_method_schema(CanonicalMethod::BreakpointCreate, false);
        assert!(breakpoint["properties"].get("location").is_none());
        assert!(
            breakpoint["allOf"][0]["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .all(|branch| branch["required"][0] != "location")
        );
    }

    #[test]
    fn groups_actions_that_share_a_parameter_contract() {
        let tools = tools(false, false);
        let run = tools.iter().find(|tool| tool["name"] == "gdb_run").unwrap();
        let control = run["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"].get("enum").is_some())
            .unwrap();
        assert_eq!(
            control["properties"]["action"]["enum"]
                .as_array()
                .unwrap()
                .len(),
            8
        );
        assert_eq!(
            control["required"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|field| field.as_str() == Some("action"))
                .count(),
            1
        );
        assert!(control["properties"]["inspect"].is_object());
        let probe = run["inputSchema"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == "probe")
            .unwrap();
        assert!(probe["properties"]["input"].is_object());
        assert_eq!(probe["properties"]["input"]["minProperties"], 1);
        assert_eq!(probe["properties"]["input"]["maxProperties"], 1);
        assert!(probe["properties"]["input"].get("oneOf").is_none());
        assert!(probe["properties"]["ignore_count"].is_object());
        assert!(
            probe["properties"]["capture"]["items"]["oneOf"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["properties"].get("memory").is_some())
        );
    }

    #[test]
    fn omits_transport_coordination_from_agent_tools() {
        let tools = tools(false, false);
        let encoded = serde_json::to_string(&tools).unwrap();
        assert!(!encoded.contains("\"required\":[]"));
        for field in [
            "accept_latest_revision",
            "lease_id",
            "expected_revision",
            "idempotency_key",
            "cancel_mode",
            "accept_current_stop",
        ] {
            assert!(!encoded.contains(&format!("\"{field}\"")));
        }
        assert!(encoded.contains("\"stop_id\""));
    }
}

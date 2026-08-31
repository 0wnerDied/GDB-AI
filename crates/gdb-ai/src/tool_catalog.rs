use std::collections::BTreeSet;

use gdb_ai_core::protocol::CanonicalMethod;
use serde_json::{Value, json};

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
        description: "Create, launch, inspect, or close a local GDB session.",
        discriminator: Some("action"),
        actions: SESSION_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_run",
        description: "Continue, interrupt, step, or wait for explicit target state.",
        discriminator: Some("action"),
        actions: RUN_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_breakpoints",
        description: "Create and manage bounded, structured breakpoints and watchpoints.",
        discriminator: Some("action"),
        actions: BREAKPOINT_ACTIONS,
        read_only: false,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_inspect",
        description: "Read one bounded debugger view with explicit stop context.",
        discriminator: Some("view"),
        actions: INSPECTION_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_evaluate",
        description: "Evaluate an expression while inferior calls and writes are disabled.",
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
        description: "Read, compare, search, or conditionally write bounded memory.",
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
        description: "Read bounded disassembly around an expression or address range.",
        discriminator: None,
        actions: DISASSEMBLY_ACTIONS,
        read_only: true,
        advanced: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_io",
        description: "Read or write the inferior PTY; send_eof requires a stopped target.",
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
    ToolProjection {
        name: "gdb_batch",
        description: "Run bounded inspection requests against one stop context.",
        discriminator: None,
        actions: BATCH_ACTIONS,
        read_only: true,
        advanced: true,
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
        description: "Wait for the next bounded session event.",
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
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": projected_schema(tool, include_advanced),
                "annotations": {
                    "readOnlyHint": tool.read_only
                        || (!include_advanced && tool.name == "gdb_memory"),
                    "destructiveHint": tool.raw,
                    "openWorldHint": false
                }
            })
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

fn projected_schema(tool: &ToolProjection, include_advanced: bool) -> Value {
    // 2026-08-30: Expanding equivalent canonical parameter contracts once
    // per MCP action repeated schema. Group them before adding the action.
    let mut groups: Vec<(Value, Vec<&str>)> = Vec::new();
    for action in tool
        .actions
        .iter()
        .filter(|action| include_advanced || !action.advanced)
    {
        let schema = projected_method_schema(action.method);
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
fn projected_method_schema(method: CanonicalMethod) -> Value {
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
    schema
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
        assert_eq!(
            method_for_tool("gdb_memory", Some("read"), false, false),
            Some(CanonicalMethod::MemoryRead)
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
                "gdb_breakpoints",
                "gdb_inspect",
                "gdb_evaluate",
                "gdb_memory",
                "gdb_disassemble",
                "gdb_io",
                "gdb_events",
            ]
        );
        assert!(!tool_exists("gdb_values", false, false));
        assert!(tool_exists("gdb_values", true, false));
        assert!(method_for_tool("gdb_memory", Some("write"), false, false).is_none());
        assert!(method_for_tool("gdb_memory", Some("write"), true, false).is_some());
        assert_eq!(
            tools(false, false)
                .into_iter()
                .find(|tool| tool["name"] == "gdb_memory")
                .unwrap()["annotations"]["readOnlyHint"],
            true
        );
        assert!(method_for_tool("gdb_io", Some("close_stdin"), true, false).is_none());
        assert!(method_for_tool("gdb_agent", Some("experiment"), true, false).is_none());
        assert!(method_for_tool("gdb_session", Some("acquire_write_lease"), true, false).is_none());
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
        assert!(serde_json::to_vec(&tools).unwrap().len() < 14_000);
        assert!(
            serde_json::to_vec(&super::tools(true, false))
                .unwrap()
                .len()
                < 29_000
        );
    }

    #[test]
    fn omits_transport_coordination_from_agent_tools() {
        let tools = tools(false, false);
        let encoded = serde_json::to_string(&tools).unwrap();
        for field in [
            "accept_latest_revision",
            "lease_id",
            "expected_revision",
            "idempotency_key",
            "cancel_mode",
        ] {
            assert!(!encoded.contains(&format!("\"{field}\"")));
        }
        assert!(encoded.contains("\"stop_id\""));
    }
}

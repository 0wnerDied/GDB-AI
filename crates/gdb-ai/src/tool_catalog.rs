use std::collections::BTreeSet;

use gdb_ai_core::protocol::CanonicalMethod;
use serde_json::{Value, json};

#[derive(Clone, Copy)]
struct ToolAction {
    name: &'static str,
    method: CanonicalMethod,
}

struct ToolProjection {
    name: &'static str,
    description: &'static str,
    discriminator: Option<&'static str>,
    actions: &'static [ToolAction],
    read_only: bool,
    raw: bool,
}

macro_rules! action {
    ($name:literal, $method:ident) => {
        ToolAction {
            name: $name,
            method: CanonicalMethod::$method,
        }
    };
}

const SESSION_ACTIONS: &[ToolAction] = &[
    action!("create", SessionCreate),
    action!("launch", TargetLaunch),
    action!("attach", TargetAttach),
    action!("connect_remote", TargetConnectRemote),
    action!("open_core", TargetOpenCore),
    action!("detach", TargetDetach),
    action!("restart", TargetRestart),
    action!("kill", TargetKill),
    action!("status", SessionGet),
    action!("list", SessionList),
    action!("capabilities", SessionCapabilities),
    action!("providers", SessionProviders),
    action!("acquire_write_lease", SessionAcquireWriteLease),
    action!("release_write_lease", SessionReleaseWriteLease),
    action!("attempt_recovery", SessionAttemptRecovery),
    action!("close", SessionClose),
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
    action!("diff", InspectionDiff),
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
    action!("write", MemoryWrite),
    action!("search", MemorySearch),
    action!("compare", MemoryCompare),
];
const REGISTER_ACTIONS: &[ToolAction] = &[
    action!("read", RegisterRead),
    action!("write", RegisterWrite),
];
const DISASSEMBLY_ACTIONS: &[ToolAction] = &[action!("", DisassemblyRead)];
const IO_ACTIONS: &[ToolAction] = &[
    action!("read", InferiorIoRead),
    action!("write", InferiorIoWrite),
    action!("close_stdin", InferiorIoCloseStdin),
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
const AGENT_ACTIONS: &[ToolAction] = &[
    action!("probe", AgentProbe),
    action!("experiment", AgentExperiment),
    action!("hypothesis_check", AgentHypothesisCheck),
];
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
        raw: false,
    },
    ToolProjection {
        name: "gdb_run",
        description: "Continue, interrupt, step, or wait for explicit target state.",
        discriminator: Some("action"),
        actions: RUN_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_breakpoints",
        description: "Create and manage bounded, structured breakpoints and watchpoints.",
        discriminator: Some("action"),
        actions: BREAKPOINT_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_inspect",
        description: "Read one bounded debugger view with explicit stop context.",
        discriminator: Some("view"),
        actions: INSPECTION_ACTIONS,
        read_only: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_evaluate",
        description: "Evaluate an expression while inferior calls and writes are disabled.",
        discriminator: None,
        actions: EVALUATE_ACTIONS,
        read_only: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_values",
        description: "Create and page stop-scoped GDB variable objects.",
        discriminator: Some("action"),
        actions: VALUE_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_memory",
        description: "Read, compare, search, or conditionally write bounded memory.",
        discriminator: Some("action"),
        actions: MEMORY_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_registers",
        description: "Read semantic register roles or write one authorized register.",
        discriminator: Some("action"),
        actions: REGISTER_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_disassemble",
        description: "Read bounded disassembly around an expression or address range.",
        discriminator: None,
        actions: DISASSEMBLY_ACTIONS,
        read_only: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_io",
        description: "Read or write the inferior PTY independently from GDB control output.",
        discriminator: Some("action"),
        actions: IO_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_tracking",
        description: "Manage bounded tracked expressions and memory ranges.",
        discriminator: Some("action"),
        actions: TRACKING_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_signals",
        description: "Read or update structured signal handling policy.",
        discriminator: Some("action"),
        actions: SIGNAL_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_batch",
        description: "Run bounded inspection requests against one stop context.",
        discriminator: None,
        actions: BATCH_ACTIONS,
        read_only: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_agent",
        description: "Run a bounded probe, experiment, or runtime hypothesis check.",
        discriminator: Some("action"),
        actions: AGENT_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_events",
        description: "Wait for the next bounded session event.",
        discriminator: None,
        actions: EVENT_ACTIONS,
        read_only: true,
        raw: false,
    },
    ToolProjection {
        name: "gdb_kernel",
        description: "Inspect kernel targets or run allowlisted monitor commands.",
        discriminator: Some("action"),
        actions: KERNEL_ACTIONS,
        read_only: false,
        raw: false,
    },
    ToolProjection {
        name: "gdb_raw",
        description: "Run audited raw MI or console commands with reconciliation.",
        discriminator: Some("action"),
        actions: RAW_ACTIONS,
        read_only: false,
        raw: true,
    },
];

pub fn method_for_tool(tool_name: &str, action_name: Option<&str>) -> Option<CanonicalMethod> {
    let tool = TOOLS.iter().find(|tool| tool.name == tool_name)?;
    let action_name = action_name.unwrap_or_default();
    tool.actions
        .iter()
        .find(|action| action.name == action_name)
        .map(|action| action.method)
}

pub fn discriminator_for_tool(tool_name: &str) -> Option<&'static str> {
    TOOLS
        .iter()
        .find(|tool| tool.name == tool_name)
        .and_then(|tool| tool.discriminator)
}

pub fn tool_exists(tool_name: &str) -> bool {
    TOOLS.iter().any(|tool| tool.name == tool_name)
}

pub fn tools(include_raw: bool) -> Vec<Value> {
    TOOLS
        .iter()
        .filter(|tool| include_raw || !tool.raw)
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": projected_schema(tool),
                "annotations": {
                    "readOnlyHint": tool.read_only,
                    "destructiveHint": tool.raw,
                    "openWorldHint": false
                }
            })
        })
        .collect()
}

pub fn tool_names(include_raw: bool) -> Vec<&'static str> {
    TOOLS
        .iter()
        .filter(|tool| include_raw || !tool.raw)
        .map(|tool| tool.name)
        .collect()
}

fn projected_schema(tool: &ToolProjection) -> Value {
    let branches = tool
        .actions
        .iter()
        .map(|action| projected_method_schema(tool.discriminator, *action))
        .collect::<Vec<_>>();
    if branches.len() == 1 {
        branches.into_iter().next().unwrap()
    } else {
        json!({"oneOf": branches})
    }
}

// 2026-08-28: Handwritten MCP fields drifted from canonical validation.
// Project transport metadata around the same per-method parameter schema.
fn projected_method_schema(discriminator: Option<&str>, action: ToolAction) -> Value {
    let mut schema = action.method.parameter_schema();
    let mut required = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let properties = schema["properties"].as_object_mut().unwrap();
    properties.insert("session_id".into(), json!({"type": "string"}));
    properties.insert(
        "expected_revision".into(),
        json!({"type": "integer", "minimum": 0}),
    );
    properties.insert(
        "idempotency_key".into(),
        json!({"type": "string", "maxLength": 256}),
    );
    properties.insert(
        "cancel_mode".into(),
        json!({
            "type": "string",
            "enum": ["detach_waiter", "interrupt_target", "close_session"]
        }),
    );
    if action.method.requires_session() {
        required.insert("session_id".into());
    }
    if let Some(discriminator) = discriminator {
        properties.insert(discriminator.into(), json!({"const": action.name}));
        required.insert(discriminator.into());
    }
    schema["required"] = Value::Array(required.into_iter().map(Value::String).collect());
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_canonical_parameter_contracts() {
        let tools = tools(true);
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
            method_for_tool("gdb_memory", Some("read")),
            Some(CanonicalMethod::MemoryRead)
        );
    }
}

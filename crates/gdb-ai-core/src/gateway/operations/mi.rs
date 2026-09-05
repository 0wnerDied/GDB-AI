use std::collections::BTreeMap;

use gdb_ai_mi::{MiRecord, MiResult, MiValue};
use serde_json::{Value, json};

use super::encoding::parse_address;
use crate::{
    Error, ErrorCode, Result,
    domain::{FrameId, FrameSummary},
};

pub(super) fn result_text(record: &MiRecord, name: &str) -> Option<String> {
    MiResult::find_str(record.results(), name).map(str::to_owned)
}

pub(super) fn frame_summary(record: &MiRecord) -> Option<FrameSummary> {
    let fields = MiResult::find(record.results(), "frame")?.results()?;
    Some(frame_summary_fields(fields))
}

pub(super) fn frame_summary_fields(fields: &[MiResult]) -> FrameSummary {
    FrameSummary {
        level: MiResult::find_str(fields, "level")
            .and_then(|level| level.parse().ok())
            .unwrap_or(0),
        address: MiResult::find_str(fields, "addr").map(str::to_owned),
        function: MiResult::find_str(fields, "func").map(str::to_owned),
        source: MiResult::find_str(fields, "fullname")
            .or_else(|| MiResult::find_str(fields, "file"))
            .map(str::to_owned),
        line: MiResult::find_str(fields, "line").and_then(|line| line.parse().ok()),
    }
}

pub(super) fn normalized_threads(
    record: &MiRecord,
    state: &crate::domain::SessionState,
) -> Vec<Value> {
    let Some(threads) = MiResult::find(record.results(), "threads") else {
        return Vec::new();
    };
    aggregate_items(threads, "thread")
        .into_iter()
        .filter_map(|fields| {
            let backend_id = MiResult::find_str(fields, "id")?;
            let thread = state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| thread.backend_id == backend_id);
            Some(json!({
                "thread_id": thread.map(|thread| &thread.id),
                "backend_id": backend_id,
                "inferior_id": state.inferiors.values()
                    .find(|inferior| inferior.threads.contains_key(backend_id))
                    .map(|inferior| &inferior.id),
                "state": MiResult::find_str(fields, "state"),
                "name": MiResult::find_str(fields, "name"),
                "frame": MiResult::find(fields, "frame")
                    .and_then(MiValue::results)
                    .map(frame_summary_fields)
            }))
        })
        .collect()
}

pub(super) fn normalized_frames(
    record: &MiRecord,
    state: &crate::domain::SessionState,
    parameters: &Value,
) -> Vec<Value> {
    let Some(stack) = MiResult::find(record.results(), "stack") else {
        return Vec::new();
    };
    // 2026-08-28: Assigning frames to the first non-running thread could
    // mint handles for a different thread than the explicit MI stop focus.
    let thread = parameters
        .get("thread_id")
        .and_then(Value::as_str)
        .and_then(|thread_id| {
            state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| thread.id.0 == thread_id)
        })
        .or_else(|| {
            let stopped = state.stopped_thread_id.as_ref()?;
            state
                .inferiors
                .values()
                .flat_map(|inferior| inferior.threads.values())
                .find(|thread| &thread.id == stopped)
        });
    aggregate_items(stack, "frame")
        .into_iter()
        .map(|fields| {
            let frame = frame_summary_fields(fields);
            let frame_id = thread.and_then(|thread| {
                state
                    .stop_id
                    .as_ref()
                    .map(|stop| FrameId::new(&thread.id, stop, frame.level))
            });
            json!({
                "frame_id": frame_id,
                "level": frame.level,
                "address": frame.address,
                "function": frame.function,
                "source": frame.source.map(|path| json!({"path": path, "line": frame.line}))
            })
        })
        .collect()
}

pub(super) fn normalized_variables(record: &MiRecord, name: &str) -> Vec<Value> {
    let Some(variables) = MiResult::find(record.results(), name) else {
        return Vec::new();
    };
    aggregate_items(variables, "variable")
        .into_iter()
        .map(|fields| {
            json!({
                "name": MiResult::find_str(fields, "name"),
                "type": MiResult::find_str(fields, "type"),
                "value": MiResult::find_str(fields, "value")
                    .map(|value| value.chars().take(16 * 1024).collect::<String>()),
                "dynamic": MiResult::find_str(fields, "dynamic") == Some("1")
            })
        })
        .collect()
}

pub(super) fn normalized_arguments(record: &MiRecord) -> Vec<Value> {
    let Some(frames) = MiResult::find(record.results(), "stack-args") else {
        return Vec::new();
    };
    aggregate_items(frames, "frame")
        .into_iter()
        .map(|fields| {
            let arguments = MiResult::find(fields, "args")
                .map(|args| {
                    aggregate_items(args, "arg")
                        .into_iter()
                        .map(|fields| {
                            json!({
                                "name": MiResult::find_str(fields, "name"),
                                "type": MiResult::find_str(fields, "type"),
                                "value": MiResult::find_str(fields, "value")
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({
                "level": MiResult::find_str(fields, "level")
                    .and_then(|level| level.parse::<u64>().ok()),
                "arguments": arguments
            })
        })
        .collect()
}

pub(super) fn normalized_modules(record: &MiRecord) -> Vec<Value> {
    let Some(modules) = MiResult::find(record.results(), "shared-libraries") else {
        return Vec::new();
    };
    aggregate_items(modules, "library")
        .into_iter()
        .map(|fields| {
            json!({
                "module_id": MiResult::find_str(fields, "id")
                    .or_else(|| MiResult::find_str(fields, "target-name")),
                "target_name": MiResult::find_str(fields, "target-name"),
                "host_name": MiResult::find_str(fields, "host-name"),
                "from": MiResult::find_str(fields, "from"),
                "to": MiResult::find_str(fields, "to"),
                "symbols_loaded": MiResult::find_str(fields, "symbols-loaded")
                    .map(|loaded| loaded == "1")
            })
        })
        .collect()
}

pub(super) fn normalized_source_files(record: &MiRecord) -> Vec<Value> {
    let Some(files) = MiResult::find(record.results(), "files") else {
        return Vec::new();
    };
    aggregate_items(files, "file")
        .into_iter()
        .map(|fields| {
            json!({
                "file": MiResult::find_str(fields, "file"),
                "fullname": MiResult::find_str(fields, "fullname"),
                "debug_fully_read": MiResult::find_str(fields, "debug-fully-read")
                    .map(|read| read == "true")
            })
        })
        .collect()
}

pub(super) fn normalized_symbols(record: &MiRecord) -> Vec<Value> {
    let Some(groups) = MiResult::find(record.results(), "symbols").and_then(MiValue::results)
    else {
        return Vec::new();
    };
    let mut output = Vec::new();
    if let Some(debug) = MiResult::find(groups, "debug") {
        for file in aggregate_items(debug, "file") {
            let path = MiResult::find_str(file, "fullname")
                .or_else(|| MiResult::find_str(file, "filename"));
            if let Some(symbols) = MiResult::find(file, "symbols") {
                output.extend(
                    aggregate_items(symbols, "symbol")
                        .into_iter()
                        .filter_map(|symbol| normalized_symbol(symbol, path)),
                );
            }
        }
    }
    if let Some(nondebug) = MiResult::find(groups, "nondebug") {
        output.extend(
            aggregate_items(nondebug, "symbol")
                .into_iter()
                .filter_map(|symbol| normalized_symbol(symbol, None)),
        );
    }
    output
}

fn normalized_symbol(fields: &[MiResult], path: Option<&str>) -> Option<Value> {
    let name = MiResult::find_str(fields, "name")?;
    let mut symbol = json!({
        "name": name,
        "type": MiResult::find_str(fields, "type"),
        "address": MiResult::find_str(fields, "address"),
        "source": path.map(|path| json!({
            "path": path,
            "line": MiResult::find_str(fields, "line")
                .and_then(|line| line.parse::<u64>().ok())
        }))
    });
    symbol
        .as_object_mut()
        .unwrap()
        .retain(|_, value| !value.is_null());
    if let Some(source) = symbol.get_mut("source").and_then(Value::as_object_mut) {
        source.retain(|_, value| !value.is_null());
    }
    Some(symbol)
}

pub(super) fn disassembly_instructions(
    record: &MiRecord,
    current: Option<u64>,
    around: Option<(usize, usize)>,
) -> Vec<Value> {
    let mut instructions = Vec::new();
    for result in record.results() {
        collect_instructions(&result.value, None, None, current, &mut instructions);
    }
    let Some((current, (before, after))) = current.zip(around) else {
        return instructions;
    };
    limit_disassembly_instructions(instructions, current, before, after)
}

fn limit_disassembly_instructions(
    instructions: Vec<Value>,
    current: u64,
    before: usize,
    after: usize,
) -> Vec<Value> {
    // 2026-08-30: The byte window deliberately over-reads for variable-width
    // targets, but returning every decoded instruction inflated Agent context.
    let pivot = instructions
        .iter()
        .position(|instruction| instruction["current"] == true)
        .or_else(|| {
            instructions.iter().position(|instruction| {
                instruction["address"]
                    .as_str()
                    .and_then(|address| parse_address(address).ok())
                    .is_some_and(|address| address >= current)
            })
        })
        .unwrap_or_else(|| instructions.len().saturating_sub(1));
    let start = pivot.saturating_sub(before);
    let end = pivot
        .saturating_add(after)
        .saturating_add(1)
        .min(instructions.len());
    instructions
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect()
}

pub(super) fn collect_instructions(
    value: &MiValue,
    inherited_file: Option<&str>,
    inherited_line: Option<u64>,
    current: Option<u64>,
    output: &mut Vec<Value>,
) {
    match value {
        MiValue::Tuple(results) | MiValue::ResultList(results) => {
            let file = MiResult::find_str(results, "fullname")
                .or_else(|| MiResult::find_str(results, "file"))
                .or(inherited_file);
            let line = MiResult::find_str(results, "line")
                .and_then(|line| line.parse().ok())
                .or(inherited_line);
            if let (Some(address), Some(instruction)) = (
                MiResult::find_str(results, "address"),
                MiResult::find_str(results, "inst"),
            ) {
                let address_number = parse_address(address).ok();
                let (mnemonic, operands) = instruction
                    .split_once(char::is_whitespace)
                    .map_or((instruction, ""), |(mnemonic, operands)| {
                        (mnemonic, operands.trim())
                    });
                output.push(json!({
                    "address": address,
                    "offset": MiResult::find_str(results, "offset")
                        .and_then(|offset| offset.parse::<i64>().ok()),
                    "bytes": MiResult::find_str(results, "opcodes"),
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "function": MiResult::find_str(results, "func-name"),
                    "source": file.map(|file| json!({"path": file, "line": line})),
                    "current": address_number.is_some() && address_number == current
                }));
            }
            for result in results {
                collect_instructions(&result.value, file, line, current, output);
            }
        }
        MiValue::ValueList(values) => {
            for value in values {
                collect_instructions(value, inherited_file, inherited_line, current, output);
            }
        }
        MiValue::Const(_) => {}
    }
}

pub(super) fn result_string_list(record: &MiRecord, name: &str) -> Vec<String> {
    let Some(MiValue::ValueList(values)) = MiResult::find(record.results(), name) else {
        return Vec::new();
    };
    values
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .collect()
}

pub(super) fn aggregate_items<'a>(value: &'a MiValue, result_name: &str) -> Vec<&'a [MiResult]> {
    match value {
        MiValue::ValueList(values) => values.iter().filter_map(|value| value.results()).collect(),
        MiValue::ResultList(results) => results
            .iter()
            .filter(|result| result.name == result_name)
            .filter_map(|result| result.value.results())
            .collect(),
        MiValue::Tuple(results) => vec![results],
        MiValue::Const(_) => Vec::new(),
    }
}

pub(super) fn register_values(record: &MiRecord) -> BTreeMap<usize, Value> {
    let Some(values) = MiResult::find(record.results(), "register-values") else {
        return BTreeMap::new();
    };
    aggregate_items(values, "register-values")
        .into_iter()
        .filter_map(|fields| {
            let number = MiResult::find_str(fields, "number")?.parse().ok()?;
            let value = MiResult::find_str(fields, "value")?;
            Some((number, Value::String(value.to_owned())))
        })
        .collect()
}

pub(super) fn register_role_candidates(role: &str) -> Option<&'static [&'static str]> {
    Some(match role {
        "pc" => &["rip", "pc"],
        "sp" => &["rsp", "sp"],
        "fp" => &["rbp", "x29", "fp"],
        "return" => &["rax", "x0"],
        "flags" => &["eflags", "cpsr"],
        "syscall_number" => &["orig_rax", "x8"],
        "syscall_return" => &["rax", "x0"],
        "tls" => &["fs_base", "tpidr_el0"],
        "argument_0" => &["rdi", "x0"],
        "argument_1" => &["rsi", "x1"],
        "argument_2" => &["rdx", "x2"],
        "argument_3" => &["rcx", "x3"],
        "argument_4" => &["r8", "x4"],
        "argument_5" => &["r9", "x5"],
        "argument_6" => &["x6"],
        "argument_7" => &["x7"],
        _ => return None,
    })
}

pub(super) fn target_architecture(register_names: &[String]) -> &'static str {
    // 2026-08-29: `-gdb-show architecture` reports the configured selector
    // `auto`, not the architecture selected from a live remote target.
    if find_register_name(register_names, "rip").is_some() {
        "i386:x86-64"
    } else if find_register_name(register_names, "x29").is_some() {
        "aarch64"
    } else {
        "unknown"
    }
}

pub(super) fn resolve_register_name(requested: &str, names: &[String]) -> Result<String> {
    if let Some(name) = find_register_name(names, requested) {
        return Ok(name.to_owned());
    }
    let candidates = register_role_candidates(requested).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("unknown register or role {requested}"),
        )
    })?;
    candidates
        .iter()
        .find_map(|candidate| find_register_name(names, candidate))
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                format!("target has no register for role {requested}"),
            )
        })
}

pub(super) fn find_register_name<'a>(names: &'a [String], requested: &str) -> Option<&'a str> {
    // 2026-08-29: QEMU preserves uppercase AArch64 system-register names in
    // its target description; a lowercase exact lookup made `$sp_el0` void.
    names
        .iter()
        .find(|name| name.eq_ignore_ascii_case(requested))
        .map(String::as_str)
}

pub(super) fn valid_integer_literal(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if let Some(hex) = unsigned.strip_prefix("0x") {
        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    } else {
        !unsigned.is_empty() && unsigned.bytes().all(|byte| byte.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_overread_disassembly_around_the_current_instruction() {
        let instructions = (0..10)
            .map(|index| {
                json!({
                    "address": format!("0x{index:x}"),
                    "current": index == 5
                })
            })
            .collect::<Vec<_>>();
        let bounded = limit_disassembly_instructions(instructions, 5, 2, 3);
        assert_eq!(bounded.len(), 6);
        assert_eq!(bounded[0]["address"], "0x3");
        assert_eq!(bounded[5]["address"], "0x8");
    }
}

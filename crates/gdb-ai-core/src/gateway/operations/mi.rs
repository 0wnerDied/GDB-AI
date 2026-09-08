use std::collections::BTreeMap;

use gdb_ai_mi::{MiRecord, MiResult, MiValue};
use serde_json::{Value, json};

use super::{
    context::observation_context,
    encoding::parse_address,
    values::{result_bool, result_value, value_status},
};
use crate::{
    Error, ErrorCode, Result,
    domain::{FrameId, FrameSummary},
    normalize::frame_summary_fields,
};

pub(super) fn result_text(record: &MiRecord, name: &str) -> Option<String> {
    MiResult::find_str(record.results(), name).map(str::to_owned)
}

pub(super) fn frame_summary(record: &MiRecord) -> Option<FrameSummary> {
    let fields = MiResult::find(record.results(), "frame")?.results()?;
    Some(frame_summary_fields(fields))
}

pub(super) fn normalized_threads(
    record: &MiRecord,
    state: &crate::domain::SessionState,
    offset: u64,
    limit: usize,
) -> (Vec<Value>, usize) {
    let Some(threads) = MiResult::find(record.results(), "threads") else {
        return (Vec::new(), 0);
    };
    // 2026-09-09: Thread pages built JSON and scanned registries for every
    // omitted thread. Page valid MI entries before resolving their keyed IDs.
    let mut threads = aggregate_items(threads, "thread");
    threads.retain(|fields| MiResult::find_str(fields, "id").is_some());
    let total = threads.len();
    let threads = threads
        .into_iter()
        .skip(offset.min(total as u64) as usize)
        .take(limit)
        .map(|fields| {
            let backend_id = MiResult::find_str(fields, "id").unwrap();
            let selected = state.inferiors.values().find_map(|inferior| {
                inferior
                    .threads
                    .get(backend_id)
                    .map(|thread| (inferior, thread))
            });
            json!({
                "thread_id": selected.map(|(_, thread)| &thread.id),
                "backend_id": backend_id,
                // 2026-09-05: Dropping GDB's target identity hid the OS TID
                // needed to match a blocked thread to a native lock owner.
                "target_id": MiResult::find_str(fields, "target-id"),
                "inferior_id": selected.map(|(inferior, _)| &inferior.id),
                "state": MiResult::find_str(fields, "state"),
                "name": MiResult::find_str(fields, "name"),
                "frame": MiResult::find(fields, "frame")
                    .and_then(MiValue::results)
                    .map(frame_summary_fields)
            })
        })
        .collect();
    (threads, total)
}

pub(super) fn normalized_frames(
    record: &MiRecord,
    state: &crate::domain::SessionState,
    parameters: &Value,
) -> Result<Vec<Value>> {
    let Some(stack) = MiResult::find(record.results(), "stack") else {
        return Ok(Vec::new());
    };
    // 2026-09-08: Frame-only and inferior-only selection minted stack handles
    // for the default thread. Use the same resolved selection as MI commands.
    let context = observation_context(parameters, state)?;
    Ok(aggregate_items(stack, "frame")
        .into_iter()
        .map(|fields| {
            let frame = frame_summary_fields(fields);
            let frame_id = context.as_ref().and_then(|context| {
                context
                    .thread_id
                    .as_ref()
                    .map(|thread| FrameId::new(thread, &context.stop_id, frame.level))
            });
            let mut facts = json!({
                "frame_id": frame_id,
                "level": frame.level,
                "address": frame.address,
                "function": frame.function,
                "source": frame.source.map(|path| json!({"path": path, "line": frame.line}))
            });
            if let Some(module) = frame.module {
                facts["module"] = Value::String(module);
            }
            facts
        })
        .collect())
}

fn normalized_variable(fields: &[MiResult]) -> Value {
    // 2026-09-08: Locals silently truncated long strings and dropped binary
    // values. Share value-object availability and lossless byte semantics;
    // the ordinary response budget owns paging/artifact fallback.
    let mut variable = json!({
        "name": result_value(fields, "name"),
        "type": result_value(fields, "type"),
        "value": result_value(fields, "value"),
        "status": value_status(fields)
    });
    // 2026-09-09: Missing MI flags became invented false facts on every
    // local and frame argument. Preserve only debugger-reported booleans.
    if let Some(dynamic) = result_bool(fields, "dynamic") {
        variable["dynamic"] = Value::Bool(dynamic);
    }
    variable
}

pub(super) fn normalized_variables(record: &MiRecord, name: &str) -> Vec<Value> {
    let Some(variables) = MiResult::find(record.results(), name) else {
        return Vec::new();
    };
    aggregate_items(variables, "variable")
        .into_iter()
        .map(normalized_variable)
        .collect()
}

pub(super) fn normalized_frame_variables(
    types: &MiRecord,
    values: Option<&MiRecord>,
) -> Result<(Vec<Value>, Vec<Value>)> {
    fn fields(record: &MiRecord) -> Result<&MiValue> {
        MiResult::find(record.results(), "variables")
            .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB omitted frame variables"))
    }
    let typed = aggregate_items(fields(types)?, "variable");
    let values = values
        .map(|record| fields(record).map(|fields| aggregate_items(fields, "variable")))
        .transpose()?;
    // All-values omits types. Join only identical ordered symbol identities,
    // including declaration and shadowing fields when GDB supplies them.
    if let Some(values) = &values
        && (typed.len() != values.len()
            || typed.iter().zip(values).any(|(typed, value)| {
                ["name", "arg", "filename", "fullname", "line", "shadowed"]
                    .iter()
                    .any(|field| MiResult::find(typed, field) != MiResult::find(value, field))
            }))
    {
        return Err(Error::new(
            ErrorCode::GdbError,
            "GDB variable identities changed between type and value reads",
        ));
    }
    let mut arguments = Vec::new();
    let mut locals = Vec::new();
    for (index, fields) in typed.iter().enumerate() {
        let mut variable = normalized_variable(fields);
        if let Some(values) = &values {
            variable["value"] = result_value(values[index], "value").unwrap_or(Value::Null);
            variable["status"] = json!(value_status(values[index]));
            if let Some(dynamic) = result_bool(values[index], "dynamic") {
                variable["dynamic"] = Value::Bool(dynamic);
            }
        }
        if result_bool(fields, "arg") == Some(true) {
            arguments.push(variable);
        } else {
            locals.push(variable);
        }
    }
    Ok((arguments, locals))
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
                        .map(normalized_variable)
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
    #[test]
    fn locals_and_arguments_share_lossless_value_semantics() {
        let record = gdb_ai_mi::parse_record(
            br#"1^done,variables=[{name="wide",type="unsigned long",value="18446744073709551615"},{name="bytes",value="\377",dynamic="1"},{name="aggregate",type="struct pair",dynamic="0"}],stack-args=[frame={level="0",args=[{name="bytes",value="\377",dynamic="1"}]}]"#,
            gdb_ai_mi::MiLimits::default(),
        ).unwrap();
        let locals = super::normalized_variables(&record, "variables");
        assert_eq!(locals[0]["value"], "18446744073709551615");
        assert_eq!(locals[1]["value"]["data_base64"], "/w==");
        assert_eq!(locals[1]["status"], "available");
        assert_eq!(locals[2]["status"], "not_collected");
        assert!(locals[0].get("dynamic").is_none());
        assert_eq!(locals[1]["dynamic"], true);
        assert_eq!(locals[2]["dynamic"], false);
        assert_eq!(
            super::normalized_arguments(&record)[0]["arguments"][0],
            locals[1]
        );
        let value = "x".repeat(16 * 1024 + 1);
        let encoded = format!("1^done,variables=[{{name=\"long\",value=\"{value}\"}}]");
        let record =
            gdb_ai_mi::parse_record(encoded.as_bytes(), gdb_ai_mi::MiLimits::default()).unwrap();
        assert_eq!(
            super::normalized_variables(&record, "variables")[0]["value"],
            value
        );
    }

    use super::*;

    #[test]
    fn frame_variables_join_values_only_for_identical_symbols() {
        let parse = |text: &str| {
            gdb_ai_mi::parse_record(text.as_bytes(), gdb_ai_mi::MiLimits::default()).unwrap()
        };
        let types = parse(
            r#"1^done,variables=[{name="input",arg="1",type="int",value="2"},{name="counts",type="struct summary"},{name="x",type="int",value="1",fullname="scope.c",line="1",shadowed="true"},{name="x",type="char",value="2",fullname="scope.c",line="2"}]"#,
        );
        let full = r#"2^done,variables=[{name="input",arg="1",value="2"},{name="counts",value="{accepted = 8, rejected = 1}"},{name="x",value="1",fullname="scope.c",line="1",shadowed="true"},{name="x",value="\377",fullname="scope.c",line="2"}]"#;
        let (arguments, simple) = normalized_frame_variables(&types, None).unwrap();
        assert_eq!(
            arguments,
            vec![json!({"name": "input", "type": "int", "value": "2", "status": "available"})]
        );
        assert_eq!(simple[0]["status"], "not_collected");
        let (merged_arguments, merged) =
            normalized_frame_variables(&types, Some(&parse(full))).unwrap();
        assert_eq!(merged_arguments, arguments);
        assert_eq!(
            merged[0],
            json!({"name": "counts", "type": "struct summary", "value": "{accepted = 8, rejected = 1}", "status": "available"})
        );
        assert_eq!(merged[1]["value"], "1");
        assert_eq!(merged[2]["type"], "char");
        assert_eq!(merged[2]["value"]["data_base64"], "/w==");
        for (before, after) in [
            ("name=\"counts\"", "name=\"other\""),
            ("arg=\"1\"", "arg=\"0\""),
            ("scope.c", "other.c"),
            ("line=\"1\"", "line=\"3\""),
            ("shadowed=\"true\"", "shadowed=\"false\""),
        ] {
            let changed = parse(&full.replace(before, after));
            assert_eq!(
                normalized_frame_variables(&types, Some(&changed))
                    .unwrap_err()
                    .code,
                ErrorCode::GdbError
            );
        }
        for missing in ["2^done", "2^done,variables=[]"] {
            assert_eq!(
                normalized_frame_variables(&types, Some(&parse(missing)))
                    .unwrap_err()
                    .code,
                ErrorCode::GdbError
            );
        }
    }

    #[test]
    fn full_frame_variables_preserve_native_read_errors_as_failed_values() {
        let types = gdb_ai_mi::parse_record(
            br#"1^done,variables=[{name="counts",type="Summary &"}]"#,
            gdb_ai_mi::MiLimits::default(),
        )
        .unwrap();
        let full = gdb_ai_mi::parse_record(
            br#"2^done,variables=[{name="counts",value="<error reading variable: Cannot access memory at address 0x1234>"}]"#,
            gdb_ai_mi::MiLimits::default(),
        ).unwrap();
        let (_, variables) = normalized_frame_variables(&types, Some(&full)).unwrap();
        assert_eq!(variables[0]["type"], "Summary &");
        assert_eq!(variables[0]["status"], "failed");
        assert_eq!(
            variables[0]["value"],
            "<error reading variable: Cannot access memory at address 0x1234>"
        );
        let quoted = gdb_ai_mi::parse_record(
            br#"3^done,variables=[{name="counts",value="\"<error reading variable: user text>\""}]"#,
            gdb_ai_mi::MiLimits::default(),
        ).unwrap();
        let (_, variables) = normalized_frame_variables(&types, Some(&quoted)).unwrap();
        assert_eq!(variables[0]["status"], "available");
    }

    #[test]
    fn thread_pages_preserve_metadata_order_and_total() {
        use crate::{
            domain::{DomainEvent, JournaledEvent, SessionId, SessionState},
            reducer::StateReducer,
        };

        let mut reducer =
            StateReducer::new(SessionState::creating(SessionId("sess_threads".into())));
        for (index, (inferior, thread)) in [("i1", "10"), ("i2", "2")].into_iter().enumerate() {
            reducer
                .apply(&JournaledEvent::for_replay(
                    index as u64 + 1,
                    DomainEvent::ThreadCreated {
                        backend_inferior: inferior.into(),
                        backend_thread: thread.into(),
                    },
                ))
                .unwrap();
        }
        let state = reducer.state();
        let record = gdb_ai_mi::parse_record(
            br#"1^done,threads=[{id="2",target-id="worker 2",name="two",state="stopped",frame={level="2",addr="0x20",func="worker",file="worker.c",fullname="/work/worker.c",line="9"}},{name="missing id"},{id="10",target-id="worker 10",state="running"},{id="99",state="stopped"}]"#,
            gdb_ai_mi::MiLimits::default(),
        ).unwrap();
        let expected = [
            json!({
                "thread_id": state.inferiors["i2"].threads["2"].id,
                "backend_id": "2", "target_id": "worker 2",
                "inferior_id": state.inferiors["i2"].id,
                "state": "stopped", "name": "two",
                "frame": {
                    "level": 2, "address": "0x20", "function": "worker",
                    "source": "/work/worker.c", "line": 9
                }
            }),
            json!({
                "thread_id": state.inferiors["i1"].threads["10"].id,
                "backend_id": "10", "target_id": "worker 10",
                "inferior_id": state.inferiors["i1"].id,
                "state": "running", "name": null, "frame": null
            }),
            json!({
                "thread_id": null, "backend_id": "99", "target_id": null,
                "inferior_id": null, "state": "stopped", "name": null, "frame": null
            }),
        ];
        for (offset, limit) in [(0, 4), (1, 1), (2, 8), (3, 1), (u64::MAX, 1)] {
            let (page, total) = normalized_threads(&record, state, offset, limit);
            assert_eq!(total, expected.len());
            let start = offset.min(total as u64) as usize;
            assert_eq!(page, expected[start..(start + limit).min(total)]);
        }
        for input in [b"1^done".as_slice(), b"1^done,threads=[]"] {
            let record = gdb_ai_mi::parse_record(input, gdb_ai_mi::MiLimits::default()).unwrap();
            assert_eq!(normalized_threads(&record, state, 0, 1), (vec![], 0));
        }
    }

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

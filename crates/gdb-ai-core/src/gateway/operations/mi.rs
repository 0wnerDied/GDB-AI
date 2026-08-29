use super::*;

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

pub(super) fn disassembly_instructions(record: &MiRecord, current: Option<u64>) -> Vec<Value> {
    let mut instructions = Vec::new();
    for result in record.results() {
        collect_instructions(&result.value, None, None, current, &mut instructions);
    }
    instructions
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

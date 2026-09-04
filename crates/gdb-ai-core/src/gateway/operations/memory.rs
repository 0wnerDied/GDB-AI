use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiRecord, MiResult};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    context::{context_options, require_stopped_context},
    encoding::{hex_decode, hex_encode, input_bytes, parse_address},
    evaluation::{safe_evaluate_command, validate_expression},
    mi::{aggregate_items, result_text},
    request::{bool_value, required_session, string, unsigned},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, TrackingDefinition, TrackingId},
    gateway::Gateway,
    protocol::ApiRequest,
    session::{CommandReply, SessionHandle},
};

fn memory_contents(record: &MiRecord, maximum: usize) -> Result<Vec<u8>> {
    let memory = MiResult::find(record.results(), "memory").ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            "GDB memory response has no memory field",
        )
    })?;
    let mut bytes = Vec::new();
    for item in aggregate_items(memory, "memory") {
        let offset = MiResult::find_str(item, "offset")
            .ok_or_else(|| Error::new(ErrorCode::GdbError, "memory block has no offset"))?;
        let offset = usize::try_from(parse_address(offset)?)
            .map_err(|_| Error::new(ErrorCode::OutputLimit, "memory block offset is too large"))?;
        // 2026-08-30: GDB returns every readable block in the requested
        // range. Concatenating blocks across an unreadable gap shifted later
        // bytes to the wrong address, so expose only the contiguous prefix.
        if offset != bytes.len() {
            break;
        }
        let contents = MiResult::find_str(item, "contents")
            .ok_or_else(|| Error::new(ErrorCode::GdbError, "memory block has no contents"))?;
        let contents = hex_decode(contents)?;
        // 2026-08-30: A malformed or hostile remote backend could return more
        // bytes than requested and bypass the API memory bound during decode.
        if contents.len() > maximum.saturating_sub(bytes.len()) {
            return Err(Error::new(
                ErrorCode::GdbError,
                "GDB memory response exceeds the requested length",
            ));
        }
        bytes.extend(contents);
    }
    Ok(bytes)
}

fn require_complete_read(actual: usize, requested: usize, allow_partial: bool) -> Result<()> {
    if !allow_partial && actual != requested {
        Err(Error::new(
            ErrorCode::PartialRead,
            format!("requested {requested} bytes, read {actual}"),
        ))
    } else {
        Ok(())
    }
}

fn validate_memory_range(start: u64, length: usize) -> Result<()> {
    let last_offset = u64::try_from(length.saturating_sub(1)).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "memory range length exceeds the address space",
        )
    })?;
    // 2026-08-30: A one-chunk request near u64::MAX reached GDB before the
    // per-chunk cursor advanced, so the existing overflow check never ran.
    start.checked_add(last_offset).map(|_| ()).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "memory range overflows address space",
        )
    })
}

// 2026-08-28: A single 16 MiB read expands beyond the MI record limit as
// hexadecimal text. Keep backend records bounded while preserving one API read.
pub(super) async fn read_memory_bytes(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
    start: u64,
    length: usize,
    allow_partial: bool,
) -> Result<(Vec<u8>, u64)> {
    handle
        .stable_observation(
            expected,
            Box::pin(read_memory_bytes_in_observation(
                handle,
                expected,
                start,
                length,
                allow_partial,
            )),
        )
        .await
}

async fn read_memory_bytes_in_observation(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
    start: u64,
    length: usize,
    allow_partial: bool,
) -> Result<(Vec<u8>, u64)> {
    const CHUNK_BYTES: usize = 64 * 1024;

    validate_memory_range(start, length)?;
    let mut bytes = Vec::with_capacity(length);
    let mut evidence_seq = handle.with_state(|state| state.event_seq);
    while bytes.len() < length {
        // 2026-08-28: Chunked reads could resume after an interrupt at a new
        // stop and concatenate bytes from different execution epochs.
        require_same_execution_context(handle, expected)?;
        let chunk = (length - bytes.len()).min(CHUNK_BYTES);
        let address = start.checked_add(bytes.len() as u64).ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "memory range overflows address space",
            )
        })?;
        let reply = match handle
            .command(
                MiCommand::new("-data-read-memory-bytes")?
                    .bare(format!("0x{address:x}"))?
                    .bare(chunk.to_string())?,
            )
            .await
        {
            Ok(reply) => reply,
            Err(error)
                if allow_partial && !bytes.is_empty() && error.code != ErrorCode::StaleContext =>
            {
                break;
            }
            Err(error) => return Err(error),
        };
        require_same_execution_context(handle, expected)?;
        evidence_seq = reply.evidence_seq;
        let part = memory_contents(&reply.record, chunk)?;
        let part_len = part.len();
        bytes.extend(part);
        if part_len < chunk {
            break;
        }
    }
    // 2026-08-30: Compare-and-write and memory comparison called this shared
    // path directly, so a short read could satisfy a precondition for a larger
    // requested range. Enforce the caller's completeness contract here.
    require_complete_read(bytes.len(), length, allow_partial)?;
    Ok((bytes, evidence_seq))
}

fn require_same_execution_context(
    handle: &SessionHandle,
    expected: &crate::domain::SessionState,
) -> Result<()> {
    let current = handle.state();
    if current.stop_id == expected.stop_id && current.execution_epoch == expected.execution_epoch {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::StaleContext,
            "target stop changed during composite operation",
        ))
    }
}

fn require_expected_bytes(parameters: &Value, actual: &[u8]) -> Result<()> {
    if expected_bytes_match(parameters, actual)? {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::MemoryPreconditionFailed,
            "memory no longer matches the expected value",
        ))
    }
}

fn expected_bytes_match(parameters: &Value, actual: &[u8]) -> Result<bool> {
    let expected = parameters.get("expected").ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "expected bytes or sha256 are required",
        )
    })?;
    if let Some(encoded) = expected.get("bytes_base64").and_then(Value::as_str) {
        let bytes = BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid expected bytes_base64: {error}"),
            )
        })?;
        return Ok(bytes == actual);
    }
    if let Some(expected_hash) = expected.get("sha256").and_then(Value::as_str) {
        if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expected sha256 must contain 64 hexadecimal digits",
            ));
        }
        return Ok(format!("{:x}", Sha256::digest(actual)).eq_ignore_ascii_case(expected_hash));
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "expected must contain bytes_base64 or sha256",
    ))
}

fn search_pattern(parameters: &Value) -> Result<Vec<u8>> {
    let pattern = parameters.get("pattern").ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "memory search pattern is required",
        )
    })?;
    let bytes = if let Some(hex) = pattern.get("hex").and_then(Value::as_str) {
        hex_decode(hex).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "memory search hex pattern is invalid",
            )
        })?
    } else if let Some(encoded) = pattern.get("data_base64").and_then(Value::as_str) {
        BASE64.decode(encoded).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid memory search data_base64: {error}"),
            )
        })?
    } else if let Some(text) = pattern.get("text").and_then(Value::as_str) {
        text.as_bytes().to_vec()
    } else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "pattern must contain hex, data_base64, or text",
        ));
    };
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "memory search pattern must contain 1 to 65536 bytes",
        ));
    }
    Ok(bytes)
}

fn last_hex_address(text: &str) -> Option<u64> {
    let suffix = text.rsplit_once("0x")?.1;
    let digits = suffix.bytes().take_while(u8::is_ascii_hexdigit).count();
    u64::from_str_radix(&suffix[..digits], 16).ok()
}

pub(super) fn find_memory_result(
    reply: &CommandReply,
    start: u64,
    length: usize,
    maximum: usize,
) -> (Vec<String>, bool, usize, bool) {
    let mut console = Vec::new();
    let mut diagnostics = Vec::new();
    for record in &reply.stream_records {
        match record {
            MiRecord::ConsoleStream(bytes) => console.extend(bytes),
            MiRecord::LogStream(bytes) => diagnostics.extend(bytes),
            _ => {}
        }
    }
    let console = String::from_utf8_lossy(&console);
    let end = start.saturating_add(length.saturating_sub(1) as u64);
    let mut matches = console
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().next())
        .filter(|token| token.starts_with("0x"))
        .filter_map(|token| parse_address(token).ok())
        .filter(|address| (start..=end).contains(address))
        .map(|address| format!("0x{address:016x}"))
        .collect::<Vec<_>>();
    let truncated = matches.len() > maximum || reply.stream_truncated;
    matches.truncate(maximum);
    let diagnostics = String::from_utf8_lossy(&diagnostics);
    let partial = diagnostics.contains("halting search");
    let searched_length = if partial {
        last_hex_address(&diagnostics)
            .and_then(|address| address.checked_sub(start))
            .map_or(0, |length_read| length_read.min(length as u64) as usize)
    } else {
        length
    };
    (matches, truncated, searched_length, partial)
}

impl Gateway {
    pub(super) async fn memory_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        // 2026-08-28: The public read limit was accidentally capped to one
        // backend chunk, making the configured 16 MiB logical limit unusable.
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "memory length must be between 1 and {}",
                    self.config.limits.memory_read_bytes
                ),
            ));
        }
        let allow_partial = bool_value(&request.parameters, "allow_partial", false);
        // 2026-09-04: Literal-only reads forced pointer chasing through an
        // evaluate turn followed by a memory turn. Resolve and read under the
        // existing stable-stop fence so one expression-addressed call is exact.
        let (address, bytes, evidence_seq) = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let address = if let Some(expression) = request
                        .parameters
                        .get("address_expression")
                        .and_then(Value::as_str)
                    {
                        validate_expression(expression)?;
                        let command = context_options(
                            MiCommand::new("-data-evaluate-expression")?.string(expression),
                            &request.parameters,
                            &state,
                        )?;
                        let reply = safe_evaluate_command(&entry.handle, command).await?;
                        let value = result_text(&reply.record, "value").ok_or_else(|| {
                            Error::new(ErrorCode::GdbError, "address expression returned no value")
                        })?;
                        crate::domain::Address::parse(&format!("0x{:x}", parse_address(&value)?))?
                    } else {
                        crate::domain::Address::parse(&string(&request.parameters, "address")?)?
                    };
                    let (bytes, evidence_seq) = read_memory_bytes_in_observation(
                        &entry.handle,
                        &state,
                        parse_address(address.as_str())?,
                        length,
                        allow_partial,
                    )
                    .await?;
                    Ok((address, bytes, evidence_seq))
                }),
            )
            .await?;
        let partial = bytes.len() != length;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        // 2026-08-30: Memory observations omitted their stop identity, which
        // made Agent evidence ambiguous and forced MCP to repeat session state.
        if bytes.len() > self.config.limits.inline_memory_bytes {
            let uri = self.put_artifact(Some(entry.handle.id()), &bytes, "target-memory")?;
            Ok(json!({
                "stop_id": state.stop_id,
                "address": address,
                "requested_length": length,
                "read_length": bytes.len(),
                "sha256": sha256,
                "preview_hex": hex_encode(&bytes[..bytes.len().min(64)]),
                "artifact": uri,
                "partial": partial,
                "truncated": true,
                "evidence_seq": evidence_seq
            }))
        } else {
            Ok(json!({
                "stop_id": state.stop_id,
                "address": address,
                "requested_length": length,
                "read_length": bytes.len(),
                "data_base64": BASE64.encode(&bytes),
                "sha256": sha256,
                "partial": partial,
                "truncated": false,
                "evidence_seq": evidence_seq
            }))
        }
    }

    pub(super) async fn memory_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address = crate::domain::Address::parse(&string(&request.parameters, "address")?)?;
        let bytes = input_bytes(&request.parameters)?;
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory writes must contain 1 to 65536 bytes",
            ));
        }
        // 2026-08-28: Releasing the composite read before compare-and-write
        // allowed another direct SessionHandle command to invalidate the
        // precondition. Keep the read, check, write, and state event together.
        let (before, reply) = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let (before, _) = read_memory_bytes(
                        &entry.handle,
                        &state,
                        parse_address(address.as_str())?,
                        bytes.len(),
                        false,
                    )
                    .await?;
                    require_expected_bytes(&request.parameters, &before)?;
                    let reply = entry
                        .handle
                        .command(
                            MiCommand::new("-data-write-memory-bytes")?
                                .bare(address.as_str())?
                                .bare(hex_encode(&bytes))?,
                        )
                        .await?;
                    entry
                        .handle
                        .record_event(DomainEvent::MemoryChanged)
                        .await?;
                    Ok((before, reply))
                }),
            )
            .await?;
        Ok(json!({
            "address": address,
            "length": bytes.len(),
            "before_sha256": format!("{:x}", Sha256::digest(&before)),
            "after_sha256": format!("{:x}", Sha256::digest(&bytes)),
            "snapshot_invalidated": true,
            "command": reply
        }))
    }

    pub(super) async fn memory_compare(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address = crate::domain::Address::parse(&string(&request.parameters, "address")?)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory comparison length is outside configured limits",
            ));
        }
        let (bytes, evidence_seq) = read_memory_bytes(
            &entry.handle,
            &state,
            parse_address(address.as_str())?,
            length,
            false,
        )
        .await?;
        let matches = expected_bytes_match(&request.parameters, &bytes)?;
        Ok(json!({
            "stop_id": state.stop_id,
            "address": address,
            "length": length,
            "matches": matches,
            "sha256": format!("{:x}", Sha256::digest(&bytes)),
            "evidence_seq": evidence_seq
        }))
    }

    pub(super) async fn memory_search(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let start = crate::domain::Address::parse(&string(&request.parameters, "start")?)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory search length must be positive",
            ));
        }
        let pattern = search_pattern(&request.parameters)?;
        let max_results = request
            .parameters
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .clamp(1, 1_000) as usize;
        let start_number = parse_address(start.as_str())?;
        validate_memory_range(start_number, length)?;
        let pattern = pattern
            .iter()
            .map(|byte| format!("0x{byte:02x}"))
            .collect::<Vec<_>>()
            .join(",");
        // 2026-09-04: Reading a large search range through 64 KiB MI chunks
        // made one GDB operation thousands of service round trips. Let GDB
        // scan it in place and bound its address output with one sentinel.
        let command = MiCommand::new("-interpreter-exec")?
            .bare("console")?
            .string(format!(
                "find /b /{} {}, +{}, {pattern}",
                max_results + 1,
                start.as_str(),
                length
            ));
        let reply = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async { entry.handle.command(command).await }),
            )
            .await?;
        let (matches, truncated, searched_length, partial) =
            find_memory_result(&reply, start_number, length, max_results);
        Ok(json!({
            "stop_id": state.stop_id,
            "start": start,
            "requested_length": length,
            "searched_length": searched_length,
            "matches": matches,
            "partial": partial,
            "truncated": truncated,
            "evidence_seq": reply.evidence_seq
        }))
    }

    pub(super) async fn tracking_add_expression(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let expression = string(&request.parameters, "expression")?;
        validate_expression(&expression)?;
        let max_value_bytes = request
            .parameters
            .get("max_value_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4_096) as usize;
        if max_value_bytes == 0 || max_value_bytes > 1024 * 1024 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "max_value_bytes must be between 1 and 1048576",
            ));
        }
        let definition = TrackingDefinition::Expression {
            tracking_id: TrackingId::new(),
            expression,
            max_value_bytes,
        };
        entry.handle.add_tracking(definition.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_added".into(),
            })
            .await?;
        Ok(serde_json::to_value(definition)?)
    }

    pub(super) async fn tracking_add_memory(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let address_expression = string(&request.parameters, "address_expression")?;
        validate_expression(&address_expression)?;
        let length = unsigned(&request.parameters, "length")? as usize;
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "tracked memory length is outside configured limits",
            ));
        }
        let max_history = request
            .parameters
            .get("max_history")
            .and_then(Value::as_u64)
            .unwrap_or(32)
            .clamp(1, 256) as usize;
        let definition = TrackingDefinition::Memory {
            tracking_id: TrackingId::new(),
            address_expression,
            length,
            max_history,
        };
        entry.handle.add_tracking(definition.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_added".into(),
            })
            .await?;
        Ok(serde_json::to_value(definition)?)
    }

    pub(super) async fn tracking_remove(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let tracking_id = string(&request.parameters, "tracking_id")?;
        let removed = entry.handle.remove_tracking(tracking_id).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "tracking_removed".into(),
            })
            .await?;
        Ok(json!({ "removed": removed }))
    }

    pub(super) async fn tracking_list(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        Ok(serde_json::to_value(entry.handle.tracking().await?)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::ErrorCode;
    use gdb_ai_mi::{MiLimits, parse_record};

    use super::{memory_contents, require_complete_read, validate_memory_range};

    #[test]
    fn memory_blocks_stop_at_the_first_unreadable_gap() {
        let record = parse_record(
            br#"1^done,memory=[{begin="0x1000",offset="0x0",end="0x1002",contents="aabb"},{begin="0x1002",offset="0x2",end="0x1004",contents="ccdd"},{begin="0x1008",offset="0x8",end="0x100a",contents="eeff"}]"#,
            MiLimits::default(),
        )
        .unwrap();

        assert_eq!(
            memory_contents(&record, 4).unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd]
        );
    }

    #[test]
    fn memory_blocks_cannot_exceed_the_requested_length() {
        let record = parse_record(
            br#"1^done,memory=[{begin="0x1000",offset="0x0",end="0x1003",contents="aabbcc"}]"#,
            MiLimits::default(),
        )
        .unwrap();

        assert_eq!(
            memory_contents(&record, 2).unwrap_err().code,
            ErrorCode::GdbError
        );
    }

    #[test]
    fn complete_memory_reads_reject_short_results() {
        assert!(require_complete_read(2, 4, true).is_ok());
        assert_eq!(
            require_complete_read(2, 4, false).unwrap_err().code,
            ErrorCode::PartialRead
        );
    }

    #[test]
    fn memory_ranges_cannot_wrap_the_address_space() {
        assert!(validate_memory_range(u64::MAX, 1).is_ok());
        assert_eq!(
            validate_memory_range(u64::MAX, 2).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }
}

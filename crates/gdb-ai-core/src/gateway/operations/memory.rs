use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::{MiRecord, MiResult};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    context::require_stopped_context,
    encoding::{hex_decode, hex_encode, input_bytes, parse_address},
    evaluation::validate_expression,
    mi::aggregate_items,
    request::{bool_value, required_session, string, unsigned},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, TrackingDefinition, TrackingId},
    gateway::Gateway,
    protocol::ApiRequest,
    session::SessionHandle,
};

fn memory_contents(record: &MiRecord) -> Result<Vec<u8>> {
    let memory = MiResult::find(record.results(), "memory").ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            "GDB memory response has no memory field",
        )
    })?;
    let mut bytes = Vec::new();
    for item in aggregate_items(memory, "memory") {
        if let Some(contents) = MiResult::find_str(item, "contents") {
            bytes.extend(hex_decode(contents)?);
        }
    }
    Ok(bytes)
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

    let mut bytes = Vec::with_capacity(length);
    let mut evidence_seq = handle.state().event_seq;
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
        let part = memory_contents(&reply.record)?;
        let part_len = part.len();
        bytes.extend(part);
        if part_len < chunk {
            break;
        }
    }
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

impl Gateway {
    pub(super) async fn memory_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let address_text = string(&request.parameters, "address")?;
        let address = crate::domain::Address::parse(&address_text)?;
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
        let (bytes, evidence_seq) = read_memory_bytes(
            &entry.handle,
            &state,
            parse_address(address.as_str())?,
            length,
            bool_value(&request.parameters, "allow_partial", false),
        )
        .await?;
        let partial = bytes.len() != length;
        if partial && !bool_value(&request.parameters, "allow_partial", false) {
            return Err(Error::new(
                ErrorCode::PartialRead,
                format!("requested {length} bytes, read {}", bytes.len()),
            ));
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if bytes.len() > self.config.limits.inline_memory_bytes {
            let uri = self.put_artifact(Some(entry.handle.id()), &bytes, "target-memory")?;
            Ok(json!({
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
        if length == 0 || length > self.config.limits.memory_read_bytes {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "memory search length is outside configured limits",
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
        let (bytes, evidence_seq) =
            read_memory_bytes(&entry.handle, &state, start_number, length, true).await?;
        let mut matches = bytes
            .windows(pattern.len())
            .enumerate()
            .filter(|(_, window)| *window == pattern.as_slice())
            .take(max_results + 1)
            .map(|(offset, _)| format!("0x{:016x}", start_number + offset as u64))
            .collect::<Vec<_>>();
        // 2026-08-28: Exactly max_results matches was incorrectly reported as
        // truncated. Read one sentinel match before setting the flag.
        let truncated = matches.len() > max_results;
        matches.truncate(max_results);
        // 2026-08-28: Search permits a bounded short read, but callers could
        // only infer it from two lengths. Mark partial evidence explicitly.
        let partial = bytes.len() < length;
        Ok(json!({
            "start": start,
            "requested_length": length,
            "searched_length": bytes.len(),
            "matches": matches,
            "partial": partial,
            "truncated": truncated,
            "evidence_seq": evidence_seq
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

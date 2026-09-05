use std::{collections::BTreeMap, time::Instant};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gdb_ai_mi::MiRecord;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    context::{context_options, require_stopped_context},
    encoding::{hex_encode, parse_address},
    evaluation::safe_evaluate_command,
    memory::read_memory_bytes,
    mi::{
        disassembly_instructions, frame_summary, normalized_arguments, normalized_frames,
        normalized_modules, normalized_source_files, normalized_symbols, normalized_threads,
        normalized_variables, register_role_candidates, register_values, resolve_register_name,
        result_string_list, result_text, target_architecture, valid_integer_literal,
    },
    reconciliation::{optional_command, reconcile_breakpoints},
    request::{bool_value, bounded_limit, required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, SessionId, TrackingDefinition},
    gateway::{Gateway, SessionEntry},
    protocol::{ApiRequest, CanonicalMethod},
    providers::mappings,
    session::CommandReply,
};

impl Gateway {
    pub(super) async fn inspection_get(&self, request: &ApiRequest) -> Result<Value> {
        let view = string(&request.parameters, "view")?;
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        match view.as_str() {
            "stop_context" => {
                // 2026-08-30: This Agent-facing view returned the complete
                // session registry, repeating unrelated breakpoints, modules,
                // threads, and signal policies at every stop.
                let frame = state.stopped_frame();
                let reason = match state.stop_reason_detail.as_ref() {
                    Some(reason) => serde_json::to_value(reason)?,
                    None => json!(state.stop_reason),
                };
                Ok(json!({
                    "stop_id": state.stop_id,
                    "reason": reason,
                    "inferior_id": state.stopped_inferior_id,
                    "thread_id": state.stopped_thread_id,
                    "frame": frame,
                    "snapshot": state.snapshot,
                    "execution_epoch": state.execution_epoch,
                    "event_seq": state.event_seq,
                    "partial": state.stop_id.is_some() && frame.is_none()
                }))
            }
            "target" => Ok(serde_json::to_value(state)?),
            "capabilities" => Ok(serde_json::to_value(entry.handle.capabilities())?),
            "providers" => self.session_providers(request).await,
            "crash" => {
                let mut snapshot = self.inspection_snapshot(request).await?;
                snapshot["crash_signature"] =
                    Value::String(crate::providers::crash_signature(&entry.handle.state()));
                snapshot["source"] = json!({
                    "provider": "userland-security",
                    "version": "1.0.0",
                    "mechanism": "bounded-stop-snapshot"
                });
                Ok(snapshot)
            }
            "threads" => self.inspection_threads(&entry, request).await,
            "stack" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                let offset = request
                    .parameters
                    .get("offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as usize;
                let end = offset.saturating_add(limit - 1);
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-frames",
                        vec![("bare", offset.to_string()), ("bare", end.to_string())],
                    )
                    .await?;
                let frames = normalized_frames(&reply.record, &state, &request.parameters);
                let continuation = (frames.len() == limit).then(|| {
                    format!(
                        "stack:{}:{}",
                        state.stop_id.as_ref().unwrap(),
                        offset + frames.len()
                    )
                });
                Ok(json!({
                    "stop_id": state.stop_id,
                    "offset": offset,
                    "limit": limit,
                    "frames": frames,
                    "continuation": continuation,
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "frame" => {
                let reply = self
                    .inspection_command(&entry, request, "-stack-info-frame", vec![])
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "frame": frame_summary(&reply.record),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "locals" => {
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-variables",
                        vec![("bare", "--simple-values".into())],
                    )
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "variables": normalized_variables(&reply.record, "variables"),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "arguments" => {
                let limit =
                    bounded_limit(&request.parameters, 16, self.config.limits.stack_frames)?;
                let offset = request
                    .parameters
                    .get("offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(u32::MAX as u64) as usize;
                let end = offset.saturating_add(limit - 1);
                let reply = self
                    .inspection_command(
                        &entry,
                        request,
                        "-stack-list-arguments",
                        vec![
                            ("bare", "--simple-values".into()),
                            ("bare", offset.to_string()),
                            ("bare", end.to_string()),
                        ],
                    )
                    .await?;
                Ok(json!({
                    "stop_id": state.stop_id,
                    "offset": offset,
                    "limit": limit,
                    "arguments": normalized_arguments(&reply.record),
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "registers" => self.register_read(request).await,
            "modules" => {
                let reply = self
                    .inspection_command(&entry, request, "-file-list-shared-libraries", vec![])
                    .await?;
                // 2026-09-04: GDB's shared-library command omits the main
                // executable, forcing Agents to request mappings before they
                // can use a target module offset. Include the bounded local
                // mapping page in the same view.
                let mapped_files = mappings(&state, 0, 64.min(self.config.limits.value_children))?;
                Ok(json!({
                    "modules": normalized_modules(&reply.record),
                    "mapped_files": mapped_files,
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "breakpoints" => {
                let reply = entry.handle.command(MiCommand::new("-break-list")?).await?;
                reconcile_breakpoints(&entry.handle, &reply.record).await?;
                Ok(json!({
                    "breakpoints": entry.handle.state().breakpoints,
                    "evidence_seq": reply.evidence_seq
                }))
            }
            "symbols" => self.symbol_search(&entry, request).await,
            "source" => {
                if request.parameters.get("path").is_some() {
                    self.source_excerpt(request).await
                } else {
                    let reply = self
                        .inspection_command(&entry, request, "-file-list-exec-source-files", vec![])
                        .await?;
                    Ok(json!({
                        "files": normalized_source_files(&reply.record),
                        "evidence_seq": reply.evidence_seq
                    }))
                }
            }
            "mappings" => {
                let limit = bounded_limit(
                    &request.parameters,
                    64.min(self.config.limits.value_children),
                    self.config.limits.value_children,
                )?;
                let offset = request
                    .parameters
                    .get("offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .try_into()
                    .map_err(|_| {
                        Error::new(ErrorCode::OutputLimit, "mapping offset is too large")
                    })?;
                mappings(&state, offset, limit)
            }
            "signals" => Ok(serde_json::to_value(state.signal_policies)?),
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "unsupported inspection view",
            )),
        }
    }

    async fn inspection_threads(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
    ) -> Result<Value> {
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let limit = bounded_limit(
            &request.parameters,
            64.min(self.config.limits.value_children),
            self.config.limits.value_children,
        )?;
        let offset = request.parameters["offset"].as_u64().unwrap_or(0);
        let depth = request.parameters["stack_depth"].as_u64();
        if depth.is_some_and(|depth| depth == 0 || depth > self.config.limits.stack_frames as u64) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "stack_depth must be between 1 and {}",
                    self.config.limits.stack_frames
                ),
            ));
        }
        // 2026-09-05: Thread discovery followed by per-thread stack calls
        // split hang diagnosis across turns. Capture the page at one stop,
        // with explicit thread context so concurrent readers cannot mix frames.
        entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let reply = self
                        .inspection_command(entry, request, "-thread-info", vec![])
                        .await?;
                    let threads = normalized_threads(&reply.record, &state);
                    let total = threads.len();
                    let mut threads: Vec<_> = threads
                        .into_iter()
                        .skip(offset.min(total as u64) as usize)
                        .take(limit)
                        .collect();
                    let mut evidence_seq = reply.evidence_seq;
                    if let Some(depth) = depth {
                        for thread in &mut threads {
                            let thread_id = thread["thread_id"].as_str().ok_or_else(|| {
                                Error::new(ErrorCode::StaleContext, "thread has no current handle")
                            })?;
                            let parameters =
                                json!({"stop_id": state.stop_id, "thread_id": thread_id});
                            let command = context_options(
                                MiCommand::new("-stack-list-frames")?,
                                &parameters,
                                &state,
                            )?
                            .bare("0")?
                            .bare((depth - 1).to_string())?;
                            match entry.handle.command(command).await {
                                Ok(reply) => {
                                    let frames =
                                        normalized_frames(&reply.record, &state, &parameters);
                                    if frames.len() == depth as usize {
                                        thread["next_frame_offset"] = Value::from(depth);
                                    }
                                    thread["frames"] = json!(frames);
                                    thread.as_object_mut().unwrap().remove("frame");
                                    evidence_seq = reply.evidence_seq;
                                }
                                Err(error) if error.code == ErrorCode::GdbError => {
                                    thread["error"] =
                                        json!({"code": error.code, "message": error.message});
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    let next = offset.saturating_add(threads.len() as u64);
                    let mut result = json!({
                        "stop_id": state.stop_id,
                        "threads": threads,
                        "evidence_seq": evidence_seq
                    });
                    if next < total as u64 {
                        result["next_offset"] = Value::from(next);
                    }
                    Ok(result)
                }),
            )
            .await
    }

    // 2026-09-05: Large C++ targets previously forced Agents through nm,
    // readelf, and repeated GDB CLI sessions for symbol and type layout.
    // Keep both bounded debugger-native facts in one semantic inspection.
    async fn symbol_search(&self, entry: &SessionEntry, request: &ApiRequest) -> Result<Value> {
        let query = string(&request.parameters, "query")?;
        if query.is_empty() || query.len() > 512 || query.contains(['\r', '\n', '\0']) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "symbol query must contain 1 to 512 single-line bytes",
            ));
        }
        let kind = request
            .parameters
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("functions");
        let command_name = match kind {
            "functions" => "-symbol-info-functions",
            "types" => "-symbol-info-types",
            "variables" => "-symbol-info-variables",
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "symbol kind must be functions, types, or variables",
                ));
            }
        };
        let limit = bounded_limit(&request.parameters, 32, self.config.limits.value_children)?;
        let mut command = MiCommand::new(command_name)?;
        if kind != "types" {
            command = command.bare("--include-nondebug")?;
        }
        command = command
            .bare("--name")?
            .string(&query)
            .bare("--max-results")?
            .bare(limit.saturating_add(1).to_string())?;
        let search = entry.handle.command(command).await?;
        let mut symbols = normalized_symbols(&search.record);
        let truncated = symbols.len() > limit;
        symbols.truncate(limit);
        let mut result = json!({
            "stop_id": entry.handle.state().stop_id,
            "query": query,
            "kind": kind,
            "limit": limit,
            "symbols": symbols,
            "truncated": truncated,
            "evidence_seq": search.evidence_seq
        });

        if let Some(type_name) = request
            .parameters
            .get("type_layout")
            .and_then(Value::as_str)
        {
            if type_name.is_empty()
                || type_name.len() > 512
                || type_name.contains(['\r', '\n', '\0'])
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "type_layout must contain 1 to 512 single-line bytes",
                ));
            }
            let layout = entry
                .handle
                .command(
                    MiCommand::new("-interpreter-exec")?
                        .bare("console")?
                        .string(format!("ptype /o {type_name}")),
                )
                .await?;
            let mut bytes = Vec::new();
            for record in &layout.stream_records {
                if let MiRecord::ConsoleStream(output) = record {
                    bytes.extend(output);
                }
            }
            const MAX_LAYOUT_BYTES: usize = 32 * 1024;
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            let layout_truncated = layout.stream_truncated || text.len() > MAX_LAYOUT_BYTES;
            if text.len() > MAX_LAYOUT_BYTES {
                let mut end = MAX_LAYOUT_BYTES;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                text.truncate(end);
            }
            result["type_layout"] = json!({
                "name": type_name,
                "text": text.trim(),
                "truncated": layout_truncated
            });
            result["evidence_seq"] = Value::from(layout.evidence_seq);
        }
        Ok(result)
    }

    pub(super) async fn inspection_command(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        name: &str,
        arguments: Vec<(&str, String)>,
    ) -> Result<CommandReply> {
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let mut command = MiCommand::new(name)?;
        command = context_options(command, &request.parameters, &state)?;
        for (kind, argument) in arguments {
            command = if kind == "bare" {
                command.bare(argument)?
            } else {
                command.string(argument)
            };
        }
        entry.handle.command(command).await
    }

    pub(super) async fn inspection_snapshot(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let profile = request
            .parameters
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or("standard");
        let frames = match profile {
            "minimal" => 1,
            "brief" => 3,
            "standard" => 8,
            "deep" => bounded_limit(&request.parameters, 8, self.config.limits.stack_frames)?,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unknown snapshot profile",
                ));
            }
        };
        // 2026-08-28: Publishing SnapshotStarted before profile validation
        // left the current snapshot permanently BUILDING on invalid input.
        entry
            .handle
            .record_event(DomainEvent::SnapshotStarted {
                stop_id: state.stop_id.clone().unwrap(),
            })
            .await?;
        let built = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(self.build_and_commit_snapshot(&entry, request, &state, profile, frames)),
            )
            .await;
        if built.is_err() {
            entry
                .handle
                .record_event(DomainEvent::SnapshotFailed {
                    stop_id: state.stop_id.clone().unwrap(),
                })
                .await?;
        }
        built
    }

    pub(super) async fn build_and_commit_snapshot(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        state: &crate::domain::SessionState,
        profile: &str,
        frames: usize,
    ) -> Result<Value> {
        let started = Instant::now();
        let mut warnings = Vec::new();
        let stack = optional_command(
            &entry.handle,
            context_options(
                MiCommand::new("-stack-list-frames")?,
                &request.parameters,
                state,
            )?
            .bare("0")?
            .bare((frames - 1).to_string())?,
            "stack",
            &mut warnings,
        )
        .await
        .map(|reply| normalized_frames(&reply.record, state, &request.parameters))
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or(Value::Null);
        // 2026-09-01: GDB's stack-list-variables already includes top-frame
        // arguments, so brief snapshots repeated those values in a second
        // multi-frame argument list. Keep the variables superset; deeper
        // profiles retain arguments from every frame.
        let locals = if profile == "minimal" {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-stack-list-variables")?,
                    &request.parameters,
                    state,
                )?
                .bare("--simple-values")?,
                "locals",
                &mut warnings,
            )
            .await
            .map(|reply| normalized_variables(&reply.record, "variables"))
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null)
        };
        let arguments = if matches!(profile, "minimal" | "brief") {
            Value::Null
        } else {
            optional_command(
                &entry.handle,
                context_options(
                    MiCommand::new("-stack-list-arguments")?,
                    &request.parameters,
                    state,
                )?
                .bare("--simple-values")?
                .bare("0")?
                .bare((frames - 1).to_string())?,
                "arguments",
                &mut warnings,
            )
            .await
            .map(|reply| normalized_arguments(&reply.record))
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(Value::Null)
        };
        let registers = if profile == "minimal" {
            Value::Null
        } else {
            match self.register_read(request).await {
                Ok(registers) => registers,
                Err(error) => {
                    warnings.push(json!({
                        "code": "REGISTERS_UNAVAILABLE",
                        "message": error.to_string()
                    }));
                    Value::Null
                }
            }
        };
        let disassembly = if matches!(profile, "brief" | "standard" | "deep") {
            let mut disassembly_request = request.clone();
            if profile == "brief" {
                let parameters = disassembly_request.parameters.as_object_mut().unwrap();
                if !parameters.contains_key("around") && !parameters.contains_key("range") {
                    parameters.insert(
                        "around".into(),
                        json!({
                            "expression": "$pc",
                            "before_instructions": 4,
                            "after_instructions": 7
                        }),
                    );
                }
                parameters
                    .entry("include_source")
                    .or_insert(Value::Bool(false));
            }
            match self.disassembly_read(&disassembly_request).await {
                Ok(disassembly) => disassembly,
                Err(error) => {
                    warnings.push(json!({
                        "code": "DISASSEMBLY_UNAVAILABLE",
                        "message": error.to_string()
                    }));
                    Value::Null
                }
            }
        } else {
            Value::Null
        };
        let (tracked, changes) = match self
            .capture_tracking(entry, request, state, &mut warnings)
            .await
        {
            Ok(tracking) => tracking,
            Err(error) => {
                warnings.push(json!({
                    "code": "TRACKING_UNAVAILABLE",
                    "message": error.to_string()
                }));
                (BTreeMap::new(), BTreeMap::new())
            }
        };
        let partial = !warnings.is_empty();
        let stop_id = state.stop_id.clone().unwrap();
        let current = entry.handle.state();
        let snapshot_id = format!("snap_{stop_id}");
        let snapshot = json!({
            "snapshot_id": &snapshot_id,
            "stop_id": &stop_id,
            "revision": current.revision,
            "profile": profile,
            "reason": state.stop_reason,
            "reason_detail": state.stop_reason_detail,
            "stack": stack,
            "locals": locals,
            "arguments": arguments,
            "registers": registers,
            "disassembly": disassembly,
            "tracked": tracked,
            "changes": changes,
            "warnings": warnings,
            "partial": partial,
            "evidence": [{"kind": "mi-event", "uri": format!("gdbai://session/{}/event/{}", entry.handle.id(), current.event_seq)}]
        });
        entry
            .handle
            .commit_snapshot(
                snapshot_id,
                snapshot.clone(),
                stop_id,
                state.execution_epoch,
                partial,
            )
            .await?;
        self.metrics
            .snapshot(started.elapsed().as_micros() as u64, partial);
        Ok(snapshot)
    }

    pub(super) async fn inspection_diff(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let before_id = string(&request.parameters, "before_snapshot_id")?;
        let after_id = string(&request.parameters, "after_snapshot_id")?;
        let before = entry.handle.snapshot(before_id.clone()).await?;
        let after = entry.handle.snapshot(after_id.clone()).await?;
        let mut changes = BTreeMap::new();
        for field in ["reason", "stack", "locals", "registers", "tracked"] {
            let old = before.get(field).cloned().unwrap_or(Value::Null);
            let new = after.get(field).cloned().unwrap_or(Value::Null);
            if old != new {
                changes.insert(field, json!({ "before": old, "after": new }));
            }
        }
        Ok(json!({
            "before_snapshot_id": before_id,
            "after_snapshot_id": after_id,
            "changes": changes,
            "partial": before.get("partial") == Some(&Value::Bool(true))
                || after.get("partial") == Some(&Value::Bool(true))
        }))
    }

    pub(super) async fn inspection_snapshot_get(&self, request: &ApiRequest) -> Result<Value> {
        let session_id = SessionId::parse(required_session(request)?)?;
        let snapshot_id = string(&request.parameters, "snapshot_id")?;
        if let Ok(entry) = self.entry(&session_id.0).await {
            return entry.handle.snapshot(snapshot_id).await;
        }
        // 2026-08-28: Historical snapshots remain authoritative SQLite
        // evidence after the live worker has been removed from the registry.
        self.store
            .get_snapshot(&session_id, &snapshot_id)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot not found"))
    }

    pub(super) async fn inspection_batch(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let baseline = entry.handle.state();
        require_stopped_context(&request.parameters, &baseline)?;
        let requests = request
            .parameters
            .get("requests")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "batch requests are required"))?;
        if requests.is_empty() || requests.len() > 16 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "batch accepts 1 to 16 reads",
            ));
        }
        entry
            .handle
            .stable_observation(
                &baseline,
                Box::pin(async {
                    let mut results = BTreeMap::new();
                    for item in requests {
                        let view = string(item, "view")?;
                        // 2026-09-01: Requiring a name identical to every view
                        // repeated request tokens. Use the view as its result
                        // key; names remain available for duplicate views.
                        let name = item
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or(&view)
                            .to_owned();
                        if results.contains_key(&name) {
                            return Err(Error::new(
                                ErrorCode::Conflict,
                                "batch request names must be unique",
                            ));
                        }
                        let mut parameters = item.clone();
                        parameters["stop_id"] =
                            Value::String(baseline.stop_id.as_ref().unwrap().0.clone());
                        let subrequest = ApiRequest {
                            api_version: request.api_version.clone(),
                            request_id: format!("{}:{name}", request.request_id),
                            session_id: request.session_id.clone(),
                            method: CanonicalMethod::InspectionGet,
                            expected_revision: None,
                            idempotency_key: None,
                            parameters,
                        };
                        results.insert(name, self.inspection_get(&subrequest).await?);
                    }
                    Ok(json!({
                        "stop_id": baseline.stop_id,
                        "revision": entry.handle.with_state(|state| state.revision),
                        "results": results
                    }))
                }),
            )
            .await
    }

    pub(super) async fn capture_tracking(
        &self,
        entry: &SessionEntry,
        request: &ApiRequest,
        state: &crate::domain::SessionState,
        warnings: &mut Vec<Value>,
    ) -> Result<(BTreeMap<String, Value>, BTreeMap<String, Value>)> {
        let mut observations = BTreeMap::new();
        let mut presented = BTreeMap::new();
        for definition in entry.handle.tracking().await? {
            let tracking_id = definition.id().0.clone();
            let mut presentation = None;
            let observation = match definition {
                TrackingDefinition::Expression {
                    expression,
                    max_value_bytes,
                    ..
                } => {
                    let command = context_options(
                        MiCommand::new("-data-evaluate-expression")?.string(&expression),
                        &request.parameters,
                        state,
                    )?;
                    match safe_evaluate_command(&entry.handle, command).await {
                        Ok(reply) => {
                            let value = result_text(&reply.record, "value").unwrap_or_default();
                            if value.len() > max_value_bytes {
                                let uri = self.put_artifact(
                                    Some(entry.handle.id()),
                                    value.as_bytes(),
                                    "target-value",
                                )?;
                                json!({
                                    "expression": expression,
                                    "sha256": format!("{:x}", Sha256::digest(value.as_bytes())),
                                    "preview": value.chars().take(max_value_bytes.min(256)).collect::<String>(),
                                    "artifact": uri,
                                    "truncated": true
                                })
                            } else {
                                json!({ "expression": expression, "value": value })
                            }
                        }
                        Err(error) => {
                            warnings.push(json!({
                                "code": "TRACKED_EXPRESSION_UNAVAILABLE",
                                "tracking_id": tracking_id,
                                "message": error.to_string()
                            }));
                            continue;
                        }
                    }
                }
                TrackingDefinition::Memory {
                    address_expression,
                    length,
                    ..
                } => {
                    let command = context_options(
                        MiCommand::new("-data-evaluate-expression")?.string(&address_expression),
                        &request.parameters,
                        state,
                    )?;
                    let address = match safe_evaluate_command(&entry.handle, command).await {
                        Ok(reply) => result_text(&reply.record, "value")
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorCode::GdbError,
                                    "tracked address expression returned no value",
                                )
                            })
                            .and_then(|value| parse_address(&value)),
                        Err(error) => Err(error),
                    };
                    let bytes = match address {
                        Ok(address) => {
                            read_memory_bytes(&entry.handle, state, address, length, true).await
                        }
                        Err(error) => Err(error),
                    };
                    match bytes {
                        Ok((bytes, evidence_seq)) => {
                            let length = bytes.len();
                            let sha256 = format!("{:x}", Sha256::digest(&bytes));
                            let data_base64 = BASE64.encode(&bytes);
                            // 2026-08-30: Presentation decoded the just-created
                            // base64 value back into a second full memory buffer.
                            // Build both views while the captured bytes are live.
                            if length > self.config.limits.inline_memory_bytes {
                                let preview_hex = hex_encode(&bytes[..length.min(64)]);
                                let uri = self.put_artifact(
                                    Some(entry.handle.id()),
                                    &bytes,
                                    "tracked-memory",
                                )?;
                                presentation = Some(json!({
                                    "address_expression": &address_expression,
                                    "length": length,
                                    "sha256": &sha256,
                                    "preview_hex": preview_hex,
                                    "artifact": uri,
                                    "truncated": true,
                                    "evidence_seq": evidence_seq
                                }));
                            }
                            json!({
                                "address_expression": &address_expression,
                                "length": length,
                                "sha256": sha256,
                                "data_base64": data_base64,
                                "evidence_seq": evidence_seq
                            })
                        }
                        Err(error) => {
                            warnings.push(json!({
                                "code": "TRACKED_MEMORY_UNAVAILABLE",
                                "tracking_id": tracking_id,
                                "message": error.to_string()
                            }));
                            continue;
                        }
                    }
                }
            };
            // 2026-08-28: Tracked memory was copied into snapshots and SQLite
            // as base64. Keep bytes only in bounded worker history and artifacts.
            let presentation = presentation.unwrap_or_else(|| observation.clone());
            observations.insert(tracking_id.clone(), observation);
            presented.insert(tracking_id, presentation);
        }
        let changes = entry.handle.record_tracking(observations).await?;
        Ok((presented, changes))
    }

    pub(super) async fn register_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let names_reply = entry
            .handle
            .command(MiCommand::new("-data-list-register-names")?)
            .await?;
        let names = result_string_list(&names_reply.record, "register-names");
        let requested_roles = request
            .parameters
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                let mut roles = vec!["pc".into(), "sp".into(), "fp".into(), "return".into()];
                // 2026-09-04: Standard register views omitted ABI arguments,
                // forcing one expression-evaluation turn per call register.
                // Include every argument role supported by the target ABI.
                if !matches!(
                    request.parameters.get("profile").and_then(Value::as_str),
                    Some("minimal" | "brief")
                ) {
                    roles.extend((0..8).map(|index| format!("argument_{index}")));
                }
                roles
            });
        let mut role_numbers = BTreeMap::new();
        for role in requested_roles {
            let candidates = register_role_candidates(&role).ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unknown register role {role}"),
                )
            })?;
            if let Some((number, _)) = names
                .iter()
                .enumerate()
                .find(|(_, name)| candidates.contains(&name.as_str()))
            {
                role_numbers.insert(role, number);
            }
        }
        let architecture = target_architecture(&names);
        // 2026-08-28: GDB interprets an empty register-number list as all
        // registers. Return an explicit empty role map instead of expanding a
        // missing semantic role into an unbounded backend observation.
        if role_numbers.is_empty() {
            return Ok(json!({
                "stop_id": state.stop_id,
                "roles": {},
                "architecture": architecture,
                "limitations": ["requested register roles are unavailable"],
                "evidence_seq": names_reply.evidence_seq
            }));
        }
        let mut command = context_options(
            MiCommand::new("-data-list-register-values")?.bare("x")?,
            &request.parameters,
            &state,
        )?;
        for number in role_numbers.values() {
            command = command.bare(number.to_string())?;
        }
        let values_reply = entry.handle.command(command).await?;
        let values = register_values(&values_reply.record);
        let roles: BTreeMap<String, Value> = role_numbers
            .into_iter()
            .map(|(role, number)| {
                let value = values.get(&number).cloned().unwrap_or(Value::Null);
                (role, value)
            })
            .collect();
        Ok(json!({
            "stop_id": state.stop_id,
            "roles": roles,
            "architecture": architecture,
            "evidence_seq": values_reply.evidence_seq
        }))
    }

    pub(super) async fn register_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let requested = string(&request.parameters, "register")?;
        let value = string(&request.parameters, "value")?;
        let reason = string(&request.parameters, "reason")?;
        if !valid_integer_literal(&value) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "register value must be a decimal or hexadecimal integer",
            ));
        }
        // 2026-08-28: Register compare/write evidence previously released the
        // command sequence between MI requests, so another command could alter
        // the register before the recorded after-value. Keep it one observation.
        let (register, before, write, after) = entry
            .handle
            .stable_observation(
                &state,
                Box::pin(async {
                    let names_reply = entry
                        .handle
                        .command(MiCommand::new("-data-list-register-names")?)
                        .await?;
                    let names = result_string_list(&names_reply.record, "register-names");
                    let register = resolve_register_name(&requested, &names)?;
                    let read = |expression: String| {
                        context_options(
                            MiCommand::new("-data-evaluate-expression")?.string(expression),
                            &request.parameters,
                            &state,
                        )
                    };
                    let before = entry.handle.command(read(format!("${register}"))?).await?;
                    let write = entry
                        .handle
                        .command(read(format!("${register}={value}"))?)
                        .await?;
                    let after = entry.handle.command(read(format!("${register}"))?).await?;
                    entry
                        .handle
                        .record_event(DomainEvent::RegisterChanged {
                            register: register.clone(),
                        })
                        .await?;
                    Ok((register, before, write, after))
                }),
            )
            .await?;
        Ok(json!({
            "register": register,
            "before": result_text(&before.record, "value"),
            "after": result_text(&after.record, "value"),
            "reason": reason,
            "snapshot_invalidated": true,
            "command": write
        }))
    }

    pub(super) async fn disassembly_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let (start, end, current, around_limit) = if let Some(range) =
            request.parameters.get("range")
        {
            let start = crate::domain::Address::parse(&string(range, "start")?)?;
            let end = crate::domain::Address::parse(&string(range, "end")?)?;
            let start_number = parse_address(start.as_str())?;
            let end_number = parse_address(end.as_str())?;
            if end_number <= start_number || end_number - start_number > 64 * 1024 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "disassembly range must be positive and at most 64 KiB",
                ));
            }
            (start_number, end_number, None, None)
        } else {
            let around = request
                .parameters
                .get("around")
                .unwrap_or(&request.parameters);
            let expression = around
                .get("expression")
                .and_then(Value::as_str)
                .unwrap_or("$pc");
            let reply = entry
                .handle
                .command(context_options(
                    MiCommand::new("-data-evaluate-expression")?.string(expression),
                    &request.parameters,
                    &state,
                )?)
                .await?;
            let address = result_text(&reply.record, "value")
                .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB did not return an address"))?;
            let address = parse_address(&address)?;
            let before = around
                .get("before_instructions")
                .and_then(Value::as_u64)
                .unwrap_or(8)
                .min(64);
            let after = around
                .get("after_instructions")
                .and_then(Value::as_u64)
                .unwrap_or(16)
                .min(64);
            (
                address.saturating_sub(before * 16),
                address.saturating_add(after * 16 + 16),
                Some(address),
                Some((before as usize, after as usize)),
            )
        };
        let include_source = bool_value(&request.parameters, "include_source", true);
        let include_bytes = bool_value(&request.parameters, "include_bytes", true);
        let mode = match (include_source, include_bytes) {
            (false, false) => "0",
            (true, false) => "1",
            (false, true) => "2",
            (true, true) => "3",
        };
        let reply = entry
            .handle
            .command(
                MiCommand::new("-data-disassemble")?
                    .bare("-s")?
                    .bare(format!("0x{start:x}"))?
                    .bare("-e")?
                    .bare(format!("0x{end:x}"))?
                    .bare("--")?
                    .bare(mode)?,
            )
            .await?;
        let architecture = entry
            .handle
            .command(MiCommand::new("-data-list-register-names")?)
            .await
            .ok()
            .map(|reply| target_architecture(&result_string_list(&reply.record, "register-names")))
            .unwrap_or("unknown");
        let mut instructions = disassembly_instructions(&reply.record, current, around_limit);
        // 2026-08-31: Some GDB modes still supplied source metadata and the
        // normalizer emitted null opcode fields. Enforce both requested
        // projections on the semantic result instead of trusting MI shape.
        if !include_source || !include_bytes {
            for instruction in &mut instructions {
                if let Some(instruction) = instruction.as_object_mut() {
                    if !include_source {
                        instruction.remove("source");
                    }
                    if !include_bytes {
                        instruction.remove("bytes");
                    }
                }
            }
        }
        // 2026-08-30: Disassembly omitted its stop identity, so MCP repeated
        // the session state and callers could not attribute cached evidence.
        Ok(json!({
            "stop_id": state.stop_id,
            "architecture": architecture,
            "syntax": "target-default",
            "range": {"start": format!("0x{start:016x}"), "end": format!("0x{end:016x}")},
            "instructions": instructions,
            "evidence_seq": reply.evidence_seq,
            "bounded": true
        }))
    }

    pub(super) async fn source_excerpt(&self, request: &ApiRequest) -> Result<Value> {
        let requested = std::path::PathBuf::from(string(&request.parameters, "path")?);
        let mapped = self
            .config
            .security
            .source_map
            .iter()
            .find_map(|mapping| {
                requested
                    .strip_prefix(&mapping.from)
                    .ok()
                    .map(|suffix| mapping.to.join(suffix))
            })
            .unwrap_or(requested);
        let path = self.workspace_path(&mapped.to_string_lossy(), false)?;
        let source_path = path.clone();
        // 2026-08-31: A workspace entry could change after path validation,
        // and synchronous FIFO or filesystem reads blocked the async Gateway.
        // Verify that the opened descriptor is regular and cap its
        // blocking-pool read.
        let source = tokio::task::spawn_blocking(move || -> Result<String> {
            use std::{io::Read as _, os::unix::fs::OpenOptionsExt as _};

            const MAX_SOURCE_BYTES: usize = 1024 * 1024;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
                .open(source_path)?;
            if !file.metadata()?.is_file() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "source path is not a regular file",
                ));
            }
            let mut bytes = Vec::new();
            file.by_ref()
                .take((MAX_SOURCE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_SOURCE_BYTES {
                return Err(Error::new(
                    ErrorCode::OutputLimit,
                    "source file exceeds 1 MiB",
                ));
            }
            String::from_utf8(bytes).map_err(|_| {
                Error::new(ErrorCode::InvalidArgument, "source file is not valid UTF-8")
            })
        })
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("source read task failed: {error}"),
            )
        })??;
        let lines = source.lines().collect::<Vec<_>>();
        let center = request
            .parameters
            .get("line")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .clamp(1, lines.len().max(1) as u64) as usize;
        let before = request
            .parameters
            .get("before_lines")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .min(100) as usize;
        let after = request
            .parameters
            .get("after_lines")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .min(100) as usize;
        let start = center.saturating_sub(before + 1);
        let end = center.saturating_add(after).min(lines.len());
        let excerpt = lines[start..end]
            .iter()
            .enumerate()
            .map(|(offset, text)| json!({ "line": start + offset + 1, "text": text }))
            .collect::<Vec<_>>();
        Ok(json!({
            "path": path,
            "start_line": start + 1,
            "end_line": end,
            "lines": excerpt,
            "partial": start > 0 || end < lines.len(),
            "source": {"provider": "linux-userland", "mechanism": "workspace-file"}
        }))
    }
}

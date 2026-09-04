use std::time::Duration;

use serde_json::{Value, json};
use tokio::{sync::broadcast, time::Instant};

use super::{
    encoding::{MAX_INFERIOR_INPUT_BYTES, byte_content, input_bytes},
    request::{required_session, unsigned},
};
use crate::{
    Error, ErrorCode, Result,
    domain::{DomainEvent, OutputSource},
    gateway::Gateway,
    protocol::ApiRequest,
    session::{OutputRing, PublishedEvent, SessionHandle},
};

struct IoWriteStep {
    wait_for: Option<Vec<u8>>,
    bytes: Vec<u8>,
}

fn io_write_steps(parameters: &Value) -> Result<Option<Vec<IoWriteStep>>> {
    let Some(steps) = parameters.get("steps").and_then(Value::as_array) else {
        return Ok(None);
    };
    if steps.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "inferior I/O steps cannot be empty",
        ));
    }
    let mut total = 0usize;
    let mut parsed = Vec::with_capacity(steps.len());
    for step in steps {
        let wait_for = step
            .get("wait_for")
            .and_then(Value::as_str)
            .map(|text| text.as_bytes().to_vec());
        if wait_for.as_ref().is_some_and(Vec::is_empty) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "inferior I/O wait_for cannot be empty",
            ));
        }
        let bytes = input_bytes(step)?;
        total = total.saturating_add(bytes.len());
        parsed.push(IoWriteStep { wait_for, bytes });
    }
    if total > MAX_INFERIOR_INPUT_BYTES {
        return Err(Error::new(
            ErrorCode::OutputLimit,
            "inferior input is limited to 64 KiB per call",
        ));
    }
    Ok(Some(parsed))
}

async fn wait_for_pty(
    handle: &SessionHandle,
    events: &mut broadcast::Receiver<PublishedEvent>,
    cursor: &mut u64,
    prompt: &[u8],
    deadline: Instant,
    step: usize,
    written: usize,
) -> Result<()> {
    let mut pending = Vec::new();
    let mut pending_offset = *cursor;
    let mut scan_offset = *cursor;
    let mut deadline_expired = false;
    loop {
        let read = handle
            .read_output(OutputRing::Inferior, scan_offset, 64 * 1024)
            .await?;
        if read.gap {
            pending.clear();
            pending_offset = read.available_from;
        }
        scan_offset = read.next_offset;
        pending.extend_from_slice(&read.bytes);
        if let Some(found) = pending
            .windows(prompt.len())
            .position(|window| window == prompt)
        {
            *cursor = pending_offset + (found + prompt.len()) as u64;
            return Ok(());
        }
        let keep = prompt.len().saturating_sub(1).max(4 * 1024);
        if pending.len() > keep {
            let discarded = pending.len() - keep;
            pending.drain(..discarded);
            pending_offset += discarded as u64;
        }
        // 2026-09-04: PTY output and its deadline can become ready in the
        // same scheduler turn. Re-read the authoritative ring once after the
        // timer fires so an already-produced prompt is never hidden.
        if deadline_expired {
            return Err(Error::new(
                ErrorCode::Timeout,
                format!("inferior I/O step {step} did not observe its prompt"),
            )
            .with_details(json!({
                "step_index": step,
                "wait_for": String::from_utf8_lossy(prompt),
                "written": written,
                "next_offset": scan_offset,
                "output": byte_content(pending)
            })));
        }
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(PublishedEvent {
                event:
                    DomainEvent::OutputAdvanced {
                        source: OutputSource::InferiorPty,
                        ..
                    },
                ..
            }))
            | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Ok(PublishedEvent { event, .. }))
                if matches!(event, DomainEvent::BackendExited { .. })
                    || handle.state().attributed_exit(&event) =>
            {
                return Err(Error::new(
                    ErrorCode::InvalidState,
                    format!("inferior exited before I/O step {step} observed its prompt"),
                )
                .with_details(json!({
                    "step_index": step,
                    "wait_for": String::from_utf8_lossy(prompt),
                    "written": written,
                    "next_offset": scan_offset,
                    "output": byte_content(pending)
                })));
            }
            Ok(Ok(_)) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                return Err(Error::new(
                    ErrorCode::GdbExited,
                    "session event stream closed during inferior I/O",
                ));
            }
            Err(_) => deadline_expired = true,
        }
    }
}

impl Gateway {
    pub(super) async fn io_read(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let offset = request
            .parameters
            .get("after_offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(64 * 1024)
            .min(64 * 1024) as usize;
        let ring = match request
            .parameters
            .get("stream")
            .and_then(Value::as_str)
            .unwrap_or("pty")
        {
            "pty" => OutputRing::Inferior,
            "target" => OutputRing::Target,
            "console" => OutputRing::Console,
            "log" => OutputRing::Log,
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unknown output stream",
                ));
            }
        };
        let read = entry.handle.read_output(ring, offset, max_bytes).await?;
        let evidence =
            matches!(ring, OutputRing::Inferior).then(|| entry.handle.inferior_output_evidence());
        let mut result = json!({
            "requested_offset": read.requested_offset,
            "available_from": read.available_from,
            "next_offset": read.next_offset,
            "gap": read.gap,
            "evidence": evidence
        });
        result
            .as_object_mut()
            .unwrap()
            .extend(byte_content(read.bytes));
        Ok(result)
    }

    pub(super) async fn io_write(&self, request: &ApiRequest) -> Result<Value> {
        let timeout_ms = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(self.config.server.wait_timeout_ms);
        if timeout_ms > 300_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "inferior I/O timeout must be between 1 and 300000 ms",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        if let Some(steps) = io_write_steps(&request.parameters)? {
            // 2026-09-04: Queuing a whole menu transcript lets broad target
            // reads swallow later answers, while one RPC per prompt made a
            // single setup take 101 Agent calls. Gate each later write on the
            // target's exact PTY prompt and journal the transaction once.
            let mut events = entry.handle.subscribe();
            let mut cursor = entry.handle.inferior_output_position();
            let deadline = Instant::now() + Duration::from_millis(timeout_ms);
            let steps_count = steps.len();
            let mut written = 0usize;
            let outcome: Result<Value> = async {
                for (index, step) in steps.into_iter().enumerate() {
                    if let Some(prompt) = step.wait_for {
                        wait_for_pty(
                            &entry.handle,
                            &mut events,
                            &mut cursor,
                            &prompt,
                            deadline,
                            index,
                            written,
                        )
                        .await?;
                    }
                    if !step.bytes.is_empty() {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        let requested = step.bytes.len();
                        match entry
                            .handle
                            .write_inferior_with_timeout(step.bytes, false, remaining)
                            .await
                        {
                            Ok(step_written) => written += step_written,
                            Err(error) => {
                                let step_written = error
                                    .details
                                    .as_ref()
                                    .and_then(|details| details["written"].as_u64())
                                    .unwrap_or(0)
                                    .min(requested as u64)
                                    as usize;
                                written += step_written;
                                return Err(error.with_details(json!({
                                    "step_index": index,
                                    "step_written": step_written,
                                    "step_remaining": requested - step_written,
                                    "written": written
                                })));
                            }
                        }
                    }
                }
                Ok(json!({ "steps_completed": steps_count, "written": written }))
            }
            .await;
            if written > 0 {
                entry
                    .handle
                    .record_event(DomainEvent::ControllerChanged {
                        kind: "inferior_input".into(),
                    })
                    .await?;
            }
            return outcome;
        }
        let bytes = input_bytes(&request.parameters)?;
        if bytes.len() > MAX_INFERIOR_INPUT_BYTES {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "inferior input is limited to 64 KiB per call",
            ));
        }
        let written = entry
            .handle
            .write_inferior_with_timeout(bytes, false, Duration::from_millis(timeout_ms))
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_input".into(),
            })
            .await?;
        Ok(json!({ "written": written }))
    }

    pub(super) async fn io_send_eof(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        // 2026-08-31: VEOF cannot wake a read already sleeping in raw mode.
        // Require a debugger stop so resume restarts the read in canonical mode.
        if entry.handle.with_state(|state| state.stop_id.is_none()) {
            return Err(Error::new(
                ErrorCode::TargetRunning,
                "send_eof requires a stopped target; interrupt it first",
            ));
        }
        // 2026-08-28: Writing VEOF to a PTY never closes its file descriptor;
        // the old close_stdin result falsely claimed an OS-level half-close.
        // 2026-08-31: One VEOF only releases pending input after raw mode;
        // queue a second boundary so the inferior observes EOF as requested.
        entry
            .handle
            .write_inferior_with_timeout(vec![0x04, 0x04], true, self.config.server.wait_timeout())
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_veof_sent".into(),
            })
            .await?;
        Ok(json!({
            "sent": true,
            "closed": false,
            "mechanism": "pty_veof"
        }))
    }

    pub(super) async fn io_resize(&self, request: &ApiRequest) -> Result<Value> {
        let rows = unsigned(&request.parameters, "rows")?;
        let columns = unsigned(&request.parameters, "columns")?;
        if rows == 0 || columns == 0 || rows > u16::MAX as u64 || columns > u16::MAX as u64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "invalid PTY dimensions",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        entry
            .handle
            .resize_inferior(rows as u16, columns as u16)
            .await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_terminal_resized".into(),
            })
            .await?;
        Ok(json!({ "rows": rows, "columns": columns }))
    }
}

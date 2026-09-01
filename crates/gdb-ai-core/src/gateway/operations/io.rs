use serde_json::{Value, json};

use super::{
    encoding::{MAX_INFERIOR_INPUT_BYTES, byte_content, input_bytes},
    request::{required_session, unsigned},
};
use crate::{
    Error, ErrorCode, Result, domain::DomainEvent, gateway::Gateway, protocol::ApiRequest,
    session::OutputRing,
};

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
        let entry = self.entry(required_session(request)?).await?;
        let bytes = input_bytes(&request.parameters)?;
        if bytes.len() > MAX_INFERIOR_INPUT_BYTES {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "inferior input is limited to 64 KiB per call",
            ));
        }
        let written = entry
            .handle
            .write_inferior_with_timeout(bytes, false, self.config.server.wait_timeout())
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

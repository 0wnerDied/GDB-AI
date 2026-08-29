use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};

use super::{
    encoding::input_bytes,
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
        let text = std::str::from_utf8(&read.bytes).ok().map(str::to_owned);
        let evidence =
            matches!(ring, OutputRing::Inferior).then(|| entry.handle.inferior_output_evidence());
        Ok(json!({
            "requested_offset": read.requested_offset,
            "available_from": read.available_from,
            "next_offset": read.next_offset,
            "gap": read.gap,
            "encoding": if text.is_some() { "utf-8" } else { "binary" },
            "text": text,
            "data_base64": BASE64.encode(read.bytes),
            "evidence": evidence
        }))
    }

    pub(super) async fn io_write(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let bytes = input_bytes(&request.parameters)?;
        if bytes.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorCode::OutputLimit,
                "inferior input is limited to 64 KiB per call",
            ));
        }
        entry.handle.write_inferior(bytes.clone()).await?;
        entry
            .handle
            .record_event(DomainEvent::ControllerChanged {
                kind: "inferior_input".into(),
            })
            .await?;
        Ok(json!({ "written": bytes.len() }))
    }

    pub(super) async fn io_send_eof(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        // 2026-08-28: Writing VEOF to a PTY never closes its file descriptor;
        // the old close_stdin result falsely claimed an OS-level half-close.
        entry.handle.write_inferior(vec![0x04]).await?;
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

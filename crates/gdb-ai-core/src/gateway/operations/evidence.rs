use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::{Value, json};

use super::request::{required_session, string};
use crate::{
    Error, ErrorCode, Result,
    domain::SessionId,
    gateway::{Caller, Gateway, same_principal},
    protocol::ApiRequest,
};

fn event_receive_error(
    error: tokio::sync::broadcast::error::RecvError,
    session_id: &str,
    requested_after: u64,
    current_event_seq: u64,
) -> Error {
    // 2026-08-29: Collapsing lag and closure into INTERNAL gave clients no
    // way to distinguish a recoverable cursor gap from a terminal stream.
    match error {
        tokio::sync::broadcast::error::RecvError::Lagged(skipped) => Error::new(
            ErrorCode::EventGap,
            format!("event subscriber missed {skipped} events"),
        )
        .retryable()
        .with_details(json!({
            "requested_after": requested_after,
            "dropped_events": skipped,
            "available_after": current_event_seq,
            "current_event_seq": current_event_seq,
            "resync": format!("gdbai://session/{session_id}/status")
        })),
        tokio::sync::broadcast::error::RecvError::Closed => {
            Error::new(ErrorCode::StreamClosed, "session event stream closed").with_details(json!({
                "current_event_seq": current_event_seq,
                "session": format!("gdbai://session/{session_id}/status")
            }))
        }
    }
}

impl Gateway {
    pub(super) async fn artifact_get(
        &self,
        request: &ApiRequest,
        caller: &Caller,
    ) -> Result<Value> {
        let uri = string(&request.parameters, "uri")?;
        // 2026-08-28: Content-addressed URIs are identifiers, not bearer
        // credentials. Enforce the creating session's ownership on every read.
        let metadata = self
            .store
            .artifact(&uri)?
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "artifact not found"))?;
        let sessions = self.store.artifact_sessions(&uri)?;
        let mut owned = false;
        for session_id in &sessions {
            let session_id = SessionId::parse(session_id)?;
            if self
                .store
                .session_owner(&session_id)?
                .is_some_and(|owner| same_principal(&owner, &caller.identity))
            {
                owned = true;
                break;
            }
        }
        if !caller.admin && !owned {
            let message = if sessions.is_empty() {
                "global artifacts require administrative access"
            } else {
                "artifact belongs to another session owner"
            };
            return Err(Error::new(ErrorCode::PolicyDenied, message));
        }
        let offset = request
            .parameters
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let inline_maximum = (self.config.limits.tool_response_bytes / 4).clamp(1, 64 * 1024);
        let max_bytes = request
            .parameters
            .get("max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(inline_maximum as u64)
            .min(inline_maximum as u64) as usize;
        if max_bytes == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "artifact max_bytes must be positive",
            ));
        }
        // 2026-08-28: Inlining a complete large artifact caused the outer
        // response limiter to replace it with another artifact. Page raw bytes
        // below the envelope budget instead.
        // 2026-08-29: The first range read verifies the complete artifact;
        // running that hash on a Tokio worker stalled unrelated requests.
        let artifacts = self.artifacts.clone();
        let artifact_uri = uri.clone();
        let (bytes, total_bytes) = tokio::task::spawn_blocking(move || {
            artifacts.get_range(&artifact_uri, offset, max_bytes)
        })
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("artifact read task failed: {error}"),
            )
        })??;
        let next_offset = offset + bytes.len() as u64;
        Ok(json!({
            "uri": uri,
            "size": total_bytes,
            "sensitivity": metadata.sensitivity,
            "max_page_bytes": inline_maximum,
            "offset": offset,
            "next_offset": next_offset,
            "data_base64": BASE64.encode(bytes),
            "truncated": next_offset < total_bytes
        }))
    }

    pub(super) async fn events_wait(&self, request: &ApiRequest) -> Result<Value> {
        let entry = self.entry(required_session(request)?).await?;
        let after = request
            .parameters
            .get("after_event_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // 2026-08-28: Reading state before subscribing lost an event emitted
        // in the gap and left a waiter blocked until timeout. Subscribe first,
        // then use state as the coalescing check for that race window.
        let mut events = entry.handle.subscribe();
        if let Some(current) = entry
            .handle
            .with_state(|state| (state.event_seq > after).then(|| state.clone()))
        {
            return Ok(json!({ "state": current, "coalesced": true }));
        }
        let timeout_ms = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5_000);
        if timeout_ms == 0 || timeout_ms > 300_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "event timeout must be between 1 and 300000 ms",
            ));
        }
        let event = tokio::time::timeout(Duration::from_millis(timeout_ms), events.recv())
            .await
            .map_err(|_| Error::new(ErrorCode::Timeout, "event wait timed out").retryable())?
            .map_err(|error| {
                let (session_id, event_seq) = entry
                    .handle
                    .with_state(|state| (state.session_id.0.clone(), state.event_seq));
                // 2026-08-29: Typed EVENT_GAP errors were visible to callers
                // but absent from operational metrics, hiding resync pressure.
                if matches!(&error, tokio::sync::broadcast::error::RecvError::Lagged(_)) {
                    self.metrics.event_gap();
                }
                event_receive_error(error, &session_id, after, event_seq)
            })?;
        Ok(serde_json::to_value(event)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_errors_preserve_resynchronization_semantics() {
        let gap = event_receive_error(
            tokio::sync::broadcast::error::RecvError::Lagged(7),
            "sess_test",
            10,
            30,
        );
        assert_eq!(gap.code, ErrorCode::EventGap);
        assert!(gap.retryable);
        assert_eq!(gap.details.as_ref().unwrap()["dropped_events"], 7);
        assert_eq!(gap.details.as_ref().unwrap()["available_after"], 30);
        assert_eq!(
            gap.details.as_ref().unwrap()["resync"],
            "gdbai://session/sess_test/status"
        );

        let closed = event_receive_error(
            tokio::sync::broadcast::error::RecvError::Closed,
            "sess_test",
            10,
            30,
        );
        assert_eq!(closed.code, ErrorCode::StreamClosed);
        assert!(!closed.retryable);
    }
}

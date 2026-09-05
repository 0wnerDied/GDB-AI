use std::time::Duration;

use gdb_ai_mi::MiRecord;
use serde_json::{Value, json};

use super::{
    encoding::{byte_content, first_word},
    reconciliation::{
        reconcile_breakpoints, reconcile_inferiors, reconcile_libraries, reconcile_threads,
        reconciliation_command,
    },
    request::{required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::DomainEvent,
    gateway::{Gateway, SessionEntry},
    policy::validate_console_command,
    protocol::ApiRequest,
};

impl Gateway {
    pub(super) async fn raw_console(&self, request: &ApiRequest) -> Result<Value> {
        self.metrics.raw_command();
        let command_text = string(&request.parameters, "command")?;
        validate_console_command(&command_text)?;
        let entry = self.entry(required_session(request)?).await?;
        let timeout = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(2_000);
        if timeout == 0 || timeout > 60_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw command timeout must be between 1 and 60000 ms",
            ));
        }
        // 2026-08-28: Invalid raw arguments used to taint state before any
        // command was sent. Record the effect only after validation succeeds.
        entry
            .handle
            .record_event(DomainEvent::ConsistencyTainted {
                reason: format!(
                    "raw console command executed: {}",
                    first_word(&command_text)
                ),
            })
            .await?;
        // 2026-08-31: Propagating a raw command error before reconciliation
        // made the next request pay for recovery and then fail its revision.
        // Reconcile definitive GDB errors, but preserve timeout fences.
        let reply = match entry
            .handle
            .command_with_timeout(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(command_text),
                Duration::from_millis(timeout),
            )
            .await
        {
            Ok(reply) => reply,
            Err(error) if error.code == ErrorCode::GdbError => {
                let _ = self.reconcile_session(&entry, false).await;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let reconciliation = self.reconcile_session(&entry, false).await?;
        let mut result = json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        });
        // 2026-09-05: Runtime helper output was exposed only as MI byte
        // arrays or a later console-ring read. Keep each stream in this turn.
        let (mut console, mut target, mut log) = (Vec::new(), Vec::new(), Vec::new());
        for record in &reply.stream_records {
            match record {
                MiRecord::ConsoleStream(bytes) => console.extend_from_slice(bytes),
                MiRecord::TargetStream(bytes) => target.extend_from_slice(bytes),
                MiRecord::LogStream(bytes) => log.extend_from_slice(bytes),
                _ => {}
            }
        }
        for (name, bytes) in [("console", console), ("target", target), ("log", log)] {
            if !bytes.is_empty() {
                result[name] = Value::Object(byte_content(bytes));
            }
        }
        if reply.stream_truncated {
            result["truncated"] = Value::Bool(true);
        }
        Ok(result)
    }

    pub(super) async fn raw_mi(&self, request: &ApiRequest) -> Result<Value> {
        self.metrics.raw_command();
        let name = string(&request.parameters, "command")?;
        if raw_mi_is_denied(&name) {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "raw MI command bypasses a protected host or target boundary",
            ));
        }
        let managed = raw_mi_is_managed(&name);
        let entry = self.entry(required_session(request)?).await?;
        let mut command = MiCommand::new(name.clone())?;
        let arguments = request
            .parameters
            .get("arguments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if arguments.len() > 64 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw MI accepts at most 64 arguments",
            ));
        }
        let mut argument_bytes = 0usize;
        for argument in arguments {
            let (kind, value) = if let Some(value) = argument.as_str() {
                ("string", value.to_owned())
            } else {
                (
                    argument
                        .get("kind")
                        .and_then(Value::as_str)
                        .unwrap_or("string"),
                    string(&argument, "value")?,
                )
            };
            argument_bytes = argument_bytes.saturating_add(value.len());
            if argument_bytes > 16 * 1024 {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "raw MI arguments exceed 16384 bytes",
                ));
            }
            command = match kind {
                "bare" => command.bare(value)?,
                "string" => command.string(value),
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "raw MI argument kind must be bare or string",
                    ));
                }
            };
        }
        let timeout = request
            .parameters
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(2_000);
        if timeout == 0 || timeout > 60_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "raw command timeout must be between 1 and 60000 ms",
            ));
        }
        entry
            .handle
            .record_event(if managed {
                DomainEvent::ConsistencyDirty {
                    reason: format!("managed raw MI command executed: {name}"),
                }
            } else {
                DomainEvent::ConsistencyTainted {
                    reason: format!("unknown raw MI command executed: {name}"),
                }
            })
            .await?;
        let reply = match entry
            .handle
            .command_with_timeout(command, Duration::from_millis(timeout))
            .await
        {
            Ok(reply) => reply,
            Err(error) if error.code == ErrorCode::GdbError => {
                let _ = self.reconcile_session(&entry, managed).await;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let reconciliation = self.reconcile_session(&entry, managed).await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        }))
    }

    pub(in crate::gateway) async fn reconcile_session(
        &self,
        entry: &SessionEntry,
        restore_clean: bool,
    ) -> Result<Value> {
        self.metrics.reconciliation();
        let can_restore = restore_clean
            && entry.handle.with_state(|state| state.consistency)
                != crate::domain::Consistency::Tainted;
        if can_restore {
            entry
                .handle
                .record_event(DomainEvent::ConsistencyReconciling)
                .await?;
        }
        let mut warnings = Vec::new();
        let groups = reconciliation_command(
            &entry.handle,
            MiCommand::new("-list-thread-groups")?
                .bare("--recurse")?
                .bare("1")?,
            "thread groups",
            &mut warnings,
        )
        .await;
        let threads = reconciliation_command(
            &entry.handle,
            MiCommand::new("-thread-info")?,
            "threads",
            &mut warnings,
        )
        .await;
        let breakpoints = reconciliation_command(
            &entry.handle,
            MiCommand::new("-break-list")?,
            "breakpoints",
            &mut warnings,
        )
        .await;
        let libraries = reconciliation_command(
            &entry.handle,
            MiCommand::new("-file-list-shared-libraries")?,
            "shared libraries",
            &mut warnings,
        )
        .await;

        if let Some(reply) = &groups {
            reconcile_inferiors(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &threads {
            reconcile_threads(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &breakpoints {
            reconcile_breakpoints(&entry.handle, &reply.record).await?;
        }
        if let Some(reply) = &libraries {
            reconcile_libraries(&entry.handle, &reply.record).await?;
        }
        let capabilities = match entry.handle.refresh_target_capabilities().await {
            Ok(capabilities) => Some(capabilities),
            Err(error) => {
                warnings.push(format!("target features: {error}"));
                None
            }
        };
        if can_restore && (groups.is_none() || threads.is_none() || breakpoints.is_none()) {
            entry
                .handle
                .record_event(DomainEvent::ConsistencyLost {
                    reason: "reconciliation could not recover required registries".into(),
                })
                .await?;
            return Err(Error::new(
                ErrorCode::ConsistencyLost,
                "reconciliation could not recover required registries",
            ));
        }
        entry
            .handle
            .record_event(DomainEvent::ConsistencyRestored {
                warnings: warnings.clone(),
            })
            .await?;
        Ok(json!({
            "status": if can_restore { "clean" } else { "tainted" },
            "warnings": warnings,
            "capabilities": capabilities,
            "managed_surface": ["inferiors", "threads", "breakpoints", "libraries", "target_features"]
        }))
    }
}

fn raw_mi_is_managed(command: &str) -> bool {
    [
        "-break-",
        "-exec-",
        "-gdb-show",
        "-list-thread-groups",
        "-list-target-features",
        "-file-list-shared-libraries",
        "-stack-list-",
        "-stack-select-frame",
        "-thread-info",
        "-thread-select",
    ]
    .iter()
    .any(|prefix| command.starts_with(prefix))
}

// 2026-08-28: Raw MI previously bypassed workspace, attach, remote endpoint,
// and safe-startup policy. Protected setup operations use their semantic APIs.
fn raw_mi_is_denied(command: &str) -> bool {
    matches!(
        command,
        "-interpreter-exec"
            | "-gdb-exit"
            | "-gdb-set"
            | "-target-select"
            | "-target-attach"
            | "-target-file-get"
            | "-target-file-put"
            | "-target-file-delete"
            | "-file-exec-and-symbols"
            | "-file-exec-file"
            | "-file-symbol-file"
            | "-environment-cd"
            | "-inferior-tty-set"
    )
}

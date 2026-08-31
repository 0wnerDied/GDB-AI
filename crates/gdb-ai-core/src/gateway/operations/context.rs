use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use super::{
    execution::breakpoint_location,
    request::{string, unsigned},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{StopId, WaitBaseline},
    gateway::Gateway,
    providers::live_module_offset,
    session::{SessionHandle, WaitUntil},
};

impl Gateway {
    pub(super) fn workspace_path(
        &self,
        value: &str,
        directory: bool,
    ) -> Result<std::path::PathBuf> {
        let path = std::fs::canonicalize(value).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("cannot canonicalize path {value:?}: {error}"),
            )
        })?;
        // 2026-08-31: Treating every non-directory as a file admitted FIFOs,
        // sockets, and devices into source and target paths. File inputs must
        // resolve to regular files before any potentially blocking open.
        let expected_type = if directory {
            path.is_dir()
        } else {
            path.is_file()
        };
        if !expected_type {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                if directory {
                    "path is not a directory"
                } else {
                    "path is not a file"
                },
            ));
        }
        let allowed = self
            .config
            .security
            .workspace_roots
            .iter()
            .any(|root| std::fs::canonicalize(root).is_ok_and(|root| path.starts_with(root)));
        if !allowed {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "path escapes configured workspace roots",
            ));
        }
        Ok(path)
    }

    pub(super) fn breakpoint_location(
        &self,
        parameters: &Value,
        state: &crate::domain::SessionState,
    ) -> Result<(String, Option<(String, u64)>)> {
        let location = parameters.get("location").unwrap_or(parameters);
        if let Some(source) = location.get("source") {
            // 2026-08-28: Source breakpoints previously bypassed workspace
            // canonicalization even though every other target path was checked.
            let path = self.workspace_path(&string(source, "path")?, false)?;
            return Ok((
                format!("{}:{}", path.to_string_lossy(), unsigned(source, "line")?),
                None,
            ));
        }
        if let Some(module_offset) = location.get("module_offset") {
            let module = string(module_offset, "module")?;
            let offset = crate::domain::Address::parse(&string(module_offset, "offset")?)?;
            let offset = u64::from_str_radix(&offset.as_str()[2..], 16)
                .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid module offset"))?;
            // 2026-08-28: GDB does not report a loader-launched stripped PIE
            // as a shared library, so `module+offset` remained pending. The
            // existing local mapping provider supplies the actual load bias.
            if let Some(address) = live_module_offset(state, &module, offset)? {
                // 2026-09-01: Dropping metadata after immediate resolution
                // left the absolute breakpoint stale on the next ASLR run.
                return Ok((format!("*{address}"), Some((module, offset))));
            }
            return Ok((breakpoint_location(parameters)?, Some((module, offset))));
        }
        Ok((breakpoint_location(parameters)?, None))
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WaitSpec {
    pub(super) until: String,
    #[serde(default = "default_wait_ms")]
    pub(super) timeout_ms: u64,
}

impl WaitSpec {
    pub(super) fn validate(&self) -> Result<()> {
        // 2026-08-28: Wait validation once ran after the associated control
        // command, so invalid input could resume or kill a target before erroring.
        if !matches!(
            self.until.as_str(),
            "accepted" | "running" | "stopped" | "settled" | "snapshot" | "exited"
        ) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unknown wait condition",
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "wait timeout must be between 1 and 300000 ms",
            ));
        }
        Ok(())
    }
}

pub(super) fn default_wait_ms() -> u64 {
    5_000
}

pub(super) fn wait_spec(parameters: &Value) -> Result<Option<WaitSpec>> {
    let wait: Option<WaitSpec> = parameters
        .get("wait")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| Error::new(ErrorCode::InvalidArgument, error.to_string()))?;
    if let Some(wait) = &wait {
        wait.validate()?;
    }
    Ok(wait)
}

pub(super) async fn wait_if_requested(
    handle: &SessionHandle,
    wait: Option<WaitSpec>,
    baseline: Option<&crate::domain::SessionState>,
) -> Result<crate::domain::SessionState> {
    match wait {
        Some(wait) => apply_wait(handle, wait, baseline).await,
        None => Ok(handle.state()),
    }
}

pub(super) async fn apply_wait(
    handle: &SessionHandle,
    wait: WaitSpec,
    baseline: Option<&crate::domain::SessionState>,
) -> Result<crate::domain::SessionState> {
    let baseline = baseline.map(WaitBaseline::from);
    apply_wait_baseline(handle, wait, baseline.as_ref(), None).await
}

pub(super) async fn apply_wait_baseline(
    handle: &SessionHandle,
    wait: WaitSpec,
    baseline: Option<&WaitBaseline>,
    expected_execution_epoch: Option<u64>,
) -> Result<crate::domain::SessionState> {
    wait.validate()?;
    let until = match wait.until.as_str() {
        "accepted" => return Ok(handle.state()),
        "running" => WaitUntil::Running,
        "stopped" => WaitUntil::Stopped,
        "settled" => WaitUntil::Settled,
        "snapshot" => WaitUntil::Snapshot,
        "exited" => WaitUntil::Exited,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "unknown wait condition",
            ));
        }
    };
    let timeout = Duration::from_millis(wait.timeout_ms);
    match (baseline, expected_execution_epoch) {
        (Some(baseline), Some(expected_execution_epoch)) => {
            handle
                .wait_for_operation(until, timeout, baseline, expected_execution_epoch)
                .await
        }
        (Some(baseline), None) => handle.wait_after_baseline(until, timeout, baseline).await,
        (None, _) => handle.wait(until, timeout).await,
    }
}

pub(super) fn context_options(
    mut command: MiCommand,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<MiCommand> {
    if let Some(stop) = parameters.get("stop_id").and_then(Value::as_str) {
        state.require_stop(&StopId(stop.to_owned()))?;
    }
    let requested_thread = parameters
        .get("thread_id")
        .and_then(Value::as_str)
        .map(|public_thread| current_backend_thread(state, public_thread))
        .transpose()?;
    let mut frame_level = parameters.get("frame_level").and_then(Value::as_u64);
    let frame_thread = if let Some(frame) = parameters.get("frame_id").and_then(Value::as_str) {
        let stop = state.stop_id.as_ref().ok_or_else(|| {
            Error::new(ErrorCode::TargetRunning, "frame requires a stopped target")
        })?;
        let (backend_thread, level) = state
            .inferiors
            .values()
            .flat_map(|inferior| inferior.threads.values())
            .find_map(|thread| {
                let prefix = if thread.id.0.starts_with("thr_") || stop.0.starts_with("stop_") {
                    format!("frm_{}_{}_", thread.id.0, stop.0)
                } else {
                    format!("f{}_{}_", thread.id.0, stop.0)
                };
                frame
                    .strip_prefix(&prefix)
                    .and_then(|level| level.parse::<u64>().ok())
                    .map(|level| (thread.backend_id.clone(), level))
            })
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::StaleContext,
                    "frame handle is not current for this stop",
                )
            })?;
        frame_level = Some(level);
        Some(backend_thread)
    } else {
        None
    };
    if let (Some(requested), Some(frame)) = (&requested_thread, &frame_thread)
        && requested != frame
    {
        return Err(Error::new(
            ErrorCode::StaleContext,
            "thread and frame handles refer to different threads",
        ));
    }
    // 2026-08-28: Frame handles supplied only a frame level to GDB, leaving
    // their owning thread implicit. On a multi-thread stop this could inspect
    // a different selected thread. Encode the frame's thread and stop focus.
    let backend_thread = requested_thread.or(frame_thread).or_else(|| {
        command_uses_stop_focus(&command.name)
            .then_some(state.stopped_thread_id.as_ref())
            .flatten()
            .and_then(|thread| current_backend_thread(state, &thread.0).ok())
    });
    let mut contextual = MiCommand::new(command.name.clone())?;
    if let Some(backend_thread) = backend_thread {
        contextual = contextual.bare("--thread")?.bare(backend_thread)?;
    }
    if frame_level.is_none() && command_uses_top_frame(&command.name) {
        frame_level = Some(0);
    }
    if let Some(level) = frame_level {
        contextual = contextual.bare("--frame")?.bare(level.to_string())?;
    }
    // 2026-08-28: Context options belong before positional MI arguments.
    // Several callers build expressions first, so appending options made
    // explicit context syntactically ineffective or invalid.
    contextual.arguments.append(&mut command.arguments);
    Ok(contextual)
}

pub(super) fn current_backend_thread(
    state: &crate::domain::SessionState,
    public_thread: &str,
) -> Result<String> {
    state
        .inferiors
        .values()
        .flat_map(|inferior| inferior.threads.values())
        .find(|thread| thread.id.0 == public_thread)
        .map(|thread| thread.backend_id.clone())
        .ok_or_else(|| Error::new(ErrorCode::StaleContext, "thread handle is not current"))
}

pub(super) fn command_uses_stop_focus(command: &str) -> bool {
    matches!(
        command,
        "-exec-step"
            | "-exec-next"
            | "-exec-finish"
            | "-exec-step-instruction"
            | "-exec-next-instruction"
            | "-exec-until"
            | "-stack-info-frame"
            | "-stack-list-frames"
            | "-stack-list-variables"
            | "-stack-list-arguments"
            | "-data-evaluate-expression"
            | "-data-list-register-values"
            | "-var-create"
    )
}

pub(super) fn command_uses_top_frame(command: &str) -> bool {
    matches!(
        command,
        "-stack-info-frame"
            | "-stack-list-variables"
            | "-data-evaluate-expression"
            | "-data-list-register-values"
            | "-var-create"
    )
}

pub(super) fn require_stopped_context(
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<()> {
    let stop = state.stop_id.as_ref().ok_or_else(|| {
        Error::new(
            ErrorCode::TargetRunning,
            "inspection requires stopped target",
        )
    })?;
    if let Some(expected) = parameters.get("stop_id").and_then(Value::as_str) {
        state.require_stop(&StopId(expected.to_owned()))?;
    } else if parameters
        .get("accept_current_stop")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(Error::new(
            ErrorCode::StaleContext,
            format!("inspection requires stop_id (current is {stop})"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{ArtifactConfig, Config, PersistenceConfig},
        domain::{DomainEvent, FrameId, JournaledEvent, SessionId, SessionState, StopReason},
        reducer::StateReducer,
    };
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn workspace_file_paths_reject_special_files() {
        let directory = tempdir().unwrap();
        let fifo = directory.path().join("source.fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let mut config = Config {
            artifacts: ArtifactConfig {
                path: directory.path().join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: directory.path().join("state.sqlite"),
                sessions: directory.path().join("sessions"),
            },
            ..Config::default()
        };
        config.security.workspace_roots = vec![directory.path().to_owned()];
        let gateway = Gateway::new(config).unwrap();

        let error = gateway
            .workspace_path(&fifo.to_string_lossy(), false)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn frame_context_encodes_its_thread_before_positional_arguments() {
        let mut reducer = StateReducer::new(SessionState::creating(SessionId("sess_ctx".into())));
        for (seq, event) in [
            (
                1,
                DomainEvent::InferiorAdded {
                    backend_id: "i1".into(),
                    pid: Some(7),
                },
            ),
            (
                2,
                DomainEvent::ThreadCreated {
                    backend_inferior: "i1".into(),
                    backend_thread: "1".into(),
                },
            ),
            (
                3,
                DomainEvent::ThreadCreated {
                    backend_inferior: "i1".into(),
                    backend_thread: "2".into(),
                },
            ),
            (
                4,
                DomainEvent::TargetStopped {
                    backend_inferior: Some("i1".into()),
                    backend_thread: Some("2".into()),
                    reason: "breakpoint-hit".into(),
                    reason_detail: Some(StopReason::Breakpoint {
                        backend_number: Some("1".into()),
                        disposition: Some("keep".into()),
                    }),
                    frame: None,
                },
            ),
        ] {
            reducer
                .apply(&JournaledEvent::for_replay(seq, event))
                .unwrap();
        }
        let state = reducer.state();
        let stop = state.stop_id.as_ref().unwrap();
        let stopped_thread = state.stopped_thread_id.as_ref().unwrap();
        let frame = FrameId::new(stopped_thread, stop, 3);
        let command = context_options(
            MiCommand::new("-data-evaluate-expression")
                .unwrap()
                .string("$pc"),
            &json!({"stop_id": stop, "frame_id": frame}),
            state,
        )
        .unwrap();
        assert_eq!(
            command.encoded(1),
            b"1-data-evaluate-expression --thread 2 --frame 3 \"$pc\"\n"
        );

        let other_thread = &state.inferiors["i1"].threads["1"].id;
        let error = context_options(
            MiCommand::new("-stack-info-frame").unwrap(),
            &json!({
                "stop_id": stop,
                "thread_id": other_thread,
                "frame_id": frame
            }),
            state,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::StaleContext);

        let focused = context_options(
            MiCommand::new("-data-evaluate-expression")
                .unwrap()
                .string("$pc"),
            &json!({"stop_id": stop}),
            state,
        )
        .unwrap();
        assert_eq!(
            focused.encoded(2),
            b"2-data-evaluate-expression --thread 2 --frame 0 \"$pc\"\n"
        );
    }
}

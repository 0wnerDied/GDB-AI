use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    OfflineCore,
    LiveObserver,
    #[default]
    DebugControl,
    LabMutation,
    RawAdmin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Read,
    VolatileTargetRead,
    Control,
    TargetMutation,
    HostMutation,
    Network,
    Raw,
}

impl Profile {
    pub fn authorize_method(self, method: &str, effect: Effect) -> Result<()> {
        // 2026-08-28: Read-only profiles could create sessions but could not
        // acquire a lease, open a core, or close their own session.
        if matches!(
            method,
            "session.create"
                | "session.close"
                | "session.acquire_write_lease"
                | "session.release_write_lease"
        ) || (self == Self::OfflineCore && method == "target.open_core")
        {
            return Ok(());
        }
        self.authorize(effect)
    }

    pub fn authorize(self, effect: Effect) -> Result<()> {
        let allowed = match self {
            Self::OfflineCore | Self::LiveObserver => effect == Effect::Read,
            Self::DebugControl => matches!(effect, Effect::Read | Effect::Control),
            Self::LabMutation => {
                matches!(
                    effect,
                    Effect::Read
                        | Effect::VolatileTargetRead
                        | Effect::Control
                        | Effect::TargetMutation
                )
            }
            Self::RawAdmin => true,
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::PolicyDenied,
                format!("profile {self:?} does not permit effect {effect:?}"),
            ))
        }
    }
}

pub fn effect_for_method(method: &str) -> Option<Effect> {
    Some(match method {
        method
            if method.starts_with("session.get")
                || method.starts_with("session.list")
                || method == "session.capabilities"
                || method == "session.providers"
                || method == "session.transcript"
                || method == "session.event"
                || method.starts_with("inspection.")
                || method == "value.evaluate"
                || method == "value.children"
                || method == "value.update"
                || method == "memory.read"
                || method == "memory.search"
                || method == "memory.compare"
                || method == "register.read"
                || method == "disassembly.read"
                || method == "inferior_io.read"
                || method == "execution.wait"
                || method == "tracking.list"
                || method == "breakpoint.list"
                || method == "signal.get"
                || method == "agent.hypothesis_check"
                || method == "kernel.inspect"
                || method == "artifact.get"
                || method == "events.wait" =>
        {
            Effect::Read
        }
        "target.connect_remote" => Effect::Network,
        "memory.write"
        | "register.write"
        | "inferior.call"
        | "inferior_io.write"
        | "inferior_io.close_stdin"
        | "inferior_io.resize" => Effect::TargetMutation,
        "raw.mi" | "raw.console" | "kernel.monitor" => Effect::Raw,
        method
            if method.starts_with("target.")
                || method.starts_with("execution.")
                || method.starts_with("breakpoint.")
                || method.starts_with("tracking.")
                || method == "signal.update"
                || method == "agent.probe"
                || method == "agent.experiment"
                || method == "value.create"
                || method == "value.release" =>
        {
            Effect::Control
        }
        "session.create"
        | "session.close"
        | "session.acquire_write_lease"
        | "session.release_write_lease"
        | "session.attempt_recovery" => Effect::Control,
        _ => return None,
    })
}

pub fn validate_console_command(command: &str) -> Result<()> {
    // 2026-08-28: Prefix validation alone allowed a newline to append a
    // second denied CLI command inside one interpreter-exec request.
    if command.is_empty()
        || command.len() > 16 * 1024
        || command
            .bytes()
            .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(Error::new(
            ErrorCode::PolicyDenied,
            "raw console command is empty, oversized, or multiline",
        ));
    }
    let normalized = command.trim().to_ascii_lowercase();
    let verb = normalized.split_whitespace().next().unwrap_or_default();
    // 2026-08-28: GDB accepts abbreviated commands, so a deny-list for
    // "shell", "python", and "quit" could be bypassed with sh, py, or q.
    // Raw console remains useful through an explicit host-safe command set.
    let allowed = [
        "apropos",
        "backtrace",
        "break",
        "catch",
        "condition",
        "continue",
        "delete",
        "disable",
        "disassemble",
        "down",
        "enable",
        "finish",
        "frame",
        "help",
        "ignore",
        "info",
        "list",
        "next",
        "nexti",
        "print",
        "ptype",
        "rbreak",
        "run",
        "show",
        "step",
        "stepi",
        "tbreak",
        "thread",
        "until",
        "up",
        "watch",
        "whatis",
        "x",
    ];
    if !allowed.contains(&verb) {
        Err(Error::new(
            ErrorCode::PolicyDenied,
            "raw console command is outside the host-safe allowlist",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_profiles_do_not_escalate() {
        assert!(Profile::DebugControl.authorize(Effect::Control).is_ok());
        assert!(
            Profile::DebugControl
                .authorize(Effect::TargetMutation)
                .is_err()
        );
        assert!(Profile::LabMutation.authorize(Effect::Raw).is_err());
        assert!(Profile::RawAdmin.authorize(Effect::Raw).is_ok());
        assert!(
            Profile::OfflineCore
                .authorize_method("target.open_core", Effect::Control)
                .is_ok()
        );
        assert!(
            Profile::OfflineCore
                .authorize_method("breakpoint.create", Effect::Control)
                .is_err()
        );
    }

    #[test]
    fn console_validation_blocks_host_escape_classes() {
        for command in [
            "shell id",
            " Python ",
            "set auto-load yes",
            "monitor reset",
            "show language\nshell id",
            "sh id",
            "q",
            "target remote 127.0.0.1:1234",
        ] {
            assert!(validate_console_command(command).is_err(), "{command}");
        }
        assert!(validate_console_command("info registers").is_ok());
    }
}

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
    Control,
    TargetMutation,
    HostMutation,
    Network,
    Raw,
}

impl Profile {
    pub fn authorize(self, effect: Effect) -> Result<()> {
        let allowed = match self {
            Self::OfflineCore | Self::LiveObserver => effect == Effect::Read,
            Self::DebugControl => matches!(effect, Effect::Read | Effect::Control),
            Self::LabMutation => {
                matches!(
                    effect,
                    Effect::Read | Effect::Control | Effect::TargetMutation
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
                || method == "tracking.list"
                || method == "breakpoint.list"
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
        "raw.mi" | "raw.console" => Effect::Raw,
        method
            if method.starts_with("target.")
                || method.starts_with("execution.")
                || method.starts_with("breakpoint.")
                || method.starts_with("tracking.")
                || method == "value.create"
                || method == "value.release" =>
        {
            Effect::Control
        }
        "session.create"
        | "session.close"
        | "session.acquire_write_lease"
        | "session.release_write_lease" => Effect::Control,
        _ => return None,
    })
}

pub fn validate_console_command(command: &str) -> Result<()> {
    let normalized = command.trim().to_ascii_lowercase();
    let denied = [
        "shell",
        "python",
        "source",
        "define",
        "document",
        "commands",
        "if",
        "while",
        "end",
        "interpreter-exec",
        "maintenance",
        "monitor",
        "add-auto-load-safe-path",
        "set auto-load",
        "set debuginfod enabled",
        "set startup-with-shell",
        "set exec-wrapper",
    ];
    if denied.iter().any(|prefix| {
        normalized == *prefix
            || normalized
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with(char::is_whitespace))
    }) {
        Err(Error::new(
            ErrorCode::PolicyDenied,
            "raw console command belongs to a denied command class",
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
    }

    #[test]
    fn console_validation_blocks_host_escape_classes() {
        for command in ["shell id", " Python ", "set auto-load yes", "monitor reset"] {
            assert!(validate_console_command(command).is_err(), "{command}");
        }
        assert!(validate_console_command("info registers").is_ok());
    }
}

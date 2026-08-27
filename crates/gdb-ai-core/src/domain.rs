use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{Error, ErrorCode, Result};

macro_rules! public_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new() -> Self {
                Self(format!(concat!($prefix, "_{}"), Ulid::new()))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.starts_with(concat!($prefix, "_")) {
                    Ok(Self(value))
                } else {
                    Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid {} identifier", $prefix),
                    ))
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

public_id!(SessionId, "sess");
public_id!(BreakpointId, "bp");
public_id!(OperationId, "op");
public_id!(LeaseId, "lease");
public_id!(TrackingId, "track");

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StopId(pub String);

impl StopId {
    pub fn from_event(session: &SessionId, event_seq: u64) -> Self {
        Self(format!("stop_{}_{event_seq}", session.0))
    }
}

impl fmt::Display for StopId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InferiorId(pub String);

impl InferiorId {
    pub fn from_backend(session: &SessionId, generation: u64, backend_id: &str) -> Self {
        Self(format!(
            "inf_{}_{}_{}",
            session.0,
            generation,
            safe_component(backend_id)
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreadId(pub String);

impl ThreadId {
    pub fn from_backend(inferior: &InferiorId, generation: u64, backend_id: &str) -> Self {
        Self(format!(
            "thr_{}_{}_{}",
            inferior.0,
            generation,
            safe_component(backend_id)
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FrameId(pub String);

impl FrameId {
    pub fn new(thread: &ThreadId, stop: &StopId, level: u32) -> Self {
        Self(format!("frm_{}_{}_{}", thread.0, stop.0, level))
    }
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address(String);

impl Address {
    pub fn parse(value: &str) -> Result<Self> {
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "address must start with 0x"))?;
        if digits.is_empty()
            || digits.len() > 16
            || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "address must contain 1 to 16 hexadecimal digits",
            ));
        }
        let number = u64::from_str_radix(digits, 16)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid address"))?;
        Ok(Self(format!("0x{number:016x}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionLifecycle {
    Creating,
    Ready,
    Active,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackendHealth {
    Starting,
    Healthy,
    Busy,
    Unresponsive,
    Dead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InferiorStatus {
    Empty,
    Connecting,
    Stopped,
    Running,
    Exited,
    Detached,
    Disconnected,
    Core,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Consistency {
    Clean,
    ManagedDirty,
    Reconciling,
    Tainted,
    Lost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSummary {
    pub level: u32,
    pub address: Option<String>,
    pub function: Option<String>,
    pub source: Option<String>,
    pub line: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadState {
    pub id: ThreadId,
    pub backend_id: String,
    pub running: bool,
    pub frame: Option<FrameSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferiorState {
    pub id: InferiorId,
    pub backend_id: String,
    pub pid: Option<u64>,
    pub generation: u64,
    pub status: InferiorStatus,
    pub exit_code: Option<String>,
    pub threads: BTreeMap<String, ThreadState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotStatus {
    Building,
    Ready,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRef {
    pub snapshot_id: String,
    pub stop_id: StopId,
    pub status: SnapshotStatus,
    pub partial: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakpointState {
    pub id: BreakpointId,
    pub backend_number: String,
    pub enabled: bool,
    pub pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleState {
    pub id: String,
    pub target_name: Option<String>,
    pub host_name: Option<String>,
    pub symbols_loaded: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: SessionId,
    pub lifecycle: SessionLifecycle,
    pub backend: BackendHealth,
    pub consistency: Consistency,
    pub event_seq: u64,
    pub revision: u64,
    pub execution_epoch: u64,
    pub stop_id: Option<StopId>,
    pub stop_reason: Option<String>,
    pub inferiors: BTreeMap<String, InferiorState>,
    pub breakpoints: BTreeMap<String, BreakpointState>,
    pub modules: BTreeMap<String, ModuleState>,
    pub snapshot: Option<SnapshotRef>,
    pub limitations: Vec<String>,
}

impl SessionState {
    pub fn creating(session_id: SessionId) -> Self {
        Self {
            session_id,
            lifecycle: SessionLifecycle::Creating,
            backend: BackendHealth::Starting,
            consistency: Consistency::Clean,
            event_seq: 0,
            revision: 0,
            execution_epoch: 0,
            stop_id: None,
            stop_reason: None,
            inferiors: BTreeMap::new(),
            breakpoints: BTreeMap::new(),
            modules: BTreeMap::new(),
            snapshot: None,
            limitations: Vec::new(),
        }
    }

    pub fn require_revision(&self, expected: u64) -> Result<()> {
        if self.revision == expected {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::StaleRevision,
                format!(
                    "expected revision {expected}, current revision is {}",
                    self.revision
                ),
            ))
        }
    }

    pub fn require_stop(&self, stop_id: &StopId) -> Result<()> {
        if self.stop_id.as_ref() == Some(stop_id) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::StaleContext,
                format!(
                    "context belongs to {stop_id}, current stop is {:?}",
                    self.stop_id
                ),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DomainEvent {
    SessionClosing,
    SessionClosed,
    BackendStarted,
    BackendExited {
        status: Option<i32>,
    },
    TargetRunning {
        backend_inferiors: Vec<String>,
    },
    TargetStopped {
        backend_inferior: Option<String>,
        backend_thread: Option<String>,
        reason: String,
        frame: Option<FrameSummary>,
    },
    InferiorAdded {
        backend_id: String,
        pid: Option<u64>,
    },
    InferiorRemoved {
        backend_id: String,
    },
    InferiorExited {
        backend_id: String,
        exit_code: Option<String>,
    },
    ThreadCreated {
        backend_inferior: String,
        backend_thread: String,
    },
    ThreadExited {
        backend_inferior: Option<String>,
        backend_thread: String,
    },
    BreakpointCreated {
        backend_number: String,
        enabled: bool,
        pending: bool,
    },
    BreakpointModified {
        backend_number: String,
        enabled: bool,
        pending: bool,
    },
    BreakpointDeleted {
        backend_number: String,
    },
    LibraryLoaded {
        id: String,
        target_name: Option<String>,
        host_name: Option<String>,
        symbols_loaded: Option<bool>,
    },
    LibraryUnloaded {
        id: String,
    },
    MemoryChanged,
    SnapshotReady {
        stop_id: StopId,
        partial: bool,
    },
    SnapshotFailed {
        stop_id: StopId,
    },
    ConsistencyDirty {
        reason: String,
    },
    ConsistencyTainted {
        reason: String,
    },
    ConsistencyRestored {
        warnings: Vec<String>,
    },
    ConsistencyLost {
        reason: String,
    },
    TargetDisconnected,
    Output {
        source: OutputSource,
        bytes: Vec<u8>,
    },
    UnknownBackendEvent {
        class: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputSource {
    InferiorPty,
    MiTargetStream,
    GdbConsoleStream,
    GdbLogStream,
    ServerDiagnostic,
}

#[derive(Clone, Debug)]
pub struct JournaledEvent {
    seq: u64,
    event: DomainEvent,
}

impl JournaledEvent {
    pub(crate) fn new(seq: u64, event: DomainEvent) -> Self {
        Self { seq, event }
    }

    pub fn for_replay(seq: u64, event: DomainEvent) -> Self {
        Self { seq, event }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn event(&self) -> &DomainEvent {
        &self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_addresses_without_json_numbers() {
        assert_eq!(
            Address::parse("0x7f").unwrap().as_str(),
            "0x000000000000007f"
        );
        assert!(Address::parse("127").is_err());
        assert!(Address::parse("0x10000000000000000").is_err());
    }
}

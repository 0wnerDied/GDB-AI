use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    InvalidState,
    StaleRevision,
    StaleContext,
    NotFound,
    AlreadyExists,
    Conflict,
    WriteLeaseRequired,
    WriteLeaseExpired,
    PolicyDenied,
    CapabilityMissing,
    Unsupported,
    TargetRunning,
    TargetStopped,
    TargetExited,
    TargetDisconnected,
    TargetUnavailable,
    Timeout,
    Cancelled,
    EventGap,
    StreamClosed,
    OutputLimit,
    MemoryPreconditionFailed,
    PartialRead,
    GdbError,
    GdbUnresponsive,
    GdbExited,
    MiParseError,
    MiProtocolLimit,
    ConsistencyDirty,
    ConsistencyLost,
    Internal,
}

#[derive(Debug, Error)]
#[error("{code:?}: {message}")]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: Option<serde_json::Value>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            details: None,
        }
    }

    pub fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorCode::Internal, error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::new(ErrorCode::Internal, error.to_string())
    }
}

impl From<gdb_ai_mi::MiError> for Error {
    fn from(error: gdb_ai_mi::MiError) -> Self {
        let code = match error {
            gdb_ai_mi::MiError::Limit { .. } => ErrorCode::MiProtocolLimit,
            _ => ErrorCode::MiParseError,
        };
        Self::new(code, error.to_string())
    }
}

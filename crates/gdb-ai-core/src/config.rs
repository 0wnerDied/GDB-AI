use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, Result, policy::Profile};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub gdb: GdbConfig,
    pub limits: Limits,
    pub journal: JournalConfig,
    pub output: OutputConfig,
    pub storage: StorageConfig,
    pub artifacts: ArtifactConfig,
    pub persistence: PersistenceConfig,
    pub security: SecurityConfig,
}

impl Default for Config {
    fn default() -> Self {
        let data = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("gdb-ai"));
        Self {
            server: ServerConfig::default(),
            gdb: GdbConfig::default(),
            limits: Limits::default(),
            journal: JournalConfig::default(),
            output: OutputConfig::default(),
            storage: StorageConfig::default(),
            artifacts: ArtifactConfig {
                path: data.join("artifacts"),
            },
            persistence: PersistenceConfig {
                sqlite: data.join("gdb-ai.sqlite"),
                sessions: data.join("sessions"),
            },
            security: SecurityConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalDurability {
    #[default]
    Performance,
    Durable,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JournalConfig {
    pub durability: JournalDurability,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputEvidenceMode {
    #[default]
    EphemeralRing,
    BoundedSpool,
    Artifact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    pub evidence: OutputEvidenceMode,
    pub max_bytes: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            evidence: OutputEvidenceMode::EphemeralRing,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let config = match path {
            Some(path) => toml::from_str(&std::fs::read_to_string(path)?).map_err(|error| {
                crate::Error::new(crate::ErrorCode::InvalidArgument, error.to_string())
            })?,
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let timeouts_valid = self.server.command_timeout_ms > 0
            && self.server.command_timeout_ms <= 300_000
            && self.server.wait_timeout_ms > 0
            && self.server.wait_timeout_ms <= 300_000
            && self.server.write_lease_ms > 0
            && self.server.http_session_idle_ms >= 1_000
            && self.storage.closed_session_retention_ms >= 1_000
            && self.storage.audit_retention_ms >= 1_000;
        let limits_valid = self.server.max_sessions > 0
            && self.server.max_sessions <= 1_024
            && self.server.max_http_sessions > 0
            && self.server.max_http_sessions <= 16_384
            && self.limits.mi_record_bytes >= 1_024
            && self.limits.mi_depth > 0
            && self.limits.tool_response_bytes >= 1_024
            && self.limits.inline_memory_bytes > 0
            && self.limits.inline_memory_bytes <= self.limits.memory_read_bytes
            && self.limits.memory_read_bytes > 0
            && self.limits.inferior_output_ring_bytes > 0
            && self.limits.console_output_ring_bytes > 0
            && self.limits.stack_frames > 0
            && self.limits.value_children > 0
            && self.limits.value_depth > 0
            && self.limits.session_artifact_bytes > 0
            && self.limits.owner_artifact_bytes >= self.limits.session_artifact_bytes
            && self.limits.owner_artifact_bytes <= self.limits.total_artifact_bytes
            && self.limits.total_artifact_bytes >= self.limits.session_artifact_bytes
            && self.limits.total_artifact_bytes <= i64::MAX as usize
            && self.limits.journal_bytes > 0
            && self.limits.process_memory_bytes > 0
            && self.limits.process_cpu_seconds > 0
            && self.limits.process_open_files >= 32
            && self.storage.max_closed_sessions > 0
            && self.storage.max_audit_rows > 0
            && self.storage.max_audit_rows <= i64::MAX as usize
            && self.storage.max_snapshots_per_session > 0
            && self.storage.max_operations_per_session > 0
            && self.output.max_bytes > 0
            && self.output.max_bytes <= self.limits.session_artifact_bytes;
        if !timeouts_valid || !limits_valid || self.security.workspace_roots.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "configuration contains an invalid timeout, limit, or empty workspace policy",
            ));
        }
        if self
            .security
            .remote_allowlist
            .iter()
            .any(|endpoint| endpoint.parse::<std::net::SocketAddr>().is_err())
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "remote_allowlist entries must be pinned IP addresses and ports",
            ));
        }
        if let Some(hash) = &self.gdb.python_extension_sha256
            && (hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "python_extension_sha256 must contain 64 hexadecimal digits",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub max_closed_sessions: usize,
    pub closed_session_retention_ms: u64,
    pub max_audit_rows: usize,
    pub audit_retention_ms: u64,
    pub max_snapshots_per_session: usize,
    pub max_operations_per_session: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_closed_sessions: 256,
            closed_session_retention_ms: 7 * 24 * 60 * 60 * 1_000,
            max_audit_rows: 100_000,
            audit_retention_ms: 30 * 24 * 60 * 60 * 1_000,
            max_snapshots_per_session: 256,
            max_operations_per_session: 4_096,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub max_http_sessions: usize,
    pub http_session_idle_ms: u64,
    pub command_timeout_ms: u64,
    pub wait_timeout_ms: u64,
    pub write_lease_ms: u64,
    pub unix_socket: Option<PathBuf>,
    pub requests_per_second: u64,
    pub request_burst: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            max_http_sessions: 128,
            http_session_idle_ms: 15 * 60 * 1_000,
            command_timeout_ms: 15_000,
            wait_timeout_ms: 5_000,
            write_lease_ms: 30_000,
            unix_socket: None,
            requests_per_second: 100,
            request_burst: 200,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GdbConfig {
    pub path: PathBuf,
    pub preferred_mi: String,
    pub fallback_mi: String,
    pub python_extension: Option<PathBuf>,
    pub python_extension_sha256: Option<String>,
}

impl Default for GdbConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("gdb"),
            preferred_mi: "mi4".into(),
            fallback_mi: "mi3".into(),
            python_extension: None,
            python_extension_sha256: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub mi_record_bytes: usize,
    pub mi_depth: usize,
    pub tool_response_bytes: usize,
    pub inline_memory_bytes: usize,
    pub memory_read_bytes: usize,
    pub inferior_output_ring_bytes: usize,
    pub console_output_ring_bytes: usize,
    pub stack_frames: usize,
    pub value_children: usize,
    pub value_depth: usize,
    pub session_artifact_bytes: usize,
    pub owner_artifact_bytes: usize,
    pub total_artifact_bytes: usize,
    pub journal_bytes: usize,
    pub process_memory_bytes: u64,
    pub process_cpu_seconds: u64,
    pub process_open_files: u64,
    pub process_count: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            mi_record_bytes: 8 * 1024 * 1024,
            mi_depth: 128,
            tool_response_bytes: 256 * 1024,
            inline_memory_bytes: 4 * 1024,
            memory_read_bytes: 16 * 1024 * 1024,
            inferior_output_ring_bytes: 8 * 1024 * 1024,
            console_output_ring_bytes: 2 * 1024 * 1024,
            stack_frames: 64,
            value_children: 1_000,
            value_depth: 8,
            session_artifact_bytes: 512 * 1024 * 1024,
            owner_artifact_bytes: 1024 * 1024 * 1024,
            total_artifact_bytes: 4 * 1024 * 1024 * 1024,
            journal_bytes: 64 * 1024 * 1024,
            process_memory_bytes: 2 * 1024 * 1024 * 1024,
            process_cpu_seconds: 3_600,
            process_open_files: 1_024,
            process_count: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactConfig {
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub sqlite: PathBuf,
    pub sessions: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub default_profile: Profile,
    pub workspace_roots: Vec<PathBuf>,
    pub remote_allowlist: Vec<String>,
    pub attach_allowlist: Vec<u64>,
    pub environment_allowlist: Vec<String>,
    pub source_map: Vec<SourceMap>,
    pub sandbox: SandboxMode,
    pub kernel_enabled: bool,
    pub monitor_allowlist: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    #[default]
    Auto,
    Required,
    Disabled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceMap {
    pub from: PathBuf,
    pub to: PathBuf,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_profile: Profile::DebugControl,
            workspace_roots: vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))],
            remote_allowlist: Vec::new(),
            attach_allowlist: Vec::new(),
            environment_allowlist: Vec::new(),
            source_map: Vec::new(),
            sandbox: SandboxMode::Auto,
            kernel_enabled: false,
            monitor_allowlist: Vec::new(),
        }
    }
}

impl ServerConfig {
    pub fn command_timeout(&self) -> Duration {
        Duration::from_millis(self.command_timeout_ms.max(1))
    }

    pub fn wait_timeout(&self) -> Duration {
        Duration::from_millis(self.wait_timeout_ms.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_journal_durability() {
        let config: Config = toml::from_str(
            "[journal]\ndurability = \"durable\"\n\
             [output]\nevidence = \"bounded_spool\"\nmax_bytes = 4096\n",
        )
        .unwrap();
        assert_eq!(config.journal.durability, JournalDurability::Durable);
        assert_eq!(config.output.evidence, OutputEvidenceMode::BoundedSpool);
        assert_eq!(config.output.max_bytes, 4096);
    }
}

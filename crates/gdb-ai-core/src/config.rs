use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{Result, policy::Profile};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: ServerConfig,
    pub gdb: GdbConfig,
    pub limits: Limits,
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

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        match path {
            Some(path) => Ok(
                toml::from_str(&std::fs::read_to_string(path)?).map_err(|error| {
                    crate::Error::new(crate::ErrorCode::InvalidArgument, error.to_string())
                })?,
            ),
            None => Ok(Self::default()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub max_sessions: usize,
    pub command_timeout_ms: u64,
    pub wait_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            command_timeout_ms: 5_000,
            wait_timeout_ms: 5_000,
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
}

impl Default for GdbConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("gdb"),
            preferred_mi: "mi4".into(),
            fallback_mi: "mi3".into(),
            python_extension: None,
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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_profile: Profile::DebugControl,
            workspace_roots: vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))],
            remote_allowlist: Vec::new(),
            attach_allowlist: Vec::new(),
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

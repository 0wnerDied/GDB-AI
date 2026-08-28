use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    domain::{InferiorStatus, SessionState, TargetOrigin},
    session::SessionCapabilities,
};

pub const LINUX_KERNEL_PROVIDER_VERSION: &str = "1.1.0";

#[derive(Clone, Debug, Serialize)]
pub struct ProviderDescriptor {
    pub name: &'static str,
    pub version: &'static str,
    pub status: ProviderStatus,
    pub effects: &'static [&'static str],
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Available,
    Conditional,
    Unavailable,
}

pub fn descriptors(
    state: &SessionState,
    capabilities: &SessionCapabilities,
    kernel_enabled: bool,
) -> Vec<ProviderDescriptor> {
    let local = matches!(
        state.target_origin,
        TargetOrigin::Local | TargetOrigin::Attach
    );
    let stopped = state.inferiors.values().any(|inferior| {
        matches!(
            inferior.status,
            InferiorStatus::Stopped | InferiorStatus::Core
        )
    });
    vec![
        ProviderDescriptor {
            name: "generic-gdb",
            version: "1.0.0",
            status: ProviderStatus::Available,
            effects: &["READ", "CONTROL", "TARGET_MUTATION"],
            limitations: Vec::new(),
        },
        ProviderDescriptor {
            name: "linux-userland",
            version: "1.0.0",
            status: if local {
                ProviderStatus::Available
            } else {
                ProviderStatus::Conditional
            },
            effects: &["READ"],
            limitations: if local {
                Vec::new()
            } else {
                vec!["target does not expose a local /proc PID".into()]
            },
        },
        ProviderDescriptor {
            name: "remote",
            version: "1.0.0",
            status: match state.target_origin {
                TargetOrigin::Remote if capabilities.target_features.is_empty() => {
                    ProviderStatus::Conditional
                }
                TargetOrigin::Remote => ProviderStatus::Available,
                TargetOrigin::Unknown => ProviderStatus::Conditional,
                TargetOrigin::Local | TargetOrigin::Attach | TargetOrigin::Core => {
                    ProviderStatus::Unavailable
                }
            },
            effects: &["READ", "CONTROL", "NETWORK"],
            limitations: if state.target_origin == TargetOrigin::Unknown {
                vec!["connect a remote target before probing features".into()]
            } else if state.target_origin == TargetOrigin::Remote
                && capabilities.target_features.is_empty()
            {
                vec!["remote target advertised no target features".into()]
            } else {
                Vec::new()
            },
        },
        ProviderDescriptor {
            name: "userland-security",
            version: "1.0.0",
            status: if stopped {
                ProviderStatus::Available
            } else {
                ProviderStatus::Conditional
            },
            effects: &["READ"],
            limitations: if stopped {
                Vec::new()
            } else {
                vec!["crash triage requires a stopped target or core".into()]
            },
        },
        ProviderDescriptor {
            name: "linux-kernel",
            version: LINUX_KERNEL_PROVIDER_VERSION,
            status: if kernel_enabled {
                ProviderStatus::Conditional
            } else {
                ProviderStatus::Unavailable
            },
            effects: &["READ", "CONTROL"],
            limitations: if kernel_enabled {
                vec!["requires a connected KGDB/QEMU target and trusted symbols".into()]
            } else {
                vec!["security.kernel_enabled is false".into()]
            },
        },
    ]
}

pub fn crash_signature(state: &SessionState) -> String {
    let mut evidence = state.stop_reason.clone().unwrap_or_default();
    for inferior in state.inferiors.values() {
        for thread in inferior.threads.values() {
            if let Some(frame) = &thread.frame {
                evidence.push('|');
                evidence.push_str(frame.function.as_deref().unwrap_or("?"));
                evidence.push('|');
                evidence.push_str(frame.address.as_deref().unwrap_or("?"));
            }
        }
    }
    format!("sha256:{:x}", Sha256::digest(evidence.as_bytes()))
}

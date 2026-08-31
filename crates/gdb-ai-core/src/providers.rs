use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Result,
    domain::{Address, InferiorStatus, SessionState, TargetOrigin},
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

pub(crate) fn mappings(state: &SessionState, offset: usize, limit: usize) -> Result<Value> {
    // 2026-08-28: A remote PID can collide with an unrelated host PID. Never
    // consult host /proc unless the reducer recorded a local target origin.
    if !matches!(
        state.target_origin,
        TargetOrigin::Local | TargetOrigin::Attach
    ) {
        return Ok(json!({
            "mappings": [],
            "offset": offset,
            "limit": limit,
            "truncated": false,
            "partial": true,
            "limitations": ["target origin does not permit host /proc access"],
            "source": {"provider": "remote", "mechanism": "unavailable"}
        }));
    }
    let Some(pid) = state.inferiors.values().find_map(|inferior| inferior.pid) else {
        return Ok(json!({
            "mappings": [],
            "offset": offset,
            "limit": limit,
            "truncated": false,
            "partial": true,
            "limitations": ["target does not expose a local /proc memory map"],
            "source": {"provider": "remote", "mechanism": "unavailable"}
        }));
    };
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    // 2026-08-31: Ignoring the requested limit returned every process mapping
    // to Agents. Page during parsing so large targets do not inflate replies.
    let (ranges, truncated) = mapping_page(&maps, offset, limit);
    let next_offset = offset + ranges.len();
    Ok(json!({
        "mappings": ranges,
        "offset": offset,
        "limit": limit,
        "truncated": truncated,
        "continuation": truncated.then(|| json!({"offset": next_offset})),
        "partial": false,
        "source": {"provider": "linux-userland", "mechanism": "proc-maps"}
    }))
}

fn mapping_page(maps: &str, offset: usize, limit: usize) -> (Vec<Value>, bool) {
    let mut ranges = maps
        .lines()
        .filter_map(parse_proc_map)
        .skip(offset)
        .take(limit + 1)
        .collect::<Vec<_>>();
    let truncated = ranges.len() > limit;
    ranges.truncate(limit);
    (ranges, truncated)
}

fn parse_proc_map(line: &str) -> Option<Value> {
    let mut fields = line
        .splitn(6, char::is_whitespace)
        .filter(|field| !field.is_empty());
    let (start, end) = fields.next()?.split_once('-')?;
    let permissions = fields.next()?;
    let offset = fields.next()?;
    let device = fields.next()?;
    let inode = fields.next()?.parse::<u64>().ok()?;
    // 2026-08-28: splitn leaves the maps column padding in its final field;
    // returning that padding broke exact path comparison and module lookup.
    let path = fields.next().unwrap_or("").trim_start();
    Some(json!({
        "start": format!("0x{start}"), "end": format!("0x{end}"),
        "permissions": permissions, "offset": format!("0x{offset}"),
        "device": device, "inode": inode, "path": path, "source": "linux-proc"
    }))
}

pub(crate) fn live_module_offset(
    state: &SessionState,
    module: &str,
    offset: u64,
) -> Result<Option<String>> {
    if !matches!(
        state.target_origin,
        TargetOrigin::Local | TargetOrigin::Attach
    ) {
        return Ok(None);
    }
    let Some(pid) = state.inferiors.values().find_map(|inferior| inferior.pid) else {
        return Ok(None);
    };
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return Ok(None);
    };
    module_offset_from_maps(&maps, module, offset)
}

fn module_offset_from_maps(maps: &str, module: &str, offset: u64) -> Result<Option<String>> {
    let requested_name = Path::new(module).file_name();
    for mapping in maps.lines().filter_map(parse_proc_map) {
        let path = mapping["path"].as_str().unwrap_or("");
        if path != module && requested_name != Path::new(path).file_name() {
            continue;
        }
        let Some(start) = mapping["start"]
            .as_str()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        let Some(file_offset) = mapping["offset"]
            .as_str()
            .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        let Some(address) = start
            .checked_sub(file_offset)
            .and_then(|base| base.checked_add(offset))
        else {
            continue;
        };
        return Ok(Some(
            Address::parse(&format!("0x{address:x}"))?
                .as_str()
                .to_owned(),
        ));
    }
    Ok(None)
}

#[cfg(test)]
mod mapping_tests {
    use super::*;

    #[test]
    fn resolves_stripped_pie_module_offsets_from_proc_maps() {
        let maps = concat!(
            "555555554000-555555555000 r--p 00000000 00:21 1 /tmp/mini_vfs\n",
            "555555555000-555555557000 r-xp 00001000 00:21 1 /tmp/mini_vfs\n",
        );
        assert_eq!(
            module_offset_from_maps(maps, "mini_vfs", 0x1c9c).unwrap(),
            Some("0x0000555555555c9c".into())
        );
        assert_eq!(
            module_offset_from_maps(maps, "other", 0x1c9c).unwrap(),
            None
        );
    }

    #[test]
    fn pages_process_mappings_at_the_requested_limit() {
        let maps = concat!(
            "1000-2000 r--p 00000000 00:00 1 /first\n",
            "2000-3000 r-xp 00001000 00:00 1 /second\n",
            "3000-4000 rw-p 00002000 00:00 1 /third\n",
        );

        let (page, truncated) = mapping_page(maps, 1, 1);

        assert_eq!(page.len(), 1);
        assert_eq!(page[0]["path"], "/second");
        assert!(truncated);
    }
}

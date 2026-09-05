use std::collections::{BTreeMap, BTreeSet};

use gdb_ai_mi::{MiRecord, MiResult, MiValue};
use serde_json::{Value, json};

use super::mi::aggregate_items;
use crate::{
    Result,
    backend::MiCommand,
    domain::{BreakpointLocationState, DomainEvent},
    session::{CommandReply, SessionHandle},
};

pub(super) async fn optional_command(
    handle: &SessionHandle,
    command: MiCommand,
    name: &str,
    warnings: &mut Vec<Value>,
) -> Option<CommandReply> {
    match handle.command(command).await {
        Ok(reply) => Some(reply),
        Err(error) => {
            warnings.push(json!({ "code": format!("{}_UNAVAILABLE", name.to_uppercase()), "message": error.to_string() }));
            None
        }
    }
}

pub(super) async fn reconciliation_command(
    handle: &SessionHandle,
    command: MiCommand,
    name: &str,
    warnings: &mut Vec<String>,
) -> Option<CommandReply> {
    match handle.command(command).await {
        Ok(reply) => Some(reply),
        Err(error) => {
            warnings.push(format!("{name}: {error}"));
            None
        }
    }
}

pub(super) async fn reconcile_inferiors(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(groups) = MiResult::find(record.results(), "groups") else {
        return Ok(());
    };
    let observed = aggregate_items(groups, "group")
        .into_iter()
        .filter_map(|fields| {
            Some((
                MiResult::find_str(fields, "id")?.to_owned(),
                MiResult::find_str(fields, "pid").and_then(|pid| pid.parse().ok()),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle.with_state(|state| state.inferiors.keys().cloned().collect::<Vec<_>>());
    for (backend_id, pid) in &observed {
        handle
            .record_event(DomainEvent::InferiorAdded {
                backend_id: backend_id.clone(),
                pid: *pid,
            })
            .await?;
    }
    for backend_id in existing {
        if !observed.contains_key(&backend_id) {
            handle
                .record_event(DomainEvent::InferiorRemoved { backend_id })
                .await?;
        }
    }
    Ok(())
}

pub(super) async fn reconcile_threads(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(threads) = MiResult::find(record.results(), "threads") else {
        return Ok(());
    };
    let fallback_group = handle.with_state(|state| {
        state
            .inferiors
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| "i1".into())
    });
    let observed = aggregate_items(threads, "thread")
        .into_iter()
        .filter_map(|fields| {
            Some((
                MiResult::find_str(fields, "id")?.to_owned(),
                MiResult::find_str(fields, "group-id")
                    .unwrap_or(&fallback_group)
                    .to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle.with_state(|state| {
        state
            .inferiors
            .values()
            .flat_map(|inferior| {
                inferior
                    .threads
                    .keys()
                    .cloned()
                    .map(|thread| (thread, inferior.backend_id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    });
    for (backend_thread, backend_inferior) in &observed {
        handle
            .record_event(DomainEvent::ThreadCreated {
                backend_inferior: backend_inferior.clone(),
                backend_thread: backend_thread.clone(),
            })
            .await?;
    }
    for (backend_thread, backend_inferior) in existing {
        if !observed.contains_key(&backend_thread) {
            handle
                .record_event(DomainEvent::ThreadExited {
                    backend_inferior: Some(backend_inferior),
                    backend_thread,
                })
                .await?;
        }
    }
    Ok(())
}

pub(super) async fn reconcile_breakpoints(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(table) =
        MiResult::find(record.results(), "BreakpointTable").and_then(MiValue::results)
    else {
        return Ok(());
    };
    let Some(body) = MiResult::find(table, "body") else {
        return Ok(());
    };
    let observed = aggregate_items(body, "bkpt")
        .into_iter()
        .filter_map(|fields| {
            let number = MiResult::find_str(fields, "number")?.to_owned();
            let enabled = MiResult::find_str(fields, "enabled").is_none_or(|value| value == "y");
            let pending = MiResult::find_str(fields, "pending").is_some_and(|value| value == "y")
                || MiResult::find_str(fields, "addr") == Some("<PENDING>");
            Some((number, (enabled, pending)))
        })
        .collect::<BTreeMap<_, _>>();
    let existing = handle.with_state(|state| state.breakpoints.keys().cloned().collect::<Vec<_>>());
    for fields in aggregate_items(body, "bkpt") {
        synchronize_breakpoint(handle, fields).await?;
    }
    for backend_number in existing {
        if !observed.contains_key(&backend_number) {
            handle
                .record_event(DomainEvent::BreakpointDeleted { backend_number })
                .await?;
        }
    }
    Ok(())
}

pub(super) async fn synchronize_breakpoint(
    handle: &SessionHandle,
    fields: &[MiResult],
) -> Result<()> {
    let Some(backend_number) = MiResult::find_str(fields, "number").map(str::to_owned) else {
        return Ok(());
    };
    let enabled = MiResult::find_str(fields, "enabled").is_none_or(|value| value == "y");
    let pending = MiResult::find_str(fields, "pending").is_some_and(|value| value == "y")
        || MiResult::find_str(fields, "addr") == Some("<PENDING>");
    let previous = handle.with_state(|state| state.breakpoints.get(&backend_number).cloned());
    // 2026-08-28: Breakpoint reads relied on optional notifications and then
    // emitted unconditional modifications, leaving stale registries or
    // advancing revisions on every list. Synchronize only observed changes.
    if previous
        .as_ref()
        .is_none_or(|breakpoint| breakpoint.enabled != enabled || breakpoint.pending != pending)
    {
        let event = if previous.is_some() {
            DomainEvent::BreakpointModified {
                backend_number: backend_number.clone(),
                enabled,
                pending,
            }
        } else {
            DomainEvent::BreakpointCreated {
                backend_number: backend_number.clone(),
                enabled,
                pending,
            }
        };
        handle.record_event(event).await?;
    }
    let (existing, public_id, event_seq) = handle.with_state(|state| {
        let breakpoint = state.breakpoints.get(&backend_number);
        let existing = breakpoint
            .map(|breakpoint| breakpoint.locations.clone())
            .unwrap_or_default();
        let public_id = breakpoint
            .map(|breakpoint| breakpoint.id.0.clone())
            .unwrap_or_else(|| {
                if state.session_id.uses_compact_handles() {
                    format!("b{}", backend_number.replace('.', "_"))
                } else {
                    format!("bp_{}", backend_number.replace('.', "_"))
                }
            });
        (existing, public_id, state.event_seq)
    });
    let location_fields = MiResult::find(fields, "locations")
        .map(|locations| aggregate_items(locations, "location"))
        .unwrap_or_default();
    let location_fields = if location_fields.is_empty() && !pending {
        vec![fields]
    } else {
        location_fields
    };
    let locations = location_fields
        .into_iter()
        .enumerate()
        .map(|(index, location)| {
            let number = MiResult::find_str(location, "number")
                .unwrap_or(&backend_number)
                .to_owned();
            BreakpointLocationState {
                id: existing
                    .iter()
                    .find(|existing| existing.backend_number == number)
                    .map(|existing| existing.id.clone())
                    .unwrap_or_else(|| format!("bpl_{public_id}_{event_seq}_{}", index + 1)),
                backend_number: number,
                address: MiResult::find_str(location, "addr")
                    .filter(|address| *address != "<PENDING>")
                    .map(str::to_owned),
                function: MiResult::find_str(location, "func").map(str::to_owned),
            }
        })
        .collect();
    if existing != locations {
        handle
            .record_event(DomainEvent::BreakpointLocations {
                backend_number,
                locations,
            })
            .await
    } else {
        Ok(())
    }
}

pub(super) async fn reconcile_libraries(handle: &SessionHandle, record: &MiRecord) -> Result<()> {
    let Some(libraries) = MiResult::find(record.results(), "shared-libraries") else {
        return Ok(());
    };
    let observed = aggregate_items(libraries, "library")
        .into_iter()
        .filter_map(|fields| {
            let id = MiResult::find_str(fields, "id")
                .or_else(|| MiResult::find_str(fields, "target-name"))?
                .to_owned();
            Some((id, fields))
        })
        .collect::<Vec<_>>();
    let observed_ids = observed
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let existing = handle.with_state(|state| state.modules.keys().cloned().collect::<Vec<_>>());
    for (id, fields) in observed {
        handle
            .record_event(DomainEvent::LibraryLoaded {
                id,
                target_name: MiResult::find_str(fields, "target-name").map(str::to_owned),
                host_name: MiResult::find_str(fields, "host-name").map(str::to_owned),
                symbols_loaded: MiResult::find_str(fields, "symbols-loaded")
                    .map(|value| value == "1"),
            })
            .await?;
    }
    for id in existing {
        if !observed_ids.contains(&id) {
            handle
                .record_event(DomainEvent::LibraryUnloaded { id })
                .await?;
        }
    }
    Ok(())
}

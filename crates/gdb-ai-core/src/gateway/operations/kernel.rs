use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{
    context::{context_options, require_stopped_context},
    encoding::{first_word, gdb_c_string, parse_gdb_u64},
    evaluation::safe_evaluate_command,
    mi::{find_register_name, result_string_list, result_text},
    request::{bounded_limit, bounded_offset, required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{DomainEvent, TargetOrigin},
    gateway::{Gateway, SessionEntry},
    protocol::{ApiRequest, CanonicalMethod},
    providers::LINUX_KERNEL_PROVIDER_VERSION,
};

async fn kernel_current_text(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
) -> Result<(String, u64)> {
    let reply = entry
        .handle
        .command(MiCommand::new("-data-list-register-names")?)
        .await?;
    let names = result_string_list(&reply.record, "register-names");
    if find_register_name(&names, "gs_base").is_some() {
        // 2026-08-28: Newer x86 kernels moved current_task into pcpu_hot,
        // while older distribution symbols expose the standalone per-CPU
        // variable. Try only the two documented layouts and preserve any
        // timeout or transport failure from the first evaluation.
        let modern = "*(struct task_struct **)((unsigned long)$gs_base+(unsigned long)&pcpu_hot.current_task)";
        match kernel_text(entry, parameters, state, modern).await {
            Ok(value) => Ok(value),
            Err(error) if error.code == ErrorCode::GdbError => kernel_text(
                entry,
                parameters,
                state,
                "*(struct task_struct **)((unsigned long)$gs_base+(unsigned long)&current_task)",
            )
            .await,
            Err(error) => Err(error),
        }
    } else if let Some(sp_el0) = find_register_name(&names, "sp_el0") {
        kernel_text(
            entry,
            parameters,
            state,
            &format!("(struct task_struct *)${sp_el0}"),
        )
        .await
    } else {
        Err(Error::new(
            ErrorCode::CapabilityMissing,
            "current task requires x86-64 gs_base or AArch64 sp_el0",
        ))
    }
}

async fn kernel_text(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
    expression: &str,
) -> Result<(String, u64)> {
    let command = context_options(
        MiCommand::new("-data-evaluate-expression")?.string(expression),
        parameters,
        state,
    )?;
    let reply = safe_evaluate_command(&entry.handle, command).await?;
    let value = result_text(&reply.record, "value")
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB omitted expression value"))?;
    Ok((value, reply.evidence_seq))
}

async fn kernel_address(
    entry: &SessionEntry,
    parameters: &Value,
    state: &crate::domain::SessionState,
    expression: &str,
) -> Result<(u64, u64)> {
    let (value, evidence_seq) = kernel_text(entry, parameters, state, expression).await?;
    Ok((parse_gdb_u64(&value)?, evidence_seq))
}

impl Gateway {
    pub(super) async fn kernel_inspect(&self, request: &ApiRequest) -> Result<Value> {
        if !self.config.security.kernel_enabled {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "Linux kernel provider is disabled",
            ));
        }
        let entry = self.entry(required_session(request)?).await?;
        let state = entry.handle.state();
        require_stopped_context(&request.parameters, &state)?;
        let view = string(&request.parameters, "view")?;
        match view.as_str() {
            "current_task" | "init_task" => {
                // 2026-08-28: Linux current is a C macro, while current_task
                // is an unrelocated per-CPU offset. Resolve the live pointer
                // from the architecture register and keep task output bounded.
                let (value, evidence_seq) = if view == "current_task" {
                    kernel_current_text(&entry, &request.parameters, &state).await?
                } else {
                    kernel_text(&entry, &request.parameters, &state, "&init_task").await?
                };
                Ok(json!({
                    "view": view,
                    "value": value,
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "gdb-expression"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "version" => {
                let (value, evidence_seq) =
                    kernel_text(&entry, &request.parameters, &state, "(char *)linux_banner")
                        .await?;
                Ok(json!({
                    "view": view,
                    "version": gdb_c_string(&value),
                    "rendered": value,
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "vmlinux-symbol"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "base" => {
                let (address, evidence_seq) =
                    kernel_address(&entry, &request.parameters, &state, "&_text").await?;
                Ok(json!({
                    "view": view,
                    "address": format!("0x{address:016x}"),
                    "symbol": "_text",
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "vmlinux-symbol"
                    },
                    "evidence_seq": evidence_seq
                }))
            }
            "tasks" => self.kernel_tasks(request, &entry, &state).await,
            "modules" => self.kernel_modules(request, &entry, &state).await,
            "capabilities" => {
                let names_reply = entry
                    .handle
                    .command(MiCommand::new("-data-list-register-names")?)
                    .await?;
                let names = result_string_list(&names_reply.record, "register-names");
                let (architecture, current_task) =
                    if find_register_name(&names, "gs_base").is_some() {
                        ("x86-64", "gs_base + current_task per-CPU offset")
                    } else if find_register_name(&names, "sp_el0").is_some() {
                        ("aarch64", "sp_el0")
                    } else {
                        ("unknown", "unavailable")
                    };
                let symbols =
                    match kernel_address(&entry, &request.parameters, &state, "&init_task").await {
                        Ok(symbols) => Some(symbols),
                        Err(error) if error.code == ErrorCode::GdbError => None,
                        Err(error) => return Err(error),
                    };
                Ok(json!({
                    "view": view,
                    "architecture": architecture,
                    "transport": match state.target_origin {
                        TargetOrigin::Remote => "gdb-remote",
                        TargetOrigin::Core => "core",
                        _ => "native",
                    },
                    "symbols": {
                        "status": if symbols.is_some() { "supported" } else { "unsupported" },
                        "mode": "trusted-vmlinux"
                    },
                    "current_task": {
                        "status": if current_task == "unavailable" {
                            "unsupported"
                        } else if symbols.is_some() {
                            "supported"
                        } else {
                            "conditional"
                        },
                        "mechanism": current_task
                    },
                    "monitor": {
                        "status": if self.config.security.monitor_allowlist.is_empty() {
                            "unsupported"
                        } else {
                            "conditional"
                        },
                        "allowlist": self.config.security.monitor_allowlist.clone()
                    },
                    "limitations": [
                        "symbol-free heuristic discovery is not enabled",
                        "QEMU monitor support is confirmed only by an allowlisted command"
                    ],
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "target-probe"
                    },
                    "evidence_seq": symbols
                        .map(|(_, evidence_seq)| evidence_seq)
                        .unwrap_or(names_reply.evidence_seq)
                }))
            }
            "stack" => {
                let mut subrequest = request.clone();
                subrequest.method = CanonicalMethod::InspectionGet;
                subrequest.parameters["view"] = Value::String("stack".into());
                let mut result = self.inspection_get(&subrequest).await?;
                result["view"] = Value::String("stack".into());
                result["source"] = json!({
                    "provider": "linux-kernel",
                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                    "mechanism": "gdb-stack"
                });
                Ok(result)
            }
            "panic" => {
                let mut subrequest = request.clone();
                subrequest.method = CanonicalMethod::InspectionSnapshot;
                subrequest.parameters["profile"] = Value::String("standard".into());
                let mut result = self.inspection_snapshot(&subrequest).await?;
                result["view"] = Value::String("panic".into());
                result["source"] = json!({
                    "provider": "linux-kernel",
                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                    "mechanism": "bounded-stop-snapshot"
                });
                Ok(result)
            }
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                "unsupported kernel inspection view",
            )),
        }
    }

    pub(super) async fn kernel_tasks(
        &self,
        request: &ApiRequest,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<Value> {
        let limit = bounded_limit(&request.parameters, 32, self.config.limits.value_children)?;
        let offset = bounded_offset(
            &request.parameters,
            self.config.limits.value_children,
            "kernel task",
        )?;
        let (init_task, mut evidence_seq) =
            kernel_address(entry, &request.parameters, state, "&init_task").await?;
        let (head, seq) =
            kernel_address(entry, &request.parameters, state, "&init_task.tasks").await?;
        evidence_seq = evidence_seq.max(seq);
        let (mut cursor, seq) =
            kernel_address(entry, &request.parameters, state, "init_task.tasks.next").await?;
        evidence_seq = evidence_seq.max(seq);
        // 2026-08-28: Optional current-task metadata previously swallowed
        // timeouts and could send more MI commands after an unknown outcome.
        let current = match kernel_current_text(entry, &request.parameters, state).await {
            Ok((value, _)) => Some(parse_gdb_u64(&value)?),
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::CapabilityMissing | ErrorCode::GdbError
                ) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let mut task_addresses = vec![init_task];
        let mut seen = BTreeSet::new();
        while cursor != head && task_addresses.len() < offset.saturating_add(limit + 1) {
            if !seen.insert(cursor) {
                return Err(Error::new(
                    ErrorCode::GdbError,
                    "kernel task list contains a cycle outside init_task",
                ));
            }
            let expression = format!(
                "(struct task_struct *)((char *)0x{cursor:x} - (unsigned long)&((struct task_struct *)0)->tasks)"
            );
            let (task, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            task_addresses.push(task);
            let expression = format!("((struct list_head *)0x{cursor:x})->next");
            let (next, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            cursor = next;
        }
        let truncated = cursor != head || task_addresses.len() > offset.saturating_add(limit);
        let mut tasks = Vec::new();
        for task in task_addresses.into_iter().skip(offset).take(limit) {
            let (pid, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->pid"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let (tgid, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->tgid"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let (name, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct task_struct *)0x{task:x})->comm"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            tasks.push(json!({
                "address": format!("0x{task:016x}"),
                "pid": parse_gdb_u64(&pid)?,
                "tgid": parse_gdb_u64(&tgid)?,
                "name": gdb_c_string(&name),
                "current": current.map(|current| current == task)
            }));
        }
        let next_offset = offset + tasks.len();
        Ok(json!({
            "view": "tasks",
            "tasks": tasks,
            "offset": offset,
            "limit": limit,
            "truncated": truncated,
            "continuation": truncated.then(|| json!({"offset": next_offset})),
            "partial": current.is_none(),
            "warnings": if current.is_none() {
                vec!["current task could not be resolved"]
            } else {
                Vec::new()
            },
            "stop_id": state.stop_id,
            "source": {
                "provider": "linux-kernel",
                "version": LINUX_KERNEL_PROVIDER_VERSION,
                "mechanism": "task_struct.tasks"
            },
            "evidence_seq": evidence_seq
        }))
    }

    pub(super) async fn kernel_modules(
        &self,
        request: &ApiRequest,
        entry: &SessionEntry,
        state: &crate::domain::SessionState,
    ) -> Result<Value> {
        let limit = bounded_limit(&request.parameters, 32, self.config.limits.value_children)?;
        let offset = bounded_offset(
            &request.parameters,
            self.config.limits.value_children,
            "kernel module",
        )?;
        let (head, mut evidence_seq) =
            kernel_address(entry, &request.parameters, state, "&modules").await?;
        let (mut cursor, seq) =
            kernel_address(entry, &request.parameters, state, "modules.next").await?;
        evidence_seq = evidence_seq.max(seq);
        let mut module_addresses = Vec::new();
        let mut seen = BTreeSet::new();
        while cursor != head && module_addresses.len() < offset.saturating_add(limit + 1) {
            if !seen.insert(cursor) {
                return Err(Error::new(
                    ErrorCode::GdbError,
                    "kernel module list contains a cycle outside modules",
                ));
            }
            let expression = format!(
                "(struct module *)((char *)0x{cursor:x} - (unsigned long)&((struct module *)0)->list)"
            );
            let (module, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            module_addresses.push(module);
            let expression = format!("((struct list_head *)0x{cursor:x})->next");
            let (next, seq) =
                kernel_address(entry, &request.parameters, state, &expression).await?;
            evidence_seq = evidence_seq.max(seq);
            cursor = next;
        }
        let truncated = cursor != head || module_addresses.len() > offset.saturating_add(limit);
        let mut modules = Vec::new();
        for module in module_addresses.into_iter().skip(offset).take(limit) {
            let (name, seq) = kernel_text(
                entry,
                &request.parameters,
                state,
                &format!("((struct module *)0x{module:x})->name"),
            )
            .await?;
            evidence_seq = evidence_seq.max(seq);
            let modern_base = format!("((struct module *)0x{module:x})->mem[0].base");
            let legacy_base = format!("((struct module *)0x{module:x})->core_layout.base");
            let legacy_size = format!("((struct module *)0x{module:x})->core_layout.size");
            let (base, size, layout, seq) = match kernel_text(
                entry,
                &request.parameters,
                state,
                &modern_base,
            )
            .await
            {
                Ok((base, base_seq)) => {
                    let count_expression =
                        "sizeof(((struct module *)0)->mem) / sizeof(((struct module *)0)->mem[0])";
                    let (count, mut size_seq) =
                        kernel_text(entry, &request.parameters, state, count_expression).await?;
                    let count = parse_gdb_u64(&count)?;
                    if count == 0 || count > 32 {
                        return Err(Error::new(
                            ErrorCode::OutputLimit,
                            "kernel module memory layout count is invalid",
                        ));
                    }
                    let mut size = 0_u64;
                    for index in 0..count {
                        let expression =
                            format!("((struct module *)0x{module:x})->mem[{index}].size");
                        let (part, seq) =
                            kernel_text(entry, &request.parameters, state, &expression).await?;
                        size = size.checked_add(parse_gdb_u64(&part)?).ok_or_else(|| {
                            Error::new(ErrorCode::OutputLimit, "kernel module size exceeds 64 bits")
                        })?;
                        size_seq = size_seq.max(seq);
                    }
                    (
                        base,
                        size.to_string(),
                        "module_memory",
                        base_seq.max(size_seq),
                    )
                }
                // 2026-08-28: Only an absent legacy field justifies trying
                // the alternate layout. Preserve timeout and transport errors
                // so an unknown command outcome remains fenced.
                Err(error) if error.code == ErrorCode::GdbError => {
                    let (base, base_seq) =
                        kernel_text(entry, &request.parameters, state, &legacy_base).await?;
                    let (size, size_seq) =
                        kernel_text(entry, &request.parameters, state, &legacy_size).await?;
                    (base, size, "core_layout", base_seq.max(size_seq))
                }
                Err(error) => return Err(error),
            };
            evidence_seq = evidence_seq.max(seq);
            modules.push(json!({
                "address": format!("0x{module:016x}"),
                "name": gdb_c_string(&name),
                "base": format!("0x{:016x}", parse_gdb_u64(&base)?),
                "size": parse_gdb_u64(&size)?,
                "layout": layout
            }));
        }
        let next_offset = offset + modules.len();
        Ok(json!({
            "view": "modules",
            "modules": modules,
            "offset": offset,
            "limit": limit,
            "truncated": truncated,
            "continuation": truncated.then(|| json!({"offset": next_offset})),
            "stop_id": state.stop_id,
            "source": {
                "provider": "linux-kernel",
                "version": LINUX_KERNEL_PROVIDER_VERSION,
                "mechanism": "modules-list"
            },
            "evidence_seq": evidence_seq
        }))
    }

    pub(super) async fn kernel_monitor(&self, request: &ApiRequest) -> Result<Value> {
        if !self.config.security.kernel_enabled {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "Linux kernel provider is disabled",
            ));
        }
        let monitor = string(&request.parameters, "command")?;
        if monitor.len() > 4_096
            || monitor
                .bytes()
                .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "monitor command is empty, oversized, or multiline",
            ));
        }
        let verb = first_word(&monitor);
        if !self
            .config
            .security
            .monitor_allowlist
            .iter()
            .any(|allowed| allowed == verb)
        {
            return Err(Error::new(
                ErrorCode::PolicyDenied,
                "monitor command is not allowlisted",
            ));
        }
        self.metrics.raw_command();
        let entry = self.entry(required_session(request)?).await?;
        entry
            .handle
            .record_event(DomainEvent::ConsistencyTainted {
                reason: format!("target monitor command executed: {verb}"),
            })
            .await?;
        let reply = entry
            .handle
            .command(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(format!("monitor {monitor}")),
            )
            .await?;
        let reconciliation = self.reconcile_session(&entry, false).await?;
        Ok(json!({
            "command": reply,
            "state_after": entry.handle.state(),
            "reconciliation": reconciliation
        }))
    }
}

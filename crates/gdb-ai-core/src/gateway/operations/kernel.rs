use std::collections::BTreeSet;

use gdb_ai_mi::MiRecord;
use serde_json::{Value, json};

use super::{
    context::{context_options, require_stopped_context},
    encoding::{first_word, gdb_c_string, parse_address, parse_gdb_u64},
    evaluation::safe_evaluate_command,
    memory::{find_memory_result, read_memory_bytes},
    mi::{find_register_name, result_string_list, result_text},
    request::{bounded_limit, bounded_offset, required_session, string},
};
use crate::{
    Error, ErrorCode, Result,
    backend::MiCommand,
    domain::{Address, DomainEvent, TargetOrigin},
    gateway::{Gateway, SessionEntry},
    protocol::{ApiRequest, CanonicalMethod},
    providers::LINUX_KERNEL_PROVIDER_VERSION,
};

const X86_KERNEL_START: u64 = 0xffff_ffff_8000_0000;
const X86_MODULE_START: u64 = 0xffff_ffff_c000_0000;
const X86_MODULE_END: u64 = 0xffff_ffff_ff00_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct KernelMapping {
    start: u64,
    end: u64,
    permissions: String,
}

impl KernelMapping {
    fn size(&self) -> u64 {
        self.end - self.start
    }

    fn json(&self) -> Value {
        json!({
            "start": format!("0x{:016x}", self.start),
            "end": format!("0x{:016x}", self.end),
            "size": self.size(),
            "permissions": self.permissions,
        })
    }
}

#[derive(Debug)]
struct KernelImageContext {
    pc: u64,
    image: KernelMapping,
    image_mappings: Vec<KernelMapping>,
    module_candidates: Vec<KernelMapping>,
    module_candidates_truncated: bool,
    kernel_page_table: bool,
    evidence_seq: u64,
}

#[derive(Debug)]
struct KernelBootstrap {
    context: KernelImageContext,
    version_address: Option<u64>,
    version: Option<String>,
    evidence_seq: u64,
}

fn parse_qemu_memory_map(output: &[u8]) -> Vec<KernelMapping> {
    let output = String::from_utf8_lossy(output);
    let mut mappings = output
        .split(['\n', '|'])
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let _size = fields.next()?;
            let permissions = fields.next()?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            (start < end && start & (1 << 63) != 0).then(|| KernelMapping {
                start,
                end,
                permissions: permissions.to_owned(),
            })
        })
        .collect::<Vec<_>>();
    mappings.sort_by_key(|mapping| (mapping.start, mapping.end));
    mappings.dedup();
    mappings
}

fn kernel_image_mappings(mappings: &[KernelMapping]) -> Vec<KernelMapping> {
    mappings
        .iter()
        .filter(|mapping| {
            mapping.start >= X86_KERNEL_START
                && mapping.end <= X86_MODULE_START
                && mapping.size() >= 1024 * 1024
                && !mapping.permissions.contains('w')
        })
        .cloned()
        .collect()
}

fn select_kernel_image(mappings: &[KernelMapping]) -> Option<KernelMapping> {
    let mappings = kernel_image_mappings(mappings);
    // 2026-09-04: Some distro kernels place text and rodata in separate
    // mappings. Treat their complete span as the image while preserving each
    // readable segment for searches, so gaps cannot hide version or kallsyms.
    let image = KernelMapping {
        start: mappings.first()?.start,
        end: mappings.last()?.end,
        permissions: "-r-".into(),
    };
    // 2026-09-04: KPTI's user PGD exposes a 2 MiB entry mapping that matched
    // the old image heuristic. Reject that isolated window so callers retry
    // the paired kernel PGD instead of scanning unrelated entry code.
    (image.size() > 2 * 1024 * 1024).then_some(image)
}

fn command_output(reply: &crate::session::CommandReply) -> Vec<u8> {
    let mut output = Vec::new();
    for record in &reply.stream_records {
        if let MiRecord::ConsoleStream(bytes) | MiRecord::TargetStream(bytes) = record {
            output.extend(bytes);
        }
    }
    output
}

fn kernel_cr3_script(body: &str) -> String {
    let body = body.replace('\n', "\n    ");
    // 2026-09-04: KPTI user stops expose only the shadow page table, so QEMU
    // cannot read the kernel image. Use Linux's adjacent kernel PGD for one
    // command and restore the exact CR3 before any other Agent can observe it.
    format!(
        concat!(
            "import gdb\n",
            "gdb.execute('set $_gdbai_kernel_saved_cr3 = $cr3', to_string=True)\n",
            "try:\n",
            "    gdb.execute('set $cr3 = $_gdbai_kernel_saved_cr3 & 0x000fffffffffe000', to_string=True)\n",
            "    {body}\n",
            "finally:\n",
            "    gdb.execute('set $cr3 = $_gdbai_kernel_saved_cr3', to_string=True)\n",
            "    gdb.set_convenience_variable('_gdbai_kernel_saved_cr3', None)"
        ),
        body = body
    )
}

async fn qemu_memory_map(
    entry: &SessionEntry,
    kernel_page_table: bool,
) -> Result<(Vec<KernelMapping>, u64)> {
    let body = "print('|'.join(line for line in gdb.execute('monitor info mem', to_string=True).splitlines() if line.startswith('ffffffff')))";
    let script = if kernel_page_table {
        kernel_cr3_script(body)
    } else {
        format!("import gdb\n{body}")
    };
    let reply = entry
        .handle
        .command(
            MiCommand::new("-interpreter-exec")?
                .bare("console")?
                .string(format!("python exec({})", serde_json::to_string(&script)?)),
        )
        .await?;
    Ok((
        parse_qemu_memory_map(&command_output(&reply)),
        reply.evidence_seq,
    ))
}

const KERNEL_SYMBOL_PREFIX: &str = "gdbai-kernel-symbols:";

fn kernel_symbol_output(output: &[u8]) -> Result<Value> {
    let output = String::from_utf8_lossy(output);
    let start = output
        .find(KERNEL_SYMBOL_PREFIX)
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "GDB omitted kernel symbol facts"))?
        + KERNEL_SYMBOL_PREFIX.len();
    let end = output[start..]
        .find(['\r', '\n'])
        .map_or(output.len(), |end| start + end);
    let value: Value = serde_json::from_str(&output[start..end])?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(Error::new(ErrorCode::CapabilityMissing, error));
    }
    Ok(value)
}

fn requested_kernel_symbols(parameters: &Value, required: bool) -> Result<Vec<String>> {
    let Some(values) = parameters.get("names") else {
        return if required {
            Err(Error::new(
                ErrorCode::InvalidArgument,
                "names is required for the symbols view",
            ))
        } else {
            Ok(Vec::new())
        };
    };
    let names = values
        .as_array()
        .expect("kernel names passed contract validation")
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if names.is_empty() || names.len() > 64 || names.iter().any(String::is_empty) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "names must contain between 1 and 64 non-empty symbol names",
        ));
    }
    Ok(names)
}

fn kernel_module_text_offset(facts: &Value, requested: &str, offset: u64) -> Result<Value> {
    if let Some(error) = facts["module_error"].as_str() {
        return Err(Error::new(
            ErrorCode::CapabilityMissing,
            format!("kernel module discovery failed: {error}"),
        ));
    }
    let modules = facts["modules"]
        .as_array()
        .ok_or_else(|| Error::new(ErrorCode::GdbError, "runtime kallsyms omitted modules"))?;
    let module = modules
        .iter()
        .find(|module| module["name"] == requested)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                format!("loaded kernel module {requested:?} was not found"),
            )
            .with_details(json!({
                "available_modules": modules.iter().filter_map(|module| module["name"].as_str()).collect::<Vec<_>>()
            }))
        })?;
    let segments = module["segments"].as_array().ok_or_else(|| {
        Error::new(
            ErrorCode::CapabilityMissing,
            format!("kernel module {requested:?} has no validated memory segments"),
        )
    })?;
    let segment = segments
        .iter()
        .find(|segment| segment["kind"] == "text")
        .or_else(|| segments.iter().find(|segment| segment["kind"] == "core"))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::CapabilityMissing,
                format!("kernel module {requested:?} has no executable segment"),
            )
        })?;
    let base = parse_address(segment["base"].as_str().ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            "kernel module segment omitted its base",
        )
    })?)?;
    let size = segment["size"].as_u64().ok_or_else(|| {
        Error::new(
            ErrorCode::GdbError,
            "kernel module segment omitted its size",
        )
    })?;
    if offset >= size {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("kernel module text offset 0x{offset:x} exceeds its 0x{size:x}-byte segment"),
        ));
    }
    let address = base.checked_add(offset).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "kernel module text offset overflows its runtime base",
        )
    })?;
    Ok(json!({
        "space": "kernel",
        "module": requested,
        "module_address": module["address"],
        "segment": segment["kind"],
        "base": segment["base"],
        "size": size,
        "offset": format!("0x{offset:x}"),
        "address": format!("0x{address:016x}")
    }))
}

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
    pub(super) async fn resolve_kernel_module_offset(
        &self,
        entry: &SessionEntry,
        parameters: &Value,
        state: &crate::domain::SessionState,
        selector: &Value,
    ) -> Result<Value> {
        if !self.config.security.kernel_enabled {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "Linux kernel provider is disabled",
            ));
        }
        let module = string(selector, "module")?;
        let normalized = Address::parse(&string(selector, "offset")?)?;
        let offset = u64::from_str_radix(&normalized.as_str()[2..], 16)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "invalid module offset"))?;
        // 2026-09-04: Kernel probes previously required separate bootstrap,
        // address arithmetic, and raw breakpoint calls. Resolve the live text
        // segment under the probe's stopped-state fence instead.
        let (_, facts, evidence_seq) = self
            .symbol_free_kernel_facts(entry, parameters, state, &[])
            .await?;
        let mut resolved = kernel_module_text_offset(&facts, &module, offset)?;
        resolved["evidence_seq"] = Value::from(evidence_seq);
        Ok(resolved)
    }

    async fn kernel_image_context(
        &self,
        entry: &SessionEntry,
        parameters: &Value,
        state: &crate::domain::SessionState,
    ) -> Result<KernelImageContext> {
        let names_reply = entry
            .handle
            .command(MiCommand::new("-data-list-register-names")?)
            .await?;
        let names = result_string_list(&names_reply.record, "register-names");
        if find_register_name(&names, "gs_base").is_none() {
            return Err(Error::new(
                ErrorCode::CapabilityMissing,
                "symbol-free bootstrap currently requires an x86-64 QEMU target",
            ));
        }
        let (pc, pc_seq) = kernel_address(entry, parameters, state, "$pc").await?;
        // 2026-09-04: Forwarding `monitor info mem` produced tens
        // of MiB of MI and journal data before the useful kernel
        // mappings. Capture it inside GDB and emit only global
        // kernel addresses so one semantic call stays bounded.
        let (mut mappings, mut monitor_seq) = qemu_memory_map(entry, false).await?;
        let mut kernel_page_table = false;
        // 2026-09-04: A stop inside a loadable module made the PC
        // mapping look like the kernel image. Select the first
        // large read-only core mapping independently of stop site.
        let image = if let Some(image) = select_kernel_image(&mappings) {
            image
        } else {
            let (kernel_mappings, evidence_seq) = qemu_memory_map(entry, true).await?;
            let image = select_kernel_image(&kernel_mappings).ok_or_else(|| {
                Error::new(
                    ErrorCode::CapabilityMissing,
                    "QEMU did not report a symbol-free kernel image mapping",
                )
            })?;
            mappings = kernel_mappings;
            monitor_seq = monitor_seq.max(evidence_seq);
            kernel_page_table = true;
            image
        };
        let image_mappings = kernel_image_mappings(&mappings);
        let mut module_candidates = mappings
            .into_iter()
            .filter(|mapping| {
                mapping.start >= X86_MODULE_START
                    && mapping.end <= X86_MODULE_END
                    && (mapping.end <= image.start || mapping.start >= image.end)
            })
            .collect::<Vec<_>>();
        let module_candidates_truncated = module_candidates.len() > 128;
        module_candidates.truncate(128);
        Ok(KernelImageContext {
            pc,
            image,
            image_mappings,
            module_candidates,
            module_candidates_truncated,
            kernel_page_table,
            evidence_seq: names_reply.evidence_seq.max(pc_seq).max(monitor_seq),
        })
    }

    async fn scan_kernel_symbols(
        &self,
        entry: &SessionEntry,
        image_mappings: &[KernelMapping],
        module_mappings: &[KernelMapping],
        kernel_page_table: bool,
        names: &[String],
    ) -> Result<(Value, u64)> {
        let names = serde_json::to_string(names)?;
        let ranges = serde_json::to_string(
            &image_mappings
                .iter()
                .map(|mapping| [mapping.start, mapping.end])
                .collect::<Vec<_>>(),
        )?;
        let module_ranges = serde_json::to_string(
            &module_mappings
                .iter()
                .map(|mapping| [mapping.start, mapping.end])
                .collect::<Vec<_>>(),
        )?;
        let script = format!(
            "{}\n_gdbai_kernel_symbols({ranges}, {module_ranges}, {names})",
            include_str!("kernel_symbols.py"),
        );
        let script = if kernel_page_table {
            kernel_cr3_script(&script)
        } else {
            script
        };
        let command = format!("python exec({})", serde_json::to_string(&script)?);
        let reply = entry
            .handle
            .command(
                MiCommand::new("-interpreter-exec")?
                    .bare("console")?
                    .string(command),
            )
            .await?;
        Ok((
            kernel_symbol_output(&command_output(&reply))?,
            reply.evidence_seq,
        ))
    }

    async fn symbol_free_kernel_facts(
        &self,
        entry: &SessionEntry,
        parameters: &Value,
        state: &crate::domain::SessionState,
        names: &[String],
    ) -> Result<(KernelImageContext, Value, u64)> {
        // 2026-09-04: Symbol-less guests previously forced Agents to transfer
        // raw maps and rebuild kallsyms manually. Keep discovery and exact-name
        // resolution behind one stopped-state observation.
        let context = self.kernel_image_context(entry, parameters, state).await?;
        let (facts, evidence_seq) = self
            .scan_kernel_symbols(
                entry,
                &context.image_mappings,
                &context.module_candidates,
                context.kernel_page_table,
                names,
            )
            .await?;
        let evidence_seq = context.evidence_seq.max(evidence_seq);
        Ok((context, facts, evidence_seq))
    }

    async fn kernel_bootstrap(
        &self,
        entry: &SessionEntry,
        parameters: &Value,
        state: &crate::domain::SessionState,
    ) -> Result<KernelBootstrap> {
        entry
            .handle
            .stable_observation(
                state,
                Box::pin(async {
                    let context = self.kernel_image_context(entry, parameters, state).await?;
                    if context.kernel_page_table {
                        let (facts, evidence_seq) = self
                            .scan_kernel_symbols(
                                entry,
                                &context.image_mappings,
                                &context.module_candidates,
                                true,
                                &[],
                            )
                            .await?;
                        return Ok(KernelBootstrap {
                            version_address: facts["version_address"]
                                .as_str()
                                .map(parse_address)
                                .transpose()?,
                            version: facts["version"].as_str().map(str::to_owned),
                            evidence_seq: context.evidence_seq.max(evidence_seq),
                            context,
                        });
                    }
                    let needle = b"Linux version ";
                    let pattern = needle
                        .iter()
                        .map(|byte| format!("0x{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let mut version_address = None;
                    let mut version = None;
                    let mut version_seq = context.evidence_seq;
                    // 2026-09-04: The image can retain a shorter banner
                    // template before the populated linux_banner. Prefer the
                    // longest bounded match so version reports runtime text.
                    for mapping in &context.image_mappings {
                        let length = usize::try_from(mapping.size()).map_err(|_| {
                            Error::new(ErrorCode::OutputLimit, "kernel image mapping is too large")
                        })?;
                        let find = entry
                            .handle
                            .command(
                                MiCommand::new("-interpreter-exec")?
                                    .bare("console")?
                                    .string(format!(
                                        "find /b /9 0x{:x}, +{}, {pattern}",
                                        mapping.start, length
                                    )),
                            )
                            .await?;
                        let (matches, _, _, _) =
                            find_memory_result(&find, mapping.start, length, 8);
                        version_seq = version_seq.max(find.evidence_seq);
                        for address in matches
                            .iter()
                            .filter_map(|address| parse_address(address).ok())
                        {
                            let length =
                                usize::try_from((mapping.end - address).min(512)).unwrap_or(512);
                            let (bytes, evidence_seq) =
                                read_memory_bytes(&entry.handle, state, address, length, true)
                                    .await?;
                            let end = bytes
                                .iter()
                                .position(|byte| *byte == 0)
                                .unwrap_or(bytes.len());
                            let candidate = String::from_utf8_lossy(&bytes[..end])
                                .trim_end_matches(['\r', '\n'])
                                .to_owned();
                            if candidate.starts_with("Linux version ")
                                && version
                                    .as_ref()
                                    .is_none_or(|current: &String| candidate.len() > current.len())
                            {
                                version_address = Some(address);
                                version = Some(candidate);
                            }
                            version_seq = version_seq.max(evidence_seq);
                        }
                    }

                    Ok(KernelBootstrap {
                        evidence_seq: context.evidence_seq.max(version_seq),
                        context,
                        version_address,
                        version,
                    })
                }),
            )
            .await
    }

    fn kernel_bootstrap_result(
        &self,
        bootstrap: &KernelBootstrap,
        state: &crate::domain::SessionState,
    ) -> Value {
        let warnings = bootstrap
            .version
            .is_none()
            .then_some("Linux version string was not found in the kernel image mapping")
            .into_iter()
            .collect::<Vec<_>>();
        json!({
            "view": "bootstrap",
            "architecture": "x86-64",
            "mode": "kernel",
            "pc": format!("0x{:016x}", bootstrap.context.pc),
            "image": bootstrap.context.image.json(),
            "image_segments": bootstrap.context.image_mappings.iter().map(KernelMapping::json).collect::<Vec<_>>(),
            "version": bootstrap.version,
            "version_address": bootstrap.version_address.map(|address| format!("0x{address:016x}")),
            "module_candidates": bootstrap.context.module_candidates.iter().map(KernelMapping::json).collect::<Vec<_>>(),
            "module_candidates_truncated": bootstrap.context.module_candidates_truncated,
            "page_table": if bootstrap.context.kernel_page_table { "paired-kernel" } else { "current" },
            "partial": !warnings.is_empty(),
            "warnings": warnings,
            "stop_id": state.stop_id,
            "source": {
                "provider": "linux-kernel",
                "version": LINUX_KERNEL_PROVIDER_VERSION,
                "mechanism": "qemu-info-mem+gdb-find"
            },
            "evidence_seq": bootstrap.evidence_seq
        })
    }

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
            "bootstrap" => {
                let names = requested_kernel_symbols(&request.parameters, false)?;
                if names.is_empty() {
                    let bootstrap = self
                        .kernel_bootstrap(&entry, &request.parameters, &state)
                        .await?;
                    return Ok(self.kernel_bootstrap_result(&bootstrap, &state));
                }
                entry
                    .handle
                    .stable_observation(
                        &state,
                        Box::pin(async {
                            let (context, facts, evidence_seq) = self
                                .symbol_free_kernel_facts(
                                    &entry,
                                    &request.parameters,
                                    &state,
                                    &names,
                                )
                                .await?;
                            let version_address = facts["version_address"]
                                .as_str()
                                .map(parse_address)
                                .transpose()?;
                            let bootstrap = KernelBootstrap {
                                context,
                                version_address,
                                version: facts["version"].as_str().map(str::to_owned),
                                evidence_seq,
                            };
                            let mut result = self.kernel_bootstrap_result(&bootstrap, &state);
                            result["symbols"] = facts["symbols"].clone();
                            result["missing_symbols"] = facts["missing"].clone();
                            result["current_tasks"] = facts["current_tasks"].clone();
                            result["modules"] = facts["modules"].clone();
                            result["kallsyms"] = facts["kallsyms"].clone();
                            if let Some(error) = facts["module_error"].as_str() {
                                result["partial"] = Value::Bool(true);
                                result["warnings"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(Value::String(format!("module discovery: {error}")));
                            }
                            Ok(result)
                        }),
                    )
                    .await
            }
            "current_task" => {
                // 2026-08-28: Linux current is a C macro, while current_task
                // is an unrelocated per-CPU offset. Resolve the live pointer
                // from the architecture register and keep task output bounded.
                let current = kernel_current_text(&entry, &request.parameters, &state).await;
                if let Err(error) = &current
                    && error.code == ErrorCode::GdbError
                {
                    return entry
                        .handle
                        .stable_observation(
                            &state,
                            Box::pin(async {
                                let (_, facts, evidence_seq) = self
                                    .symbol_free_kernel_facts(
                                        &entry,
                                        &request.parameters,
                                        &state,
                                        &[],
                                    )
                                    .await?;
                                let tasks = facts["current_tasks"].as_array().ok_or_else(|| {
                                    Error::new(
                                        ErrorCode::CapabilityMissing,
                                        "kallsyms did not resolve any current task",
                                    )
                                })?;
                                let task = tasks
                                    .iter()
                                    .find(|task| task["selected"] == true)
                                    .or_else(|| tasks.first())
                                    .ok_or_else(|| {
                                        Error::new(
                                            ErrorCode::CapabilityMissing,
                                            "kallsyms did not resolve any current task",
                                        )
                                    })?;
                                Ok(json!({
                                    "view": view,
                                    "value": task["task"],
                                    "task": task,
                                    "tasks": tasks,
                                    "stop_id": state.stop_id,
                                    "source": {
                                        "provider": "linux-kernel",
                                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                                        "mechanism": "runtime-kallsyms+gs-base"
                                    },
                                    "evidence_seq": evidence_seq
                                }))
                            }),
                        )
                        .await;
                }
                let (value, evidence_seq) = current?;
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
            "init_task" => {
                let init_task =
                    kernel_text(&entry, &request.parameters, &state, "&init_task").await;
                if let Err(error) = &init_task
                    && error.code == ErrorCode::GdbError
                {
                    return entry
                        .handle
                        .stable_observation(
                            &state,
                            Box::pin(async {
                                let (_, facts, evidence_seq) = self
                                    .symbol_free_kernel_facts(
                                        &entry,
                                        &request.parameters,
                                        &state,
                                        &["init_task".to_owned()],
                                    )
                                    .await?;
                                let value = facts["symbols"]
                                    .as_array()
                                    .and_then(|symbols| symbols.first())
                                    .and_then(|symbol| symbol["address"].as_str())
                                    .ok_or_else(|| {
                                        Error::new(
                                            ErrorCode::CapabilityMissing,
                                            "runtime kallsyms did not contain init_task",
                                        )
                                    })?;
                                Ok(json!({
                                    "view": view,
                                    "value": value,
                                    "stop_id": state.stop_id,
                                    "source": {
                                        "provider": "linux-kernel",
                                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                                        "mechanism": "runtime-kallsyms"
                                    },
                                    "evidence_seq": evidence_seq
                                }))
                            }),
                        )
                        .await;
                }
                let (value, evidence_seq) = init_task?;
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
            "symbols" => {
                let names = requested_kernel_symbols(&request.parameters, true)?;
                entry
                    .handle
                    .stable_observation(
                        &state,
                        Box::pin(async {
                            let (context, facts, evidence_seq) = self
                                .symbol_free_kernel_facts(
                                    &entry,
                                    &request.parameters,
                                    &state,
                                    &names,
                                )
                                .await?;
                            let missing = facts["missing"].clone();
                            let mut warnings = Vec::new();
                            if let Some(error) = facts["module_error"].as_str() {
                                warnings.push(format!("module discovery: {error}"));
                            }
                            let partial = !warnings.is_empty()
                                || missing.as_array().is_some_and(|values| !values.is_empty());
                            Ok(json!({
                                "view": view,
                                "architecture": "x86-64",
                                "image": context.image.json(),
                                "image_segments": context.image_mappings.iter().map(KernelMapping::json).collect::<Vec<_>>(),
                                "symbols": facts["symbols"],
                                "missing": missing,
                                "current_tasks": facts["current_tasks"],
                                "modules": facts["modules"],
                                "kallsyms": facts["kallsyms"],
                                "page_table": if context.kernel_page_table { "paired-kernel" } else { "current" },
                                "partial": partial,
                                "warnings": warnings,
                                "stop_id": state.stop_id,
                                "source": {
                                    "provider": "linux-kernel",
                                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                                    "mechanism": "runtime-kallsyms"
                                },
                                "evidence_seq": evidence_seq
                            }))
                        }),
                    )
                    .await
            }
            "version" => {
                let symbol =
                    kernel_text(&entry, &request.parameters, &state, "(char *)linux_banner").await;
                if let Err(error) = &symbol
                    && error.code == ErrorCode::GdbError
                {
                    let bootstrap = self
                        .kernel_bootstrap(&entry, &request.parameters, &state)
                        .await?;
                    let version = bootstrap.version.ok_or_else(|| {
                        Error::new(
                            ErrorCode::CapabilityMissing,
                            "Linux version string was not found in the kernel image mapping",
                        )
                    })?;
                    return Ok(json!({
                        "view": view,
                        "version": version,
                        "address": bootstrap.version_address.map(|address| format!("0x{address:016x}")),
                        "stop_id": state.stop_id,
                        "source": {
                            "provider": "linux-kernel",
                            "version": LINUX_KERNEL_PROVIDER_VERSION,
                            "mechanism": "qemu-info-mem+gdb-find"
                        },
                        "evidence_seq": bootstrap.evidence_seq
                    }));
                }
                let (value, evidence_seq) = symbol?;
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
                let symbol = kernel_address(&entry, &request.parameters, &state, "&_text").await;
                if let Err(error) = &symbol
                    && error.code == ErrorCode::GdbError
                {
                    let bootstrap = self
                        .kernel_bootstrap(&entry, &request.parameters, &state)
                        .await?;
                    return Ok(json!({
                        "view": view,
                        "address": format!("0x{:016x}", bootstrap.context.image.start),
                        "end": format!("0x{:016x}", bootstrap.context.image.end),
                        "size": bootstrap.context.image.end - bootstrap.context.image.start,
                        "symbol": null,
                        "stop_id": state.stop_id,
                        "source": {
                            "provider": "linux-kernel",
                            "version": LINUX_KERNEL_PROVIDER_VERSION,
                            "mechanism": "qemu-info-mem"
                        },
                        "evidence_seq": bootstrap.evidence_seq
                    }));
                }
                let (address, evidence_seq) = symbol?;
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
                let typed_symbols =
                    match kernel_address(&entry, &request.parameters, &state, "&init_task").await {
                        Ok(symbols) => Some(symbols),
                        Err(error) if error.code == ErrorCode::GdbError => None,
                        Err(error) => return Err(error),
                    };
                let runtime_kallsyms =
                    architecture == "x86-64" && matches!(state.target_origin, TargetOrigin::Remote);
                Ok(json!({
                    "view": view,
                    "architecture": architecture,
                    "transport": match state.target_origin {
                        TargetOrigin::Remote => "gdb-remote",
                        TargetOrigin::Core => "core",
                        _ => "native",
                    },
                    "symbols": {
                        "status": if typed_symbols.is_some() {
                            "supported"
                        } else if runtime_kallsyms {
                            "conditional"
                        } else {
                            "unsupported"
                        },
                        "mode": if typed_symbols.is_some() {
                            "trusted-vmlinux"
                        } else {
                            "runtime-kallsyms"
                        }
                    },
                    "bootstrap": {
                        "status": if runtime_kallsyms {
                            "conditional"
                        } else {
                            "unsupported"
                        },
                        "mechanism": "QEMU monitor info mem"
                    },
                    "current_task": {
                        "status": if current_task == "unavailable" {
                            "unsupported"
                        } else if typed_symbols.is_some() {
                            "supported"
                        } else {
                            "conditional"
                        },
                        "mechanism": current_task
                    },
                    "modules": {
                        "status": if typed_symbols.is_some() {
                            "supported"
                        } else if runtime_kallsyms {
                            "conditional"
                        } else {
                            "unsupported"
                        },
                        "mechanism": if typed_symbols.is_some() {
                            "trusted-vmlinux"
                        } else {
                            "runtime-kallsyms+modules-list"
                        }
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
                        "symbol-free kallsyms is verified on Linux 5.15, 6.1, 6.6, 6.12, 6.13, 6.15, and 7.2 x86-64 distribution kernels",
                        "QEMU monitor support is confirmed only by an allowlisted command"
                    ],
                    "stop_id": state.stop_id,
                    "source": {
                        "provider": "linux-kernel",
                        "version": LINUX_KERNEL_PROVIDER_VERSION,
                        "mechanism": "target-probe"
                    },
                    "evidence_seq": typed_symbols
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
        let head = kernel_address(entry, &request.parameters, state, "&modules").await;
        let (head, mut evidence_seq) = match head {
            Ok(value) => value,
            // 2026-09-04: Stripped guests previously made the typed module
            // view fail before returning even the stable list/name prefix.
            // Reuse the bounded runtime scanner under the same stop fence.
            Err(error) if error.code == ErrorCode::GdbError => {
                return entry
                    .handle
                    .stable_observation(
                        state,
                        Box::pin(async {
                            let (_, facts, evidence_seq) = self
                                .symbol_free_kernel_facts(entry, &request.parameters, state, &[])
                                .await?;
                            let all = facts["modules"].as_array().ok_or_else(|| {
                                Error::new(
                                    ErrorCode::GdbError,
                                    "runtime kallsyms omitted the module list",
                                )
                            })?;
                            let modules = all
                                .iter()
                                .skip(offset)
                                .take(limit)
                                .cloned()
                                .collect::<Vec<_>>();
                            let truncated = offset.saturating_add(modules.len()) < all.len();
                            let next_offset = offset + modules.len();
                            let warnings = facts["module_error"]
                                .as_str()
                                .map(str::to_owned)
                                .into_iter()
                                .collect::<Vec<_>>();
                            Ok(json!({
                                "view": "modules",
                                "modules": modules,
                                "offset": offset,
                                "limit": limit,
                                "truncated": truncated,
                                "continuation": truncated.then(|| json!({"offset": next_offset})),
                                "partial": !warnings.is_empty(),
                                "warnings": warnings,
                                "stop_id": state.stop_id,
                                "source": {
                                    "provider": "linux-kernel",
                                    "version": LINUX_KERNEL_PROVIDER_VERSION,
                                    "mechanism": "runtime-kallsyms+modules-list"
                                },
                                "evidence_seq": evidence_seq
                            }))
                        }),
                    )
                    .await;
            }
            Err(error) => return Err(error),
        };
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        KernelMapping, kernel_module_text_offset, kernel_symbol_output, parse_qemu_memory_map,
        requested_kernel_symbols, select_kernel_image,
    };

    #[test]
    fn parses_only_high_qemu_memory_mappings() {
        let mappings = parse_qemu_memory_map(
            b"noise\n0000000000400000-0000000000410000 0000000000010000 ur-\n\
              ffffffff81200000-ffffffff82f00000 0000000001d00000 -r-|\
              ffffffff83000000-ffffffff84000000 0000000001000000 -r-|\
              ffffffffc0010000-ffffffffc0011000 0000000000001000 -rw\n",
        );

        assert_eq!(
            mappings,
            vec![
                KernelMapping {
                    start: 0xffff_ffff_8120_0000,
                    end: 0xffff_ffff_82f0_0000,
                    permissions: "-r-".into(),
                },
                KernelMapping {
                    start: 0xffff_ffff_8300_0000,
                    end: 0xffff_ffff_8400_0000,
                    permissions: "-r-".into(),
                },
                KernelMapping {
                    start: 0xffff_ffff_c001_0000,
                    end: 0xffff_ffff_c001_1000,
                    permissions: "-rw".into(),
                },
            ]
        );
        assert_eq!(
            select_kernel_image(&mappings),
            Some(KernelMapping {
                start: mappings[0].start,
                end: mappings[1].end,
                permissions: "-r-".into(),
            })
        );
        assert_eq!(
            select_kernel_image(&[KernelMapping {
                start: 0xffff_ffff_8100_0000,
                end: 0xffff_ffff_8120_0000,
                permissions: "-r-".into(),
            }]),
            None
        );
    }

    #[test]
    fn extracts_only_the_compact_kernel_symbol_payload() {
        let value = kernel_symbol_output(
            b"console noise\ngdbai-kernel-symbols:{\"symbols\":[{\"name\":\"commit_creds\"}]}\n",
        )
        .unwrap();
        assert_eq!(value["symbols"][0]["name"], "commit_creds");

        let names = requested_kernel_symbols(
            &json!({"names": ["prepare_kernel_cred", "commit_creds", "commit_creds"]}),
            true,
        )
        .unwrap();
        assert_eq!(names, ["commit_creds", "prepare_kernel_cred"]);
    }

    #[test]
    fn resolves_only_offsets_inside_a_kernel_module_text_segment() {
        let facts = json!({
            "modules": [{
                "address": "0xffffffff81001000",
                "name": "sample",
                "segments": [{
                    "kind": "text",
                    "base": "0xffffffffc0000000",
                    "size": 0x1000
                }]
            }],
            "module_error": null
        });

        let resolved = kernel_module_text_offset(&facts, "sample", 0x123).unwrap();
        assert_eq!(resolved["address"], "0xffffffffc0000123");
        assert!(kernel_module_text_offset(&facts, "sample", 0x1000).is_err());
    }
}

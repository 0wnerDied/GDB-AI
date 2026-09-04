use std::{
    fs::File,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use gdb_ai_core::{
    config::{ArtifactConfig, Config, PersistenceConfig},
    domain::Consistency,
    gateway::{Caller, Gateway},
    policy::Profile,
    protocol::{API_VERSION, ApiRequest, ApiResponse},
};
use serde_json::{Value, json};
use tempfile::tempdir;

mod support;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rejects_incidental_kernel_module_names() {
    if !support::require_commands(&["gdb"]) {
        return;
    }
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/gateway/operations/kernel_symbols.py");
    let gdb = std::env::var_os("GDB_AI_GDB_PATH").unwrap_or_else(|| "gdb".into());
    let output = Command::new(gdb)
        .args(["-nx", "-batch", "-x"])
        .arg(script)
        .args([
            "-ex",
            "python assert _module_name(b'6T\\0\\x01' + b'\\0' * 52, 0) is None; assert _module_name(b'sample_mod\\0', 0) is None; assert _module_name(b'sample_mod\\0' + b'\\0' * 45, 0) == 'sample_mod'",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "module-name parser check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kernel_artifacts() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let image = std::env::var_os("GDB_AI_KERNEL_IMAGE").map(PathBuf::from);
    let symbols = std::env::var_os("GDB_AI_KERNEL_VMLINUX").map(PathBuf::from);
    let module = std::env::var_os("GDB_AI_KERNEL_MODULE").map(PathBuf::from);
    if let (Some(image), Some(symbols), Some(module)) = (image, symbols, module)
        && image.is_file()
        && symbols.is_file()
        && module.is_file()
    {
        return Some((image, symbols, module));
    }
    if std::env::var_os("GDB_AI_REQUIRE_KERNEL_INTEGRATION").is_some() {
        panic!("kernel image, vmlinux, and module environment variables must name files");
    }
    eprintln!("skipped kernel integration; Debian kernel artifacts are not configured");
    None
}

fn build_initramfs(directory: &std::path::Path, module: &std::path::Path) -> PathBuf {
    let root = directory.join("initramfs");
    for path in ["bin", "dev", "proc", "sys"] {
        std::fs::create_dir_all(root.join(path)).unwrap();
    }
    let busybox = std::env::var_os("GDB_AI_KERNEL_BUSYBOX")
        .map(PathBuf::from)
        .or_else(|| {
            ["/usr/bin/busybox", "/bin/busybox"]
                .into_iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
        })
        .expect("busybox must be installed for kernel integration");
    assert!(busybox.is_file(), "kernel busybox must name a file");
    std::fs::copy(busybox, root.join("bin/busybox")).unwrap();
    std::fs::copy(module, root.join("test.ko")).unwrap();
    let init = root.join("init");
    std::fs::write(
        &init,
        "#!/bin/busybox sh\n/bin/busybox mount -t proc proc /proc\n/bin/busybox insmod /test.ko\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&init).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&init, permissions).unwrap();
    let archive = directory.join("initramfs.cpio");
    let status = Command::new("sh")
        .args([
            "-c",
            "find . -print0 | cpio --null --quiet -o --format=newc",
        ])
        .current_dir(&root)
        .stdout(Stdio::from(File::create(&archive).unwrap()))
        .status()
        .unwrap();
    assert!(status.success(), "failed to build kernel initramfs");
    archive
}

fn request(
    id: &str,
    session_id: Option<&str>,
    method: &str,
    revision: Option<u64>,
    parameters: Value,
) -> ApiRequest {
    ApiRequest {
        api_version: API_VERSION.into(),
        request_id: id.into(),
        session_id: session_id.map(str::to_owned),
        method: method.parse().unwrap(),
        expected_revision: revision,
        idempotency_key: None,
        parameters,
    }
}

async fn call(gateway: &Gateway, caller: &Caller, request: ApiRequest) -> ApiResponse {
    let response = gateway.dispatch(request, caller).await;
    assert!(
        response.error.is_none(),
        "response error: {:?}",
        response.error
    );
    response
}

#[tokio::test]
async fn loads_matching_kernel_helpers_for_bounded_dmesg() {
    if !support::require_commands(&["cc", "gdb"]) {
        return;
    }

    let directory = tempdir().unwrap();
    let executable = directory.path().join("vmlinux");
    let source = directory.path().join("kernel.c");
    std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    assert!(
        Command::new("cc")
            .args(["-g", "-O0"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        directory.path().join("vmlinux-gdb.py"),
        "import gdb\nclass Dmesg(gdb.Command):\n    def __init__(self):\n        super().__init__('lx-dmesg', gdb.COMMAND_DATA)\n    def invoke(self, arg, from_tty):\n        for index in range(6):\n            gdb.write('[%d.000000] helper line %d\\n' % (index, index))\nDmesg()\n",
    )
    .unwrap();

    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.security.workspace_roots = vec![directory.path().to_owned()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller::local("kernel-helper-test");
    let created = call(
        &gateway,
        &caller,
        request("create-helper", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_ref().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    let launched = call(
        &gateway,
        &caller,
        request(
            "launch-helper",
            Some(session_id),
            "target.launch",
            created.revision,
            json!({
                "program": executable,
                "lease_id": lease_id,
                "stop": "main"
            }),
        ),
    )
    .await;
    let stop_id = launched
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let dmesg = call(
        &gateway,
        &caller,
        request(
            "inspect-helper-dmesg",
            Some(session_id),
            "kernel.inspect",
            None,
            json!({"view": "dmesg", "limit": 2, "stop_id": stop_id}),
        ),
    )
    .await;
    let result = dmesg.result.as_ref().unwrap();
    assert_eq!(
        result["lines"],
        json!(["[4.000000] helper line 4", "[5.000000] helper line 5"])
    );
    assert_eq!(result["total_lines"], 6);
    assert_eq!(result["truncated"], true);
    assert_eq!(result["helper"], "vmlinux-gdb.py");
    assert_eq!(result["source"]["mechanism"], "linux-gdb-scripts");

    gateway.shutdown().await;
}

#[tokio::test]
async fn inspects_a_public_debian_kernel_over_qemu_rsp() {
    let Some((kernel_image, vmlinux, module)) = kernel_artifacts() else {
        return;
    };
    let architecture = std::env::var("GDB_AI_KERNEL_ARCH").unwrap_or_else(|_| "x86_64".into());
    let (gdb, qemu, console, expected_architecture, base_prefix) = match architecture.as_str() {
        "x86_64" => ("gdb", "qemu-system-x86_64", "ttyS0", "x86-64", "0xffffffff"),
        "aarch64" => (
            "gdb-multiarch",
            "qemu-system-aarch64",
            "ttyAMA0",
            "aarch64",
            "0xffff",
        ),
        value => panic!("unsupported kernel integration architecture: {value}"),
    };
    if !support::require_commands(&["cpio", gdb, qemu]) {
        return;
    }

    let directory = tempdir().unwrap();
    let initramfs = build_initramfs(directory.path(), &module);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut qemu_command = Command::new(qemu);
    if architecture == "aarch64" {
        qemu_command.args(["-machine", "virt,accel=tcg", "-cpu", "max"]);
    } else {
        qemu_command.args(["-accel", "tcg"]);
    }
    let _qemu = ChildGuard(
        qemu_command
            .args(["-m", "512M", "-smp", "1", "-S"])
            .arg("-kernel")
            .arg(&kernel_image)
            .arg("-initrd")
            .arg(initramfs)
            .args([
                "-append",
                &format!("console={console} nokaslr rdinit=/init"),
            ])
            .arg("-gdb")
            .arg(format!("tcp:{endpoint}"))
            .args(["-display", "none", "-serial", "none", "-monitor", "none"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.gdb.path = gdb.into();
    config.security.default_profile = Profile::RawAdmin;
    config.security.workspace_roots = vec![
        directory.path().to_owned(),
        vmlinux.parent().unwrap().to_owned(),
    ];
    config.security.remote_allowlist = vec![endpoint.clone()];
    config.security.kernel_enabled = true;
    config.security.monitor_allowlist = vec!["info".into()];
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "kernel-provider-test".into(),
        admin: true,
    };

    let created = call(
        &gateway,
        &caller,
        request("create", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_ref().unwrap().clone();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let connected = call(
        &gateway,
        &caller,
        request(
            "connect",
            Some(&session_id),
            "target.connect_remote",
            created.revision,
            json!({
                "lease_id": lease_id,
                "mode": "remote",
                "endpoint": endpoint,
                "executable": vmlinux,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    let reset_stop = connected
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let breakpoint = call(
        &gateway,
        &caller,
        request(
            "start-kernel-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            connected.revision,
            json!({"lease_id": lease_id, "location": {"function": "start_kernel"}}),
        ),
    )
    .await;
    let stopped = call(
        &gateway,
        &caller,
        request(
            "continue-to-start-kernel",
            Some(&session_id),
            "execution.control",
            breakpoint.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": reset_stop,
                "wait": {"until": "snapshot", "timeout_ms": 15000}
            }),
        ),
    )
    .await;
    let kernel_stop = stopped
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();

    let init_task = call(
        &gateway,
        &caller,
        request(
            "inspect-init-task",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "init_task", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert!(
        init_task.result.as_ref().unwrap()["value"]
            .as_str()
            .is_some_and(|value| value.contains("init_task"))
    );
    let current_task = call(
        &gateway,
        &caller,
        request(
            "inspect-current-task",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "current_task", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert!(
        current_task.result.as_ref().unwrap()["value"]
            .as_str()
            .is_some_and(|value| value.contains("init_task"))
    );
    assert_eq!(
        current_task.result.as_ref().unwrap()["source"]["provider"],
        "linux-kernel"
    );

    let capabilities = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-capabilities",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "capabilities", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert_eq!(
        capabilities.result.as_ref().unwrap()["architecture"],
        expected_architecture
    );
    assert_eq!(
        capabilities.result.as_ref().unwrap()["transport"],
        "gdb-remote"
    );

    let version = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-version",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "version", "stop_id": kernel_stop}),
        ),
    )
    .await;
    let version_result = version.result.as_ref().unwrap();
    let expected_release = std::env::var("GDB_AI_KERNEL_RELEASE").unwrap_or_else(|_| {
        kernel_image
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("vmlinuz-"))
            .expect("kernel image name must identify its release")
            .to_owned()
    });
    assert!(
        version_result["version"].as_str().is_some_and(
            |value| value.starts_with("Linux version ") && value.contains(&expected_release)
        ),
        "unexpected kernel version: {version_result}"
    );

    let mut helper = vmlinux.as_os_str().to_owned();
    helper.push("-gdb.py");
    let has_kernel_helpers = PathBuf::from(helper).is_file();

    let base = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-base",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "base", "stop_id": kernel_stop}),
        ),
    )
    .await;
    assert!(
        base.result.as_ref().unwrap()["address"]
            .as_str()
            .is_some_and(|address| address.starts_with(base_prefix)),
        "kernel base must be a canonical {expected_architecture} kernel address"
    );

    let tasks = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-tasks",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "tasks", "stop_id": kernel_stop, "limit": 8}),
        ),
    )
    .await;
    let task = &tasks.result.as_ref().unwrap()["tasks"][0];
    assert_eq!(task["pid"], 0);
    assert_eq!(task["name"], "swapper");
    assert_eq!(task["current"], true);

    let modules = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-modules",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "modules", "stop_id": kernel_stop, "limit": 8}),
        ),
    )
    .await;
    assert_eq!(
        modules.result.as_ref().unwrap()["modules"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    let stack = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-stack",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "stack", "stop_id": kernel_stop, "limit": 4}),
        ),
    )
    .await;
    assert!(
        stack.result.as_ref().unwrap()["frames"]
            .as_array()
            .is_some_and(|frames| !frames.is_empty())
    );
    assert_eq!(
        stack.result.as_ref().unwrap()["source"]["provider"],
        "linux-kernel"
    );

    let module_breakpoint = call(
        &gateway,
        &caller,
        request(
            "module-init-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            stack.revision,
            json!({"lease_id": lease_id, "location": {"function": "do_init_module"}}),
        ),
    )
    .await;
    let module_stop = call(
        &gateway,
        &caller,
        request(
            "continue-to-module-init",
            Some(&session_id),
            "execution.control",
            module_breakpoint.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": kernel_stop,
                "wait": {"until": "snapshot", "timeout_ms": 30000}
            }),
        ),
    )
    .await;
    let module_stop_id = module_stop
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let loaded_modules = call(
        &gateway,
        &caller,
        request(
            "inspect-loaded-kernel-module",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "modules", "stop_id": module_stop_id, "limit": 8}),
        ),
    )
    .await;
    let loaded_modules_result = loaded_modules.result.as_ref().unwrap();
    let module_name =
        std::env::var("GDB_AI_KERNEL_MODULE_NAME").unwrap_or_else(|_| "irqbypass".into());
    let loaded_module = loaded_modules_result["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|module| module["name"] == module_name)
        .unwrap_or_else(|| {
            panic!(
                "{module_name} module must be visible at do_init_module: {loaded_modules_result}"
            )
        });
    assert_ne!(loaded_module["base"], "0x0000000000000000");
    assert!(loaded_module["size"].as_u64().is_some_and(|size| size > 0));
    if let Ok(layout) = std::env::var("GDB_AI_KERNEL_MODULE_LAYOUT") {
        assert_eq!(loaded_module["layout"], layout);
    }
    if has_kernel_helpers {
        let dmesg = call(
            &gateway,
            &caller,
            request(
                "inspect-kernel-dmesg",
                Some(&session_id),
                "kernel.inspect",
                None,
                json!({"view": "dmesg", "stop_id": module_stop_id, "limit": 8}),
            ),
        )
        .await;
        let result = dmesg.result.as_ref().unwrap();
        assert!(
            result["lines"]
                .as_array()
                .is_some_and(|lines| !lines.is_empty() && lines.len() <= 8),
            "matching Linux helpers must return a bounded kernel log: {result}"
        );
        assert_eq!(result["source"]["mechanism"], "linux-gdb-scripts");
    }

    let panic_breakpoint = call(
        &gateway,
        &caller,
        request(
            "panic-breakpoint",
            Some(&session_id),
            "breakpoint.create",
            loaded_modules.revision,
            json!({"lease_id": lease_id, "location": {"function": "panic"}}),
        ),
    )
    .await;
    let panic_stop = call(
        &gateway,
        &caller,
        request(
            "continue-to-kernel-panic",
            Some(&session_id),
            "execution.control",
            panic_breakpoint.revision,
            json!({
                "action": "continue",
                "lease_id": lease_id,
                "stop_id": module_stop_id,
                "wait": {"until": "snapshot", "timeout_ms": 30000}
            }),
        ),
    )
    .await;
    assert_eq!(
        panic_stop.state.as_ref().unwrap().stop_reason.as_deref(),
        Some("breakpoint-hit")
    );
    let panic_stop_id = panic_stop
        .state
        .as_ref()
        .unwrap()
        .stop_id
        .as_ref()
        .unwrap()
        .0
        .clone();
    let panic_context = call(
        &gateway,
        &caller,
        request(
            "inspect-kernel-panic-context",
            Some(&session_id),
            "kernel.inspect",
            None,
            json!({"view": "panic", "stop_id": panic_stop_id}),
        ),
    )
    .await;
    assert!(panic_context.result.as_ref().unwrap()["snapshot_id"].is_string());
    assert_eq!(
        panic_context.result.as_ref().unwrap()["source"]["provider"],
        "linux-kernel"
    );

    let monitored = call(
        &gateway,
        &caller,
        request(
            "monitor-registers",
            Some(&session_id),
            "kernel.monitor",
            panic_context.revision,
            json!({"lease_id": lease_id, "command": "info registers"}),
        ),
    )
    .await;
    assert_eq!(
        monitored.state.as_ref().unwrap().consistency,
        Consistency::Tainted
    );
    assert_eq!(
        monitored.result.as_ref().unwrap()["reconciliation"]["status"],
        "tainted"
    );

    call(
        &gateway,
        &caller,
        request(
            "close",
            Some(&session_id),
            "session.close",
            monitored.revision,
            json!({"lease_id": lease_id}),
        ),
    )
    .await;
}

#[tokio::test]
async fn bootstraps_a_symbol_free_modern_kernel_over_qemu_rsp() {
    let Some(endpoint) = std::env::var_os("GDB_AI_KERNEL_RSP_ENDPOINT") else {
        eprintln!("skipped symbol-free kernel integration; RSP endpoint is not configured");
        return;
    };
    if !support::require_commands(&["gdb"]) {
        return;
    }
    let endpoint = endpoint.to_string_lossy().into_owned();
    let directory = tempdir().unwrap();
    let mut config = Config {
        artifacts: ArtifactConfig {
            path: directory.path().join("artifacts"),
        },
        persistence: PersistenceConfig {
            sqlite: directory.path().join("state.sqlite"),
            sessions: directory.path().join("sessions"),
        },
        ..Config::default()
    };
    config.security.default_profile = Profile::RawAdmin;
    config.security.workspace_roots = vec![directory.path().to_owned()];
    config.security.remote_allowlist = vec![endpoint.clone()];
    config.security.kernel_enabled = true;
    if let Ok(timeout) = std::env::var("GDB_AI_KERNEL_COMMAND_TIMEOUT_MS") {
        config.server.command_timeout_ms = timeout.parse().unwrap();
    }
    let gateway = Gateway::new(config).unwrap();
    let caller = Caller {
        identity: "symbol-free-kernel-test".into(),
        admin: true,
    };

    let created = call(
        &gateway,
        &caller,
        request("create", None, "session.create", None, json!({})),
    )
    .await;
    let session_id = created.session_id.as_deref().unwrap();
    let lease_id = created.result.as_ref().unwrap()["write_lease"]["lease_id"]
        .as_str()
        .unwrap();
    let connected = call(
        &gateway,
        &caller,
        request(
            "connect",
            Some(session_id),
            "target.connect_remote",
            created.revision,
            json!({
                "lease_id": lease_id,
                "mode": "remote",
                "endpoint": endpoint,
                "wait": {"until": "snapshot", "timeout_ms": 5000}
            }),
        ),
    )
    .await;
    let stop_id = connected.state.as_ref().unwrap().stop_id.as_ref().unwrap();
    let layout = call(
        &gateway,
        &caller,
        request(
            "layout",
            Some(session_id),
            "kernel.inspect",
            None,
            json!({"view": "bootstrap", "stop_id": stop_id}),
        ),
    )
    .await;
    let layout = layout.result.as_ref().unwrap();
    assert!(
        layout["version"]
            .as_str()
            .is_some_and(|value| value.starts_with("Linux version "))
    );
    assert!(
        layout["image_segments"]
            .as_array()
            .is_some_and(|segments| !segments.is_empty())
    );
    if let Ok(expected) = std::env::var("GDB_AI_KERNEL_EXPECT_PAGE_TABLE") {
        assert_eq!(layout["page_table"], expected);
    }

    let page_table = call(
        &gateway,
        &caller,
        request(
            "page-table",
            Some(session_id),
            "kernel.inspect",
            None,
            json!({
                "view": "page_table",
                "address_expression": layout["image"]["start"],
                "stop_id": stop_id
            }),
        ),
    )
    .await;
    let page_table = page_table.result.as_ref().unwrap();
    assert_eq!(page_table["mapped"], true);
    assert!(
        page_table["physical_address"]
            .as_str()
            .is_some_and(|address| address.starts_with("0x"))
    );
    assert!(
        page_table["levels"]
            .as_array()
            .is_some_and(|levels| (3..=5).contains(&levels.len()))
    );
    if let Ok(expected) = std::env::var("GDB_AI_KERNEL_EXPECT_PAGE_TABLE") {
        assert_eq!(page_table["root_source"], expected);
    }

    let started = std::time::Instant::now();
    let bootstrap = call(
        &gateway,
        &caller,
        request(
            "bootstrap",
            Some(session_id),
            "kernel.inspect",
            None,
            json!({
                "view": "bootstrap",
                "stop_id": stop_id,
                "names": ["_stext", "commit_creds", "prepare_kernel_cred"]
            }),
        ),
    )
    .await;
    let result = bootstrap.result.as_ref().unwrap();
    if let Ok(expected) = std::env::var("GDB_AI_KERNEL_EXPECT_PAGE_TABLE") {
        assert_eq!(result["page_table"], expected);
    }
    assert_eq!(result["missing_symbols"], json!([]));
    assert_eq!(result["symbols"].as_array().unwrap().len(), 3);
    assert!(
        result["current_tasks"]
            .as_array()
            .is_some_and(|tasks| !tasks.is_empty()),
        "bootstrap must recover at least the selected CPU task: {result}"
    );
    assert!(result["symbols"].as_array().unwrap().iter().all(|symbol| {
        symbol["address"]
            .as_str()
            .is_some_and(|address| address.starts_with("0x"))
    }));
    eprintln!("symbol-free bootstrap elapsed: {:?}", started.elapsed());
    if let Ok(expected) = std::env::var("GDB_AI_KERNEL_EXPECT_MODULE") {
        let module = result["modules"]
            .as_array()
            .and_then(|modules| modules.iter().find(|module| module["name"] == expected))
            .unwrap_or_else(|| panic!("expected runtime module {expected}: {result}"));
        assert!(
            module["base"]
                .as_str()
                .is_some_and(|base| base.starts_with("0x"))
        );
        assert!(module["size"].as_u64().is_some_and(|size| size > 0));
        assert!(
            module["segments"]
                .as_array()
                .is_some_and(|segments| !segments.is_empty())
        );
        if let Ok(expected_base) = std::env::var("GDB_AI_KERNEL_EXPECT_MODULE_BASE") {
            assert_eq!(module["base"], expected_base);
        }

        let modules = call(
            &gateway,
            &caller,
            request(
                "runtime-modules",
                Some(session_id),
                "kernel.inspect",
                None,
                json!({"view": "modules", "stop_id": stop_id}),
            ),
        )
        .await;
        assert!(
            modules.result.as_ref().unwrap()["modules"]
                .as_array()
                .is_some_and(|modules| modules.iter().any(|module| module["name"] == expected))
        );

        if let Ok(offset) = std::env::var("GDB_AI_KERNEL_PROBE_OFFSET") {
            let mut parameters = json!({
                "lease_id": lease_id,
                "stop_id": stop_id,
                "kernel_module_offset": {"module": expected, "offset": offset},
                "capture": [{"stack": {"limit": 2}}],
                "budget": {"max_calls": 6, "wall_time_ms": 15000}
            });
            if let Ok(input) = std::env::var("GDB_AI_KERNEL_PROBE_INPUT") {
                parameters["input"] = json!({"text": input});
            }
            let started = std::time::Instant::now();
            let probe = call(
                &gateway,
                &caller,
                request(
                    "runtime-module-probe",
                    Some(session_id),
                    "agent.probe",
                    connected.revision,
                    parameters,
                ),
            )
            .await;
            eprintln!("kernel module probe elapsed: {:?}", started.elapsed());
            let probe = probe.result.as_ref().unwrap();
            assert_eq!(probe["capture_count"], 1);
            assert_eq!(probe["resolved_location"]["module"], expected);
            assert_eq!(probe["resolved_location"]["offset"], offset);
        }
    }
    gateway.shutdown().await;
}

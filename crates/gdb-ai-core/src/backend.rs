use async_trait::async_trait;
use gdb_ai_mi::{MiFramer, MiLimits, MiRecord, encode_command, parse_record, quote_c_string};
use nix::{pty::openpty, unistd::ttyname};
use serde::Serialize;
use std::{
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::{Notify, mpsc},
};

use crate::{
    Error, ErrorCode, Result,
    config::{GdbConfig, Limits, SandboxMode},
    ring::{ByteRing, RingRead},
};

#[derive(Clone, Debug)]
pub enum MiArgument {
    Bare(String),
    String(Vec<u8>),
}

impl MiArgument {
    fn encode(&self) -> String {
        match self {
            Self::Bare(value) => value.clone(),
            Self::String(value) => quote_c_string(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MiCommand {
    pub name: String,
    pub arguments: Vec<MiArgument>,
}

impl MiCommand {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if !name.starts_with('-')
            || name.len() < 2
            || !name
                .bytes()
                .skip(1)
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "MI command name must be a dash followed by letters, digits, or dashes",
            ));
        }
        Ok(Self {
            name,
            arguments: Vec::new(),
        })
    }

    pub fn bare(mut self, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\r' | b'\n'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "bare MI argument contains whitespace",
            ));
        }
        self.arguments.push(MiArgument::Bare(value));
        Ok(self)
    }

    pub fn string(mut self, value: impl AsRef<[u8]>) -> Self {
        self.arguments
            .push(MiArgument::String(value.as_ref().to_vec()));
        self
    }

    pub fn encoded(&self, token: u64) -> Vec<u8> {
        encode_command(
            token,
            &self.name,
            &self
                .arguments
                .iter()
                .map(MiArgument::encode)
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Debug)]
pub enum BackendInput {
    Mi { raw: Vec<u8>, record: MiRecord },
    ProtocolError(Error),
    GdbStderr(Vec<u8>),
    InferiorPty(Vec<u8>),
    GdbEof,
    PtyEof,
}

#[derive(Clone, Debug, Serialize)]
pub struct BackendDescriptor {
    pub name: &'static str,
    pub mi_version: String,
    pub pty: String,
    // 2026-08-28: Bubblewrap was reported as a complete sandbox even though
    // this process only configures filesystem/network hardening and rlimits.
    pub filesystem_hardened: bool,
    pub network_isolated: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SandboxOptions {
    pub mode: SandboxMode,
    pub allow_network: bool,
}

pub struct PtyOutput {
    ring: Mutex<ByteRing>,
    closed: AtomicBool,
    closed_notify: Notify,
}

impl PtyOutput {
    fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(ByteRing::new(capacity)),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        }
    }

    fn append(&self, bytes: &[u8]) {
        self.closed.store(false, Ordering::Release);
        self.ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .append(bytes);
    }

    fn mark_closed(&self) -> bool {
        let changed = !self.closed.swap(true, Ordering::AcqRel);
        if changed {
            self.closed_notify.notify_waiters();
        }
        changed
    }

    pub fn reset(&self) {
        self.closed.store(false, Ordering::Release);
    }

    pub fn read(&self, after_offset: u64, max_bytes: usize) -> RingRead {
        self.ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read(after_offset, max_bytes)
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .dropped_bytes()
    }

    pub async fn wait_closed(&self, timeout: Duration) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let notified = self.closed_notify.notified();
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let _ = tokio::time::timeout(timeout, notified).await;
    }
}

pub struct GdbBackend {
    child: Child,
    stdin: ChildStdin,
    input: BackendInputs,
    pty_writer: tokio::fs::File,
    pty_output: Arc<PtyOutput>,
    descriptor: BackendDescriptor,
}

struct BackendInputs {
    control: mpsc::Receiver<BackendInput>,
    stderr: mpsc::Receiver<BackendInput>,
    pty: mpsc::Receiver<BackendInput>,
    control_closed: bool,
    stderr_closed: bool,
    pty_closed: bool,
}

impl BackendInputs {
    async fn recv(&mut self) -> Option<BackendInput> {
        loop {
            if self.control_closed && self.stderr_closed && self.pty_closed {
                return None;
            }
            tokio::select! {
                biased;
                input = self.control.recv(), if !self.control_closed => match input {
                    Some(input) => return Some(input),
                    None => self.control_closed = true,
                },
                input = self.stderr.recv(), if !self.stderr_closed => match input {
                    Some(input) => return Some(input),
                    None => self.stderr_closed = true,
                },
                input = self.pty.recv(), if !self.pty_closed => match input {
                    Some(input) => return Some(input),
                    None => self.pty_closed = true,
                },
            }
        }
    }
}

#[async_trait]
pub trait DebugBackend: Send {
    fn descriptor(&self) -> &BackendDescriptor;
    fn pty_path(&self) -> &str;
    async fn send(&mut self, token: u64, command: &MiCommand) -> Result<Vec<u8>>;
    async fn next_input(&mut self) -> Option<BackendInput>;
    async fn write_inferior(&mut self, bytes: &[u8]) -> Result<()>;
    async fn resize_inferior(&self, rows: u16, columns: u16) -> Result<()>;
    fn inferior_output(&self) -> Arc<PtyOutput>;
    fn signal_interrupt(&mut self) -> Result<()>;
    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>>;
    async fn shutdown(&mut self) -> Result<()>;
}

impl GdbBackend {
    pub async fn spawn(
        config: &GdbConfig,
        mi_version: &str,
        session_dir: &Path,
        mi_limits: MiLimits,
        resource_limits: &Limits,
        sandbox: SandboxOptions,
    ) -> Result<Self> {
        std::fs::create_dir_all(session_dir)?;
        let pty = openpty(None, None).map_err(|error| {
            Error::new(ErrorCode::Internal, format!("cannot allocate PTY: {error}"))
        })?;
        let pty_path = ttyname(&pty.slave).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("cannot resolve PTY name: {error}"),
            )
        })?;
        let master = std::fs::File::from(pty.master);
        let writer = master.try_clone()?;
        // 2026-08-28: Retaining the parent slave prevented the master reader
        // from observing inferior shutdown. The resolved path is all GDB needs.
        drop(pty.slave);
        let inferior_tmp = session_dir.join("tmp");
        std::fs::create_dir_all(&inferior_tmp)?;

        let sandboxed = sandbox_available(sandbox.mode)?;
        let mut command = if sandboxed {
            let mut command = Command::new("/usr/bin/bwrap");
            // 2026-08-28: Replacing all of /tmp with the session tmp directory
            // hid /tmp targets and a session directory located below /tmp.
            // Bind only the session path and direct temporary writes with TMPDIR.
            command
                .arg("--die-with-parent")
                .arg("--new-session")
                .arg("--ro-bind")
                .arg("/")
                .arg("/")
                .arg("--bind")
                .arg(session_dir)
                .arg(session_dir)
                .arg("--proc")
                .arg("/proc")
                // 2026-08-28: Binding all host devices contradicted the
                // device-deny policy. Create a minimal /dev and expose only
                // devpts so the already allocated inferior PTY remains usable.
                .arg("--dev")
                .arg("/dev")
                .arg("--dev-bind")
                .arg("/dev/pts")
                .arg("/dev/pts")
                .arg("--chdir")
                .arg(session_dir);
            if !sandbox.allow_network {
                command.arg("--unshare-net");
            }
            command.arg("--").arg(&config.path);
            command
        } else {
            Command::new(&config.path)
        };
        command
            .arg("-q")
            .arg("-nx")
            .arg("-iex")
            .arg("set auto-load no")
            .arg("-iex")
            .arg("set debuginfod enabled off")
            .arg("-iex")
            .arg("set startup-with-shell off")
            .arg("-iex")
            .arg("set disable-randomization off")
            .arg("-iex")
            .arg("set may-call-functions off")
            .arg(format!("--interpreter={mi_version}"))
            .current_dir(session_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", session_dir)
            .env("TMPDIR", &inferior_tmp)
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("TERM", "dumb")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let address_space = resource_limits.process_memory_bytes;
        let cpu_seconds = resource_limits.process_cpu_seconds;
        let file_bytes = resource_limits.session_artifact_bytes as u64;
        let open_files = resource_limits.process_open_files;
        let processes = resource_limits.process_count;
        // SAFETY: pre_exec runs after fork and before exec. The closure uses
        // only async-signal-safe libc calls and captured integer values.
        unsafe {
            command.pre_exec(move || {
                set_limit(libc::RLIMIT_AS, address_space)?;
                set_limit(libc::RLIMIT_CPU, cpu_seconds)?;
                set_limit(libc::RLIMIT_FSIZE, file_bytes)?;
                set_limit(libc::RLIMIT_NOFILE, open_files)?;
                // 2026-08-28: RLIMIT_NPROC is counted for the host UID and
                // prevented bubblewrap from creating its namespace. Apply it
                // only when an operator explicitly configures a nonzero value.
                if processes > 0 {
                    set_limit(libc::RLIMIT_NPROC, processes)?;
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command.spawn().map_err(|error| {
            Error::new(
                ErrorCode::TargetUnavailable,
                format!("failed to start {}: {error}", config.path.display()),
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "GDB stdin pipe missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "GDB stdout pipe missing"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "GDB stderr pipe missing"))?;

        // 2026-08-28: PTY bulk output previously filled the shared backend
        // queue and delayed MI results and stop events. Keep each source under
        // independent backpressure and always poll control records first.
        let (control_sender, control) = mpsc::channel(256);
        let (stderr_sender, stderr_input) = mpsc::channel(32);
        let (pty_sender, pty_input) = mpsc::channel(32);
        let pty_output = Arc::new(PtyOutput::new(resource_limits.inferior_output_ring_bytes));
        tokio::spawn(read_mi(stdout, control_sender, mi_limits));
        tokio::spawn(read_stderr(stderr, stderr_sender));
        tokio::spawn(read_pty(
            tokio::fs::File::from_std(master),
            pty_sender,
            pty_output.clone(),
        ));

        Ok(Self {
            child,
            stdin,
            input: BackendInputs {
                control,
                stderr: stderr_input,
                pty: pty_input,
                control_closed: false,
                stderr_closed: false,
                pty_closed: false,
            },
            pty_writer: tokio::fs::File::from_std(writer),
            pty_output,
            descriptor: BackendDescriptor {
                name: "gdb",
                mi_version: mi_version.to_owned(),
                pty: pty_path.to_string_lossy().into_owned(),
                filesystem_hardened: sandboxed,
                network_isolated: sandboxed && !sandbox.allow_network,
            },
        })
    }

    pub fn descriptor(&self) -> &BackendDescriptor {
        &self.descriptor
    }

    pub fn pty_path(&self) -> &str {
        &self.descriptor.pty
    }

    pub async fn send(&mut self, token: u64, command: &MiCommand) -> Result<Vec<u8>> {
        let raw = command.encoded(token);
        self.stdin.write_all(&raw).await.map_err(|error| {
            Error::new(
                ErrorCode::GdbExited,
                format!("cannot write GDB stdin: {error}"),
            )
        })?;
        self.stdin.flush().await.map_err(|error| {
            Error::new(
                ErrorCode::GdbExited,
                format!("cannot flush GDB stdin: {error}"),
            )
        })?;
        Ok(raw)
    }

    pub async fn next_input(&mut self) -> Option<BackendInput> {
        self.input.recv().await
    }

    pub async fn write_inferior(&mut self, bytes: &[u8]) -> Result<()> {
        self.pty_writer.write_all(bytes).await?;
        self.pty_writer.flush().await?;
        Ok(())
    }

    pub async fn resize_inferior(&self, rows: u16, columns: u16) -> Result<()> {
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads the supplied winsize during the call; the
        // fd is owned by self and the pointer remains valid for the call.
        let result = unsafe {
            libc::ioctl(
                self.pty_writer.as_raw_fd(),
                libc::TIOCSWINSZ,
                &winsize as *const libc::winsize,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn inferior_output(&self) -> Arc<PtyOutput> {
        self.pty_output.clone()
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("cannot inspect GDB child: {error}"),
            )
        })
    }

    pub fn signal_interrupt(&mut self) -> Result<()> {
        let pid = self
            .child
            .id()
            .ok_or_else(|| Error::new(ErrorCode::GdbExited, "GDB process has exited"))?;
        let signal = nix::sys::signal::Signal::SIGINT;
        nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid as i32), signal).map_err(
            |error| {
                Error::new(
                    ErrorCode::GdbUnresponsive,
                    format!("cannot signal GDB process group: {error}"),
                )
            },
        )?;
        // 2026-08-28: GDB CLI helpers may create a separate process group, so
        // signaling GDB's group alone left the helper blocking its event loop.
        for descendant in process_descendants(pid) {
            let result = nix::sys::signal::kill(nix::unistd::Pid::from_raw(descendant), signal);
            if let Err(error) = result
                && error != nix::errno::Errno::ESRCH
            {
                return Err(Error::new(
                    ErrorCode::GdbUnresponsive,
                    format!("cannot signal GDB child {descendant}: {error}"),
                ));
            }
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.stdin.write_all(b"-gdb-exit\n").await;
            if tokio::time::timeout(std::time::Duration::from_secs(2), self.child.wait())
                .await
                .is_err()
            {
                // 2026-08-28: Killing only GDB after a shutdown timeout left
                // locally launched inferiors alive in its process group.
                if let Some(pid) = self.child.id() {
                    let _ = nix::sys::signal::killpg(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                } else {
                    self.child.start_kill()?;
                }
                let _ = self.child.wait().await;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DebugBackend for GdbBackend {
    fn descriptor(&self) -> &BackendDescriptor {
        self.descriptor()
    }

    fn pty_path(&self) -> &str {
        self.pty_path()
    }

    async fn send(&mut self, token: u64, command: &MiCommand) -> Result<Vec<u8>> {
        self.send(token, command).await
    }

    async fn next_input(&mut self) -> Option<BackendInput> {
        self.next_input().await
    }

    async fn write_inferior(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_inferior(bytes).await
    }

    async fn resize_inferior(&self, rows: u16, columns: u16) -> Result<()> {
        self.resize_inferior(rows, columns).await
    }

    fn inferior_output(&self) -> Arc<PtyOutput> {
        self.inferior_output()
    }

    fn signal_interrupt(&mut self) -> Result<()> {
        self.signal_interrupt()
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.shutdown().await
    }
}

fn process_descendants(root: u32) -> Vec<i32> {
    fn collect(parent: i32, descendants: &mut Vec<i32>) {
        let path = format!("/proc/{parent}/task/{parent}/children");
        let Ok(children) = std::fs::read_to_string(path) else {
            return;
        };
        for child in children
            .split_ascii_whitespace()
            .filter_map(|child| child.parse::<i32>().ok())
        {
            collect(child, descendants);
            descendants.push(child);
        }
    }

    let mut descendants = Vec::new();
    if let Ok(root) = i32::try_from(root) {
        collect(root, &mut descendants);
    }
    descendants
}

fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // SAFETY: setrlimit copies the provided struct during this call.
    if unsafe { libc::setrlimit(resource, &limit) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn sandbox_available(mode: SandboxMode) -> Result<bool> {
    if mode == SandboxMode::Disabled {
        return Ok(false);
    }
    let available = Path::new("/usr/bin/bwrap").is_file()
        && StdCommand::new("/usr/bin/bwrap")
            .args([
                "--die-with-parent",
                "--unshare-net",
                "--ro-bind",
                "/",
                "/",
                "--",
                "true",
            ])
            .status()
            .is_ok_and(|status| status.success());
    if !available && mode == SandboxMode::Required {
        return Err(Error::new(
            ErrorCode::TargetUnavailable,
            "required bubblewrap sandbox is unavailable",
        ));
    }
    Ok(available)
}

async fn read_stderr<R>(mut reader: R, sender: mpsc::Sender<BackendInput>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; 64 * 1024];
    loop {
        if sender.is_closed() {
            break;
        }
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => {
                if sender
                    .send(BackendInput::GdbStderr(buffer[..length].to_vec()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

async fn read_pty<R>(mut reader: R, sender: mpsc::Sender<BackendInput>, output: Arc<PtyOutput>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; 64 * 1024];
    loop {
        if sender.is_closed() {
            break;
        }
        match reader.read(&mut buffer).await {
            Ok(0) => {
                if output.mark_closed() && sender.send(BackendInput::PtyEof).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(length) => {
                let bytes = buffer[..length].to_vec();
                // 2026-08-28: Exit state could overtake the actor notification
                // and hide trailing output. Publish bytes before queueing metadata.
                output.append(&bytes);
                if sender.send(BackendInput::InferiorPty(bytes)).await.is_err() {
                    break;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                if output.mark_closed() && sender.send(BackendInput::PtyEof).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(_) => break,
        }
    }
}

async fn read_mi<R>(mut reader: R, sender: mpsc::Sender<BackendInput>, limits: MiLimits)
where
    R: AsyncRead + Unpin,
{
    let mut framer = MiFramer::new(limits);
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let length = match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(length) => length,
            Err(error) => {
                let _ = sender
                    .send(BackendInput::ProtocolError(Error::new(
                        ErrorCode::GdbExited,
                        format!("cannot read GDB stdout: {error}"),
                    )))
                    .await;
                return;
            }
        };
        let records = match framer.push(&buffer[..length]) {
            Ok(records) => records,
            Err(error) => {
                let preview = framer.preview(64);
                let error = Error::from(error).with_details(serde_json::json!({
                    "preview_hex": hex_preview(&preview),
                    "preview_bytes": preview.len()
                }));
                let _ = sender.send(BackendInput::ProtocolError(error)).await;
                return;
            }
        };
        for raw in records {
            match parse_record(&raw, limits) {
                Ok(record) => {
                    if sender.send(BackendInput::Mi { raw, record }).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    // 2026-08-28: Parser violations lost the bounded raw
                    // evidence needed to diagnose malformed GDB output.
                    let error = Error::from(error).with_details(serde_json::json!({
                        "preview_hex": hex_preview(&raw[..raw.len().min(64)]),
                        "record_bytes": raw.len()
                    }));
                    let _ = sender.send(BackendInput::ProtocolError(error)).await;
                    return;
                }
            }
        }
    }
    if let Ok(Some(raw)) = framer.finish()
        && !raw.is_empty()
    {
        match parse_record(&raw, limits) {
            Ok(record) => {
                let _ = sender.send(BackendInput::Mi { raw, record }).await;
            }
            Err(error) => {
                let error = Error::from(error).with_details(serde_json::json!({
                    "preview_hex": hex_preview(&raw[..raw.len().min(64)]),
                    "record_bytes": raw.len()
                }));
                let _ = sender.send(BackendInput::ProtocolError(error)).await;
            }
        }
    }
    let _ = sender.send(BackendInput::GdbEof).await;
}

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut preview = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(preview, "{byte:02x}");
    }
    preview
}

pub fn session_directory(root: &Path, session_id: &str) -> PathBuf {
    root.join(session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn command_encoder_prevents_token_and_newline_injection() {
        assert!(MiCommand::new("1-exec-run").is_err());
        assert!(MiCommand::new("-exec-run\n-gdb-exit").is_err());
        assert!(MiCommand::new("-exec-run").unwrap().bare("x y").is_err());
        let command = MiCommand::new("-file-exec-and-symbols")
            .unwrap()
            .string("/tmp/a b");
        assert_eq!(
            command.encoded(7),
            b"7-file-exec-and-symbols \"/tmp/a b\"\n"
        );
    }

    #[test]
    fn dropping_parent_slave_exposes_master_hangup() {
        let pty = openpty(None, None).unwrap();
        let mut master = std::fs::File::from(pty.master);
        drop(pty.slave);

        let error = master.read(&mut [0]).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[tokio::test]
    async fn pty_backpressure_does_not_block_mi_control() {
        let (control_sender, control) = mpsc::channel(1);
        let (_stderr_sender, stderr) = mpsc::channel(1);
        let (pty_sender, pty) = mpsc::channel(1);
        let mut inputs = BackendInputs {
            control,
            stderr,
            pty,
            control_closed: false,
            stderr_closed: false,
            pty_closed: false,
        };
        pty_sender
            .try_send(BackendInput::InferiorPty(vec![0; 64 * 1024]))
            .unwrap();
        control_sender
            .try_send(BackendInput::Mi {
                raw: b"(gdb)\n".to_vec(),
                record: MiRecord::Prompt,
            })
            .unwrap();

        assert!(matches!(
            inputs.recv().await,
            Some(BackendInput::Mi {
                record: MiRecord::Prompt,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn pty_bytes_reach_ring_before_actor_notification() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send(BackendInput::PtyEof).unwrap();
        let output = Arc::new(PtyOutput::new(64));
        let task = tokio::spawn(read_pty(reader, sender, output.clone()));

        writer.write_all(b"marker reached\n").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !output.read(0, 64).bytes.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(output.read(0, 64).bytes, b"marker reached\n");
        task.abort();
    }
}

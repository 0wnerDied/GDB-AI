use async_trait::async_trait;
use gdb_ai_mi::{MiFramer, MiLimits, MiRecord, encode_command, parse_record, quote_c_string};
use nix::{
    pty::openpty,
    sys::resource::{Resource, setrlimit},
    unistd::ttyname,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc as std_mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::{Notify, mpsc},
};

use crate::{
    Error, ErrorCode, Result,
    config::{GdbConfig, Limits, OutputConfig, OutputEvidenceMode, SandboxMode},
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
    InferiorPty,
    GdbEof,
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

#[derive(Clone, Debug, Serialize)]
pub struct OutputEvidenceStatus {
    pub mode: OutputEvidenceMode,
    pub captured_bytes: u64,
    pub spooled_bytes: u64,
    pub dropped_bytes: u64,
    pub complete: bool,
    pub durability: &'static str,
    pub sha256: Option<String>,
    pub artifact_uri: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug)]
struct OutputSpoolState {
    captured: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    active: AtomicBool,
    complete: AtomicBool,
    finalized: AtomicBool,
    failed: AtomicBool,
    sha256: Mutex<Option<String>>,
    artifact_uri: Mutex<Option<String>>,
    error: Mutex<Option<String>>,
}

#[derive(Debug)]
struct OutputSpool {
    mode: OutputEvidenceMode,
    path: PathBuf,
    max_bytes: u64,
    sender: Mutex<Option<std_mpsc::SyncSender<Vec<u8>>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    state: Arc<OutputSpoolState>,
}

impl OutputSpool {
    fn create(session_dir: &Path, name: &str, config: &OutputConfig) -> Result<Self> {
        // 2026-08-29: MI fallback starts a second backend in the same session
        // directory. Give each attempt its own spool so create_new stays safe.
        let path = session_dir.join(format!("inferior-output-{name}.spool"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        let (sender, receiver) = std_mpsc::sync_channel::<Vec<u8>>(64);
        let state = Arc::new(OutputSpoolState {
            captured: AtomicU64::new(0),
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            active: AtomicBool::new(true),
            complete: AtomicBool::new(false),
            finalized: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            sha256: Mutex::new(None),
            artifact_uri: Mutex::new(None),
            error: Mutex::new(None),
        });
        let writer_state = state.clone();
        let worker = std::thread::spawn(move || write_output_spool(file, receiver, writer_state));
        Ok(Self {
            mode: config.evidence,
            path,
            max_bytes: config.max_bytes as u64,
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            state,
        })
    }

    fn capture(&self, bytes: &[u8]) {
        if !self.state.active.load(Ordering::Acquire) {
            // 2026-08-30: PTY bytes can arrive after close timed out and the
            // spool was finalized. Any such drop invalidates its completeness.
            self.state.complete.store(false, Ordering::Release);
            self.state
                .dropped
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return;
        }
        let captured = self.state.captured.load(Ordering::Relaxed);
        let length = (self.max_bytes.saturating_sub(captured) as usize).min(bytes.len());
        let sent = length > 0
            && self
                .sender
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_some_and(|sender| sender.try_send(bytes[..length].to_vec()).is_ok());
        if sent {
            self.state
                .captured
                .fetch_add(length as u64, Ordering::Relaxed);
        }
        if !sent || length < bytes.len() {
            // 2026-08-29: PTY offsets alone could outlive the ring without any
            // recoverable bytes. Preserve a bounded prefix, but never block the
            // target when storage is full or slow; mark the remainder dropped.
            let dropped = bytes.len() - if sent { length } else { 0 };
            self.state
                .dropped
                .fetch_add(dropped as u64, Ordering::Relaxed);
            self.state.active.store(false, Ordering::Release);
            self.sender
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }
    }

    fn finish(&self) -> OutputEvidenceStatus {
        self.state.active.store(false, Ordering::Release);
        self.sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(worker) = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            && worker.join().is_err()
        {
            self.state.failed.store(true, Ordering::Release);
        }
        self.status()
    }

    fn read(&self, after_offset: u64, max_bytes: usize) -> Option<RingRead> {
        let written = self.state.written.load(Ordering::Acquire);
        if after_offset >= written {
            return None;
        }
        let mut file = File::open(&self.path).ok()?;
        file.seek(std::io::SeekFrom::Start(after_offset)).ok()?;
        let length = (written - after_offset).min(max_bytes as u64) as usize;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes).ok()?;
        Some(RingRead {
            requested_offset: after_offset,
            available_from: 0,
            next_offset: after_offset + length as u64,
            gap: false,
            bytes,
        })
    }

    fn status(&self) -> OutputEvidenceStatus {
        OutputEvidenceStatus {
            mode: self.mode,
            captured_bytes: self.state.captured.load(Ordering::Acquire),
            spooled_bytes: self.state.written.load(Ordering::Acquire),
            dropped_bytes: self.state.dropped.load(Ordering::Acquire),
            complete: self.state.complete.load(Ordering::Acquire),
            durability: if self
                .state
                .artifact_uri
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_some()
            {
                "artifact"
            } else if self.state.finalized.load(Ordering::Acquire) {
                "synced"
            } else {
                "buffered"
            },
            sha256: self
                .state
                .sha256
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            artifact_uri: self
                .state
                .artifact_uri
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            error: self
                .state
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .or_else(|| {
                    self.state
                        .failed
                        .load(Ordering::Acquire)
                        .then(|| "inferior output spool write failed".to_owned())
                }),
        }
    }
}

fn write_output_spool(
    mut file: File,
    receiver: std_mpsc::Receiver<Vec<u8>>,
    state: Arc<OutputSpoolState>,
) {
    let mut hasher = Sha256::new();
    for bytes in receiver {
        if file.write_all(&bytes).is_err() {
            state.failed.store(true, Ordering::Release);
            state.active.store(false, Ordering::Release);
            return;
        }
        hasher.update(&bytes);
        state
            .written
            .fetch_add(bytes.len() as u64, Ordering::Release);
    }
    if file.sync_data().is_err() {
        state.failed.store(true, Ordering::Release);
        return;
    }
    *state
        .sha256
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some(format!("{:x}", hasher.finalize()));
    state.complete.store(
        state.dropped.load(Ordering::Acquire) == 0,
        Ordering::Release,
    );
    state.finalized.store(true, Ordering::Release);
}

pub struct PtyOutput {
    ring: Mutex<ByteRing>,
    evidence_mode: OutputEvidenceMode,
    spool: Option<OutputSpool>,
    closed: AtomicBool,
    closed_notify: Notify,
    rearm_notify: Notify,
}

impl PtyOutput {
    #[cfg(test)]
    fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(ByteRing::new(capacity)),
            evidence_mode: OutputEvidenceMode::EphemeralRing,
            spool: None,
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
            rearm_notify: Notify::new(),
        }
    }

    fn with_evidence(
        capacity: usize,
        config: &OutputConfig,
        session_dir: &Path,
        name: &str,
    ) -> Result<Self> {
        let spool = match config.evidence {
            OutputEvidenceMode::EphemeralRing => None,
            OutputEvidenceMode::BoundedSpool | OutputEvidenceMode::Artifact => {
                Some(OutputSpool::create(session_dir, name, config)?)
            }
        };
        Ok(Self {
            ring: Mutex::new(ByteRing::new(capacity)),
            evidence_mode: config.evidence,
            spool,
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
            rearm_notify: Notify::new(),
        })
    }

    fn append(&self, bytes: &[u8]) {
        self.closed.store(false, Ordering::Release);
        let mut ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ring.append(bytes);
        drop(ring);
        if let Some(spool) = &self.spool {
            spool.capture(bytes);
        }
    }

    pub(crate) fn position(&self) -> (u64, u64) {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (ring.end_offset(), ring.dropped_bytes())
    }

    fn mark_closed(&self) -> bool {
        let changed = !self.closed.swap(true, Ordering::AcqRel);
        if changed {
            self.closed_notify.notify_waiters();
        }
        changed
    }

    pub fn reset(&self) {
        if self.closed.swap(false, Ordering::AcqRel) {
            self.rearm_notify.notify_waiters();
        }
    }

    async fn wait_rearmed(&self) {
        loop {
            let notified = self.rearm_notify.notified();
            if !self.closed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub fn read(&self, after_offset: u64, max_bytes: usize) -> RingRead {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read(after_offset, max_bytes);
        if ring.gap
            && let Some(read) = self
                .spool
                .as_ref()
                .and_then(|spool| spool.read(after_offset, max_bytes))
        {
            return read;
        }
        ring
    }

    pub fn evidence_status(&self) -> OutputEvidenceStatus {
        match &self.spool {
            Some(spool) => spool.status(),
            None => {
                let (end, dropped) = self.position();
                OutputEvidenceStatus {
                    mode: self.evidence_mode,
                    captured_bytes: end.saturating_sub(dropped),
                    spooled_bytes: 0,
                    dropped_bytes: dropped,
                    complete: false,
                    durability: "ephemeral",
                    sha256: None,
                    artifact_uri: None,
                    error: None,
                }
            }
        }
    }

    pub fn finish_evidence(&self) -> OutputEvidenceStatus {
        match &self.spool {
            Some(spool) => spool.finish(),
            None => self.evidence_status(),
        }
    }

    pub fn evidence_path(&self) -> Option<&Path> {
        self.spool.as_ref().map(|spool| spool.path.as_path())
    }

    pub fn set_artifact_uri(&self, uri: String) {
        if let Some(spool) = &self.spool {
            *spool
                .state
                .artifact_uri
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(uri);
        }
    }

    pub fn set_evidence_error(&self, error: String) {
        if let Some(spool) = &self.spool {
            spool.state.complete.store(false, Ordering::Release);
            *spool
                .state
                .error
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        }
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
        output_config: &OutputConfig,
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
            .arg("-iex")
            .arg("unset environment MALLOC_ARENA_MAX")
            .arg(format!("--interpreter={mi_version}"))
            .current_dir(session_dir)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", session_dir)
            .env("TMPDIR", &inferior_tmp)
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("TERM", "dumb")
            // 2026-08-29: GDB 10 creates a glibc arena for each worker before
            // the prompt and can exhaust RLIMIT_AS on large hosts. Bound GDB's
            // allocator arenas, then remove this variable from the inferior.
            .env("MALLOC_ARENA_MAX", "2")
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
                set_limit(Resource::RLIMIT_AS, address_space)?;
                set_limit(Resource::RLIMIT_CPU, cpu_seconds)?;
                set_limit(Resource::RLIMIT_FSIZE, file_bytes)?;
                set_limit(Resource::RLIMIT_NOFILE, open_files)?;
                // 2026-08-28: RLIMIT_NPROC is counted for the host UID and
                // prevented bubblewrap from creating its namespace. Apply it
                // only when an operator explicitly configures a nonzero value.
                if processes > 0 {
                    set_limit(Resource::RLIMIT_NPROC, processes)?;
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
        let (pty_sender, pty_input) = mpsc::channel(1);
        let pty_output = Arc::new(PtyOutput::with_evidence(
            resource_limits.inferior_output_ring_bytes,
            output_config,
            session_dir,
            mi_version,
        )?);
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

fn set_limit(resource: Resource, value: u64) -> std::io::Result<()> {
    // 2026-08-29: libc's private resource type differs between GNU and musl;
    // use nix's portable wrapper so both official and developer builds work.
    setrlimit(resource, value as libc::rlim_t, value as libc::rlim_t).map_err(Into::into)
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
                output.mark_closed();
                // 2026-08-28: A closed reusable PTY master returns EOF/EIO
                // immediately. Wait for the next run instead of polling it.
                tokio::select! {
                    _ = output.wait_rearmed() => {}
                    _ = sender.closed() => break,
                }
            }
            Ok(length) => {
                output.append(&buffer[..length]);
                // 2026-08-29: Awaiting one metadata message per PTY chunk let
                // a slow actor stop PTY draining and eventually block target
                // output. A full channel already contains a sufficient wakeup.
                if !try_notify_pty(&sender, BackendInput::InferiorPty) {
                    break;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                output.mark_closed();
                // 2026-08-28: Linux reports PTY hangup as EIO. A target run
                // explicitly rearms the reader when a new slave can appear.
                tokio::select! {
                    _ = output.wait_rearmed() => {}
                    _ = sender.closed() => break,
                }
            }
            Err(_) => break,
        }
    }
}

fn try_notify_pty(sender: &mpsc::Sender<BackendInput>, input: BackendInput) -> bool {
    match sender.try_send(input) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
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
    use std::{
        io::Read,
        pin::Pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll},
    };
    use tokio::io::ReadBuf;

    struct CountingEof(Arc<AtomicUsize>);

    impl AsyncRead for CountingEof {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

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
        pty_sender.try_send(BackendInput::InferiorPty).unwrap();
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
    async fn full_notification_queue_does_not_stop_pty_drain() {
        let (mut writer, reader) = tokio::io::duplex(8);
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send(BackendInput::InferiorPty).unwrap();
        let output = Arc::new(PtyOutput::new(256));
        let task = tokio::spawn(read_pty(reader, sender, output.clone()));

        let expected = vec![b'x'; 128];
        tokio::time::timeout(Duration::from_secs(1), writer.write_all(&expected))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if output.position().0 == expected.len() as u64 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(output.read(0, 256).bytes, expected);
        task.abort();
    }

    #[tokio::test]
    async fn closed_pty_waits_for_explicit_rearm() {
        let reads = Arc::new(AtomicUsize::new(0));
        let (sender, _receiver) = mpsc::channel(1);
        let output = Arc::new(PtyOutput::new(64));
        let task = tokio::spawn(read_pty(CountingEof(reads.clone()), sender, output.clone()));

        output.wait_closed(Duration::from_secs(1)).await;
        assert!(output.closed.load(Ordering::Acquire));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(reads.load(Ordering::Relaxed), 1);

        output.reset();
        output.wait_closed(Duration::from_secs(1)).await;
        assert!(output.closed.load(Ordering::Acquire));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        task.abort();
    }

    #[test]
    fn bounded_spool_preserves_a_recoverable_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let output = PtyOutput::with_evidence(
            2,
            &OutputConfig {
                evidence: OutputEvidenceMode::BoundedSpool,
                max_bytes: 4,
            },
            directory.path(),
            "test",
        )
        .unwrap();
        output.append(b"abcdef");
        let status = output.finish_evidence();
        assert_eq!(status.captured_bytes, 4);
        assert_eq!(status.spooled_bytes, 4);
        assert_eq!(status.dropped_bytes, 2);
        assert!(!status.complete);
        assert_eq!(status.durability, "synced");
        assert_eq!(output.read(0, 8).bytes, b"abcd");
        assert_eq!(
            status.sha256.as_deref(),
            Some("88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589")
        );
    }

    #[test]
    fn late_output_invalidates_finalized_spool_completeness() {
        let directory = tempfile::tempdir().unwrap();
        let output = PtyOutput::with_evidence(
            16,
            &OutputConfig {
                evidence: OutputEvidenceMode::BoundedSpool,
                max_bytes: 16,
            },
            directory.path(),
            "late-output",
        )
        .unwrap();
        output.append(b"kept");
        assert!(output.finish_evidence().complete);

        output.append(b"late");
        let status = output.evidence_status();
        assert!(!status.complete);
        assert_eq!(status.dropped_bytes, 4);
    }
}

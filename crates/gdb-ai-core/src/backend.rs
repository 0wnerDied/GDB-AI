use async_trait::async_trait;
use gdb_ai_mi::{MiFramer, MiLimits, MiRecord, encode_command, parse_record, quote_c_string};
use nix::{pty::openpty, unistd::ttyname};
use serde::Serialize;
use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
};

use crate::{
    Error, ErrorCode, Result,
    config::{GdbConfig, Limits, SandboxMode},
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
    pub sandboxed: bool,
    pub network_isolated: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct SandboxOptions {
    pub mode: SandboxMode,
    pub allow_network: bool,
}

pub struct GdbBackend {
    child: Child,
    stdin: ChildStdin,
    input: mpsc::Receiver<BackendInput>,
    pty_writer: tokio::fs::File,
    _pty_slave: OwnedFd,
    descriptor: BackendDescriptor,
}

#[async_trait]
pub trait DebugBackend: Send {
    fn descriptor(&self) -> &BackendDescriptor;
    fn pty_path(&self) -> &str;
    async fn send(&mut self, token: u64, command: &MiCommand) -> Result<Vec<u8>>;
    async fn next_input(&mut self) -> Option<BackendInput>;
    async fn write_inferior(&mut self, bytes: &[u8]) -> Result<()>;
    async fn resize_inferior(&self, rows: u16, columns: u16) -> Result<()>;
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

        let (sender, input) = mpsc::channel(256);
        tokio::spawn(read_mi(stdout, sender.clone(), mi_limits));
        tokio::spawn(read_chunks(stderr, sender.clone(), StreamKind::Stderr));
        tokio::spawn(read_chunks(
            tokio::fs::File::from_std(master),
            sender,
            StreamKind::Pty,
        ));

        Ok(Self {
            child,
            stdin,
            input,
            pty_writer: tokio::fs::File::from_std(writer),
            _pty_slave: pty.slave,
            descriptor: BackendDescriptor {
                name: "gdb",
                mi_version: mi_version.to_owned(),
                pty: pty_path.to_string_lossy().into_owned(),
                sandboxed,
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
        use std::os::fd::AsRawFd;
        // SAFETY: TIOCSWINSZ reads the supplied winsize during the call; the
        // fd is owned by self and the pointer remains valid for the call.
        let result = unsafe {
            libc::ioctl(
                self._pty_slave.as_raw_fd(),
                libc::TIOCSWINSZ,
                &winsize as *const libc::winsize,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("cannot inspect GDB child: {error}"),
            )
        })
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

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.shutdown().await
    }
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

enum StreamKind {
    Stderr,
    Pty,
}

async fn read_chunks<R>(mut reader: R, sender: mpsc::Sender<BackendInput>, kind: StreamKind)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; 64 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                if matches!(kind, StreamKind::Pty) {
                    let _ = sender.send(BackendInput::PtyEof).await;
                }
                break;
            }
            Ok(length) => {
                let input = match kind {
                    StreamKind::Stderr => BackendInput::GdbStderr(buffer[..length].to_vec()),
                    StreamKind::Pty => BackendInput::InferiorPty(buffer[..length].to_vec()),
                };
                if sender.send(input).await.is_err() {
                    break;
                }
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
}

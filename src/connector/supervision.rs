use std::{io, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader},
    process::{Child, Command},
    sync::mpsc,
    time::{interval, timeout},
};

use super::{
    bounded_file,
    guard::verify_guard_marker,
    readiness::{HealthMarkers, Registrations},
    remove_marker,
};

#[cfg(test)]
#[path = "supervision_tests.rs"]
mod tests;

/// Run the bundled client only after successful egress installation. Linux
/// parent-death SIGKILL and kill-on-drop cover supervisor failure; explicit
/// SIGTERM/SIGINT forwarding has a five-second hard kill deadline.
#[cfg(target_os = "linux")]
pub async fn run(config: &Path, ready: &Path) -> Result<()> {
    let markers = HealthMarkers::new(ready)?;
    verify_guard_marker()?;

    let bytes = bounded_file(config)?;
    let contents = std::str::from_utf8(&bytes).context("FRP config is not UTF-8")?;
    let registrations = Registrations::from_config(contents)?;

    let mut command = Command::new("/usr/local/bin/frpc");
    command.args(["-c"]).arg(config);
    supervise(command, registrations, markers).await
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_: &Path, _: &Path) -> Result<()> {
    bail!("connector supervision requires Linux")
}

#[cfg(target_os = "linux")]
async fn supervise(
    command: Command,
    mut registrations: Registrations,
    markers: HealthMarkers,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    // Register handlers before spawning: otherwise a fast termination could
    // interrupt the wrapper without forwarding the requested signal.
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    let mut process = Process::spawn(command)?;
    let (send, mut logs) = mpsc::channel::<Result<String>>(64);
    let stdout = process.child.stdout.take().context("missing FRP stdout")?;
    let stderr = process.child.stderr.take().context("missing FRP stderr")?;
    tokio::spawn(stream_logs(stdout, send.clone()));
    tokio::spawn(stream_logs(stderr, send));
    let mut tick = interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            biased;
            _ = terminate.recv() => {
                remove_marker(&markers.ready)?;
                process.stop(libc::SIGTERM).await?;

                return Ok(());
            }
            _ = interrupt.recv() => {
                remove_marker(&markers.ready)?;
                process.stop(libc::SIGINT).await?;

                return Ok(());
            }
            status = process.child.wait() => {
                let status = status?;
                bail!("FRP client exited: {status}");
            }
            _ = tick.tick() => markers.refresh(registrations.ready())?,
            line = logs.recv() => {
                let line = line.context("FRP console streams closed")??;
                let was_ready = registrations.ready();
                registrations.observe(&line);

                if registrations.ready() != was_ready {
                    tracing::info!(registered = registrations.ready(), "FRP registration state changed");
                }

                markers.refresh(registrations.ready())?;
                // Do not re-emit untrusted remote error text (which can include
                // injected log lines or credentials). Report state transitions
                // through readiness and preserve bounded memory.
            }
        }
    }
}

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
struct Process {
    child: Child,
    pid: i32,
}

#[cfg(target_os = "linux")]
impl Process {
    fn spawn(mut command: Command) -> Result<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        let parent = std::process::id() as libc::pid_t;

        // SAFETY: the pre-exec callback only invokes async-signal-safe Linux
        // syscalls and constructs io::Error. Check PPID after setting PDEATHSIG
        // to close the race where the parent died before prctl.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }

                if libc::getppid() != parent {
                    libc::_exit(127);
                }

                Ok(())
            });
        }

        let child = command.spawn().context("cannot start bundled FRP client")?;
        let pid = child.id().context("spawned FRP client has no PID")? as i32;
        Ok(Self { child, pid })
    }

    fn signal(&self, signal: i32) -> Result<()> {
        // SAFETY: pid is the positive PID of a child placed in its own process
        // group, so -pid cannot target the supervisor's process group.
        if unsafe { libc::kill(-self.pid, signal) } != 0 {
            let error = io::Error::last_os_error();

            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }

        Ok(())
    }

    async fn stop(&mut self, signal: i32) -> Result<()> {
        self.signal(signal)?;
        match timeout(SHUTDOWN_TIMEOUT, self.child.wait()).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                self.signal(libc::SIGKILL)?;
                timeout(SHUTDOWN_TIMEOUT, self.child.wait())
                    .await
                    .context("FRP did not exit after SIGKILL")??;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.signal(libc::SIGKILL);
    }
}

const MAX_LOG_BYTES: usize = 16_384;

async fn stream_logs(reader: impl AsyncRead + Unpin, sender: mpsc::Sender<Result<String>>) {
    let mut reader = BufReader::new(reader);

    loop {
        match bounded_line(&mut reader).await {
            Ok(Some(line)) => {
                if sender.send(Ok(line)).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(error) => {
                let _ = sender.send(Err(error)).await;

                return;
            }
        }
    }
}

async fn bounded_line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> Result<Option<String>> {
    let mut buffer = Vec::new();
    let bytes = reader
        .take(MAX_LOG_BYTES as u64 + 1)
        .read_until(b'\n', &mut buffer)
        .await?;
    ensure!(bytes <= MAX_LOG_BYTES, "FRP log line exceeds size limit");

    if bytes == 0 {
        Ok(None)
    } else {
        Ok(Some(
            String::from_utf8(buffer).context("invalid FRP log encoding")?,
        ))
    }
}

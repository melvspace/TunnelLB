//! Isolated local processes with bounded I/O, deadlines, and private input files.
use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};

const OUTPUT_LIMIT: usize = 64 * 1024;

pub(super) fn isolated_command(program: &str, home: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", home)
        .env("LC_ALL", "C")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .current_dir(home)
        .kill_on_drop(true);

    command
}

pub(super) struct Output {
    pub(super) success: bool,
    pub(super) stdout: String,
    pub(super) stderr: String,
}

pub(super) async fn execute(mut command: Command, input: &[u8], limit: Duration) -> Result<Output> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("starting OpenSSH; ensure openssh-client is installed in the worker image")?;
    let mut stdin = child.stdin.take().context("missing SSH stdin")?;
    let stdout = child.stdout.take().context("missing SSH stdout")?;
    let stderr = child.stderr.take().context("missing SSH stderr")?;
    let operation = async {
        let write = async move {
            if let Err(error) = stdin.write_all(input).await
                && error.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(error.into());
            }

            // ChildStdin's shutdown alone need not close the pipe. Send EOF so
            // remote bash -s cannot wait indefinitely after the last command.
            drop(stdin);

            Ok::<(), anyhow::Error>(())
        };

        let (status, _, stdout, stderr) = tokio::try_join!(
            async { Ok::<_, anyhow::Error>(child.wait().await?) },
            write,
            read_bounded(stdout),
            read_bounded(stderr)
        )?;

        Ok::<_, anyhow::Error>(Output {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    };

    match timeout(limit, operation).await {
        Ok(Ok(result)) => Ok(result),
        outcome => {
            let _ = child.kill().await;
            let _ = child.wait().await;

            match outcome {
                Ok(Err(error)) => {
                    Err(error.context("SSH process failed or exceeded its output limit"))
                }

                Err(_) => bail!(
                    "SSH command timed out; check network reachability and pending remote cleanup"
                ),
                _ => unreachable!(),
            }
        }
    }
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0; 4096];

    loop {
        let count = reader.read(&mut buffer).await?;

        if count == 0 {
            return Ok(output);
        }

        ensure!(
            output.len() + count <= OUTPUT_LIMIT,
            "remote output exceeded 64 KiB"
        );
        output.extend_from_slice(&buffer[..count]);
    }
}

pub(super) async fn read_limited_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    ensure!(file.metadata().await?.is_file(), "expected a regular file");
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() as u64 <= limit,
        "input file exceeds its size limit"
    );

    Ok(bytes)
}

pub(super) async fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .await?;
    file.write_all(bytes).await?;
    file.shutdown().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn private_key_copy_is_mode_0600_and_output_is_bounded() {
        tokio::fs::create_dir_all("/tmp/codex").await.unwrap();
        let directory = tempfile::tempdir_in("/tmp/codex").unwrap();
        let key = directory.path().join("key");
        private_file(&key, b"secret").await.unwrap();
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(private_file(&key, b"replacement").await.is_err());
        assert!(read_bounded(&[b'a'; OUTPUT_LIMIT + 1][..]).await.is_err());
        assert_eq!(read_bounded(&b"ok"[..]).await.unwrap(), b"ok");
    }

    #[tokio::test]
    async fn process_runner_sends_eof_and_enforces_deadlines_and_output_limits() {
        tokio::fs::create_dir_all("/tmp/codex").await.unwrap();
        let home = tempfile::tempdir_in("/tmp/codex").unwrap();
        let result = execute(
            isolated_command("cat", home.path()),
            b"received stdin",
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(result.success);
        assert_eq!(result.stdout, "received stdin");
        let mut command = isolated_command("sleep", home.path());
        command.arg("10");
        let started = std::time::Instant::now();
        assert!(
            execute(command, b"", Duration::from_millis(30))
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            execute(
                isolated_command("yes", home.path()),
                b"",
                Duration::from_secs(2)
            )
            .await
            .is_err()
        );
    }
}

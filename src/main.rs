use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, Write},
    net::SocketAddrV4,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Result, anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use kube::CustomResourceExt;
use tracing_subscriber::EnvFilter;
use tunnellb::{api::Server, connector, controller, provision};

const DEFAULT_READY_PATH: &str = "/tmp/tunnellb-ready";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESULT_BYTES: usize = 4096;
const WORKER_FAILURE: &str = "SSH worker failed";
const FAILURE_RESULT: &[u8] = b"{\"error\":\"SSH worker failed\"}";

#[derive(Parser)]
#[command(name = "tunnellb", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reconcile Servers and LoadBalancer Services.
    Controller(controller::Config),
    /// Print the Server CustomResourceDefinition as YAML.
    Crd,
    /// Install the worker pod's egress guard before starting its main process.
    Guard(GuardArgs),
    /// Supervise an FRP connector after its egress guard is installed.
    Connector {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_READY_PATH)]
        ready: PathBuf,
    },
    /// Check the connector's health marker.
    Ready {
        #[arg(long, default_value = DEFAULT_READY_PATH)]
        path: PathBuf,
    },
    /// Perform one bounded SSH operation and write its termination result.
    SshWorker(WorkerArgs),
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct GuardArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    allow: Option<SocketAddrV4>,
}

#[derive(Args)]
struct WorkerArgs {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value = "/dev/termination-log")]
    result: PathBuf,
    #[arg(long, default_value = "/opt/frp")]
    frp_directory: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init()
        .is_err()
    {
        eprintln!("Could not initialize logging");

        return ExitCode::FAILURE;
    }

    // Parsing and subprocess errors can contain credential material. Only these
    // fixed messages cross the process boundary; never print the error chain.
    let failure = match &cli.command {
        Command::Controller(_) => "Controller failed",
        Command::Crd => "CRD generation failed",
        Command::Guard(_) => "Egress guard failed",
        Command::Connector { .. } => "Connector failed",
        Command::Ready { .. } => "Connector is not ready",
        Command::SshWorker(_) => WORKER_FAILURE,
    };
    match dispatch(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            tracing::error!("{failure}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Controller(config) => controller::run(config).await,
        Command::Crd => Ok(serde_yaml::to_writer(io::stdout().lock(), &Server::crd())?),
        Command::Guard(args) => match (args.config, args.allow) {
            (Some(config), None) => connector::apply_guard(&config).await,
            (None, Some(address)) => connector::apply_allow(address).await,
            _ => Err(anyhow!("Exactly one guard destination is required")),
        },
        Command::Connector { config, ready } => connector::run(&config, &ready).await,
        Command::Ready { path } => connector::ready(&path),
        Command::SshWorker(args) => run_worker(args).await,
    }
}

fn worker_failure() -> anyhow::Error {
    anyhow!(WORKER_FAILURE)
}

fn parse_request(reader: impl Read) -> Result<provision::Request> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| worker_failure())?;
    ensure!(bytes.len() <= MAX_REQUEST_BYTES, WORKER_FAILURE);
    serde_json::from_slice(&bytes).map_err(|_| worker_failure())
}

fn read_request(path: &Path) -> Result<provision::Request> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Projected Secret paths are symlinks, so follow them, but do not block
        // forever opening a FIFO supplied as a request path.
        options.custom_flags(libc::O_NONBLOCK);
    }

    let file = options.open(path).map_err(|_| worker_failure())?;
    ensure!(
        file.metadata().map_err(|_| worker_failure())?.is_file(),
        WORKER_FAILURE
    );
    parse_request(file)
}

fn encode_outcome(outcome: &provision::Outcome) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(outcome).map_err(|_| worker_failure())?;
    ensure!(bytes.len() <= MAX_RESULT_BYTES, WORKER_FAILURE);
    Ok(bytes)
}

fn write_result(file: &mut File, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_RESULT_BYTES, WORKER_FAILURE);
    file.rewind().map_err(|_| worker_failure())?;
    file.set_len(0).map_err(|_| worker_failure())?;
    file.write_all(bytes).map_err(|_| worker_failure())?;
    file.flush().map_err(|_| worker_failure())
}

async fn run_worker(args: WorkerArgs) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    let mut result = options.open(&args.result).map_err(|_| worker_failure())?;
    ensure!(
        result.metadata().map_err(|_| worker_failure())?.is_file(),
        WORKER_FAILURE
    );
    // Kubernetes bind-mounts this file: update it in place, never rename over it.
    // Establish a safe failure result and detect unwritable output before SSH.
    write_result(&mut result, FAILURE_RESULT)?;
    let request = read_request(&args.request)?;
    let outcome = provision::run(&request, &args.key, &args.frp_directory)
        .await
        .map_err(|_| worker_failure())?;
    let bytes = encode_outcome(&outcome)?;
    write_result(&mut result, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn request_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "operation": "enroll",
            "address": "203.0.113.1",
            "sshUser": "operator",
            "sshPort": 22,
            "serverUid": "55555555-5555-4555-8555-555555555555",
            "publication": null,
            "serverConfig": null,
            "serverCertificate": null,
            "serverPrivateKey": null,
            "expectedKnownHosts": null
        }))
        .unwrap()
    }

    fn outcome(known_hosts: String) -> provision::Outcome {
        provision::Outcome {
            known_hosts,
            fingerprint: "SHA256:example".into(),
            architecture: "amd64".into(),
            allocation: None,
        }
    }

    fn scratch() -> tempfile::TempDir {
        std::fs::create_dir_all("/tmp/codex").unwrap();
        tempfile::tempdir_in("/tmp/codex").unwrap()
    }

    #[test]
    fn guard_requires_exactly_one_destination() {
        for args in [
            vec!["tunnellb", "guard", "--config", "/etc/tunnellb/guard.json"],
            vec!["tunnellb", "guard", "--allow", "203.0.113.1:22"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }

        let error = Cli::try_parse_from(["tunnellb", "guard"]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        let error = Cli::try_parse_from([
            "tunnellb",
            "guard",
            "--config",
            "guard.json",
            "--allow",
            "203.0.113.1:22",
        ])
        .err()
        .unwrap();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        assert!(Cli::try_parse_from(["tunnellb", "guard", "--allow", "[::1]:22"]).is_err());
    }

    #[test]
    fn generated_worker_and_connector_arguments_have_expected_defaults() {
        let cli = Cli::try_parse_from([
            "tunnellb",
            "ssh-worker",
            "--request",
            "/etc/request/request.json",
            "--key",
            "/etc/ssh-key/ssh-privatekey",
        ])
        .unwrap();
        let Command::SshWorker(args) = cli.command else {
            panic!("wrong subcommand");
        };
        assert_eq!(args.result, Path::new("/dev/termination-log"));
        assert_eq!(args.frp_directory, Path::new("/opt/frp"));
        assert!(Cli::try_parse_from(["tunnellb", "ssh-worker", "--request", "r"]).is_err());
        let cli = Cli::try_parse_from(["tunnellb", "connector", "--config", "frpc.toml"]).unwrap();
        let Command::Connector { ready, .. } = cli.command else {
            panic!("wrong subcommand");
        };
        assert_eq!(ready, Path::new(DEFAULT_READY_PATH));
        let Command::Ready { path } = Cli::try_parse_from(["tunnellb", "ready"]).unwrap().command
        else {
            panic!("wrong subcommand");
        };
        assert_eq!(path, Path::new(DEFAULT_READY_PATH));
    }

    #[test]
    fn request_limit_checks_the_whole_input() {
        let mut bytes = request_json();
        bytes.resize(MAX_REQUEST_BYTES, b' ');
        assert!(parse_request(bytes.as_slice()).is_ok());
        bytes.push(b' ');
        assert!(parse_request(bytes.as_slice()).is_err());
        let mut bytes = request_json();
        bytes.extend_from_slice(b" garbage");
        assert!(parse_request(bytes.as_slice()).is_err());
        assert!(parse_request([0xff].as_slice()).is_err());
    }

    #[test]
    fn parser_errors_do_not_include_secret_input() {
        let request = b"{\"operation\":\"SECRET_SENTINEL\"}";
        let error = parse_request(request.as_slice()).err().unwrap();
        assert_eq!(format!("{error:#}"), WORKER_FAILURE);
        assert!(!format!("{error:?}").contains("SECRET_SENTINEL"));
    }

    #[test]
    fn outcome_limit_counts_serialized_bytes_including_escaping() {
        for allocation in [
            None,
            Some(provision::AllocationOutcome::Reserved {
                control_port: u16::MAX,
            }),
            Some(provision::AllocationOutcome::PortConflict { port: u16::MAX }),
            Some(provision::AllocationOutcome::ControlRangeExhausted),
            Some(provision::AllocationOutcome::ReservationChanged),
        ] {
            let mut result = outcome(String::new());
            result.allocation = allocation;
            let overhead = encode_outcome(&result).unwrap().len();

            result.known_hosts = "a".repeat(MAX_RESULT_BYTES - overhead);
            assert_eq!(encode_outcome(&result).unwrap().len(), MAX_RESULT_BYTES);
            result.known_hosts.push('a');
            let error = encode_outcome(&result).unwrap_err();
            assert_eq!(format!("{error:#}"), WORKER_FAILURE);

            for value in ["\n", "é"] {
                result.known_hosts = value.repeat(MAX_RESULT_BYTES / 2);
                assert!(encode_outcome(&result).is_err());
            }
        }
    }

    #[tokio::test]
    async fn failed_request_replaces_stale_success_with_safe_result() {
        let directory = scratch();
        let request = directory.path().join("request.json");
        let result = directory.path().join("result.json");
        std::fs::write(&request, b"{\"operation\":\"SECRET_SENTINEL\"}").unwrap();
        std::fs::write(
            &result,
            encode_outcome(&outcome("old host".into())).unwrap(),
        )
        .unwrap();
        let error = run_worker(WorkerArgs {
            request,
            key: directory.path().join("unused-key"),
            result: result.clone(),
            frp_directory: directory.path().into(),
        })
        .await
        .unwrap_err();
        assert_eq!(format!("{error:#}"), WORKER_FAILURE);
        assert_eq!(std::fs::read(result).unwrap(), FAILURE_RESULT);
    }

    #[test]
    fn result_is_rewritten_without_replacing_the_file() {
        let directory = scratch();
        let path = directory.path().join("result.json");
        let mut file = File::create(&path).unwrap();
        write_result(&mut file, &[b'x'; MAX_RESULT_BYTES]).unwrap();
        write_result(&mut file, FAILURE_RESULT).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), FAILURE_RESULT);
    }
}

//! Optional kernel-level check; all firewall changes stay in private namespaces.
use super::*;

#[test]
#[ignore = "requires installed UFW, Python 3, iproute2, and unprivileged user/network/mount namespaces"]
fn real_ufw_opens_and_closes_only_publication_ports() {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all("/tmp/codex").unwrap();
    let scratch = tempfile::tempdir_in("/tmp/codex").unwrap();
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let request = request(Operation::Apply);
    let prelude = super::super::host::prelude(&request).replace(
        "/var/lib/tunnellb",
        scratch.path().join("state").to_str().unwrap(),
    );
    let script = format!(
        "scratch={}\n{SETUP}\n{prelude}\n{EXERCISE}",
        shell_quote(scratch.path().to_str().unwrap())
    );
    let mut child = std::process::Command::new("timeout")
        .args([
            "--kill-after=5",
            "60",
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "--propagation",
            "private",
            "bash",
            "-s",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const SETUP: &str = r#"
set -Eeuo pipefail
umask 077
mkdir -p "$scratch/ufw/applications.d"
cp /usr/share/ufw/*.rules /usr/share/ufw/*.init /usr/share/ufw/ufw.conf "$scratch/ufw/"
cp /etc/ufw/sysctl.conf "$scratch/ufw/"
cp /etc/default/ufw "$scratch/default"
cp -r /usr/lib/ufw "$scratch/ufw-lib"
mount --bind "$scratch/ufw" /etc/ufw
mount --bind "$scratch/default" /etc/default/ufw
mount --bind "$scratch/ufw-lib" /usr/lib/ufw
mount -t tmpfs tmpfs /run
ip link set lo up
ip netns add client
ip link add edge type veth peer name peer
ip link set peer netns client
ip address add 198.18.0.1/30 dev edge
ip link set edge up
ip netns exec client ip address add 198.18.0.2/30 dev peer
ip netns exec client ip link set peer up
ip netns exec client ip link set lo up
cat > "$scratch/listen.py" <<'PY'
import pathlib, select, socket, sys
sockets = []
for kind, ports in [(socket.SOCK_STREAM, [222, 22000, 22, 80, 443, 53, 8080]),
                    (socket.SOCK_DGRAM, [53, 443])]:
    for port in ports:
        server = socket.socket(socket.AF_INET, kind)
        server.bind(("0.0.0.0", port))
        if kind == socket.SOCK_STREAM:
            server.listen()
        sockets.append(server)
pathlib.Path(sys.argv[1]).touch()
while True:
    for server in select.select(sockets, [], [])[0]:
        if server.type == socket.SOCK_STREAM:
            connection, _ = server.accept()
            connection.close()
        else:
            data, peer = server.recvfrom(1024)
            server.sendto(data, peer)
PY
python3 "$scratch/listen.py" "$scratch/listening" &
listener=$!
trap 'kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true' EXIT
for attempt in {1..100}; do
    [ ! -e "$scratch/listening" ] || break
    sleep .02
done
test -e "$scratch/listening"
cat > "$scratch/connect.py" <<'PY'
import socket, sys
protocol, port, expected = sys.argv[1:]
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
client.settimeout(.3)
try:
    client.connect(("198.18.0.1", int(port)))
    if protocol == "udp":
        client.send(b"test")
        assert client.recv(1024) == b"test"
    reachable = True
except OSError:
    reachable = False
finally:
    client.close()
assert reachable == (expected == "open"), (protocol, port, expected, reachable)
PY
check() { ip netns exec client python3 "$scratch/connect.py" "$@"; }
ufw default deny incoming >/dev/null
ufw allow 222/tcp comment administrator-ssh >/dev/null
ufw allow 443/tcp comment administrator-https >/dev/null
ufw --force enable >/dev/null
baseline=$(ufw show added)
check tcp 222 open
check tcp 22000 closed
check tcp 22 closed
check tcp 80 closed
check udp 53 closed
"#;

const EXERCISE: &str = r#"
initialize_host
claim_directory "$owned"
publication=pub-0123
firewall_ports='22000/tcp|22/tcp|80/tcp|443/tcp|53/udp'
open_firewall
open_firewall
[ "${#firewall_name}" -le 64 ]
if grep -F "$firewall_name" /etc/ufw/user6.rules; then exit 1; fi
for port in 22000 22 80 443; do check tcp "$port" open; done
check udp 53 open
check tcp 53 closed
check udp 443 closed
check tcp 8080 closed
# Repair a lost rule while FRP's listeners continue running.
ufw --force delete allow in from 0.0.0.0/0 to any app "$firewall_name" comment "$firewall_tag" >/dev/null
check tcp 22000 closed
open_firewall
check tcp 22000 open
close_firewall
close_firewall
[ "$(ufw show added)" = "$baseline" ]
for port in 22000 22 80; do check tcp "$port" closed; done
check udp 53 closed
check tcp 443 open
check tcp 222 open
# Explicit administrator source restrictions stay ahead of managed allows.
ufw deny from 198.18.0.2 to any port 80 proto tcp comment administrator-restriction >/dev/null
baseline=$(ufw show added)
open_firewall
check tcp 22000 open
check tcp 80 closed
close_firewall
[ "$(ufw show added)" = "$baseline" ]
# A replacement opens its new ports and leaves the removed port blocked.
firewall_ports='22000/tcp|8080/tcp'
open_firewall
check tcp 8080 open
check tcp 80 closed
# Persistence and cleanup also work while the firewall is inactive.
ufw disable >/dev/null
close_firewall
open_firewall
[ "$(ufw status)" = "Status: inactive" ]
ufw --force enable >/dev/null
check tcp 8080 open
close_firewall
check tcp 8080 closed
[ "$(ufw show added)" = "$baseline" ]
"#;

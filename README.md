# TunnelLB

TunnelLB publishes Kubernetes `LoadBalancer` Services through an existing external
Linux server. The operator is written in Rust with kube-rs. It installs pinned
FRP binaries over SSH and creates an outbound connector for each Service/Server
pair.

```text
Internet → edge IPv4:Service.port → encrypted FRP tunnel → Service ClusterIP → Pods
                                       ↑
                              cluster initiates connection
```

The edge is a dedicated proxy, with no Kubernetes credentials, cluster membership,
Pod-network routes or Tailscale membership. Application TLS terminates inside the
cluster. The public IP already belongs to the supplied server; TunnelLB does not
allocate addresses from a cloud provider.

This is an initial implementation. Read the supported configuration and security
boundaries below before exposing applications.

## Supported configuration

- Linux Kubernetes nodes, IPv4 Services, kube-proxy and pod veth networking.
  The integration target is k3s `v1.35.1+k3s1` with its default networking.
- **Disable k3s ServiceLB** using `--disable=servicelb` on all servers. On the
  tested version, its EndpointSlice status worker clears TunnelLB ingress
  addresses even when `loadBalancerClass` is set.
- Dedicated Debian 12/13 or Ubuntu 22.04/24.04 edges, systemd ≥244, amd64 or arm64.
  Supply root SSH access or an account with passwordless `sudo -n`.
- TCP and UDP. SCTP, transparent original source IP, IPv6, arbitrary LAN targets,
  cloud provisioning and floating IP failover are outside this version.
- One controller replica and one installation per cluster. The chart uses
  `Recreate`; do not scale it up.
- The dedicated operator namespace must permit a trusted init container with
  `NET_ADMIN`. Workers themselves are nonroot, capability-free and tokenless.
  The chart's namespace admission setting allows that init container; no
  workload requests `privileged: true`, host networking or host PID access.
- NetworkPolicy enforcement is required. CNI socket load balancing that rewrites
  destinations before pod iptables is not a supported configuration.

## Install

GitHub releases publish amd64/arm64 images to
`ghcr.io/melvspace/tunnellb:<version>`; the version has no `v` prefix. Check out
the matching [GitHub release](https://github.com/melvspace/TunnelLB/releases) tag
for its Helm chart, then replace `VERSION` below with that published version:

```bash
helm upgrade --install tunnellb ./charts/tunnellb \
  --namespace tunnellb-system --create-namespace \
  --set image.tag=VERSION
```

For local development, build and load `tunnellb:<version>` using the version in
`Cargo.toml`, then install with `--set image.repository=tunnellb`.

The chart targets Helm 4. For an existing, dedicated namespace, add
`--set createNamespace=false` and configure its admission policy yourself.
`networkPolicy.apiServerCIDRs` can restrict controller egress to the API's exact
addresses. Without it, only the controller receives TCP 443/6443 egress to any
address. Connectors and SSH Jobs get separate, narrower policies.

The controller needs Kubernetes API credentials. The forwarding and SSH worker
pods have `automountServiceAccountToken: false`. SSH private-key Secrets are read
only from the operator namespace.

## Register a server

Authorize a dedicated SSH public key on the edge using your normal VPS setup.
The matching private key stays in a Kubernetes Secret:

```bash
kubectl -n tunnellb-system create secret generic edge-1-ssh \
  --from-file=ssh-privatekey=/path/to/private-key
```

Apply a Server, replacing the documentation address and SSH user:

```yaml
apiVersion: tunnellb.io/v1alpha1
kind: Server
metadata:
  name: edge-1
spec:
  address: "203.0.113.10"
  ssh:
    user: root
    privateKeySecretRef:
      name: edge-1-ssh
  pool: public
  allowedNamespaces: [apps]
```

The first Job discovers the SSH host key. The controller persists it before a
second, strictly pinned Job logs in and installs FRP. Subsequent key changes
block SSH operations. This is **trust on first use**; first-contact identity is
not independently verified.

Enrollment installs checksum-verified FRP 0.71.1 and owned systemd units. It
creates a dedicated locked service account and retains your original authorized
key. The operator does not configure cloud firewalls, flush host firewall rules
or join the server to your VPN.

Allow the management SSH port, intended public Service ports and the allocated
TCP tunnel control ports through your firewall. `controlPortRange` defaults to
20000–29999. `reservedPorts` excludes additional ports from allocation. Management
SSH is always reserved.

```bash
kubectl get servers
kubectl get server edge-1 -o yaml
kubectl -n tunnellb-system get jobs,pods
```

Changing the Server address or SSH port requires cleanup and a new enrollment.
To retry installation intentionally after fixing an edge, change the
`tunnellb.io/re-enroll` annotation on the Server. Unchanged enrolled Servers do
not continually run root installation Jobs.

## Share a server across clusters

Register the same address in each cluster, with an SSH Secret in each operator
namespace. No cluster identifier or separate port ranges are required. Each
Server's Kubernetes UID identifies its registration on the host; the Server
names may be the same.

The host reserves public ports before starting a tunnel and chooses a free
control port from that Server's `controlPortRange`. Reservations are serialized
under a host-wide lock and persist while connectors are disconnected. Different
clusters must use different public **port numbers**, including across TCP/UDP.
For example, cluster A can publish TCP 443 while cluster B publishes TCP 25565
and UDP 24454.

A conflicting Service reports `PortConflict` and retries on the next ten-minute
provisioning window; it cannot take over another registration's ports. Removing
one Server stops only its publications and releases only its reservations.
Other clusters continue using the host.
An abandoned registration keeps its remote reservations until cleaned up.

All participating cluster administrators must be trusted: root-capable SSH
access can change any host state. `reservedPorts` is a local cluster policy;
configure the same exclusions in each cluster when needed. Keep one Server
object per address within each cluster.

## Publish a Service

An administrator enables a namespace:

```bash
kubectl label namespace apps tunnellb.io/enabled=true
```

Application owners can then publish ordinary, pod-selected Services:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: apps
spec:
  type: LoadBalancer
  loadBalancerClass: tunnellb.io/edge
  allocateLoadBalancerNodePorts: false
  selector:
    app: web
  ports:
    - name: https
      port: 443
      targetPort: 8443
      protocol: TCP
```

The Service receives the Server's address in `status.loadBalancer.ingress`,
with `ipMode: Proxy`. `TunnelLBReady` reports allocation, provisioning and tunnel
registration state. Registration does not prove application-level health.
Source addresses are those of the connector unless the receiver supports the
optional PROXY protocol.

| Annotation | Example | Meaning |
|---|---|---|
| `tunnellb.io/servers` | `edge-1,edge-2` | Select these Servers explicitly. |
| `tunnellb.io/pool` | `public` | Restrict selection to a Server pool. |
| `tunnellb.io/replicas` | `"2"` | Request two independent edge addresses. |
| `tunnellb.io/proxy-protocol` | `https=v2,minecraft=v2` | Enable framing on named Service ports. |

Without selection annotations, one eligible Server is chosen and the assignment
is persisted. Adding Servers does not move existing publications. An explicit
Server list determines the number of endpoints; an accompanying `replicas`
value must match its length. Pool and explicit Server selection are mutually
exclusive.

Servers can restrict namespaces with `allowedNamespaces`; an empty list permits
every administrator-enabled namespace. A Server holds one public address.
Different publications must use distinct **numeric ports**, including across
TCP/UDP, because FRP's authorization allowlist is numeric. One Service can publish
TCP and UDP on the same number. Each publication also consumes a separate tunnel
control port.

PROXY framing is off by default. TCP supports v1/v2; UDP supports only v2 and
requires a compatible application. FRP's UDP association framing is not a
universal replacement for transparent source IP. The edge can forge PROXY
addresses; do not treat them as authentication.

Only pod-backed, IPv4 ClusterIP Services are supported. Headless, selectorless,
ExternalName and hostNetwork backends are rejected, as are manual or mismatched
EndpointSlices. `externalTrafficPolicy` and `internalTrafficPolicy` must be
`Cluster`; source-range restrictions and manually assigned `loadBalancerIP` are
not implemented. Existing NodePorts must be removed, even after setting
`allocateLoadBalancerNodePorts: false`.

If your application namespace denies ingress, explicitly allow the generated
connector pods from `tunnellb-system` to the selected application ports. TunnelLB
does not edit tenant ingress policies.

## Lifecycle and recovery

Each publication has independent credentials, an FRP server unit and one
connector Deployment. Backend Pod replacement does not change the immutable
connector configuration. Service destination or port changes stop the old
connector before applying the replacement; existing connections are interrupted.

Edge outages retain previously published IPs. Connectors reconnect, and status
reports degraded registration. Multiple addresses are independent entry points;
TunnelLB does not move an address, promise session failover or manage DNS.

The last approved forwarding configuration continues if the controller or API
is unavailable. Service revocation requires the controller and the node running
the connector to be reachable. Once the connector process exits, its backend
connections end. A hostile edge may still listen on its public ports or serve
its own content.

Delete Services before deleting a Server. Finalizers stop connectors, remove
remote publication units and release reservations. Server deletion also removes
owned runtime files. Cleanup waits when the remote host is unreachable.

An administrator can explicitly abandon an unreachable Server:

```bash
kubectl annotate server edge-1 tunnellb.io/force-delete=true
kubectl delete server edge-1
```

Local connector termination is still required. Remote files/listeners may remain.
Service-level force deletion only detaches the Service after local termination:
its reservation remains until remote cleanup succeeds. It cannot free ports
still occupied by another tenant's abandoned remote process.

Uninstall retains the registration's revocation marker, locked edge account and
shared, versioned FRP binary cache. A new Server UID can immediately reuse ports
released by completed cleanup. The retired UID cannot enroll again.
Do not delete operator state Secrets or allocation ConfigMaps to work around a
pending cleanup.

Hosts installed with the older, single-owner layout are rejected without
conversion. Complete their cleanup using the old operator first, verify that no
TunnelLB units remain running, then archive the remaining `/var/lib/tunnellb`
and `/opt/tunnellb` directories before enrolling with this version. Do not remove
ownership markers from an active installation.

## Security boundary

The edge can send traffic only through proxies configured by the cluster-side
client. It cannot supply an arbitrary backend address. Application TLS keys stay
inside the cluster, and no SSH agent forwarding is enabled.

Connectors and SSH clients are separate from the controller. Every worker starts
behind an exact pod-network egress allowlist installed before its application
process starts, plus a NetworkPolicy. The SSH allowlist contains only the edge
SSH endpoint; the connector allowlist contains its edge control endpoint and
published Service ports. No DNS, API, node or general LAN route is intentionally
allowed. Guard installation failure prevents the worker from starting.

These controls do not make published applications safe from malicious input.
EndpointSlice validation is reactive, with a nonzero controller response window;
it is not an admission policy for hostile administrators. A compromised kernel
or a privileged administrator is outside this boundary. Keep tenants away from
the operator namespace and Server/state-management permissions.

TLS passthrough alone cannot guarantee confidentiality against an edge that can
obtain a new valid certificate using IP-based domain validation. Use suitable
DNS validation and CA authorization controls for that threat model.

## Releases

[Release Please](https://github.com/googleapis/release-please-action) maintains a
release PR from Conventional Commits on `main`. Merging that PR creates the
`vX.Y.Z` tag and GitHub release. The first release is `v0.1.0`; later releases
update Cargo manifests, the changelog, and Helm versions together. The chart's
image tag matches the crate version.

Install a GitHub App on this repository with **Contents**, **Issues**, and
**Pull requests** read/write permissions. Configure these repository settings:

| Setting | Name | Value |
|---|---|---|
| Actions variable | `APP_ID` | GitHub App ID |
| Actions secret | `APP_PRIVATE_KEY` | GitHub App PEM private key |

The release workflow creates a short-lived, repository-scoped App token. Its
release PRs receive normal CI checks. Use Conventional Commit titles when
squashing PRs, such as `fix: ...`, `feat: ...`, or `ci: ...`.

Publishing reruns Rust and Helm checks against the released commit, then builds
the existing Dockerfile for `linux/amd64` and `linux/arm64`. Only complete version
tags such as `0.1.0` are published. A failed publication can be retried with
GitHub Actions' **Re-run failed jobs** on that release's workflow.

GHCR authentication uses the job's `GITHUB_TOKEN` with `packages: write`; it
needs no registry password or PAT. GitHub initially creates packages as private.
For anonymous cluster pulls, make the package public after the first push;
otherwise configure `imagePullSecrets`. An existing package must grant this
repository Actions access. See [GitHub's registry
documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- crd > charts/tunnellb/crds/servers.yaml
helm lint charts/tunnellb --namespace tunnellb-system --strict
```

The image bundles the official FRP release binaries and verifies checksums during
the build and before remote installation. Tests cover parsing, allocation,
ownership, API object normalization, credentials, host-key handling, generated
scripts, process supervision and guard configuration.

The ignored integration test requires a prepared, disposable Linux Docker
environment: a `tunnellb-e2e` k3d cluster with a loopback API and ServiceLB
disabled, and a fresh `tunnellb-e2e-edge` container built from
[`tests/fixtures/edge.Dockerfile`](tests/fixtures/edge.Dockerfile). The edge needs
private cgroups, no host mounts, an authorized test SSH key and an unrelated
`e2e-unpublished.service` HTTP listener on port 18090. Label both the edge and
their shared Docker network `tunnellb.io/e2e=tunnellb-e2e`.

Keep the kubeconfig and generated SSH key under `/tmp/codex/tunnellb-e2e/`:

```bash
TUNNELLB_E2E_ALLOW_DESTRUCTIVE=1 \
TUNNELLB_E2E_KUBECONFIG=/tmp/codex/tunnellb-e2e/kubeconfig \
TUNNELLB_E2E_SSH_KEY=/tmp/codex/tunnellb-e2e/ssh/id_ed25519 \
TUNNELLB_E2E_K3D="$(command -v k3d)" \
cargo test --locked --test e2e -- --ignored --nocapture
```

The test builds/imports images, installs Helm, enrolls the edge and exercises
forwarding, guards, restarts and cleanup. It refuses existing Servers or
TunnelLB Services. Never supply a production kubeconfig. The implementation
contract and verification scope are in [`PLAN.md`](PLAN.md).

Set `TUNNELLB_E2E_SECOND_KUBECONFIG` to a second disposable k3d cluster's
kubeconfig, `TUNNELLB_E2E_SECOND_CLUSTER` to its name, and
`TUNNELLB_E2E_FIXTURE` to the shared Docker ownership label to exercise
shared-host enrollment, automatic control-port selection,
cross-cluster conflicts, uninterrupted traffic during another registration's
deletion, and released-port reuse. Both clusters must share the isolated test
edge's Docker network.

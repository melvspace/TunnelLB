# TunnelLB implementation plan

## Product contract

Build a Rust operator using kube-rs. A cluster administrator registers a dedicated
Debian/Ubuntu systemd server with an existing public IPv4 address, SSH username
and a reference to a Kubernetes SSH private-key Secret. The operator provisions
and maintains FRP automatically. The supplied key must already be authorized and
the account must be root or support noninteractive sudo.

The remote server is not a Kubernetes node or a member of the cluster's VPN.
Cluster-side connectors initiate authenticated, encrypted outbound tunnels.
Only explicitly published, ordinary pod-backed Services are eligible. Application
TLS terminates inside the cluster. TCP and UDP are supported; PROXY protocol is
opt-in per Service port and requires a compatible receiving application.

Enrollment uses trust on first use for SSH host keys. Record the first key in
operator-owned state and reject changes. Resetting host identity is an explicit
administrator operation. First-contact identity is not independently verified.

Administrators control Server enrollment and namespace opt-in. Applications use
`type: LoadBalancer` and `loadBalancerClass: tunnellb.io/edge`.
NodePort allocation is optional and does not change tunnel routing.
Annotations provide explicit Server or pool selection, multiple entry points
and per-port PROXY protocol.

## Allocation and lifecycle

- Select one eligible Server by default. Preserve assignments across controller
  restarts and the arrival of additional Servers.
- Allow several Services to share an address on disjoint numeric ports. FRP's
  server allowlist is numeric, so cross-publication TCP/UDP reuse is excluded.
  Reserve SSH and tunnel control ports. Never steal existing allocations.
- Allow independent clusters to register the same host. Each Server UID owns
  its enrollment, credentials, units and terminal revocation marker. Root SSH
  administrators are mutually trusted.
- Reserve public and control ports atomically on the host before applying a
  publication. Host reservations survive tunnel outages and arbitrate across
  cluster-local ledgers. Automatically choose an available control port in the
  requested range, then commit it locally before starting the connector.
- Persist allocation ownership with Service and Server UIDs and optimistic
  concurrency. Service status is a projection, not the allocation database.
- Several Servers provide independent addresses, not a floating IP or seamless
  connection failover.
- Keep previously published addresses during transient outages and report
  degraded state. Reconnect without automatic DNS changes.
- Continue the last approved forwarding configuration during controller/API
  outages. Revocation cannot have a fixed deadline under a control-plane or node
  partition.
- Revoke from inside the cluster by terminating affected connector processes.
  FRP hot reload alone does not close all existing TCP connections.
- Remove only owned remote files and units. Report pending remote cleanup and
  provide an explicit administrative abandonment action for unreachable hosts.
  Keep the user's original authorized key and other registrations' tunnels.
  Retain shared immutable binaries and per-UID revocations after uninstall;
  completed cleanup permits a new registration to reuse the released ports.
- Pin component versions. Deliberate upgrades may interrupt connections;
  reconciliation of an unchanged configuration must not restart connectors.

## Implementation

1. Define the cluster-scoped `Server` CRD with kube-rs, validated typed Service
   requests, backend validation and deterministic port allocation.
2. Build FRP configuration and credentials for isolated Service/Server
   publications. Use an independent FRP server instance and control port per
   publication to avoid a global client credential or an unverified server-plugin
   authorization model. The remote host is still untrusted.
3. Implement an SSH worker that accepts a structured request, performs pinned
   host-key verification after first enrollment, installs verified bundled FRP
   binaries, and converges systemd units and owned configuration. Bound remote
   output, operation time and retries; never enable SSH agent forwarding.
4. Generate hardened connector Deployments and short-lived SSH Jobs in the
   operator namespace. They receive only their required credentials and no
   Kubernetes service-account token.
5. Add NetworkPolicies and an explicit pod-network egress guard. If a trusted
   init container requires `NET_ADMIN`, restrict that capability to installation
   of rules in its own pod network namespace; the exposed process receives no
   capabilities. Never use host networking. Validate the supported kube-proxy
   networking path rather than claiming support for every CNI implementation.
6. Implement kube-rs reconciliation for Servers and Services, persistent
   allocations, asynchronous Jobs, conditions, finalizers, immutable
   publication configuration, status publication using `ipMode: Proxy`, and
   recovery after interrupted operations.
7. Watch and validate EndpointSlices and their referenced Pods. Reject
   selectorless, ExternalName, headless, manual/external endpoints and hostNetwork
   backends. Revoke invalid publications. Validate destination changes, not just
   the initial Service declaration.
8. Package a pinned container image and Helm chart with CRDs, scoped RBAC,
   resource limits, health probes, installation examples and root README.
9. Add CI for formatting, linting, tests, generated CRD consistency and Helm
   validation. Keep temporary development harnesses under `/tmp/codex/`.

## Verification and release gates

- Unit tests cover request validation, annotation parsing, stable assignment,
  cross-protocol numeric port collisions, ownership, credential/config generation,
  unsafe backend rejection and idempotency.
- Test real FRP TCP and UDP forwarding, optional PROXY framing, TLS passthrough,
  independent credentials, a hostile peer's inability to select arbitrary local
  destinations, and process-based session revocation.
- Test real SSH enrollment, first-key persistence, changed-key rejection,
  idempotent installation and owned cleanup against a disposable server.
- Exercise the operator in a disposable local Kubernetes cluster: namespace
  authorization, Service status, backend churn, controller restart, remote
  outage/reconnection, collisions and deletion with active connections.
- Exercise two independent clusters sharing one disposable host: concurrent
  durable numeric claims, automatic control-port selection, cross-cluster
  conflicts, cleanup isolation and reuse by a new Server UID. Verify that
  delayed reservation/apply operations cannot restore revoked generations.
- Test network guards against API, node, LAN and unpublished destinations on the
  supported networking configuration. Report the actual scope of evidence;
  passing probes are not a proof against arbitrary software vulnerabilities.
- Check k3s ServiceLB coexistence explicitly. Its version-specific status worker
  may interfere despite `loadBalancerClass`; document disabling ServiceLB when
  coexistence cannot be supported. Never silently change the user's cluster.
- Have Claude independently review the implementation and resolve concrete
  findings before the final verification.

PROXY client addresses are asserted by the remote edge and are not trusted
authentication. A compromised edge can disrupt traffic and attack applications
deliberately published through it. Isolation claims apply to tested, supported
networking; they do not promise immunity from application or kernel exploits.

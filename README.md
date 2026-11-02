# TunnelLB

TunnelLB makes Kubernetes Services available through a public server.
It installs [FRP](https://github.com/fatedier/frp) and starts encrypted tunnels from the cluster to the server.
The server sends TCP and UDP traffic through these tunnels to your applications.
The public server does not need to be a Kubernetes node or join the cluster's VPN.

## Before you start

- Use Kubernetes 1.32 or later with Linux nodes, kube-proxy, veth interfaces, and NetworkPolicy enforcement.
- Do not use CNI socket-level load balancing.
- On k3s, disable ServiceLB with `--disable=servicelb` on each control-plane node.
- Use Helm 4.
- Use a public IPv4 server with amd64 or arm64, systemd, and Debian 12/13 or Ubuntu 22.04/24.04.

## 1. Install TunnelLB

Install TunnelLB once in each cluster.
Use a namespace that only TunnelLB uses.
If the namespace is already present, add `--set createNamespace=false` to the Helm command.
The admission policy of this namespace must let init containers use `NET_ADMIN`.

Select a chart version from [GitHub Releases](https://github.com/melvspace/TunnelLB/releases).
Chart releases use `chart-vX.Y.Z` tags and have their own versions.
Replace `X.Y.Z` with the chart version number without `chart-v`.

```bash
helm upgrade --install tunnellb oci://ghcr.io/melvspace/charts/tunnellb \
  --version X.Y.Z \
  --namespace tunnellb-system --create-namespace
```

## 2. Add a public server

Use `root` or an SSH account with passwordless sudo.
TunnelLB uses this account to install FRP and start or stop its systemd services.
Add your SSH public key to that account's `authorized_keys` file.

Make the SSH port reachable before enrollment. TunnelLB checks UFW during enrollment
and automatically manages a separate UFW application profile for each publication.
It opens only the assigned TCP control port and the Service's TCP/UDP ports, and removes
those rules when the publication is deleted or replaced. Existing SSH and administrator
rules are preserved. If UFW is inactive, rules are saved for later activation;
TunnelLB does not install, enable, disable, or reset the firewall.

These rules permit IPv4 traffic from any source; the control connection uses TLS and
a per-publication authentication token. Cloud firewalls and other host firewall managers
are outside this automation. After applying the edge configuration, TunnelLB checks
the control port from its worker and reports a specific diagnostic if it is unreachable.
The Service still waits for the connector to register before receiving an external IP.
Reconciliation retries automatically after failures. If UFW is removed while managed
rules exist, restore it to let cleanup complete; TunnelLB keeps the port claims until
it can confirm that its rules are removed.

Create a Secret from the SSH private key:

```bash
kubectl -n tunnellb-system create secret generic edge-1-ssh \
  --from-file=ssh-privatekey=/path/to/private-key
```

Save this manifest as `server.yaml`.
Replace `203.0.113.10` with your server's public IPv4 address.
Set `ssh.user` to your SSH account.
Set `allowedNamespaces` to the namespaces that can use this server.

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
  allowedNamespaces: [apps]
```

```bash
kubectl apply -f server.yaml
kubectl get servers --watch
```

Wait for the `Ready` phase.
TunnelLB saves the first SSH host key and stops SSH operations if that key changes.

## 3. Publish a Service

Create a namespace for your application:

```bash
kubectl create namespace apps
kubectl label namespace apps tunnellb.io/enabled=true
```

Deploy your application in `apps`.
Save this manifest as `service.yaml`.
Set `selector` and `targetPort` to match your application Pods.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: apps
spec:
  type: LoadBalancer
  loadBalancerClass: tunnellb.io/edge
  selector:
    app: web
  ports:
    - name: https
      protocol: TCP
      port: 443
      targetPort: 8443
```

```bash
kubectl apply -f service.yaml
kubectl -n apps get service web --watch
```

The `EXTERNAL-IP` column shows the public server address.
For HTTPS, configure TLS in your application or ingress gateway.
For UDP, set `protocol: UDP`.

Use Services with Pod selectors and a ClusterIP.
Do not use headless Services or `hostNetwork` Pods.
Keep `externalTrafficPolicy` and `internalTrafficPolicy` set to `Cluster`.
If your application has an ingress NetworkPolicy, let connector Pods in `tunnellb-system` connect to its ports.

## Options

Add these settings to the Service's `metadata.annotations`:

| Annotation | Example | Effect |
|---|---|---|
| `tunnellb.io/servers` | `"edge-1,edge-2"` | Uses the specified servers. |
| `tunnellb.io/pool` | `"public"` | Selects servers with `spec.pool: public`. |
| `tunnellb.io/server-selector` | `"topology.kubernetes.io/region=region-a"` | Filters Server labels, optionally within a pool. |
| `tunnellb.io/replicas` | `"2"` | Uses two servers instead of one. |
| `tunnellb.io/proxy-protocol` | `"https=v2"` | Sends the client IP through PROXY protocol on the named port. |

Use either `servers` or `pool`.
If you set both `servers` and `replicas`, set `replicas` to the number of listed servers.
Use PROXY protocol only if your application can read it.
Without PROXY protocol, the application sees the tunnel connector's IP.

See the [chart settings](charts/tunnellb/values.yaml) and [Server settings](examples/server.yaml) for more options.

## Regional Server selection

Label Server resources with operator-supplied regions and zones, independently of
application pools. For example, an existing `edge-a-1` Server with
`spec.pool: application` can have these labels:

```sh
kubectl label server edge-a-1 topology.kubernetes.io/region=region-a topology.kubernetes.io/zone=zone-a-1
```

A Service can request two servers in `region-a` within that pool:

```yaml
metadata:
  annotations:
    tunnellb.io/pool: "application"
    tunnellb.io/server-selector: "topology.kubernetes.io/region=region-a"
    tunnellb.io/replicas: "2"
```

`server-selector` uses Kubernetes label selector syntax: `=`, `==`, `!=`, `in`,
`notin`, key existence (`key`), and key absence (`!key`). Comma-separated
requirements are ANDed, for example
`topology.kubernetes.io/region in (region-a,region-b),!maintenance`.
Negative requirements (`!=`, `notin`) also match Servers missing the named label.
An empty or malformed selector is rejected with `InvalidService`.
Explicit `tunnellb.io/servers` cannot be combined with `server-selector` or `pool`;
conflicting settings are rejected even if the named servers currently match.

Selection always requires namespace opt-in and Server namespace authorization,
and new allocations still require a ready, valid Server with a unique address
and available public and control ports. The selector narrows these checks; it
never expands a pool or grants access. Without `server-selector`, allocation
behavior is unchanged.

Existing assignments that remain eligible are retained, including when another
matching Server becomes available. Adding or editing a selector does not restart
an eligible publication. Server label updates trigger reconciliation. If a Server
stops matching, TunnelLB stops and cleans up its publication before allocating a
replacement; this interrupts connections on that edge and may change the public
IP. A label change alone does not move assignments that still match. Existing
assignments retain the usual readiness and backend outage behavior.

When a valid selector cannot supply the requested replicas, `TunnelLBReady=False`
has reason `ServerSelectorUnsatisfied` and reports allocated versus requested
replicas. This includes zero matching or eligible Servers, unready Servers, and
port exhaustion. Available assignments continue serving and retain their
published IPs while TunnelLB retries. Provisioning or backend failures can report
their own more specific condition reasons.

Regions are labels, not IP geolocation. ExternalDNS remains responsible for A/SRV
records; regional selection does not install DNS or monitoring infrastructure,
check application health, or provide automatic DNS failover.

## Use one server with several clusters

Add a `Server` with the same public address in each cluster.
Create only one `Server` for that address in each cluster.
Use different public port numbers for different Services.
This rule also applies to a TCP Service and a UDP Service.
One Service can use both protocols on the same port.

TunnelLB selects available tunnel ports automatically.
If a Service shows `PortConflict`, TunnelLB tries again in ten minutes or less.
If you delete a `Server`, TunnelLB removes only that Server's tunnels.

## Check status

```bash
kubectl get servers
kubectl -n apps describe service web
kubectl -n tunnellb-system get pods,jobs
```

If TunnelLB cannot connect to the server, the Service keeps its IP address.
TunnelLB connects again when the server is available.

## Uninstall

1. Delete the Services that use TunnelLB. Wait for their removal to complete.
2. Delete the Servers. Wait for their removal to complete.
3. Uninstall the operator:

   ```bash
   helm uninstall tunnellb --namespace tunnellb-system
   ```

If TunnelLB cannot connect to a server, removal waits until the connection is available.

## Releases

Release Please opens separate release PRs for the application and Helm chart.
Application tags use `vX.Y.Z` and publish the container image.
Chart tags use `chart-vX.Y.Z` and publish the Helm chart.
Changes only under `charts/tunnellb` do not trigger an application release.

To use a new image by default, wait for the image to be published.
Then update `appVersion` in `charts/tunnellb/Chart.yaml` and `image.tag` in
`charts/tunnellb/values.yaml` together, using a `fix(chart):` or `feat(chart):` commit.
Release Please bumps the chart's `version` independently.

## Prometheus telemetry

TunnelLB supplies telemetry to an existing monitoring stack. It installs no
Prometheus, Grafana, alerting, or logging service. Enable cluster scrape access
with Helm `--set metrics.enabled=true`. The controller serves `GET /metrics`
on `metrics.port` (9090); each connector serves the same path on
`metrics.connectorPort` (9090). The controller Service is
`tunnellb-metrics.<release-namespace>.svc`. Set
`metrics.scraperNamespaceSelector` and `metrics.scraperPodSelector` to the labels
of your scraper. Both selectors must match the same source peer. Default-deny
policies remain in effect for all other clients and ports. The metrics listener
has no authentication or TLS; keep it inside the cluster and use the configured
NetworkPolicy with a supporting CNI. Cluster administrators can grant additional
access through other additive NetworkPolicies.

Enable `metrics.podMonitor.enabled=true` only when Prometheus Operator CRDs
already exist. This creates separate controller and connector PodMonitors;
`metrics.podMonitor.labels` must match your Prometheus monitor selector, and its
namespace selector must include the release namespace. Set
`metrics.podMonitor.interval` to change the default 30s interval. Both Helm
monitoring options default to false; normal installation needs no monitoring
CRDs. Binary options are controller `--metrics-address` /
`TUNNELLB_METRICS_ADDRESS` (default `127.0.0.1:9090`), controller
`--connector-metrics-address` / `TUNNELLB_CONNECTOR_METRICS_ADDRESS` (default
`0.0.0.0:9090`), and connector `--metrics-address`.

Without Prometheus Operator, use Kubernetes pod discovery (requires Prometheus
RBAC to list/watch pods). Replace `tunnellb-system` with your release namespace:

```yaml
scrape_configs:
  - job_name: tunnellb
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [tunnellb-system]
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_container_port_name]
        regex: metrics
        action: keep
      - source_labels: [__meta_kubernetes_pod_phase]
        regex: Running
        action: keep
      - source_labels: [__meta_kubernetes_pod_name]
        target_label: pod
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
```

### Metric contracts

All names below begin with `tunnellb_`. Counters and duration sums reset when the
emitting process restarts. Absent series mean no observation yet, not a measured
zero. Durations use seconds; timestamps use Unix seconds. There are no raw
errors, client IPs, Job IDs, credential hashes, or credentials in labels.
Operation/result/reason labels are fixed allowlists. Object identity labels are
bounded by the managed cluster inventory; port/protocol labels add at most one
series per published port. Resource recreation can create new publication
identities, so configure appropriate Prometheus retention.

| Metric suffix | Type / units | Exact meaning and labels |
| --- | --- | --- |
| `reconciliations_total` | counter / passes | Completed Server/Service reconcile calls; labels `operation` (`server`, `service`), `result` (`success`, `failure`), `reason` (`none`, `ReconcileFailed`, or a safe worker reason). A successful pass may report a pending or invalid resource; this counts execution, not provisioning success. |
| `reconcile_failures_total` | counter / passes | Failed calls, with the same labels. |
| `reconcile_duration_seconds_sum` | counter / seconds | Total execution duration after acquiring the controller lock; divide its rate by the reconciliation count rate for mean duration. Same labels. |
| `ssh_operations_total` | counter / Jobs | Observed terminal, ownership-verified SSH Jobs, by `operation` (`enroll`, `reserve`, `apply`, `remove`, `uninstall`), `result`, and safe `reason`. |
| `ssh_failures_total` | counter / Jobs | Terminal failed operations with the same labels. |
| `ssh_attempts_total` | counter / attempts | Ownership-verified terminated worker containers found when a Job becomes terminal, including retries; labels `operation`, `reason` (`none` on success). Pending attempts are not counted yet. |
| `ssh_duration_seconds_sum` | counter / seconds | Sum of terminated worker execution times, including retries, excluding scheduling and queue time; same labels as `ssh_operations_total`. Zero if Kubernetes supplies no timestamps. |
| `server_enrolled` | gauge / boolean | Last inventory observation of Server phase Ready; label `server`. Reconstructed every 30s; removed objects disappear on the next successful inventory refresh. |
| `publication_provisioned` | gauge / boolean | Persisted applied configuration hash equals desired hash and removal is not committed; labels `publication`, `server`, `service_namespace`, `service`. It does not assert connector registration. Same inventory/reset behavior. |
| `publication_info` | gauge / constant 1 | Maps publication ID to `server`, `service_namespace`, `service`, `protocol`, `port`; refreshed from inventory. Join with the connector pod's existing `tunnellb.io/publication` label to correlate container/exporter metrics. |
| `connector_subprocess_restarts` | gauge / restarts | Controller inventory observation of the connector container's Kubernetes restart count, labelled `publication`; resets on pod replacement. The supervisor starts one FRP child per container and exits on child failure; kubelet performs restarts. Use existing kube-state-metrics for durable pod restart history. |
| `connector_registered` | gauge / boolean | Connector-local aggregate registration of all expected FRP proxies, initially zero. |
| `connector_registration_losses_total` | counter / transitions | Aggregate registered-to-unregistered transitions observed from FRP output. |
| `connector_registration_successes_total` | counter / transitions | Aggregate unregistered-to-registered transitions, including initial registration and subsequent recoveries. |
| `last_registration_success_timestamp_seconds` | gauge / Unix seconds | Connector-local time of the latest aggregate registration success; absent until success and reset on container restart. |
| `last_enrollment_success_timestamp_seconds` | gauge / Unix seconds | Controller observation time of the latest successful pinned enrollment Job; absent until observed and reset on controller restart. Discovery alone does not count. |

Registration counters retain losses/recoveries that occur between scrapes while
the connector stays alive. They cannot retain events across a container crash
before the next scrape. SSH results are deduplicated by a process-local FIFO of
4096 terminal Job UIDs (never labels); a controller restart or eviction followed
by repolling an old Job may count it again. These are operational counters, not
an audit or billing ledger. Last-success timestamps are observation times.

Routine SSH failures use safe status reasons including `SSHAuthenticationFailed`,
`SSHHostKeyMismatch`, `SSHTimeout`, `SSHConnectionRefused`, `SSHUnreachable`,
`SSHKeyInvalid`, `UnsupportedHost`, `RemoteSudoRequired`, and
`RemoteProvisioningFailed`. Existing firewall reasons remain specific;
`SSHFailed` is the explicit unknown fallback. Completion logs contain operation,
Server, publication, reason, and duration without arbitrary remote output or raw
error chains. Logs at higher verbosity are unnecessary for these diagnoses.

### Edge FRP traffic metrics

Every new publication provisions the bundled FRP v0.71.1 Prometheus collector.
Its **edge frps process** binds its authenticated web server to IPv6 loopback
`[::1]:<allocated-control-port + 1>`. Enable or disable scraping through your
external monitoring configuration; this does not replace publications or interrupt
their connections. Metrics collection and its private listener remain active.
Existing publications created without metrics retain their original socket layout
until explicitly recreated or naturally replaced.

New publications reserve both adjacent numbers within `controlPortRange`, in the
local ledger and the host-wide claim. Neither number can overlap another
publication or public port. The distinct numbers also avoid Go's dual-stack
wildcard listener collision. IPv6 loopback must be enabled on the edge. No
monitoring port is opened by TunnelLB's host firewall. The dashboard and admin API
remain loopback-only, with a dedicated username `metrics` and the publication token
as password; do not expose that listener directly.

Use an existing restricted reverse proxy on the edge to publish **only** the
exact metrics route. For example, inside an existing nginx TLS virtual host:

```nginx
# One explicitly configured path per publication/control allocation.
location = /tunnellb/pub-example/metrics {
    allow 192.0.2.10; # replace with your Prometheus source address
    deny all;
    limit_except GET { deny all; }
    proxy_pass http://[::1]:23457/metrics?;
}
location /tunnellb/ { return 404; }
```

Use a dedicated virtual host with no general proxy fallback to the FRP listener;
restrict its ingress to your scraper at the host/provider firewall too. FRP v0.71.1 authenticates `/metrics` using the same Basic authentication middleware
as its admin handlers. Prometheus must send username `metrics` and the publication
token; nginx forwards the Authorization header to the loopback listener. Store
the token from the controller's `credentials-<publication>` Secret (`token` key)
in a protected password file mounted into Prometheus. Never put it in target
labels, command arguments or logs. Do not forward arbitrary paths or queries. Configure a separate
exact location for each live publication using `publication_info` and its
persisted control allocation; remove locations when publications are removed.
No generated FRP files or managed systemd units need editing. Prometheus reaches
this TLS proxy as an external target, independently of cluster PodMonitors:

```yaml
scrape_configs:
  - job_name: tunnellb-edge-publication
    scheme: https
    metrics_path: /tunnellb/pub-example/metrics
    basic_auth:
      username: metrics
      password_file: /etc/prometheus/secrets/pub-example-token
    static_configs:
      - targets: [edge-monitoring.example.com:443]
        labels:
          publication: pub-example
          server: edge-one
```

FRP exposes its own traffic bytes, connection totals/current connections and
client/proxy state at this target. Its metric names and labels follow the
[pinned FRP collector](https://github.com/fatedier/frp/tree/v0.71.1/pkg/metrics/prometheus),
not the TunnelLB metric contract. Edge counters reset on frps restart. Keep
proxy names (publication/protocol/port) as correlation identifiers and do not
add client IP labels.

FRP registration proves an acknowledged tunnel registration, not backend
reachability or application health. Neither these counters nor traffic volume
measure RTT, jitter, packet loss, retransmissions, Minecraft tick time or GC.
Use existing host/container exporters and network instrumentation for resources,
CPU throttling and TCP retransmissions, and separate application probes/exporters
for end-to-end responsiveness.

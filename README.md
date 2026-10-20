# TunnelLB

TunnelLB makes Kubernetes Services available through a public server.
It installs [FRP](https://github.com/fatedier/frp) and starts encrypted tunnels from the cluster to the server.
The server sends TCP and UDP traffic through these tunnels to your applications.
The public server stays outside the cluster.

## Before you start

- Use Kubernetes 1.32 or later with Linux nodes, kube-proxy, veth interfaces, and NetworkPolicy enforcement.
- Do not use CNI socket-level load balancing.
- On k3s, disable ServiceLB with `--disable=servicelb` on each control-plane node.
- Use Helm 4.
- Use a public IPv4 server with amd64 or arm64, systemd, and Debian 12/13 or Ubuntu 22.04/24.04.
- Use a server without k3s or Tailscale.

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
| `tunnellb.io/replicas` | `"2"` | Uses two servers instead of one. |
| `tunnellb.io/proxy-protocol` | `"https=v2"` | Sends the client IP through PROXY protocol on the named port. |

Use either `servers` or `pool`.
If you set both `servers` and `replicas`, set `replicas` to the number of listed servers.
Use PROXY protocol only if your application can read it.
Without PROXY protocol, the application sees the tunnel connector's IP.

See the [chart settings](charts/tunnellb/values.yaml) and [Server settings](examples/server.yaml) for more options.

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

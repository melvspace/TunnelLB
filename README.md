# TunnelLB

Use a Linux server with a public IP to expose Kubernetes Services over TCP and
UDP. TunnelLB installs [FRP](https://github.com/fatedier/frp) over SSH and connects
your cluster to the server through encrypted outbound tunnels. The public server
stays outside your cluster and needs no Kubernetes credentials.

```text
Internet → public server → tunnel → Kubernetes Service → application
```

Written in Rust with [kube-rs](https://kube.rs/). Works with an existing VPS;
TunnelLB does not create servers or allocate public IPs.

## Requirements

- Kubernetes 1.32+, Linux nodes, kube-proxy with pod veth networking, and enforced
  NetworkPolicies. CNI socket-level load balancing is not supported.
- **On k3s, disable ServiceLB** with `--disable=servicelb` on every server node.
- Helm 4 and a dedicated namespace for TunnelLB. The chart configures admission
  to allow the `NET_ADMIN` init container used to restrict tunnel traffic.
- A public IPv4 server running Debian 12/13 or Ubuntu 22.04/24.04, with systemd,
  on amd64 or arm64. SSH access must be root or have passwordless sudo.
- Server firewall access for SSH, your application's public ports, and TCP
  **20000–29999** for tunnel connections. TunnelLB does not change your firewall.

## Install

Choose a [release](https://github.com/melvspace/TunnelLB/releases) and replace
`X.Y.Z` with its version, without the `v` prefix:

```bash
VERSION="X.Y.Z"
git clone --depth 1 --branch "v$VERSION" https://github.com/melvspace/TunnelLB.git
cd TunnelLB

helm upgrade --install tunnellb ./charts/tunnellb \
  --namespace tunnellb-system --create-namespace \
  --set image.tag="$VERSION"
```

Images are published at `ghcr.io/melvspace/tunnellb`. See
[Helm values](charts/tunnellb/values.yaml) for configuration. For an existing
namespace, set `createNamespace=false` and allow `NET_ADMIN` in its admission
policy. Run one TunnelLB installation per cluster.

## Add a server

Add a dedicated SSH public key to the server's `authorized_keys`, then store the
matching private key in the operator namespace:

```bash
kubectl -n tunnellb-system create secret generic edge-1-ssh \
  --from-file=ssh-privatekey=/path/to/private-key
```

Save this as `server.yaml`, replacing the address and SSH user, then run
`kubectl apply -f server.yaml`:

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

TunnelLB installs FRP automatically. It trusts the SSH host key on first contact
and blocks subsequent connections if that key changes. Check enrollment with
`kubectl get servers`; wait for `Ready` before publishing.

Use `spec.controlPortRange` to change the tunnel port range and
`spec.reservedPorts` to keep other ports unavailable to TunnelLB. The SSH port is
always reserved. See the [Server example](examples/server.yaml).

## Publish an application

Enable the application's namespace:

```bash
kubectl create namespace apps
kubectl label namespace apps tunnellb.io/enabled=true
```

Deploy your application there, then save this as `service.yaml`. Adjust the
selector and target port to match your Pods:

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

```bash
kubectl apply -f service.yaml
kubectl -n apps get service web --watch
```

When ready, `EXTERNAL-IP` shows the server's public address. Traffic to port 443
reaches your Pods on port 8443. Your application or ingress gateway handles TLS;
TunnelLB does not manage application certificates. For UDP, use `protocol: UDP`
([example](examples/udp-service.yaml)).

If your application has a deny-ingress NetworkPolicy, allow its application ports
from the connector Pods in `tunnellb-system`. Only Services selecting ordinary
Pods are supported; headless, selectorless and `hostNetwork` backends are not.
When converting an existing Service, remove any allocated NodePorts and keep
both traffic policies at their default, `Cluster`.

### Service options

Add these under `metadata.annotations`:

| Annotation | Example | Purpose |
|---|---|---|
| `tunnellb.io/servers` | `"edge-1,edge-2"` | Choose specific servers. |
| `tunnellb.io/pool` | `"public"` | Choose from servers with `spec.pool: public`. |
| `tunnellb.io/replicas` | `"2"` | Publish on two servers instead of one. |
| `tunnellb.io/proxy-protocol` | `"https=v2"` | Send client address metadata to a compatible receiver. |

By default, TunnelLB picks one eligible server and keeps that assignment. Choose
either a server list or a pool. An explicit server list sets the replica count;
if you also set `replicas`, it must match the list length.

Applications normally see the connector's IP. PROXY protocol requires receiver
support: TCP accepts v1/v2, UDP only v2. Addresses reported by the public server
are not proof of a client's identity.

## Share a server across clusters

Register the same server in each cluster. TunnelLB chooses separate tunnel ports
and prevents public port conflicts, even while a cluster is disconnected.
Different Services must use different **port numbers**, including across TCP and
UDP. A single Service may use both protocols on the same number.

A conflict appears as `PortConflict` and is retried within ten minutes. Deleting
one cluster's Server leaves other clusters' tunnels running. Use one Server
object per address in each cluster, and only share with administrators you trust:
each has root-capable SSH access.

## Check status and remove tunnels

```bash
kubectl get servers
kubectl -n apps describe service web
kubectl -n tunnellb-system get pods,jobs
```

Server outages keep the assigned IP; tunnels reconnect when the server returns.
Multiple servers provide independent addresses, without automatic DNS or session
failover. Changing a Service's ports or destination interrupts its connections.

Delete published Services and wait for cleanup, then delete their Servers.
**Wait for both steps to finish before uninstalling TunnelLB.** If a server is
unreachable, deletion waits for remote cleanup. Once cleanup completes, its ports
can be reused.

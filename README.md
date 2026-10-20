# TunnelLB

TunnelLB installs [FRP](https://github.com/fatedier/frp) on a public server.
It sends TCP and UDP traffic through encrypted tunnels to Kubernetes Services.
The cluster starts the tunnels. The public server is not a cluster node.

## Requirements

- Use Kubernetes 1.32 or later with Linux nodes, kube-proxy, pod veth networking,
  and NetworkPolicy enforcement. TunnelLB cannot use CNI socket-level load balancing.
- On k3s, disable ServiceLB with `--disable=servicelb` on every server node.
- Use Helm 4. Install TunnelLB once in each cluster. Use a namespace only for TunnelLB.
- Use an amd64 or arm64 server with public IPv4 and systemd.
  Use Debian 12/13 or Ubuntu 22.04/24.04.
- Use root SSH access or an account with passwordless sudo.
- Open SSH, application ports, and TCP ports **20000–29999** in the server firewall.

## Install

Select a [release](https://github.com/melvspace/TunnelLB/releases).
Replace `X.Y.Z` with its version number. Do not include the `v` prefix.

```bash
VERSION="X.Y.Z"
helm upgrade --install tunnellb oci://ghcr.io/melvspace/charts/tunnellb \
  --version "$VERSION" \
  --namespace tunnellb-system --create-namespace
```

For a namespace that is already present, set `createNamespace=false`.
Configure its admission policy to let `NET_ADMIN` init containers run.
See [chart settings](charts/tunnellb/values.yaml).

## Add a server

Add the SSH public key to the server's `authorized_keys` file.
Store the private key in a Secret:

```bash
kubectl -n tunnellb-system create secret generic edge-1-ssh \
  --from-file=ssh-privatekey=/path/to/private-key
```

Save this manifest as `server.yaml`. Replace the address and SSH user.

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
kubectl get servers
```

Wait until the Server status is `Ready`.
TunnelLB accepts the first SSH host key. If the key changes, TunnelLB stops SSH operations.
For port settings, see the [Server example](examples/server.yaml).

## Publish an application

Create the application namespace. Enable TunnelLB for that namespace:

```bash
kubectl create namespace apps
kubectl label namespace apps tunnellb.io/enabled=true
```

Deploy your application in `apps`. Save this manifest as `service.yaml`.
Set the selector and target port for your application Pods.

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
      port: 443
      targetPort: 8443
      protocol: TCP
```

```bash
kubectl apply -f service.yaml
kubectl -n apps get service web --watch
```

`EXTERNAL-IP` shows the public server address. Configure TLS in your application or ingress gateway.
For UDP, set `protocol: UDP` ([example](examples/udp-service.yaml)).

Use Services with Pod selectors. TunnelLB cannot use headless, selectorless, or `hostNetwork` backends.
If a NetworkPolicy blocks ingress, let connector Pods in `tunnellb-system` access the application ports.
To disable automatic NodePort allocation, set `allocateLoadBalancerNodePorts: false`.
This setting is optional.
Keep `externalTrafficPolicy` and `internalTrafficPolicy` set to `Cluster`.

### Service options

Add these settings under `metadata.annotations`:

| Annotation | Example | Function |
|---|---|---|
| `tunnellb.io/servers` | `"edge-1,edge-2"` | Select these servers. |
| `tunnellb.io/pool` | `"public"` | Select servers with `spec.pool: public`. |
| `tunnellb.io/replicas` | `"2"` | Use two servers. |
| `tunnellb.io/proxy-protocol` | `"https=v2"` | Send client IP data through PROXY protocol. |

By default, TunnelLB selects one server. Use either `servers` or `pool`.
A `servers` list sets the number of replicas.
If you also set `replicas`, use the number of servers in the list.

Without PROXY protocol, applications receive the connector's IP.
Use receivers that can read PROXY protocol: v1/v2 for TCP, or v2 for UDP.
Do not use PROXY addresses to authenticate clients.

## Share a server

Create a Server in each cluster. Use one Server object for each address in each cluster.
Use different public port numbers for different Services, also across TCP and UDP.
One Service can use both protocols on the same port.

TunnelLB selects available tunnel ports. It keeps port reservations when a cluster disconnects.
If a Service shows `PortConflict`, TunnelLB tries again in ten minutes or less.
If you delete the Server in one cluster, the tunnels of other clusters continue.

Each cluster's administrator can run commands as root on the server.

## Status and removal

```bash
kubectl -n apps describe service web
kubectl -n tunnellb-system get pods,jobs
```

If a server stops, the Service keeps its IP address.
The tunnels connect again when the server is available.
TunnelLB does not provide DNS updates or session failover.
If you change the ports or destination of a Service, TunnelLB closes its connections.

1. Delete the published Services. Wait for deletion to complete.
2. Delete the Servers. Wait for deletion to complete.
3. Uninstall TunnelLB.

If a server is unreachable, deletion waits for remote cleanup.

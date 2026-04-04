# Kubernetes and Cloud-Native Patterns

Patterns for RBAC misconfiguration, pod security, network exposure, unsafe volume mounts, and cross-namespace access in Kubernetes manifests, Helm charts, and operator code (Go, YAML).

---

## Table of contents

1. [RBAC misconfiguration](#rbac-misconfiguration)
2. [Pod security](#pod-security)
3. [Network exposure](#network-exposure)
4. [Unsafe volume mounts](#unsafe-volume-mount)
5. [Cross-namespace access](#cross-namespace-access)
6. [Cloud metadata SSRF](#cloud-metadata-ssrf)
7. [General search strategy](#general-search-strategy)

---

## RBAC misconfiguration

Overpermissive ClusterRoles/Roles that grant more access than the workload requires. Particularly dangerous when an operator's service account has broad cluster-scoped access that an attacker can leverage.

### Dangerous patterns (YAML manifests)

**Wildcard verbs or resources:**
```yaml
# VULNERABLE: full cluster admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

**Secrets access at cluster scope:**
```yaml
# VULNERABLE: can read all secrets in cluster
kind: ClusterRole
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
```

**Escalation-capable verbs:**
```yaml
# VULNERABLE: can create/modify roles and bindings
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "clusterrolebindings"]
  verbs: ["create", "update", "patch"]
```

**Bind/escalate/impersonate:**
```yaml
# VULNERABLE: can escalate own privileges
verbs: ["bind", "escalate", "impersonate"]
```

### Dangerous patterns (Go operator code)
```go
// VULNERABLE: building RBAC rules programmatically with wildcards
PolicyRule{Verbs: []string{"*"}, Resources: []string{"*"}}

// VULNERABLE: creating ClusterRoleBinding to cluster-admin
Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa}}
RoleRef: rbacv1.RoleRef{Name: "cluster-admin"}
```

### What to check
- ClusterRole vs Role: cluster-scoped access when namespace-scoped would suffice.
- `secrets`, `pods/exec`, `nodes/proxy` access without clear justification.
- Service accounts bound to overpermissive roles but used by internet-facing workloads.

---

## Pod security

Missing or insufficient security context on pods and containers. Default settings in Kubernetes are permissive -- security requires explicit opt-in.

### Dangerous patterns (YAML)

**Running as root:**
```yaml
# VULNERABLE: no runAsNonRoot constraint
securityContext: {}

# VULNERABLE: explicit root
securityContext:
  runAsUser: 0
```

**Privileged container:**
```yaml
# VULNERABLE: full host access
securityContext:
  privileged: true
```

**Missing capability drops:**
```yaml
# VULNERABLE: inherits default Linux capabilities
# Missing: securityContext.capabilities.drop: ["ALL"]
```

**Host namespace access:**
```yaml
# VULNERABLE: shares host PID/network/IPC namespace
hostPID: true
hostNetwork: true
hostIPC: true
```

**Writable root filesystem:**
```yaml
# VULNERABLE: container can write to its own filesystem
# Missing: readOnlyRootFilesystem: true
```

### Dangerous patterns (Helm charts)
```yaml
# VULNERABLE: empty securityContext in values.yaml defaults
securityContext: {}
podSecurityContext: {}

# VULNERABLE: privileged toggled by value with permissive default
privileged: {{ .Values.security.privileged | default true }}
```

### Dangerous patterns (Go operator code)
```go
// VULNERABLE: building PodSpec without SecurityContext
PodSpec{Containers: []corev1.Container{{Name: "app", Image: img}}}

// VULNERABLE: setting privileged in code
SecurityContext: &corev1.SecurityContext{Privileged: boolPtr(true)}
```

### What to check
- Every container should have explicit `securityContext` with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and `capabilities.drop: ["ALL"]`.
- `hostPID`, `hostNetwork`, `hostIPC` should be absent or false.
- Helm chart defaults should be secure, not permissive.

---

## Network exposure

Unauthenticated service endpoints, missing NetworkPolicy, and services exposed beyond their intended scope.

### Dangerous patterns (YAML)

**LoadBalancer exposing internal service:**
```yaml
# VULNERABLE: internal operator port exposed to internet
kind: Service
spec:
  type: LoadBalancer
  ports:
  - port: 8080   # metrics, health, or management endpoint
```

**Missing NetworkPolicy:**
If no `NetworkPolicy` objects exist in a namespace, all pod-to-pod traffic is allowed by default. Any pod that gets compromised can reach all other pods.

**Binding to 0.0.0.0:**
```yaml
# In Go operator code:
# VULNERABLE: health/management server on all interfaces
http.ListenAndServe(":6676", handler)
# or
listener, _ := net.Listen("tcp", "0.0.0.0:8080")
```

### Dangerous patterns (Go operator code)
```go
// VULNERABLE: REST endpoint with no auth middleware
mux.HandleFunc("/suspend", suspendHandler)
mux.HandleFunc("/status/", statusHandler)

// VULNERABLE: metrics endpoint without auth
http.Handle("/metrics", promhttp.Handler())
```

### What to check
- Management, health, metrics, and debug endpoints: are they exposed beyond the pod/cluster?
- Services of type `LoadBalancer` or `NodePort` for internal-only workloads.
- Presence of `NetworkPolicy` resources restricting ingress/egress.
- Go/Java HTTP servers binding to `0.0.0.0` with unauthenticated handlers.

---

## Unsafe volume mount

Host filesystem paths mounted into containers, giving the container access to sensitive host resources.

### Dangerous patterns (YAML)

**Docker socket mount:**
```yaml
# VULNERABLE: container can control the Docker daemon = host root
volumes:
- name: docker-sock
  hostPath:
    path: /var/run/docker.sock
```

**Sensitive host paths:**
```yaml
# VULNERABLE: access to host PKI, SSH keys, etc.
hostPath:
  path: /etc/pki
hostPath:
  path: /root/.ssh
hostPath:
  path: /etc/kubernetes/pki
```

**Writable host mounts:**
```yaml
# VULNERABLE: writable mount to host filesystem
volumeMounts:
- mountPath: /host
  name: host-root
volumes:
- name: host-root
  hostPath:
    path: /
```

### Dangerous patterns (Go operator code)
```go
// VULNERABLE: building volume spec with hostPath
HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}
```

### What to check
- `hostPath` volumes, especially `/var/run/docker.sock`, `/`, `/etc`, `/proc`, `/sys`.
- Whether the mount is `readOnly: true` (mitigates but does not eliminate risk for some paths).
- Use of `emptyDir`, `configMap`, `secret`, or `persistentVolumeClaim` instead (preferred).

---

## Cross-namespace access

Operators or workloads that can read, modify, or leak resources across namespace boundaries without proper scoping.

### Dangerous patterns (Go operator code)
```go
// VULNERABLE: operator lists resources across all namespaces
client.List(ctx, &list, client.InNamespace(""))

// VULNERABLE: REST endpoint exposes cross-namespace data
// e.g. /status/<namespace>/<name> with no authz check
mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
    parts := strings.Split(r.URL.Path, "/")
    ns, name := parts[2], parts[3]
    // fetches resource from arbitrary namespace
})
```

### Dangerous patterns (YAML)
```yaml
# VULNERABLE: ClusterRole (not Role) with broad resource access
# combined with ClusterRoleBinding
kind: ClusterRole
rules:
- apiGroups: [""]
  resources: ["pods", "services", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "delete"]
```

### What to check
- Operator watches/lists with empty namespace (cluster-wide) when it should be scoped.
- REST/gRPC endpoints that accept a namespace parameter without authorization.
- ClusterRole + ClusterRoleBinding when Role + RoleBinding in specific namespaces would suffice.

---

## Cloud metadata SSRF

Environment variables or user-controlled values used to construct URLs that can reach cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.).

### Dangerous patterns (Go)
```go
// VULNERABLE: environment variable used as URL without validation
site := os.Getenv("COHERENCE_SITE")
resp, _ := http.Get(site)  // can be set to http://169.254.169.254/...

// VULNERABLE: user-controlled host in URL construction
url := fmt.Sprintf("http://%s:%d/api", userHost, port)
```

### Dangerous patterns (YAML)
```yaml
# VULNERABLE: env var from user-supplied ConfigMap used as URL
env:
- name: CALLBACK_URL
  valueFrom:
    configMapKeyRef:
      name: user-config
      key: callback-url
```

### What to check
- Environment variables used to build HTTP request URLs.
- Whether URL validation blocks private/link-local ranges (169.254.x.x, 10.x.x.x, 172.16-31.x.x, fd00::/8).
- Cloud IAM credentials exposed via metadata endpoint.

---

## General search strategy

### High-signal grep patterns for Kubernetes YAML
```
ClusterRole|ClusterRoleBinding
verbs:.*\*|resources:.*\*
hostPath:|hostPID:|hostNetwork:|hostIPC:
privileged:\s*true
runAsUser:\s*0
docker\.sock
type:\s*LoadBalancer|type:\s*NodePort
securityContext:\s*\{\}
capabilities:
```

### High-signal grep patterns for Go operator code
```
ClusterRole|PolicyRule|RoleBinding
ListenAndServe|net\.Listen
hostPath|HostPathVolumeSource
SecurityContext|Privileged
InNamespace\s*\(\s*""\s*\)
169\.254\.169\.254|metadata\.google
```

### Analysis approach
1. **Find RBAC definitions** (ClusterRole, Role) and check for wildcards, secrets access, escalation verbs.
2. **Find pod/deployment specs** and check for securityContext, hostPath, privileged.
3. **Find service definitions** and check for LoadBalancer/NodePort on internal endpoints.
4. **Find HTTP servers** in operator code and check for authentication on management endpoints.
5. **Check for NetworkPolicy** objects -- absence is a finding in any production-targeted namespace.
6. **Trace environment variables** used in URL construction to check for metadata SSRF.

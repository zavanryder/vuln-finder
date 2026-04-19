# Kubernetes Operator Patterns

Operator-specific security patterns for controller-runtime / kubebuilder / operator-sdk code.

## CRD field injection

User-supplied CRD spec fields that flow unsanitized into shell commands, templates, or API calls.

```go
// VULNERABLE: spec field passed directly to exec
cmd := exec.Command("mysqldump", "--databases", cr.Spec.DatabaseName)

// VULNERABLE: Go template injection via CRD spec field
tmpl := template.New("config").Parse(cr.Spec.ConfigTemplate)

// VULNERABLE: user-controlled value in label selector
selector := labels.SelectorFromSet(labels.Set{"app": cr.Spec.AppName})
client.List(ctx, &podList, client.MatchingLabelsSelector{Selector: selector})
```

**What to check:** Trace every `cr.Spec.*` field to exec, template, label selector, SQL, or URL. Validate with kubebuilder markers (`+kubebuilder:validation:Pattern`).

## Cross-namespace access (confused deputy)

Operator's elevated RBAC fetches resources from namespaces the requesting user should not access.

```go
// VULNERABLE: user sets spec.SecretRef.Namespace, operator fetches without SAR
client.Get(ctx, types.NamespacedName{
    Namespace: cr.Spec.SecretRef.Namespace,
    Name:      cr.Spec.SecretRef.Name,
}, secret)
```

**What to check:** Any `ObjectRef`/`ResourceRef`/`SecretRef` with a `Namespace` field. Operator must perform `SubjectAccessReview` before accessing the referenced resource. Check whether content is leaked in `.Status` or events.

## RBAC escalation

```yaml
# VULNERABLE: self-privilege-escalation
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate", "bind"]

# VULNERABLE: cross-identity access
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]

# VULNERABLE: secrets read + pods/exec = extract any SA token
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

**What to check:** `escalate`, `bind`, `impersonate` verbs. Combination of `secrets` read + `pods/exec`. ClusterRoleBinding to `cluster-admin` or wildcard ClusterRole.

## Webhook security

```yaml
# VULNERABLE: webhook bypass when service is down (fail-open)
kind: MutatingWebhookConfiguration
webhooks:
- name: mutate.example.com
  failurePolicy: Ignore

# VULNERABLE: affects kube-system, can break control plane
  namespaceSelector: {}
```

```go
// VULNERABLE: webhook sets SA from user-controlled annotation
pod.Spec.ServiceAccountName = pod.Annotations["inject.example.com/sa-name"]

// VULNERABLE: webhook grants privileged based on label
if pod.Labels["privileged"] == "true" {
    pod.Spec.Containers[0].SecurityContext.Privileged = boolPtr(true)
}
```

**What to check:** `failurePolicy: Ignore`. Webhook serving plain HTTP (no TLS). Webhook mutating `securityContext`, `serviceAccountName`, `volumes`. Missing `namespaceSelector` excluding `kube-system`.

## Controller reconciliation

```go
// VULNERABLE: secret data in logs
log.Info("Reconciling", "dbPassword", string(secret.Data["password"]))

// VULNERABLE: credentials in status (readable by any user with get on CR)
cr.Status.ConnectionInfo = fmt.Sprintf("postgres://%s:%s@%s", user, pass, host)

// VULNERABLE: orphan accumulation -- no cleanup on CR deletion
deployment := &appsv1.Deployment{...}
client.Create(ctx, deployment)  // missing controllerutil.SetControllerReference

// VULNERABLE: tight requeue loop without backoff (amplification)
return ctrl.Result{Requeue: true}, nil  // should use RequeueAfter with backoff
```

**What to check:** `log.Info`/`log.Error` including `secret.Data`. `.Status` fields with credentials. `client.Create` without `SetControllerReference`/`SetOwnerReference`. Error-path `Requeue: true` without `RequeueAfter`.

## Operator deployment

```yaml
# VULNERABLE: operator runs as root
containers:
- name: manager
  securityContext:
    runAsUser: 0
  # VULNERABLE: mutable tag -- supply chain risk
  image: example.com/operator:latest
  # VULNERABLE: unbounded resource consumption
  resources: {}
```

```go
// VULNERABLE: split-brain when running multiple replicas
mgr, _ := ctrl.NewManager(cfg, ctrl.Options{LeaderElection: false})
```

**What to check:** `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: ["ALL"]`. Image digest vs mutable tag. `resources.limits` on operator pod. `LeaderElection: true` with valid lease name.

## Search strategy

### Grep patterns (Go)
```
exec\.Command|template\.Parse|Spec\.\w+.*Namespace|SubjectAccessReview
escalate|bind|impersonate|SetControllerReference|Requeue:\s*true
secret\.Data|\.Data\["|LeaderElection
```

### Grep patterns (YAML)
```
failurePolicy:\s*Ignore|namespaceSelector:\s*\{\}
verbs:.*escalate|verbs:.*bind|verbs:.*impersonate
image:.*:latest|resources:\s*\{\}|runAsUser:\s*0
```

### Approach
1. Find CRD types (`*_types.go`), trace spec fields to reconciler usage.
2. Find ObjectRef/SecretRef fields, check for SubjectAccessReview.
3. Find RBAC manifests, check for escalation verbs.
4. Find webhook configs, check failurePolicy/TLS/namespace selector.
5. Find reconcile functions, check for secret logging, missing owner refs, tight requeue.
6. Check operator deployment for root, mutable tags, missing limits.

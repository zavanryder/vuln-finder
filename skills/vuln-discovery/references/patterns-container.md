# Container and IaC Patterns

Patterns for Dockerfile security, Helm chart misconfiguration, image tag pinning, and Terraform/HCL infrastructure-as-code vulnerabilities.

---

## Table of contents

1. [Dockerfile security](#dockerfile-security)
2. [Helm chart misconfiguration](#helm-chart-misconfiguration)
3. [Terraform / HCL misconfiguration](#terraform--hcl-misconfiguration)
4. [General search strategy](#general-search-strategy)

---

## Dockerfile security

### Running as root
```dockerfile
# VULNERABLE: no USER directive -- defaults to root
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y app
CMD ["app"]

# VULNERABLE: explicit root
USER root
```

Containers running as root can exploit kernel vulnerabilities or writable mounts to escape to the host.

### Unpinned base images
```dockerfile
# VULNERABLE: :latest is mutable, can change without notice
FROM node:latest
FROM python

# SAFER: pinned digest
FROM node:20.11.0-alpine@sha256:abc123...
```

### ADD from remote URL
```dockerfile
# VULNERABLE: downloads and extracts without integrity check
ADD https://example.com/app.tar.gz /opt/

# SAFER: use COPY + RUN curl with checksum
COPY app.tar.gz /opt/
RUN echo "expected_sha256  /opt/app.tar.gz" | sha256sum -c
```

### Secrets in build
```dockerfile
# VULNERABLE: secret baked into image layer
ENV DATABASE_PASSWORD=hunter2
COPY .env /app/.env
ARG API_KEY
RUN curl -H "Authorization: Bearer $API_KEY" https://...
```

Build args and ENV values persist in image layers and can be extracted with `docker history`.

### Unnecessary packages and tools
```dockerfile
# VULNERABLE: attack surface in production image
RUN apt-get install -y curl wget netcat gcc make
```

Production images should be minimal. Use multi-stage builds to separate build tools from runtime.

### Exposed debug ports
```dockerfile
# SUSPICIOUS: debug port exposed
EXPOSE 5005
EXPOSE 9229
EXPOSE 4200
```

---

## Helm chart misconfiguration

### Permissive defaults in values.yaml
```yaml
# VULNERABLE: security off by default
securityContext: {}
podSecurityContext: {}
networkPolicy:
  enabled: false
rbac:
  create: true
  clusterScope: true  # cluster-wide when namespace would suffice
```

### Hardcoded secrets in values
```yaml
# VULNERABLE: credentials in values.yaml (committed to repo)
database:
  password: "admin123"
redis:
  auth: "changeme"
```

### Tpl injection in Helm templates
```yaml
# VULNERABLE: user-supplied value rendered as template
{{ tpl .Values.customAnnotation . }}
# If customAnnotation contains {{ ... }}, it executes as Go template
```

### Missing resource limits
```yaml
# VULNERABLE: no resource limits -- pod can consume entire node
resources: {}
```

---

## Terraform / HCL misconfiguration

### Public access to storage
```hcl
# VULNERABLE: S3 bucket publicly accessible
resource "aws_s3_bucket_public_access_block" "example" {
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# VULNERABLE: GCS bucket public
resource "google_storage_bucket_iam_member" "public" {
  member = "allUsers"
}
```

### Unencrypted storage and transport
```hcl
# VULNERABLE: no encryption on RDS
resource "aws_db_instance" "db" {
  storage_encrypted = false
}

# VULNERABLE: no encryption on S3
resource "aws_s3_bucket" "data" {
  # missing server_side_encryption_configuration
}

# VULNERABLE: ELB without HTTPS
resource "aws_lb_listener" "http" {
  port     = 80
  protocol = "HTTP"
}
```

### Overpermissive IAM
```hcl
# VULNERABLE: admin access
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
```

### Security groups with 0.0.0.0/0
```hcl
# VULNERABLE: SSH from anywhere
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# VULNERABLE: database port from anywhere
resource "aws_security_group_rule" "db" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  cidr_blocks = ["0.0.0.0/0"]
}
```

### Missing logging and monitoring
```hcl
# VULNERABLE: CloudTrail or flow logs disabled
resource "aws_cloudtrail" "trail" {
  enable_logging = false
}
```

---

## General search strategy

### High-signal grep patterns for Dockerfiles
```
FROM.*:latest|FROM [a-z]+$
USER root|USER 0
ADD https?://
ENV.*(PASSWORD|SECRET|KEY|TOKEN)
EXPOSE.*(5005|9229|4200|8000|3000)
```

### High-signal grep patterns for Helm charts
```
securityContext:\s*\{\}
password:|secret:|token:|auth:
tpl\s+\.Values
networkPolicy:.*enabled:\s*false
resources:\s*\{\}
```

### High-signal grep patterns for Terraform/HCL
```
cidr_blocks.*0\.0\.0\.0/0|ingress.*0\.0\.0\.0
Action.*=.*\*|Effect.*Allow.*Action.*\*
storage_encrypted\s*=\s*false|encrypted\s*=\s*false
allUsers|allAuthenticatedUsers
enable_logging\s*=\s*false
block_public_acls\s*=\s*false
```

### Analysis approach
1. **Dockerfiles**: Check `FROM` for pinning, `USER` for non-root, `ADD` for remote URLs, `ENV`/`ARG` for secrets, `EXPOSE` for debug ports.
2. **Helm charts**: Check `values.yaml` defaults for permissive security settings, hardcoded credentials, tpl injection vectors.
3. **Terraform**: Check IAM policies for wildcards, security groups for 0.0.0.0/0, storage for encryption, logging for disabled flags.
4. **Cross-cutting**: Verify that secrets are managed externally (Vault, KMS, sealed-secrets) rather than hardcoded in any IaC files.

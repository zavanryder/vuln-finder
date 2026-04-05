# Cloud IaC Patterns

Patterns for cloud-provider-specific infrastructure-as-code security: Azure ARM/Bicep, AWS CloudFormation, GCP Terraform, OCI Terraform, and cross-cloud shell provisioning.

---

## Table of contents

1. [Azure ARM / Bicep](#azure-arm--bicep)
2. [AWS CloudFormation](#aws-cloudformation)
3. [GCP Terraform](#gcp-terraform)
4. [OCI Terraform](#oci-terraform)
5. [Cross-cloud shell provisioning](#cross-cloud-shell-provisioning)
6. [General search strategy](#general-search-strategy)

---

## Azure ARM / Bicep

### Network exposure
```bicep
// VULNERABLE: NSG allows all inbound to admin ports
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  properties: {
    securityRules: [{
      properties: {
        sourceAddressPrefix: '*'          // any source
        destinationPortRange: '22'
        access: 'Allow'
        direction: 'Inbound'
      }
    }]
  }
}
```

ARM JSON equivalent:
```json
{
  "type": "Microsoft.Network/networkSecurityGroups",
  "properties": {
    "securityRules": [{
      "properties": {
        "sourceAddressPrefix": "*",
        "destinationPortRange": "22",
        "access": "Allow",
        "direction": "Inbound"
      }
    }]
  }
}
```

Both `*` and `Internet` as `sourceAddressPrefix` allow public internet access. Dangerous destination ports include 22 (SSH), 3389 (RDP), 7001-9000 (WebLogic admin consoles), 5432 (PostgreSQL), 3306 (MySQL), 1433 (MSSQL), and 1521 (Oracle DB).

### Storage account misconfiguration
```bicep
// VULNERABLE: storage accessible from all networks, HTTP allowed
properties: {
    networkAcls: {
      defaultAction: 'Allow'             // no network restriction
    }
    supportsHttpsTrafficOnly: false       // allows cleartext HTTP
    publicNetworkAccess: 'Enabled'
    // missing: minimumTlsVersion: 'TLS1_2'
    // missing: encryption configuration
}
```

When `defaultAction` is `Allow`, the storage account accepts traffic from any network. Combined with HTTP and missing TLS enforcement, data in transit is exposed to interception.

### Container Registry (ACR)
```bicep
// VULNERABLE: public ACR with admin user, no content trust
properties: {
    adminUserEnabled: true                // shared credential, not RBAC
    publicNetworkAccess: 'Enabled'        // internet-reachable
    policies: {
      trustPolicy: { status: 'disabled' } // unsigned images accepted
    }
    encryption: { status: 'disabled' }
}
```

Admin credentials are a single shared username/password pair that cannot be scoped or audited per-user. Disabling trust policy allows unsigned or tampered images to be pulled.

### Key Vault
```bicep
// VULNERABLE: public Key Vault without deletion protection
properties: {
    publicNetworkAccess: 'Enabled'
    enableSoftDelete: false               // permanent deletion possible
    enablePurgeProtection: false           // no recovery window
}
```

Without soft-delete and purge protection, secrets and keys can be permanently destroyed with no recovery window, enabling destructive attacks by compromised identities.

### Overpermissive managed identity
```bicep
// VULNERABLE: Contributor at subscription scope
var roleId = 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor
module roleAssignment '_roleAssignment.bicep' = {
  scope: subscription()                    // entire subscription!
  params: { roleDefinitionId: roleId, principalId: identity.principalId }
}
```

Owner role ID is `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`. Both Contributor and Owner at `subscription()` or `managementGroup()` scope grant excessive privileges. Scope should be limited to specific resource groups.

### SQL Server
```bicep
// VULNERABLE: public SQL with allow-all firewall
properties: { publicNetworkAccess: 'Enabled' }
resource firewallRule 'firewallRules' = {
  properties: {
    startIpAddress: '0.0.0.0'            // allows all Azure IPs
    endIpAddress: '255.255.255.255'       // allows all IPs
  }
}
```

The range `0.0.0.0` to `255.255.255.255` permits connections from any IP. Even `0.0.0.0` to `0.0.0.0` alone enables the "Allow Azure services" flag, which opens access from any Azure-hosted workload across any tenant.

### ARM template secrets in commands
```json
// VULNERABLE: password concatenated into command string
{
  "commandToExecute": "[concat('sh script.sh <<< \"', parameters('adminUser'), ' ', parameters('adminPassword'), '\"')]"
}
```

This exposes credentials in `/proc/*/cmdline` and Azure VM extension logs. Use environment variables via `protectedSettings` instead; values in `protectedSettings` are encrypted at rest and not logged.

### App Service
```bicep
// VULNERABLE: no HTTPS enforcement, debug enabled
properties: {
    httpsOnly: false
    siteConfig: {
      remoteDebuggingEnabled: true
      minTlsVersion: '1.0'               // should be 1.2+
    }
}
```

Remote debugging opens an authenticated port on the App Service, and TLS 1.0 is vulnerable to BEAST and POODLE attacks.

---

## AWS CloudFormation

### Security groups
```yaml
# VULNERABLE: SSH from anywhere
Type: AWS::EC2::SecurityGroup
Properties:
  SecurityGroupIngress:
    - IpProtocol: tcp
      FromPort: 22
      ToPort: 22
      CidrIp: 0.0.0.0/0                 # any source
```

Dangerous ports to check: 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL), 27017 (MongoDB), 6379 (Redis), 9200 (Elasticsearch).

### Overpermissive IAM
```yaml
# VULNERABLE: admin access
Type: AWS::IAM::Policy
Properties:
  PolicyDocument:
    Statement:
      - Effect: Allow
        Action: '*'
        Resource: '*'
```

Wildcard action and resource grants full AWS account access. Even `Action: 'iam:*'` or `Action: 's3:*'` with `Resource: '*'` are overpermissive for most use cases.

### S3 bucket
```yaml
# VULNERABLE: no public access block, no encryption
Type: AWS::S3::Bucket
Properties:
  BucketName: my-bucket
  # missing: PublicAccessBlockConfiguration
  # missing: BucketEncryption with ServerSideEncryptionConfiguration
```

Safe version:
```yaml
Type: AWS::S3::Bucket
Properties:
  PublicAccessBlockConfiguration:
    BlockPublicAcls: true
    BlockPublicPolicy: true
    IgnorePublicAcls: true
    RestrictPublicBuckets: true
  BucketEncryption:
    ServerSideEncryptionConfiguration:
      - ServerSideEncryptionByDefault:
          SSEAlgorithm: aws:kms
```

### RDS
```yaml
# VULNERABLE: public, unencrypted, password in template
Type: AWS::RDS::DBInstance
Properties:
  PubliclyAccessible: true
  StorageEncrypted: false
  MasterUserPassword: 'hardcoded-password'   # should use Secrets Manager
```

Passwords should reference `AWS::SecretsManager::Secret` or `ssm-secure` parameters rather than plaintext in templates. Templates are stored in CloudFormation history and S3, making hardcoded secrets recoverable.

### Load balancer
```yaml
# VULNERABLE: HTTP listener, no redirect to HTTPS
Type: AWS::ElasticLoadBalancingV2::Listener
Properties:
  Port: 80
  Protocol: HTTP
```

An HTTP listener without a redirect action serves traffic in cleartext. The listener should either use HTTPS with a certificate or redirect all HTTP traffic to HTTPS.

### CloudTrail
```yaml
# VULNERABLE: logging disabled
Type: AWS::CloudTrail::Trail
Properties:
  IsLogging: false
  EnableLogFileValidation: false
```

Disabled CloudTrail logging removes the audit trail for API calls. Disabled log file validation allows tampered logs to go undetected.

### Lambda secrets
```yaml
# VULNERABLE: secrets in environment variables (visible in console/API)
Type: AWS::Lambda::Function
Properties:
  Environment:
    Variables:
      DB_PASSWORD: 'hunter2'
      API_KEY: 'sk-live-...'
```

Lambda environment variables are visible in the AWS Console, `GetFunction` API response, and CloudFormation stack outputs. Use Secrets Manager or SSM Parameter Store with runtime retrieval instead.

### EC2 UserData
```yaml
# VULNERABLE: secrets embedded in UserData (base64 decoded, visible in metadata)
Type: AWS::EC2::Instance
Properties:
  UserData:
    Fn::Base64: !Sub |
      #!/bin/bash
      echo "DB_PASS=${DatabasePassword}" >> /etc/app.env
```

UserData is base64-encoded, not encrypted. It is retrievable from instance metadata (`http://169.254.169.254/latest/user-data`) and visible in CloudFormation templates and EC2 console.

---

## GCP Terraform

### Firewall rules
```hcl
# VULNERABLE: SSH from anywhere
resource "google_compute_firewall" "allow_ssh" {
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
```

Using the `default` network is itself a risk, as it comes with pre-created permissive firewall rules. Custom networks with explicit firewall rules are preferred.

### Public storage
```hcl
# VULNERABLE: bucket readable by anyone on internet
resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"                    # public internet access
}
```

`allUsers` means unauthenticated public access. `allAuthenticatedUsers` means any Google account holder, which is still essentially public since anyone can create a Google account.

### Overpermissive IAM
```hcl
# VULNERABLE: project-wide editor (near-admin)
resource "google_project_iam_member" "editor" {
  project = "my-project"
  role    = "roles/editor"              # overpermissive primitive role
  member  = "serviceAccount:${google_service_account.sa.email}"
}
```

`roles/owner` and `roles/editor` are primitive roles that grant broad access across all services in a project. Replace with fine-grained predefined roles scoped to specific services (e.g. `roles/storage.admin`, `roles/cloudsql.client`).

### Cloud SQL
```hcl
# VULNERABLE: public access, no SSL
resource "google_sql_database_instance" "db" {
  settings {
    ip_configuration {
      authorized_networks {
        value = "0.0.0.0/0"            # any IP can connect
      }
      require_ssl = false               # cleartext connections
    }
  }
}
```

Cloud SQL instances with `0.0.0.0/0` in authorized networks accept connections from any IP. Combined with `require_ssl = false`, credentials and queries travel in cleartext.

### GKE cluster
```hcl
# VULNERABLE: legacy ABAC, no network policy, public endpoint
resource "google_container_cluster" "primary" {
  enable_legacy_abac = true              # bypasses RBAC
  network_policy { enabled = false }     # no pod-to-pod isolation
  # missing: private_cluster_config
  # missing: master_authorized_networks_config
}
```

Legacy ABAC allows any authenticated user to perform any action. Without `private_cluster_config`, the Kubernetes API server is publicly accessible. Without `master_authorized_networks_config`, any IP can reach the API.

### Compute instance
```hcl
# VULNERABLE: default service account with full access
resource "google_compute_instance" "vm" {
  service_account {
    email  = "PROJECT_NUMBER-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]          # full API access
  }
  metadata = {
    startup-script = "echo DB_PASS=${var.db_password} >> /etc/env"  # secret in metadata
  }
}
```

The `cloud-platform` scope grants the service account access to all GCP APIs. The default compute service account typically has Editor role, making this combination equivalent to full project access. Startup scripts are readable from instance metadata.

### KMS
```hcl
# VULNERABLE: no automatic key rotation
resource "google_kms_crypto_key" "key" {
  name     = "my-key"
  key_ring = google_kms_key_ring.ring.id
  # missing: rotation_period (should be <= 90 days)
}
```

Without `rotation_period`, keys are never automatically rotated. Long-lived keys increase the blast radius of key compromise.

---

## OCI Terraform

### Security list
```hcl
# VULNERABLE: SSH from anywhere
resource "oci_core_security_list" "open" {
  vcn_id = oci_core_vcn.vcn.id
  ingress_security_rules {
    protocol = "6"                       # TCP
    source   = "0.0.0.0/0"              # any source
    tcp_options {
      min = 22
      max = 22
    }
  }
}
```

Also check NSG rules: `oci_core_network_security_group_security_rule` with `direction = "INGRESS"` and `source = "0.0.0.0/0"` has the same effect.

### Object storage
```hcl
# VULNERABLE: public bucket
resource "oci_objectstorage_bucket" "public" {
  access_type = "ObjectRead"             # or "ObjectReadWithoutList"
  # should be "NoPublicAccess"
  # missing: kms_key_id for encryption
  # missing: versioning = "Enabled"
}
```

`ObjectRead` and `ObjectReadWithoutList` both allow unauthenticated access to objects. Only `NoPublicAccess` restricts to authenticated IAM principals.

### IAM policy
```hcl
# VULNERABLE: overly broad permissions
resource "oci_identity_policy" "admin" {
  statements = [
    "allow group Admins to manage all-resources in tenancy"
  ]
}
```

`manage all-resources` grants full control over every resource type in the specified scope. Policies should use specific resource types (e.g. `manage buckets`, `use instances`) and compartment scope instead of tenancy.

### Database
```hcl
# VULNERABLE: database without NSG or encryption
resource "oci_database_db_system" "db" {
  # missing: nsg_ids = [oci_core_network_security_group.db.id]
  # missing: kms_key_id for TDE encryption
  # missing: deletion_protection
}
```

Without NSG attachment, the database relies solely on subnet-level security lists, which are often overpermissive. Missing KMS key means data is encrypted with Oracle-managed keys that the customer cannot rotate or revoke.

### Compute instance
```hcl
# VULNERABLE: secrets in user_data metadata
resource "oci_core_instance" "vm" {
  metadata = {
    user_data = base64encode(<<-EOF
      #!/bin/bash
      echo "DB_PASS=hunter2" >> /etc/app.env
    EOF
    )
  }
  # missing: source_details.kms_key_id for boot volume encryption
}
```

`user_data` is base64-encoded, not encrypted. It is retrievable from the instance metadata service (`http://169.254.169.254/opc/v1/instance/metadata/user_data`) and visible in the OCI Console.

### KMS Vault
```hcl
# VULNERABLE: not using private vault
resource "oci_kms_vault" "vault" {
  vault_type = "DEFAULT"                 # should be "VIRTUAL_PRIVATE" for isolation
}
```

DEFAULT vaults share HSM partitions with other tenants. `VIRTUAL_PRIVATE` vaults provide dedicated HSM partitions for cryptographic isolation.

### Subnet
```hcl
# VULNERABLE: public IPs allowed on private subnet
resource "oci_core_subnet" "private" {
  prohibit_public_ip_on_vnic = false     # should be true for private subnets
}
```

When `prohibit_public_ip_on_vnic` is false, instances in the subnet can be assigned public IPs, defeating the purpose of a private subnet.

---

## Cross-cloud shell provisioning

### Docker login with password on CLI
```bash
# VULNERABLE: password visible in process listing (/proc/*/cmdline)
docker login registry.example.com -u $USER -p $PASSWORD

# SAFE: password via stdin
echo "$PASSWORD" | docker login registry.example.com -u $USER --password-stdin
```

### TLS verification disabled
```bash
# VULNERABLE: allows MITM attacks
curl --insecure https://admin-server:7001/health
curl -k https://api.example.com/status
wget --no-check-certificate https://...
```

Disabling TLS verification means the client accepts any certificate, including attacker-controlled ones. This is especially dangerous when credentials are sent in the same request.

### Overpermissive file permissions
```bash
# VULNERABLE: world-readable/writable
chmod 777 /opt/app/config
mount -t cifs //server/share /mnt -o dir_mode=0777,file_mode=0777

# SAFE: restricted to owner/group
chmod 750 /opt/app/config
mount -t cifs //server/share /mnt -o uid=appuser,gid=appgroup,dir_mode=0750,file_mode=0640
```

### Credentials in log output
```bash
# VULNERABLE: credentials echoed to stdout -> captured in deployment logs
echo "password=$storageAccountKey"
echo "Connecting with user=$DB_USER pass=$DB_PASS"

# SAFE: suppress credential values in output
echo "Configuring storage credentials..."
```

Deployment systems (CI/CD runners, cloud provisioning agents) capture stdout/stderr into logs. Credentials printed to output end up in log storage, often with broad read access.

### Credentials as CLI arguments
```bash
# VULNERABLE: visible in process listing
mysql -u admin -p'secretpass' -h dbhost
psql "postgresql://admin:secretpass@dbhost/mydb"
curl --user admin:password http://api:8080/manage

# SAFE: use environment variables or config files
export PGPASSWORD="$DB_PASS"
psql -U admin -h dbhost mydb
```

Arguments are visible to any user on the system via `ps aux` or `/proc/*/cmdline`. Environment variables are only visible to the process owner and root.

### Plaintext HTTP with credentials
```bash
# VULNERABLE: credentials sent over cleartext HTTP
curl --user $USER:$PASS http://${HOST}:${PORT}/management/api
wget --http-user=$USER --http-password=$PASS http://...

# SAFE: use HTTPS with proper certificate
curl --cacert /path/to/ca.pem --user $USER:$PASS https://${HOST}:${SSL_PORT}/management/api
```

Sending credentials over HTTP exposes them to any network observer. This is common in provisioning scripts that target management APIs during initial deployment, before TLS is configured.

---

## General search strategy

### High-signal grep patterns for Azure ARM/Bicep
```
sourceAddressPrefix.*\*|sourceAddressPrefix.*Internet
defaultAction.*Allow
publicNetworkAccess.*Enabled
adminUserEnabled.*true
supportsHttpsTrafficOnly.*false
commandToExecute.*password|commandToExecute.*secret
scope.*subscription\(\)|scope.*managementGroup\(\)
trustPolicy.*disabled
enableSoftDelete.*false|enablePurgeProtection.*false
startIpAddress.*0\.0\.0\.0
httpsOnly.*false
remoteDebuggingEnabled.*true
```

### High-signal grep patterns for AWS CloudFormation
```
CidrIp.*0\.0\.0\.0/0|CidrIpv6.*::/0
Action.*['"]\*['"]|Resource.*['"]\*['"]
PubliclyAccessible.*true
StorageEncrypted.*false
IsLogging.*false
EnableLogFileValidation.*false
Protocol.*HTTP[^S]
MasterUserPassword
PublicAccessBlockConfiguration
UserData.*password|UserData.*secret
```

### High-signal grep patterns for GCP Terraform
```
source_ranges.*0\.0\.0\.0/0
allUsers|allAuthenticatedUsers
roles/(owner|editor)
enable_legacy_abac.*true
require_ssl.*false
authorized_networks.*0\.0\.0\.0
rotation_period
cloud-platform.*scopes
```

### High-signal grep patterns for OCI Terraform
```
source.*0\.0\.0\.0/0
access_type.*ObjectRead
manage all-resources
prohibit_public_ip_on_vnic.*false
vault_type.*DEFAULT
```

### High-signal grep patterns for shell provisioning
```
docker login.*-p\s
curl.*(--insecure|-k\s)
wget.*--no-check-certificate
chmod\s+777|dir_mode=0777|file_mode=0777
echo.*(password|secret|credential|key|token)=
(mysql|psql|curl --user).*-p['\"]
http://.*--user|http://.*-u\s
```

### Analysis approach
1. **Azure**: Check NSG rules for `*` source, storage accounts for network ACLs and HTTPS, ACR for public access and admin user, Key Vault for deletion protection, role assignments for scope.
2. **AWS**: Check security groups for 0.0.0.0/0, IAM for wildcard actions, S3 for public access blocks, RDS for public accessibility, CloudTrail for logging, ELB for HTTPS.
3. **GCP**: Check firewall rules for 0.0.0.0/0, IAM for primitive roles, GCS for allUsers, Cloud SQL for authorized networks, GKE for legacy features.
4. **OCI**: Check security lists and NSGs for 0.0.0.0/0, buckets for public access, IAM for broad policies, databases for NSG attachment and encryption.
5. **Shell**: Check for credentials on command line, disabled TLS, overpermissive file modes, secrets in log output.

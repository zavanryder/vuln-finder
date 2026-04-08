# Oracle Database Patterns

Patterns for PL/SQL injection, Oracle connection security, ORDS vulnerabilities, TDE/wallet misconfig, default credentials, and Oracle-specific dangerous APIs.

---

## Table of contents

1. [PL/SQL injection](#plsql-injection)
2. [Oracle connection security](#oracle-connection-security)
3. [Oracle REST Data Services (ORDS)](#oracle-rest-data-services-ords)
4. [TDE and wallet security](#tde-and-wallet-security)
5. [Default and weak credentials](#default-and-weak-credentials)
6. [Oracle-specific dangerous patterns](#oracle-specific-dangerous-patterns)
7. [Search strategy](#search-strategy)

---

## PL/SQL injection

Dynamic SQL constructed via string concatenation instead of bind variables.

### Dangerous sinks

| Sink | Risk |
|------|------|
| `EXECUTE IMMEDIATE expr \|\| var` | Direct SQL injection |
| `DBMS_SQL.PARSE` with concatenation | Direct SQL injection |
| `DBMS_UTILITY.EXEC_DDL_STATEMENT` | DDL injection |
| `DBMS_ASSERT` misuse | Quoting bypass if wrong assert function used |

```sql
-- VULNERABLE: concatenation
EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = ''' || p_name || '''';
DBMS_SQL.PARSE(l_cursor, 'DELETE FROM orders WHERE id = ' || p_id, DBMS_SQL.NATIVE);

-- SAFE: bind variables
EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name = :1' USING p_name;
```

### Second-order SQL injection

Data stored safely via bind variable, then retrieved and concatenated into dynamic SQL in a different procedure:

```sql
SELECT username INTO l_name FROM profiles WHERE id = :1;
EXECUTE IMMEDIATE 'BEGIN audit_pkg.log(''' || l_name || '''); END;';
```

---

## Oracle connection security

### Plaintext passwords in connection strings

| Language | Vulnerable pattern |
|----------|--------------------|
| Java/JDBC | `DriverManager.getConnection("jdbc:oracle:thin:@host:1521/svc", "sys", "password")` |
| Python/oracledb | `oracledb.connect(user="admin", password="secret", dsn="host/svc")` |
| Node/oracledb | `oracledb.getConnection({ user: "admin", password: "secret", connectString: "host/svc" })` |
| Go/godror | `sql.Open("godror", "admin/secret@host:1521/svc")` |
| Shell/sqlplus | `sqlplus sys/change_on_install@orcl as sysdba` |

### SYSDBA/SYSOPER abuse

Application code should never connect as `SYSDBA`/`SYSOPER`. Check for `AS SYSDBA` in scripts, `internal_logon="SYSDBA"` (Python), or `privilege: oracledb.SYSDBA` (Node).

### Database links with embedded credentials

```sql
CREATE DATABASE LINK remote_link CONNECT TO admin IDENTIFIED BY secret_password USING 'remote_db';
```

Credentials stored in `SYS.LINK$`, queryable by privileged users.

### Oracle Net Services misconfig

- **sqlnet.ora**: `SQLNET.ENCRYPTION_SERVER = ACCEPTED` or `REJECTED` instead of `REQUIRED`.
- **listener.ora**: `ADMIN_RESTRICTIONS_LISTENER = OFF` enables unauthenticated remote admin.
- **tnsnames.ora**: Plaintext credentials embedded in connect descriptors.

---

## Oracle REST Data Services (ORDS)

- **SQL injection**: ORDS handler SQL with inline parameter substitution instead of proper bind.
- **`/ords/sql` endpoint**: SQL worksheet enabled in production with over-privileged schema allows arbitrary SQL execution.
- **Access control bypass**: Missing `p_security_scheme` on `ORDS.DEFINE_MODULE` or missing role-based access on REST modules.
- **Cross-schema access**: `GET /ords/OTHER_SCHEMA/table_name` when ORDS lacks explicit schema whitelisting.

---

## TDE and wallet security

- **Wallet auto-login in production**: `cwallet.sso` allows any process with filesystem access to open the wallet without a password. Should not be used without strict filesystem restrictions.
- **Weak TDE master key passwords**: `ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "welcome1"` in setup scripts.
- **Cleartext wallet passwords in scripts**:
  ```bash
  mkstore -wrl /opt/oracle/wallet -createCredential mydb admin secret_password
  orapki wallet create -wallet /opt/oracle/wallet -pwd Welcome1 -auto_login
  ```

---

## Default and weak credentials

### Known Oracle default passwords

`sys/change_on_install`, `system/manager`, `scott/tiger`, `hr/hr`, `oe/oe`, `sh/sh`, `dbsnmp/dbsnmp`, `outln/outln`, `mdsys/mdsys`, `ctxsys/ctxsys`.

### Weak password patterns in setup scripts

Search for: `welcome1`, `oracle`, `Oracle123`, `test`, `changeme`, `password`, `admin`, `P@ssw0rd`, `manager` in `CREATE USER ... IDENTIFIED BY` and `ALTER USER ... IDENTIFIED BY` statements.

### Default listener passwords

`PASSWORDS_LISTENER = oracle` in `listener.ora`, or no password set at all.

---

## Oracle-specific dangerous patterns

### SSRF from PL/SQL

| Package | Capability | Risk |
|---------|-----------|------|
| `UTL_HTTP.REQUEST` | Outbound HTTP | SSRF to internal services |
| `UTL_TCP.OPEN_CONNECTION` | Raw TCP | Port scanning, data exfil |
| `UTL_SMTP.OPEN_CONNECTION` | SMTP | Spam relay, data exfil |
| `UTL_FILE.FOPEN` | Filesystem R/W | Arbitrary file access on DB server |
| `HTTPURITYPE().getclob()` | HTTP via URI type | SSRF variant |

### Privilege escalation

- **DBMS_SCHEDULER**: `CREATE_JOB` with `job_type => 'PLSQL_BLOCK'` can execute `GRANT DBA` if the scheduler owner is privileged.
- **ALTER SYSTEM**: `ALTER SYSTEM SET utl_file_dir='*'`, `ALTER SYSTEM SET remote_os_authent=TRUE`.
- **ALTER SESSION**: `ALTER SESSION SET CURRENT_SCHEMA = SYS` to access SYS objects.

### Java stored procedures with OS exec

```sql
CREATE OR REPLACE JAVA SOURCE NAMED "CmdExec" AS
import java.io.*;
public class CmdExec {
  public static String run(String cmd) throws Exception {
    return Runtime.getRuntime().exec(cmd).toString();
  }
};
```

---

## Search strategy

### High-signal grep patterns

```
EXECUTE\s+IMMEDIATE\s+.*\|\|
DBMS_SQL\.PARSE\s*\(.*\|\|
UTL_HTTP\.REQUEST|UTL_TCP\.OPEN|UTL_SMTP\.OPEN
UTL_FILE\.FOPEN
DBMS_SCHEDULER\.CREATE_JOB
CREATE\s+DATABASE\s+LINK.*IDENTIFIED\s+BY
AS\s+SYSDBA
SQLNET\.ENCRYPTION_SERVER\s*=\s*(ACCEPTED|REJECTED)
ALTER\s+SYSTEM\s+SET
cwallet\.sso
password.*=.*(welcome1|oracle|tiger|changeme|manager|change_on_install)
/ords/sql
IDENTIFIED\s+BY\s+["']?\w+["']?
```

### Analysis approach

1. **PL/SQL source**: Search `.sql`, `.pks`, `.pkb`, `.prc`, `.fnc` for `EXECUTE IMMEDIATE` and `DBMS_SQL` with `||`.
2. **Connection code**: Search `.java`, `.py`, `.js`, `.go`, `.sh` for connection strings with inline passwords.
3. **Config files**: Search `sqlnet.ora`, `listener.ora`, `tnsnames.ora`, `wallet/` for weak encryption and embedded credentials.
4. **ORDS config**: Search for ORDS module definitions lacking access control and `/ords/sql` enablement.
5. **Setup scripts**: Search `.sql` and `.sh` for `CREATE USER ... IDENTIFIED BY`, default passwords.

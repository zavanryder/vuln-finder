#!/usr/bin/env bash
# First-pass candidate search for dangerous patterns in a codebase.
# Usage: ./scripts/grep-patterns.sh [directory] [language] [class]
#   directory: path to scan (default: current dir)
#   language:  optional filter - py, php, rb, js, ts, java, go, cs, kt, c, cpp, sh, yml (omit for all)
#   class:     optional bug-class filter - injection, access, memory, cicd, secrets, crypto, ssrf, upload (omit for all)
# Output is candidate lines; confirm each in context before reporting.

ROOT="${1:-.}"
LANG="${2:-}"
CLASS="${3:-}"

# Prefer rg (ripgrep) when available; fall back to grep.
if command -v rg &>/dev/null; then
  SEARCHER="rg"
else
  SEARCHER="grep"
fi

include_args() {
  if [[ "$SEARCHER" == "rg" ]]; then
    case "$LANG" in
      py|python)     echo "--type py" ;;
      php)           echo "--glob '*.php'" ;;
      rb|ruby)       echo "--type ruby" ;;
      js|javascript) echo "--glob '*.{js,mjs,cjs}'" ;;
      ts|typescript) echo "--glob '*.{ts,tsx}'" ;;
      java)          echo "--type java" ;;
      go|golang)     echo "--type go" ;;
      cs|csharp)     echo "--glob '*.cs'" ;;
      kt|kotlin)     echo "--glob '*.{kt,kts}'" ;;
      c)             echo "--glob '*.{c,h}'" ;;
      cpp|c++)       echo "--glob '*.{cpp,cc,cxx,hpp,hxx,h}'" ;;
      sh|shell|bash) echo "--type sh" ;;
      yml|yaml|actions) echo "--glob '*.{yml,yaml}'" ;;
      *)             echo "" ;;
    esac
  else
    case "$LANG" in
      py|python)     echo "--include=*.py" ;;
      php)           echo "--include=*.php" ;;
      rb|ruby)       echo "--include=*.rb" ;;
      js|javascript) echo "--include=*.js --include=*.mjs --include=*.cjs" ;;
      ts|typescript) echo "--include=*.ts --include=*.tsx" ;;
      java)          echo "--include=*.java" ;;
      go|golang)     echo "--include=*.go" ;;
      cs|csharp)     echo "--include=*.cs" ;;
      kt|kotlin)     echo "--include=*.kt --include=*.kts" ;;
      c)             echo "--include=*.c --include=*.h" ;;
      cpp|c++)       echo "--include=*.cpp --include=*.cc --include=*.hpp --include=*.h" ;;
      sh|shell|bash) echo "--include=*.sh --include=*.bash" ;;
      yml|yaml|actions) echo "--include=*.yml --include=*.yaml" ;;
      *)             echo "--include=*.py --include=*.php --include=*.rb --include=*.js --include=*.mjs --include=*.ts --include=*.tsx --include=*.java --include=*.go --include=*.cs --include=*.kt --include=*.c --include=*.cpp --include=*.h --include=*.sh --include=*.yml --include=*.yaml" ;;
    esac
  fi
}

INCLUDES=$(include_args)

run() {
  if [[ "$SEARCHER" == "rg" ]]; then
    eval rg -n "$INCLUDES" -- "'$1'" "$ROOT" 2>/dev/null || true
  else
    eval grep -rn -E "$INCLUDES" "'$1'" "$ROOT" 2>/dev/null || true
  fi
}

should_run() {
  [[ -z "$CLASS" ]] || [[ "$CLASS" == "$1" ]]
}

echo "Candidate lines (confirm in context before reporting):"
echo "=== Scan: dir=$ROOT lang=${LANG:-all} class=${CLASS:-all} searcher=$SEARCHER ==="
echo ""

# --- Injection / deserialization / code execution ---
if should_run "injection"; then
  echo "--- Deserialization / unsafe load ---"
  run 'pickle\.loads|yaml\.load\s*\(|marshal\.loads|unserialize\s*\('
  run 'YAML\.load\s*\(|YAML\.unsafe_load|Marshal\.load\s*\(|Marshal\.restore'
  run 'ObjectInputStream|readObject\s*\(|BinaryFormatter|\.Deserialize\s*\('
  run 'XStream\.fromXML|XMLDecoder|NetDataContractSerializer'
  run 'node-serialize|js-yaml\.load'

  echo "--- Command / shell injection ---"
  run 'os\.system|subprocess\.(call|run|Popen).*shell\s*=\s*True'
  run 'exec\s*\(|shell_exec|system\s*\(|passthru|child_process\.(exec|execSync)'
  run 'Open3\.(capture2|popen3)|IO\.popen\s*\('
  run 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\.Command|Process\.Start'

  echo "--- Code injection ---"
  run 'eval\s*\(|new Function\s*\(|vm\.runIn|setTimeout\s*\(\s*["\x27]'
  run 'instance_eval|class_eval|send\s*\(|public_send'
  run 'ScriptEngine\.eval|CSharpCodeProvider'

  echo "--- SQL / query injection ---"
  run 'execute\s*\(.*%|\.format\s*\(.*request|Statement\.execute|executeQuery\s*\(.*\+'
  run 'mysqli_query|mysql_query|PDO::query|CommandText\s*=\s*.*\+|FromSqlRaw'
  run 'find_by_sql\s*\(|\.where\s*\(.*#\{|execute\s*\(.*#\{'
  run 'knex\.raw|\.query\s*\(.*\$\{|db\.Exec.*Sprintf|db\.Query.*Sprintf'

  echo "--- NoSQL injection ---"
  run '\$where|\$regex|\$gt|\$ne.*req\.(body|query|params)'

  echo "--- XXE ---"
  run 'DocumentBuilderFactory|SAXParser|XMLReader|simplexml_load|DOMDocument::loadXML'
  run 'XMLInputFactory|XmlDocument\.Load|Nokogiri::XML|REXML::Document'

  echo "--- SSTI ---"
  run 'Template\s*\(.*\)\.render|render_template_string|ERB\.new.*\.result'
  run 'Freemarker|Velocity|render inline:'

  echo "--- LDAP injection ---"
  run 'ldap_search|LdapTemplate\.search|DirectorySearcher|Net::LDAP'
fi

# --- Prototype pollution (JS/TS) ---
if should_run "injection"; then
  echo "--- Prototype pollution ---"
  run '__proto__|constructor\.prototype|merge\s*\(.*req\.|extend\s*\(.*req\.'
  run 'Object\.assign\s*\(.*req\.|deepmerge|deep-extend|defaultsDeep'
  run 'lodash\.merge|_\.merge|_\.defaultsDeep|_\.set'
fi

# --- Access control ---
if should_run "access"; then
  echo "--- Missing auth middleware ---"
  run 'skip_before_action.*authenticate|AllowAnonymous|csrf_exempt|csrf\.disable'
  run 'permitAll|@Public|CORS_ALLOW_ALL_ORIGINS'
  run 'verify_authenticity_token.*:null_session|IgnoreAntiforgeryToken'

  echo "--- IDOR / direct object access ---"
  run 'findById\s*\(.*params|find_by_sql.*params|Model\.find\s*\(.*params'
  run 'get_object_or_404\s*\(|objects\.(get|filter)\s*\(.*pk='

  echo "--- JWT / session ---"
  run 'jwt\.decode|jwt\.verify|jsonwebtoken|alg.*none|algorithms.*\[\]'
  run 'JwtParser|JwtDecoder|JWT\.decode'

  echo "--- CSRF indicators ---"
  run 'csrf_exempt|skip.*verify_authenticity|csurf|csrf\.disable'

  echo "--- CORS ---"
  run 'Access-Control-Allow-Origin|cors\s*\(|@CrossOrigin|rack-cors'
fi

# --- SSRF / redirect ---
if should_run "ssrf"; then
  echo "--- SSRF / open redirect ---"
  run 'fetch\s*\(|axios\.(get|post)\s*\(|http\.Get\s*\(|urlopen\s*\('
  run 'URI\.open\s*\(|Net::HTTP\.get\s*\(|RestClient\.get|HTTParty\.get'
  run 'redirect\s*\(.*req\.|redirect_to\s*.*params|sendRedirect\s*\(.*request'
  run 'window\.location\s*=|\.redirect\s*\(.*(query|body|params)'
fi

# --- Path / file ---
if should_run "injection"; then
  echo "--- Path traversal / file access ---"
  run 'open\s*\(.*request|readFile\s*\(.*req|os\.Open\s*\(|File\.Open\s*\('
  run 'File\.(read|open)\s*\(.*params|send_file\s*\(.*params|Pathname\.new\s*\(.*params'
  run 'ZipEntry\.getName|zipfile\.extractall|tarfile\.extractall|adm-zip|unzipper'
fi

# --- XSS / output ---
if should_run "injection"; then
  echo "--- XSS ---"
  run 'innerHTML\s*=|document\.write|dangerouslySetInnerHTML'
  run 'html_safe|\.raw\s*\(|v-html|th:utext|\{!!.*!!\}'
fi

# --- Secrets / crypto ---
if should_run "secrets"; then
  echo "--- Hardcoded secrets ---"
  run 'password\s*=\s*["\x27]|api_key\s*=\s*["\x27]|secret\s*=\s*["\x27]|token\s*=\s*["\x27]'
  run 'SECRET_KEY\s*=|SecretKeySpec|PRIVATE.KEY'
  run 'AWS_ACCESS_KEY|GITHUB_TOKEN|SLACK_TOKEN|DATABASE_URL.*password'
fi

if should_run "crypto"; then
  echo "--- Weak crypto ---"
  run 'Math\.random|random\.random|rand\(\)|mt_rand|math/rand'
  run 'MD5|SHA1|DES|RC4|ECB|createHash.*md5'
fi

# --- File upload ---
if should_run "upload"; then
  echo "--- Insecure file upload ---"
  run 'multer\s*\(|move_uploaded_file|FileUpload|IFormFile|originalname'
  run 'content_type.*octet|\.save\s*\(.*filename'
fi

# --- Memory safety (C/C++) ---
if should_run "memory"; then
  echo "--- Buffer overflow / unsafe functions ---"
  run 'strcpy\s*\(|strcat\s*\(|sprintf\s*\(|gets\s*\(|scanf.*%s'
  run 'memcpy\s*\(|memmove\s*\(|memset\s*\('

  echo "--- Use-after-free / double free ---"
  run 'free\s*\(|delete\s+|delete\[\]'

  echo "--- Format string ---"
  run 'printf\s*\([^"]*\buser\b|printf\s*\(\s*[a-zA-Z_]|syslog\s*\([^,]*,[^"]*\buser'

  echo "--- Integer overflow ---"
  run 'malloc\s*\(.*\*|calloc\s*\(|alloca\s*\('
fi

# --- CI/CD / GitHub Actions ---
if should_run "cicd"; then
  echo "--- GitHub Actions injection ---"
  run 'github\.event\.pull_request\.(title|body)|github\.event\.issue\.(title|body)'
  run 'github\.event\.comment\.body|github\.head_ref|github\.event\.head_commit\.message'
  run 'pull_request_target'

  echo "--- Actions permissions ---"
  run 'permissions:\s*write-all|permissions:\s*\{\}'

  echo "--- Unpinned actions ---"
  run 'uses:.*@(main|master|v[0-9]+)\s*$'

  echo "--- Artifact handling ---"
  run 'download-artifact|upload-artifact'

  echo "--- Secrets in logs ---"
  run 'echo.*\$\{\{\s*secrets\.'
fi

# --- Resource exhaustion ---
if should_run "injection"; then
  echo "--- Resource exhaustion indicators ---"
  run 'findAll\s*\(|\.all\s*$|objects\.all|find\s*\(\s*\{\s*\}'
  run 'MAX_CONTENT_LENGTH|max-file-size|fileSize|MAX_UPLOAD'
fi

echo ""
echo "=== Scan complete ==="

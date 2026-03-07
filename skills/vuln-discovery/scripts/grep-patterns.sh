#!/usr/bin/env bash
# Optional first-pass grep for common dangerous patterns in a codebase.
# Usage: ./scripts/grep-patterns.sh [directory] [language]
#   directory: path to scan (default: current dir)
#   language: optional filter - py, php, rb, js, ts, java, go, cs (omit for all)
# Output is candidate lines; confirm each in context (data flow, sanitization) before reporting.

ROOT="${1:-.}"
LANG="${2:-}"

include_args() {
  if [[ -z "$LANG" ]]; then
    echo "--include=*.py --include=*.php --include=*.rb --include=*.js --include=*.mjs --include=*.cjs --include=*.ts --include=*.tsx --include=*.java --include=*.go --include=*.cs"
  else
    case "$LANG" in
      py|python)   echo "--include=*.py" ;;
      php)         echo "--include=*.php" ;;
      rb|ruby)     echo "--include=*.rb" ;;
      js|javascript) echo "--include=*.js --include=*.mjs --include=*.cjs" ;;
      ts|typescript)  echo "--include=*.ts --include=*.tsx" ;;
      java)        echo "--include=*.java" ;;
      go|golang)   echo "--include=*.go" ;;
      cs|csharp|dotnet) echo "--include=*.cs" ;;
      *)           echo "--include=*.py --include=*.php --include=*.rb --include=*.js --include=*.ts --include=*.java --include=*.go --include=*.cs" ;;
    esac
  fi
}

INCLUDES=$(include_args)

run() {
  grep -rn -E "$1" $INCLUDES "$ROOT" 2>/dev/null || true
}

echo "Candidate lines (confirm in context before reporting):"
echo "---"

# Deserialization / code execution
run 'pickle\.loads|yaml\.load\s*\(|marshal\.loads|unserialize\s*\('
run 'YAML\.load\s*\(|Marshal\.load\s*\(|Marshal\.restore\s*\(|ERB\.new\s*\(.*\.result'
run 'eval\s*\(|exec\s*\(|ObjectInputStream|readObject\s*\(|BinaryFormatter|\.Deserialize\s*\('

# Command / shell
run 'os\.system|subprocess\.(call|run|Popen).*shell\s*=\s*True'
run 'exec\s*\(|shell_exec|system\s*\(|passthru|child_process\.(exec|execSync)'
run 'system\s*\(|Open3\.(capture2|popen3)|IO\.popen\s*\('
run 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\.Command|Process\.Start'

# SQL / query
run 'execute\s*\(.*%|\.format\s*\(.*request|Statement\.execute|executeQuery\s*\(.*\+'
run 'mysqli_query|mysql_query|PDO::query|CommandText\s*=\s*.*\+|FromSqlRaw'
run 'find_by_sql\s*\(|\.where\s*\(.*#\{|execute\s*\(.*#\{'

# Prototype pollution / merge (JS/TS)
run '__proto__|constructor\.prototype|merge\s*\(|extend\s*\(.*req\.|Object\.assign\s*\(.*req\.'

# SSRF / redirect
run 'fetch\s*\(|axios\.(get|post)\s*\(|http\.Get\s*\(|urlopen\s*\(|redirect\s*\('
run 'open\s*\(\s*[a-zA-Z_].*uri|URI\.open\s*\(|Net::HTTP\.get\s*\(|redirect_to\s*.*params'
run '\.redirect\s*\(.*(query|body|params)|window\.location\s*='

# Path / file
run 'open\s*\(.*request|readFile\s*\(.*req|os\.Open\s*\(|File\.Open\s*\(|new File\s*\('
run 'File\.(read|open)\s*\(.*params|send_file\s*\(.*params|Pathname\.new\s*\(.*params'

# XSS / output
run 'innerHTML\s*=|document\.write|dangerouslySetInnerHTML'

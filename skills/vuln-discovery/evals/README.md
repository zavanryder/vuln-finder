# Evaluation Corpus

Regression fixtures for the vuln-discovery skill. Each fixture is a small, self-contained code file that either **contains a known vulnerability** or is **intentionally safe**.

## Structure

```
evals/
├── README.md              # this file
├── expected.json          # manifest of all fixtures and expected findings
├── fixtures/              # code files organized by language
│   ├── python/
│   ├── javascript/
│   ├── java/
│   ├── go/
│   ├── c/
│   └── github-actions/
└── chains/                # multi-file fixtures for exploit-chain testing
```

## Running evals

Point the skill at a fixture file or directory and compare the output against `expected.json`.

```
# Single fixture
"Find all vulnerabilities in evals/fixtures/python/sqli_vulnerable.py"

# Language batch
"Scan evals/fixtures/javascript/ for ALL bug types"

# Chain fixture
"Scan evals/chains/ssrf-to-rce/ for ALL bug types"
```

## Expected results format

Each entry in `expected.json` specifies:
- `file`: path to fixture relative to `evals/`
- `language`: target language
- `is_vulnerable`: true if findings are expected, false if the file is intentionally safe
- `expected_findings`: array of expected bug-class IDs and minimum severity
- `acceptable_misses`: findings that are hard to detect statically (not counted as failures)
- `false_positive_trap`: if true, the file looks suspicious but is actually safe -- any finding is a false positive

## Adding fixtures

1. Write a small, focused code file (one vulnerability per file for isolated tests, or combine for chain tests).
2. Add an entry to `expected.json`.
3. Verify by running the skill against the fixture.

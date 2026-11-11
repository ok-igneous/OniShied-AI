# Repository Governance and GitHub Settings

## Repository model

- The repository is currently public by an explicit owner decision to keep development moving while GitHub Actions billing access is blocked. This is a temporary exposure decision, not a security recommendation. Reassess visibility before adding proprietary detection logic, customer data, deployment configuration, or integrations.
- Use `main` as the protected integration branch and short-lived feature branches for work.
- Contributors should open pull requests; no direct pushes by contributors.
- Keep the owner account as administrator. Give contributors the minimum repository role needed.
- Never store customer telemetry, production exports, API keys, credentials, private keys, or database dumps in Git.

## Pull request expectations

Every pull request must:
- Describe the change, risk, test evidence, and migration impact.
- Pass the CI checks before merge.
- Include tests for denied as well as allowed security-sensitive behavior.
- Stay within the 500-line source-file ceiling.
- Receive review from the code owner for security, identity, authorization, database, tenant isolation, and response-execution changes.

`.github/CODEOWNERS` identifies the repository owner. CODEOWNERS does not itself enforce review; GitHub branch protection or repository rules must be enabled separately.

## GitHub Actions

The CI workflow is in `.github/workflows/ci.yml`. It checks source-file size, schema tests, TypeScript type checking, and build output.

If a run shows `startup_failure` with zero jobs, the workflow has not reached its first step. Check repository Settings → Actions → General:
1. Confirm Actions are enabled for the repository.
2. Confirm the selected policy permits the required GitHub-hosted runners and the `actions/checkout` and `actions/setup-node` actions.
3. Confirm there are no organization or account policies blocking workflow execution.
4. Re-run the workflow after correcting the setting.

## Branch protection limitation

Before the repository was made public, `main` was checked and reported `protected: false`; the connected integration could not read or change branch protection. Branch protection must be rechecked in the current public-repository state. Do not assume it is active.

Do not assume branch protection is active. In GitHub repository Settings → Branches, check whether classic branch protection is available for this plan. If available, protect `main` with:
- Require a pull request before merging.
- Require one approval when there is another qualified reviewer.
- Require the CI validation check.
- Require conversation resolution.
- Restrict force pushes and branch deletion.

If the plan does not support protection for this private repository, use the documented manual rule: contributors work only on branches and the owner merges reviewed changes. Upgrade or make the repository public only after consciously evaluating cost and source-code disclosure risk.

## Public repository precautions

Because this repository is currently public:
- Commit only synthetic fixtures and clearly fake example values.
- Never commit customer telemetry, production exports, API keys, credentials, private keys, database dumps, internal incident reports, or sensitive architecture details.
- Review the full commit history before assuming a deleted secret is no longer exposed. If a real secret was committed, revoke/rotate it immediately; deleting the file or rewriting Git history does not invalidate the credential.
- Verify secret-scanning availability and alert status in repository Settings → Security. Do not assume scanning is active.
- Consider returning the repository to private once the account-level Actions restriction is resolved, unless public development is an intentional product strategy.

## Current automation gaps

- A committed npm lockfile is still required for reproducible installs and dependable dependency auditing. The current execution environment could not reach the npm registry to generate one.
- Dependabot update configuration is present, but its first update PRs have not yet been observed.
- Secret scanning and CodeQL status must be verified in GitHub repository Security settings; do not assume either is enabled.

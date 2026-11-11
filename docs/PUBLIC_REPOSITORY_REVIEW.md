# Public Repository Exposure Review

**Review date:** 2026-11-11  
**Repository:** `ok-igneous/OniShied-AI`  
**Visibility at review:** Public  
**Review status:** Partial; not a certified secret scan

## Why this review exists

The repository was made public to keep development moving while the owner's GitHub account is blocked from starting Actions jobs by an account-level billing lock. Public visibility does not remove that billing restriction.

## Checks completed

- Confirmed through GitHub repository metadata that the repository is public.
- Inspected the current `.env.example`; it contains blank secret fields and explicit instructions to use local credentials. No usable API key, database password, or connector token was present in the inspected current file.
- Inspected the current PostgreSQL bootstrap script; it accepts passwords through psql variables and does not embed credentials.
- Inspected the current application configuration; credentials are read from environment variables.
- Inspected the initial commit tree; it contained only a minimal README.
- Inspected the historical commit that removed `scripts/dev-db.sql`. That removed file contained the literal placeholder password `replace-this-local-password`, not a real credential. The file is absent from the current tree, but the historical commit remains visible.

## What has not been established

- This was not a complete content scan of every blob in every historical commit.
- GitHub secret-scanning alerts could not be independently verified through the available repository integration.
- No dedicated Gitleaks or TruffleHog scan has completed.
- Therefore, this review does **not** certify that the entire Git history is free of secrets.

## Required owner actions

1. Open repository **Settings → Security** and inspect secret-scanning settings and alerts, if available.
2. Review the full commit history with a dedicated secret scanner when a trusted environment is available.
3. If any real credential is found, revoke or rotate it immediately. Do not rely on deleting the file or rewriting history as a substitute for rotation.
4. Keep all real credentials, customer data, security telemetry, database exports, and incident records out of this public repository.
5. Reassess public visibility before proprietary detection logic, production integrations, or customer-facing deployment configuration is committed.

## Decision

Continue using synthetic data only. Treat the repository as publicly disclosed. Do not add secrets or customer data. This partial review is a risk-control record, not a claim that the repository is fully clean.

# Azure Deployment Update Runbook

Date: 2026-06-01

Purpose: define the production update path for this rebuild after explicit deployment approval.

No command in this runbook was executed during the rebuild implementation.

## Preconditions

- Explicit approval to deploy has been given in the active thread or release change.
- Current branch is reviewed and ready.
- Working tree is clean except approved release artifacts.
- `PATCHFORGE_AUTH_REQUIRED=true` remains configured for production.
- No real secrets are pasted into terminal commands or evidence files.
- Synthetic validation data has agreed cleanup steps.
- Azure context targets tenant `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`, subscription `9ae9da49-de67-443b-af55-ce9db33ed8f4`, region `uksouth`, and resource group `rg-diiac-patchforge-prod`.

## Build And Test Gate

Run and capture output:

```powershell
npm test
```

from `backend-api`.

```powershell
npm test
```

from `Frontend`.

```powershell
npm run build
```

from `Frontend`.

```powershell
python -m pytest tests\test_contracts.py
```

from the repo root.

```powershell
python -m pytest runtime\tests
```

from the repo root.

## Azure Plan Gate

Run IaC validation and a what-if plan before any image or revision update:

```powershell
.\scripts\validate_iac.ps1
```

```powershell
.\scripts\plan_azure_deployment.ps1
```

Capture the plan output under a deploy-approved evidence folder. Stop if the plan includes unexpected destructive changes, public exposure changes, identity changes, Key Vault access changes, or database replacement.

## Image Build And Push

Use the existing image build/push script with a unique rebuild tag after approval. The prior live image tag documented in PF0 was `pfaz10-20260530-e728ec0`; do not overwrite it.

Record:

- ACR login target.
- Image tag.
- Image digests for frontend, bridge/API, runtime, SRA, worker, and scheduler.
- Build logs with secrets redacted.

## Container Apps Update

Update only the intended Container Apps:

- `ca-patchforge-ui-prod`
- `ca-patchforge-bridge-prod`
- `ca-patchforge-runtime-prod`
- `ca-patchforge-sra-prod`
- `ca-patchforge-worker-prod`
- `ca-patchforge-scheduler-prod`

Record before and after active revisions. Keep previous active revisions available for rollback until post-deploy validation is complete.

## Post-Deploy Smoke

Capture:

- `https://patchforge.diiac.io/` returns HTTP 200.
- `https://api.patchforge.diiac.io/health` returns HTTP 200.
- `https://api.patchforge.diiac.io/readiness` returns HTTP 200 and reports production storage/auth readiness.
- Protected API routes reject unauthenticated requests.
- Signed-in browser validation passes the checklist in `LIVE_UI_VALIDATION_RUNBOOK.md`.

## Rollback

If a blocking defect is found:

- Stop validation writes.
- Re-activate the previous healthy Container Apps revisions recorded in pre-update evidence.
- Re-run health/readiness and signed-in smoke.
- Record rollback evidence and the reason.

Do not delete the restore tag or pre-update evidence.

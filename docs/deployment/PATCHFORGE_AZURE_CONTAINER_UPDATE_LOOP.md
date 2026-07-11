# PatchForge Azure Container Update Loop

Date: 2026-06-22

Status: promoted operating guidance after human approval in the active 2026-06-22 repo session.

## Purpose

Use this loop when PatchForge needs an Azure Container Apps image update and the existing validation, deployment, and release-evidence loops need to be composed for a specific image-update pass.

The loop verifies ARM/Bicep accuracy, versions the intended container image set, catalogues image tags, digests, active revisions, and script/template inputs, and records the change evidence. It does not authorize Azure mutation, ACR pruning, production data mutation, or release approval.

## Existing Loops To Reuse

| Need | Existing source | Reuse rule |
| --- | --- | --- |
| Local validation and IaC build | `docs/validation/PATCHFORGE_VALIDATION_PLAN.md`, `scripts/validate_iac.ps1` | Run before any approved image promotion or deployment. |
| Customer-production readiness boundary | `docs/validation/PATCHFORGE_VALIDATION_PLAN.md`, `docs/validation/PATCHFORGE_READINESS_SUMMARY.md`, `CURRENT_RELEASE.md`, `QUALITY_GATES_REPORT.json`, `PATCHFORGE_OPEN_GAPS_REGISTER.md` | Use current readiness registers before any customer delivery or production-readiness claim. |
| Azure access and what-if | `docs/deployment/PATCHFORGE_AZURE_ACCESS_CHECKLIST.md`, `scripts/plan_azure_deployment.ps1` | What-if/read-only planning only unless a separate deployment approval exists. |
| Current deployment boundary | `docs/deployment/PATCHFORGE_DEPLOYMENT_READINESS.md`, `docs/deployment/PATCHFORGE_ROLLOUT_PLAN.md` | Preserve the explicit approval boundary for Container Apps revisions, Key Vault, DNS, identities, and production data. |
| Image build and push plan | `scripts/build_push_images.ps1` | Dry-run by default. Use `-Execute` only after explicit approval. |
| Prior Azure update evidence | `docs/release/evidence/2026-06-01-patchforge-rebuild/AZURE_DEPLOYMENT_UPDATE_RUNBOOK.md` | Reuse its digest, active-revision, smoke, and rollback evidence pattern. |
| Release version catalog | `CURRENT_RELEASE.md`, `QUALITY_GATES_REPORT.json`, `docs/release/*_RELEASE_BASELINE_MANIFEST.json` | Do not contradict current status registers without new evidence. |

## Authority Boundary

Allowed without a fresh deployment approval:

- inspect repo scripts, Bicep, parameters, Dockerfiles, and release docs
- run local tests, local Docker builds, `az bicep build`, `scripts/validate_iac.ps1`, and Azure what-if/read-only inspection
- create a draft evidence folder and draft release manifest
- record Docker Desktop and local build readiness evidence

Requires explicit human approval:

- `scripts/build_push_images.ps1 -Execute`
- `az acr login` followed by push operations
- any ACR retention or prune operation
- `az containerapp update`, `az deployment sub create`, or any Container Apps revision change
- Key Vault, DNS, identity, role assignment, database, or production data mutation
- promotion of future loop revisions into the operating catalog
- release, production readiness, customer acceptance, or CAB/risk-acceptance decisions

## Loop Version Record

| Loop version | Date | Change | Verification |
| --- | --- | --- | --- |
| 1.0 | 2026-06-22 | First promoted PatchForge Azure Container Apps image-update loop. Composes existing IaC validation, Docker Desktop prestage, ACR digest cataloguing, Container Apps revision evidence, live smoke, rollback, and release documentation boundaries. | `scripts/plan_azure_deployment.ps1` preview with and without image overrides; `scripts/validate_iac.ps1`; `git diff --check`. |

## Inputs To Freeze

Before running mutable steps, name these values in the evidence folder:

- branch and commit SHA
- working-tree status and any unrelated dirty files
- release or baseline ID
- intended image tag, preferably `<baseline>-<yyyymmdd>-<shortsha>`
- target registry, tenant, subscription, region, and resource group
- full six-image set:
  - `diiac/patchforge-frontend`
  - `diiac/patchforge-bridge`
  - `diiac/patchforge-runtime`
  - `diiac/patchforge-sra-agent`
  - `diiac/patchforge-ingest-worker`
  - `diiac/patchforge-scheduler`
- rollback tag or previous active revisions for every Container App

Stop if the tag is reused, the branch/commit is ambiguous, the worktree has unrelated changes that make release attribution unclear, or fewer than all six images are in scope without an approved partial-update rationale.

## Evidence And Version Catalog

Create a dated evidence folder before push or deploy approval is requested:

```powershell
$Stamp = Get-Date -Format "yyyy-MM-dd"
$Evidence = "docs/release/evidence/$Stamp-azure-container-update-<baseline>"
New-Item -ItemType Directory -Force $Evidence, "$Evidence/build-push", "$Evidence/deploy-plan", "$Evidence/deploy-apply", "$Evidence/live-smoke" | Out-Null
git status --short | Out-File "$Evidence/git-status-before.txt" -Encoding utf8
git rev-parse --abbrev-ref HEAD | Out-File "$Evidence/git-branch.txt" -Encoding utf8
git rev-parse HEAD | Out-File "$Evidence/git-commit.txt" -Encoding utf8
Get-FileHash scripts/validate_iac.ps1, scripts/build_push_images.ps1, scripts/plan_azure_deployment.ps1, scripts/deploy_azure_bootstrap.ps1, infra/bicep/main.bicep, infra/bicep/container-apps.bicep, infra/parameters/prod.bicepparam -Algorithm SHA256 |
  ConvertTo-Json -Depth 4 |
  Out-File "$Evidence/script-template-hashes.json" -Encoding utf8
```

Record a draft manifest with at least these fields:

```json
{
  "product": "DIIaC PatchForge",
  "baseline_id": "<baseline>",
  "baseline_date": "YYYY-MM-DD",
  "commit": "<full-sha>",
  "image_tag": "<tag>",
  "target_registry": "acrdiiacpatchforgeprod.azurecr.io",
  "target_resource_group": "rg-diiac-patchforge-prod",
  "iac_validation": "pending",
  "what_if": "pending",
  "docker_prestage": "pending",
  "acr_digests": [],
  "active_revisions_before": {},
  "active_revisions_after": {},
  "live_smoke": "pending",
  "approval_state": "draft_not_approved"
}
```

## IaC Accuracy Gate

Run the non-mutating checks first:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
az bicep build --file infra/bicep/main.bicep
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/plan_azure_deployment.ps1 `
  -SubscriptionId 9ae9da49-de67-443b-af55-ce9db33ed8f4 `
  -TenantId 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da `
  -ImageTag <tag> `
  -AcrSku Basic `
  -RunWhatIf
```

Review `infra/bicep/container-apps.bicep` and confirm the intended image behavior:

- a full Bicep-driven image update uses the `imageTag` parameter for all six Container Apps
- `scripts/plan_azure_deployment.ps1` is run with the intended `-ImageTag`, because `infra/parameters/prod.bicepparam` keeps the bootstrap default
- the expected ACR login server is passed from the registry module
- `PATCHFORGE_AUTH_REQUIRED` remains true for production unless a separate approved security change exists
- `PATCHFORGE_BOUNDARY` remains governance-only
- custom-domain, Key Vault, identity, storage, and database changes are expected and approved, or absent

Stop if what-if shows unexpected destructive changes, identity drift, Key Vault access changes, DNS/custom-domain changes, database replacement, public exposure changes, or broad infrastructure drift unrelated to the image update. If what-if is too broad for an image-only update, keep the Bicep evidence and request approval for a targeted Container Apps image update instead.

## Docker Desktop Prestage Gate

Use Docker Desktop for local prestage only after local validation is green.

```powershell
docker version
docker info
docker context ls
docker buildx ls
docker system df
docker buildx du
```

Prestage rules:

- use the default Linux Docker Desktop context unless the evidence names another context
- keep enough local disk free for six image builds and build cache
- close unrelated local containers before timing or resource-sensitive builds
- do not run `docker system prune`, `docker builder prune`, or delete local images unless the local cleanup is explicitly approved
- capture Docker version, context, disk usage, and buildx state in the evidence folder

Local smoke builds:

```powershell
docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:ci Frontend
docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:ci backend-api
docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:ci .
```

Dry-run the full push plan:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_push_images.ps1 `
  -RegistryName acrdiiacpatchforgeprod `
  -ImageTag <tag>
```

Stop if Docker Desktop is unavailable, local builds fail, the push plan omits any of the six required images, or the target tag does not match the frozen evidence manifest.

## Approved Build And Push Gate

Only after explicit approval:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_push_images.ps1 `
  -RegistryName acrdiiacpatchforgeprod `
  -ImageTag <tag> `
  -Execute *>&1 | Tee-Object "$Evidence/build-push/build-push-images.log"
```

Catalogue ACR manifest metadata after push:

```powershell
$RegistryName = "acrdiiacpatchforgeprod"
$Repos = @(
  "diiac/patchforge-frontend",
  "diiac/patchforge-bridge",
  "diiac/patchforge-runtime",
  "diiac/patchforge-sra-agent",
  "diiac/patchforge-ingest-worker",
  "diiac/patchforge-scheduler"
)

foreach ($Repo in $Repos) {
  $SafeRepo = $Repo.Replace("/", "-")
  az acr manifest list-metadata -r $RegistryName -n $Repo --orderby time_desc -o json |
    Out-File "$Evidence/build-push/$SafeRepo-manifests.json" -Encoding utf8
}
```

`az acr manifest` is a preview Azure CLI command in the installed CLI. If it is unavailable in the release environment, capture the push log digest lines and `az acr repository show-tags -n $RegistryName --repository <repo> --detail -o json` output for every repository instead, then record the limitation in the evidence README.

The release catalogue is incomplete until each repository has the intended tag and a digest recorded. Stop if any pushed image lacks the expected tag, any digest is missing, or ACR storage pressure would require retention changes without approval.

## Approved Container Apps Update Gate

Before any approved update, capture active revisions and image values:

```powershell
$ResourceGroup = "rg-diiac-patchforge-prod"
$Apps = @(
  "ca-patchforge-ui-prod",
  "ca-patchforge-bridge-prod",
  "ca-patchforge-runtime-prod",
  "ca-patchforge-sra-prod",
  "ca-patchforge-worker-prod",
  "ca-patchforge-scheduler-prod"
)

foreach ($App in $Apps) {
  az containerapp show -g $ResourceGroup -n $App -o json |
    Out-File "$Evidence/deploy-apply/$App-before.json" -Encoding utf8
  az containerapp revision list -g $ResourceGroup -n $App --all -o json |
    Out-File "$Evidence/deploy-apply/$App-revisions-before.json" -Encoding utf8
}
```

For a full image update, update all six apps to the matching repository and tag. Record the command set in the evidence before running it. A partial update must state the approved reason and rollback path.

Approved full-update command template:

```powershell
$ImageTag = "<tag>"
$Registry = "acrdiiacpatchforgeprod.azurecr.io"
az containerapp update -g $ResourceGroup -n ca-patchforge-ui-prod --image "$Registry/diiac/patchforge-frontend:$ImageTag"
az containerapp update -g $ResourceGroup -n ca-patchforge-bridge-prod --image "$Registry/diiac/patchforge-bridge:$ImageTag"
az containerapp update -g $ResourceGroup -n ca-patchforge-runtime-prod --image "$Registry/diiac/patchforge-runtime:$ImageTag"
az containerapp update -g $ResourceGroup -n ca-patchforge-sra-prod --image "$Registry/diiac/patchforge-sra-agent:$ImageTag"
az containerapp update -g $ResourceGroup -n ca-patchforge-worker-prod --image "$Registry/diiac/patchforge-ingest-worker:$ImageTag"
az containerapp update -g $ResourceGroup -n ca-patchforge-scheduler-prod --image "$Registry/diiac/patchforge-scheduler:$ImageTag"
```

After the approved update, capture the same files with `after` names and confirm:

- each app has a new ready revision or the expected unchanged revision
- each active app image references the frozen tag
- traffic is 100 percent on the expected active revision in single-revision mode
- previous healthy revisions remain identifiable for rollback

## Post-Update Validation Gate

Run and record:

```powershell
npm --prefix backend-api test
npm --prefix Frontend test
npm --prefix Frontend run build
npm run collector:test
python -m pytest -q --basetemp .pytest_tmp
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
```

Run live smoke only after deployment approval and update:

- `https://patchforge.diiac.io/` returns HTTP 200
- `https://api.patchforge.diiac.io/health` returns HTTP 200
- `https://api.patchforge.diiac.io/readiness` returns HTTP 200 and reports production storage/auth readiness
- protected API routes reject unauthenticated requests with HTTP 401
- signed-in browser/MSAL UAT is completed when a user-facing release or production-readiness claim is in scope

No customer-production claim is complete without current readiness evidence, signed-in UAT where applicable, customer or customer-representative acceptance when customer use is claimed, and explicit human release approval.

## Change Documentation

Update release documentation only after evidence exists:

- evidence folder `README.md` with scope, approvals, commands, pass/fail results, stop conditions, and rollback notes
- draft or approved `docs/release/<baseline>_RELEASE_BASELINE_MANIFEST.json`
- `CURRENT_RELEASE.md` only when the release status truly changes
- `QUALITY_GATES_REPORT.json` only with current verification evidence
- `PATCHFORGE_OPEN_GAPS_REGISTER.md` only when a gap status changes

Every release note must distinguish:

- repository commit
- image tag
- per-repository digest
- active revision before and after
- whether Bicep was applied, what-if only, or bypassed for a targeted image-only update
- whether signed-in UAT and customer acceptance are complete, pending, or out of scope

## Stop Conditions

Stop and report the blocker when:

- explicit approval is required for push, update, prune, deployment, release, or future loop-revision promotion
- missing context prevents a trustworthy version catalogue
- Docker Desktop, local builds, or ACR push fails
- IaC validation or Bicep build fails
- what-if shows unexpected drift or destructive/platform-sensitive changes
- any image digest, active revision, rollback revision, or smoke result is missing
- protected routes do not reject unauthenticated requests
- signed-in UAT, report export proof, cleanup evidence, customer acceptance, or human release approval is missing for a production-readiness claim
- the loop would add scanning, exploit guidance, patch deployment, production mutation, autonomous CAB approval, autonomous risk acceptance, or autonomous evidence-gate closure

## Revision Rule

Future revisions can be promoted to the operating catalog only after a human reviewer confirms:

- the outcome and intended audience
- evidence paths and command accuracy
- authority boundaries and approval points
- stop conditions
- whether script automation should be added in a separate approved implementation pass

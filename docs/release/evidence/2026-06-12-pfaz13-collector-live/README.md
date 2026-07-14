# PF-AZ13 Collector Live Deployment Evidence

Date: 2026-06-12

Commit: `440d4f1`

Branch: `codex/patchforge-rebuild-20260601`

Image tag: `pfaz13-20260612-440d4f1`

## Scope

PF-AZ13 adds the governed outbound asset collector package and the live collector intake path:

- Customer-side collector CLI under `collector/`.
- Windows scheduled task and Linux systemd install helpers under `scripts/`.
- Discovery collector, policy, import, overview, and pending-review asset APIs.
- Customer Estate UI action to download collector config instead of importing a sample snapshot.
- Ask PatchForge, catalogue, and report flow refinements needed for the end-to-end user journey.
- Azure bridge OpenAI agent remains enabled with model `gpt-5.4`; `OPENAI_API_KEY` is a Key Vault secret reference.

The collector is not deployed as an Azure Container App. It runs in the customer estate or on an admin workstation/server and connects outbound to the PatchForge bridge API hosted in Azure.

## Azure Context

- Tenant: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Subscription: `9ae9da49-de67-443b-af55-ce9db33ed8f4`
- Resource group: `rg-diiac-patchforge-prod`
- Registry: `acrdiiacpatchforgeprod.azurecr.io`
- UI: `https://patchforge.diiac.io/`
- API: `https://api.patchforge.diiac.io/`

## Image Builds

ACR builds:

- Frontend build run `dbb`: succeeded.
- Backend build run `dbc`: succeeded.
- Runtime build run `dbd`: succeeded.

Published images:

| Image | Digest |
| --- | --- |
| `diiac/patchforge-frontend:pfaz13-20260612-440d4f1` | `sha256:384345937077ee4599d6bedafd9ba49e6329237f5cddf20f58e0eee76a8c86d2` |
| `diiac/patchforge-bridge:pfaz13-20260612-440d4f1` | `sha256:363ce93bdab783266f3d1e4b2db086e469f8be528c88d7d1e8f2d90e604d0a8d` |
| `diiac/patchforge-sra-agent:pfaz13-20260612-440d4f1` | `sha256:363ce93bdab783266f3d1e4b2db086e469f8be528c88d7d1e8f2d90e604d0a8d` |
| `diiac/patchforge-ingest-worker:pfaz13-20260612-440d4f1` | `sha256:363ce93bdab783266f3d1e4b2db086e469f8be528c88d7d1e8f2d90e604d0a8d` |
| `diiac/patchforge-scheduler:pfaz13-20260612-440d4f1` | `sha256:363ce93bdab783266f3d1e4b2db086e469f8be528c88d7d1e8f2d90e604d0a8d` |
| `diiac/patchforge-runtime:pfaz13-20260612-440d4f1` | `sha256:d7c1279a63dce1a8ef93c7a694ccdf5b4b4ae40a82662c03bc04979d8bbc8a72` |

Local Docker Desktop was not running, so builds were executed in ACR.

## Container App Revisions

| App | Previous revision | Active revision after deploy | Image |
| --- | --- | --- | --- |
| `ca-patchforge-ui-prod` | `ca-patchforge-ui-prod--0000035` | `ca-patchforge-ui-prod--0000036` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-frontend:pfaz13-20260612-440d4f1` |
| `ca-patchforge-bridge-prod` | `ca-patchforge-bridge-prod--0000034` | `ca-patchforge-bridge-prod--0000035` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-bridge:pfaz13-20260612-440d4f1` |
| `ca-patchforge-runtime-prod` | `ca-patchforge-runtime-prod--0000024` | `ca-patchforge-runtime-prod--0000025` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-runtime:pfaz13-20260612-440d4f1` |
| `ca-patchforge-sra-prod` | `ca-patchforge-sra-prod--0000024` | `ca-patchforge-sra-prod--0000025` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-sra-agent:pfaz13-20260612-440d4f1` |
| `ca-patchforge-worker-prod` | `ca-patchforge-worker-prod--0000024` | `ca-patchforge-worker-prod--0000025` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-ingest-worker:pfaz13-20260612-440d4f1` |
| `ca-patchforge-scheduler-prod` | `ca-patchforge-scheduler-prod--0000024` | `ca-patchforge-scheduler-prod--0000025` | `acrdiiacpatchforgeprod.azurecr.io/diiac/patchforge-scheduler:pfaz13-20260612-440d4f1` |

Release metadata env vars set during update:

- `PATCHFORGE_IMAGE_TAG=pfaz13-20260612-440d4f1`
- `CONTAINER_IMAGE_TAG=pfaz13-20260612-440d4f1`
- `PATCHFORGE_COMMIT_SHA=440d4f1`
- `PATCHFORGE_RENDERER_COMMIT=440d4f1`
- `PATCHFORGE_PRODUCT_BASELINE=PF-AZ13-COLLECTOR-INTAKE`
- `PATCHFORGE_REPORT_CONTEXT_VERSION=patchforge-report-context.pfaz13.v1`

## Key Vault And OpenAI

Bridge configuration after deployment:

- `PATCHFORGE_OPENAI_AGENT_ENABLED=true`
- `PATCHFORGE_OPENAI_MODEL=gpt-5.4`
- `OPENAI_API_KEY` is `secretRef: openai-api-key`
- `openai-api-key` is a Key Vault reference to `https://kv-diiac-itservices.vault.azure.net/secrets/diiac-openai-api-key`
- Secret reference identity: `id-patchforge-bridge-prod`

No OpenAI key value was read, logged, or committed.

## Verification

Pre-deploy local checks:

- `npm --prefix Frontend test`: PASS, 12 tests.
- `npm --prefix Frontend run build`: PASS, with existing Vite chunk-size warning.
- `npm --prefix backend-api test`: PASS, 48 tests.
- `npm run collector:test`: PASS, 4 tests.
- `python -m pytest -q --basetemp <temp>`: PASS, 28 tests, with local `.pytest_cache` warning.
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate_iac.ps1`: PASS.
- `git diff --check`: PASS.

Local collector smoke before deploy:

- Real local backend plus real collector CLI imported 1 asset.
- Asset landed as `pending_review` with `discovery_source=patchforge_collector`.

Post-deploy smoke:

- `https://patchforge.diiac.io/`: HTTP 200.
- `https://api.patchforge.diiac.io/health`: `{"status":"ok","product":"DIIaC PatchForge","boundary":"governance-only"}`.
- `https://api.patchforge.diiac.io/readiness`: ready, `storage=postgresql`, `auth_required=true`, `tenant_required=true`.
- Unauthenticated `GET /api/patchforge/metrics`: HTTP 401.
- Unauthenticated `POST /api/patchforge/discovery/collectors`: HTTP 401.
- Live browser check loaded the Microsoft sign-in shell at `https://patchforge.diiac.io/`.

## UAT Status

Deployment is live and ready for signed-in testing.

G4 live end-user acceptance is still outstanding until a signed-in user completes:

1. Open Customer Estate.
2. Register Collector.
3. Create Policy.
4. Download Collector Config.
5. Set `PATCHFORGE_COLLECTOR_TOKEN` for the target collector runtime.
6. Run `node collector/patchforge-collector.mjs --config=<downloaded-config>`.
7. Confirm imported assets appear as pending review in PatchForge.

## Rollback

If live UAT finds a blocking issue, re-point the six Container Apps to the previous image tags/revisions listed above or to their last known healthy image tags:

- UI/API previous live tag: `reports-cleanup-20260611-1956`.
- SRA/worker/scheduler previous live tag: `pfopenai-gpt54-fix-20260611-0036`.
- Runtime previous live tag: `pfopenai-gpt54-20260611-0014`.

No production purge, data deletion, patch deployment, exploit generation, autonomous CAB approval, or autonomous risk acceptance was performed.

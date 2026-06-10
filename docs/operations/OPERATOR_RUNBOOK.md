# PatchForge Operator Runbook

Date: 2026-06-10
Scope: production environment `rg-diiac-patchforge-prod` (uksouth, tenant `diiac.io`).

## Service Map

| Component | Resource | Purpose |
| --- | --- | --- |
| UI | Container App `ca-diiac-patchforge-ui` | Frontend at `https://patchforge.diiac.io` |
| Bridge/API | Container App `ca-diiac-patchforge-bridge` | Entra-protected API at `https://api.patchforge.diiac.io` |
| Runtime | Container App `ca-diiac-patchforge-runtime` | Deterministic governance, pack signing and verification |
| SRA | Container App `ca-diiac-patchforge-sra` | Advisory-only research service |
| Worker | Container App `ca-diiac-patchforge-worker` | Async ingest |
| Scheduler | Container App `ca-diiac-patchforge-scheduler` | KEV/EPSS refresh |
| Database | PostgreSQL Flexible Server `psql-diiac-patchforge-prod` | Tenant state (`patchforge_prod`) |
| Storage | `stdiiacpatchforgeprod01` | Packs, evidence, exports |
| Key Vault | `kv-diiac-patchforge-prod` | Postgres password, pack signing key `pf-pack-signing-prod` |
| Logs | Log Analytics `law-diiac-patchforge-prod` | Container console logs |

Container App names are defined in `infra/bicep/container-apps.bicep`; confirm with `az containerapp list -g rg-diiac-patchforge-prod -o table` before acting.

## Health Checks

```bash
curl -s https://api.patchforge.diiac.io/health
curl -s https://api.patchforge.diiac.io/readiness
# Runtime (internal ingress): exec a probe from within the environment or check replica status
az containerapp replica list -g rg-diiac-patchforge-prod -n ca-diiac-patchforge-runtime -o table
```

Expected: HTTP 200, `status: ok` / `status: ready`, `auth_required: true` in production.

## Log Queries (Log Analytics, KQL)

```kusto
ContainerAppConsoleLogs_CL
| where ContainerAppName_s startswith "ca-diiac-patchforge"
| where Log_s contains "patchforge_internal_error" or Log_s contains "error"
| order by TimeGenerated desc | take 100
```

Per-tenant API rate limiting emits `429 rate_limit_exceeded` in the API logs; webhook delivery failures emit `webhook_dispatch_failed`.

## Deployment

Preferred path: GitHub Actions `deploy.yml` (workflow_dispatch; requires `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` repo secrets and the `production` environment with manual approval). The workflow echoes previous image tags before updating — capture them.

Legacy/manual path: `scripts/build_push_images.ps1` then `scripts/deploy_azure_bootstrap.ps1` (always plan/what-if first; preserve custom domains and managed certificates; never disable `PATCHFORGE_AUTH_REQUIRED`).

### Rollback

```bash
az containerapp update --name <app> --resource-group rg-diiac-patchforge-prod --image <previous-image>
```

Previous images are printed by the deploy workflow, or recover via `az containerapp revision list`.

## Secrets Rotation

- **Postgres admin password**: set a new value for Key Vault secret `patchforge-postgres-admin-password`, run `az postgres flexible-server update --admin-password`, then restart the bridge/worker/scheduler apps. Verify `/readiness` afterwards.
- **Pack signing key** (`pf-pack-signing-prod`, ES256): create a new key version in Key Vault; the runtime picks up the latest version. Previously signed packs remain verifiable because the public JWK is embedded in each pack's signature metadata.
- Record every rotation as an audit event and in the release evidence directory.

## Quick Diagnosis

| Symptom | First checks |
| --- | --- |
| API 5xx | Console logs for `patchforge_internal_error`; Postgres availability; recent deploy/rollback |
| 401/403 spikes | Entra app registration/roles unchanged? Token audience/issuer in `auth.js` env vars |
| 429 responses | Per-tenant rate limit (`PATCHFORGE_RATE_LIMIT_PER_MINUTE`, default 120/min) — confirm legitimate load before raising |
| Feed refresh failing | Scheduler app logs; CISA KEV / FIRST EPSS reachability; rate-limit states recorded as governed source-feed runs |
| Pack generation 502 `pack_verification_failed` | Runtime signature verification rejected the pack — treat as an integrity incident, do not retry blindly; inspect runtime logs and Key Vault key state |
| Pack generation timeout | Runtime replica health; `PATCHFORGE_RUNTIME_TIMEOUT_MS` (default 45s) |

## Alerts

Metric alerts (container restarts, Postgres CPU/storage) are defined in `infra/bicep/monitoring-alerts.bicep` and deploy when `enableAlerts=true` with `alertEmail` set.

# PatchForge Production Hardening Evidence - 2026-05-26

## Scope

This evidence set records the PF-AZ4 hardening gate completed on 2026-05-26.

## Completed

- Bridge/API storage abstraction now supports PostgreSQL and is deployed with `PATCHFORGE_STORAGE_MODE=postgresql`.
- Bridge/API retrieves the PostgreSQL password from Azure Key Vault by managed identity using the existing secret `patchforge-postgres-admin-password`.
- Bridge/API enforces Microsoft Entra bearer-token authorization for PatchForge API routes when `PATCHFORGE_AUTH_REQUIRED=true`.
- Runtime decision-pack signing supports Azure Key Vault ES256 signing with local public-key verification.
- Runtime Key Vault signing smoke passed against `pf-pack-signing-prod`.
- PostgreSQL firewall rule `AllowAzureServices` exists for the initial Azure Container Apps connectivity model.
- Custom domains are represented in Bicep so future deployments preserve the existing managed certificate bindings.
- Image tag `pfaz4-20260526` was built, pushed, and deployed.

## Live State

- UI: `https://patchforge.diiac.io/` returned 200.
- API health: `https://api.patchforge.diiac.io/health` returned 200.
- API readiness: `https://api.patchforge.diiac.io/readiness` returned 200 with `storage=postgresql` and `auth_required=true`.
- Unauthenticated protected API call returned 401 with PatchForge app-role requirements.

## Evidence Files

- `acr-images-pfaz4.json`
- `auth-smoke-pfaz4.json`
- `bridge-production-env.json`
- `containerapp-state-pfaz4.json`
- `deployment-pf-prod-hardening-20260526.json`
- `deployment-pf-prod-hardening-domains-20260526.json`
- `http-smoke-pfaz4.json`
- `postgres-firewall-rules.json`
- `runtime-keyvault-signing-smoke.json`

## Notes

Azure CLI token smoke could not complete because the Microsoft Azure CLI first-party client has not been consented for the PatchForge API delegated scope. No token or secret was recorded. The unauthenticated API smoke confirmed enforcement with a 401 response.

The UI remains a public static command-centre shell. Protected API data now requires Entra bearer tokens with PatchForge app roles.

# PatchForge DNS Cutover Evidence - 2026-05-26

## Scope

This evidence set records the PatchForge custom-domain cutover completed on 2026-05-26 after the Porkbun DNS records were added.

## Completed

- `patchforge.diiac.io` CNAME resolves to the PatchForge UI Container App.
- `api.patchforge.diiac.io` CNAME resolves to the PatchForge bridge/API Container App.
- `asuid.patchforge.diiac.io` and `asuid.api.patchforge.diiac.io` TXT verification records resolve to the Azure Container Apps verification ID.
- Azure Container Apps managed certificates were issued successfully for both hostnames.
- Both custom domains are bound with SNI enabled.
- HTTPS smoke checks returned 200 for the UI, API health, and API readiness endpoints.

## Live URLs

- UI: `https://patchforge.diiac.io/`
- API health: `https://api.patchforge.diiac.io/health`
- API readiness: `https://api.patchforge.diiac.io/readiness`

## Evidence Files

- `dns-resolution.json`
- `containerapp-hostname-bindings.json`
- `managed-certificates.json`
- `http-smoke-custom-domains.json`

## Boundary

No exploit, scanner, patch deployment, autonomous CAB, autonomous risk acceptance, or production mutation capability was added to PatchForge application code as part of this DNS cutover.

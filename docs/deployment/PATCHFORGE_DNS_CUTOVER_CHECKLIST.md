# PatchForge DNS Cutover Checklist

## DNS Names

Primary:

- `patchforge.diiac.io`

Optional:

- `api.patchforge.diiac.io`
- `admin.patchforge.diiac.io`

Observed sibling product domains:

- `itservices.diiac.io`
- `itservices-sim.diiac.io`

Use these only as DNS operating references. PatchForge needs its own Container Apps custom domain bindings and certificates.

## Current Azure Ingress

| Surface | Current target |
| --- | --- |
| ACA environment default domain | `lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| ACA static IP | `4.250.136.215` |
| UI | `ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| Bridge/API | `ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |

The public UI and bridge are live on default Azure Container Apps hostnames and on the PatchForge custom domains.

The `diiac.io` zone is hosted at Porkbun, not Azure DNS. The required Porkbun records were added and verified on 2026-05-26.

## Cutover Result

Completed on 2026-05-26:

- `patchforge.diiac.io` bound to `ca-patchforge-ui-prod`
- `api.patchforge.diiac.io` bound to `ca-patchforge-bridge-prod`
- Azure managed certificate issued for `patchforge.diiac.io`
- Azure managed certificate issued for `api.patchforge.diiac.io`
- UI HTTPS smoke: 200
- API health HTTPS smoke: 200
- API readiness HTTPS smoke: 200

## DNS Records

Direct Azure Container Apps custom domains use these records in Porkbun:

| Type | Host | Value |
| --- | --- | --- |
| CNAME | `patchforge` | `ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| TXT | `asuid.patchforge` | `D815E8B3470ADCCFE09104F6B9557CC8DC05A4BF8DFED6FC65F27D87B54195E5` |
| CNAME | `api.patchforge` | `ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| TXT | `asuid.api.patchforge` | `D815E8B3470ADCCFE09104F6B9557CC8DC05A4BF8DFED6FC65F27D87B54195E5` |

These records resolved publicly during cutover evidence capture.

## Evidence

- `docs/release/evidence/2026-05-26-patchforge-dns-cutover/dns-resolution.json`
- `docs/release/evidence/2026-05-26-patchforge-dns-cutover/containerapp-hostname-bindings.json`
- `docs/release/evidence/2026-05-26-patchforge-dns-cutover/managed-certificates.json`
- `docs/release/evidence/2026-05-26-patchforge-dns-cutover/http-smoke-custom-domains.json`

## Future Ingress Options

Future options:

- keep direct Container Apps custom domain mapping, or
- introduce Azure Front Door with WAF and update DNS after a planned cutover

Do not create alternate records unless the production ingress target changes.

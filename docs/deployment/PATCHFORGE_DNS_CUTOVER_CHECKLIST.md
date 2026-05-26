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

The public UI and bridge are live on default Azure Container Apps hostnames. DNS has not been updated.

## Before DNS Update

Confirm:

- Azure Container Apps frontend ingress URL
- bridge/API ingress URL if separate
- TLS certificate approach
- Front Door/WAF decision
- rollback DNS record values
- TTL change window

## Required User Action

DNS must not be updated until the user confirms the target hostnames and cutover window.

## Suggested Records

The exact records depend on the final Azure ingress model:

- direct Container Apps custom domain mapping, or
- Azure Front Door endpoint with WAF

Do not create these records until the production ingress target exists and has been validated.

If using direct Container Apps custom domains, prepare to map:

- `patchforge.diiac.io` to the UI app
- `api.patchforge.diiac.io` to the bridge/API app

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

The `diiac.io` zone is hosted at Porkbun, not Azure DNS. Azure CLI cannot complete the DNS update unless Porkbun API credentials are provided or the records are added in the Porkbun console.

## Before DNS Update

Confirm:

- Azure Container Apps frontend ingress URL
- bridge/API ingress URL if separate
- TLS certificate approach
- Front Door/WAF decision
- rollback DNS record values
- TTL change window

## Required DNS Records

For direct Azure Container Apps custom domains, add or confirm these records in Porkbun:

| Type | Host | Value |
| --- | --- | --- |
| CNAME | `patchforge` | `ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| TXT | `asuid.patchforge` | `D815E8B3470ADCCFE09104F6B9557CC8DC05A4BF8DFED6FC65F27D87B54195E5` |
| CNAME | `api.patchforge` | `ca-patchforge-bridge-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io` |
| TXT | `asuid.api.patchforge` | `D815E8B3470ADCCFE09104F6B9557CC8DC05A4BF8DFED6FC65F27D87B54195E5` |

After propagation, bind the hostnames to the Container Apps and create managed certificates.

## Required User Action

Update the Porkbun records above or provide Porkbun API access for this zone. After the records resolve publicly, run the Azure Container Apps custom-domain binding step.

## Suggested Records

The exact records depend on the final Azure ingress model:

- direct Container Apps custom domain mapping, or
- Azure Front Door endpoint with WAF

Do not create alternate records unless the production ingress target changes.

If using direct Container Apps custom domains, prepare to map:

- `patchforge.diiac.io` to the UI app
- `api.patchforge.diiac.io` to the bridge/API app

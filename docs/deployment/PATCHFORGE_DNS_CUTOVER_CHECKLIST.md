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

# PatchForge Gates Evidence - 2026-05-26

## Scope

This evidence set records the post-bootstrap PatchForge identity, signing, database, DNS, and health gates completed in the DIIaC tenant on 2026-05-26.

## Completed Gates

- Entra app registrations created or confirmed for `DIIaC PatchForge API` and `DIIaC PatchForge UI`.
- PatchForge app roles created on both app registrations.
- PatchForge admin and reader group assignments confirmed on both service principals.
- `n.bailey@diiac.io` and `nbailey@diiac.io` confirmed as members of all DIIaC admin groups discovered in the tenant.
- Azure Key Vault production signing key `pf-pack-signing-prod` created and smoke-verified with ES256 signing and verification.
- Azure Database for PostgreSQL Flexible Server `psql-diiac-patchforge-prod` created with database `patchforge_prod`.
- Public UI, bridge health, and bridge readiness HTTP smoke checks returned 200.

## Pending Gate

DNS is still pending because `diiac.io` is hosted outside Azure DNS at Porkbun.

Required records are captured in `dns-required-records.json` and in `docs/deployment/PATCHFORGE_DNS_CUTOVER_CHECKLIST.md`.

## Evidence Files

- `admin-group-membership.json`
- `containerapp-db-env.json`
- `containerapp-state-after-gates.json`
- `dns-required-records.json`
- `entra-apps.json`
- `http-smoke-after-gates.json`
- `keyvault-signing-smoke.json`
- `postgres-database-state.json`
- `postgres-deployment-summary.json`
- `postgres-state.json`

## Boundary

No exploit, scanner, patch deployment, autonomous CAB, autonomous risk acceptance, or production mutation capability was added to PatchForge application code as part of these gates.

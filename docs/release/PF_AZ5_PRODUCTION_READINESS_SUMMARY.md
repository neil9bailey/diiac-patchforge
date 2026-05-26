# PF-AZ5 Production Readiness Summary

Date: 2026-05-26

## State

PatchForge is live on Azure Container Apps with custom domains, PostgreSQL storage, Entra-protected API routes, and Key Vault production signing support.

PF-AZ5 adds production intelligence hardening:

- fail-closed production auth guard
- production tenant-context hardening
- actor and tenant lineage on writes
- Bayesian Patch Risk Inference
- vendor and threat landscape intelligence
- source-bound agent finding governance
- live API-bound UI pages
- board-grade report sections
- signed pack intelligence artefacts

## Final Gate Result

PF-AZ5 passed post-deployment live UI user validation under `docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/live-ui/`.

Validated:

- UI HTTP 200
- API health/readiness HTTP 200
- readiness reports `storage=postgresql` and `auth_required=true`
- unauthenticated protected route returns HTTP 401
- signed-in MSAL browser workflow shows `n.bailey@diiac.io` with `PatchForge.Admin`
- live UI ingest of `CVE-2026-PF-DEMO-001`
- SRA advisory-only/source-bound output
- Bayesian advisory-only output
- signed decision pack `PF-20260526-e90d3a02`
- Key Vault ES256 signing smoke
- exported pack verification PASS with `final_approval_issued=false`

## Honest Gaps

- Live scanner integrations are not implemented.
- Patch deployment remains prohibited and not implemented.
- Exploit generation remains prohibited and not implemented.
- Bayesian output is advisory-only and cannot approve or close gates.
- Vendor and threat intelligence remains source-bound until reviewed.
- Live customer validation is not claimed unless explicitly evidenced.
- Azure CLI custom API token acquisition remains blocked by interactive consent for the Azure CLI client; browser/MSAL validation succeeded and was used for the user workflow.

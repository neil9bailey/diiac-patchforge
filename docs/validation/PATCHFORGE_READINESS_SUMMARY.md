# PatchForge Readiness Summary

## Current Readiness

PatchForge is live on Azure Container Apps under the DIIaC tenant with:

- custom UI domain `https://patchforge.diiac.io`
- custom API domain `https://api.patchforge.diiac.io`
- Microsoft Entra app registrations and PatchForge app roles
- PostgreSQL-backed tenant state
- Key Vault production signing path
- Azure Container Apps revisions for UI, bridge/API, runtime, SRA, worker, and scheduler
- source-bound evidence and signed pack governance controls
- guided Action Center, Finding Detail, Review & Approve, Reports & Packs, Guide, and Admin workflow
- professional protected DOCX/PDF report generation from signed decision packs
- PF-AZ8 image tag `pfaz8-20260527-cc708fd` on all PatchForge Container Apps

PF-AZ8 adds the customer-demo workflow hardening requested after report/UI review:

- Action Center that translates findings into decision-ready work
- plain-English finding intelligence
- exploitability intelligence without exploit code, payloads, or procedural steps
- autonomous analysis summary with human approval still required
- SRA advisory-only workflow
- signed-pack support for `finding_intelligence_snapshot.json`
- board/CAB DOCX and PDF reports generated from live signed evidence
- Admin health visibility for database, storage, Key Vault, signing, bridge, runtime, and frontend status

## Live Validation

PF-AZ8 Azure update and live UI user validation are complete for the current commit and image tag.

- User: `n.bailey@diiac.io`
- Role displayed: `PatchForge.Admin`
- Validated record: `CVE-2026-48172`
- Signed pack: `PF-20260527-9fc7f010`
- Pack verification: PASS
- Manifest verification: PASS
- Signature verification: PASS
- Signing provider: `azure_key_vault`
- Final approval: `false`
- DOCX report generation: PASS
- PDF report generation: PASS
- PostgreSQL readiness: PASS
- Protected unauthenticated route returns: HTTP 401
- Evidence path: `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/live-ui/`

## Remaining Gaps

- live scanner integrations are not implemented
- patch deployment is not implemented and remains prohibited
- exploit generation is not implemented and remains prohibited
- Bayesian prior updates are dry-run/proposal-only
- vendor and threat intelligence remains source-bound until reviewed
- no third-party customer production validation is claimed

These are not blockers for the governed PatchForge product demo because scanner operation, patch deployment, exploit generation, and autonomous approvals are intentionally outside the product boundary.

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, or approve risk without accountable human review.

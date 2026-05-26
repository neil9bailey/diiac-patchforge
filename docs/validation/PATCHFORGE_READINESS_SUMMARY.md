# PatchForge Readiness Summary

## Current Readiness

PatchForge is live on Azure Container Apps under the DIIaC tenant with:

- custom UI domain `https://patchforge.diiac.io`
- custom API domain `https://api.patchforge.diiac.io`
- Entra app registrations and PatchForge app roles
- PostgreSQL-backed tenant state
- Key Vault production signing path
- Azure Container Apps revisions for UI, bridge/API, runtime, SRA, worker, and scheduler
- source-bound evidence and signed pack governance controls
- PF-AZ5 image tag `pfaz5-20260526-8a145e8` on all PatchForge Container Apps

PF-AZ5 adds production intelligence hardening:

- fail-closed production auth checks
- token/config-derived tenant context in production
- actor and tenant lineage on write actions
- Bayesian Patch Risk Inference
- vendor and threat landscape intelligence
- live API-bound UI surfaces
- board-grade reports and signed pack intelligence artefacts

## Live Validation

PF-AZ5 Azure update and live UI user validation are complete for the current commit and image tag.

- User: `n.bailey@diiac.io`
- Role displayed: `PatchForge.Admin`
- Test vulnerability: `CVE-2026-PF-DEMO-001`
- Signed pack: `PF-20260526-e90d3a02`
- Pack verification: PASS
- Final approval: `false`
- Readiness state: blocked pending evidence/human gates
- Evidence path: `docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/live-ui/`

## Remaining Gaps

- live scanner integrations are not implemented
- patch deployment is not implemented and remains prohibited
- exploit generation is not implemented and remains prohibited
- Bayesian prior updates are dry-run/proposal-only
- vendor and threat intelligence remains source-bound until reviewed
- no third-party customer production validation is claimed

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, or approve risk without accountable human review.

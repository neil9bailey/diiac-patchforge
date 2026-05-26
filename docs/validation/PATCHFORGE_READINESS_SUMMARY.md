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

PF-AZ5 adds production intelligence hardening:

- fail-closed production auth checks
- token/config-derived tenant context in production
- actor and tenant lineage on write actions
- Bayesian Patch Risk Inference
- vendor and threat landscape intelligence
- live API-bound UI surfaces
- board-grade reports and signed pack intelligence artefacts

## Completion Gate

PF-AZ5 is not considered complete until the Azure update and live UI user validation evidence are captured for the current commit and image tag.

## Remaining Gaps

- live scanner integrations are not implemented
- patch deployment is not implemented and remains prohibited
- exploit generation is not implemented and remains prohibited
- Bayesian prior updates are dry-run/proposal-only
- vendor and threat intelligence remains source-bound until reviewed
- no third-party customer production validation is claimed

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, or approve risk without accountable human review.

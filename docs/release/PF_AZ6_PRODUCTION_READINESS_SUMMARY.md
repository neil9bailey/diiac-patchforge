# PF-AZ6 Production Readiness Summary

Date: 2026-05-26

PF-AZ6 adds live public vulnerability intelligence feeds to PatchForge while retaining the governance-only product boundary.

## Implemented

- CISA Known Exploited Vulnerabilities Catalog refresh endpoint.
- FIRST EPSS enrichment endpoint.
- Source-feed run ledger.
- Source-feed contracts.
- UI Source Feeds page bound to protected API calls.
- Command Center and utility rail source-feed status.
- Tests confirming public intelligence stays source-bound, pending review, advisory-only, and unable to close hard gates alone.

## Local Readiness

- Backend/SRA tests: PASS.
- Python runtime/contract tests: PASS.
- Frontend tests: PASS.
- Frontend production build: PASS.
- IaC validation: PASS.
- Bicep build: PASS.
- Docker build smoke: PASS.

## Azure Readiness

Azure rollout is pending for this baseline. PF-AZ5 remains the active deployed production image set until PF-AZ6 images are pushed to ACR and Container Apps are updated.

## Boundaries

PatchForge remains a governance product only. PF-AZ6 does not add scanning, exploit generation, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance.

## Final Validation Required

PF-AZ6 is not final until:

- GitHub push succeeds.
- PF-AZ6 images are built and pushed to ACR.
- Azure Container Apps are updated.
- Live API smoke passes.
- Browser/MSAL live UI validation passes at `https://patchforge.diiac.io`.
- A real CISA/FIRST source-feed workflow is validated through the deployed UI.

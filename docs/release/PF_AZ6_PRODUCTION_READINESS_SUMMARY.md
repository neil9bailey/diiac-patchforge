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

Azure rollout completed for this baseline. PF-AZ6 is active on all PatchForge Container Apps with image tag `pfaz6-20260526-473b055`.

Active revisions:

- UI: `ca-patchforge-ui-prod--0000008`
- Bridge/API: `ca-patchforge-bridge-prod--0000007`
- Runtime: `ca-patchforge-runtime-prod--0000006`
- SRA: `ca-patchforge-sra-prod--0000005`
- Worker: `ca-patchforge-worker-prod--0000005`
- Scheduler: `ca-patchforge-scheduler-prod--0000005`

## Boundaries

PatchForge remains a governance product only. PF-AZ6 does not add scanning, exploit generation, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance.

## Final Validation

PF-AZ6 live validation passed:

- GitHub push succeeded.
- PF-AZ6 images were built and pushed to ACR.
- Azure Container Apps were updated.
- Live API smoke passed.
- Browser/MSAL live UI validation passed at `https://patchforge.diiac.io`.
- CISA KEV and FIRST EPSS source-feed workflows were validated through the deployed UI.
- Signed pack `PF-20260526-8312f908` for `CVE-2026-48172` verified with Azure Key Vault signing.
- The earlier PF-AZ5 synthetic validation record `CVE-2026-PF-DEMO-001` and linked production PostgreSQL records were removed.
- The temporary PostgreSQL firewall rule used for cleanup was removed after verification.

Evidence: `docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/`

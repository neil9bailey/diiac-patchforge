# PatchForge Rebuild Live Test Deployment Evidence

Date: 2026-06-01

Branch: `codex/patchforge-rebuild-20260601`

Deployed code commit: `c6d59a8`

Image tag: `pfrebuild-20260601-c6d59a8`

## Deployment Scope

The rebuild branch was deployed to the existing Azure Container Apps production test surface for live operator testing after explicit user approval in the active thread.

The update used targeted Container Apps image revisions only. The full Bicep what-if was reviewed and was not applied because it showed broad live-state drift and would have changed Container App environment ordering/image values if applied directly.

## Updated Apps

- `ca-patchforge-ui-prod`
- `ca-patchforge-bridge-prod`
- `ca-patchforge-runtime-prod`
- `ca-patchforge-sra-prod`
- `ca-patchforge-worker-prod`
- `ca-patchforge-scheduler-prod`

## Active Revisions After Update

- UI: `ca-patchforge-ui-prod--0000027`
- Bridge/API: `ca-patchforge-bridge-prod--0000024`
- Runtime: `ca-patchforge-runtime-prod--0000022`
- SRA: `ca-patchforge-sra-prod--0000021`
- Worker: `ca-patchforge-worker-prod--0000021`
- Scheduler: `ca-patchforge-scheduler-prod--0000021`

All active revisions reported healthy and had 100% traffic.

## Public Smoke

- `https://patchforge.diiac.io/` returned HTTP 200.
- `https://api.patchforge.diiac.io/health` returned HTTP 200.
- `https://api.patchforge.diiac.io/readiness` returned HTTP 200 with PostgreSQL storage and auth required.
- `https://api.patchforge.diiac.io/api/patchforge/security-action-center` returned HTTP 401 unauthenticated, as expected.

## Evidence Files

- `deploy-plan/azure-context.json`
- `deploy-plan/validate-iac.log`
- `deploy-plan/what-if.log`
- `deploy-plan/plan-exit-codes.json`
- `deploy-apply/active-revisions-before.json`
- `build-push/build-push-images.log`
- `build-push/build-push-summary.json`
- `build-push/acr-digests.json`
- `deploy-apply/containerapp-update-results.json`
- `deploy-apply/active-revisions-after.json`
- `live-smoke/public-http-smoke.json`

## Remaining Live Validation

The in-app browser was opened to `https://patchforge.diiac.io/` and showed the rebuilt PatchForge Intelligence sign-in boundary. Signed-in MSAL validation, synthetic data entry, signed pack generation, export verification, and cleanup remain to be completed by an operator with the required PatchForge roles.

No real customer data, credentials, secrets, exploit payloads, or production mutation test data were used.


# PF-AZ5 Live UI Validation

Date: 2026-05-26

Result: PASS

Validated URL: `https://patchforge.diiac.io`

Signed-in user displayed by UI: `n.bailey@diiac.io`

Displayed role: `PatchForge.Admin`

## Workflow Evidence

- Opened the live UI and confirmed Microsoft Entra sign-in.
- Signed in through MSAL and confirmed role-gated admin navigation.
- Ingested `CVE-2026-PF-DEMO-001` through the deployed UI.
- Confirmed queue rendering from live API data: Critical, known exploited, internet exposed, Orion Gateway, patch available.
- Ran SRA exploit-risk advisory and confirmed source-bound, pending-review, advisory-only output.
- Ran Bayesian Patch Risk advisory and confirmed it cannot close hard gates or approve risk.
- Generated and exported signed decision pack `PF-20260526-e90d3a02`.
- Verified the exported pack reports `verified=true`, `manifest_ok=true`, and `signature_ok=true`.
- Confirmed `final_approval_issued=false` and readiness remains blocked pending human/evidence gates.
- Navigated Command Center, Guide, Vulnerability Queue, Asset & Service Exposure, Decision Workbench, Emergency Patch, Risk Acceptances, Compensating Controls, SRA Research, Evidence Catalogue, Decision Packs, Vendor & Threat Landscape, and Admin.

## Key Files

- `ui-smoke-summary.json`
- `live-api-smoke.json`
- `live-auth-smoke.json`
- `live-pack-verification.txt`
- `PF-20260526-e90d3a02.json`
- `keyvault-signing-smoke.json`
- `postgres-smoke.json`
- `containerapp-active-revisions.json`
- `browser-screenshots/`
- `console-log.txt`

Console notes are limited to Microsoft login BSSO/fav icon noise; no app-breaking console error was observed during the validated workflow.

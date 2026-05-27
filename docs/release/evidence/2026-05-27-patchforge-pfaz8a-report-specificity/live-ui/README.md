# PF-AZ8A Live UI Validation Evidence

Date: 2026-05-27

Validated target:

- UI: `https://patchforge.diiac.io`
- API: `https://api.patchforge.diiac.io`
- Image tag: `pfaz8a-20260527-4f3bbe8`
- Signed-in user: `n.bailey@diiac.io`
- Displayed role: `PatchForge.Admin`

## Result

PASS. The deployed PF-AZ8A UI/API path was validated through a signed-in browser session after Azure Container Apps were updated.

## Workflow

- Opened the live UI and signed in through Microsoft Entra.
- Confirmed the context banner for `CVE-2026-48172`.
- Confirmed safer wording: `Automated Governance Analysis Completed`.
- Confirmed the old autonomous-analysis heading is absent.
- Confirmed the human-approval notice is visible.
- Generated live signed pack `PF-20260527-934d6e60`.
- Exported customer, board, and CAB reports as DOCX and PDF from the protected API.
- Verified signed-pack manifest and signature.
- Rendered exported PDFs to PNG contact sheets and inspected the output.

## Evidence Files

- `ui-smoke-summary.json`
- `live-api-smoke.json`
- `live-auth-smoke.json`
- `live-pack-verification.json`
- `live-report-fetch-summary.json`
- `live-report-visual-qa.json`
- `keyvault-signing-smoke.json`
- `postgres-smoke.json`
- `containerapp-active-revisions.json`
- `admin-health-live.json`
- `browser-screenshots/`
- `exported-reports/`
- `report-render-qa/`
- `console-log.txt`

## Boundary

PF-AZ8A remains governance-only. It does not scan environments, generate exploit instructions, deploy patches, mutate production systems, approve CAB decisions, close remediation, or accept risk autonomously.

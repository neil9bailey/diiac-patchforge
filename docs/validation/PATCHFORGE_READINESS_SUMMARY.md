# PatchForge Readiness Summary

## Current Readiness

Date: 2026-06-04

PatchForge is live on Azure Container Apps under the DIIaC tenant with:

- custom UI domain `https://patchforge.diiac.io`
- custom API domain `https://api.patchforge.diiac.io`
- Microsoft Entra app registrations and PatchForge app roles
- PostgreSQL-backed tenant state
- Key Vault production signing path
- Azure Container Apps revisions for UI, bridge/API, runtime, SRA, worker, and scheduler
- source-bound evidence and signed pack governance controls
- seven-area PF-AZ11 navigation: Security Action Center, Vendors & Exploits Register, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, Reports, and Admin
- protected DOCX/PDF report generation from signed decision packs

Current deployed image state:

| Component | Image tag | Active revision |
| --- | --- | --- |
| UI | `pfaz11-20260603-f56fd2b` | `ca-patchforge-ui-prod--0000029` |
| Bridge/API | `pfrebuild-20260601-43f953c` | `ca-patchforge-bridge-prod--0000025` |
| Runtime | `pfrebuild-20260601-43f953c` | `ca-patchforge-runtime-prod--0000023` |
| SRA | `pfrebuild-20260601-43f953c` | `ca-patchforge-sra-prod--0000022` |
| Worker | `pfrebuild-20260601-43f953c` | `ca-patchforge-worker-prod--0000022` |
| Scheduler | `pfrebuild-20260601-43f953c` | `ca-patchforge-scheduler-prod--0000022` |

## PF-AZ11 Validation State

Completed:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- protected Security Action Center route unauthenticated HTTP 401: PASS
- live signed-out browser shell: PASS
- frontend tests for current UI commit: PASS, 10 tests
- frontend production build for current UI commit: PASS, Vite chunk-size advisory only

Pending:

- signed-in Microsoft Entra PatchForge.Admin UAT through the seven-area flow
- protected Ask PatchForge workflow validation, including ambiguous "this CVE" questions
- fresh PF-AZ11 signed-pack generation
- fresh PF-AZ11 Customer/Board/CAB DOCX/PDF export and review
- production validation-record cleanup after any signed-in PF-AZ11 UAT records

Known access blocker:

- Azure CLI API token acquisition for the PatchForge API returns AADSTS65001 for the Azure CLI application. Use browser/MSAL for protected UI validation until the API token consent issue is resolved.

## Remaining Gaps

- PF-AZ11 signed-in end-user UAT is not yet claimed.
- Fresh PF-AZ11 report-generation proof is not yet claimed.
- Customer production validation is not claimed.
- Live scanner integrations are not implemented and remain outside the current product boundary.
- Patch deployment is not implemented and remains prohibited.
- Exploit generation is not implemented and remains prohibited.
- Bayesian prior updates remain dry-run/proposal-only.
- Vendor and threat intelligence remains source-bound until reviewed.

These are not blockers for the governed PatchForge product boundary, but they are blockers for claiming a fully validated PF-AZ11 release.

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, autonomously approve CAB decisions, autonomously accept risk, or autonomously close evidence gates.

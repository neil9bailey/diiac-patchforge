# PF-AZ10 Simplified Experience Evidence

Date: 2026-05-30

Release: `PF-AZ10-SIMPLIFIED-EXPERIENCE`

Image tag: `pfaz10-20260530-e728ec0`

Commit: `e728ec0`

## Scope

PF-AZ10 simplified PatchForge around five customer-facing areas:

- Global Security Action Center
- Customer Estate
- Ask PatchForge
- Reports & Packs
- Admin

It added deterministic global CVE/advisory search, Customer Estate free-text extraction and matching, Patch Compare, advisory-only Ask PatchForge answers, and consolidated signed reports/packs.

## Validation Summary

- Local syntax, backend tests, frontend tests/build, Python tests, IaC validation, Bicep build, and Docker build smoke: PASS
- GitHub push to `origin/main`: PASS
- ACR image build/push for frontend, bridge/API, runtime, SRA, worker, and scheduler: PASS
- Azure Container Apps update: PASS
- UI/API HTTP smoke and unauthenticated protected-route check: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io` with `PatchForge.Admin`: PASS
- Live Global Security Action Center catalogue/search/detail validation: PASS
- Live Customer Estate extraction, asset confirmation, matching, and Patch Compare: PASS
- Live Ask PatchForge advisory response validation: PASS
- Live signed pack generation, verification, DOCX/PDF export, and report review: PASS
- Production validation records removed after evidence capture: PASS
- Temporary PostgreSQL firewall rule removal verified: PASS

## Evidence Files

- `deploy-apply/acr-tags-e728ec0.json`
- `deploy-apply/active-revisions-e728ec0.json`
- `deploy-apply/containerapp-image-update-results-final.json`
- `live-ui/http-smoke-e728ec0.json`
- `live-ui/live-validation-summary-e728ec0.json`
- `live-ui/postgres-validation-cleanup-e728ec0.json`
- `live-ui/postgres-cleanup-firewall-final-e728ec0.json`
- `live-ui/pfaz10-e728ec0-reports-packs-final.png`
- `reports/PF-20260530-02cd95b4.json`
- `reports/PF-20260530-02cd95b4-customer-patch-governance-pack.docx`
- `reports/PF-20260530-02cd95b4-customer-patch-governance-pack.pdf`
- `reports/PF-20260530-02cd95b4-board-vulnerability-remediation-summary.docx`
- `reports/PF-20260530-02cd95b4-board-vulnerability-remediation-summary.pdf`
- `reports/PF-20260530-02cd95b4-cab-patch-decision-report.docx`
- `reports/PF-20260530-02cd95b4-cab-patch-decision-report.pdf`
- `reports/PF-20260530-02cd95b4-report-review.json`

## Boundary

PF-AZ10 does not add vulnerability scanning, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

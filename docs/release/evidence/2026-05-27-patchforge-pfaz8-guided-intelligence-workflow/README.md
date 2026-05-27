# PF-AZ8 Guided Intelligence Workflow Evidence

This folder records PF-AZ8 local validation, Azure rollout, and signed-in live UI/API validation evidence for the guided PatchForge user workflow and decision-grade report upgrade.

Scope:

- Action Center, Finding Detail, Review & Approve, and Reports & Packs UI flow.
- Human-readable finding intelligence API.
- Decision-grade DOCX/PDF report generation.
- Signed-pack support for `finding_intelligence_snapshot.json`.

Local report QA:

- Sample board DOCX: `report-qa/PF-20260527-AZ8QA-board_vulnerability_remediation_summary.docx`
- Sample board PDF: `report-qa/PF-20260527-AZ8QA-board_vulnerability_remediation_summary.pdf`
- Sample CAB DOCX: `report-qa/PF-20260527-AZ8QA-cab_patch_decision_report.docx`
- Sample CAB PDF: `report-qa/PF-20260527-AZ8QA-cab_patch_decision_report.pdf`
- Word-rendered board PDF: `report-qa/word-render-board.pdf`
- Rendered page PNGs: `report-qa/render-board-word/page-1.png` through `page-5.png`

Azure rollout evidence:

- ACR tag verification: `build-push/acr-tag-verification.json`
- Deployment what-if output: `deploy-plan/what-if-output.txt`
- Container App active revisions before and after update: `deploy-apply/`
- Image tag: `pfaz8-20260527-cc708fd`

Live UI/API evidence:

- UI/API smoke: `live-ui/live-api-smoke.json`
- Signed-in workflow summary: `live-ui/ui-smoke-summary.json`
- Protected pack/report export smoke: `live-ui/live-protected-output-smoke.json`
- Key Vault signing smoke: `live-ui/keyvault-signing-smoke.json`
- PostgreSQL readiness smoke: `live-ui/postgres-smoke.json`
- Browser screenshots: `live-ui/browser-screenshots/`

Visual QA result:

- PASS. The Word-rendered board report pages were inspected after rasterisation.
- No clipping, overlap, broken tables, missing text, or orphan note page observed.
- LibreOffice/soffice was not available for the packaged renderer, so Microsoft Word automation was used for the DOCX to PDF render step and PyMuPDF was used for PNG rasterisation.

Boundary:

- No scanner, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance capability is added by PF-AZ8.

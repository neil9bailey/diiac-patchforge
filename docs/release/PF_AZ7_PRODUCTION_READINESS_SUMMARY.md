# PF-AZ7 Production Readiness Summary

Date: 2026-05-27

PF-AZ7 is live for operational customer demonstrations using live public-source intelligence, signed decision packs, and professional DOCX/PDF board outputs.

## Implemented

- DOCX report generation from signed decision packs.
- PDF report generation from signed decision packs.
- Report catalogue API.
- Protected report download endpoints.
- UI Reports page for board, CAB, customer, risk, and OT report exports.
- Decision Packs DOCX/PDF export actions.
- Scheduler mode for automated live CISA KEV refresh and FIRST EPSS enrichment.
- Scheduler lineage and boundary controls.
- IaC baseline update to keep the scheduler Container App active.

## Document Output Standard

Customer-facing board packs and reports are generated as DOCX and PDF. Markdown is not used as the customer-facing report format.

The local PF-AZ7 board-pack QA sample used real public-source CVE context for `CVE-2026-48172`. It was rendered through Microsoft Word to PDF and rasterized to page PNGs for visual inspection. No clipping, overlap, broken tables, missing text, or unreadable wrapping was observed.

Evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/doc-qa/`

## Local Readiness

- Backend/SRA tests: PASS.
- Python runtime/contract tests: PASS.
- Frontend tests: PASS.
- Frontend production build: PASS.
- IaC validation: PASS.
- Bicep build: PASS.
- Docker build smoke: PASS.
- DOCX/PDF visual QA: PASS.

## Boundaries

PatchForge remains a governance product only. PF-AZ7 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

## Azure Validation

- Image tag: `pfaz7-20260527-71643ce`.
- Active UI revision: `ca-patchforge-ui-prod--0000009`.
- Active bridge/API revision: `ca-patchforge-bridge-prod--0000008`.
- Active runtime revision: `ca-patchforge-runtime-prod--0000007`.
- Active SRA revision: `ca-patchforge-sra-prod--0000006`.
- Active worker revision: `ca-patchforge-worker-prod--0000006`.
- Active scheduler revision: `ca-patchforge-scheduler-prod--0000006`.
- Live UI validation as `n.bailey@diiac.io`: PASS.
- Displayed role `PatchForge.Admin`: PASS.
- Live API readiness with PostgreSQL and auth required: PASS.
- Fresh signed pack: `PF-20260527-54588be9`.
- Key Vault signing through live pack export: PASS.
- Live DOCX/PDF report download and visual QA: PASS.

Evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`

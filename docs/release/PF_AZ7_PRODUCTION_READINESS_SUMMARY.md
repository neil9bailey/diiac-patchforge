# PF-AZ7 Production Readiness Summary

Date: 2026-05-27

PF-AZ7 prepares PatchForge for operational customer demonstrations using live public-source intelligence, signed decision packs, and professional DOCX/PDF board outputs.

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

## Azure Readiness

Azure deployment and live UI validation are pending for this candidate and must be recorded before PF-AZ7 is marked live.

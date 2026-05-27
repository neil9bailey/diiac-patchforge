# PF-AZ8 Guided Intelligence Workflow Evidence

This folder records PF-AZ8 local validation evidence for the guided PatchForge user workflow and decision-grade report upgrade.

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

Visual QA result:

- PASS. The Word-rendered board report pages were inspected after rasterisation.
- No clipping, overlap, broken tables, missing text, or orphan note page observed.
- LibreOffice/soffice was not available for the packaged renderer, so Microsoft Word automation was used for the DOCX to PDF render step and PyMuPDF was used for PNG rasterisation.

Boundary:

- No scanner, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance capability is added by PF-AZ8.

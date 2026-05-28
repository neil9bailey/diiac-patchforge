# PF-AZ9A VendorLens Report Proof Evidence

Date: 2026-05-28

This folder records the PF-AZ9A release-clarity and report-proof increment.

Scope:

- Release naming cleanup: the VendorLens baseline is consistently recorded as `PF-AZ9-VENDORLENS`.
- Earlier operational-health release records are renamed to `PF-AZ9-OPS`.
- Current generated reports include mandatory version stamping.
- Fresh local report proof was generated from signed pack `PF-20260527-2d9f160a`, not stale pack `PF-20260526-8312f908`.

Local report proof:

- `local-reports/current-report-proof-qa.json` records structural proof for customer, board, and CAB DOCX/PDF reports.
- The generated reports include `report_template_version`, `renderer_commit`, `image_tag`, `generated_from_pack_id`, `generated_at`, `product_baseline`, and `report_context_version`.
- The generated reports include Network Vendor Applicability, Customer Configuration Context, and SRA/AIP Chat Summary sections.
- Final approval remains not issued.
- Exploit instructions, patch deployment implication, the old autonomous-analysis wording, and unsupported "not vulnerable" claims are absent.

Local visual render note:

- `documents/render_docx.py` was invoked for all three local DOCX reports.
- The local render gate could not complete because the DOCX-to-PDF converter executable was not available in this Windows environment.
- Structural DOCX/PDF proof passed locally; live UI/API report export and inspection must be completed after Azure deployment before PF-AZ9A is marked complete.

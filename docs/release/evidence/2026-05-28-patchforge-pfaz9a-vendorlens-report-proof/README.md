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
- Structural DOCX/PDF proof passed locally.

Live validation:

- Azure image tag: `pfaz9a-20260528-1a98433`.
- Live browser/MSAL sign-in: PASS as `n.bailey@diiac.io` with `PatchForge.Admin`.
- Live signed pack generated from existing source-bound `CVE-2026-48172`: `PF-20260528-9a653d50`.
- Live report exports: customer, board, and CAB DOCX/PDF all PASS.
- Report version stamping: PASS for `report_template_version`, `renderer_commit`, `image_tag`, `generated_from_pack_id`, `generated_at`, `product_baseline`, and `report_context_version`.
- VendorLens proof: Network Vendor Applicability, Customer Configuration Context, and SRA/AIP Chat Summary sections are present.
- Final approval remains not issued.
- Key Vault signing and pack verification: PASS.
- PostgreSQL readiness and live write path: PASS.

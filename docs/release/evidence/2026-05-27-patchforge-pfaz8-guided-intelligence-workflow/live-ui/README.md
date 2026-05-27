# PF-AZ8 Live UI Evidence

This folder records the signed-in production UI/API validation for PF-AZ8 after the Azure Container Apps image rollout to pfaz8-20260527-cc708fd.

Validated live paths:
- Microsoft Entra sign-in for 
.bailey@diiac.io with PatchForge.Admin visible in the UI.
- Action Center loaded from protected live APIs.
- Finding Detail rendered plain-English vulnerability intelligence.
- Review & Approve ran SRA advisory and retained human approval gates.
- A signed decision pack was generated: $(@{ok=True; captured_at=2026-05-27T03:00:12.713Z; signed_in_user_visible=True; admin_role_visible=True; pack_id=PF-20260527-9fc7f010; export_status=200; report_docx_status=200; report_pdf_status=200; report_docx_bytes=15342; report_pdf_bytes=9099; verification=; signing_provider=azure_key_vault; readiness_state=; final_approval_issued=False; artefact_keys=System.Object[]; boundary=}.pack_id).
- Protected pack export, DOCX report, and PDF report returned HTTP 200.
- Key Vault signing verification passed with manifest and signature checks.
- Admin health showed database, storage, Key Vault, signing trust, bridge, runtime, and frontend health.

Screenshots are under rowser-screenshots/. Tokens are not stored in this evidence set.

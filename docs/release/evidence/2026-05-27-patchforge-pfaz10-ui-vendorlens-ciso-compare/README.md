# PF-AZ10 Evidence

Date: 2026-05-27

Image tag: `pfaz10-20260527-513fea2`

Commit: `513fea2`

Scope:

- UI wrapping and pagination fixes.
- VendorLens clickable reference catalogue.
- NVD catalogue refresh without a single-CVE requirement.
- NVD public rate-limit handling.
- CISO patch-version comparison workflow and report artefact.

Evidence folders:

- `build-push/` records ACR image tag verification.
- `deploy-plan/` records Bicep what-if planning output.
- `deploy-apply/` records Container Apps image updates and active revisions.
- `live-ui/` records live HTTP/API smoke, browser screenshots, and UI validation notes.

No synthetic customer network asset was created in production.

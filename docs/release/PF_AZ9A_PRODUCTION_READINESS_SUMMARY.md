# PF-AZ9A Production Readiness Summary

Date: 2026-05-28

Status: PASS. PF-AZ9A is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

PF-AZ9A clarifies the VendorLens release line, renames the earlier operational-health release to `PF-AZ9-OPS`, and stamps every DOCX/PDF report with current renderer and image metadata.

## Live Baseline

- Image tag: `pfaz9a-20260528-1a98433`
- Commit: `1a98433`
- UI: `https://patchforge.diiac.io`
- API: `https://api.patchforge.diiac.io`
- Resource group: `rg-diiac-patchforge-prod`

## Validation

- Local backend, frontend, Python runtime, IaC, Bicep, and Docker gates: PASS
- GitHub push: PASS
- ACR image push: PASS for all six PatchForge images
- Targeted Container Apps update: PASS
- Live UI HTTP 200: PASS
- API readiness with PostgreSQL and Entra auth required: PASS
- Protected vulnerability route returns unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io` with `PatchForge.Admin`: PASS
- Fresh signed pack generated from existing source-bound `CVE-2026-48172`: `PF-20260528-9a653d50`
- Key Vault signing and pack verification: PASS
- Customer, board, and CAB DOCX/PDF exports: PASS

## Report Proof

The live DOCX/PDF reports include:

- `report_template_version`
- `renderer_commit`
- `image_tag`
- `generated_from_pack_id`
- `generated_at`
- `product_baseline`
- `report_context_version`

The live reports also include VendorLens Network Vendor Applicability, Customer Configuration Context, and SRA/AIP Chat Summary sections. Final approval remains not issued.

## Boundary

PF-AZ9A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

## Evidence

Evidence is recorded under `docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/`.

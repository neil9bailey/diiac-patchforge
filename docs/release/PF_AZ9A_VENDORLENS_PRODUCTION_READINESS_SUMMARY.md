# PF-AZ9A-VENDORLENS Production Readiness Summary

Date: 2026-05-28

Status: READY FOR DEMO and READY FOR NEXT AZURE RELEASE. This is DIIaC live platform validation, not third-party customer production validation.

## Release Identity

- Current active baseline: `PF-AZ9A-VENDORLENS`
- Previous live VendorLens baseline: `PF-AZ9-VENDORLENS`
- Historical operational-health baseline: `PF-AZ9-OPS-HISTORICAL`
- Image tag: `pfaz9a-20260528-923b386`
- Renderer commit: `923b386`
- Live signed pack proof: `PF-20260528-9e896f66`

## Azure State

- Deployment performed: yes
- Uses existing Azure resources: yes
- New Azure resources created in this increment: no
- Resource group: `rg-diiac-patchforge-prod`
- UI: `https://patchforge.diiac.io`
- API: `https://api.patchforge.diiac.io`
- Storage: PostgreSQL
- Auth: Microsoft Entra RBAC required
- Signing: Azure Key Vault

## Validation Summary

- Local tests and builds: PASS
- Docker build smoke: PASS
- ACR build and push: PASS
- Azure Container Apps image update: PASS
- Live UI/API smoke: PASS
- Browser/MSAL sign-in as PatchForge.Admin: PASS
- VendorLens workflow: PASS
- Signed pack generation and verification: PASS
- DOCX/PDF customer, board, and CAB report proof: PASS
- Report version stamping: PASS
- Temporary production validation data cleanup: PASS

## Boundary

PF-AZ9A does not add vulnerability scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

Evidence path: `docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/`

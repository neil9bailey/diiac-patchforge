# PatchForge Rebuild Evidence

Date: 2026-06-01

Branch: `codex/patchforge-rebuild-20260601`

Restore tag: `restore/pre-patchforge-rebuild-a4384cc-20260601`

Status: local implementation and validation evidence captured. No Azure deployment was performed.

## Scope

This evidence folder covers the PatchForge rebuild programme started on 2026-06-01. It expands PatchForge into seven top-level product areas:

- Security Action Center
- Vendors & Exploits Register
- Customer Estate
- Patch / Hotfix Compare
- Ask PatchForge
- Reports & Signed Action Packs
- Admin / Assurance

The rebuild remains source-bound, advisory-only, tenant-scoped, and human-approved. It does not add exploit generation, procedural exploit content, vulnerability scanning, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance.

## Evidence Files

- `PF0_REPO_AZURE_DISCOVERY.md` - repository identity, Azure topology references, restore point, and starting tree.
- `PATCHFORGE_PURGE_PLAN.md` - purge strategy, preservation boundaries, typed confirmations, and production mutation guardrails.
- `../../../product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md` - canonical catalogue-first rebuild blueprint.
- `PF13_TRACEABILITY_MATRIX.md` - programme requirement mapping to implementation files and tests.
- `PF13_PRODUCTION_READINESS_PACK.md` - readiness posture, validation results, known gates, and release constraints.
- `AZURE_DEPLOYMENT_UPDATE_RUNBOOK.md` - deployment update procedure to use only after explicit deployment approval.
- `LIVE_UI_VALIDATION_RUNBOOK.md` - local and post-deploy UI validation checklist for the seven-area shell.

## Local Validation

- Backend API: `npm test` from `backend-api` - PASS, 43 tests.
- Frontend unit tests: `npm test` from `Frontend` - PASS, 10 tests.
- Frontend production build: `npm run build` from `Frontend` - PASS, with Vite large chunk warning.
- Contract schemas: `python -m pytest tests\test_contracts.py` - PASS, 9 tests.
- Runtime reports/governance tests: `python -m pytest runtime\tests` - PASS, 18 tests.
- Local browser smoke at `http://127.0.0.1:5180/` - PASS for unauthenticated sign-in boundary, brand, product boundary copy, and zero browser console errors.

## Release Boundary

This evidence set is suitable for review and deployment planning. It is not proof of production deployment. Live Azure validation, ACR image publication, Container Apps revision updates, and production smoke evidence must be captured in a later deploy-approved evidence folder.

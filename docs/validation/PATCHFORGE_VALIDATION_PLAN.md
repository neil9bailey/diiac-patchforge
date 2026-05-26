# PatchForge Validation Plan

## Scope

This plan validates the local PatchForge baseline through PF-E10.

## Validation Gates

1. Product boundary documents exist and repeat the no-scanner, no-exploit, no-deployment, no-autonomous-approval boundary.
2. Azure IaC builds locally and does not deploy resources.
3. Domain schemas and evidence models load.
4. Backend API tests pass.
5. Runtime governance and signed pack tests pass.
6. Frontend tests and production build pass.
7. SRA advisory tests pass.
8. Decision Control Center tests pass.
9. Report rendering tests pass.
10. Demo seed data parses.

## Commands

```powershell
python -m pytest -q --basetemp .pytest_tmp
npm test
npm --prefix Frontend test
npm --prefix Frontend run build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1
```

## Azure Gate

Do not run deployment create/apply commands until the user confirms Azure tenant, subscription, target region, signing approach, and DNS plan.


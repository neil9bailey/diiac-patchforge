# PF13 Production Readiness Pack

Date: 2026-06-01

Readiness state: locally ready for deployment review. Production deploy remains gated.

## Product State

PatchForge now presents a seven-area operational shell:

- Security Action Center for grouped, searchable CVE/advisory exposure work.
- Vendors & Exploits Register for source-bound vendor, CVE, KEV, EPSS, patch, exploit-signal, and evidence confidence review.
- Customer Estate for device and asset evidence intake.
- Patch / Hotfix Compare for human-approved remediation option comparison.
- Ask PatchForge for defensive, source-bound answers.
- Reports & Signed Action Packs for exportable governance packs.
- Admin / Assurance for configuration, readiness, and trust boundaries.

The product mark in the shell is `PatchForge Intelligence by DIIaC`.

## Local Validation Results

| Check | Command | Result |
| --- | --- | --- |
| Backend API tests | `npm test` from `backend-api` | PASS, 43 tests |
| Frontend unit tests | `npm test` from `Frontend` | PASS, 10 tests |
| Frontend production build | `npm run build` from `Frontend` | PASS, Vite large chunk warning only |
| Contract schemas | `python -m pytest tests\test_contracts.py` | PASS, 9 tests |
| Runtime tests | `python -m pytest runtime\tests` | PASS, 18 tests |
| Local browser smoke | `http://127.0.0.1:5180/` | PASS for unauthenticated sign-in boundary, brand, product boundary copy, and zero browser console errors |

## Implementation Summary

- Added fixture-backed source adapters for NVD, CISA KEV, FIRST EPSS, CVE Services, GitHub Advisory, and vendor advisory sources.
- Added source normalization with source URL, source hash, fetched time, freshness, confidence, source type, and pending human review.
- Added config redaction and parser evidence for Cisco, Fortinet, Palo Alto, Juniper, Windows, Linux, VMware, and generic key-value inputs.
- Added customer, estate, asset, config evidence, exposure match, patch action, patch compare, signed action pack, and workflow storage collections.
- Added deterministic priority scoring and patch/hotfix comparison outputs.
- Added workflow item creation and state transitions with audit trail.
- Added signed action pack creation and verification using deterministic local digest semantics.
- Added defensive refusal handling for offensive Ask PatchForge requests.
- Added contract schemas for the rebuild domain model set.
- Expanded frontend navigation and report/action-pack labels to match the seven-area shell.

## Data And Safety Controls

- Safe synthetic data only was used in tests.
- Config uploads store redacted content and a hash of the raw upload, not raw secret values.
- Source adapters strip unsafe exploit mechanics from normalized summaries.
- Ask PatchForge refuses requests for exploit code, payloads, bypass instructions, or attacker playbooks.
- PatchForge remains advisory-only and does not scan, exploit, deploy patches, mutate Azure resources, approve CAB changes, or accept risk.
- Human review and approval flags are present in priority, compare, action pack, and workflow responses.

## Tenant And Access Controls

- Existing Entra role model remains in place.
- Tenant context resolution remains enforced in backend routes.
- New collections are tenant-scoped through the same storage abstraction.
- Admin / Assurance remains visible in the shell but locked for non-admin users.

## Deployment Readiness

Ready for deployment planning:

- Code builds locally.
- Automated backend, frontend, contract, and runtime tests pass.
- Restore tag exists for the pre-rebuild commit.
- Deployment runbook exists in this evidence folder.

Not yet complete:

- No ACR images were built or pushed for this branch.
- No Azure Container Apps revisions were updated for this branch.
- No live custom-domain smoke was performed for this branch.
- No signed-in production UI validation was performed for this branch.
- Local browser validation did not authenticate through Microsoft; signed-in seven-area interaction is covered by frontend component tests and must be repeated in production after deployment approval.

## Release Recommendation

Proceed to deployment only after explicit deploy approval. Use `AZURE_DEPLOYMENT_UPDATE_RUNBOOK.md` for build, push, what-if, update, smoke, and rollback evidence capture.

## Canonical Blueprint Reconciliation Update

Update timestamp: 2026-06-01T21:15:00+01:00

Canonical blueprint: `docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md`

Current top-level product shell:

- Security Action Center
- Vendors & Exploits Register
- Customer Operational Assets
- Patch / Hotfix Compare
- Ask PatchForge
- Reports
- Admin, presented as System & Data Health

Additional implementation since the original readiness pack:

- PF0 blueprint and validation script committed.
- PF1 navigation and operational guide aligned to the catalogue-first blueprint.
- PF2 factory reset and purge controls added with dry-run, typed confirmation, Admin-only execution, and local JSON CLI reset support.
- PF3 source adapters expanded to the blueprint vendor/source set through deterministic fixtures, not restricted scraping.
- PF4 Vendors & Exploits Register API aliases added.
- PF5 Customer Operational Assets API aliases added and used by the frontend.
- PF11 Reports API aliases added and used by the frontend.

Current validation results:

| Check | Command | Result |
| --- | --- | --- |
| Syntax checks | `node --check` on backend server/auth/source/search/report/config/vendor/scheduler/SRA modules | PASS |
| Blueprint validation | `python scripts\validate_patchforge_blueprint.py` | PASS |
| Factory reset compile | `python -m py_compile scripts\patchforge_factory_reset.py` | PASS |
| Factory reset dry-run | `python scripts\patchforge_factory_reset.py --reports --dry-run` | PASS |
| Backend tests | `npm --prefix backend-api test` | PASS, 44 tests |
| Frontend tests | `npm --prefix Frontend test` | PASS, 10 tests |
| Frontend build | `npm --prefix Frontend run build` | PASS, Vite large chunk warning only |
| Python tests | `python -m pytest -q --basetemp .pytest_tmp` | PASS, 27 tests |
| IaC validation | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\validate_iac.ps1` | PASS, no deployment run |
| Bicep build | `az bicep build --file infra\bicep\main.bicep` | PASS, Bicep update warning only |

No Azure deployment, ACR image push, production purge, production data mutation, GitHub push, or live UI validation was performed during this reconciliation pass.

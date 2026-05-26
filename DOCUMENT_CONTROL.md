# Document Control

## Product

DIIaC™ PatchForge

## Control Summary

| Document | Owner | Status | Version | Date |
| --- | --- | --- | --- | --- |
| README.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| CURRENT_RELEASE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| RELEASE_BASELINE_MANIFEST.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| CODEX_WORKING_MEMORY.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_MASTER_WORKING_BRIEF.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_PRODUCT_POSITIONING.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_PRODUCT_BOUNDARY.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_INTENDED_USE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_CLAIMS_MATRIX.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_BOUNDARY_MATRIX.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_ARCHITECTURE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_AZURE_ARCHITECTURE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_SECURITY_MODEL.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_IMPLEMENTATION_PROGRAMME.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_EPIC_TRACKER.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_EPIC_BACKLOG.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/main.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/container-apps.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/storage.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/keyvault.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/postgres-or-sql.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/monitoring.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/parameters/prod.bicepparam | DIIaC | Placeholder | 0.1.0 | 2026-05-26 |
| scripts/validate_iac.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/plan_azure_deployment.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/build_push_images.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/*.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/evidence_models.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| tests/test_contracts.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| package.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/server.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/patchforge/storage.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/patchforge-api.test.mjs | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/governance_runtime.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/tests/test_governance_runtime.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/package.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/src/App.tsx | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/src/styles.css | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/src/App.test.tsx | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| customer-config/demo/admin_config.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/sra/securityResearchAgent.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/sra/securityResearchAgent.test.mjs | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/decision_control_center.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/tests/test_decision_control_center.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |

## Change Control

All substantive changes should be made through the PatchForge implementation programme and committed with a PF epic prefix where practical.

## Boundary Control

PatchForge must retain a clear product boundary in product docs, UI surfaces, reports, decision packs, and admin configuration:

- no exploit generation
- no patch deployment
- no production mutation
- no autonomous CAB
- no autonomous risk acceptance
- no replacement claim for scanner, SIEM/SOAR, ITSM, CMDB, EDR/XDR, or OT engineering systems

# Document Control

## Product

DIIaC™ PatchForge

## Control Summary

The current live controlled baseline is the `f51802d` six-image `PF-AZ-ENTERPRISE-AUTOMATION-20260714D` rollout. Overall release acceptance remains **partial**. The closeout branch locally fixes/tests report verification and implements/tests navigation, verified ZIP, server-issued tenant-scoped token cleanup, and repaired IaC; none is live. Its separate validation is Python 53/53, backend 94/94, frontend 28/28, Playwright/axe 2/2, collector 8/8, frontend build/bundle PASS, and IaC PASS; deployed `f51802d` totals remain unchanged. The What-If has 0 destructive, 0 image, and 0 environment-removal changes; its only scale delta is scheduler `min0→1`, required by the in-process timer. Thirteen unsupported resources keep it not fully determinate. Production report acceptance, live UAT, full apply under exact approval, collector/customer acceptance, and legal/licensing closure remain open.

| Document | Owner | Status | Version | Date |
| --- | --- | --- | --- | --- |
| README.md | DIIaC | Active | 0.4.0 | 2026-07-14 |
| CURRENT_RELEASE.md | DIIaC | Active | 3.0.0 | 2026-07-14 |
| RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 3.0.0 | 2026-07-14 |
| QUALITY_GATES_REPORT.json | DIIaC | Active | 2.0.0 | 2026-07-14 |
| VALIDATION_OUTPUTS.md | DIIaC | Active | 2.0.0 | 2026-07-14 |
| PATCHFORGE_OPEN_GAPS_REGISTER.md | DIIaC | Active | 2.0.0 | 2026-07-14 |
| governance/adr/ADR-PF-AZ12-001-operational-intelligence-value.md | DIIaC | Approved | 0.1.0 | 2026-06-04 |
| docs/features/VENDORLENS_NETWORK_VENDOR_INTELLIGENCE.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/product/VENDORLENS_PRODUCT_BOUNDARY.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/operations/VENDORLENS_OPERATOR_GUIDE.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ9_VENDORLENS_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.2.0 | 2026-05-27 |
| docs/release/PF_AZ9_VENDORLENS_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.2.0 | 2026-05-27 |
| docs/release/PF_AZ10_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ10_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ9A_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-28 |
| docs/release/PF_AZ9A_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-28 |
| docs/release/PF_AZ9A_VENDORLENS_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-28 |
| docs/release/PF_AZ9A_VENDORLENS_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-28 |
| docs/release/evidence/2026-05-30-patchforge-pfaz10-simplified-experience/** | DIIaC | Evidence | 0.1.0 | 2026-05-30 |
| docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/** | DIIaC | Evidence | 0.1.0 | 2026-05-28 |
| CODEX_WORKING_MEMORY.md | DIIaC | Active | 0.5.0 | 2026-05-26 |
| docs/product/PATCHFORGE_MASTER_WORKING_BRIEF.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_PRODUCT_POSITIONING.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_PRODUCT_BOUNDARY.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_INTENDED_USE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_CLAIMS_MATRIX.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/product/PATCHFORGE_BOUNDARY_MATRIX.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_ARCHITECTURE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_AZURE_ARCHITECTURE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_SECURITY_MODEL.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/architecture/PATCHFORGE_MCP_AGENT_INTELLIGENCE.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_IMPLEMENTATION_PROGRAMME.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_EPIC_TRACKER.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/epics/PATCHFORGE_EPIC_BACKLOG.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/main.bicep | DIIaC | Updated | 0.3.0 | 2026-05-26 |
| infra/bicep/container-apps.bicep | DIIaC | Updated | 0.3.0 | 2026-05-27 |
| infra/bicep/container-registry.bicep | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| infra/bicep/identity.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/storage.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/keyvault.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/bicep/postgres-or-sql.bicep | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| infra/bicep/monitoring.bicep | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| infra/parameters/prod.bicepparam | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| scripts/validate_iac.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/plan_azure_deployment.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/deploy_azure_bootstrap.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/build_push_images.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/configure_entra_apps.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/*.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/evidence_models.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| tests/test_contracts.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| package.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/package.json | DIIaC | Updated | 0.3.0 | 2026-05-27 |
| backend-api/package-lock.json | DIIaC | Updated | 0.2.0 | 2026-05-27 |
| backend-api/server.js | DIIaC | Updated | 0.6.0 | 2026-05-30 |
| backend-api/patchforge/intelligence.js | DIIaC | Active | 0.2.0 | 2026-05-27 |
| backend-api/patchforge/searchIndex.js | DIIaC | Active | 0.1.0 | 2026-05-30 |
| backend-api/patchforge/reports.js | DIIaC | Active | 0.5.0 | 2026-05-30 |
| backend-api/patchforge/scheduler.js | DIIaC | Active | 0.1.0 | 2026-05-27 |
| backend-api/patchforge/configApplicability.js | DIIaC | Active | 0.1.0 | 2026-05-27 |
| backend-api/patchforge/vendorLens.js | DIIaC | Active | 0.3.0 | 2026-05-30 |
| backend-api/patchforge/storage.js | DIIaC | Updated | 0.3.0 | 2026-05-30 |
| backend-api/patchforge-api.test.mjs | DIIaC | Updated | 0.7.0 | 2026-05-30 |
| backend-api/patchforge/searchIndex.test.mjs | DIIaC | Active | 0.1.0 | 2026-05-30 |
| runtime/governance_runtime.py | DIIaC | Updated | 0.2.0 | 2026-05-27 |
| runtime/health_server.py | DIIaC | Updated | 0.2.0 | 2026-05-27 |
| runtime/tests/test_governance_runtime.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/package.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/src/App.tsx | DIIaC | Updated | 0.6.0 | 2026-05-30 |
| Frontend/src/api.ts | DIIaC | Updated | 0.5.0 | 2026-05-30 |
| Frontend/src/styles.css | DIIaC | Updated | 0.6.0 | 2026-05-30 |
| Frontend/src/App.test.tsx | DIIaC | Updated | 0.5.0 | 2026-05-30 |
| Frontend/src/test-setup.ts | DIIaC | Updated | 0.2.0 | 2026-05-27 |
| customer-config/default/admin_config.json | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| backend-api/sra/securityResearchAgent.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/sra/securityResearchAgent.test.mjs | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/decision_control_center.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/tests/test_decision_control_center.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/reports.py | DIIaC | Updated | 0.4.0 | 2026-05-30 |
| runtime/tests/test_reports.py | DIIaC | Updated | 0.3.0 | 2026-05-30 |
| docs/demos/PATCHFORGE_CUSTOMER_DEMONSTRATION_RUNBOOK.md | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| docs/release/evidence/patchforge-customer-demonstration/README.md | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| docs/validation/PATCHFORGE_VALIDATION_PLAN.md | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/validation/PATCHFORGE_READINESS_SUMMARY.md | DIIaC | Active | 1.0.0 | 2026-07-14 |
| docs/validation/PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md | DIIaC | Active | 1.0.0 | 2026-07-14 |
| docs/validation/PATCHFORGE_AUTOMATION_AND_UI_READINESS_REVIEW_2026-07-11.md | DIIaC | Active | 1.1.0 | 2026-07-14 |
| .github/workflows/ci.yml | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| .dockerignore | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| requirements-dev.txt | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| requirements-runtime.txt | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_DEPLOYMENT_READINESS.md | DIIaC | Updated | 1.0.0 | 2026-07-14 |
| docs/deployment/PATCHFORGE_AZURE_ACCESS_CHECKLIST.md | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_DIIAC_TENANT_REFERENCE.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_DNS_CUTOVER_CHECKLIST.md | DIIaC | Updated | 0.5.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_ENTRA_RBAC_CHECKLIST.md | DIIaC | Updated | 0.4.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_SIGNING_STRATEGY.md | DIIaC | Updated | 0.3.0 | 2026-05-26 |
| docs/deployment/PATCHFORGE_ROLLOUT_PLAN.md | DIIaC | Updated | 0.5.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-azure-bootstrap/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-azure-bootstrap/*.json | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-gates/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-gates/*.json | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-dns-cutover/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-dns-cutover/*.json | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-production-hardening/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-production-hardening/*.json | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-live-product/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-live-product/*.json | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-07-14-patchforge-enterprise-image-rollout/** | DIIaC | Evidence | 0.1.0 | 2026-07-14 |
| docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/README.md | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/** | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/PF_AZ5_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/release/PF_AZ5_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/release/PF_AZ6_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/release/PF_AZ6_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-26 |
| docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/** | DIIaC | Evidence | 0.1.0 | 2026-05-26 |
| docs/release/PF_AZ7_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ7_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/** | DIIaC | Evidence | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ8_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ8_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.1.0 | 2026-05-27 |
| docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/** | DIIaC | Evidence | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ9_OPS_RELEASE_BASELINE_MANIFEST.json | DIIaC | Historical | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ9_OPS_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Historical | 0.1.0 | 2026-05-27 |
| docs/release/evidence/2026-05-27-patchforge-pfaz9-operational-health-enablement/** | DIIaC | Evidence | 0.1.0 | 2026-05-27 |
| docs/release/PF_AZ8A_RELEASE_BASELINE_MANIFEST.json | DIIaC | Active | 0.2.0 | 2026-05-27 |
| docs/release/PF_AZ8A_PRODUCTION_READINESS_SUMMARY.md | DIIaC | Active | 0.2.0 | 2026-05-27 |
| docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/** | DIIaC | Evidence | 0.1.0 | 2026-05-27 |
| docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/** | DIIaC | Evidence | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_vendor_profile.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_product_family.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_product_model.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_firmware_version.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/vendor_security_advisory.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/vendor_cve_mapping.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/customer_network_asset.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_config_feature.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/config_applicability_assessment.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/network_vendor_patch_posture.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/sra_config_chat_session.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/sra_config_chat_message.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| contracts/domain-models/patchforge/vendorlens_decision_context.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-27 |
| runtime/bayesian_patch_risk.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/bayesian_patch_risk_snapshot.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/patch_prior_usage_manifest.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/patch_prior_update_proposal.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/patch_learning_telemetry_snapshot.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/vendor_profile.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/product_profile.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/vendor_advisory.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/threat_landscape_signal.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/vendor_intelligence_snapshot.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/source_feed_manifest.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| contracts/domain-models/patchforge/source_feed_run.schema.json | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/Dockerfile | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/public/patchforge-config.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/patchforge/sourceFeeds.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/src/auth.tsx | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| Frontend/nginx.conf | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| backend-api/Dockerfile | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| backend-api/auth.js | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| runtime/Dockerfile | DIIaC | Updated | 0.2.0 | 2026-05-26 |
| runtime/health_server.py | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| compose.yaml | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/start_local_dev.ps1 | DIIaC | Baseline | 0.1.0 | 2026-05-26 |
| scripts/build_push_images.ps1 | DIIaC | Updated | 0.2.0 | 2026-05-26 |

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

# PF-AZ9-VENDORLENS Production Readiness Summary

Date: 2026-05-27

Status: DEPLOYED TO AZURE AND LIVE VALIDATED.

PF-AZ9-VENDORLENS adds a dedicated Network Vendor Intelligence and Config-Aware Patch Advisor to PatchForge. It is designed to help users understand whether public vendor/CVE intelligence applies to their actual customer estate, product model, firmware version, enabled features, exposure posture, and reviewed evidence.

## Completed Locally

- Network/security vendor catalogue for Cisco, Fortinet, Palo Alto Networks, Juniper, F5, Citrix / NetScaler, Check Point, Sophos, SonicWall, WatchGuard, Aruba / HPE, Ubiquiti, MikroTik, Barracuda, Zscaler, Cloudflare, and Akamai.
- Source-bound advisory ingest path for NVD CVE metadata, configured vendor RSS/JSON sources, and credential-gated Cisco PSIRT metadata.
- Customer network asset records with vendor, family, model, firmware, site, service owner, exposure, enabled features, disabled features, and evidence state.
- Configuration applicability engine that returns governed posture, urgency posture, evidence used, evidence missing, and human-review requirements.
- Ask PatchForge SRA/AIP chat API for config-aware questions.
- VendorLens UI page with Network Vendors, Product Families, Advisories & CVEs, Customer Estate Match, Config Applicability, Urgency & Recommended Posture, Ask PatchForge, Vendor Evidence Packs, and Admin: Vendor Sources tabs.
- Signed pack artefacts for network vendor profile, customer network asset, vendor security advisory, config applicability, SRA config chat, and VendorLens decision context.
- DOCX/PDF reports with Network Vendor Applicability, Customer Configuration Context, Affected Feature Assessment, Exposure Assessment, Evidence Required to Prove Not Applicable, Urgent Patch / Mitigation / Scope Confirmation Recommendation, and SRA/AIP Chat Summary.

## Local Validation

- Backend syntax: PASS
- Backend tests: PASS, 27 tests
- Frontend tests: PASS, 11 tests
- Frontend build: PASS
- Python runtime tests: PASS, 26 tests
- IaC validation: PASS
- Bicep build: PASS
- Docker frontend, bridge/API, and runtime build smoke: PASS
- Local DOCX/PDF report generation: PASS
- Local DOCX structural wording checks: PASS

DOCX-to-PNG visual rendering could not be completed locally because LibreOffice/soffice is unavailable on PATH. The live exported board report passed DOCX structural QA for VendorLens sections, final-approval wording, and boundary wording after Azure deployment.

## Boundary

VendorLens is source-bound advisory intelligence. It does not verify customer configuration unless evidence is attached and reviewed. It does not approve patching, risk acceptance, not-applicable status, CAB decisions, or closure automatically. It does not provide exploit steps or deploy patches.

## Azure State

PF-AZ9-VENDORLENS is deployed to Azure Container Apps using image tag `pfaz9-20260527-e8a0de2` from commit `e8a0de2`.

Active revisions:

- UI: `ca-patchforge-ui-prod--0000013`
- Bridge/API: `ca-patchforge-bridge-prod--0000012`
- Runtime: `ca-patchforge-runtime-prod--0000011`
- SRA: `ca-patchforge-sra-prod--0000010`
- Worker: `ca-patchforge-worker-prod--0000010`
- Scheduler: `ca-patchforge-scheduler-prod--0000010`

Live validation:

- UI HTTP 200: PASS
- API readiness HTTP 200 with PostgreSQL storage and auth required: PASS
- Protected VendorLens route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- VendorLens catalogue loaded: PASS
- Customer network asset, source-bound advisory, config applicability, and Ask PatchForge workflow: PASS
- Signed pack verification: PASS, `PF-20260527-2d9f160a`
- Key Vault signing: PASS, `azure_key_vault`
- PostgreSQL live write path: PASS
- Board DOCX/PDF report export with VendorLens sections: PASS

The validation asset, advisory, assessment, chat, decision pack, and linked audit records were removed from production PostgreSQL after evidence capture so no PF-AZ9 synthetic validation data remains in the live product. Evidence is retained under `docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/`.

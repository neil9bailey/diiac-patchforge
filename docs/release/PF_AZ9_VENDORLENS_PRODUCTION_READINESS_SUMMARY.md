# PF-AZ9 VendorLens Production Readiness Summary

Date: 2026-05-27

Status: LOCAL VALIDATED, AZURE DEPLOYMENT PENDING.

PF-AZ9 VendorLens adds a dedicated Network Vendor Intelligence and Config-Aware Patch Advisor to PatchForge. It is designed to help users understand whether public vendor/CVE intelligence applies to their actual customer estate, product model, firmware version, enabled features, exposure posture, and reviewed evidence.

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

DOCX-to-PNG visual rendering could not be completed locally because LibreOffice/soffice is unavailable on PATH. Live exported report files will be checked again after Azure deployment.

## Boundary

VendorLens is source-bound advisory intelligence. It does not verify customer configuration unless evidence is attached and reviewed. It does not approve patching, risk acceptance, not-applicable status, CAB decisions, or closure automatically. It does not provide exploit steps or deploy patches.

## Azure State

Azure deployment has not yet been performed for this VendorLens increment. The next gate is GitHub push, image build/push, Container Apps update, and live browser/MSAL validation at `https://patchforge.diiac.io`.

# PF13 Traceability Matrix

Date: 2026-06-01

Status: implemented locally and validated through automated local checks. No deployment performed.

## Programme Traceability

| Item | Requirement | Implementation evidence | Validation evidence | Status |
| --- | --- | --- | --- | --- |
| PF0 | Confirm repo identity, Azure topology, restore point, and safe starting tree. | `PF0_REPO_AZURE_DISCOVERY.md`, restore tag `restore/pre-patchforge-rebuild-a4384cc-20260601`. | Git discovery and PF0 commit `dcc2e65`. | Complete |
| PF1 | Rebuild shell to seven PatchForge top-level areas. | `Frontend/src/App.tsx`, `Frontend/src/App.test.tsx`. | Frontend tests and production build. | Complete |
| PF2 | Add source-bound public and vendor source adapter model. | `backend-api/patchforge/sourceAdapters.js`, `backend-api/server.js`, source feed storage collections. | Backend API test "PatchForge rebuild source adapters normalise fixture-backed intelligence". | Complete |
| PF3 | Normalize vendor, product, CVE, advisory, EPSS, KEV, and exploit signal metadata without unsafe content. | `sourceAdapters.js`, `contracts/domain-models/patchforge/vendor.schema.json`, `product.schema.json`, `cve.schema.json`, `exploit_signal.schema.json`. | Backend source adapter test; contract schema tests. | Complete |
| PF4 | Import and parse customer estates from CSV/manual input. | `backend-api/patchforge/configParsers.js`, `backend-api/server.js`, storage collections `customers`, `customer_assets`, `customer_estates`. | Backend tenant-scoped customer CSV import test. | Complete |
| PF5 | Redact configs and never persist raw secrets. | `configParsers.js`, `config_evidence.schema.json`. | Backend config redaction/parser test with synthetic secret. | Complete |
| PF6 | Match exposure using customer assets, configs, advisories, and source confidence. | `server.js`, storage collections `config_evidence`, `exposure_matches`, existing Customer Estate match functions. | Backend Customer Estate and rebuild API tests. | Complete |
| PF7 | Build deterministic priority index with KEV, EPSS, CVSS, exposure, criticality, patch maturity, confidence, and gaps. | `backend-api/patchforge/priority.js`, `patch_action.schema.json`. | Backend priority/index test. | Complete |
| PF8 | Compare direct patch, hotfix, major upgrade, workaround, compensating controls, and defer-with-exception options. | `priority.js`, `patch_compare_report.schema.json`, `Frontend/src/App.tsx`. | Backend patch compare test and frontend shell tests. | Complete |
| PF9 | Keep Ask PatchForge defensive and refuse exploit-code/payload/bypass requests. | `backend-api/patchforge/searchIndex.js`, Ask PatchForge UI copy. | Backend Ask PatchForge refusal test. | Complete |
| PF10 | Expand reports and signed action packs for CISO, SOC, vendor exposure, estate vulnerability, patch/hotfix, emergency, and monthly governance use cases. | `backend-api/patchforge/reports.js`, `runtime/reports.py`, `signed_action_pack.schema.json`. | Backend action pack tests; runtime report tests. | Complete |
| PF11 | Track workflow from review to verified fix with human approval. | `priority.js`, `server.js`, storage collection `workflow_items`. | Backend workflow transition test. | Complete |
| PF12 | Preserve tenant isolation and no autonomous production approval. | `server.js`, storage tenant scoping, UI role handling. | Existing auth/tenant tests plus customer asset tenant test. | Complete |
| PF13 | Capture readiness docs, validation results, and deployment gates. | This evidence folder. | Local validation commands listed in `PF13_PRODUCTION_READINESS_PACK.md`. | Complete |

## Safety Traceability

| Boundary | Evidence |
| --- | --- |
| No exploit generation or procedural exploit guidance | `searchIndex.js` refusal guard; backend Ask PatchForge refusal test; source adapters strip unsafe terms. |
| No patch deployment or production mutation | API returns comparison/action recommendations only; tests assert no exploit or patch deployment endpoints exist. |
| No autonomous CAB approval or risk acceptance | Priority, compare, packs, and workflow objects include human approval flags and final approval remains false. |
| No raw secret persistence | Config parser stores redacted config and upload hash only; backend redaction test checks the raw synthetic secret is absent. |
| Source-bound evidence | Source adapter records include source URL, source hash, freshness, confidence, fetched time, and pending review state. |
| Tenant isolation | Storage collections are tenant-scoped; auth and tenant tests remain passing. |

## Open Release Gates

- Production deploy approval is not granted in this evidence set.
- ACR build/push evidence is not captured for this branch.
- Azure Container Apps revision update evidence is not captured for this branch.
- Live custom-domain smoke and signed-in browser validation must be performed only after explicit deploy approval.

## Canonical Blueprint Reconciliation

Update timestamp: 2026-06-01T21:15:00+01:00

Canonical blueprint: `docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md`

| Epic | Current implementation evidence | Validation evidence | Status |
| --- | --- | --- | --- |
| PF0 | Blueprint, purge plan, docs index, README link, and restore tag `restore/pre-patchforge-rebuild-7d2a121-20260601`. | `python scripts\validate_patchforge_blueprint.py`; commit `75d5ff8`. | Complete |
| PF1 | Main nav is Security Action Center, Vendors & Exploits Register, Customer Operational Assets, Patch / Hotfix Compare, Ask PatchForge, Reports, Admin. | `npm --prefix Frontend test`; `npm --prefix Frontend run build`; commit `e16902d`. | Complete |
| PF2 | `scripts/patchforge_factory_reset.py`, `/api/patchforge/admin/purge`, dry-run counts, typed confirmation, System & Data Health controls. | Backend purge test; CLI dry-run; commit `e4dbd14`. | Complete |
| PF3 | Fixture-backed source adapters include NVD, CISA KEV, FIRST EPSS, GitHub Advisory, CVE Services, Microsoft MSRC, Cisco PSIRT, Fortinet PSIRT, Palo Alto, Juniper, VMware/Broadcom, Ivanti, Citrix, Linux, Apple, CISA alerts, and NCSC. | Backend source adapter test; commit `15c99dd`. | Complete |
| PF4 | Vendors & Exploits Register API aliases: `/api/patchforge/vendors-exploits-register`, `/search`, and `/cves/:id`. | Backend catalogue alias test; commit `15c99dd`. | Complete |
| PF5-PF7 | Customer Operational Assets API aliases now back the frontend: `/api/patchforge/customer-operational-assets/...`; existing parsers, redaction, and exposure matching remain tenant-scoped. | Backend customer operational asset alias test; frontend tests/build; commit `15c99dd`. | Complete |
| PF8-PF10 | Patch / Hotfix Compare and Ask PatchForge remain advisory-only, defensive, and human-review gated. | Existing backend patch compare and Ask PatchForge refusal tests. | Complete |
| PF11-PF12 | Reports API aliases `/api/patchforge/reports/overview` and `/api/patchforge/reports/generate`; signed action packs remain verifiable and final approval remains false unless human workflow records approval. | Backend reports alias and signed pack tests. | Complete |
| PF13 | Admin is System & Data Health with purge controls, source/data health, and no dead main-nav links. | Frontend Admin test; backend admin health/purge tests. | Complete |
| PF14 | Local validation completed. No deployment performed in this reconciliation pass. | Node checks, backend tests, frontend tests/build, Python tests, IaC validation, Bicep build. | Local complete; live gated |

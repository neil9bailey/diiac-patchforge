# PF-AZ-ENTERPRISE-AUTOMATION-20260714D Validation Outputs

## Current Validation Position

Date: 2026-07-14

Status: **PARTIAL PASS**. The guarded image-only Azure rollout succeeded for source `f51802d3544260259c252e6be88d6e7bae596868` and tag `pfaz-enterprise-20260714d-f51802d`. Production still runs that exact image state. The closeout branch locally fixes/tests the Azure EC/P-256 enum-label report mismatch and implements/tests navigation, verified ZIP, exact-ID cleanup, and repaired IaC; none of those follow-ups is live. Overall acceptance remains partial because the production DOCX path failed closed and live report/UAT/IaC-apply/collector/legal gates remain open.

Deployed `f51802d` candidate validation recorded before rollout — unchanged:

- Python: PASS, 39/39
- Backend API: PASS, 89/89
- Frontend: PASS, 24/24
- Playwright/axe: PASS, 2/2
- Windows collector: PASS, 8/8 plus lifecycle validation
- Container security: PASS, three unique images with zero high/critical findings

Closeout-branch validation — separate local evidence, not deployed:

- Python: PASS, 53/53
- Backend API: PASS, 94/94
- Frontend: PASS, 28/28
- Playwright/axe: PASS, 2/2
- Windows collector: PASS, 8/8
- Frontend build/bundle: PASS; entry `270.20 kB`, total JavaScript `634.39/650 kB`
- IaC: PASS

Release authorization and provenance:

- GitHub approval run `29345354677`, attempt `1`: PASS
- Exact commit/tag/baseline/report-context authorization: PASS
- Authorization SHA-256: `d5b7470d8f8b76eb0a152d1c805dc4964f30725b471a3474787ad3763a806007`
- GitHub attestation verification: PASS
- ACR exact-tag digest readback: PASS, six images
- Six-image ES256 provenance manifest: PASS
- Manifest SHA-256: `d9c8f265aaab5c7d10549f1730620a9681bb0b13ff10c8b870973f52c07b9615`
- Post-release temporary signing-key access revocation: PASS

Azure image rollout:

| Component | Digest | Active/latest-ready revision |
| --- | --- | --- |
| UI | `sha256:88377ddcc4afe164ddb4206429b737f97935d8636f4f5f9ced0e09f8e7b1ff87` | `ca-patchforge-ui-prod--0000041` |
| Bridge/API | `sha256:56a1b6b502594a5ebf18d0ab56467c2a2e2028fb4d0884d456542f864f3442bf` | `ca-patchforge-bridge-prod--0000040` |
| Runtime | `sha256:2b608109548e4596a8ab5195a17c0ac581cdf2fe4e0ed09cd4d2b9ec8fdf93ca` | `ca-patchforge-runtime-prod--0000031` |
| SRA | `sha256:44808c86c32816210d2086f173e77ff5b33bcf91c47fb578c2fb38c6f7fb994d` | `ca-patchforge-sra-prod--0000030` |
| Worker | `sha256:f0585c19fabbf5ce9bc6d7dec01f7915ee342ab7e524df9384323da1b4f63ded` | `ca-patchforge-worker-prod--0000030` |
| Scheduler | `sha256:11e58260e16c38636cfcc2804554ea58c4f3e954aa64a42b5075d60dba2af23f` | `ca-patchforge-scheduler-prod--0000030` |

Release completion readback:

- Six apps use the exact candidate image tag: PASS
- Succeeded/Healthy/Provisioned/latest-ready alignment: PASS, six apps
- Latest-revision traffic: PASS, 100% on six apps
- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with PostgreSQL/auth/tenant readiness: PASS
- Protected route unauthenticated HTTP 401: PASS

Signed-in Admin UAT:

- Microsoft Entra authenticated Admin session: PASS
- Displayed role `PatchForge.Admin`: PASS
- Admin health: PASS, 13/13 checks
- DOCX report generation in live `f51802d`: FAIL CLOSED, `signature_cryptographic_verification_failed`
- Root cause: Azure enum labels `KeyType.ec` / `KeyCurveName.p_256` were not normalized to standards-form `EC` / `P-256` before download verification
- Closeout fix: PASS locally; explicit supported-label normalization followed by unchanged full ES256 verification
- Negative cryptographic coverage: PASS locally for unknown aliases/curves, malformed coordinates, wrong keys, tampered signatures, and short signatures
- Production report acceptance: OPEN; fixed closeout source is not deployed and no fresh live report is accepted
- Ingestion navigation in live `f51802d`: OPEN GAP; closeout-branch fix implemented/tested locally, not live
- Verified ZIP UI journey in live `f51802d`: OPEN GAP; closeout-branch path implemented/tested locally, not live
- Production cleanup/absence proof: OPEN; local closeout cleanup uses a server-issued tenant-scoped expiring preview token plus SHA-256 exact-record-ID digest, displays exact IDs, retains audit, and fails closed on direct/cross-tenant/drift/reuse attempts
- Other role journeys: NOT EVIDENCED in this session

IaC/configuration disposition:

- Full Bicep apply: NOT PERFORMED
- Fresh repaired-IaC What-If: PASS across 43 resources — 0 destructive, 7 modify, 20 no-change, 3 ignore, and 13 unsupported
- Determinacy: PARTIAL; 13 unsupported resources require explicit resolution or approval before apply
- Semantic readback: 0 image changes, 0 environment removals, and one intentional scale delta — scheduler `minReplicas` `0→1` because its in-process timer must remain running
- Intended changes: release-metadata convergence on six apps and 12 probe additions across six apps
- Candidate images are current, but live release-metadata environment values still identify the July 11 baseline and commit; the current approval covered the image-only `f51802d` rollout, not the repaired-IaC apply
- Apply gate: separate exact approval for the closeout-branch source and reviewed configuration delta

Remaining human/external gates:

- trusted Windows collector signing;
- clean customer-machine and representative customer UAT;
- legal/licensing review and root license decision.

Sanitized evidence path:

`docs/release/evidence/2026-07-14-patchforge-enterprise-image-rollout/`

Boundary note: the successful image rollout does not add scanning, exploit generation, patch deployment, autonomous evidence approval, autonomous CAB approval, or autonomous risk acceptance, and it does not convert the partial UAT result into full product acceptance.

# PF-AZ11-CUSTOMER-DEMO-MATURITY Validation Outputs

## Current PF-AZ11 Validation Position

Date: 2026-06-04

Status: PARTIAL PASS. PF-AZ11-CUSTOMER-DEMO-MATURITY is deployed on Azure. Public UI/API smoke validation and signed-out browser validation passed. Full signed-in end-user UAT and fresh PF-AZ11 report proof remain pending.

Current image state:

- UI: `pfaz11-20260603-f56fd2b`
- Bridge/API, runtime, SRA, worker, scheduler: `pfrebuild-20260601-43f953c`

Validation completed:

- `npm --prefix Frontend test`: PASS, 10 tests for UI commit `f56fd2b`
- `npm --prefix Frontend run build`: PASS, Vite chunk-size advisory only
- UI HTTP 200 at `https://patchforge.diiac.io/`: PASS
- API health HTTP 200 at `https://api.patchforge.diiac.io/health`: PASS
- Protected Security Action Center route unauthenticated HTTP 401: PASS
- Browser signed-out shell renders `PatchForge Intelligence by DIIaC(TM)` without duplicate product wording: PASS
- Active UI revision `ca-patchforge-ui-prod--0000029` is healthy and serving 100 percent traffic: PASS

Validation not yet claimed:

- signed-in Microsoft Entra PatchForge.Admin seven-area UAT
- protected Ask PatchForge Juniper/CVE ambiguity validation in live UI
- fresh PF-AZ11 signed-pack generation
- fresh Customer Patch Governance Pack DOCX/PDF export and review
- fresh Board Vulnerability Summary DOCX/PDF export and review
- fresh CAB Patch Decision Report DOCX/PDF export and review
- production validation-record cleanup after any signed-in PF-AZ11 UAT records

Evidence path:

`docs/release/evidence/2026-06-01-patchforge-rebuild-live-deploy/`

Boundary note: PF-AZ11-CUSTOMER-DEMO-MATURITY does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ10-SIMPLIFIED-EXPERIENCE Validation Outputs

## PF-AZ10-SIMPLIFIED-EXPERIENCE Local Validation

Date: 2026-05-30

Status: PASS. PF-AZ10-SIMPLIFIED-EXPERIENCE is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Replace top-level navigation with Global Security Action Center, Customer Estate, Ask PatchForge, Reports & Packs, and Admin.
- Consolidate Finding Detail, Review & Approve, VendorLens, Vulnerability Queue, Vendor & Threat Landscape, SRA Research, Decision Packs, Source Feeds, and Evidence Catalogue into the simplified workflows.
- Add deterministic global CVE/advisory search across vulnerability, advisory, vendor, customer asset, applicability, and source-feed records.
- Add grouped Vendor -> Product Family -> CVE/Advisory catalogue, severity/urgency cards, filters, source state, review state, customer matches, and approval posture.
- Add Customer Estate asset extraction, upsert, matching, exposure matches, and Patch Compare.
- Add Ask PatchForge advisory-only responses with human approval required and `final_approval_issued=false`.
- Simplify report packs and require renderer, baseline, signing, verification, and final approval metadata in DOCX/PDF outputs.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/searchIndex.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/patchforge/vendorLens.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 32 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `npm --prefix Frontend run build`: PASS, Vite chunk-size advisory only
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz10-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz10-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz10-local .`: PASS

Azure rollout:

- GitHub push: PASS, deployed application commit `e728ec0`
- Image tag: `pfaz10-20260530-e728ec0`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Targeted Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000021`
  - Bridge/API: `ca-patchforge-bridge-prod--0000020`
  - Runtime: `ca-patchforge-runtime-prod--0000019`
  - SRA: `ca-patchforge-sra-prod--0000018`
  - Worker: `ca-patchforge-worker-prod--0000018`
  - Scheduler: `ca-patchforge-scheduler-prod--0000018`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected Security Action Center route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- New five-item navigation visible: PASS
- Global Security Action Center opened and grouped CVE/advisory catalogue loaded: PASS
- Search by vendor, product, feature, and CVE: PASS
- CVE Detail and Evidence & Approval panel opened: PASS
- Customer Estate opened: PASS
- Free-text device extraction for `FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only.`: PASS
- Extracted fields included vendor, product family, model, firmware, enabled/disabled features, management exposure, and unreviewed evidence state: PASS
- Temporary validation asset upserted, matched, and then removed after evidence capture: PASS
- Current CVE/advisory matching: PASS
- Patch Compare: PASS, final approval false and human review required
- Ask PatchForge advisory response: PASS, required response sections present, no final approval, human approval required
- Fresh signed pack generated: `PF-20260530-02cd95b4`
- Pack verification: PASS, `verified=true`
- Key Vault signing: PASS, `azure_key_vault`
- Customer Patch Governance Pack DOCX/PDF export: PASS
- Board Vulnerability Summary DOCX/PDF export: PASS
- CAB Patch Decision Report DOCX/PDF export: PASS
- Live report metadata stamping: PASS
- Simplified report sections: PASS
- Final approval remained false: PASS
- Production validation data cleanup: PASS, 9 records removed
- Temporary PostgreSQL firewall cleanup: PASS

PF-AZ10-SIMPLIFIED-EXPERIENCE evidence path:

`docs/release/evidence/2026-05-30-patchforge-pfaz10-simplified-experience/`

Important boundary note: PF-AZ10-SIMPLIFIED-EXPERIENCE does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ9A-VENDORLENS Validation Outputs

## PF-AZ9A Local Validation

Date: 2026-05-28

Status: PASS. PF-AZ9A is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Clarify release naming so the current active baseline is `PF-AZ9A-VENDORLENS`, the previous VendorLens baseline is `PF-AZ9-VENDORLENS`, and the earlier operational-health release is `PF-AZ9-OPS-HISTORICAL`.
- Replace ambiguous manifest wording with reused-resource fields.
- Stamp every DOCX/PDF report with current renderer and image metadata.
- Prove current reports are not stale and include VendorLens sections.
- Harden VendorLens product/feature aliases, version range handling, fixed-version logic, superseded advisory handling, and reviewed/unreviewed feature evidence states.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/patchforge/vendorLens.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 29 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- Docker frontend, bridge/API, and runtime build smoke: PASS
- Local structural DOCX/PDF report proof: PASS
- Local DOCX render attempt: NOT AVAILABLE because the local DOCX-to-PDF converter executable is missing

Azure rollout:

- GitHub push: PASS, commit `923b386`
- Image tag: `pfaz9a-20260528-923b386`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Azure what-if: captured; targeted image-only rollout used to avoid broad infrastructure drift
- Targeted Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000018`
  - Bridge/API: `ca-patchforge-bridge-prod--0000017`
  - Runtime: `ca-patchforge-runtime-prod--0000016`
  - SRA: `ca-patchforge-sra-prod--0000015`
  - Worker: `ca-patchforge-worker-prod--0000015`
  - Scheduler: `ca-patchforge-scheduler-prod--0000015`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability and VendorLens routes unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- VendorLens UI opened and rendered: PASS
- Vendor catalogue loaded: PASS, 17 vendors and 730 source-bound advisories before temporary validation
- Temporary live VendorLens workflow executed for `CVE-2026-923386`: PASS
- Config applicability assessment: PASS, `requires_review` with `urgent_scope_confirmation_required`
- Ask PatchForge chat: PASS, advisory-only with evidence missing and final approval false
- Fresh signed pack generated: `PF-20260528-9e896f66`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `azure_key_vault`
- PostgreSQL readiness and live write path: PASS
- Customer Patch Governance Pack DOCX/PDF export: PASS
- Board Vulnerability Remediation Summary DOCX/PDF export: PASS
- CAB Patch Decision Report DOCX/PDF export: PASS
- Live report version stamping: PASS
- VendorLens report sections: PASS
- Final approval remained false: PASS
- Production validation data cleanup: PASS, 17 records removed and post-cleanup browser check confirmed absence
- Temporary PostgreSQL firewall cleanup: PASS

PF-AZ9A evidence path:

`docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/`

Important boundary note: PF-AZ9A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous evidence-gate closure, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ10 UI, VendorLens Catalogue, and CISO Patch Comparison Validation Outputs

## PF-AZ10 Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ10 is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Fix UI wrapping and content overflow in finding cards, context banners, hero panels, status lines, and VendorLens panels.
- Add pagination to growing content areas including findings, vulnerability queue, assets/services, source feeds/runs, vendor lists, VendorLens advisories/assets/gaps, decision packs, reports, Admin health checks, and Admin sections.
- Add clickable VendorLens reference catalogue with source details and per-vendor refresh action.
- Refresh NVD catalogue records without requiring a single CVE input.
- Handle NVD public API rate limits as governed `completed_with_warnings` or `rate_limited` feed-run states instead of a broken UI workflow.
- Add CISO patch-version comparison workflow and report artefact.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/patchforge/vendorLens.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 29 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS

Azure rollout:

- GitHub push: PASS, latest commit `513fea2`
- Image tag: `pfaz10-20260527-513fea2`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; targeted image-only rollout used to avoid broad infrastructure drift
- Container Apps image update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000016`
  - Bridge/API: `ca-patchforge-bridge-prod--0000015`
  - Runtime: `ca-patchforge-runtime-prod--0000014`
  - SRA: `ca-patchforge-sra-prod--0000013`
  - Worker: `ca-patchforge-worker-prod--0000013`
  - Scheduler: `ca-patchforge-scheduler-prod--0000013`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability and VendorLens routes unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Action Center and Finding Detail visual overflow checks: PASS
- VendorLens reference catalogue loads: PASS, 17 vendors
- VendorLens active advisories: PASS, 730 source-bound records
- NVD catalogue refresh: PASS, governed `completed_with_warnings` state observed when the public NVD API rate limit was reached
- Patch Compare pagination: PASS, `1-10 of 730 comparison advisories`
- App console-breaking errors: PASS; only a Microsoft login favicon 404 was observed

PF-AZ10 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz10-ui-vendorlens-ciso-compare/`

Important boundary note: PF-AZ10 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

# PF-AZ9-VENDORLENS Validation Outputs

## PF-AZ9-VENDORLENS Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ9-VENDORLENS is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Add VendorLens Network Vendor Intelligence and Config-Aware Patch Advisor.
- Add source-bound network/security vendor catalogue and advisory ingest foundations.
- Add customer network asset, model, firmware, feature, exposure, and review-state records.
- Add config applicability engine and Ask PatchForge SRA/AIP chat.
- Add VendorLens UI and Admin: Vendor Sources controls.
- Add signed-pack artefacts and DOCX/PDF report sections for network vendor applicability.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/patchforge/configApplicability.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 27 tests
- `npm --prefix Frontend test`: PASS, 11 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 26 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz9-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz9-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz9-local .`: PASS

Document quality gate:

- Customer Patch Governance Pack DOCX/PDF generated with VendorLens sections: PASS
- Board Vulnerability Remediation Summary DOCX/PDF generated with VendorLens sections: PASS
- CAB Patch Decision Report DOCX/PDF generated with VendorLens sections: PASS
- DOCX structural wording checks: PASS
- DOCX-to-PNG render: NOT AVAILABLE locally because LibreOffice/soffice is unavailable on PATH
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/local-reports/`

Important boundary note: PF-AZ9-VENDORLENS does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `e8a0de2`
- Image tag: `pfaz9-20260527-e8a0de2`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000013`
  - Bridge/API: `ca-patchforge-bridge-prod--0000012`
  - Runtime: `ca-patchforge-runtime-prod--0000011`
  - SRA: `ca-patchforge-sra-prod--0000010`
  - Worker: `ca-patchforge-worker-prod--0000010`
  - Scheduler: `ca-patchforge-scheduler-prod--0000010`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected VendorLens route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- VendorLens catalogue loaded: PASS, 17 tracked vendors
- Customer network asset create workflow: PASS
- Source-bound vendor advisory ingest workflow: PASS
- Config applicability assessment: PASS, `requires_review` with `urgent_scope_confirmation_required`
- Ask PatchForge chat: PASS, advisory-only with short answer, governed posture, evidence used, evidence missing, and final approval false
- Signed pack generated: `PF-20260527-2d9f160a`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `azure_key_vault`, `pf-pack-signing-prod`
- PostgreSQL readiness and live write path: PASS
- Board DOCX/PDF report export: PASS
- DOCX structural QA for VendorLens report sections and final-approval boundary: PASS
- PF-AZ9-VENDORLENS live validation records removed from production PostgreSQL after evidence capture: PASS

PF-AZ9-VENDORLENS evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/`

# PF-AZ8A Validation Outputs

## PF-AZ8A Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ8A is deployed to Azure and validated through the live UI/API as a signed-in PatchForge Admin user.

Scope:

- Replace risky autonomous-analysis wording with safer automated-governance wording.
- Improve customer-facing posture for known-exploited public-source records with unconfirmed exposure.
- Add KEV/EPSS interpretation and source-bound vendor/threat intelligence wording.
- Make evidence gaps specific enough for customer, CAB, and board decisions.
- Add customer-specific assurance, impact, communication, shareable-position, and not-yet-claimable report sections.
- Add decision-option status, reason, required evidence, and approval fields.
- Add persistent UI context banner and simple next-action cards.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz8a-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz8a-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz8a-local .`: PASS

Document quality gate:

- Customer Patch Governance Pack DOCX generated from PF-AZ8A report context: PASS
- Board Vulnerability Remediation Summary DOCX generated from PF-AZ8A report context: PASS
- CAB Patch Decision Report DOCX generated from PF-AZ8A report context: PASS
- Matching PDF artefacts generated and rendered to page PNGs: PASS
- DOCX structural checks: PASS
- Microsoft Word open checks: PASS
- Required wording and boundary checks: PASS
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/local-report-qa/`

Important boundary note: PF-AZ8A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `4f3bbe8`
- Image tag: `pfaz8a-20260527-4f3bbe8`
- ACR image push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000012`
  - Bridge/API: `ca-patchforge-bridge-prod--0000011`
  - Runtime: `ca-patchforge-runtime-prod--0000010`
  - SRA: `ca-patchforge-sra-prod--0000009`
  - Worker: `ca-patchforge-worker-prod--0000009`
  - Scheduler: `ca-patchforge-scheduler-prod--0000009`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Context banner for `CVE-2026-48172`: PASS
- Safer automation wording visible: PASS
- Old autonomous-analysis heading absent: PASS
- Human approval notice visible: PASS
- Fresh signed pack generated after PF-AZ8A rollout: `PF-20260527-934d6e60`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS, `pf-pack-signing-prod`, ES256, `azure_key_vault`
- Final approval remained false: PASS
- Customer Patch Governance Pack DOCX/PDF export: PASS
- Board Vulnerability Remediation Summary DOCX/PDF export: PASS
- CAB Patch Decision Report DOCX/PDF export: PASS
- DOCX wording checks and PDF render QA: PASS
- PostgreSQL readiness: PASS

PF-AZ8A evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/`

# PF-AZ9-OPS-HISTORICAL Validation Outputs

## PF-AZ9-OPS-HISTORICAL Operational Health Enablement

Date: 2026-05-27

Status: PASS. PF-AZ9-OPS-HISTORICAL is deployed to Azure and validated through the live Admin UI/API.

Scope:

- Enable MCP agent intake health as governed.
- Enable public source feeds health as ready.
- Enable worker health as ready.
- Enable scheduler health as ready.
- Preserve source-feed and agent-intake defaults during Admin config saves.
- Show health mode detail in the Admin UI.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/patchforge/storage.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `npm --prefix Frontend run build`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `git diff --check`: PASS

Azure rollout:

- GitHub push: PASS, commit `c494375`
- Image tag: `pfaz9-20260527-c494375`
- ACR tag verification: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- Targeted Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000011`
  - Bridge/API: `ca-patchforge-bridge-prod--0000010`
  - Runtime: `ca-patchforge-runtime-prod--0000009`
  - SRA: `ca-patchforge-sra-prod--0000008`
  - Worker: `ca-patchforge-worker-prod--0000008`
  - Scheduler: `ca-patchforge-scheduler-prod--0000008`

Live validation:

- UI HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected Admin health unauthenticated HTTP 401: PASS
- Browser/MSAL session as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- MCP agent intake: PASS, `governed`
- Public source feeds: PASS, `ready`
- Worker health: PASS, `ready`
- Scheduler health: PASS, `ready`

PF-AZ9-OPS-HISTORICAL evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz9-operational-health-enablement/`

# PF-AZ8 Validation Outputs

## PF-AZ8 Local Validation

Date: 2026-05-27

Status: PASS. PF-AZ8 is deployed to Azure and validated through the live UI/API.

Scope:

- Guided Action Center, Finding Detail, Review & Approve, and Reports & Packs workflow.
- Human-readable finding intelligence API.
- Decision-grade DOCX/PDF board and CAB reports.
- Signed-pack support for `finding_intelligence_snapshot.json`.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/patchforge/intelligence.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `npm --prefix backend-api test`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 10 tests
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz8-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz8-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz8-local .`: PASS
- `git diff --check`: PASS

Document quality gate:

- Local board DOCX generated from signed-pack context: PASS
- Local board PDF generated from same context: PASS
- Local CAB DOCX generated from signed-pack context: PASS
- Local CAB PDF generated from same context: PASS
- Microsoft Word-rendered DOCX pages inspected as PNGs: PASS
- No clipping, overlap, broken tables, missing text, unreadable wrapping, or orphan note page observed.
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/report-qa/`

Important boundary note: PF-AZ8 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Azure rollout:

- GitHub push: PASS, commit `cc708fd`
- Image tag: `pfaz8-20260527-cc708fd`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000010`
  - Bridge/API: `ca-patchforge-bridge-prod--0000009`
  - Runtime: `ca-patchforge-runtime-prod--0000008`
  - SRA: `ca-patchforge-sra-prod--0000007`
  - Worker: `ca-patchforge-worker-prod--0000007`
  - Scheduler: `ca-patchforge-scheduler-prod--0000007`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql`, `auth_required=true`, and `tenant_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Simplified guided navigation smoke across Action Center, Finding Detail, Review & Approve, Reports & Packs, Guide, and Admin: PASS
- Real public-source record validated: `CVE-2026-48172`
- Finding Detail plain-English intelligence: PASS
- Exploitability intelligence boundary: PASS, no exploit code, payloads, or procedural exploitation steps shown
- Review & Approve automated governance analysis summary: PASS
- SRA advisory: PASS, advisory-only
- Fresh signed pack generated after PF-AZ8 rollout: `PF-20260527-9fc7f010`
- Pack verification: PASS, `verified=true`, `manifest_ok=true`, `signature_ok=true`
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- Final approval remained false: PASS
- Protected DOCX report generation from live signed pack: PASS
- Protected PDF report generation from live signed pack: PASS
- Admin health route: PASS, database, storage, Key Vault, signing trust, bridge, runtime, and frontend health visible
- PostgreSQL readiness: PASS

PF-AZ8 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz8-guided-intelligence-workflow/`

# PF-AZ6 / PF-AZ7 Validation Outputs

## PF-AZ7 Live Validation

Date: 2026-05-27

PF-AZ7 is deployed to Azure and validated through the live UI as a signed-in PatchForge Admin user.

Scope:

- Professional DOCX and PDF board-pack generation from signed decision packs.
- Protected report catalogue and report download APIs.
- UI Reports page and Decision Pack DOCX/PDF export actions.
- Scheduler mode for recurring live CISA KEV and FIRST EPSS refresh.
- Scheduler source lineage, advisory-only controls, and no scanner/no deployment boundaries.

Local validation:

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/patchforge/reports.js`: PASS
- `node --check backend-api/patchforge/scheduler.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `node --test backend-api/patchforge-api.test.mjs`: PASS, 20 tests
- `npm --prefix backend-api test`: PASS, 24 tests
- `npm test`: PASS, 24 backend/SRA tests
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix Frontend test`: PASS, 13 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz7-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz7-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz7-local .`: PASS

Document quality gate:

- Local DOCX board pack generated from real public-source CVE context: PASS
- Local PDF board pack generated from the same signed-pack context: PASS
- Microsoft Word-rendered DOCX pages inspected as PNGs: PASS
- No clipping, overlap, broken tables, missing text, or unreadable wrapping observed.
- QA evidence: `docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/doc-qa/docx-pdf-visual-qa.json`

Azure rollout:

- GitHub push: PASS, commit `71643ce4123bed543c9b0b55c39347b4775946d1`
- Image tag: `pfaz7-20260527-71643ce`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Scheduler min/max replicas: PASS, one active replica
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000009`
  - Bridge/API: `ca-patchforge-bridge-prod--0000008`
  - Runtime: `ca-patchforge-runtime-prod--0000007`
  - SRA: `ca-patchforge-sra-prod--0000006`
  - Worker: `ca-patchforge-worker-prod--0000006`
  - Scheduler: `ca-patchforge-scheduler-prod--0000006`

Live validation:

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Protected reports route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- Full navigation smoke across Command Center, Guide, Vulnerability Queue, Asset & Service Exposure, Decision Workbench, Emergency Patch, Risk Acceptances, Compensating Controls, SRA Research, Evidence Catalogue, Decision Packs, Reports, Source Feeds, Vendor & Threat Landscape, and Admin: PASS
- Scheduler run completed at 2026-05-27T00:29:31Z: PASS
- Real public-source record validated: `CVE-2026-48172`
- SRA advisory for `CVE-2026-48172`: PASS, advisory-only/source-bound/pending-review
- Bayesian advisory for `CVE-2026-48172`: PASS, advisory-only
- Fresh signed pack generated after PF-AZ7 rollout: `PF-20260527-54588be9`
- Pack verification: PASS, `manifest_ok=true`, `signature_ok=true`, `source_pack_immutable=true`
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- Final approval remained false: PASS
- DOCX report download from live UI/API: PASS
- PDF report download from live UI/API: PASS
- Fresh DOCX/PDF visual QA: PASS
- PostgreSQL readiness and protected list/export paths: PASS

PF-AZ7 evidence path:

`docs/release/evidence/2026-05-27-patchforge-pfaz7-operational-demo/`

Important boundary note: PF-AZ7 does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance.

Date: 2026-05-26

This file records PF-AZ6 validation commands and rollout evidence. It will be updated again after Azure deployment and live UI validation.

## PF-AZ6 Scope

- Live CISA KEV public source feed refresh.
- Live FIRST EPSS public source feed enrichment.
- Source-feed run ledger.
- UI Source Feeds page bound to protected live APIs.
- Source-bound, pending-review, advisory-only controls for public intelligence.

## Pre-Flight

- Git remote: `https://github.com/neil9bailey/diiac-patchforge.git`
- Branch: `main`
- Azure tenant: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`
- Resource group: `rg-diiac-patchforge-prod`

## Local Validation

- `node --check backend-api/server.js`: PASS
- `node --check backend-api/auth.js`: PASS
- `node --check backend-api/sra/securityResearchAgent.js`: PASS
- `python -m pytest -q --basetemp .pytest_tmp`: PASS, 25 tests
- `npm --prefix backend-api test`: PASS, 22 tests
- `npm test`: PASS, 22 backend/SRA tests
- `npm --prefix Frontend test`: PASS, 12 tests
- `npm --prefix Frontend run build`: PASS
- `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/validate_iac.ps1`: PASS
- `az bicep build --file infra/bicep/main.bicep`: PASS
- `docker build -f Frontend/Dockerfile -t diiac/patchforge-frontend:pfaz6-local Frontend`: PASS
- `docker build -f backend-api/Dockerfile -t diiac/patchforge-bridge:pfaz6-local backend-api`: PASS
- `docker build -f runtime/Dockerfile -t diiac/patchforge-runtime:pfaz6-local .`: PASS
- Local signed pack verification: not rerun in the PF-AZ6 pre-Azure gate; runtime signing path is unchanged from PF-AZ5 and live pack verification will be rerun after Azure rollout.

PF-AZ6 Azure rollout status: PASS.

## Azure Rollout

- Git push: PASS, commit `473b055005cb2bb212e47f46aaf4e660faeb7d3a`
- Image tag: `pfaz6-20260526-473b055`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- ACR tag verification: PASS for all six repositories
- Full Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000008`
  - Bridge/API: `ca-patchforge-bridge-prod--0000007`
  - Runtime: `ca-patchforge-runtime-prod--0000006`
  - SRA: `ca-patchforge-sra-prod--0000005`
  - Worker: `ca-patchforge-worker-prod--0000005`
  - Scheduler: `ca-patchforge-scheduler-prod--0000005`

## Live Validation

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected vulnerability route unauthenticated HTTP 401: PASS
- Protected source-feed route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- CISA KEV feed refresh: PASS, 1603 records seen, 5 ingested
- FIRST EPSS feed refresh: PASS, `CVE-2026-48172` enriched
- Real CISA records observed in queue: `CVE-2026-48172`, `CVE-2026-9082`, `CVE-2025-34291`, `CVE-2026-34926`, `CVE-2008-4250`
- Bayesian Patch Risk advisory on `CVE-2026-48172`: PASS
- Signed decision pack generated and exported: `PF-20260526-8312f908`
- Pack verification: PASS
- Key Vault signing smoke: PASS through live pack export with `signing_provider=azure_key_vault`
- PostgreSQL readiness: PASS
- Production no-demo-data cleanup: PASS, old PF-AZ5 synthetic validation record `CVE-2026-PF-DEMO-001` and linked records removed
- Temporary PostgreSQL firewall rule cleanup: PASS, only `AllowAzureServices` remained after validation
- Final approval remained false: PASS

Evidence path:

`docs/release/evidence/2026-05-26-patchforge-pfaz6-live-source-intelligence/`

## PF-AZ5 Historical Validation

- Git push: PASS, commit `8a145e849a2c57fed3bc00440f2f2f8b29585f72`
- Image tag: `pfaz5-20260526-8a145e8`
- ACR build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler images
- Full Bicep what-if: captured; not applied because it included broader drift/noise than the image rollout required
- Targeted image-only Container Apps update: PASS
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000007`
  - Bridge/API: `ca-patchforge-bridge-prod--0000006`
  - Runtime: `ca-patchforge-runtime-prod--0000005`
  - SRA: `ca-patchforge-sra-prod--0000004`
  - Worker: `ca-patchforge-worker-prod--0000004`
  - Scheduler: `ca-patchforge-scheduler-prod--0000004`

## Live Validation

- UI HTTP 200: PASS
- API health HTTP 200: PASS
- API readiness HTTP 200 with `storage=postgresql` and `auth_required=true`: PASS
- Protected route unauthenticated HTTP 401: PASS
- Browser/MSAL sign-in as `n.bailey@diiac.io`: PASS
- Displayed role `PatchForge.Admin`: PASS
- UI ingest of `CVE-2026-PF-DEMO-001`: PASS
- SRA exploit-risk advisory source-bound/advisory-only: PASS
- Bayesian Patch Risk advisory-only: PASS
- Signed decision pack generated and exported: `PF-20260526-e90d3a02`
- Pack verification: PASS
- Key Vault ES256 signing smoke: PASS
- Final approval remained false with readiness blocked pending evidence/human gates: PASS

Evidence path:

`docs/release/evidence/2026-05-26-patchforge-pfaz5-intelligence-rollout/`

Note: Azure CLI token acquisition for the custom PatchForge API was blocked by AADSTS65001 interactive consent for the Azure CLI client, so the authenticated workflow was validated through the deployed browser/MSAL path.

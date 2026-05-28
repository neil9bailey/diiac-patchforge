# PatchForge Readiness Summary

## Current Readiness

PatchForge is live on Azure Container Apps under the DIIaC tenant with:

- custom UI domain `https://patchforge.diiac.io`
- custom API domain `https://api.patchforge.diiac.io`
- Microsoft Entra app registrations and PatchForge app roles
- PostgreSQL-backed tenant state
- Key Vault production signing path
- Azure Container Apps revisions for UI, bridge/API, runtime, SRA, worker, and scheduler
- source-bound evidence and signed pack governance controls
- guided Action Center, Finding Detail, Review & Approve, Reports & Packs, Guide, and Admin workflow
- professional protected DOCX/PDF report generation from signed decision packs
- PF-AZ9A image tag `pfaz9a-20260528-1a98433` on all PatchForge Container Apps

PF-AZ8 added the customer-demo workflow hardening requested after report/UI review:

- Action Center that translates findings into decision-ready work
- plain-English finding intelligence
- exploitability intelligence without exploit code, payloads, or procedural steps
- automated governance analysis summary with human approval still required
- SRA advisory-only workflow
- signed-pack support for `finding_intelligence_snapshot.json`
- board/CAB DOCX and PDF reports generated from live signed evidence
- Admin health visibility for database, storage, Key Vault, signing, bridge, runtime, and frontend status

PF-AZ9-OPS completes the operational health checks:

- MCP agent intake reports `governed`
- public source feeds report `ready`
- worker health reports `ready`
- scheduler health reports `ready`
- Admin health shows operational mode detail

PF-AZ8A completes the customer report specificity and guided decision-usefulness refinement:

- safer `Automated Governance Analysis Completed` wording
- explicit human-approval notice below automated governance preparation
- urgent scope confirmation posture for known-exploited public-source records with unconfirmed customer exposure
- KEV/EPSS plain-English explanation where known-exploited and low EPSS signals appear together
- customer-specific assurance, impact, evidence, communication, shareable-position, and not-yet-claimable sections
- specific evidence gaps with rationale, required evidence, examples, owner role, and next decision gate
- live customer, board, and CAB DOCX/PDF reports exported from signed pack `PF-20260527-934d6e60`

PF-AZ9-VENDORLENS completes the network vendor intelligence and config-aware patch advisor increment:

- major network/security vendor catalogue with source-bound advisory source metadata
- customer network asset records for vendor, product family, model, firmware, enabled/disabled features, and exposure
- config applicability assessment with urgency posture, evidence used, evidence missing, and final approval false
- Ask PatchForge config-aware SRA/AIP chat that remains advisory-only
- VendorLens UI tabs for vendors, advisories, estate match, applicability, urgency, chat, evidence packs, and source administration
- signed-pack artefacts for VendorLens snapshots
- DOCX/PDF report sections for Network Vendor Applicability and Customer Configuration Context

PF-AZ9A completes the VendorLens release clarity and current-report proof increment:

- current-facing release naming is consistently `PF-AZ9-VENDORLENS`
- earlier operational health release naming is separated as `PF-AZ9-OPS`
- release manifests distinguish new Azure resource creation from reuse of existing Azure resources
- all DOCX/PDF report exports include report template, renderer commit, image tag, source pack, generation time, product baseline, and report context version stamps
- fresh live customer, board, and CAB reports were exported from signed pack `PF-20260528-9a653d50`
- current reports prove VendorLens sections, customer configuration context, SRA/AIP chat summary, final approval false, and no exploit or patch deployment implication

## Live Validation

PF-AZ9A Azure update and live UI/API validation are complete for the current commit and image tag.

- User: `n.bailey@diiac.io`
- Role displayed: `PatchForge.Admin`
- Validated workflow: VendorLens report proof, source-bound finding review, signed pack generation, report export, and version-stamp verification
- Signed pack: `PF-20260528-9a653d50`
- Pack verification: PASS
- Manifest verification: PASS
- Signature verification: PASS
- Signing provider: `azure_key_vault`
- Final approval: `false`
- Customer DOCX/PDF report generation: PASS
- Board DOCX/PDF report generation: PASS
- CAB DOCX/PDF report generation: PASS
- Report version stamping: PASS
- VendorLens report sections: PASS
- Live DOCX/PDF structural QA: PASS
- PostgreSQL readiness: PASS
- Protected unauthenticated route returns: HTTP 401
- Evidence path: `docs/release/evidence/2026-05-28-patchforge-pfaz9a-vendorlens-report-proof/live-ui/`
- PF-AZ9-VENDORLENS evidence path: `docs/release/evidence/2026-05-27-patchforge-pfaz9-vendorlens/live-ui/`
- PF-AZ8A report specificity evidence path: `docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/live-ui/`
- PF-AZ9-OPS operational health evidence path: `docs/release/evidence/2026-05-27-patchforge-pfaz9-operational-health-enablement/live-ui/`

## Remaining Gaps

- live scanner integrations are not implemented
- patch deployment is not implemented and remains prohibited
- exploit generation is not implemented and remains prohibited
- Bayesian prior updates are dry-run/proposal-only
- vendor and threat intelligence remains source-bound until reviewed
- no third-party customer production validation is claimed

These are not blockers for the governed PatchForge product demo because scanner operation, patch deployment, exploit generation, and autonomous approvals are intentionally outside the product boundary.

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, or approve risk without accountable human review.

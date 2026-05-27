# VendorLens Operator Guide

## Daily Flow

1. Open VendorLens.
2. Confirm the network vendor catalogue loads.
3. Refresh or ingest source-bound vendor advisory/CVE records.
4. Attach customer network asset evidence: vendor, product family, model, firmware, exposure, enabled features, disabled features, owner, site, and configuration evidence references.
5. Run Config Applicability.
6. Ask PatchForge a configuration-aware question.
7. Review evidence gaps.
8. Generate the signed decision pack from the governed finding.
9. Export DOCX/PDF customer, CAB, or board reports.
10. Record accountable human review and approval outside the source pack as the process proceeds.

## Source Handling

NVD CVE metadata is refreshed on demand by CVE ID. Cisco PSIRT support is credentials-reference gated unless an explicitly configured source URL is safe to call without credentials. Generic vendor RSS/JSON sources are configured in Admin and remain source-bound.

Every source retrieval records:

- source URL
- source hash
- retrieval timestamp
- run status
- records seen
- records ingested
- source-bound and review-required flags

## Configuration Evidence

Use reviewed evidence wherever possible:

- CMDB or network asset inventory
- firewall or gateway controller export
- firmware/software version evidence
- feature enablement evidence
- external exposure or management-plane exposure evidence
- service owner confirmation
- change record or configuration review event

If a feature is recorded as disabled but evidence is not reviewed, VendorLens keeps the posture at `requires_review`. It does not treat the asset as safe automatically.

## Approval Boundary

VendorLens output is advisory. Human approval remains required. PatchForge does not approve CAB decisions, risk acceptance, patch deployment, not-applicable status, or closure autonomously.

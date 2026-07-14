# ADR-PF-UX-002: Report Catalogue Rationalisation

Status: Approved

Date: 2026-06-11

Epic: EPIC-PF-UX-CATALOGUE-REPORT-FLOW

## Context

PatchForge reports are signed governance outputs. The previous visible catalogue exposed broad report labels such as CISO executive brief, security operations action plan, vendor exposure report, emergency advisory report, and monthly governance pack.

The current implementation generated those broad labels through the same generic decision-pack renderer. Only four report types currently have clear end-user jobs and audience-specific sections:

1. Customer Patch Governance Pack
2. Board Vulnerability Summary
3. CAB Patch Decision Report
4. Technical Evidence Appendix

Leaving many generic labels visible makes the reporting flow feel noisy and implies report maturity that the implementation does not yet provide.

## Decision

PatchForge will rationalise the active report catalogue to the four report outputs that are currently differentiated and useful:

- `customer_patch_governance_pack`
- `board_vulnerability_remediation_summary`
- `cab_patch_decision_report`
- `technical_evidence_appendix`

The removed active report types are:

- `ciso_executive_risk_brief`
- `security_operations_action_plan`
- `vendor_exposure_report`
- `customer_estate_vulnerability_report`
- `patch_hotfix_decision_pack`
- `emergency_advisory_report`
- `monthly_vulnerability_governance_pack`
- `ciso_patch_version_comparison_report`
- legacy alias `board_vulnerability_summary`

Requests for removed report types should fail closed with `unknown_report_type`. They can be reintroduced later only when each has distinct scope controls, audience-specific content, and verification coverage.

The runtime text report renderer must follow the same active catalogue and avoid rendering every possible section into every report.

## Acceptance Criteria

- Backend report catalogue and allowed report errors list only the four active report types.
- Runtime report catalogue contains the same active report types.
- Each active report type renders successfully in relevant automated tests.
- Removed report types are rejected rather than silently producing generic reports.
- Reports UI wording reflects the four practical outputs.
- Content quality review runs against the active catalogue.
- Governance boundary remains unchanged: no autonomous approval, no patch deployment, no risk acceptance, no scanning, and no exploit guidance.

## Consequences

The visible Reports page becomes simpler and more credible. Existing old links to removed report type URLs will return a controlled `unknown_report_type` error.

Future stakeholder or monthly reports can still be added, but they require explicit design, report-specific content, scope controls, and test coverage.

## Verification Expectations

- Backend unit tests for catalogue, export success, and removed report rejection.
- Runtime tests for active report rendering and section relevance.
- Frontend tests for Reports page copy/actions.
- Backend syntax and test suite.
- Frontend test/build where UI changes are made.
- Security review confirming advisory-only report boundaries are unchanged.

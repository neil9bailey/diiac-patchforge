# ADR-PF-AZ12-001: Operational Intelligence Value Improvements

Status: Approved

Date: 2026-06-04

Epic: EPIC-PF-AZ12-OPERATIONAL-INTELLIGENCE-VALUE

## Context

PatchForge PF-AZ11 is live as a governed vulnerability, advisory, customer estate, patch comparison, Ask PatchForge, and reports product. The current baseline improves the simplified customer experience, but the product still has operational-value gaps in release truth, UI clarity, report credibility, and deterministic advisor usefulness.

This change is design-altering because it affects the approved user journey, report outputs, and advisor explanation model. It must stay within the existing PatchForge governance boundary.

## Decision

PatchForge will improve operational value within the existing PF-AZ11 architecture by refining the UI, deterministic advisory intelligence, report outputs, and release-truth documentation.

The work will keep the existing React/Vite frontend, Node backend, deterministic search and applicability modules, and current report rendering path. It will not introduce new services, topology changes, dependencies, scanning, exploit logic, patch deployment, autonomous approvals, risk acceptance, or evidence-gate closure.

The seven-area navigation model remains the approved baseline:

1. Security Action Center
2. Vendors & Exploits Register
3. Customer Operational Assets
4. Patch / Hotfix Compare
5. Ask PatchForge
6. Reports
7. Admin

## Approved Increments

1. PF-AZ12.1 Baseline Truth Pack
   - Principal: Principal Governance Engine
   - Scope: align current release, readiness, gaps, and baseline documents to the deployed PF-AZ11 state.

2. PF-AZ12.2 UI Operational Clarity
   - Principal: Principal Frontend
   - Scope: improve table layout, selected-context visibility, evidence summaries, and workflow clarity.

3. PF-AZ12.3 Ask PatchForge Intelligence Clarity
   - Principal: Principal Governance Engine
   - Scope: strengthen deterministic advisor reasoning, ambiguity handling, candidate-match explanation, evidence confidence, and "what would change the answer" detail.

4. PF-AZ12.4 Reports & Outputs Credibility
   - Principal: Principal Governance Engine and Principal Frontend
   - Scope: improve report preflight, shareable/not-yet-claimable sections, stale-pack warnings, evidence gaps, final approval state, and signed metadata visibility.

5. PF-AZ12.5 Live UAT Evidence
   - Principal: UAT Lead
   - Scope: real signed-in PatchForge.Admin validation, not synthetic-only.

## Out Of Scope

- Vulnerability scanning
- Exploit generation
- Procedural exploit steps
- Patch deployment
- Production mutation
- Autonomous CAB approval
- Autonomous risk acceptance
- Autonomous evidence-gate closure
- Auth, Entra, Azure infrastructure, database migrations, or signing model changes unless separately approved

## Verification Expectations

- Targeted unit tests per increment
- Frontend tests and production build for UI changes
- Backend tests for intelligence and report changes
- Fresh generated DOCX/PDF reports for report-output changes
- Browser validation against the deployed UI before release
- G4 real end-user UAT before release signoff

## Consequences

PatchForge remains advisory-only and governance-bound while becoming clearer and more valuable for operational users. Improvements must be delivered incrementally with explicit validation evidence and no drift from the approved product boundary.

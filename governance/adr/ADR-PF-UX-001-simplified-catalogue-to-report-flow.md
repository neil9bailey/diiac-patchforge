# ADR-PF-UX-001: Simplified Catalogue-To-Report User Flow

Status: Approved

Date: 2026-06-11

Epic: EPIC-PF-UX-CATALOGUE-REPORT-FLOW

## Context

PatchForge already has governed intelligence foundations: source-bound CVE/advisory records, VendorLens vendor and product context, customer operational assets, Ask PatchForge, patch comparison, signed packs, and reports.

The current product surface is still too fragmented for end users. Users need a clear path:

1. Keep the CVE, advisory, patch, KEV, EPSS, and source-evidence catalogue credible and current.
2. Keep the vendor catalogue current with user-maintained vendor/product details.
3. Let intelligence and automation connect vendor/CVE evidence to customer estate context.
4. Use Ask PatchForge as the guided end-to-end workbench for how-to, what-if, impact, risk, run-plan, must-do reasoning, and report preparation.
5. Use Reports for stakeholder, steering group, CAB, customer, and board decision outputs.

This is design-altering because it changes the approved information architecture and end-user journey. It must stay within the existing PatchForge architecture and governance boundary.

## Decision

PatchForge will simplify the visible end-user information architecture into six primary areas:

1. Patch & CVE Catalogue
2. Vendor Catalogue
3. Customer Estate
4. Ask PatchForge
5. Reports
6. Admin

The work will reuse the existing React/Vite frontend, Node ESM backend, VendorLens/source-feed services, deterministic Ask PatchForge advisor, signed-pack/report APIs, and current Azure deployment shape.

The first implementation increment is UI-flow consolidation only:

- Rename and clarify the visible navigation.
- Remove hidden or low-value legacy pages from the visible end-user journey.
- Present CVE/patch intelligence as a dedicated catalogue.
- Present vendor/product intelligence as a dedicated vendor catalogue.
- Make Ask PatchForge the guided end-to-end workbench that leads users from asset/vendor context to candidate CVEs, patch comparison, report pack generation, and stakeholder reports.
- Keep Reports as the full decision-output section.

No new service, database migration, dependency, autonomous approval, patch deployment, exploit logic, scanner, production mutation, or risk-acceptance automation is approved by this ADR.

## Acceptance Criteria

- The default signed-in journey starts from Patch & CVE Catalogue, Vendor Catalogue, Customer Estate, Ask PatchForge, Reports, and Admin.
- Ask PatchForge visibly explains the end-to-end flow: identify context, select or refresh candidate CVEs, assess impact/risk, compare patch or mitigation options, generate signed pack, and export reports.
- Vendor catalogue clearly supports user-maintained vendor/product details and source refresh.
- Patch & CVE catalogue clearly communicates source-bound evidence, refresh state, customer matches, patch availability, and final approval status.
- Reports clearly supports stakeholder and steering group decision outputs from signed packs.
- User-facing acceptance requires live signed-in testing; synthetic tests alone cannot clear G4.

## Consequences

PatchForge becomes easier to adopt without changing its governance boundary. The UI should feel like a guided operational product rather than a set of disconnected technical pages.

The tradeoff is that some existing legacy surfaces remain in code for compatibility but are no longer part of the primary visible navigation unless separately approved.

## Verification Expectations

- Frontend unit tests for navigation/Ask/Reports behavior.
- Frontend production build.
- Backend tests if backend behavior changes.
- Security review confirming no approval/deployment/risk-acceptance boundary weakening.
- Live signed-in UAT on the deployed UI before release signoff.

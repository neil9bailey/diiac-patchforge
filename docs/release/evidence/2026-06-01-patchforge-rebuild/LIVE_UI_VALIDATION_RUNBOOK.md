# Live UI Validation Runbook

Date: 2026-06-01

Purpose: validate the seven-area PatchForge shell locally and, after approved deployment, in production.

## Local Browser Smoke

Use a local dev server or preview server and validate:

- The left navigation has exactly these top-level areas:
  - Security Action Center
  - Vendors & Exploits Register
  - Customer Estate
  - Patch / Hotfix Compare
  - Ask PatchForge
  - Reports & Signed Action Packs
  - Admin / Assurance
- The initial view is Security Action Center.
- The DIIaC/PatchForge Intelligence brand is visible.
- The boundary panel states source-bound, human-approved, no exploit/scan/patch-deploy behavior.
- The Vendors & Exploits Register shows CVE/advisory, vendor, product, severity, CVSS, EPSS, KEV, exploited signal, affected versions, fixed versions, patch status, customer estate, evidence confidence, and unresolved gaps.
- Patch / Hotfix Compare shows direct patch, hotfix, major upgrade, workaround, compensating controls, and defer-with-exception options.
- Ask PatchForge copy states it refuses exploit code, payloads, bypass instructions, and attacker playbooks.
- Reports & Signed Action Packs includes signed pack generation and report options.
- Admin / Assurance is visible to all users and locked when the user is not an admin.

## Production Browser Smoke

Run only after explicit deployment approval and successful health/readiness checks.

Validate with a signed-in account that has appropriate PatchForge roles:

- MSAL sign-in succeeds.
- The current tenant is `diiac.io`.
- Security Action Center loads real source-bound catalogue rows.
- Search works with CVE, vendor, product, feature, firmware, customer match, and patch availability filters.
- Customer Estate can use synthetic validation data and all validation data is removed after evidence capture.
- Ask PatchForge gives defensive answers and refuses offensive exploit requests.
- Reports & Signed Action Packs can generate, verify, and export a signed action pack.
- Admin / Assurance shows production readiness state without exposing secrets.

## Evidence To Capture

- Browser screenshots for each top-level area.
- Console log with no critical runtime errors.
- API health/readiness response bodies.
- Active Container Apps revisions before and after update.
- Generated pack verifier result.
- Cleanup evidence for any synthetic validation data.

## Stop Conditions

Stop validation and rollback or hold the release if:

- Navigation does not match the seven-area shell.
- Protected routes are accessible without authentication.
- Any UI exposes a raw secret, exploit payload, bypass steps, or patch deployment command.
- Signed action pack verification fails.
- Tenant-scoped data appears under the wrong tenant.
- Production health/readiness is not green.

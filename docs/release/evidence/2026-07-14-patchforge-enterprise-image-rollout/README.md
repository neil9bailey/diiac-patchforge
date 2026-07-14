# PatchForge Enterprise Image Rollout Evidence

Date: 2026-07-14

Status: **PARTIAL ACCEPTANCE**. The governed `f51802d` image-only Azure rollout succeeded for all six Container Apps. Public smoke and signed-in Admin health checks passed. A strict report-verification normalization fix plus navigation, verified ZIP, exact-ID cleanup, and repaired IaC are implemented/tested only in the subsequent closeout branch and are not part of the live image state. Production report integrity, live closeout-workflow proof, full IaC apply, collector acceptance, and legal gates remain open.

## Release Identity

- Product baseline: `PF-AZ-ENTERPRISE-AUTOMATION-20260714D`
- Source commit: `f51802d3544260259c252e6be88d6e7bae596868`
- Image tag: `pfaz-enterprise-20260714d-f51802d`
- Report context: `patchforge-report-context.pfaz-enterprise-20260714d.v1`
- GitHub production approval run: `29345354677`, attempt `1`
- Guarded release execution: `succeeded`
- Six-image provenance manifest SHA-256: `d9c8f265aaab5c7d10549f1730620a9681bb0b13ff10c8b870973f52c07b9615`

## Evidence Included

- `release-summary.json` — approval and attestation identifiers, provenance, six image digests and active revisions, and public smoke results.
- `signed-in-uat-summary.json` — sanitized Admin health UAT result and explicit blockers.
- `iac-drift-summary.json` — the live `f51802d` configuration boundary plus the successful but not fully determinate repaired-IaC What-If.
- `rbac-revocation-summary.json` — sanitized post-release proof that the temporary signing-key data-plane assignment was no longer present.

## Acceptance Boundary

Passed:

- exact release authorization and GitHub attestation verification;
- six immutable ACR images and digests;
- signed and verified six-image provenance manifest;
- six healthy, provisioned, latest-ready active revisions at 100% latest-revision traffic;
- UI, API health, API readiness, and expected unauthenticated `401` smoke checks;
- signed-in `PatchForge.Admin` access and 13/13 Admin health checks.

Open or failed closed:

- DOCX report generation stopped with `signature_cryptographic_verification_failed`;
- ingestion navigation was not complete in the live `f51802d` signed-in journey; the closeout fix is implemented/tested locally only;
- verified ZIP was not complete in the live `f51802d` journey; the closeout path is implemented/tested locally only;
- targeted cleanup was not completed in production; local cleanup uses a server-issued tenant-scoped expiring preview token bound to a SHA-256 digest of displayed exact record IDs, fails closed on direct/cross-tenant/drift/reuse attempts, and retains audit;
- the full Bicep template was not applied; the repaired closeout What-If succeeded over 43 resources with 0 destructive, 7 modify, 20 no-change, 3 ignore, and 13 unsupported, so it is not fully determinate;
- semantic analysis found 0 image changes and 0 environment removals; proposed changes converge metadata on six apps, add 12 probes, and intentionally change scheduler `minReplicas` from `0` to `1` because its timer is in-process;
- live release-metadata environment variables still identify the previous July 11 baseline even though the container images use the July 14 tag;
- trusted Windows collector signing, clean customer-machine UAT, representative customer acceptance, and legal/licensing review remain open.

## Closeout-Branch Report Fix — Not Live

- High-confidence root cause: Azure Key Vault SDK enum labels appeared as `KeyType.ec` and `KeyCurveName.p_256`, while the download verifier required standards-form `EC` and `P-256`.
- Local fix: normalize only explicitly supported Azure/standards EC P-256 labels to `EC` / `P-256`, then perform unchanged full ES256 verification.
- Legacy-label compatibility remains cryptographic; it does not trust labels without signature verification.
- Unknown aliases, unsupported curves, malformed coordinates, wrong public keys, tampered signatures, and short signatures fail closed.
- The fix is not deployed. Production report acceptance remains open until fresh live selected-pack ZIP/DOCX/PDF bytes verify and reports are reviewed.

## Closeout-Branch Validation — Not Live

- Python: 53/53
- Backend API: 94/94
- Frontend: 28/28
- Playwright/axe: 2/2
- Windows collector: 8/8
- Frontend build/bundle: PASS; entry `270.20 kB`, total JavaScript `634.39/650 kB`
- IaC: PASS

These are separate closeout-branch results. The deployed `f51802d` candidate totals remain unchanged.

## Sanitization

This folder contains summaries only. It intentionally excludes rollback image archives, Docker tar files, raw authorization or browser-auth payloads, tokens, secret values, raw attestation bundles, raw signatures, database records, and operator identity identifiers. Key names, key IDs, image digests, revision names, workflow/run identifiers, HTTP outcomes, and secret-free status metadata are retained because they are required for release traceability.

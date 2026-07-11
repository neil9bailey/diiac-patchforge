# PF-AZ-MODERN-UI-20260711 release evidence

This directory contains the sanitized release record for the PatchForge enterprise UI and governed delivery rollout completed on 2026-07-11.

## Outcome

- Git commit `907995fdf1ea290a7e551463e461af8a884cf44c` is pushed to `codex/patchforge-rebuild-20260601`.
- Draft PR `#2` is clean and all 8 checks pass.
- Six immutable images tagged `pfaz-modern-ui-20260711-907995f` were built locally, pushed to ACR, and verified by exact registry/local digest comparison.
- Six existing Azure Container Apps were updated in dependency order. Every app is healthy, latest-ready aligned, on 100% latest-revision traffic, and reports the exact release metadata.
- Public UI, health, readiness, and unauthenticated access-boundary smoke checks pass.
- The production signed-out shell passes desktop and 390px mobile layout checks without horizontal overflow or browser warnings/errors.

## Deployment safety

The full Bicep apply was not performed. Exact-tag what-if reported 18 modifications, 9 no-change resources, 13 unsupported items, and 3 ignored items, including live topology/storage drift risk. The rollout therefore changed only the six existing Container App images and their non-secret release metadata.

Rollback archives for both the original June baseline and the immediately preceding July image set were retained outside the repository before mutation. The targeted rollout controller was configured to stop on any failed gate and restore all attempted apps in reverse order.

## Remaining human gates

The browser had no authenticated PatchForge session, so the following are explicitly pending:

- signed-in Microsoft Entra UAT through Patch & CVE Catalogue, Vendor Catalogue, Customer Estate, Ask PatchForge, Reports, and Admin;
- a fresh signed action pack and verification;
- fresh Customer, Board, and CAB DOCX/PDF export and visual review;
- cleanup of any production validation records created by that UAT.

No signed-in UAT, signed-pack, report-export, or cleanup success is claimed by this evidence set.

## Evidence files

- `release-summary.json`
- `build-push/acr-image-digests.json`
- `deploy-apply/containerapp-revisions.json`
- `live-smoke/public-http-smoke.json`
- `live-ui/uat-summary.json`

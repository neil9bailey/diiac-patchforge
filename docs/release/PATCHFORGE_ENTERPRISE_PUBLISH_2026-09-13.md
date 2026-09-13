# Enterprise candidate publishing plan

Date: 2026-09-13. Epic: `EPIC-PF-ENTERPRISE-READINESS-20260913`.

The user requested publishing the enterprise improvements, synchronising repositories, updating Azure and providing tests with success criteria. This authorises the release work; it does not create missing test results, protected environment approval or commercial acceptance.

## Source and validation

Publish the reviewed hardening changes from `codex/patchforge-enterprise-review-20260913` through the protected `main` pull-request workflow. The original checkout's source/collector edits are already represented upstream; retain their named recovery stash rather than overwrite newer fixes. The two untracked June evidence directories remain local and are excluded from publication.

The [local validation record](../validation/PATCHFORGE_ENTERPRISE_REVIEW_VALIDATION_2026-09-13.md) records 108 backend, 44 frontend, 53 Python, 9 collector and 4 browser tests, plus a passing production build. Remote required CI/security checks must also pass on the candidate; local results do not bypass branch protection.

## Azure scope and prerequisites

- Use `scripts/publish_patchforge_production.ps1` with the full released commit and new matching image tag, baseline and report context. Never reuse an existing image tag or July approval artifact.
- Preserve existing authentication, tenant enforcement, secret references, storage, custom domains and access assignments.
- The protected GitHub production workflow must produce an explicitly reviewed, attested authorization bound to the exact release inputs. Do not construct approval records locally or change environment/branch protection.
- Existing Azure/Docker/GitHub sessions are available. Actual Key Vault signing access must pass the publisher's preflight; no new access assignment is included automatically.
- Publisher backs up current images outside Git, verifies registry digests and signed provenance, updates the six apps in order and verifies readiness/public smoke. Failure triggers its reverse-order image rollback.

## Separate configuration gap

Image-only publishing does not change Container App environment metadata or scheduler scaling. September readback still showed the July image tag and scheduler minimum zero. The repository's Bicep specifies scheduler minimum one, but full-template application includes additional changes and is not a substitute for a narrow reviewed plan.

A separate configuration plan must bind any intended updates to `PATCHFORGE_IMAGE_TAG`, `CONTAINER_IMAGE_TAG`, `PATCHFORGE_COMMIT_SHA`, `PATCHFORGE_RENDERER_COMMIT`, `PATCHFORGE_PRODUCT_BASELINE`, `PATCHFORGE_REPORT_CONTEXT_VERSION`, and scheduler minimum one. Capture exact previous values, identify continuous compute cost, preserve all other configuration and specify exact rollback/readback. Do not silently append configuration changes to an image-only authorization.

## Acceptance and handoff

Use the [user acceptance checklist](../validation/PATCHFORGE_ENTERPRISE_USER_ACCEPTANCE_2026-09-13.md) only after the operator confirms the actual running candidate. The current subscription/repository exposes a production deployment, not an implemented staging/UAT environment. New live role journeys, exact report bytes and human acceptance remain outstanding. A successful image update would be a testable deployment, not proof of G4/G5 completion or general availability.

This plan does not assert that a commit, merge, deployment or acceptance has already succeeded. Record actual publishing and deployment outcomes separately with their immutable identities and evidence.

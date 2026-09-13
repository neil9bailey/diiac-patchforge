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

## First candidate execution evidence

- Candidate `a5f2f74a4afc79a4839c419b17d642c02b729c60` was pushed as [PR 33](https://github.com/neil9bailey/diiac-patchforge/pull/33). Its guarded publisher dry run passed; no execution was attempted.
- [CI run 34732840856](https://github.com/neil9bailey/diiac-patchforge/actions/runs/34732840856) passed application, Python, collector and Bicep checks but failed all three container vulnerability scans. Runtime: 9 high/3 critical; frontend: 2 high; bridge: 2 high. These are OS package findings, distinct from npm dependency results. The failed run remains part of the evidence.
- [Security run 34732840855](https://github.com/neil9bailey/diiac-patchforge/actions/runs/34732840855) passed dependency review, both CodeQL analyses and repository scanning. Container fixes still require their own passing run.
- Live Key Vault metadata read for `pf-pack-signing-prod` returned `ForbiddenByRbac` with no applicable assignment. The current identity's observed inherited role is Owner; that does not confer Key Vault data-plane signing access. No role assignment was created or modified. Signing access requires explicit authorization and a narrowly scoped grant or an already-authorized release operator.
- All six apps still report July 11 release environment metadata while their configured image tag names the July 14 image release. Scheduler minimum remains zero. Preserve this distinction in testing and release claims.
- Targeted same-distribution Dockerfile upgrades subsequently built locally for all three image types, preserving pinned base digests and non-root users. Readback found Alpine OpenSSL libraries `3.5.8-r0`, Bookworm PCRE2 `10.42-1+deb12u1`, and Trixie gzip `1.13-1+deb13u1`, PCRE2 `10.46-1~deb13u2`, SQLite `3.46.1-7+deb13u2`, Perl `5.40.1-6+deb13u1`. Nginx configuration, Node syntax and Python dependency consistency checks passed. Publisher contract regression: 6/6 passed. Vulnerability closure still requires the subsequent protected CI scan; these local builds are not published Azure images.

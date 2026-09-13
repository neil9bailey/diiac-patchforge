# Enterprise review validation evidence

Date: 2026-09-13

Candidate base: `a102f69809a92d7c51983c513ab23b70dbe932f6` plus local diff on `codex/patchforge-enterprise-review-20260913`.

## Scope

Original checkout and existing edits are preserved. Work is in `F:\code\diiac\patchforge-enterprise-review-20260913`. No deployment, production data mutation, contract acceptance or customer installation was performed.

The workspace gate contract uses local compatibility mode because `team_validate_handoff` is unavailable. The [handoff record](enterprise-review-2026-09-13-handoffs.json) does not claim Cortex attestation or production acceptance.

## Read-only live evidence

- Six apps in `rg-diiac-patchforge-prod` use tag `pfaz-enterprise-20260714d-f51802d`, provisioning `Succeeded`, matching latest/latest-ready revisions.
- All six have minimum zero and maximum one replica.
- Scheduler: no probes; HTTP concurrent-request scaling; replica list empty.
- Public UI, API health/readiness: HTTP 200.
- Readiness: `ready`, PostgreSQL, authentication and tenancy required.
- Unauthenticated protected metrics: HTTP 401, `missing_bearer_token`.
- Image digests were not re-attested; fresh production report/export proof is not claimed.

## Local verification

- Python contracts/runtime: 53 passed.
- Collector: 9 passed.
- Focused scheduler/automation: 12 passed; complete backend additionally passed final warning-preservation regression.
- Security boundary focused tests: 5 passed; corrected existing API scenario and final boolean case passed.
- Frontend focused trust/Guide tests: 9 passed. Final complete frontend suite: **44/44 passed**, including nine tenant-context regression cases; repeated after Reports accessibility fixes with 44/44 passing in 101.19 seconds.
- Frontend audit: original four findings (one high, three moderate); targeted compatible updates now return zero.
- Backend install audit: zero findings.
- Initial full backend: 107/108 passed; remaining purge fixture still used the deliberately retired endpoint. The fixture now seeds the historical record directly and retains the purge assertions. Final full backend: **108/108 passed**.
- Final production frontend build and TypeScript: passed after the accessibility fixes. Entry JavaScript 274.23 kB against 500 kB; total 644.15 kB against 650 kB. Feature and authentication chunk budgets also passed. Total bundle headroom is small and should be preserved in subsequent work.
- Independent final diff audit: no outstanding actionable findings. This was a static review, not a penetration test or production acceptance.
- Python runtime and development requirements audited with `pip_audit --no-deps --disable-pip`: no known vulnerabilities in the directly listed dependencies. The full resolver audit did not complete and was interrupted; transitive dependency coverage is not claimed.
- Browser first run: existing two journeys passed; two new Guide journeys failed because their exact text selectors omitted the visible `Responsibility:` prefix. With role-scoped selectors corrected, the next run exposed real Reports keyboard-access and mobile-overflow defects. The decision-pack scroll region is now labelled/focusable and report columns collapse at viewport widths of 1280px or less, preserving wider desktop sizing. Final complete rerun: **4/4 passed** in 50.1 seconds, including role handoffs, Guide-to-Reports navigation, keyboard focus, horizontal-overflow assertions and tagged WCAG axe checks. This is focused accessibility coverage, not whole-product accessibility certification.
- Manual browser inspection against an isolated, real local JSON API: Guide loaded with empty estate/evidence states, role responsibilities and report guidance; Guide-to-Reports navigation worked and downloads remained disabled without a verified pack. This used development preview authentication, not Entra or a production runtime. Temporary servers and tabs were closed afterwards.
- Targeted common-secret-pattern scan of changed files: no matches. This is not a comprehensive secret-history scan.
- Changed Markdown: 43 relative links checked, no missing targets/fragments; final independent documentation review found no substantive commercial overclaims after configured-tag wording was qualified.

### Reproduction commands

Run from the isolated worktree unless a prefix is supplied:

```powershell
npm --prefix backend-api test
npm --prefix Frontend test
npm --prefix Frontend run build
npm --prefix Frontend run test:e2e
npm run collector:test
python -m pytest -q --basetemp C:\Users\Public\patchforge-review-pytest-20260913
npm --prefix Frontend audit --audit-level=moderate
npm --prefix backend-api audit --audit-level=moderate
python -m pip_audit -r requirements-runtime.txt --no-deps --disable-pip
python -m pip_audit -r requirements-dev.txt --no-deps --disable-pip
git diff --check
```

The backend and frontend npm audits were repeated after implementation and both returned zero known vulnerabilities. Direct Python dependency audits must not be interpreted as full transitive coverage.

## Compatibility

- `POST /api/patchforge/action-packs` now returns HTTP 410. Use the existing runtime decision-pack workflow. Historical digest inspection is not signature authenticity.
- Workflow IDs are server generated; only `triage` and `ciso_review_required` are supported. Arbitrary status strings cannot issue approval or verified closure.
- Scheduler can return `incomplete`, `completed_at=null`, `finished_at` and `incomplete_work_items`. Incomplete cycles have no success checkpoint; terminal failures require reconciliation.
- No historical production record is rewritten or retrospectively trusted.
- Tenant switches clear prior UI state and reject late results from old contexts. Server actions already sent are not cancelled; existing server-side tenancy and role controls remain authoritative.

## Acceptance limits

Mock-backed browser/API checks are engineering evidence. They do not establish live Entra acceptance, customer separation, exact production report bytes, collector customer-machine acceptance, legal approval or service commitments. These remain pilot/release requirements in the [review](../product/PATCHFORGE_ENTERPRISE_REVIEW_2026-09-13.md).

The live sign-in journey reached Microsoft's password screen; no password was entered and signed-in acceptance was not completed. A new candidate deployment and accountable end-user session are required to close G4. G5 formal security/compliance acceptance and G6 human release remain open; no commit, push or Azure mutation was performed in this review.

Local handoff records mark G0-G3 complete and G4 blocked pending the live session/candidate. They are validated against the workspace JSON schema in local compatibility mode; this does not substitute for server attestation or a human release decision.

# PatchForge 14-Area Improvement Closure Matrix

Date: 2026-07-14

Scope: the enterprise automation, trust, reporting, operator-experience, delivery, and release improvements requested after the 2026-07-11 readiness review.

## Decision

The implementation candidate contains the planned local changes for Areas 4-13. It is **not yet a completed production release**. Areas 1-3 and 14 remain live-gated, and the Windows collector still requires a trusted PatchForge code-signing certificate plus representative customer-machine acceptance before it can be described as a customer-ready unattended package.

This document does not replace `CURRENT_RELEASE.md`, `VALIDATION_OUTPUTS.md`, `QUALITY_GATES_REPORT.json`, or `RELEASE_BASELINE_MANIFEST.json`. Those records must only be updated after a clean commit, remote checks, accountable approval, Azure rollout, live readback, signed-in UAT, report inspection, and cleanup evidence exist.

## Status Language

| Status | Meaning |
| --- | --- |
| Implemented locally | The source, UI, script, test, or infrastructure definition is present in this working candidate. |
| Validated locally | A relevant automated check has passed against the candidate; the final combined release run may still be pending. |
| Live pending | Production execution or readback has not yet been performed for this candidate. |
| Human gate | An accountable user, approver, certificate owner, or customer representative must perform or approve the step. |
| Out of scope | The action is intentionally prohibited by the PatchForge governance boundary. |

## Closure Matrix

| Area | Current status | Implementation evidence | Operator or user action | Validation evidence required for closure | Remaining gate |
| --- | --- | --- | --- | --- | --- |
| 1. Signed-in role UAT | Live pending; human gate | Entra-backed role checks in `backend-api/auth.js`; role-aware frontend actions in `Frontend/src/App.tsx` | Sign in through the UI and exercise Reader, Analyst/Lead, CAB, Auditor, and Admin journeys without sharing credentials or bypassing MFA | Record role, permitted and denied actions, selected finding/pack, UTC time, and screenshots or browser evidence | Authenticated production session and accountable user acceptance |
| 2. Report and artifact proof | Live pending; human gate | Exact-byte artifact generation in `backend-api/patchforge/exportArtifacts.js`, report routes in `backend-api/server.js`, and signed export support in `runtime/governance_runtime.py` | Select an explicit verified pack, download ZIP/DOCX/PDF outputs, verify manifests/digests, and visually inspect every report page | Fresh production pack; exact SHA-256/digest verification; DOCX and PDF render review; ZIP member verification | Fresh production artifacts and visual QA are not yet evidenced |
| 3. UAT data cleanup | Live pending; human gate | Typed purge preview/confirmation controls in `Frontend/src/areas/GovernanceAreas.tsx` and protected Admin API paths | Preview only the prefixed UAT records, enter the typed confirmation, execute, then search/read back to prove absence | Before/after record list, purge plan, removal result, absence check, and retained audit event | Must follow Areas 1-2; no cleanup is required until live UAT creates records |
| 4. Infrastructure desired state | Validated locally; live pending | Explicit `postgresMode`, existing PostgreSQL references, release metadata, probes, scale rules, and explicit ACR/storage posture in `infra/bicep/` plus guarded planning in `scripts/plan_azure_deployment.ps1` | Review the production parameter file and captured what-if; reject any unexplained replacement, deletion, or storage/database change | Bicep build passed; what-if contains six intentional Container App modifications plus one managed-environment expression delta, with no create/delete/replace and PostgreSQL ignored | Accountable approval and Azure apply/readback |
| 5. Server-owned evidence workflow | Validated locally; live role journey pending | Finding-scoped evidence records/events in `backend-api/patchforge/evidenceReview.js`; protected submit/review/reopen routes; Review & Approve queue in `Frontend/src/areas/LegacyAreas.tsx` | Select one finding, submit source-bound evidence, record a rationale, accept/reject by role, and reopen or replace expired/invalidated evidence | Backend 89/89 passed, including forged/cross-finding rejection, content/revision/event replay, expiry/reopen, conflict, and actor attribution | Signed-in production role journey |
| 6. External and optional-AI security boundary | Validated locally; production readback pending | Outbound allowlist, DNS/IP checks, redirect/size/time limits in `backend-api/patchforge/outboundFetch.js`; server-owned AI evidence construction in `backend-api/server.js` | Use approved public source URLs only; treat AI output as advisory; inspect evidence sources and missing evidence rather than caller flags | Backend 89/89 passed, including SSRF/private/link-local/metadata/redirect limits and forged caller evidence flags having no effect | Production configuration readback |
| 7. Immutable, verifiable exports | Implemented locally; Area 2 live proof pending | Append-only export records and exact-byte digests in `backend-api/patchforge/exportArtifacts.js`; ZIP/report routes and runtime signing integration | Download only from a verified selected pack; retain pack ID, artifact ID, manifest, digest, signing provider, and verification result together | Mutation of JSON, DOCX, PDF, ZIP, or a ZIP member must fail verification; duplicate IDs must not overwrite prior artifacts | Fresh signed production artifacts and visual inspection |
| 8. Windows collector lifecycle | Validated locally; customer acceptance human gate | Fail-closed build/verify/setup/upgrade/revoke/uninstall scripts under `scripts/`; least-privilege auth, heartbeat, durable FIFO spool/replay, bounded quarantine, lifecycle state, and local recovery behavior in `collector/` | Verify signature and manifest before install; use managed identity or approved OS-injected auth; monitor heartbeat; preserve spool/retry and lifecycle evidence; revoke both locally and in Entra | Collector 8/8 and Windows lifecycle passed; backend replay idempotency/conflict tests passed; production signature and clean Windows VM UAT remain external | Trusted PatchForge signing certificate and representative customer-machine UAT |
| 9. Resilient scheduler and worker | Validated locally; live health readback pending | Idempotency keys, leases, checkpoints, bounded retry, dead-letter/quarantine, replay/reconciliation, backlog/checkpoint SLOs, and operator actions in `backend-api/patchforge/automationWork.js` and `worker.js` | In Admin, investigate alerts and failure reasons, correct dependencies, allow bounded replay, and confirm checkpoint progress; never delete failure evidence to make health green | Backend 89/89 passed, including restart/replay determinism, poison-item isolation, lease recovery, SLO alert, backlog drain, and checkpoint behavior | Live worker/scheduler health readback |
| 10. CI, security, and provenance | Validated locally; remote enforcement pending | Pinned CI actions, dependency audits, Playwright, collector lifecycle checks, Trivy image scans, SPDX SBOMs, CodeQL/dependency review, artifact attestations, Dependabot, and production approval workflow in `.github/` | Review every required check and attestation; approve the protected production environment only for the exact commit/tag/baseline | Python and npm audits passed; all three unique images build and have zero high/critical Trivy findings; GitHub environment reviewer and secret protections are configured | Push, remote GitHub checks, branch protection, approval attestation, and merge |
| 11. Frontend performance and bundle control | Validated locally; remote CI pending | Route/area lazy loading in `Frontend/src/App.tsx`, split area modules under `Frontend/src/areas/`, and enforced budget in `Frontend/scripts/check-bundle-budget.mjs` | Use the six main areas normally; report any area that fails to load without losing already loaded data | Build and 24/24 unit tests passed; entry 268.40 kB, largest feature 50.41 kB, and total JavaScript 628.61 kB are within enforced budgets | Remote CI |
| 12. Accessible, responsive, failure-tolerant UI | Validated locally; signed-in UAT pending | Keyboard navigation, focus management, live regions, responsive tables/drawer, stable selection, and partial-load retry in `Frontend/src/`; Playwright/axe coverage in `Frontend/e2e/` | Operate by keyboard, keep visible focus, close the mobile drawer with Escape, use labelled search/controls, and retry only failed panels when a partial-load warning appears | Playwright Chromium 2/2 and axe WCAG A/AA passed, including keyboard, mobile focus/Escape, Reader/Admin, selection, and partial-failure journeys | Signed-in production accessibility and responsive UAT |
| 13. Operator and release documentation | Implemented locally in this candidate | This closure matrix; refreshed operational guide, collector/automation runbook, readiness summary, backlog update, and documentation index | Start from `docs/README.md`, follow the role and workflow guidance, and keep local/live/human-gate status explicit in every release handoff | Documentation inventory, Markdown link resolution, JSON parse for closure/release records, and diff review for unsupported claims | Final release metadata refresh after Areas 1-2 and 14; legal/licensing portfolio remains a separate review gap |
| 14. GitHub and Azure production release | Live pending; human gate | Candidate release approval workflow and guarded publisher in `.github/workflows/production-release-approval.yml` and `scripts/publish_patchforge_production.ps1` | Commit cleanly, push, wait for required checks, approve the exact release authorization, preserve rollback images, publish immutable images, deploy, and verify all six apps | Local/remote SHA alignment; green checks; approval attestation; ACR digests; signed image manifest; active/latest-ready revisions; HTTP/readiness; Areas 1-3 evidence | No GitHub sync, merge, Azure mutation, or production UAT is claimed by this document |

## Operating Sequence

```text
Catalogue and sources
  -> customer/vendor context
  -> finding-scoped evidence submission
  -> role-authorized human review
  -> deterministic analysis and blockers
  -> explicit verified pack selection
  -> signed immutable exports
  -> human approval and distribution
  -> expiry/drift monitoring and reopen
```

Automation may ingest, normalize, correlate, prioritize, compile, retry, reconcile, prepare reports, sign, verify, and alert. It may not deploy a patch, mutate a customer system, accept risk, approve CAB, mark evidence reviewed, or close a decision without the required human role and evidence.

## Release Stop Conditions

Stop the production release when any of the following is true:

- the source commit, requested tag, approval artifact, image metadata, or ACR digest disagree;
- the worktree used for a release build is dirty or includes unreviewed evidence files;
- Bicep what-if includes an unexplained replacement, deletion, database change, storage change, or identity change;
- a required GitHub check, security scan, SBOM, attestation, or environment approval is missing;
- a Container App is not healthy, latest-ready, or receiving the intended traffic;
- readiness cannot prove PostgreSQL, authentication, tenant, and signing dependencies;
- a report download is not bound to an explicitly selected verified pack;
- a DOCX, PDF, ZIP, or manifest digest fails verification;
- signed-in UAT cannot prove role boundaries or creates records that cannot be safely removed;
- the trusted Windows collector signature or customer-machine acceptance is absent while customer readiness is being claimed.

## Operator References

- [Operational User Guide](../operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md)
- [Collector and Automation Runbook](../operations/PATCHFORGE_COLLECTOR_AND_AUTOMATION_RUNBOOK.md)
- [Automation and UI Readiness Review](PATCHFORGE_AUTOMATION_AND_UI_READINESS_REVIEW_2026-07-11.md)
- [Current Readiness Summary](PATCHFORGE_READINESS_SUMMARY.md)
- [Deployment Readiness](../deployment/PATCHFORGE_DEPLOYMENT_READINESS.md)
- [Azure Container Update Loop](../deployment/PATCHFORGE_AZURE_CONTAINER_UPDATE_LOOP.md)

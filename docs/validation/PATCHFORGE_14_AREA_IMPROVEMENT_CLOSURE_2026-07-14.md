# PatchForge 14-Area Improvement Closure Matrix

Date: 2026-07-14

Scope: the enterprise automation, trust, reporting, operator-experience, delivery, and release improvements requested after the 2026-07-11 readiness review.

## Decision

The `f51802d` implementation candidate was published successfully as the six-image `PF-AZ-ENTERPRISE-AUTOMATION-20260714D` Azure rollout. It is **not yet a completed product acceptance**. Area 14 passed for that image-only release and Area 1 is partial. Area 2 has a strict local fix for the Azure EC/P-256 enum-label mismatch but remains blocked until live DOCX verification passes; Area 3 and the navigation/verified-ZIP follow-ups are also closeout-branch-only. The repaired IaC What-If passed but is not fully determinate, so full apply remains a separate exact-approval gate.

The root release records distinguish the live `f51802d` approval/provenance/digest/revision/smoke/Admin-health evidence from later local closeout work. Overall state remains partial and must not be promoted until report integrity, live role and closeout workflows, exact-ID cleanup proof, separately approved IaC apply, collector, and legal gates close.

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
| 1. Signed-in role UAT | Partial; human gate | Entra-backed role checks in `backend-api/auth.js`; role-aware frontend actions in `Frontend/src/App.tsx` | Repeat signed-in journeys for Reader, Analyst/Lead, CAB, Auditor, and Admin without sharing credentials or bypassing MFA | `PatchForge.Admin` sign-in and 13/13 Admin health checks passed; no other role journey is claimed | Complete permitted/denied role evidence and accountable user acceptance |
| 2. Report and artifact proof | Strict fix passed locally; live proof blocked | Exact-byte exports plus explicit normalization of supported `KeyType.ec` / `KeyCurveName.p_256` labels to `EC` / `P-256` before full ES256 verification | Deploy exact closeout source; download ZIP/DOCX/PDF outputs, verify manifests/digests, and inspect every report page | Local tests retain cryptographic legacy compatibility and reject unknown aliases/curves, malformed coordinates, wrong keys, and tampered/short signatures; live `f51802d` still failed closed | Fresh live exact-byte ZIP/DOCX/PDF verification and visual QA without bypassing verification |
| 3. UAT data cleanup | Implemented/tested locally; live human gate | Server-issued tenant-scoped expiring preview token bound to SHA-256 digest of displayed exact record IDs; audit retained | Preview, inspect exact IDs, then execute once with the issued token | Direct execution, cross-tenant use, record drift, and token reuse fail closed; not live | Live cleanup, absence readback, retained audit |
| 4. Infrastructure desired state | What-If passed; full IaC not applied | Existing PostgreSQL references, preserved images/environment, release metadata, probes, and scheduler continuity | Resolve/approve unsupported results and bind approval to exact source/delta | 43 resources: 0 destructive, 7 modify, 20 no-change, 3 ignore, 13 unsupported; 0 image changes; 0 environment removals; metadata on six apps; +12 probes; scheduler-only intentional `min0→1` because its timer is in-process | Separate exact approval and post-apply readback required |
| 5. Server-owned evidence workflow | Validated locally; live role journey pending | Finding-scoped evidence records/events in `backend-api/patchforge/evidenceReview.js`; protected submit/review/reopen routes; Review & Approve queue in `Frontend/src/areas/LegacyAreas.tsx` | Select one finding, submit source-bound evidence, record a rationale, accept/reject by role, and reopen or replace expired/invalidated evidence | Backend 89/89 passed, including forged/cross-finding rejection, content/revision/event replay, expiry/reopen, conflict, and actor attribution | Signed-in production role journey |
| 6. External and optional-AI security boundary | Validated locally; production configuration apply pending | Outbound allowlist, DNS/IP checks, redirect/size/time limits in `backend-api/patchforge/outboundFetch.js`; server-owned AI evidence construction in `backend-api/server.js` | Use approved public source URLs only; treat AI output as advisory; inspect evidence sources and missing evidence rather than caller flags | Backend 89/89 passed; repaired IaC preserves `PATCHFORGE_SEARCH_MODE` and `PATCHFORGE_OPENAI_AGENT_ENABLED`; full apply was not performed | Separately approved production configuration readback |
| 7. Immutable, verifiable exports | Verified ZIP and signature fix tested locally; live proof open | Append-only exact-byte records, verified ZIP UI, strict EC/P-256 normalization, and runtime signing integration | Deploy exact closeout source and retain pack/artifact/manifest/digest/signing/verification evidence together | Local cryptographic positive/negative coverage passed; live DOCX correctly failed closed and no live ZIP/DOCX/PDF acceptance is claimed | Deploy and complete fresh live artifact verification/inspection |
| 8. Windows collector lifecycle | Validated locally; customer acceptance human gate | Fail-closed build/verify/setup/upgrade/revoke/uninstall scripts under `scripts/`; least-privilege auth, heartbeat, durable FIFO spool/replay, bounded quarantine, lifecycle state, and local recovery behavior in `collector/` | Verify signature and manifest before install; use managed identity or approved OS-injected auth; monitor heartbeat; preserve spool/retry and lifecycle evidence; revoke both locally and in Entra | Collector 8/8 and Windows lifecycle passed; backend replay idempotency/conflict tests passed; production signature and clean Windows VM UAT remain external | Trusted PatchForge signing certificate and representative customer-machine UAT |
| 9. Resilient scheduler and worker | Validated locally; Admin health passed | Idempotency keys, leases, checkpoints, bounded retry, dead-letter/quarantine, replay/reconciliation, backlog/checkpoint SLOs, and operator actions in `backend-api/patchforge/automationWork.js` and `worker.js` | In Admin, investigate alerts and failure reasons, correct dependencies, allow bounded replay, and confirm checkpoint progress; never delete failure evidence to make health green | Backend 89/89 passed and signed-in Admin displayed 13/13 passing health checks; this does not by itself prove every backlog/checkpoint recovery case | Retain live backlog/checkpoint/recovery evidence during continued operation |
| 10. CI, security, and provenance | Partial pass | Pinned CI actions, dependency/security checks, SBOMs, attestations, and production approval workflow | Approve only the exact source/tag/baseline | Deployed `f51802d` totals remain 39/89/24/2/8; separate closeout validation passed 51/94/27/2/8 plus build/bundle and IaC | Remote enforcement and a new exact release approval |
| 11. Frontend performance and bundle control | Validated locally; remote CI pending | Lazy areas and enforced bundle budget | Report any area-load failure without losing loaded data | Deployed candidate: 24/24, entry 268.40 kB, total 628.61 kB. Closeout branch: 28/28, build PASS, entry 270.20 kB, total 634.39/650 kB | Remote CI and live proof |
| 12. Accessible, responsive, failure-tolerant UI | Validated locally; signed-in UAT pending | Keyboard navigation, focus management, live regions, responsive tables/drawer, stable selection, and partial-load retry in `Frontend/src/`; Playwright/axe coverage in `Frontend/e2e/` | Operate by keyboard, keep visible focus, close the mobile drawer with Escape, use labelled search/controls, and retry only failed panels when a partial-load warning appears | Playwright Chromium 2/2 and axe WCAG A/AA passed, including keyboard, mobile focus/Escape, Reader/Admin, selection, and partial-failure journeys | Signed-in production accessibility and responsive UAT |
| 13. Operator and release documentation | Updated for partial live release | This closure matrix; refreshed root release controls, readiness/deployment records, and sanitized release evidence | Start from `docs/README.md`, follow the role and workflow guidance, and keep image-only/live/human-gate status explicit in every release handoff | JSON parse, Markdown link resolution, scoped diff review, and consistency checks across release records | Refresh again after report, UI, cleanup, IaC, collector, and legal gates close |
| 14. GitHub and Azure production release | Passed for `f51802d` image-only rollout; closeout not released | Production approval workflow and guarded publisher in `.github/workflows/production-release-approval.yml` and `scripts/publish_patchforge_production.ps1` | Preserve rollback images outside the repo, retain sanitized evidence, and obtain a new approval bound to the exact closeout source and intended deployment/configuration scope | Approval `29345354677`; attestation; six ACR digests; verified ES256 manifest `d9c8f265...`; six active/latest-ready revisions; public HTTP/readiness; RBAC revocation | Closeout UI/API/IaC changes are not live; Areas 1-3 and full apply/readback remain open |

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
- Bicep What-If includes an unexplained replacement, deletion, database change, storage change, or identity change, or unsupported results are neither resolved nor individually approved;
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

# PatchForge enterprise product review

Date: 2026-09-13

## Recommendation

Develop and sell PatchForge as **the DIIaC product for accountable vulnerability and patch decisions**. Connect a vulnerability to a customer's operational context, expose the evidence and alternatives, record accountable review, and give stakeholders a verifiable decision artifact.

The product has a credible enterprise proposition, but this review does not establish general availability. Position the next offer as a bounded paid pilot once the [Enterprise Offer](PATCHFORGE_ENTERPRISE_OFFER.md) admission conditions are met. A live website and passing code tests are insufficient proof of customer outcome, continuous automation or a contracted enterprise service.

## Reviewed baseline

- Original checkout: `F:\code\diiac\patchforge`, local `main` at `a7c0b41`, six commits behind remote. Existing source-adapter and collector edits were preserved.
- Latest fetched source: `a102f69809a92d7c51983c513ab23b70dbe932f6`.
- Improvement worktree: `F:\code\diiac\patchforge-enterprise-review-20260913`, branch `codex/patchforge-enterprise-review-20260913`, based on that source.
- Reviewed positioning, claims, architecture, operator journeys, intake, priority/comparison, evidence/signing, workflows, scheduling and release configuration. Used read-only Azure/public HTTP checks and current primary vendor sources. No sibling product was modified or portfolio integration exercised.

## Live build is behind the reviewed source

September 13 Azure readback returned six apps using `pfaz-enterprise-20260714d-f51802d`, provisioning `Succeeded`, and matching latest/latest-ready revisions. This verifies the configured tag; image digests were not rebuilt or re-attested in this review.

| Component | Latest-ready revision |
| --- | --- |
| UI | `ca-patchforge-ui-prod--0000041` |
| API/bridge | `ca-patchforge-bridge-prod--0000040` |
| Runtime | `ca-patchforge-runtime-prod--0000031` |
| SRA | `ca-patchforge-sra-prod--0000030` |
| Worker | `ca-patchforge-worker-prod--0000030` |
| Scheduler | `ca-patchforge-scheduler-prod--0000030` |

The UI, API health and readiness returned HTTP 200. Readiness reported PostgreSQL with required authentication and tenancy. Unauthenticated protected metrics returned HTTP 401.

The scheduler had **zero replicas**, minimum zero, maximum one, an HTTP scaling rule and no probes. Its in-process timer cannot refresh feeds while no process is running. Latest Bicep already sets scheduler minimum one, but that setting is not live. July's report-verification corrections and subsequent source security fixes are also absent from this configured production image.

July's failed report UAT remains historical evidence; no new production report success is asserted here. Recheck signed-in roles and fresh DOCX/PDF/ZIP bytes on the actual release candidate before customer use.

## Implemented improvements

The [approved correction ADR](../../governance/adr/ADR-PF-ENTERPRISE-001-trust-boundary-corrections.md) records compatibility changes and verification requirements.

| Finding | Correction | Customer value |
| --- | --- | --- |
| Auxiliary action packs advertised a public test digest as a verified signature | Retired issuance with HTTP 410 and guidance to runtime-signed decision packs; historical inspection distinguishes integrity from authenticity | No fabricated signing assurance |
| Caller IDs and arbitrary workflow states bypassed protected transitions | Server IDs, actor attribution and review-only states; unsupported approval/closure fails closed | Create cannot overwrite a record or manufacture approval |
| String false changed priority/comparison results | Semantic boolean parsing and conservative affirmative aliases | Imported signals preserve their intended meaning |
| Deferred work could complete a scheduler cycle | Completion checks all persisted cycle work; preserves retry, reconciliation and warnings | Real progress and failure visibility |
| Latest-pack QA appeared under a historical pack | Exact snapshot and review pack binding | Confidence follows the selected record |
| Delayed responses could repopulate another tenant's screen | Immediate tenant-state reset and context/generation guards across loaders and async operations | Displayed data and follow-up actions remain bound to the originating tenant context |
| Heartbeat implied installer signature verification | Separate collector reporting from package authenticity | Accurate installation trust guidance |
| Static help offered no route through the task | Tenant/role Guide, workflow links, unavailable states, report purposes and trust explanations | Operators can complete work without engineering help |
| Reports contained a non-keyboard-focusable scroll area and fixed-width mobile columns | Labelled focusable decision-pack region and responsive report columns, checked in desktop/mobile browser journeys | Keyboard access and usable reporting on smaller screens |
| Frontend dependency audit had four findings | Compatible lockfile updates for Vitest/mocker, Browserslist and baseline-browser-mapping | Removes known dependency findings |
| Sales material mixed planned, live and accepted features | Evidence-qualified claims, scoped offers, pilot measures and procurement owners | A concrete, supportable offer |

Changes are local to the review worktree, not deployed or customer-accepted. The workflow correction does not create a full approvals engine. Clients using the retired pack endpoint or arbitrary final statuses must adapt. Tenant display guards do not cancel already-sent server actions or establish shared-customer authorization.

## Defensible differentiation

Prioritisation and exception handling are not unique categories. ServiceNow documents exceptions and compensating-control assessment; Tenable describes exploitability/business-impact prioritisation; Qualys combines risk-based prioritisation with patch management. [ServiceNow](https://www.servicenow.com/docs/r/security-management/vulnerability-response/configure-exception-management-settings.html), [Tenable](https://www.tenable.com/products/vulnerability-management/use-cases/prioritization), [Qualys](https://www.qualys.com/apps/vmdr-patch).

PatchForge's proposed distinction is the combination of service-aware rationale, reviewed evidence, configuration-aware applicability, portable verified artifacts and DIIaC portfolio context. This is a strategy inference, not proof of exclusive capability. Demonstrate cases where severity alone cannot settle the decision: a disabled affected feature, constrained maintenance on an important service, or a mitigation needing an owner and expiry.

A demonstration should answer: why this matters to this estate, what is known, what is missing, who decides next, and which verifiable record the buyer receives.

## Portfolio fit

| Responsibility | PatchForge contribution | Integration proof required |
| --- | --- | --- |
| IT Enterprise / IT Services: broader service decisions | Vulnerability applicability, alternatives and evidence requirements | Tenant/service/asset mapping, authenticated versioned contract, retry/rejection |
| Customer security and change process | Reviewed recommendation and CAB/customer/board outputs | Accepted roles and accountable decision records |
| Scanner, CMDB, ITSM and deployment systems | Source-bound intake and decision artifacts | Tested adapter fields, permissions, failure modes and accepted journey |
| DIIaC assurance practices | Evidence states, lineage and verifiable records | Per-product trust validation; no automatic cross-product approval |

This is a proposed relationship. Shared branding does not establish a completed connector, unified customer entitlement or one-click portfolio workflow.

## Prioritised route to an enterprise offering

| Priority | Improvement area | Definition of done | Owner |
| --- | --- | --- | --- |
| P0 | Release convergence | Tested source, immutable images and metadata match; live exports pass | Engineering / release |
| P0 | Continuous automation | Running scheduler, feed progress, recovery and freshness alerts observed over an agreed period | Platform / operations |
| P0 | Customer and role boundaries | Actual deployment passes permitted/denied access and data separation journeys | Identity / security |
| P0 | Artifact trust | Fresh DOCX/PDF/ZIP bytes verified and all report pages inspected | Product QA / sponsor |
| P1 | Accountable approval lifecycle | Defined roles, evidence, expiry, state transitions and concurrency control | Governance engineering |
| P1 | Audit retention | Protected audit destination and retention/deletion/legal-hold policy; operational audits are currently purgeable | Security / data owner |
| P1 | Recovery and service commitments | Restore exercise and measured service/support evidence | Platform / service owner |
| P1 | Repeatable onboarding | Customer identity, source/asset mapping and offboarding accepted | Customer success |
| P1 | Collector distribution | Trusted signing and clean-machine lifecycle acceptance | Endpoint engineering |
| P1 | Procurement readiness | Licence/terms, dependency rights, data/provider arrangements and service description approved | Commercial / legal / privacy |
| P2 | Portfolio integration | Versioned handoff and accepted complete journey, including invalid/stale/replayed data | Integration engineering |
| P2 | Outcome measurement | Agreed baseline and observed effort, rework and evidence completeness; no invented ROI | Product / sponsor |
| P2 | Connector coverage | Supported adapter/version matrix and diagnostics | Integration / support |
| P2 | Enterprise scale | Representative volume, concurrent-user and backlog tests with agreed limits | QA / platform |

A dedicated customer deployment is the clearest initial scope to validate. Authentication targets one configured Entra directory; customer IDs within its records are not independently enforced customer entitlements. MSP shared-service isolation requires explicit design and acceptance before it can be promised.

## Evidence and acceptance

See [validation evidence](../validation/PATCHFORGE_ENTERPRISE_REVIEW_VALIDATION_2026-09-13.md) for actual command results and limits. Historical totals remain attached to their original candidate. The review does not grant legal approval, certify compliance, establish an SLA or substitute for customer acceptance. The [Enterprise Offer](PATCHFORGE_ENTERPRISE_OFFER.md) defines measurable next steps.

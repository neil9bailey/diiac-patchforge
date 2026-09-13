# PatchForge Enterprise Offer and Pilot Framework

Reviewed: 2026-09-13. Status: proposed commercial packaging and acceptance framework, not a price list, licence grant, service commitment or general-availability declaration.

## Buyer Proposition

**Make vulnerability decisions explainable, accountable and ready for review.**

DIIaC PatchForge brings vulnerability signals, customer asset and service context, evidence review and signed report preparation into a focused workflow. A security lead can see which cases require action, a service owner can supply operational evidence, and an authorised reviewer can explain the eventual decision to CAB, customers or auditors.

The value to prove is less manual decision preparation, clearer outstanding evidence and repeatable reporting. The product does not deploy patches or replace accountable human decisions. Its differentiated combination is a hypothesis to demonstrate in the customer's operating process, not a claim that competing products lack governance features. See the [positioning](PATCHFORGE_PRODUCT_POSITIONING.md) and [claims](PATCHFORGE_CLAIMS_MATRIX.md) documents.

## Current Commercial Readiness

PatchForge is a candidate for a bounded paid pilot once the admission evidence below is met. The repository does not establish unrestricted general availability or representative customer acceptance.

Production readback on 2026-09-13 confirmed six applications configured with tag `pfaz-enterprise-20260714d-f51802d`, latest-ready with provisioning succeeded, and public UI/health/readiness HTTP 200. Image digests and source provenance were not freshly attested. The reviewed source baseline `a102f69` is not live. The live scheduler still has minimum zero and maximum one replica; this is not proof of continuous background automation. Reports, the broader role journeys and customer collector acceptance require their own live proof. A working endpoint is not evidence that a customer can complete the entire outcome.

The current identity path accepts one configured Microsoft Entra directory and derives the business tenant from that directory mapping. Customer records within a business tenant are organisational context, not customer-specific authorisation boundaries. Shared-instance MSP customer isolation is not implemented or proven by those records. Until an explicit customer entitlement model is implemented and accepted, each customer pilot needs an independently validated deployment and authorisation boundary.

Signed artifact integrity and operational audit retention are separate capabilities. Operational audit events can be removed through the broad Admin purge path; protected, tamper-resistant or immutable audit retention is not established. An offer that requires retained audit history must first agree and validate its retention, export, access and purge controls.

Use the [open gaps register](../../PATCHFORGE_OPEN_GAPS_REGISTER.md), [readiness summary](../validation/PATCHFORGE_READINESS_SUMMARY.md) and dated release evidence when preparing an offer. Historical validation totals must remain attached to their original candidates.

## Proposed Packages

These are ways to scope an offer, not implemented licence tiers or feature entitlements. Price, term, deployment model, usage limits, support hours and service levels require an approved order or statement of work.

| Proposed offer | Buyer and scope | Acceptance evidence |
| --- | --- | --- |
| Enterprise Decision Pilot | One named customer scope, agreed services/assets and a finite set of real vulnerability decisions | Source-to-review-to-report journeys, role boundaries, measured effort and a signed customer decision on continuation |
| Enterprise Governance Subscription | Recurring evidence review, decision records and reports for an agreed estate after pilot acceptance | Production operating evidence, supported onboarding/offboarding, recovery proof and an agreed service description |
| MSP Governance Service | A proposed managed service using PatchForge to prepare customer-specific governance records | Independently validated customer deployment/authorisation boundaries, operator permissions, repeatable onboarding and customer-specific report distribution; shared-instance customer entitlement isolation and cross-customer dashboards are not included or proven |
| OT Governance Extension | A separately scoped customer use case requiring safety, support, testing and maintenance evidence | Specialist-reviewed cases with customer operating constraints and approval responsibilities; no OT engineering or safety certification claim |

VendorLens, advisory assistance and the collector are capabilities to describe explicitly within the agreed scope. No package name grants untested connectors, automated approvals, external system writes or customer-machine installation rights.

## Paid Pilot Admission

Admission is a release and customer decision based on a concrete pilot scope. Required evidence:

1. Name the customer sponsor, accountable security lead, service owner, reviewer and support contact. Agree which decisions and real records are in scope, their permitted use, and the start/end dates.
2. Fix the candidate commit, image digests, deployment, tenant and required roles. Complete the applicable release checks and live permitted/denied role journeys on that candidate.
3. Produce at least one representative signed pack and each report format promised in the pilot. Verify exact downloaded bytes and manifests, inspect all report pages, and show understandable recovery when evidence or verification blocks export.
4. Demonstrate the agreed deployment/authorisation boundary, approved data flows, retention/deletion responsibilities and the relevant restore procedure. Customer labels within one business tenant must not be treated as access isolation. Validate any promised audit retention/export and purge controls. If external AI is enabled, document the approved minimized context and provider arrangement.
5. Prove configured feed/worker progress, freshness and alert handling over the agreed observation window if continuous automation is included. Record failures and recovery, not just a green health page.
6. If the Windows collector is included, obtain trusted signing, clean-machine installation and least-privilege authentication proof, followed by offline recovery, upgrade, revocation and uninstall evidence. A pilot can exclude collector installation and use agreed source imports, but must state that exclusion.
7. Complete accountable commercial and legal review of the pilot agreement, software/dependency rights, data handling, support and liability terms. No generated document constitutes that approval.

## Customer Journey and Pilot Exit

Choose representative cases such as a normal patch review, an uncertain applicability case and a time-bound mitigation or deferral. Include an OT case only when OT is part of the agreed pilot. Use authorised real records; do not fabricate customer outcomes or seed production data for a demonstration.

| Stage | User action and useful outcome | Retained proof |
| --- | --- | --- |
| Orient | Confirm account role, tenant, source freshness and the selected advisory | Candidate, environment and role record |
| Establish applicability | Bind the advisory to the exact asset/service, version and relevant configuration | Source references, context and explicit unknowns |
| Prepare a decision | Review alternatives, blockers, ownership and expiry; request missing evidence | Finding-scoped evidence and rationale |
| Review | The permitted human roles accept or reject evidence and record the accountable decision | Actor, role, time, scope and audit trail |
| Report | Select the intended verified pack and download the audience report and retained artifact evidence | Pack/artifact IDs, digest verification and visual QA |
| Revisit | Handle stale evidence, an expired exception or changed facts while preserving the exact signed artifact | Current-state explanation, verified historical artifact and required follow-up; operational audit retention requires its separately validated controls |

Pilot exit requires the agreed journeys to pass, unresolved defects to be recorded with impact and owner, and the customer sponsor to accept or reject continuation against agreed criteria. No critical customer-isolation, identity, signing or report-integrity defect may be accepted as a normal workaround. If temporary UAT records are used, retain authorised cleanup and audit evidence.

Measure outcomes against the customer's existing process. Agree numerical targets before the pilot; the repository supplies no benchmark or guaranteed saving.

| Measure | Definition and collection method |
| --- | --- |
| Decision preparation effort | Operator minutes to assemble the same agreed decision scope; use observed task logs for the baseline and pilot |
| Review cycle time | Elapsed time from complete evidence submission to the named review outcome; report waiting time and active effort separately |
| Evidence completeness | Required evidence items accepted divided by applicable required items, with rejected, expired and unknown items shown separately |
| Report preparation effort | Operator minutes from an agreed reviewed state to a verified, readable audience report; record failed attempts |
| Rework | Number of cases returned for missing, stale or incorrectly scoped evidence, with reasons |
| Traceability and usability | Whether a reviewer can identify source, scope, decision, approver and next action in the delivered artifact without engineering help |
| Operational continuity | Configured jobs completed, freshness breaches and recovery time during the agreed observation window |

These measures can be collected manually during the pilot; this document does not claim built-in commercial analytics. Do not turn a small pilot sample into an annual ROI or security-risk reduction claim without a defensible method and customer approval.

## Proposed Portfolio Handoff

PatchForge is the specialised vulnerability/patch-decision member of the DIIaC portfolio; IT Enterprise / IT Services provides the broader service-decision context. The current relationship is described as harness-ready, not an accepted integration. Shared evidence and signing principles do not imply shared identity, data or trust infrastructure.

A future API/event handoff should be reviewed as a separate interface change and specify:

- sending and receiving product, contract version, correlation ID and customer/tenant mapping;
- service, asset and decision references with explicit ownership and permitted data use;
- artifact digest, signer/trust context, evidence review state, decision state and human approval state;
- observation/expiry time and whether the record is current, historical or superseded;
- authentication, authorisation, idempotency, retries, rejection and reconciliation;
- read-only context transfer versus a separately authorised downstream action.

An imported signed record must not automatically confer approval or close a receiving product's evidence gates. Integration acceptance must prove identity and tenant separation, exact artifact verification, stale/invalid-record rejection, replay behaviour and a human-readable cross-product journey. Until then, offers should state that any inter-product transfer is a scoped integration deliverable; do not advertise one-click portfolio operation.

## Procurement and Operating Ownership

Owner entries below identify accountable roles to assign, not people who have already approved the work.

| Gap or buyer question | Accountable role | Evidence required before commitment |
| --- | --- | --- |
| Commercial licence, dependency rights and redistribution | Legal/commercial owner | Approved terms, dependency/licence review and permitted distribution; absence of a root LICENSE is not a licence grant |
| Security assurance and vulnerability handling | Security owner | Current threat/control summary, applicable test evidence, supported reporting/remediation process and approved responses to buyer questionnaires |
| Personal/customer data and optional external AI | Privacy/data owner | Approved data map, retention/deletion terms, provider arrangements and applicable customer permissions |
| Availability, scale, backup and recovery | Platform/service owner | Measured operating evidence, restore exercise and approved support/service commitments; no invented uptime or recovery objective |
| Customer onboarding and role assignment | Customer success and identity owner | Repeatable setup/offboarding instructions and accepted tenant/role journeys |
| Customer access isolation for an MSP service | Identity/security and platform owners | Validated deployment/authorisation boundary per customer; any future shared-instance entitlement model needs an explicit contract and accepted cross-customer denied-access tests |
| Audit retention, export and purge | Security/data and service owners | Agreed retention and access policy, retained/exported audit proof and validated purge controls; current broad Admin purge can remove operational audit events |
| Collector delivery and lifecycle | Endpoint/package owner | Trusted signature, clean-machine evidence and accepted install/upgrade/revoke/uninstall procedure |
| Report and customer outcome acceptance | Product owner and customer sponsor | Exact artifact proof, visual QA, readable decision scope and customer-approved pilot results |
| Portfolio and third-party integrations | Integration owner | Approved contract, supported adapter matrix, failure handling and accepted end-to-end evidence |

## Sales and Demonstration Materials

Prepare a concise buyer brief, an accurate capability/evidence matrix, a redacted accepted report sample and a scoped pilot statement of work. Use the [Customer Demonstration Runbook](../demos/PATCHFORGE_CUSTOMER_DEMONSTRATION_RUNBOOK.md) and [Operational User Guide](../operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md) to show one complete customer decision rather than a list of screens.

Each demonstration should make five things clear: why this advisory matters to the selected estate, what is known, what evidence is missing, who must act next, and which verified record the audience can take away. Demo content, roadmap items and accepted production capabilities must be visibly distinguished.

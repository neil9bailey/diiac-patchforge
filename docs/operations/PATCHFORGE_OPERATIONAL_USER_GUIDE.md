# PatchForge Operational User Guide

## Purpose

This guide explains how end users should operate PatchForge day to day. It is written for security leads, service owners, customer assurance teams, CAB participants, and managed-service operators who need a clear, evidence-bound way to understand CVEs, customer exposure, patch applicability, and reportable governance posture.

PatchForge is a governance and assurance system. It helps teams collect source-bound intelligence, match that intelligence to customer assets, identify evidence gaps, ask advisory questions, compare patch versions, and generate signed decision artefacts. It does not replace the people, source systems, or approval processes that remain accountable for the final decision.

## Product Boundary

PatchForge does not:

- scan environments
- exploit vulnerabilities
- generate exploit code or procedural exploit steps
- deploy patches
- mutate production systems
- approve CAB decisions
- accept risk on behalf of an accountable owner
- close evidence gates autonomously
- certify that an environment is secure, safe, compliant, or not vulnerable by itself

PatchForge output is advisory until reviewed evidence and accountable human approval are attached. Reports and signed packs prove what PatchForge knew, when it knew it, what evidence was used, what was missing, and whether final approval had been issued.

## What PatchForge Is For

Use PatchForge when you need to answer operational questions such as:

- Which current CVEs and vendor advisories matter to our estate?
- Which vendors, product families, features, or firmware versions are affected?
- Do we have customer assets that may match this advisory?
- What evidence is missing before we can say a device is in scope, out of scope, patched, or still unknown?
- Does a proposed patch version appear to remediate the advisory according to reviewed source evidence?
- What can we appropriately share with a customer, board, CAB, or service owner today?
- Which human decision is still required?

## Main Navigation

PatchForge is organised around six top-level areas. A selected record can also open the finding detail and Review & Approve workflow without losing the selected finding context.

| Area | Use it for | Typical user question |
| --- | --- | --- |
| Patch & CVE Catalogue | Priority queue, CVE/advisory signals, source state, evidence state, customer matches, and next action | "What needs investigation or review now?" |
| Vendor Catalogue | Vendor/product/advisory context, selected asset, applicability, feature/version evidence, and Patch Compare | "Does this exact advisory apply to this selected asset or proposed version?" |
| Customer Estate | Customer devices, services, discovery/collector evidence, mapping, exposure, and lifecycle state | "Which of our assets may be affected, stale, or missing evidence?" |
| Ask PatchForge | Natural-language advisory questions about vendors, models, features, CVEs, versions, patches, and evidence | "Given what we know, what is the governed posture?" |
| Reports | Explicit verified-pack selection, signed packs, customer/board/CAB/technical reports, and verification context | "Which exact immutable pack am I exporting as proof?" |
| Admin | Configuration, source/worker/collector health, operational alerts, and guarded cleanup | "Is the platform healthy, and what human intervention is required?" |

## Roles And Accountable Actions

The API enforces Microsoft Entra app roles. A disabled or hidden UI control is guidance; the server-side role check is the authority.

| Role | Typical permitted use |
| --- | --- |
| `PatchForge.Reader` | Read governed records and reports; cannot submit or review evidence |
| `PatchForge.Auditor` | Read records plus Admin health/configuration and purge previews; cannot mutate configuration or execute purge |
| `PatchForge.TriageAnalyst` | Ingest and refresh source/asset records and submit finding evidence |
| `PatchForge.SecurityLead` | Review security evidence, run governed analysis, and generate decision packs |
| `PatchForge.ServiceOwner` | Submit and review service/asset-impact evidence within the supported evidence classes |
| `PatchForge.CABApprover` | Review the human-signoff class and generate packs; does not gain general triage authority |
| `PatchForge.RiskOwner` | Review risk-acceptance, control, owner, expiry, and rationale evidence classes |
| `PatchForge.Admin` | All protected PatchForge operations, including configuration and confirmed cleanup |

If an action is unavailable, confirm the signed-in role shown in the account control. Do not ask an operator to share a token, password, certificate private key, or MFA code to work around a missing assignment.

## Operating Principles

Follow these principles every time PatchForge is used operationally.

1. Start from source-bound intelligence.

   Prefer vendor advisories, CVE records, CISA KEV, EPSS, and approved source-feed records. Treat unreviewed source records as inputs, not final evidence.

2. Separate "possibly affected" from "confirmed affected".

   A vendor or product match is enough to investigate. It is not enough to declare customer exposure, non-applicability, remediation, or closure.

3. Record the customer context precisely.

   Vendor, product family, model, firmware/software version, enabled features, disabled features, internet exposure, management-plane exposure, service owner, site, and evidence state all matter.

4. Keep unknowns visible.

   Unknown firmware, unreviewed feature state, missing source review, or absent fixed-version evidence should remain visible as evidence gaps.

5. Do not overclaim.

   PatchForge can say "requires review", "evidence missing", "source-bound advisory indicates", or "proposed version appears to match fixed-version evidence". It must not say "safe", "not vulnerable", "closed", or "approved" unless reviewed evidence and accountable human approval support that claim.

6. Export only decision-grade outputs.

   Reports should show the pack ID, baseline, renderer commit, image tag, evidence state, final approval state, signing provider, and verification state.

## Daily Operational Flow

Use this flow for normal vulnerability and patch governance work.

1. Open Patch & CVE Catalogue.

   Review the priority queue, severity, KEV, EPSS, known-exploited state, patch availability, source/evidence state, customer matches, confidence, and recommended next action.

2. Search or filter the catalogue.

   Search by CVE, advisory ID, vendor, product family, model, affected feature, affected version, fixed version, source name, source feed, urgency posture, or customer match.

3. Select the advisory or CVE row.

   Keep the selected-context panel visible. Read the source posture, evidence state, affected feature, affected/fixed versions, customer matches, blockers, and final approval state. Do not assume that the first record in a refreshed list is still the intended record.

4. Open Vendor Catalogue when applicability or remediation needs review.

   Select the exact customer asset and advisory. Confirm the breadcrumb/context before running applicability or Patch Compare; never let an unrelated fallback asset/advisory drive the result.

5. Open Customer Estate.

   Add or confirm affected customer devices, services, firmware/software versions, exposure state, and feature configuration.

6. Run exposure matching.

   Treat matches as investigation candidates. Review why the match was made and which evidence is missing.

7. Run Patch Compare if a current and proposed version are known.

   Use this to compare current version against affected-version evidence and proposed version against fixed-version evidence.

8. Ask PatchForge a focused question.

   Ask about the selected CVE/advisory, asset, vendor, model, version, feature state, patch version, or evidence gap. Confirm the answer names the intended context. Use it to understand governed posture, not to bypass review.

9. Open Review & Approve from the selected finding.

   Submit immutable finding-scoped evidence with a concise summary, details, source references, and optional expiry. An authorized reviewer must record a rationale before accepting or rejecting it.

10. Resolve expiry, rejection, or conflict states.

    Expired evidence requires refreshed evidence; reopening preserves the audit trail but does not make the old evidence current. If the UI reports an integrity/revision conflict, refresh the queue and resubmit against the current finding revision.

11. Generate a signed pack.

   Use Reports only after the selected assessment has enough context to produce a meaningful output. It is valid for a pack to show blocked decisions and missing evidence.

12. Select the exact verified pack in Reports.

    Check pack ID, finding, creation time/freshness, decision posture, baseline, renderer, image tag, evidence state, final approval, customer context, VendorLens context, and verification. Historical packs remain historical even if live evidence has changed.

13. Export the right report.

   Choose the report type for the audience: customer, board, CAB, technical appendix, or signed decision pack ZIP.

14. Verify and file the output.

   Verify the manifest and exact downloaded bytes, retain the pack/artifact metadata, and store the output with the CAB, customer assurance, risk, or governance record.

## Patch & CVE Catalogue

Use this page as the first stop for global advisory triage. The table is a deduplicated priority queue; the selected intelligence panel and five-step runway show the exact context, what is complete, what is blocked, and the next permitted action.

### What To Review

Focus on:

- CVE or advisory ID
- title
- vendor
- product family
- affected feature
- severity and CVSS
- EPSS score and percentile
- CISA KEV status
- known exploited state
- patch availability
- source feed and source state
- review state
- customer matches
- urgency posture
- final approval state
- last refreshed timestamp
- selected-record context and recommended next action
- evidence review, customer match, and report runway state

### How To Search

Use direct search when you know a specific term:

- `CVE-2024-0001`
- `Fortinet`
- `FortiOS`
- `SSL-VPN`
- `Junos`
- `7.2.7`
- `Cisco ASA`
- `known exploited`

Use filters when you need operational queues:

- Severity: high or critical first.
- KEV: focus known-exploited source signals.
- EPSS threshold: identify higher probability exploitation signals.
- Patch available: identify items with a vendor patch signal.
- Customer match: find advisories that may apply to your estate.
- Review state: separate reviewed source records from pending source records.
- Urgency posture: find items that need scope confirmation or escalation.

If the catalogue is large, use the pagination controls rather than assuming the visible page is the full dataset. If one API source fails, PatchForge keeps successful panels visible and displays a partial-load warning. Use **Retry unavailable sources**; do not discard or reinterpret the successful data merely because one panel is unavailable.

### Correct Interpretation

KEV and EPSS are prioritisation signals. They do not prove that a customer asset is exposed. A customer match means PatchForge found a possible relationship between advisory intelligence and estate data. It does not prove affected status until the evidence is reviewed.

## Customer Estate

Use Customer Estate to add, query, import/discover, and match customer assets and services. Review source, owner, environment, criticality, mapping state, last-seen/heartbeat state, and evidence confidence before using a record in a governed decision.

### Minimum Useful Device Record

For a useful match, capture:

- customer
- site
- vendor
- product family
- model
- firmware or software version
- internet-facing state
- management exposure
- enabled features
- disabled features
- evidence state
- owner
- last checked date

### Free-Text Device Input

You can start with a natural description:

```text
FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only.
```

PatchForge extracts likely fields such as vendor, product family, model, version, enabled features, disabled features, exposure state, and evidence state. The extracted values are not final evidence. Review and correct them before using them in an assessment.

### Evidence State

Use the evidence state to tell reviewers how much trust to place in the record.

| State | Meaning | How to use it |
| --- | --- | --- |
| User-stated unreviewed | A user entered the information, but no reviewed evidence has been attached | Good for triage; not enough for final approval |
| Source-bound pending review | A source or import exists, but has not been accepted by a reviewer | Good for investigation; still not final evidence |
| Reviewed evidence accepted | A named reviewer accepted the evidence | Can support governed decisions |
| Rejected or superseded | Evidence is not valid for the current decision | Do not use for approval without replacement evidence |

### Good Evidence Examples

Useful evidence includes:

- inventory export
- CMDB record
- device controller export
- firmware or software version output
- vendor management console export
- configuration export
- feature state evidence
- firewall or exposure evidence
- service owner confirmation
- change record
- vendor advisory review event

Avoid relying on memory, screenshots without provenance, stale inventory, or unsupported assumptions.

## Exposure Matching

Exposure matching compares customer asset context with current CVEs and advisories. It helps prioritise review work.

A match can be based on:

- vendor name or alias
- product family or alias
- model
- affected model
- affected version
- affected feature
- fixed version
- enabled or disabled feature state
- internet-facing or management exposure
- service relationship

Treat a match as "needs review" unless the evidence shows otherwise. PatchForge should not be used to jump directly from a match to closure, risk acceptance, or customer assurance.

## Patch Compare

Use Patch Compare when you need to compare a current version with a proposed version for a specific advisory or CVE.

### Required Inputs

Provide:

- vendor
- product family
- model
- current version
- proposed version
- advisory or CVE
- affected-version evidence
- fixed-version evidence
- evidence references

### Output Meaning

Patch Compare can return:

- current version affected
- current version unknown
- current version not affected, only when evidence supports it
- proposed version remediates
- proposed version unknown
- proposed version does not remediate
- evidence needed
- recommended posture
- final approval false
- required human review

If fixed-version evidence is missing or unreviewed, treat the proposed version as unknown. Do not claim remediation until the source evidence and customer version evidence are reviewed.

## Ask PatchForge

Ask PatchForge is a natural-language advisor. It helps users understand the governed posture, evidence gaps, and next actions.

### Strong Questions

Ask specific, evidence-rich questions:

```text
We use FortiGate 100F running FortiOS 7.2.7. SSL-VPN is disabled, IPsec is enabled, and management is internal only. For CVE-2024-0001, does PatchForge recommend urgent scope confirmation?
```

```text
We patched Juniper SRX 4100 from version X to version Y. Does reviewed vendor fixed-version evidence show the proposed version remediates the selected advisory?
```

```text
What evidence is required before we can mark this advisory not applicable for Cisco ASA 5516-X with AnyConnect disabled?
```

### Weak Questions

Avoid vague prompts:

```text
Does this CVE require urgent patching?
```

That question is weak unless a CVE/advisory is selected or named, the customer asset is known, the version is known, the affected feature is clear, and evidence state is visible.

### Response Sections

Read every Ask PatchForge response through these sections:

- Short Answer
- Current Governed Posture
- Why
- What We Know
- What We Do Not Know
- Evidence Needed
- Recommended Next Action
- Decision Not Allowed Yet
- Human Approval Required

The most important section is often "What We Do Not Know". It tells the team what must be resolved before a stronger claim can be made.

## Finding Evidence Review

Open **Review & Approve** from the selected finding. The evidence queue is always bound to one persisted vulnerability and its current revision.

### Submit Evidence

1. Confirm the finding ID in the decision runway.
2. Select a supported evidence class.
3. Enter a concise statement of what was verified and for which scope.
4. Add source-bound details. Never paste tokens, passwords, private keys, or other secrets.
5. Add ticket, advisory, test, asset, or configuration references.
6. Add an expiry when the evidence or decision is time-limited.
7. Choose **Submit immutable evidence**.

Submission creates a pending record. It never issues final approval. Inspect the evidence ID, content hash, finding revision, latest event hash, expiry, and audit replay state.

### Review, Reject, Or Reopen

An authorized reviewer must enter a rationale before choosing **Accept**, **Reject**, or **Reopen review**. Review authority depends on the evidence class: CAB signoff, risk-acceptance evidence, and service evidence remain separated by role.

- Accept only evidence that proves the stated fact for the exact finding/asset/advisory scope.
- Reject evidence that is incorrect, unsupported, stale for the decision, or scoped to a different record.
- Reopen when the prior review must be reconsidered. Reopen preserves the original evidence and event history.
- Expired evidence cannot support a current decision. Submit refreshed evidence; do not extend trust by editing the old record.
- An integrity or revision conflict means another relevant change occurred or replay failed. Refresh the queue and act against the current hashes.

Caller-supplied booleans, AI output, unrelated finding reviews, and client-generated "accepted" states cannot satisfy a hard evidence gate.

## Reports

Use Reports when the team needs a signed, replayable, audience-specific record.

### Select The Report Source

Reports only enable DOCX/PDF downloads for a verified decision pack. Use **Verified decision pack** or **Use for reports** to select the exact source. The selector shows pack ID, vulnerability, and creation time; selection is never inferred from unsorted API order.

After selecting, confirm:

- selected pack ID and vulnerability ID;
- decision posture and creation time/freshness;
- source pack verification is `Verified`;
- current versus historical pack warning;
- product baseline, renderer commit, and image tag;
- evidence state and final approval state;
- customer and VendorLens context included or explicitly absent;
- content QA state for the intended report audience.

Changing the selected pack must change the context shown for every report action. If it does not, stop and refresh rather than downloading an ambiguous output.

### Before Export

Check:

- pack ID
- product baseline
- renderer commit
- renderer image tag
- final approval state
- evidence state
- VendorLens context included
- customer context included
- report current or stale warning
- report content QA status

### Report Types

| Report | Audience | Use it for |
| --- | --- | --- |
| Customer Patch Governance Pack | Customer assurance, MSP service review, account team | What is known, unknown, needed, and shareable with the customer |
| Board Vulnerability Summary | Executives, risk committee, senior leadership | Decision summary, top risks, affected vendors/products, exposure, evidence gaps |
| CAB Patch Decision Report | CAB, emergency change, service owner | Change decision request, affected devices, patch applicability, rollback/test evidence needed |
| Technical Evidence Appendix | Technical reviewers, auditors | Detailed evidence references and assessment context |
| Signed Decision Pack ZIP | Governance archive, verification, audit | Signed pack metadata, report bundle, verification material |

### Required Metadata

Every report should include:

- `report_template_version`
- `report_renderer_commit`
- `report_renderer_image_tag`
- `generated_from_pack_id`
- `generated_at_utc`
- `product_baseline`
- `report_context_version`
- `final_approval_issued`
- `signing_provider`
- `verification_state`

This metadata is part of the credibility of the output. It proves which renderer, baseline, pack, and signing path produced the report.

### Verify The Download

Keep the downloaded bytes together with the artifact/manifest response and signing metadata. Verification must cover the exact JSON, ZIP, DOCX, or PDF bytes that were delivered. For a ZIP, verify every member against the signed manifest. Any changed member, changed report, hash mismatch, signature failure, or unverified source pack makes the output unsuitable for distribution as a signed PatchForge artifact.

Visual inspection remains separate from cryptographic verification. Open/render the DOCX and PDF and check pagination, tables, headings, evidence gaps, pack/baseline metadata, final approval state, and audience wording before external use.

## Admin Health And Safe Intervention

Admin health should answer whether the deployed build, API/runtime, storage, signing, source scheduler, worker backlog/checkpoint, and collector lifecycle are ready. A `degraded`, `stale`, `pending`, `revoked`, or alert state requires investigation; it is not a cosmetic warning.

For worker or scheduler alerts:

1. Read the alert code, failure class, affected work item/source, age, threshold, and recommended operator action.
2. Confirm the worker/scheduler lease owner and whether the upstream source, PostgreSQL, and signing dependencies are available.
3. Correct the dependency or configuration problem.
4. Allow only the bounded reconciliation/replay path.
5. Confirm checkpoint advance, backlog reduction, and source-bound pending-review records.
6. Retain the failure, dead-letter, quarantine, replay, and audit records.

Do not delete or rewrite failure evidence to make health green. Replayed source work does not accept evidence, approve a decision, or authorize patch deployment.

For collector operations, follow the [Collector and Automation Runbook](PATCHFORGE_COLLECTOR_AND_AUTOMATION_RUNBOOK.md). Customer distribution requires a trusted signature and package verification; unsigned builds are development-only.

### Guarded Cleanup

Admin cleanup is a two-step operation:

1. Select the narrowest scopes and choose **Preview Purge**.
2. Review the returned collection/count plan, enter the required typed confirmation, and only then execute.

For production UAT, prefix every temporary record so the preview can distinguish it from real tenant data. Capture the before state, plan, result, absence proof, and retained audit event. Never use cleanup to remove signing/verifier core, RBAC, deployment scripts, tests, Git history, restore tags, or release evidence.

## Keyboard, Mobile, And Partial-Service Operation

- Use Tab and Shift+Tab to move through labelled navigation, search, filters, selectors, and actions; a visible focus indicator should remain present.
- On mobile, open the navigation with **Toggle navigation** and close it with the close control, overlay, or Escape. Focus should return to the navigation toggle.
- Tables collapse to labelled mobile rows; use the field labels rather than relying on desktop column position.
- Success and progress messages use polite live status; errors and conflicts use alert announcements.
- A partial-load warning lists failed data sources while preserving successful panels. Choose **Retry unavailable sources** to retry failures without silently switching the selected finding or pack.
- If keyboard focus becomes trapped, the selected context changes unexpectedly, or a report action points at a different pack, stop and record the problem before proceeding.

## Human Review And Approval

PatchForge supports human accountability. It does not replace it.

Final decisions require:

- named owner
- reviewed source evidence
- reviewed customer asset or service evidence
- reviewed version and feature evidence
- reviewed exposure evidence
- decision rationale
- approval record
- expiry date where risk acceptance or temporary deferral is involved
- CAB or governance reference where applicable

If any required evidence is missing, keep the posture at pending review, scope confirmation required, blocked pending evidence, or similar. Do not close the decision by inference.

## Operational Credibility Checklist

Before sharing PatchForge output externally, confirm:

- The report is generated from the explicitly selected verified pack.
- The selected pack ID, vulnerability, creation time, and decision posture match the intended case.
- The source records are current enough for the decision.
- The relevant customer asset or service context is present.
- Evidence gaps are specific and understandable.
- Final approval state is visible.
- Report metadata is visible.
- The signing provider and verification state are visible.
- The exact downloaded bytes and every ZIP member match the signed manifest.
- The DOCX/PDF has been visually inspected for the intended audience.
- The report does not claim PatchForge deployed a patch, approved CAB, accepted risk, or closed evidence gates.
- The report does not say an asset is safe or not vulnerable unless reviewed evidence and human approval support the exact claim.
- The intended audience can understand the current posture without knowing internal source-feed or evidence-model terminology.

## Common Operational Mistakes

Avoid these patterns:

- Treating a CVE/vendor match as confirmed customer exposure.
- Treating a disabled feature as accepted evidence without a reviewed configuration record.
- Treating a vendor patch announcement as proof that a proposed customer patch version remediates the issue.
- Asking Ask PatchForge a vague question without selecting or naming the advisory.
- Letting a refreshed list or partial API failure silently change the selected finding, asset, advisory, or pack.
- Accepting evidence without a source-bound rationale or when the content/revision/event hashes are stale.
- Treating reopened or expired evidence as current without a refreshed evidence submission.
- Exporting a report before checking stale/current warnings.
- Sharing a customer report that hides evidence gaps.
- Claiming final approval when `final_approval_issued=false`.
- Using PatchForge to bypass CAB, risk, service-owner, or customer assurance processes.

## Example Operational Scenario

1. A new high-severity advisory appears for a firewall product family.
2. The security lead opens Patch & CVE Catalogue and filters by vendor, severity, KEV, EPSS, patch availability, and customer match.
3. The service owner opens Customer Estate and confirms affected customer devices, versions, enabled features, and management exposure.
4. PatchForge finds possible customer matches.
5. Vendor Catalogue binds the exact asset and advisory, then Patch Compare is run for the current version and proposed fixed version.
6. The team opens Review & Approve, submits finding-scoped source and customer evidence, and authorized reviewers record accept/reject rationales.
7. Ask PatchForge is used to explain current governed posture and missing evidence.
8. Reports generates a signed pack; the operator explicitly selects and verifies it before downloading the correct audience report.
9. CAB or the accountable owner reviews the evidence and records the human decision.
10. The manifest, signed pack, exact report bytes, and visual QA evidence are archived with the change, risk, or customer assurance record.

## Information To Capture For Support

When a user cannot complete a workflow, capture enough context for diagnosis without including secrets:

- UTC date/time and environment;
- signed-in PatchForge role, not the access token;
- UI area and action attempted;
- tenant label shown in the UI;
- finding/CVE, asset, advisory, evidence, pack, artifact, or work-item ID involved;
- selected-context values immediately before the action;
- visible error/conflict/alert text;
- whether the failure followed a refresh, partial-load warning, expiry, or concurrent review;
- browser/device size for UI issues;
- correlation/run ID, content hash, revision hash, event hash, or artifact digest when displayed;
- a redacted screenshot if it adds value.

Never include passwords, bearer tokens, private keys, raw code-signing certificates, MFA codes, or secret environment values in a support record.

## What Good Looks Like

A credible PatchForge outcome says:

- what the advisory is
- where the source came from
- what customer assets may be affected
- what evidence proves or does not yet prove applicability
- what is known
- what is unknown
- what evidence is needed next
- what PatchForge recommends as the next governed action
- what decision is not allowed yet
- who must approve the final outcome
- whether final approval has actually been issued

That is the core value of PatchForge: clearer operational judgement, stronger evidence discipline, better-governed customer communication, and signed artefacts that preserve the reasoning behind every decision.

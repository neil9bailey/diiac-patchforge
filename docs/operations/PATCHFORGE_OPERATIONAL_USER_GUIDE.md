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

PatchForge is organised around five top-level areas.

| Area | Use it for | Typical user question |
| --- | --- | --- |
| Global Security Action Center | Global CVE, advisory, vendor, KEV, EPSS, source, review, and customer-match posture | "What threats and advisories are active, urgent, or relevant?" |
| Customer Estate | Customer devices, services, configuration evidence, exposure matches, and Patch Compare | "Which of our assets may be affected?" |
| Ask PatchForge | Natural-language advisory questions about vendors, models, features, CVEs, versions, patches, and evidence | "Given what we know, what is the governed posture?" |
| Reports & Packs | Signed packs, customer reports, board summaries, CAB reports, technical appendices, and verification | "What can we export as proof?" |
| Admin | Configuration, source settings, and operational health | "Is the platform configured and healthy?" |

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

1. Open Global Security Action Center.

   Review severity, KEV, EPSS, known-exploited, patch availability, urgency posture, source state, review state, and customer-match counts.

2. Search or filter the catalogue.

   Search by CVE, advisory ID, vendor, product family, model, affected feature, affected version, fixed version, source name, source feed, urgency posture, or customer match.

3. Select the advisory or CVE.

   Read the source posture, evidence state, affected feature, affected/fixed versions, customer matches, and final approval state.

4. Open Customer Estate.

   Add or confirm affected customer devices, services, firmware/software versions, exposure state, and feature configuration.

5. Run exposure matching.

   Treat matches as investigation candidates. Review why the match was made and which evidence is missing.

6. Run Patch Compare if a current and proposed version are known.

   Use this to compare current version against affected-version evidence and proposed version against fixed-version evidence.

7. Ask PatchForge a focused question.

   Ask about a selected CVE/advisory, vendor, model, version, feature state, patch version, or evidence gap. Use the answer to understand governed posture, not to bypass review.

8. Attach or update evidence.

   Add inventory evidence, version evidence, feature evidence, exposure evidence, vendor-source review, and named human review events.

9. Generate a signed pack.

   Use Reports & Packs only after the selected assessment has enough context to produce a meaningful output. It is valid for a pack to show blocked decisions and missing evidence.

10. Export the right report.

   Choose the report type for the audience: customer, board, CAB, technical appendix, or signed decision pack ZIP.

11. Verify and file the output.

   Verify the signed pack, retain the pack metadata, and store the report with the CAB, customer assurance, risk, or governance record.

## Global Security Action Center

Use this page as the first stop for global advisory triage.

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

### Correct Interpretation

KEV and EPSS are prioritisation signals. They do not prove that a customer asset is exposed. A customer match means PatchForge found a possible relationship between advisory intelligence and estate data. It does not prove affected status until the evidence is reviewed.

## Customer Estate

Use Customer Estate to add, query, and match customer assets and services.

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

## Reports & Packs

Use Reports & Packs when the team needs a signed, replayable, audience-specific record.

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

- The report is generated from the current selected pack.
- The source records are current enough for the decision.
- The relevant customer asset or service context is present.
- Evidence gaps are specific and understandable.
- Final approval state is visible.
- Report metadata is visible.
- The signing provider and verification state are visible.
- The report does not claim PatchForge deployed a patch, approved CAB, accepted risk, or closed evidence gates.
- The report does not say an asset is safe or not vulnerable unless reviewed evidence and human approval support the exact claim.
- The intended audience can understand the current posture without knowing internal source-feed or evidence-model terminology.

## Common Operational Mistakes

Avoid these patterns:

- Treating a CVE/vendor match as confirmed customer exposure.
- Treating a disabled feature as accepted evidence without a reviewed configuration record.
- Treating a vendor patch announcement as proof that a proposed customer patch version remediates the issue.
- Asking Ask PatchForge a vague question without selecting or naming the advisory.
- Exporting a report before checking stale/current warnings.
- Sharing a customer report that hides evidence gaps.
- Claiming final approval when `final_approval_issued=false`.
- Using PatchForge to bypass CAB, risk, service-owner, or customer assurance processes.

## Example Operational Scenario

1. A new high-severity advisory appears for a firewall product family.
2. The security lead opens Global Security Action Center and filters by vendor, severity, KEV, EPSS, patch availability, and customer match.
3. The service owner opens Customer Estate and confirms affected customer devices, versions, enabled features, and management exposure.
4. PatchForge finds possible customer matches.
5. The team reviews source records and attaches customer evidence.
6. Patch Compare is run for the current version and proposed fixed version.
7. Ask PatchForge is used to explain current governed posture and missing evidence.
8. Reports & Packs generates a signed pack and the correct audience report.
9. CAB or the accountable owner reviews the evidence and records the human decision.
10. The signed pack and report are archived with the change, risk, or customer assurance record.

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

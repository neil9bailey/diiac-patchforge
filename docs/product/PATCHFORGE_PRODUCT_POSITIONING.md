# PatchForge Product Positioning

## Product Name

DIIaC™ PatchForge

## Product Line

PatchForge is a dedicated DIIaC™ add-on product for vulnerability, patch, protection, and remediation governance.

## Public Description

DIIaC™ PatchForge helps security and service teams decide what to do about vulnerabilities affecting their estate, explain the evidence behind each decision, and prepare signed records for CAB, customer and audit review.

It connects vulnerability intelligence, asset and service context, compensating controls, accountable human review and report preparation. Verified exports remain subject to the exact release and artifact evidence described in the [Claims Matrix](PATCHFORGE_CLAIMS_MATRIX.md).

## Product Thesis

PatchForge focuses on the decision after a vulnerability signal: patch, mitigate, defer, request temporary risk acceptance, block go-live, or record verified closure after the required evidence and human approval.

Its proposed differentiation is the combination of explicit evidence gaps, asset and service applicability, deterministic decision controls, role-authorised human review, and signed audience-specific records. This is a product design thesis to validate with customers, not proof of a unique market category or superior outcomes.

Adjacent products already cover relevant parts of this workflow: ServiceNow documents vulnerability exceptions and compensating controls; Tenable describes exploitability and business-impact prioritisation; Qualys describes risk prioritisation with patching. PatchForge must demonstrate its evidence-to-decision experience and fit with a customer's existing tools instead of claiming those capabilities are absent elsewhere. [ServiceNow documentation](https://www.servicenow.com/docs/r/security-management/vulnerability-response/configure-exception-management-settings.html), [Tenable prioritisation](https://www.tenable.com/products/vulnerability-management/use-cases/prioritization), [Qualys VMDR Patch](https://www.qualys.com/apps/vmdr-patch).

## Primary Users

- security leads
- service owners
- CAB participants
- MSP service managers
- enterprise IT governance teams
- OT governance and assurance stakeholders
- customer assurance and audit teams

## Strategic Value

The initial proposed buyer is an enterprise security or service-governance lead with recurring CAB decisions and fragmented evidence. The daily users are the analyst, service owner and authorised reviewer. An MSP governance service is a second packaging route once customer isolation, repeatable onboarding and customer reporting are accepted.

For enterprise IT, the outcomes to measure are decision preparation time, review cycle time, evidence completeness and the time needed to assemble a usable report. These are pilot hypotheses; no time saving, risk reduction or ROI percentage is established by the repository.

For OT and critical infrastructure, the intended value is documenting safety impact, vendor support, maintenance windows, rollback limits and operational continuity alongside cyber urgency. A customer-specific OT pilot and specialist review are required before making sector readiness claims.

See the [Enterprise Offer and Pilot Framework](PATCHFORGE_ENTERPRISE_OFFER.md) for proposed packages, measurable acceptance and procurement work.

## Dedicated Product Rationale

PatchForge should be a sibling/add-on product rather than a feature tab inside the wider DIIaC™ IT Services build because the workflow is specialised:

```text
vulnerability -> asset/service impact -> exploitability -> patch feasibility -> decision -> evidence -> approval -> outcome feedback
```

The product should have:

- dedicated URL: `patchforge.diiac.io`
- dedicated repository: `neil9bailey/diiac-patchforge`
- dedicated Azure resources
- dedicated UI
- dedicated admin centre
- dedicated policy packs
- dedicated evidence models
- dedicated SRA advisory workflow
- optional integration with DIIaC™ IT Enterprise / IT Services

## Shared DIIaC Governance Spine

PatchForge belongs beside DIIaC IT Enterprise / IT Services as the specialised vulnerability and patch-decision product. The portfolio story is shared governance principles: traceable evidence, accountable human decisions and verifiable artifacts.

Shared principles do not establish a shared deployed runtime, cross-product sign-in, common tenant provisioning, an integration connector, or portable trust between products. Current documentation describes the IT Services relationship as harness-ready; an implemented and customer-accepted handoff is not evidenced. The proposed [portfolio handoff](PATCHFORGE_ENTERPRISE_OFFER.md#proposed-portfolio-handoff) requires an explicit contract and end-to-end validation before it is sold as an integration.

That shared spine does not change the product boundary: PatchForge governs decisions and evidence. It does not scan, exploit, deploy patches, or autonomously accept risk.

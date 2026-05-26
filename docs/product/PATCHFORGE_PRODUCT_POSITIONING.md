# PatchForge Product Positioning

## Product Name

DIIaC™ PatchForge

## Product Line

PatchForge is a dedicated DIIaC™ add-on product for vulnerability, patch, protection, and remediation governance.

## Public Description

DIIaC™ PatchForge turns vulnerability intelligence, patch signals, exploitability context, asset and service exposure, compensating controls, and human approval into governed, signed patch-decision artefacts.

## Product Thesis

AI and automated tooling are accelerating vulnerability discovery. PatchForge governs what happens next: patch, mitigate, defer, risk accept, block go-live, or close verified.

Most tools help discover vulnerabilities, ticket them, or deploy remediations. PatchForge owns the missing layer: governed, evidence-bound, human-reviewable patch and protection decisions for IT and OT assets.

## Primary Users

- security leads
- service owners
- CAB participants
- MSP service managers
- enterprise IT governance teams
- OT governance and assurance stakeholders
- customer assurance and audit teams

## Strategic Value

For MSPs, PatchForge supports managed patch-governance services, customer-facing assurance packs, audit-ready evidence, and controlled emergency change governance.

For enterprise IT, PatchForge helps reduce patch-decision delay, preserve decision rationale, prioritise based on service impact, and keep security urgency connected to operational reality.

For OT and critical infrastructure, PatchForge provides a governance bridge between cyber urgency, safety impact, vendor support, maintenance windows, rollback limits, and operational continuity.

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

PatchForge may share DIIaC governance patterns, including signed packs, evidence states, replay certificates, trust registry concepts, Entra RBAC, policy packs, and Decision Control Center patterns.

That shared spine does not change the product boundary: PatchForge governs decisions and evidence. It does not scan, exploit, deploy patches, or autonomously accept risk.

# VendorLens Product Boundary

VendorLens is part of DIIaC PatchForge. It exists to govern network vendor vulnerability and patch decisions, not to act as a scanner, exploitation system, deployment tool, or autonomous CAB.

## Permitted Use

- Review network/security vendor advisory sources.
- Ingest source-bound CVE and advisory metadata.
- Record customer network product, model, firmware, feature, exposure, and configuration evidence.
- Assess whether an advisory appears applicable, conditional, unknown, or not applicable pending review.
- Recommend governed postures such as emergency patch required, patch required, mitigate temporarily, urgent scope confirmation required, monitor, or no action pending review.
- Generate signed pack artefacts and professional DOCX/PDF reports for review.

## Prohibited Use

VendorLens must not:

- scan customer estates
- generate exploit code
- provide procedural exploit steps
- deploy patches
- change firewalls, routers, load balancers, gateways, endpoints, or cloud controls
- mutate production systems
- approve CAB decisions
- accept risk autonomously
- claim customer exposure is confirmed without reviewed customer evidence
- claim a CVE is not applicable without reviewed product, version, feature, estate, and approval evidence

## Evidence Rule

Vendor, CVE, NVD, Cisco PSIRT, generic RSS/JSON, SRA/AIP, KEV, EPSS, and customer inventory records remain source-bound until reviewed.

Source-bound records may support triage and report preparation. They cannot close hard gates or issue final decisions by themselves.

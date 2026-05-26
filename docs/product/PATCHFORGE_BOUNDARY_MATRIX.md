# PatchForge Boundary Matrix

## Purpose

This matrix defines what PatchForge may do, what it must not do, and which controls are required to keep the product inside its intended boundary.

## Capability Boundary

| Area | In scope | Out of scope | Control |
| --- | --- | --- | --- |
| Vulnerability records | Ingest source-bound vulnerability records. | Scan networks or hosts. | Source class and provenance required. |
| Exploitability | Record exploitability signals and reviewed context. | Generate exploit code, exploit steps, or active exploitation. | SRA and reports must block exploit instructions. |
| Patch availability | Track vendor patch availability and evidence. | Download, install, or deploy patches. | No deployment endpoints or orchestration actions. |
| Patch feasibility | Assess change window, rollback, testing, service impact. | Mutate production services. | Decision output only; change execution external. |
| Risk acceptance | Record temporary risk acceptance with owner, expiry, rationale. | Autonomously accept risk. | Human approval required. |
| SRA research | Produce advisory, source-bound research traces. | Close hard gates alone or approve decisions. | Review state defaults to pending. |
| Reports | Export CAB, board, customer, risk, and OT reports. | Claim certification of whole estate safety or compliance. | Claims matrix controls wording. |
| Integrations | Connect to source systems for evidence and context. | Replace source systems. | Integration role documented per connector. |
| Signed packs | Sign decision artefacts and preserve replay state. | Prove vulnerability truth by signature alone. | Signature covers artefact integrity, not source truth. |

## Evidence Boundary

| Source type | Initial state | Can close hard gate alone? | Notes |
| --- | --- | --- | --- |
| Scanner output | Source-bound | No | Requires review or corroboration. |
| Vendor advisory | Referenced or attached | Not by itself for final approval | Strong identity evidence when current and relevant. |
| CVE record | Referenced or attached | No | Supports identity and description. |
| KEV record | Referenced or attached | No | Supports urgency and known-exploited context. |
| EPSS signal | Referenced | No | Supports probability context. |
| Asset inventory | Referenced or attached | No | Requires scope confidence. |
| Service catalogue | Referenced or attached | No | Supports service impact. |
| Test evidence | Attached | Can support readiness | Must be accepted positive evidence. |
| Rollback plan | Attached | Can support readiness | Must be accepted positive evidence. |
| Compensating control | Attached | Can support mitigation | Must be reviewed and time-bound where needed. |
| Risk acceptance | Attached | Can support temporary posture | Requires owner, expiry, rationale, approval. |
| SRA trace | Pending review | No | Advisory only. |
| Human review | Reviewed/approved | Yes, where role-authorised | Must bind reviewer, role, date, and rationale. |

## UI Boundary Requirements

The UI must:

- show SRA as advisory only
- make evidence gaps prominent
- keep human review state visible
- avoid exploit-oriented language
- avoid autonomous patching language
- show signed pack trust without implying source truth

## API Boundary Requirements

The API must not expose endpoints that:

- run scanners
- generate exploit content
- deploy patches
- mutate production systems
- issue final approval without human approval payload
- risk accept without owner, expiry, and rationale


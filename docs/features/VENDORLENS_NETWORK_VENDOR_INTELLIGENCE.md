# VendorLens Network Vendor Intelligence

## Purpose

VendorLens is a dedicated PatchForge capability for network and security vendor advisory intelligence, customer estate matching, and configuration-aware patch governance.

It helps a user answer questions such as:

- We use this firewall model and patch level; are we exposed?
- We do not use this vulnerable feature; do we urgently need to patch?
- What evidence proves this CVE is not applicable?
- Should we emergency patch, mitigate, or confirm scope first?

## Operating Model

VendorLens combines:

- network/security vendor catalogue metadata
- source-bound vendor advisory and CVE records
- NVD CVE 2.0 metadata enrichment
- Cisco PSIRT openVuln support when credentials or configured safe source URLs exist
- generic vendor RSS/JSON source ingestion from Admin-configured URLs
- CISA KEV and FIRST EPSS context through the wider PatchForge intelligence layer
- customer product/model/firmware/configuration evidence
- deterministic configuration applicability assessment
- SRA/AIP guided question answering
- signed pack and DOCX/PDF report output

## Decision Boundary

VendorLens is source-bound advisory intelligence. It does not verify customer configuration unless configuration evidence is attached and reviewed.

VendorLens does not:

- scan environments
- generate exploit code
- provide procedural exploit steps
- deploy patches
- mutate production systems
- approve patching
- approve risk acceptance
- approve not-applicable status
- close CAB or remediation decisions autonomously

Human review is required for final remediation, mitigation, risk acceptance, closure, and not-applicable decisions.

## Signed Pack Artefacts

When VendorLens context is available, PatchForge can include these artefacts in signed packs:

- `network_vendor_profile_snapshot.json`
- `customer_network_asset_snapshot.json`
- `vendor_security_advisory_snapshot.json`
- `config_applicability_assessment.json`
- `sra_config_chat_session.json`
- `vendorlens_decision_context.json`

These artefacts preserve the source-pack state. Current-state updates, reviewer decisions, approvals, and later evidence remain separate governed events.

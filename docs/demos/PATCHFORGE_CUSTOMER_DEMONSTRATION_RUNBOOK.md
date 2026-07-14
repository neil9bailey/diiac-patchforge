# PatchForge Customer Demonstration Runbook

## Purpose

This runbook defines production customer demonstration practice for DIIaC PatchForge.

## Data Rule

PatchForge demonstrations use real operator-supplied tenant records only.

Do not seed, invent, or pre-load synthetic vulnerabilities, asset records, service records, risk acceptances, or signed packs.

## Preparation

1. Confirm the customer or DIIaC operator has authority to use the records being imported.
2. Ingest real vulnerability, advisory, asset, and service records through the protected UI or API.
3. Keep all ingested records source-bound and pending review until a human reviewer accepts them as positive evidence.
4. Generate signed packs only from records present in the live tenant store.
5. Show any blockers exactly as compiled by the deterministic runtime.

## Demonstration Boundary

PatchForge governs vulnerability, patch, mitigation, deferral, go-live block, and risk-acceptance decisions.

PatchForge does not scan, exploit, deploy patches, mutate production systems, replace ITSM, replace CMDB, replace SIEM/SOAR, or autonomously approve risk.

## Live Flow

1. Sign in through Microsoft Entra ID.
2. Open Patch & CVE Catalogue and confirm the live tenant, environment, account role, and source status.
3. Ingest real source-bound records, or review records already ingested through the protected API.
4. Review the priority queue, source/evidence state, customer match counts, selected-record context, blockers, and next action.
5. Open Vendor Catalogue, bind the exact customer asset and advisory, and explain applicability without showing exploit instructions or procedural exploit steps. Run Patch Compare only when current/proposed versions and source evidence are known.
6. Open Customer Estate to review customer asset, service, collector, version, feature, exposure, ownership, and evidence context.
7. Ask PatchForge a focused advisory question and confirm that final approval remains a human decision.
8. Open Review & Approve for the selected finding. Show evidence IDs/hashes, expiry, review rationale, and role separation; do not accept customer evidence merely to make the demonstration appear complete.
9. Open Reports, explicitly select the intended verified pack, and confirm pack/finding/time, immutable source posture, readiness blockers, report metadata, verification, and final approval state before download.
10. Close with the product boundary and the accountability model.

If temporary production UAT records are explicitly authorized, prefix them, capture the before state, and follow the Admin purge preview/typed-confirmation/absence-proof workflow after the report evidence is retained. Do not delete real customer records or audit evidence.

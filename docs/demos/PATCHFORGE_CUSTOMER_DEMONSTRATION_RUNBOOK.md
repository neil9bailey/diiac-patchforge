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
2. Open Security Action Center and confirm the live tenant context.
3. Ingest real source-bound records, or review records already ingested through the protected API.
4. Review the grouped CVE/advisory catalogue, source state, evidence state, and customer match counts.
5. Open Vendors & Exploits Register to explain vendor-level posture without showing exploit instructions or procedural exploit steps.
6. Open Customer Operational Assets to review customer context, then use Patch / Hotfix Compare when current and proposed versions are known.
7. Ask PatchForge a focused advisory question and confirm that final approval remains a human decision.
8. Open Reports and verify the signed pack state, immutable source posture, readiness blockers, and final approval state.
9. Close with the product boundary and the accountability model.

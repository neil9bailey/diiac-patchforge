# PatchForge Readiness Summary

Date: 2026-07-14

## Current Decision

PatchForge now runs the approved `PF-AZ-ENTERPRISE-AUTOMATION-20260714D` six-image set in Azure, but overall acceptance is **partial**.

- Area 14 passed for the guarded image-only rollout: approval run `29345354677`, attestation verification, six ACR digests, signed provenance, six healthy/latest-ready revisions, public smoke, and post-release signing-access revocation are evidenced.
- Area 1 is partial: signed-in `PatchForge.Admin` access and 13/13 Admin health checks passed, but other role journeys were not evidenced.
- Area 2 is fixed/tested locally but blocked in production: `KeyType.ec` / `KeyCurveName.p_256` are now strictly normalized to `EC` / `P-256` before full ES256 verification. Invalid aliases/curves, malformed coordinates, wrong keys, and tampered/short signatures fail. The fix and verified ZIP are not live-accepted.
- Area 3 is local-only: cleanup uses a server-issued tenant-scoped expiring preview token bound to a SHA-256 digest of exact displayed record IDs; direct/cross-tenant/drift/reuse attempts fail closed and audit is retained. Production proof is open.
- Area 4 remains open: What-If has 0 destructive/image/environment-removal changes; scheduler-only `min0→1` is intentional for its in-process timer. Thirteen unsupported resources prevent a fully determinate apply.
- Trusted Windows collector signing, clean customer-machine UAT, representative customer acceptance, and legal/licensing review remain human/external gates.

The authoritative per-area state and stop conditions are in the [14-Area Improvement Closure Matrix](PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md).

## Candidate Capabilities

The local candidate adds or strengthens:

- an explicit existing/create/disabled PostgreSQL infrastructure model;
- Container Apps startup, liveness, and readiness probes plus bounded scaling;
- finding-scoped, server-owned evidence with immutable review events, expiry, rejection, and reopen behavior;
- outbound intelligence allowlisting and SSRF controls;
- server-owned optional-AI evidence context that ignores caller review claims;
- append-only exact-byte JSON/ZIP/DOCX/PDF artifact records and digest verification;
- Windows collector package verification, least-privilege setup, heartbeat, upgrade, revoke, and uninstall controls;
- idempotent scheduler/worker leases, checkpoints, retries, dead-letter/quarantine, reconciliation, and operator-visible SLO alerts;
- dependency, code, secret, container, IaC, provenance, SBOM, and production-approval workflow definitions;
- lazy-loaded frontend areas with an enforced bundle budget;
- keyboard, focus, mobile, responsive-table, live-region, explicit pack-selection, and partial-load recovery behavior;
- updated operator, automation, release-readiness, and closure guidance.

Separate closeout-branch validation passed locally: Python 53/53, backend 94/94, frontend 28/28, Playwright/axe 2/2, collector 8/8, frontend build/bundle PASS (`270.20 kB` entry; `634.39/650 kB` total), and IaC PASS. These results do not replace the deployed `f51802d` candidate totals.

These implementation statements span two states: the live `f51802d` image-only rollout and subsequent closeout-branch changes that are locally implemented/tested but not live. They do not imply that the repaired IaC or every user workflow is production-accepted.

## Current Production Boundary

The live image set is attributable to source `f51802d3544260259c252e6be88d6e7bae596868` and tag `pfaz-enterprise-20260714d-f51802d`. The root release records contain the safe digest, revision, approval, provenance, and smoke evidence. Navigation, verified ZIP, exact-ID cleanup, and repaired IaC in the current closeout branch are not included in that live state.

The full desired-state contract is not live:

- all six apps retain the deliberate live scale posture `minReplicas=0`, `maxReplicas=1`;
- live container probe arrays are absent;
- the images use the July 14 tag, while release-metadata environment variables still report the July 11 tag, commit, baseline, and report context;
- repaired closeout IaC has 0 image and 0 environment-removal changes; scheduler-only `min0→1` is intentional;
- its 43-resource What-If reports 7 modify, 20 no-change, 3 ignore, 13 unsupported, and 0 destructive changes, with metadata convergence on six apps and 12 probe additions across six apps.

Treat the current release as an image-only deployment. The 13 unsupported results leave the repaired plan not fully determinate; no full apply is authorized until they are resolved or explicitly approved and an exact closeout-source/configuration approval is issued.

## Remaining Closure Sequence

1. Attribute and deploy the strict EC/P-256 normalization fix without weakening verification or bypassing the explicit selected-pack requirement.
2. Repeat the live DOCX flow and complete exact-byte ZIP/DOCX/PDF verification plus visual report inspection.
3. Attribute the closeout branch to a clean release source and obtain exact approval before deployment.
4. Deploy the navigation, verified-ZIP, and exact-ID cleanup changes, then complete signed-in production proof and role-by-role UAT beyond Admin health.
5. Preview and remove only the intended exact-ID UAT records, then prove absence while audit evidence remains.
6. Resolve or individually approve the 13 unsupported What-If resources and review the seven intended modifications.
7. Under a separate exact approval, apply the reviewed release-metadata and probe changes, then prove six-app metadata/readiness convergence.
8. Obtain trusted collector signing, clean customer-machine proof, representative customer acceptance, and accountable legal/licensing review.
9. Refresh the closure records again only after those gates pass.

## Hard Gates Still Open

| Gate | Status | Required proof |
| --- | --- | --- |
| Deployed `f51802d` candidate validation | Passed, unchanged | Python 39/39; backend 89/89; frontend 24/24; Playwright/axe 2/2; collector 8/8 plus Windows lifecycle; Bicep/YAML/PowerShell; dependency audits; three image builds and zero high/critical findings |
| Closeout-branch validation | Passed locally; not live | Python 53/53; backend 94/94; frontend 28/28; Playwright/axe 2/2; collector 8/8; frontend build/bundle PASS at 270.20 kB entry and 634.39/650 kB total; IaC PASS |
| Remote approval and provenance | Passed for image rollout | Approval run `29345354677`; attestation and authorization checksum verified; six-image ES256 manifest verified |
| Azure image rollout | Passed | Six exact-tag digests and six healthy/latest-ready revisions at 100% latest-revision traffic; public smoke passed |
| Repaired IaC What-If | Passed, not fully determinate | 43 resources: 0 destructive, 7 modify, 20 no-change, 3 ignore, 13 unsupported; 0 image changes; 0 environment removals; six-app metadata and 12 probes; scheduler-only intentional `min0→1` scale delta |
| Full IaC/configuration apply | Not performed; separate exact approval required | Resolve/approve unsupported results, bind approval to exact closeout source and delta, apply, then prove metadata/probe readiness |
| Signed-in UAT | Partial | Admin sign-in and 13/13 health checks passed; remaining roles and full operator journeys still require evidence |
| Fresh report proof | Local fix passed; production open | Deploy strict EC/P-256 normalization, then verify selected-pack ZIP/DOCX/PDF exact bytes and visually inspect reports |
| Ingestion and verified-ZIP UI | Implemented/tested locally; live proof open | Deploy the closeout source, then capture repeatable signed-in journeys and durable output evidence |
| Exact-ID UAT cleanup | Implemented/tested locally; live proof open | Deploy, preview one exact identifier, use typed confirmation, prove record-ID removal and absence, and retain audit history |
| Customer collector acceptance | Pending external/human gate | Trusted signature, clean Windows install, least-privilege auth, offline/retry recovery, revoke/uninstall, and representative customer acceptance |

## Product Boundary

PatchForge remains a governance and assurance product. It does not scan environments, generate exploit content, deploy patches, mutate customer production systems, autonomously approve CAB decisions, autonomously accept risk, or autonomously close evidence gates. Automation prepares and verifies evidence; accountable people decide.

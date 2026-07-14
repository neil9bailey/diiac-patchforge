# PatchForge Documentation

PatchForge documentation is organised around the product boundary, architecture, deployment, operations, validation, and release evidence. Start with the route for your role below; historical evidence under `release/evidence/` does not by itself describe the current candidate or current production state.

## Start here

| Audience | Primary document | Use it for |
| --- | --- | --- |
| End user, service owner, security lead, CAB, or assurance reviewer | [Operational User Guide](operations/PATCHFORGE_OPERATIONAL_USER_GUIDE.md) | The six-area UI, evidence review, explicit pack selection, reports, role boundaries, and support information |
| Collector or platform operator | [Collector and Automation Runbook](operations/PATCHFORGE_COLLECTOR_AND_AUTOMATION_RUNBOOK.md) | Signed Windows package lifecycle, authentication, heartbeat, scheduler/worker recovery, and safe intervention |
| Release owner or approver | [14-Area Improvement Closure Matrix](validation/PATCHFORGE_14_AREA_IMPROVEMENT_CLOSURE_2026-07-14.md) | Implementation evidence, operator actions, validation, live gates, human gates, and stop conditions |
| Reviewer or auditor | [Automation and UI Readiness Review](validation/PATCHFORGE_AUTOMATION_AND_UI_READINESS_REVIEW_2026-07-11.md) | Original findings, risk boundaries, and prioritized delivery backlog |
| Delivery team | [Current Readiness Summary](validation/PATCHFORGE_READINESS_SUMMARY.md) | Candidate-versus-live status and the remaining production closure sequence |

## Canonical rebuild blueprint

- [PatchForge Intelligence Rebuild Blueprint](product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md)

The blueprint is the governing reference for the catalogue-first rebuild. Implementation work after PF0 must remain aligned to it and must not introduce exploit generation, patch deployment, production mutation, autonomous approval, or autonomous risk acceptance.

## Key documentation areas

- [Product](product/)
- [Architecture](architecture/)
- [Deployment](deployment/)
- [Operations](operations/)
- [Validation](validation/)
- [Release evidence](release/evidence/)

## Status discipline

- `Implemented locally` means source exists in the current candidate; it does not mean Azure is updated.
- `Validated locally` means a named local check passed; it does not replace remote CI, signed-in UAT, or customer acceptance.
- `Live pending` means no production execution or readback is claimed for the candidate.
- `Human gate` means an accountable user, approver, certificate owner, or customer representative must act.
- The root `CURRENT_RELEASE.md`, `VALIDATION_OUTPUTS.md`, `QUALITY_GATES_REPORT.json`, and `RELEASE_BASELINE_MANIFEST.json` remain the release records and must not be advanced before evidence exists.

## Operating loops

- [Azure Container Update Loop](deployment/PATCHFORGE_AZURE_CONTAINER_UPDATE_LOOP.md)
- [Deployment Readiness](deployment/PATCHFORGE_DEPLOYMENT_READINESS.md)
- [Collector and Automation Runbook](operations/PATCHFORGE_COLLECTOR_AND_AUTOMATION_RUNBOOK.md)

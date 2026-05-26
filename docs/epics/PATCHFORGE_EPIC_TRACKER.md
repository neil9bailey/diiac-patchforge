# PatchForge Epic Tracker

## Delivery Rules

- Work only in `F:\code\diiac\patchforge`.
- Keep local and remote repositories synced after each completed epic.
- Do not deploy Azure resources without explicit instruction.
- Do not create exploit, scanner, patch-deployment, production-mutation, autonomous CAB, or autonomous risk-acceptance capability.
- Notify the user when Azure access or DNS changes are needed.

## Status

| Epic | Name | Status | Commit |
| --- | --- | --- | --- |
| PF-E0 | Repository bootstrap | Complete | `04bf579` |
| PF-E1 | Product identity and architecture | Complete | |
| PF-E2 | Azure IaC baseline | Complete | |
| PF-E3 | Schemas and evidence models | Complete | |
| PF-E4 | Backend API and storage | Complete | |
| PF-E5 | Runtime governance and signed packs | Complete | |
| PF-E6 | Dedicated frontend shell | Complete | |
| PF-E7 | Full Admin UI | Complete | |
| PF-E8 | SRA MCP advisory layer | Complete | |
| PF-E9 | Decision Workbench and DCC | Complete | |
| PF-E10 | Reports, demos, validation pack | Complete | |
| PF-E11 | Deployment readiness and CI/CD hardening | Complete | |

## Next Epic

Post-PF-E11: run Azure what-if only after tenant, subscription, and region are confirmed.

# PF-AZ9 Operational Health Enablement Evidence

This folder records the PF-AZ9 hotfix that enables the Admin health checks requested after live UI review.

Scope:

- MCP agent intake health changed from disabled to governed.
- Public source feeds health changed from disabled to ready.
- Worker health changed from planned to ready.
- Scheduler health changed from planned to ready with last source-feed refresh evidence.
- Admin configuration now deep-merges and normalises governed defaults so source-feed and agent-intake settings are not accidentally dropped by later partial saves.

Live validation:

- UI: `https://patchforge.diiac.io/` returned HTTP 200.
- API readiness returned PostgreSQL storage with Entra auth required.
- Protected Admin health returned HTTP 401 without a bearer token.
- Signed-in Admin health API returned HTTP 200.
- Browser validation confirmed `n.bailey@diiac.io` with `PatchForge.Admin` and the four requested checks enabled.

Evidence:

- Build/push evidence: `build-push/`
- Azure Container Apps update evidence: `deploy-apply/`
- Live UI/API evidence: `live-ui/`

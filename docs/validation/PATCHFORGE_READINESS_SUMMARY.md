# PatchForge Readiness Summary

## Current Readiness

PatchForge has a local baseline through PF-E10:

- repository and working memory
- product identity and boundary docs
- Azure IaC baseline
- domain schemas and evidence models
- backend API and local JSON storage
- deterministic governance runtime
- signed local decision packs
- frontend shell and admin UI
- SRA advisory layer
- Decision Control Center runtime foundation
- report rendering
- real-data customer demonstration runbook and validation plan

## Not Yet Production-Live

PatchForge is live on Azure Container Apps with custom DNS, production signing trust, PostgreSQL storage, and Entra app roles. Live scanner ingestion remains an integration task; no seeded or synthetic product data is shipped.

## Access Needed Later

Azure access will be needed before resource deployment or what-if against the real subscription.

DNS updates will be needed before `patchforge.diiac.io` and `api.patchforge.diiac.io` can point at production ingress.

## Boundary

PatchForge remains a governance product. It does not scan, exploit, deploy patches, mutate production systems, or approve risk without accountable human review.

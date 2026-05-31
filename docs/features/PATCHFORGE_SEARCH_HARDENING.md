# PatchForge Search Hardening

PF-AZ11 keeps the deterministic JSON/in-memory Global Security Action Center index for local development and adds an optional PostgreSQL-backed path for larger catalogues.

## Modes

- `PATCHFORGE_SEARCH_MODE=local` uses deterministic in-memory indexing from repository storage records.
- `PATCHFORGE_SEARCH_MODE=postgres` asks storage for a tenant-scoped catalogue query and falls back to the local deterministic path when unavailable.

## Indexed Fields

The catalogue indexes CVE/advisory identifiers, title, description, vendor and aliases, product and aliases, model, affected and fixed versions, affected feature and aliases, severity, CVSS, EPSS, KEV, known exploited, patch availability, workaround state, source URL/name/class/feed, retrieved/published/refresh dates, review and evidence state, customer asset/service matches, internet and management exposure, enabled/disabled features, applicability posture, urgency posture, and final approval state.

## PostgreSQL Catalogue Pattern

`securityActionCatalogueSql()` documents the optional materialized view:

- `patchforge_security_action_catalogue`
- tenant and collection index
- GIN full-text index over JSON source records
- scheduled `refresh materialized view concurrently`

Tenant isolation is enforced by querying `patchforge_records` with `tenant_id = $1`.

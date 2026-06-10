# PatchForge Multi-Tenant Onboarding

Date: 2026-06-10

## Current State (honest)

PatchForge production is operated as a **single-default-tenant deployment** (`diiac.io`). The storage layer is tenant-scoped (`tenant_id` on every record, application-layer filtering), and tenant resolution maps the Entra token `tid` claim to a tenant identifier via `PATCHFORGE_TENANT_MAPPINGS`. The `x-tenant-id` header is ignored for normal users in production (admin diagnostic override only).

## Onboarding Tenant #2 Today

1. **Entra**: register the customer's users in the `diiac.io` tenant (guest accounts) or establish their tenant ID; assign PatchForge app roles (`PatchForge.Reader` … `PatchForge.Admin`) to their users on the existing app registrations.
2. **Tenant mapping**: add the customer's Entra `tid` to the `PATCHFORGE_TENANT_MAPPINGS` env var on the bridge Container App, e.g. `{"<diiac-tid>":"diiac.io","<customer-tid>":"customer.example"}`.
3. **Admin config**: create the tenant's admin config (PUT `/api/patchforge/admin/config` as that tenant) including `approval_policy` if it differs from the default (SecurityLead + CABApprover, distinct approvers).
4. **Validate isolation**: ingest a test record as each tenant and confirm cross-tenant list isolation before go-live; remove validation records afterwards.

## Known Gaps for True Multi-Tenancy

- **App roles are global**: a user holding `PatchForge.Admin` holds it for any tenant their token maps to. Per-tenant role scoping (separate app registrations per tenant, or group-based scoping) is required before co-hosting unrelated customers.
- **No database-level isolation**: tenant separation is application-layer `tenant_id` filtering only. PostgreSQL row-level security policies keyed on a per-connection tenant setting are the planned hardening.
- **No per-tenant domain routing**: all tenants share `patchforge.diiac.io`.
- **Shared rate limits and quotas**: per-tenant request rate limiting exists (PF-AZ12); storage quotas do not.

Until the first two gaps are closed, prefer **one deployment per customer** (separate resource group + database) over co-tenancy for unrelated organizations.

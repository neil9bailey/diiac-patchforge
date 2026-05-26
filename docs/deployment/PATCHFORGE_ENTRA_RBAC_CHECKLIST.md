# PatchForge Entra RBAC Checklist

## Entra App Registration

Dedicated Entra app registrations now exist for PatchForge.

Known DIIaC tenant:

- domain: `diiac.io`
- tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`

PatchForge apps:

- API display name: `DIIaC PatchForge API`
- API app ID: `ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- API service principal ID: `549b5962-5815-4b8b-a26e-96a2b2526f1f`
- API identifier URI: `api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736`
- UI display name: `DIIaC PatchForge UI`
- UI app ID: `c4dfca53-14a5-4688-817d-6c6c7dd47407`
- UI service principal ID: `9c3b6748-782c-4919-a4b7-2994a5e1e99d`

IT Services records app ID `5d144b76-b9d4-4db7-af10-00c7c98037b9`. PatchForge uses dedicated registrations rather than reusing the IT Services registration.

Configured app roles:

- `PatchForge.Reader`
- `PatchForge.TriageAnalyst`
- `PatchForge.SecurityLead`
- `PatchForge.ServiceOwner`
- `PatchForge.CABApprover`
- `PatchForge.RiskOwner`
- `PatchForge.Admin`
- `PatchForge.Auditor`

Initial group assignments:

- `DIIAC-ITServices-Admins` -> `PatchForge.Admin`
- `DIIAC-ITServices-Standard` -> `PatchForge.Reader`

The requested users `n.bailey@diiac.io` and `nbailey@diiac.io` were checked against all DIIaC admin groups discovered in the tenant and were already members of:

- `DIIAC-ITServices-Admins`
- `DIIAC-Pharma-Admins`

Evidence:

- `docs/release/evidence/2026-05-26-patchforge-gates/entra-apps.json`
- `docs/release/evidence/2026-05-26-patchforge-gates/admin-group-membership.json`

## Token Expectations

PatchForge expects app roles to appear as role claims in access tokens. The Bridge/API should enforce role-aware authorization before production launch.

## Managed Identity Assignments

Managed identities:

- `id-patchforge-ui-prod`
- `id-patchforge-bridge-prod`
- `id-patchforge-runtime-prod`
- `id-patchforge-sra-prod`
- `id-patchforge-worker-prod`

Least privilege:

- UI: no direct Key Vault or database access
- Bridge: database read/write, limited storage, Key Vault secret read where required
- Runtime: signing key access, pack storage, database read/write
- SRA: SRA config and source storage, no signing key unless separately justified
- Workers: queue, storage, and database according to job scope

## Boundary

No Entra role should grant autonomous risk acceptance or autonomous CAB approval.

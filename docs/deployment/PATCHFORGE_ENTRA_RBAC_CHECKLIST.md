# PatchForge Entra RBAC Checklist

## Entra App Registration

Create or confirm an Entra app registration for PatchForge.

Known DIIaC tenant:

- domain: `diiac.io`
- tenant ID: `67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da`

IT Services currently records app ID `5d144b76-b9d4-4db7-af10-00c7c98037b9` for both API and UI configuration. PatchForge should use dedicated app registrations and app roles unless the user explicitly approves reuse.

Recommended app roles:

- `PatchForge.Reader`
- `PatchForge.TriageAnalyst`
- `PatchForge.SecurityLead`
- `PatchForge.ServiceOwner`
- `PatchForge.CABApprover`
- `PatchForge.RiskOwner`
- `PatchForge.Admin`
- `PatchForge.Auditor`

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

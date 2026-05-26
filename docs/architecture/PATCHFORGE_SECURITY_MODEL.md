# PatchForge Security Model

## Security Principles

PatchForge follows these security principles:

- tenant isolation by default
- least privilege access
- managed identity over static credentials
- source-bound evidence
- immutable signed source packs
- event-ledger current state
- human approval for final decisions
- no exploit generation
- no patch deployment
- no production mutation
- auditability and replayability

## Identity and Access

Production identity should use Microsoft Entra ID.

Application roles should include:

- `PatchForge.Reader`
- `PatchForge.TriageAnalyst`
- `PatchForge.SecurityLead`
- `PatchForge.ServiceOwner`
- `PatchForge.CABApprover`
- `PatchForge.RiskOwner`
- `PatchForge.Admin`
- `PatchForge.Auditor`

App roles should be included in tokens as role claims and enforced by the Bridge/API and Admin surfaces.

## Tenant Isolation

Every tenant-owned record must include tenant scope. APIs and storage abstractions must require tenant context for:

- vulnerabilities
- sources
- affected assets
- affected services
- decisions
- risk acceptances
- SRA traces
- evidence bindings
- decision packs
- reports
- admin configuration

## Evidence Trust States

Evidence states:

- referenced
- attached
- resolved
- reviewed
- accepted_positive_evidence
- rejected
- superseded

Rejected evidence cannot close blockers or count as positive evidence.

Scanner output and SRA output cannot close hard gates alone.

## SRA Security Boundary

The SRA service must:

- mark output as `advisory_only=true`
- store input and output hashes
- record source references
- default review state to `pending`
- avoid exploit instructions
- avoid deployment actions
- avoid final approvals
- avoid risk acceptance

## Decision Approval Model

Final approval starts false by default.

Risk acceptance requires:

- accountable owner
- expiry date
- rationale
- compensating controls where applicable
- human approval record

Emergency patch decisions require human approval, rollback evidence, service-impact review, and post-patch validation evidence before closure.

## Signing and Trust

Signed packs protect artefact integrity and replayability. A valid signature does not prove that all input sources were true; it proves the signed pack has not changed since signing.

Production signing should use Azure Key Vault managed keys or an approved signing trust path. Development signing may use dev/test keys only when clearly marked non-production.

## Audit Events

Audit logs should capture:

- vulnerability ingest
- source review
- evidence state changes
- decision compilation
- approval events
- risk acceptance creation/update/expiry
- pack generation
- pack verification
- admin configuration changes
- integration secret changes without exposing values
- SRA calls and review state changes

## Admin Safety

The Admin UI must:

- mask secrets after save
- require confirmation for dangerous configuration changes
- avoid live Azure mutations in early phases
- show read-only health checks
- make signing trust and evidence policy state visible


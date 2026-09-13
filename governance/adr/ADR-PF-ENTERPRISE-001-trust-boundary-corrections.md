# ADR-PF-ENTERPRISE-001: Enterprise trust boundary corrections

Status: Approved

Date: 2026-09-13

Epic: EPIC-PF-ENTERPRISE-READINESS-20260913

Architecture reviewer: Codex acting as Enterprise Architect under the workspace operating model. This records a design decision, not human production acceptance.

## Context

The user requested review and improvements to sell PatchForge as an enterprise DIIaC portfolio product. Review of `origin/main` at `a102f69` found an auxiliary action-pack endpoint issuing a public hash labelled as a verified signature, caller-controlled initial workflow states/IDs, and raw string booleans at priority and comparison boundaries. These contradict the existing product boundary and the intelligence blueprint, which requires governance-core signing and accountable human decisions.

## Decision

- Retire issuance through the auxiliary `POST /api/patchforge/action-packs` path with an explicit unavailable response and guidance to the existing runtime-backed decision-pack generation endpoint. No new signing implementation is introduced.
- Inspect historical auxiliary packs without claiming signature verification: digest integrity and cryptographic authenticity are separate results. A test digest must never produce `verified: true` or `signature_ok: true`, including nested stored metadata in the response.
- Generate workflow IDs on the server. Creation and transitions support only the evidenced review states `triage` and `ciso_review_required`. Reject unknown or final-decision states until a separate implementation binds them to server-verified evidence and accountable approval. Preserve tenant scoping, protected transition roles and audit attribution. This intentionally closes the former arbitrary-status API behavior; it is not a completed approvals engine.
- Apply the existing semantic boolean parser to priority/comparison inputs. False-like strings must not create exploitation, exposure, mitigation or deferral signals; affirmative aliases must remain conservative.
- A scheduler cycle may publish a completion checkpoint only when every required work item completed. Lease contention, lost leases, retries and dead letters remain visible as incomplete work and must not cause the same cycle to be skipped as successful.
- Refine the existing Guide and report/collector trust labels using existing API fields and components. Report QA requires an exact selected-pack identity match. A heartbeat is operational evidence, not installer authenticity.
- Bind asynchronous UI results to their originating tenant context. On tenant change clear tenant-owned display state immediately; discard stale loader, operation, error and follow-up results, including after a tenant is selected again. This protects displayed context but does not cancel server actions already sent or establish per-customer authorization.

## Alternatives

Building another signing system or a complete approval state machine would duplicate the runtime or require new evidence/approval contracts. Those are outside this bounded correction. Continuing to describe test digests and arbitrary states as trusted is rejected.

## Compatibility and validation

The auxiliary action-pack POST becomes unavailable. Historical records remain inspectable but unverified. Clients that sent custom initial IDs or final workflow states must adapt. Existing production decision-pack signing, report export verification, authentication, tenant mapping and deployment topology stay in place.

Required verification: regression tests for recomputable/forged test digests, direct-final-state creation, ID overwrite attempts, role and tenant isolation, both valid review transitions and rejected terminal transitions, priority boolean aliases, selected-pack QA isolation, collector authenticity wording and delayed responses across tenant changes. Run complete backend/frontend suites, frontend build and browser accessibility checks. Production report proof and signed-in customer acceptance remain separately evidenced; local tests do not constitute either.

## Outcome

Approved to implement the corrections within the current architecture. No new service, data migration, external connector, compliance claim or production deployment is approved by this ADR.

# PF-AZ12 Improvement Contract

Date: 2026-06-10

This contract fixes the cross-layer interfaces for the PF-AZ12 hardening and capability release so the runtime, backend API, and frontend can be implemented against the same shapes. All capabilities below remain inside the PatchForge product boundary: governance only, no scanning, no exploit content, no patch deployment, no autonomous approval.

## 1. Runtime: decision pack verification endpoint

`POST /api/runtime/decision-packs/verify`

Request body:

```json
{ "pack": { /* full pack object as returned by POST /api/runtime/decision-packs */ } }
```

Response 200:

```json
{
  "verified": true,
  "algorithm": "ES256",
  "artefact_hash_check": true,
  "manifest_hash_check": true,
  "signature_check": true,
  "failed_artefacts": []
}
```

Rules:

- Verification is stateless: hashes and signature are checked from the payload alone.
- Ed25519 signatures embed the raw public key (base64) in `sigmeta.public_key` at signing time so verification requires no external key plumbing.
- ES256 Key Vault signatures continue to embed the public JWK in sigmeta.
- `verified` is true only when all individual checks pass.

## 2. Backend: pack generation re-verification

After the bridge/API receives a generated pack from the runtime it MUST call the runtime verify endpoint before persisting. On `verified: false` the generation request fails with HTTP 502 `pack_verification_failed` and nothing is stored. The stored pack record gains `signature_verified: true` and `signature_algorithm`.

## 3. Backend: risk acceptances

- `POST /api/patchforge/risk-acceptances` — roles: RiskOwner, SecurityLead, Admin
- `GET /api/patchforge/risk-acceptances` — read roles
- `POST /api/patchforge/risk-acceptances/{id}/review` — roles: SecurityLead, Admin; body `{ "action": "accept" | "reject" | "extend", "notes": "...", "expires_at": "ISO-8601 (extend only)" }`

Record shape:

```json
{
  "risk_acceptance_id": "ra-...",
  "tenant_id": "...",
  "vulnerability_id": "CVE-....",
  "scope_description": "...",
  "justification": "...",
  "owner_upn": "...",
  "requested_by": "...",
  "expires_at": "ISO-8601",
  "status": "proposed | accepted | rejected | expired",
  "compensating_control_ids": [],
  "review_events": [ { "action": "...", "actor_upn": "...", "notes": "...", "recorded_at": "..." } ],
  "created_at": "...",
  "updated_at": "..."
}
```

`status` is derived as `expired` whenever `expires_at` is in the past, regardless of stored state. Expired acceptances can never satisfy governance posture.

List response: `{ "risk_acceptances": [...], "boundary": ... }`. Create/review response: `{ "risk_acceptance": {...}, "boundary": ... }`.

## 4. Backend: compensating controls

- `POST /api/patchforge/compensating-controls` — roles: TriageAnalyst, SecurityLead, Admin
- `GET /api/patchforge/compensating-controls` — read roles
- `POST /api/patchforge/compensating-controls/{id}/review` — roles: SecurityLead, Admin; body `{ "action": "accept" | "reject", "notes": "..." }`

Record shape:

```json
{
  "control_id": "cc-...",
  "tenant_id": "...",
  "name": "...",
  "description": "...",
  "mitigates_vulnerability_ids": [],
  "owner_upn": "...",
  "evidence_refs": [],
  "review_state": "pending_review | accepted | rejected",
  "expires_at": null,
  "review_events": [],
  "created_at": "...",
  "updated_at": "..."
}
```

List response: `{ "compensating_controls": [...], "boundary": ... }`. Create/review response: `{ "compensating_control": {...}, "boundary": ... }`.

## 5. Backend: named approval chain for decision packs

- `POST /api/patchforge/decision-packs/{packId}/approvals` — roles: SecurityLead, CABApprover, Admin; body `{ "decision_posture": "...", "notes": "..." }`
- `GET /api/patchforge/decision-packs/{packId}/approvals` — read roles

Approval event shape:

```json
{
  "approver_oid": "...",
  "approver_upn": "...",
  "approver_roles": ["PatchForge.SecurityLead"],
  "decision_posture": "...",
  "notes": "...",
  "recorded_at": "ISO-8601"
}
```

Approval policy lives in admin config under `approval_policy` with default:

```json
{ "required_roles": ["PatchForge.SecurityLead", "PatchForge.CABApprover"], "distinct_approvers": true }
```

`final_approval_recorded` on the pack record becomes true only when each required role has at least one approval event and (when `distinct_approvers`) the approver OIDs are distinct. An Admin approval may satisfy any single required role but a single Admin cannot satisfy two required roles when `distinct_approvers` is true. This records human approval evidence; it does not autonomously approve anything.

GET response: `{ "approval_events": [...], "final_approval_recorded": false, "approval_policy": {...} }`.
POST response: `{ "decision_pack": {...} }` (pack record including `approval_events` and `final_approval_recorded`).

## 6. Backend: webhooks

- `POST /api/patchforge/webhooks` — Admin; body `{ "url": "https://...", "event_types": [...], "secret": "optional" }`
- `GET /api/patchforge/webhooks` — Admin, Auditor
- `DELETE /api/patchforge/webhooks/{id}` — Admin

Event types: `decision_pack.generated`, `vulnerability.ingested`, `source_feed.completed`, `risk_acceptance.expiring`.

Delivery: JSON POST with header `x-patchforge-signature: sha256=<hex HMAC-SHA256 of body using subscription secret>` when a secret is set. Retries with exponential backoff (3 attempts), delivery results appended to a `webhook_deliveries` collection. Only `https` URLs are accepted.

## 7. Backend: pagination

Collection GET endpoints accept optional `limit` (1–500) and `offset` (>= 0). When `limit` is present the response is:

```json
{ "items": [...], "total": 123, "limit": 50, "offset": 0 }
```

Without `limit` the legacy response shape is unchanged (backward compatible).

## 8. Backend: rate limiting

Token bucket per tenant: default 120 requests/minute, override via `PATCHFORGE_RATE_LIMIT_PER_MINUTE`, disable with `PATCHFORGE_RATE_LIMIT_DISABLED=true` (tests set this). Exceeding the limit returns HTTP 429 with `Retry-After`.

## 9. Matching engine

A shared version/CPE utility module is used by both the global catalogue matching path and the VendorLens config-applicability path:

- CPE 2.3 formatted strings (`cpe:2.3:part:vendor:product:version:...`) are parsed when present on vulnerabilities/advisories and matched on vendor+product with version-range awareness.
- The version comparator previously private to `configApplicability.js` moves to `backend-api/patchforge/versionUtils.js` and is reused by `intelligence.js`.
- String/ID matching remains as fallback; results gain `match_basis`: `cpe_version_range | version_range | identifier | string_fallback` so users can see match confidence.

## 10. Runtime: risk model honesty and uncertainty

- The risk model self-describes as `model_type: "weighted_heuristic_risk_model"` and `is_bayesian_inference: false` in every snapshot.
- Each posterior gains an uncertainty band `{ "low": x, "high": y }` whose width grows with the number of unknown/missing inputs.
- `record_patch_outcome(...)` appends governed outcome observations; `propose_prior_update(...)` computes proposed deltas from observed outcomes. Prior mutation remains dry-run/proposal-only (governance lock unchanged).

## 11. Runtime: risk acceptance expiry enforcement

`DecisionControlCenter.record_risk_acceptance` raises `DecisionControlError` when `expires_at` is already in the past, and expired acceptances are excluded from posture/readiness calculations at event-recording time, not just at report time.

## 12. Frontend

- Active page, selected vulnerability/advisory/pack IDs persist in URL search params.
- A React error boundary wraps the app shell.
- Risk Acceptances and Compensating Controls pages are fully implemented against the APIs above.
- Reports & Packs shows the approval chain, records approvals with notes, and displays `signature_verified`.
- Global Security Action Center: saved filters (localStorage), bulk row selection with CSV export, SLA ageing display where `sla_due_at` exists.
- Keyboard shortcuts: Alt+1..5 switch top-level pages, `?` shows a shortcut hint, Alt+R refreshes live state.

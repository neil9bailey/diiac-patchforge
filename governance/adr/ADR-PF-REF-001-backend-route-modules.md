# ADR-PF-REF-001: Incremental Backend Route Modules

Status: Approved

Date: 2026-06-20

Epic: patchforge-architecture-refactor-loop-2026-06-20

Approved by: Human approval in Codex thread on 2026-06-20 (`ok approved`)

## Context

`backend-api/server.js` is the main HTTP composition root for PatchForge. It currently owns server setup, CORS, authorization, tenant context, request parsing, response helpers, route matching, route handlers, and lower-level business helper functions in one large file.

The previous refactor increments reduced repeated tenant request-context plumbing, but the remaining route surface is still too large to reason about comfortably. Splitting routes into focused modules is design-altering because it changes the internal backend architecture boundary. It must not change PatchForge's public API, security posture, storage contracts, or advisory-only product boundary.

## Decision

PatchForge will decompose backend API routes incrementally into route modules under `backend-api/routes/`.

The route module pattern is:

1. Keep `backend-api/server.js` as the composition root for HTTP server creation, dependency wiring, CORS, authorization, shared helpers, and process startup.
2. Move one coherent route family at a time into a small route module.
3. Pass dependencies explicitly to route modules instead of importing global storage or runtime state.
4. Return a boolean handled/not-handled result so route ordering and fall-through behavior stay obvious.
5. Preserve existing endpoint paths, HTTP methods, response shapes, status codes, authz requirements, tenant context, lineage fields, audit behavior, and boundary flags.

## First Approved Increment

Extract health/readiness routes into `backend-api/routes/platformRoutes.js`.

This first increment is intentionally small. Its purpose is to establish the route-module pattern without changing protected PatchForge behavior.

## Out Of Scope

- Public API path changes
- Authentication or authorization changes
- Tenant-resolution or tenant-override behavior changes
- Storage schema changes or migrations
- New runtime dependencies
- Vulnerability scanning, exploit generation, patch deployment, production mutation, autonomous approval, autonomous risk acceptance, or evidence-gate closure
- Full router rewrite in one diff

## Verification Expectations

- `node --check backend-api/server.js`
- `node --check backend-api/routes/platformRoutes.js`
- Backend API tests covering health and readiness
- Full backend package tests when the increment is ready
- Live local API smoke for `/health` and `/readiness`
- Autoreview/security review confirming no auth, tenant isolation, secret, dependency, or advisory-boundary regression

## Consequences

The backend can evolve toward smaller route modules without introducing a framework migration or changing deployment topology. The tradeoff is that server helpers become an explicit module boundary, so each extraction must be reviewed carefully for route ordering, dependency injection, and unchanged response semantics.

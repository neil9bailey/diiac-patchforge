import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "./server.js";
import { PatchForgeJsonStorage } from "./patchforge/storage.js";
import { createAuthConfigFromEnv } from "./auth.js";

async function withApi(run) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({ storage, auth: { required: false }, runtimeClient: fakeRuntimeClient() });
  await new Promise((resolve) => server.listen(0, resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    await run(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
}

async function withAuthenticatedApi(run, verifier) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-auth-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({
    storage,
    auth: {
      required: true,
      verifier
    },
    runtimeClient: fakeRuntimeClient()
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    await run(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
}

async function request(baseUrl, pathName, options = {}) {
  const response = await fetch(`${baseUrl}${pathName}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await response.json();
  return { response, body };
}

test("health and readiness endpoints respond", async () => {
  await withApi(async (baseUrl) => {
    const health = await request(baseUrl, "/health");
    assert.equal(health.response.status, 200);
    assert.equal(health.body.status, "ok");

    const readiness = await request(baseUrl, "/readiness");
    assert.equal(readiness.response.status, 200);
    assert.equal(readiness.body.storage, "local-json");
  });
});

test("CORS preflight allows the production UI origin", async () => {
  await withApi(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/patchforge/vulnerabilities`, {
      method: "OPTIONS",
      headers: {
        origin: "https://patchforge.diiac.io",
        "access-control-request-method": "GET",
        "access-control-request-headers": "authorization,x-tenant-id"
      }
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get("access-control-allow-origin"), "https://patchforge.diiac.io");
  });
});

test("ingests and lists vulnerabilities by tenant", async () => {
  await withApi(async (baseUrl) => {
    const ingest = await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "REAL-RECORD-1",
        canonical_id: "REAL-RECORD-1",
        title: "Customer supplied critical exposure",
        severity: "critical",
        known_exploited: true,
        internet_exposed: true,
        affected_service_ids: ["svc-customer"],
        sources: [{ source_record_id: "src-scanner-1", source_class: "scanner_output", source_name: "scanner connector" }]
      })
    });

    assert.equal(ingest.response.status, 201);
    assert.equal(ingest.body.vulnerability.source_state, "source_bound");
    assert.equal(ingest.body.vulnerability.review_state, "pending_review");

    const tenantA = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(tenantA.body.vulnerabilities.length, 1);

    const tenantB = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-b" }
    });
    assert.equal(tenantB.body.vulnerabilities.length, 0);
  });
});

test("review events update source state and rejected sources are not positive evidence", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "REAL-REJECTED-1",
        title: "Rejected source fixture",
        severity: "high",
        sources: [{ source_record_id: "src-bad", source_class: "scanner_output", source_name: "scanner" }]
      })
    });

    const review = await request(baseUrl, "/api/patchforge/vulnerabilities/REAL-REJECTED-1/review", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        source_record_id: "src-bad",
        reviewer: "security-lead",
        review_state: "rejected",
        evidence_state: "rejected",
        notes: "False positive"
      })
    });

    assert.equal(review.response.status, 200);
    assert.equal(review.body.source.review_state, "rejected");

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/REAL-REJECTED-1", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.body.vulnerability.sources.length, 1);
    assert.equal(detail.body.vulnerability.usable_evidence_sources.length, 0);
  });
});

test("agent findings ingest as source-bound advisory records", async () => {
  await withApi(async (baseUrl) => {
    const missing = await request(baseUrl, "/api/patchforge/agent-findings/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ source_class: "mythos_finding" })
    });
    assert.equal(missing.response.status, 400);
    assert.equal(missing.body.error, "finding_id_required");

    const rejectedClass = await request(baseUrl, "/api/patchforge/agent-findings/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ finding_id: "FINDING-1", source_class: "scanner_output" })
    });
    assert.equal(rejectedClass.response.status, 400);
    assert.equal(rejectedClass.body.error, "unsupported_agent_source_class");

    const ingest = await request(baseUrl, "/api/patchforge/agent-findings/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        finding_id: "MYTHOS-REAL-1",
        source_class: "mythos_finding",
        source_name: "Mythos",
        title: "Mythos correlated leading-class finding",
        severity: "critical",
        known_exploited: true,
        internet_exposed: true
      })
    });
    assert.equal(ingest.response.status, 202);
    assert.equal(ingest.body.boundary.advisory_only, true);
    assert.equal(ingest.body.boundary.can_close_hard_gates_alone, false);
    assert.equal(ingest.body.vulnerability.review_state, "pending_review");

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/MYTHOS-REAL-1", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.response.status, 200);
    assert.equal(detail.body.vulnerability.sources[0].source_class, "mythos_finding");
    assert.equal(detail.body.vulnerability.sources[0].evidence_state, "referenced");
    assert.equal(detail.body.vulnerability.usable_evidence_sources.length, 0);
  });
});

test("asset service exposure and dashboard metrics work", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/assets/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "asset-customer-1", asset_class: "application", exposure: "internet_facing" })
    });

    await request(baseUrl, "/api/patchforge/services/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        service_id: "svc-customer",
        service_name: "Customer Service",
        service_tier: "tier_1",
        customer_facing: true,
        affected_asset_ids: ["asset-customer-1"]
      })
    });

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "REAL-RECORD-1",
        title: "Critical service exposure",
        severity: "critical",
        internet_exposed: true,
        known_exploited: true,
        affected_service_ids: ["svc-customer"],
        patch_status: "overdue"
      })
    });

    const exposure = await request(baseUrl, "/api/patchforge/services/svc-customer/exposure", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(exposure.response.status, 200);
    assert.equal(exposure.body.exposure_summary.critical, 1);

    const metrics = await request(baseUrl, "/api/patchforge/dashboard/metrics", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(metrics.body.critical_exposure, 1);
    assert.equal(metrics.body.known_exploited, 1);
    assert.equal(metrics.body.patch_overdue, 1);
  });
});

test("no exploit or patch deployment endpoints exist", async () => {
  await withApi(async (baseUrl) => {
    const deploy = await request(baseUrl, "/api/patchforge/patches/deploy", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({})
    });
    assert.equal(deploy.response.status, 404);
    assert.match(deploy.body.boundary, /No scanner, exploit, patch deployment/);
  });
});

test("admin config saves locally, masks secrets, and blocks live Azure mutation", async () => {
  await withApi(async (baseUrl) => {
    const save = await request(baseUrl, "/api/patchforge/admin/config", {
      method: "PUT",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        general: { environment: "Production", governance_tier: "Enterprise Strict" },
        integrations: {
          scanner_integrations: [
            { name: "Scanner Connector", client_secret: "super-secret-value" }
          ]
        }
      })
    });
    assert.equal(save.response.status, 200);
    assert.equal(save.body.config.integrations.scanner_integrations[0].client_secret, "********");

    const config = await request(baseUrl, "/api/patchforge/admin/config", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(config.body.config.integrations.scanner_integrations[0].client_secret, "********");

    const health = await request(baseUrl, "/api/patchforge/admin/health", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(health.response.status, 200);
    assert.equal(health.body.live_azure_mutation_enabled, false);
    assert.ok(health.body.checks.some((check) => check.name === "Key Vault health"));

    const blocked = await request(baseUrl, "/api/patchforge/admin/config", {
      method: "PUT",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feature_flags: { azure_mutation_enabled: true } })
    });
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "live_azure_mutation_blocked");
  });
});

test("decision packs are generated only from ingested tenant vulnerabilities", async () => {
  await withApi(async (baseUrl) => {
    const missingId = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({})
    });
    assert.equal(missingId.response.status, 400);
    assert.equal(missingId.body.error, "vulnerability_id_required");

    const missingRecord = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ vulnerability_id: "REAL-MISSING-1" })
    });
    assert.equal(missingRecord.response.status, 404);
    assert.equal(missingRecord.body.error, "vulnerability_not_found");

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "REAL-RECORD-1",
        title: "Critical service exposure",
        severity: "critical",
        internet_exposed: true,
        known_exploited: true,
        patch_status: "patch_available",
        sources: [{
          source_record_id: "src-vendor-1",
          source_class: "vendor_advisory",
          source_name: "vendor advisory",
          evidence_state: "accepted_positive_evidence",
          review_state: "reviewed"
        }]
      })
    });

    const generated = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "REAL-RECORD-1",
        requested_posture: "patch_required"
      })
    });
    assert.equal(generated.response.status, 201);
    assert.equal(generated.body.decision_pack.vulnerability_id, "REAL-RECORD-1");
    assert.equal(generated.body.decision_pack.source_pack_immutable, true);

    const packs = await request(baseUrl, "/api/patchforge/decision-packs", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(packs.body.decision_packs.length, 1);

    const exported = await request(baseUrl, "/api/patchforge/decision-packs/PF-TEST-0001/export", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(exported.response.status, 200);
    assert.equal(exported.body.source_pack_immutable, true);
    assert.equal(exported.body.artefacts["governance_manifest.json"].pack_id, "PF-TEST-0001");

    const metrics = await request(baseUrl, "/api/patchforge/dashboard/metrics", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(metrics.body.signed_packs, 1);
  });
});

function fakeRuntimeClient() {
  return {
    async createDecisionPack(payload) {
      return {
        pack_id: "PF-TEST-0001",
        created_at: "2026-05-26T00:00:00Z",
        runtime_component: "patchforge-runtime",
        signing_provider: "test-signer",
        decision_context: {
          decision_id: "decision-test-1",
          vulnerability_id: payload.vulnerability.vulnerability_id,
          decision_posture: payload.requested_posture || "defer_pending_evidence",
          readiness: {
            readiness_state: "blocked",
            readiness_score: 25,
            blockers: ["affected_asset_scope"],
            final_approval_issued: false
          },
          blockers: ["affected_asset_scope"],
          final_approval_issued: false
        },
        verification: { verified: true },
        artefacts: {
          "governance_manifest.json": {
            pack_id: "PF-TEST-0001",
            source_pack_immutable: true
          },
          "signed_export.sigmeta.json": {
            algorithm: "test",
            dev_key_hint: null
          }
        },
        boundary: { no_patch_deployment: true, no_exploit_generation: true }
      };
    }
  };
}

test("auth gate requires a valid bearer token and PatchForge app role when enabled", async () => {
  await withAuthenticatedApi(async (baseUrl) => {
    const missing = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(missing.response.status, 401);
    assert.equal(missing.body.error, "missing_bearer_token");

    const forbidden = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-a", authorization: "Bearer no-role" }
    });
    assert.equal(forbidden.response.status, 403);
    assert.equal(forbidden.body.error, "insufficient_patchforge_role");

    const allowed = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-a", authorization: "Bearer reader" }
    });
    assert.equal(allowed.response.status, 200);
  }, async (token) => {
    if (token === "reader") {
      return { roles: ["PatchForge.Reader"], tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da", oid: "user-reader" };
    }
    return { roles: [], tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da", oid: "user-empty" };
  });
});

test("auth config accepts both API identifier URI and API client ID audiences", () => {
  const config = createAuthConfigFromEnv();
  assert.ok(config.audiences.includes("api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736"));
  assert.ok(config.audiences.includes("ec30b0eb-cfc4-48cc-a5f2-2a1345d96736"));
});

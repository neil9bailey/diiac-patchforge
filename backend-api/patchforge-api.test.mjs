import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "./server.js";
import { PatchForgeJsonStorage } from "./patchforge/storage.js";

async function withApi(run) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({ storage, auth: { required: false } });
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
    }
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

test("ingests and lists vulnerabilities by tenant", async () => {
  await withApi(async (baseUrl) => {
    const ingest = await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-10421",
        canonical_id: "CVE-2026-10421",
        title: "Orion Gateway critical exposure",
        severity: "critical",
        known_exploited: true,
        internet_exposed: true,
        affected_service_ids: ["svc-orion"],
        sources: [{ source_record_id: "src-scanner-1", source_class: "scanner_output", source_name: "demo scanner" }]
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
        vulnerability_id: "CVE-2026-20001",
        title: "Rejected source demo",
        severity: "high",
        sources: [{ source_record_id: "src-bad", source_class: "scanner_output", source_name: "scanner" }]
      })
    });

    const review = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-20001/review", {
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

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-20001", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.body.vulnerability.sources.length, 1);
    assert.equal(detail.body.vulnerability.usable_evidence_sources.length, 0);
  });
});

test("asset service exposure and dashboard metrics work", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/assets/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "asset-orion-1", asset_class: "application", exposure: "internet_facing" })
    });

    await request(baseUrl, "/api/patchforge/services/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        service_id: "svc-orion",
        service_name: "Orion Gateway",
        service_tier: "tier_1",
        customer_facing: true,
        affected_asset_ids: ["asset-orion-1"]
      })
    });

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-10421",
        title: "Critical service exposure",
        severity: "critical",
        internet_exposed: true,
        known_exploited: true,
        affected_service_ids: ["svc-orion"],
        patch_status: "overdue"
      })
    });

    const exposure = await request(baseUrl, "/api/patchforge/services/svc-orion/exposure", {
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
            { name: "Demo Scanner", client_secret: "super-secret-value" }
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

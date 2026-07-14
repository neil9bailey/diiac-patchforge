import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import JSZip from "jszip";
import { bindApprovalEventsToPrincipal, buildEvidenceItemsFromRecord, createServer } from "./server.js";
import { PatchForgeJsonStorage } from "./patchforge/storage.js";
import { createSourceFeedClient as createSourceFeedClientBase } from "./patchforge/sourceFeeds.js";
import { runSchedulerOnce } from "./patchforge/scheduler.js";
import { createAuthConfigFromEnv, rolesForRoute } from "./auth.js";
import { buildFindingIntelligence, buildIntelligenceForTenant } from "./patchforge/intelligence.js";
import { REPORT_CATALOG, REPORT_CONTEXT_VERSION, REPORT_TEMPLATE_VERSION, buildReportContext } from "./patchforge/reports.js";

const TEST_OUTBOUND_OPTIONS = {
  resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }]
};

function createSourceFeedClient(options = {}) {
  return createSourceFeedClientBase({ ...options, outboundOptions: options.outboundOptions || TEST_OUTBOUND_OPTIONS });
}

test("report context prefers immutable signed-pack intelligence over later live state", () => {
  const context = buildReportContext({
    reportType: "board_vulnerability_remediation_summary",
    pack: {
      pack_id: "PF-SNAPSHOT-001",
      vulnerability_id: "CVE-2026-SNAPSHOT-001",
      artefacts: {
        "finding_intelligence_snapshot.json": {
          summary: { executive_readout: "Signed-pack snapshot readout." },
          recommendation: { posture: "defer_pending_evidence" }
        }
      }
    },
    intelligence: {
      summary: { executive_readout: "Later mutable live readout." },
      recommendation: { posture: "patch_required" }
    }
  });

  assert.equal(context.executiveReadout, "Signed-pack snapshot readout.");
  assert.equal(context.recommendation.posture, "defer_pending_evidence");
});

test("all signed-pack generation aliases require the same elevated roles", () => {
  const expected = ["PatchForge.SecurityLead", "PatchForge.CABApprover", "PatchForge.Admin"];
  for (const pathName of [
    "/api/patchforge/decision-packs/generate",
    "/api/patchforge/reports-packs/generate",
    "/api/patchforge/reports/generate"
  ]) {
    assert.deepEqual(rolesForRoute("POST", pathName), expected);
  }
});

test("accountable approval roles retain least-privilege API read access", () => {
  const readRoles = rolesForRoute("GET", "/api/patchforge/reports-packs");
  for (const role of ["PatchForge.CABApprover", "PatchForge.RiskOwner", "PatchForge.ServiceOwner"]) {
    assert.ok(readRoles.includes(role), `${role} should be able to read governed workflow context`);
  }
});

test("finding intelligence requires a review linked to the current finding", () => {
  const intelligence = buildFindingIntelligence({
    vulnerability: {
      vulnerability_id: "CVE-2026-REVIEW-SCOPE-001",
      source_record_ids: ["source-current"],
      sources: [],
      affected_asset_ids: [],
      affected_service_ids: [],
      patch_status: "unknown"
    },
    reviews: [{
      review_id: "review-unrelated",
      vulnerability_id: "CVE-2026-OTHER-001",
      source_record_id: "source-other",
      reviewer: "security-lead"
    }]
  });

  assert.ok(intelligence.evidence.gaps.includes("Human source review event"));
});

test("finding intelligence does not correlate prefix-collision CVE identifiers", () => {
  const intelligence = buildFindingIntelligence({
    vulnerability: {
      vulnerability_id: "CVE-2026-0001",
      canonical_id: "CVE-2026-0001",
      sources: [],
      affected_asset_ids: [],
      affected_service_ids: [],
      patch_status: "unknown"
    },
    vendorAdvisories: [{
      advisory_id: "ADV-CVE-2026-00010",
      cve: "CVE-2026-00010",
      title: "Vendor notice for CVE-2026-00010",
      known_exploited: true,
      review_state: "pending_review"
    }]
  });

  assert.equal(intelligence.source_context.vendor_advisory_count, 0);
  assert.equal(intelligence.exploitability.known_exploited, false);
});

test("finding intelligence includes governed customer-network asset records", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-intelligence-assets-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await storage.ingestVulnerability("tenant-a", {
      vulnerability_id: "CVE-2026-CUSTOMER-ASSET-001",
      affected_asset_ids: ["customer-network-asset-1"]
    });
    await storage.append("customer_network_assets", {
      tenant_id: "tenant-a",
      asset_id: "customer-network-asset-1",
      model: "SRX4100",
      product_family: "Juniper SRX",
      review_state: "reviewed",
      evidence_state: "accepted_positive_evidence",
      internet_facing: true
    });

    const intelligence = await buildIntelligenceForTenant({
      storage,
      tenantId: "tenant-a",
      vulnerabilityId: "CVE-2026-CUSTOMER-ASSET-001"
    });
    assert.equal(intelligence.exposure.affected_asset_count, 1);
    assert.equal(intelligence.exposure.affected_assets[0].asset_id, "customer-network-asset-1");
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("stored EPSS score contributes to Bayesian finding analysis", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-EPSS-001",
        epss_score: 0.95,
        patch_status: "unknown"
      })
    });
    const analysis = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-EPSS-001/analyse", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({})
    });
    assert.equal(analysis.response.status, 200);
    assert.equal(analysis.body.bayesian.exploit_probability_posterior, 0.37);
  });
});

test("decision-pack evidence compiler ignores client-supplied hard-gate claims", () => {
  const items = buildEvidenceItemsFromRecord({
    sources: [{
      source_record_id: "source-persisted",
      source_class: "vendor_advisory",
      review_state: "pending_review",
      evidence_state: "referenced"
    }]
  }, [{
    evidence_ref: "forged-client-evidence",
    evidence_class: "human_review_signoff",
    source_class: "human_review",
    review_state: "reviewed",
    evidence_state: "reviewed"
  }]);

  assert.deepEqual(items.map((item) => item.evidence_ref), ["source-persisted"]);
});

test("approval lineage is server-bound and cannot be forged by the request body", () => {
  const requested = [{
    approval_type: "final",
    approval_state: "approved",
    approver: "forged-cab-chair",
    server_verified: true,
    actor_roles: ["PatchForge.Admin"]
  }];
  const untrusted = bindApprovalEventsToPrincipal(requested, {
    principal: { oid: "security-1", upn: "security@diiac.io", roles: ["PatchForge.SecurityLead"] }
  });
  assert.equal(untrusted[0].server_verified, false);
  assert.deepEqual(untrusted[0].actor_roles, []);

  const trusted = bindApprovalEventsToPrincipal(requested, {
    principal: { oid: "cab-1", upn: "cab@diiac.io", roles: ["PatchForge.CABApprover"] }
  });
  assert.equal(trusted[0].server_verified, true);
  assert.equal(trusted[0].approver, "cab@diiac.io");
  assert.deepEqual(trusted[0].actor_roles, ["PatchForge.CABApprover"]);
});

async function withApi(run, options = {}) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({
    storage,
    auth: { required: false },
    runtimeClient: fakeRuntimeClient(),
    sourceFeedClient: options.sourceFeedClient,
    vendorLensFetchImpl: options.vendorLensFetchImpl,
    vendorLensOutboundOptions: options.vendorLensOutboundOptions || TEST_OUTBOUND_OPTIONS
  });
  const baseUrl = await listenOnFetchSafePort(server);
  try {
    await run(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
}

async function withAuthenticatedApi(run, verifier, authOverrides = {}) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-auth-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({
    storage,
    auth: {
      required: true,
      verifier,
      defaultTenant: "diiac.io",
      tenantMappings: { "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da": "diiac.io" },
      ...authOverrides
    },
    runtimeClient: fakeRuntimeClient()
  });
  const baseUrl = await listenOnFetchSafePort(server);
  try {
    await run(baseUrl);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
}

async function listenOnFetchSafePort(server) {
  let lastError = null;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const port = 49152 + Math.floor(Math.random() * 12000);
    try {
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen(port, "127.0.0.1");
      });
      return `http://127.0.0.1:${port}`;
    } catch (error) {
      lastError = error;
      if (!["EADDRINUSE", "EACCES"].includes(error.code)) {
        throw error;
      }
    }
  }
  throw lastError || new Error("Unable to allocate a local PatchForge API test port.");
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

function statusFor(checks, name) {
  return checks.find((check) => check.name === name)?.status;
}

async function withEnv(values, run) {
  const previous = {};
  for (const [key, value] of Object.entries(values)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }
  try {
    await run();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
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

test("Bayesian advisory endpoints are deterministic and proposal-only", async () => {
  await withApi(async (baseUrl) => {
    const assessment = await request(baseUrl, "/api/patchforge/bayesian/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        cvss: 9.8,
        epss: 0.82,
        known_exploited: true,
        internet_exposed: true,
        patch_status: "patch_available",
        customer_facing: true
      })
    });
    assert.equal(assessment.response.status, 200);
    assert.equal(assessment.body.bayesian.advisory_only, true);
    assert.equal(assessment.body.bayesian.can_close_hard_gates_alone, false);
    assert.equal(assessment.body.bayesian.final_approval_issued, false);
    assert.equal(assessment.body.bayesian.recommended_governance_posture, "emergency_change_required");

    const priors = await request(baseUrl, "/api/patchforge/bayesian/priors", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(priors.response.status, 200);
    assert.equal(priors.body.live_prior_update_enabled, false);

    const proposal = await request(baseUrl, "/api/patchforge/bayesian/prior-update-dry-run", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ observed_outcomes: [{ outcome: "successful" }] })
    });
    assert.equal(proposal.response.status, 200);
    assert.equal(proposal.body.proposal.dry_run, true);
    assert.equal(proposal.body.proposal.live_update_applied, false);

    const blocked = await request(baseUrl, "/api/patchforge/bayesian/prior-update-dry-run", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ live_update: true })
    });
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "live_prior_update_locked");
  });
});

test("vendor and threat landscape intelligence remains source-bound", async () => {
  await withApi(async (baseUrl) => {
    const vendors = await request(baseUrl, "/api/patchforge/vendors", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(vendors.response.status, 200);
    assert.ok(vendors.body.vendors.some((vendor) => vendor.vendor_name === "Microsoft"));

    const advisory = await request(baseUrl, "/api/patchforge/vendors/microsoft/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "MS-ADV-REAL-1",
        source_class: "vendor_advisory",
        title: "Reviewed vendor advisory",
        severity: "critical",
        known_exploited: true,
        patch_available: true,
        superseded_by: "MS-ADV-REAL-2"
      })
    });
    assert.equal(advisory.response.status, 201);
    assert.equal(advisory.body.advisory.review_state, "pending_review");
    assert.equal(advisory.body.advisory.evidence_state, "referenced");
    assert.equal(advisory.body.advisory.superseded, true);

    const landscape = await request(baseUrl, "/api/patchforge/vendors/microsoft/threat-landscape", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(landscape.response.status, 200);
    assert.equal(landscape.body.metrics.active_exploitation_count, 1);
    assert.equal(landscape.body.metrics.superseded_advisory_count, 1);

    const summary = await request(baseUrl, "/api/patchforge/threat-landscape/summary", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(summary.response.status, 200);
    assert.equal(summary.body.source_bound, true);
    assert.equal(summary.body.review_required, true);
  });
});

test("VendorLens catalogue, assets, advisories, config applicability, chat, and packs stay governed", async () => {
  await withApi(async (baseUrl) => {
    const vendors = await request(baseUrl, "/api/patchforge/vendorlens/vendors", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(vendors.response.status, 200);
    assert.ok(vendors.body.vendors.some((vendor) => vendor.vendor_name === "Fortinet"));

    const asset = await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-1",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "100F",
        firmware_version: "7.2.7",
        internet_facing: true,
        management_exposure: "internet",
        enabled_features: ["ipsec_vpn"],
        disabled_features: ["ssl_vpn"],
        review_state: "pending_review",
        evidence_state: "referenced"
      })
    });
    assert.equal(asset.response.status, 201);
    assert.equal(asset.body.asset.source_state, "source_bound");

    const advisory = await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "FG-ADV-CVE-2026-REAL-001",
        vendor_id: "fortinet",
        vendor_name: "Fortinet",
        cve: "CVE-2026-REAL-001",
        title: "FortiGate SSL-VPN source-bound advisory",
        severity: "critical",
        product_family: "FortiGate",
        affected_versions: ["7.2.7"],
        affected_features: ["ssl_vpn"],
        known_exploited: true,
        patch_available: true,
        source_url: "https://www.fortiguard.com/psirt/example"
      })
    });
    assert.equal(advisory.response.status, 201);
    assert.equal(advisory.body.advisory.review_state, "pending_review");
    assert.equal(advisory.body.advisory.can_close_hard_gates_alone, false);

    const disabledUnreviewed = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-1",
        advisory_id: "FG-ADV-CVE-2026-REAL-001"
      })
    });
    assert.equal(disabledUnreviewed.response.status, 200);
    assert.equal(disabledUnreviewed.body.assessment.applicability_posture, "requires_review");
    assert.equal(disabledUnreviewed.body.assessment.urgency_posture, "urgent_scope_confirmation_required");
    assert.equal(disabledUnreviewed.body.assessment.final_approval_issued, false);
    assert.ok(disabledUnreviewed.body.assessment.evidence_gaps.every((gap) => gap.why_it_matters && gap.required_evidence && gap.suggested_owner_role && gap.next_decision_gate));

    const comparison = await request(baseUrl, "/api/patchforge/vendorlens/patch-compare", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-1",
        advisory_id: "FG-ADV-CVE-2026-REAL-001",
        target_version: "7.2.8"
      })
    });
    assert.equal(comparison.response.status, 200);
    assert.equal(comparison.body.comparison.advisory_only, true);
    assert.equal(comparison.body.comparison.no_patch_deployment, true);
    assert.equal(comparison.body.comparison.final_approval_issued, false);
    assert.match(comparison.body.comparison.ciso_summary, /Current version 7\.2\.7/);

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-2",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "100F",
        firmware_version: "7.2.7",
        internet_facing: true,
        management_exposure: "internet",
        enabled_features: ["ssl_vpn"],
        config_evidence_refs: ["cfg-reviewed-1"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const enabledKev = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-2", advisory_id: "FG-ADV-CVE-2026-REAL-001" })
    });
    assert.equal(enabledKev.body.assessment.applicability_posture, "applicable");
    assert.equal(enabledKev.body.assessment.urgency_posture, "emergency_patch_required");

    const reviewedAdvisory = await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "FG-ADV-CVE-2026-REAL-001-REVIEWED",
        vendor_id: "fortinet",
        vendor_name: "Fortinet",
        cve: "CVE-2026-REAL-001",
        title: "FortiOS SSL VPN reviewed source-bound advisory",
        severity: "critical",
        product_family: "FortiOS",
        affected_versions: ["< 7.2.8"],
        fixed_versions: ["7.2.8"],
        affected_features: ["SSL-VPN"],
        known_exploited: true,
        patch_available: true,
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence",
        source_url: "https://www.fortiguard.com/psirt/example-reviewed"
      })
    });
    assert.equal(reviewedAdvisory.response.status, 201);

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-disabled-reviewed",
        vendor_id: "fortinet",
        product_family: "Fortinet Firewall",
        model: "100F",
        firmware_version: "7.2.7",
        disabled_features: ["SSL VPN"],
        config_evidence_refs: ["cfg-reviewed-disabled-ssl-vpn"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const disabledReviewed = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-disabled-reviewed", advisory_id: "FG-ADV-CVE-2026-REAL-001-REVIEWED" })
    });
    assert.equal(disabledReviewed.body.assessment.applicability_posture, "not_applicable");
    assert.equal(disabledReviewed.body.assessment.final_approval_issued, false);

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-fixed-reviewed",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "100F",
        firmware_version: "7.2.8",
        enabled_features: ["webvpn"],
        config_evidence_refs: ["cfg-reviewed-fixed-version"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const fixedReviewed = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-fixed-reviewed", advisory_id: "FG-ADV-CVE-2026-REAL-001-REVIEWED" })
    });
    assert.equal(fixedReviewed.body.assessment.affected_version_status, "fixed_version_reviewed");
    assert.equal(fixedReviewed.body.assessment.applicability_posture, "not_applicable");
    assert.equal(fixedReviewed.body.assessment.urgency_posture, "monitor");

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-fixed-unreviewed",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "100F",
        firmware_version: "7.2.8",
        enabled_features: ["ssl_vpn"],
        review_state: "pending_review",
        evidence_state: "referenced"
      })
    });
    const fixedUnreviewed = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-fixed-unreviewed", advisory_id: "FG-ADV-CVE-2026-REAL-001-REVIEWED" })
    });
    assert.equal(fixedUnreviewed.body.assessment.affected_version_status, "fixed_version_pending_review");
    assert.equal(fixedUnreviewed.body.assessment.applicability_posture, "requires_review");

    await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "PAN-GP-2026",
        vendor_id: "palo_alto",
        vendor_name: "Palo Alto Networks",
        cve: "CVE-2026-PAN-GP-001",
        product_family: "PAN-OS",
        affected_versions: ["<= 10.2.6"],
        fixed_versions: ["10.2.7"],
        affected_features: ["GlobalProtect"],
        known_exploited: true,
        patch_available: true,
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "pan-fw-1",
        vendor_id: "palo_alto",
        product_family: "Palo Alto Firewall",
        firmware_version: "10.2.5",
        internet_facing: true,
        management_exposure: "internet",
        enabled_features: ["globalprotect"],
        config_evidence_refs: ["cfg-pan-globalprotect"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const panEnabledKev = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "pan-fw-1", advisory_id: "PAN-GP-2026" })
    });
    assert.equal(panEnabledKev.body.assessment.affected_feature_status, "affected_feature_present");
    assert.equal(panEnabledKev.body.assessment.applicability_posture, "applicable");
    assert.equal(panEnabledKev.body.assessment.urgency_posture, "emergency_patch_required");

    await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "CISCO-ASA-ANYCONNECT-2026",
        vendor_id: "cisco",
        vendor_name: "Cisco",
        cve: "CVE-2026-CISCO-ASA-001",
        product_family: "Cisco ASA",
        affected_versions: ["9.18.x"],
        affected_features: ["AnyConnect"],
        known_exploited: true,
        patch_available: true,
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "cisco-asa-1",
        vendor_id: "cisco",
        product_family: "ASA",
        firmware_version: "9.18.2",
        disabled_features: ["anyconnect"],
        review_state: "pending_review",
        evidence_state: "referenced"
      })
    });
    const ciscoDisabledUnreviewed = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "cisco-asa-1", advisory_id: "CISCO-ASA-ANYCONNECT-2026" })
    });
    assert.equal(ciscoDisabledUnreviewed.body.assessment.feature_enabled_status, "disabled_unreviewed");
    assert.equal(ciscoDisabledUnreviewed.body.assessment.applicability_posture, "requires_review");

    await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "F5-BIGIP-SUPERSEDED",
        vendor_id: "f5",
        vendor_name: "F5",
        cve: "CVE-2026-F5-001",
        product_family: "F5 BIG-IP",
        affected_versions: ["10.2.0-10.2.6"],
        affected_features: ["iControl REST"],
        superseded: true,
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "f5-bigip-1",
        vendor_id: "f5",
        product_family: "BIG-IP",
        firmware_version: "10.2.3",
        enabled_features: ["icontrol_rest"],
        config_evidence_refs: ["cfg-f5-icontrol"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const supersededPending = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "f5-bigip-1", advisory_id: "F5-BIGIP-SUPERSEDED" })
    });
    assert.equal(supersededPending.body.assessment.applicability_posture, "requires_review");
    assert.ok(supersededPending.body.assessment.evidence_required.includes("reviewed_supersedence"));

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-3",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "40F",
        firmware_version: "7.4.9",
        not_in_estate: true,
        config_evidence_refs: ["asset-owner-reviewed"],
        review_state: "reviewed",
        evidence_state: "accepted_positive_evidence"
      })
    });
    const notApplicable = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-3", advisory_id: "FG-ADV-CVE-2026-REAL-001" })
    });
    assert.equal(notApplicable.body.assessment.applicability_posture, "not_applicable");
    assert.equal(notApplicable.body.assessment.final_approval_issued, false);

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-4",
        vendor_id: "fortinet",
        product_family: "FortiGate",
        model: "100F",
        internet_facing: true,
        enabled_features: ["ssl_vpn"]
      })
    });
    const unknownFirmware = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "net-fw-4", advisory_id: "FG-ADV-CVE-2026-REAL-001" })
    });
    assert.equal(unknownFirmware.body.assessment.affected_version_status, "unknown");
    assert.equal(unknownFirmware.body.assessment.urgency_posture, "urgent_scope_confirmation_required");

    const chat = await request(baseUrl, "/api/patchforge/vendorlens/chat", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-fw-1",
        advisory_id: "FG-ADV-CVE-2026-REAL-001",
        question: "We use FortiGate 100F FortiOS 7.2.7 with SSL-VPN disabled. Do we urgently need to patch?"
      })
    });
    assert.equal(chat.response.status, 201);
    assert.ok(chat.body.response.short_answer);
    assert.ok(chat.body.response.evidence_missing);
    assert.equal(chat.body.response.final_approval_issued, false);
    assert.doesNotMatch(JSON.stringify(chat.body), /procedural exploitation instructions|exploit steps|how to exploit/i);

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-REAL-001",
        title: "FortiGate source-bound CVE",
        severity: "critical",
        known_exploited: true,
        patch_status: "patch_available",
        sources: [{ source_record_id: "src-fortinet-1", source_class: "vendor_advisory", source_name: "Fortinet PSIRT" }]
      })
    });
    const generated = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-REAL-001",
        advisory_id: "FG-ADV-CVE-2026-REAL-001",
        asset_id: "net-fw-1",
        config_applicability_assessment_id: disabledUnreviewed.body.assessment.assessment_id,
        comparison_id: comparison.body.comparison.comparison_id,
        session_id: chat.body.session.session_id
      })
    });
    assert.equal(generated.response.status, 201);
    assert.ok(generated.body.decision_pack.artefacts["config_applicability_assessment.json"]);
    assert.ok(generated.body.decision_pack.artefacts["vendorlens_patch_comparison.json"]);
    assert.ok(generated.body.decision_pack.artefacts["vendorlens_decision_context.json"]);

    const context = buildReportContext({
      reportType: "technical_evidence_appendix",
      pack: generated.body.decision_pack
    });
    assert.equal(context.configApplicability.final_approval_issued, false);
    assert.equal(context.configApplicability.urgency_posture, "urgent_scope_confirmation_required");
    assert.equal(context.vendorLensPatchComparison.final_approval_issued, false);
  });
});

test("decision pack generation excludes mismatched VendorLens context instead of mixing reports", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-GOOGLE-001",
        title: "Google Chromium source-bound CVE",
        severity: "high",
        known_exploited: true,
        patch_status: "unknown",
        sources: [{ source_record_id: "src-google-1", source_class: "kev_record", source_name: "CISA KEV" }]
      })
    });

    await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-juniper-stale",
        vendor_id: "juniper",
        vendor_name: "Juniper",
        product_family: "SRX",
        model: "4200",
        firmware_version: "21.3",
        internet_facing: true,
        enabled_features: ["ipsec_vpn", "ssl_vpn"],
        review_state: "pending_review",
        evidence_state: "referenced"
      })
    });

    await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "nvd-CVE-2007-1891",
        vendor_id: "akamai",
        vendor_name: "Akamai",
        cve: "CVE-2007-1891",
        title: "Akamai Download Manager stale advisory",
        severity: "high",
        product_family: "Download Manager",
        patch_available: false,
        source_url: "https://example.invalid/akamai"
      })
    });

    const staleAssessment = await request(baseUrl, "/api/patchforge/vendorlens/applicability/assess", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-juniper-stale",
        advisory_id: "nvd-CVE-2007-1891"
      })
    });

    const staleComparison = await request(baseUrl, "/api/patchforge/vendorlens/patch-compare", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "net-juniper-stale",
        advisory_id: "nvd-CVE-2007-1891",
        target_version: "7.2.8"
      })
    });

    const generated = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-GOOGLE-001",
        advisory_id: "nvd-CVE-2007-1891",
        asset_id: "net-juniper-stale",
        config_applicability_assessment: staleAssessment.body.assessment,
        vendorlens_patch_comparison: staleComparison.body.comparison,
        network_vendor_profile_snapshot: { vendor_id: "akamai", vendor_name: "Akamai" },
        customer_network_asset_snapshot: { asset_id: "net-juniper-stale", vendor_id: "juniper", product_family: "SRX" },
        vendor_security_advisory_snapshot: { advisory_id: "nvd-CVE-2007-1891", vendor_id: "akamai", cve: "CVE-2007-1891" }
      })
    });

    assert.equal(generated.response.status, 201);
    const artefacts = generated.body.decision_pack.artefacts;
    assert.equal(artefacts["config_applicability_assessment.json"].available, false);
    assert.equal(artefacts["vendorlens_patch_comparison.json"].available, false);
    assert.equal(artefacts["network_vendor_profile_snapshot.json"].available, false);
    assert.equal(artefacts["customer_network_asset_snapshot.json"].available, false);
    assert.equal(artefacts["vendor_security_advisory_snapshot.json"].available, false);

    const packedContext = JSON.stringify({
      network_vendor_profile_snapshot: artefacts["network_vendor_profile_snapshot.json"],
      customer_network_asset_snapshot: artefacts["customer_network_asset_snapshot.json"],
      vendor_security_advisory_snapshot: artefacts["vendor_security_advisory_snapshot.json"],
      config_applicability_assessment: artefacts["config_applicability_assessment.json"],
      vendorlens_patch_comparison: artefacts["vendorlens_patch_comparison.json"],
      vendorlens_decision_context: artefacts["vendorlens_decision_context.json"]
    });
    assert.doesNotMatch(packedContext, /CVE-2007-1891|Akamai|net-juniper-stale|SRX/i);
  });
});

test("VendorLens NVD source refresh is source-bound and pending review", async () => {
  await withApi(async (baseUrl) => {
    const refresh = await request(baseUrl, "/api/patchforge/vendorlens/sources/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ adapter: "nvd_cve_api", cve: "CVE-2026-REAL-1234", vendor_id: "cisco" })
    });
    assert.equal(refresh.response.status, 202);
    assert.equal(refresh.body.source_feed_run.status, "completed");
    assert.equal(refresh.body.source_feed_run.records_ingested, 1);

    const advisories = await request(baseUrl, "/api/patchforge/vendorlens/advisories", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(advisories.body.advisories[0].review_state, "pending_review");
    assert.equal(advisories.body.advisories[0].source_state, "source_bound");
  }, {
    vendorLensFetchImpl: async (url) => {
      assert.match(String(url), /services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/);
      return jsonResponse({
        vulnerabilities: [{
          cve: {
            id: "CVE-2026-REAL-1234",
            descriptions: [{ lang: "en", value: "Cisco example product contains a source-bound vulnerability record." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: "HIGH" } }] },
            configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:o:cisco:asa_software:9.18:*:*:*:*:*:*:*" }] }] }]
          }
        }]
      });
    }
  });
});

test("VendorLens NVD catalogue refresh pages vendor CVEs without requiring a single CVE", async () => {
  const requestedKeywords = [];
  await withApi(async (baseUrl) => {
    const refresh = await request(baseUrl, "/api/patchforge/vendorlens/sources/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ adapter: "nvd_cve_api", mode: "catalogue", vendor_id: "fortinet", results_per_page: 2, max_pages: 2, max_keywords: 3 })
    });
    assert.equal(refresh.response.status, 202);
    assert.equal(refresh.body.source_feed_run.status, "completed");
    assert.equal(refresh.body.source_feed_run.records_ingested, 3);
    assert.equal(refresh.body.source_feed_run.feed_id, "nvd-cve-2-catalogue");
    assert.ok(refresh.body.source_feed_run.source_keywords.some((item) => item.keyword === "Fortinet FortiGate"));
    assert.ok(new Set(requestedKeywords).has("Fortinet FortiGate"));

    const advisories = await request(baseUrl, "/api/patchforge/vendorlens/advisories", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(advisories.body.advisories.length, 3);
    assert.ok(advisories.body.advisories.every((item) => item.review_state === "pending_review"));
  }, {
    vendorLensFetchImpl: async (url) => {
      const parsed = new URL(String(url));
      const keyword = parsed.searchParams.get("keywordSearch");
      requestedKeywords.push(keyword);
      assert.ok(["Fortinet", "Fortinet FortiGate", "Fortinet FortiOS"].includes(keyword));
      const start = parsed.searchParams.get("startIndex");
      const ids = start === "2"
        ? ["CVE-2026-NVD-CAT-003"]
        : ["CVE-2026-NVD-CAT-001", "CVE-2026-NVD-CAT-002"];
      return jsonResponse({
        totalResults: 3,
        vulnerabilities: ids.map((id) => ({
          cve: {
            id,
            descriptions: [{ lang: "en", value: `${id} Fortinet catalogue record.` }],
            metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: "HIGH" } }] },
            configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*" }] }] }]
          }
        }))
      });
    }
  });
});

test("VendorLens NVD catalogue refresh records rate limits without failing the UI path", async () => {
  await withApi(async (baseUrl) => {
    const refresh = await request(baseUrl, "/api/patchforge/vendorlens/sources/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ adapter: "nvd_cve_api", mode: "catalogue", vendor_id: "fortinet", results_per_page: 2, max_pages: 2 })
    });
    assert.equal(refresh.response.status, 202);
    assert.equal(refresh.body.source_feed_run.status, "completed_with_warnings");
    assert.equal(refresh.body.source_feed_run.records_ingested, 2);
    assert.match(refresh.body.source_feed_run.message, /rate limit/i);
    assert.equal(refresh.body.source_feed_run.source_failures[0].status, 429);
  }, {
    vendorLensFetchImpl: async (url) => {
      const start = new URL(String(url)).searchParams.get("startIndex");
      if (start === "2") {
        return jsonResponse({ message: "rate limited" }, 429);
      }
      return jsonResponse({
        totalResults: 3,
        vulnerabilities: ["CVE-2026-NVD-RATE-001", "CVE-2026-NVD-RATE-002"].map((id) => ({
          cve: {
            id,
            descriptions: [{ lang: "en", value: "Fortinet catalogue record before rate limit." }],
            metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: "HIGH" } }] },
            configurations: [{ nodes: [{ cpeMatch: [{ criteria: "cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*" }] }] }]
          }
        }))
      });
    }
  });
});

test("PatchForge catalogue, customer operational assets, ask, and reports APIs work", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vendorlens/advisories/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        advisory_id: "FG-PFAZ10-SSLVPN",
        vendor_id: "fortinet",
        vendor_name: "Fortinet",
        cve: "CVE-2026-PFAZ10-001",
        title: "FortiOS SSL-VPN source-bound advisory",
        severity: "critical",
        product_family: "FortiGate",
        affected_versions: ["< 7.2.8"],
        fixed_versions: ["7.2.8"],
        affected_features: ["SSL-VPN"],
        known_exploited: true,
        patch_available: true,
        epss_score: 0.91,
        source_url: "https://example.invalid/fortinet-pfaz10"
      })
    });
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PFAZ10-001",
        title: "FortiOS SSL-VPN source-bound advisory",
        severity: "critical",
        vendor_id: "fortinet",
        vendor_name: "Fortinet",
        product_family: "FortiGate",
        affected_versions: ["< 7.2.8"],
        fixed_versions: ["7.2.8"],
        affected_feature: "SSL-VPN",
        known_exploited: true,
        patch_status: "patch_available",
        sources: [{ source_record_id: "src-pfaz10-1", source_class: "vendor_advisory", source_name: "Fortinet PSIRT" }]
      })
    });

    const extracted = await request(baseUrl, "/api/patchforge/customer-estate/assets/extract", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ description: "FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only." })
    });
    assert.equal(extracted.response.status, 200);
    assert.equal(extracted.body.extracted_asset.vendor_id, "fortinet");
    assert.equal(extracted.body.extracted_asset.model, "100F");
    assert.equal(extracted.body.extracted_asset.evidence_state, "user_stated_unreviewed");

    const extractedOperationalAsset = await request(baseUrl, "/api/patchforge/customer-operational-assets/assets/extract", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ description: "FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only." })
    });
    assert.equal(extractedOperationalAsset.response.status, 200);
    assert.equal(extractedOperationalAsset.body.extracted_asset.vendor_id, "fortinet");

    const upsert = await request(baseUrl, "/api/patchforge/customer-estate/assets/upsert", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ ...extracted.body.extracted_asset, asset_id: "pfaz10-fw-100f" })
    });
    assert.equal(upsert.response.status, 201);

    const match = await request(baseUrl, "/api/patchforge/customer-estate/match", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ asset_id: "pfaz10-fw-100f" })
    });
    assert.equal(match.response.status, 200);
    assert.ok(match.body.matches.some((item) => item.cve === "CVE-2026-PFAZ10-001"));
    assert.equal(match.body.final_approval_issued, false);

    const operationalAssets = await request(baseUrl, "/api/patchforge/customer-operational-assets/assets", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(operationalAssets.response.status, 200);
    assert.ok(operationalAssets.body.assets.some((asset) => asset.asset_id === "pfaz10-fw-100f"));

    const actionCenter = await request(baseUrl, "/api/patchforge/security-action-center", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(actionCenter.response.status, 200);
    assert.ok(actionCenter.body.groups.some((group) => group.vendor_name === "Fortinet"));

    const register = await request(baseUrl, "/api/patchforge/vendors-exploits-register", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(register.response.status, 200);
    assert.ok(register.body.catalogue_rows.some((row) => row.cve_id === "CVE-2026-PFAZ10-001"));

    const search = await request(baseUrl, "/api/patchforge/security-action-center/search?q=SSL-VPN&vendor=fortinet&customer_match=true", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(search.response.status, 200);
    assert.ok(search.body.catalogue_rows.some((row) => row.customer_match_count > 0));

    const detail = await request(baseUrl, "/api/patchforge/security-action-center/cves/CVE-2026-PFAZ10-001", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.response.status, 200);
    assert.equal(detail.body.cve.cve_id, "CVE-2026-PFAZ10-001");

    const registerDetail = await request(baseUrl, "/api/patchforge/vendors-exploits-register/cves/CVE-2026-PFAZ10-001", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(registerDetail.response.status, 200);
    assert.equal(registerDetail.body.cve.cve_id, "CVE-2026-PFAZ10-001");

    const patchCompare = await request(baseUrl, "/api/patchforge/customer-estate/patch-compare", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        asset_id: "pfaz10-fw-100f",
        advisory_id: "FG-PFAZ10-SSLVPN",
        current_version: "7.2.7",
        proposed_version: "7.2.8"
      })
    });
    assert.equal(patchCompare.response.status, 200);
    assert.equal(patchCompare.body.comparison.current_version_affected, "affected");
    assert.equal(patchCompare.body.comparison.final_approval_issued, false);
    assert.equal(patchCompare.body.comparison.no_patch_deployment, true);

    const ask = await request(baseUrl, "/api/patchforge/ask", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        question: "We use FortiGate 100F FortiOS 7.2.7 with SSL-VPN disabled. Does CVE-2026-PFAZ10-001 require urgent patching?"
      })
    });
    assert.equal(ask.response.status, 200);
    assert.equal(ask.body.response.final_approval_issued, false);
    assert.equal(ask.body.response.human_approval_required, true);

    await withEnv({
      OPENAI_API_KEY: undefined,
      PATCHFORGE_OPENAI_AGENT_ENABLED: undefined,
      PATCHFORGE_OPENAI_MODEL: undefined
    }, async () => {
      const agentStatus = await request(baseUrl, "/api/patchforge/agents/status", {
        headers: { "x-tenant-id": "tenant-a" }
      });
      assert.equal(agentStatus.response.status, 200);
      assert.equal(agentStatus.body.openai_agent.enabled, false);
      assert.equal(agentStatus.body.openai_agent.model, "gpt-5.4");
      assert.equal(agentStatus.body.openai_agent.key_configured, false);
      assert.equal(agentStatus.body.openai_agent.key_value_exposed, false);
      assert.equal(agentStatus.body.openai_agent.final_approval_issued, false);

      const disabledAgent = await request(baseUrl, "/api/patchforge/agents/ask", {
        method: "POST",
        headers: { "x-tenant-id": "tenant-a" },
        body: JSON.stringify({
          question: "Does CVE-2026-PFAZ10-001 require urgent patching?",
          vulnerability_id: "CVE-2026-PFAZ10-001",
          deterministic_answer: { final_approval_issued: true, forged: true },
          evidence: { accepted_positive_evidence: true },
          reviewed_exposure_evidence: true,
          reviewed_applicability_evidence: true,
          reviewed_customer_assurance_evidence: true
        })
      });
      assert.equal(disabledAgent.response.status, 202);
      assert.equal(disabledAgent.body.agent_guidance.status, "disabled");
      assert.equal(disabledAgent.body.agent_guidance.fallback.final_approval_issued, false);
      assert.equal(disabledAgent.body.agent_guidance.can_close_hard_gates, false);
      assert.equal(disabledAgent.body.server_evidence_context.finding_binding.vulnerability_id, "CVE-2026-PFAZ10-001");
      assert.equal(disabledAgent.body.server_evidence_context.reviewed_exposure_evidence, false);
      assert.equal(disabledAgent.body.server_evidence_context.reviewed_applicability_evidence, false);
      assert.equal(disabledAgent.body.server_evidence_context.reviewed_customer_assurance_evidence, false);
      assert.equal(disabledAgent.body.server_evidence_context.caller_review_flags_ignored, true);
    });

    const reports = await request(baseUrl, "/api/patchforge/reports-packs", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(reports.response.status, 200);
    assert.ok(reports.body.export_options.includes("Technical Evidence Appendix"));

    const reportsOverview = await request(baseUrl, "/api/patchforge/reports/overview", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(reportsOverview.response.status, 200);
    assert.ok(reportsOverview.body.export_options.includes("Technical Evidence Appendix"));

    const generated = await request(baseUrl, "/api/patchforge/reports-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PFAZ10-001",
        advisory_id: "FG-PFAZ10-SSLVPN",
        asset_id: "pfaz10-fw-100f",
        comparison_id: patchCompare.body.comparison.comparison_id
      })
    });
    assert.equal(generated.response.status, 201);
    assert.equal(generated.body.decision_pack.final_approval_issued, false);
    assert.equal(generated.body.decision_pack.report_template_version, REPORT_TEMPLATE_VERSION);
    assert.equal(generated.body.decision_pack.report_context_version, REPORT_CONTEXT_VERSION);
    assert.equal(generated.body.pre_export_state.final_approval_issued, false);
    assert.ok(generated.body.report_quality_reviews.every((review) => review.status === "PASS"));
  });
});

test("PatchForge rebuild source adapters normalise fixture-backed intelligence", async () => {
  await withApi(async (baseUrl) => {
    const adapters = await request(baseUrl, "/api/patchforge/sources/adapters", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(adapters.response.status, 200);
    assert(adapters.body.adapters.some((adapter) => adapter.adapter_id === "nvd-cve-api"));
    assert(adapters.body.adapters.some((adapter) => adapter.adapter_id === "github-advisory"));
    for (const adapterId of ["microsoft-msrc", "cisco-psirt", "fortinet-psirt", "juniper-advisories", "cisa-alerts", "ncsc-advisories"]) {
      assert(adapters.body.adapters.some((adapter) => adapter.adapter_id === adapterId), `${adapterId} adapter missing`);
    }

    const sync = await request(baseUrl, "/api/patchforge/sources/sync", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ adapter_id: "github-advisory", fetched_at: "2026-06-01T00:00:00.000Z" })
    });
    assert.equal(sync.response.status, 202);
    assert.equal(sync.body.source_feed_run.status, "completed");
    assert.equal(sync.body.normalized_records[0].source, "GitHub");
    assert.equal(sync.body.normalized_records[0].source_hash.length, 64);
    assert.equal(sync.body.normalized_records[0].confidence > 0, true);
    assert.doesNotMatch(JSON.stringify(sync.body), /reverse shell|shellcode|metasploit/i);
  });
});

test("config redaction and parsers never persist raw synthetic secrets", async () => {
  await withApi(async (baseUrl) => {
    const config = [
      "hostname edge-fw-01",
      "config vpn ssl settings",
      "set password SyntheticSecret123!",
      "set source-interface wan1",
      "FortiOS 7.2.7"
    ].join("\n");
    const parsed = await request(baseUrl, "/api/patchforge/config/parse", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ customer_id: "cust-a", asset_id: "asset-a", config })
    });
    assert.equal(parsed.response.status, 200);
    assert.equal(parsed.body.config_evidence.redaction_status, "redacted");
    assert.equal(parsed.body.config_evidence.raw_secret_values_persisted, false);
    assert.equal(parsed.body.config_evidence.parser_family, "fortinet");
    assert.match(parsed.body.config_evidence.redacted_config, /\[REDACTED_SECRET\]/);
    assert.doesNotMatch(JSON.stringify(parsed.body), /SyntheticSecret123!/);
  });
});

test("customer asset CSV import is tenant scoped", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/customers", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ id: "cust-a", name: "Customer A", tenant_key: "tenant-a" })
    });
    const imported = await request(baseUrl, "/api/patchforge/customers/cust-a/assets", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        csv: "hostname,vendor,product,version,internet_exposed,criticality\nedge-fw-01,Fortinet,FortiGate,7.2.7,true,critical"
      })
    });
    assert.equal(imported.response.status, 201);
    assert.equal(imported.body.imported, 1);

    const tenantA = await request(baseUrl, "/api/patchforge/customers/cust-a/assets", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    const tenantB = await request(baseUrl, "/api/patchforge/customers/cust-a/assets", {
      headers: { "x-tenant-id": "tenant-b" }
    });
    assert.equal(tenantA.body.assets.length, 1);
    assert.equal(tenantB.body.assets.length, 0);
  });
});

test("asset discovery collectors import categorized assets as source-bound pending-review evidence", async () => {
  await withApi(async (baseUrl) => {
    const overview = await request(baseUrl, "/api/patchforge/discovery/overview", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(overview.response.status, 200);
    assert.ok(overview.body.discovery.categories.includes("network_device"));
    assert.equal(overview.body.discovery.boundary.no_vulnerability_scanning, true);
    assert.equal(overview.body.discovery.boundary.no_patch_deployment, true);

    const collector = await request(baseUrl, "/api/patchforge/discovery/collectors", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        collector_id: "collector-london-1",
        name: "London discovery collector",
        platform: "windows",
        site: "London",
        categories: ["network_device", "security_appliance", "physical_server"]
      })
    });
    assert.equal(collector.response.status, 201);
    assert.equal(collector.body.collector.connection_mode, "outbound_only");
    assert.equal(collector.body.collector.final_approval_issued, false);

    const policy = await request(baseUrl, "/api/patchforge/discovery/policies", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        policy_id: "policy-london-network",
        collector_id: "collector-london-1",
        name: "London network and server inventory",
        categories: ["network_device", "security_appliance", "physical_server"],
        discovery_methods: ["manual_snapshot", "snmpv3_read_only"],
        credential_reference: "customer-vault:patchforge/snmpv3-readonly",
        scope: {
          sites: ["London"],
          ip_ranges: ["10.10.0.0/24"]
        }
      })
    });
    assert.equal(policy.response.status, 201);
    assert.equal(policy.body.policy.credential_mode, "reference_only");
    assert.equal(policy.body.policy.read_only, true);

    const imported = await request(baseUrl, "/api/patchforge/discovery/import", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        run_id: "run-london-1",
        collector_id: "collector-london-1",
        policy_id: "policy-london-network",
        discovery_method: "manual_snapshot",
        assets: [{
          asset_id: "disc-fw-juniper-1",
          category: "security_appliance",
          hostname: "srx4100-edge-1",
          vendor_name: "Juniper",
          product_family: "SRX",
          model: "SRX4100",
          firmware_version: "22.4R3",
          internet_facing: true,
          management_exposure: "internal_management",
          enabled_features: ["ipsec_vpn", "ssl_vpn"],
          ip_addresses: ["10.10.0.10"],
          confidence: 0.91
        }, {
          asset_id: "disc-win-phys-1",
          category: "physical_server",
          hostname: "win-hv-01",
          vendor_name: "Microsoft",
          product_family: "Windows Server",
          os_version: "2022",
          enabled_features: ["hyper-v"],
          confidence: 0.8
        }]
      })
    });
    assert.equal(imported.response.status, 202);
    assert.equal(imported.body.run.status, "completed");
    assert.equal(imported.body.run.imported_asset_count, 2);
    assert.equal(imported.body.run.final_approval_issued, false);
    assert.equal(imported.body.boundary.no_exploit_execution, true);
    assert.equal(imported.body.imported_assets[0].review_state, "pending_review");
    assert.equal(imported.body.imported_assets[0].evidence_state, "collector_imported_unreviewed");
    assert.equal(imported.body.imported_assets[0].asset_category, "security_appliance");
    assert.equal(imported.body.imported_assets[0].collector_id, "collector-london-1");
    assert.equal(imported.body.imported_assets[0].collector_policy_id, "policy-london-network");
    assert.equal(imported.body.imported_assets[0].collector_run_id, "run-london-1");
    assert.equal(imported.body.imported_assets[0].final_approval_issued, false);

    const assets = await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(assets.response.status, 200);
    const discoveredFirewall = assets.body.assets.find((asset) => asset.asset_id === "disc-fw-juniper-1");
    assert.equal(discoveredFirewall.discovery_source, "patchforge_collector");
    assert.equal(discoveredFirewall.review_required, true);
    assert.deepEqual(discoveredFirewall.ip_addresses, ["10.10.0.10"]);

    const updatedOverview = await request(baseUrl, "/api/patchforge/discovery/overview", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(updatedOverview.body.discovery.metrics.collector_count, 1);
    assert.equal(updatedOverview.body.discovery.metrics.collector_imported_asset_count, 2);
    assert.equal(updatedOverview.body.discovery.metrics.pending_review_asset_count, 2);

    const rawSecret = await request(baseUrl, "/api/patchforge/discovery/policies", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        collector_id: "collector-london-1",
        name: "Bad policy",
        password: "do-not-store"
      })
    });
    assert.equal(rawSecret.response.status, 400);
    assert.equal(rawSecret.body.error, "raw_secret_rejected");

    await request(baseUrl, "/api/patchforge/discovery/collectors", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        collector_id: "collector-manchester-1",
        name: "Manchester discovery collector",
        platform: "linux",
        site: "Manchester",
        categories: ["network_device"]
      })
    });
    await request(baseUrl, "/api/patchforge/discovery/policies", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        policy_id: "policy-manchester-network",
        collector_id: "collector-manchester-1",
        name: "Manchester network inventory",
        categories: ["network_device"]
      })
    });
    const mismatchedPolicy = await request(baseUrl, "/api/patchforge/discovery/import", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        collector_id: "collector-london-1",
        policy_id: "policy-manchester-network",
        assets: [{
          category: "network_device",
          hostname: "edge-switch-1",
          vendor_name: "Cisco"
        }]
      })
    });
    assert.equal(mismatchedPolicy.response.status, 400);
    assert.equal(mismatchedPolicy.body.error, "policy_collector_mismatch");

    const tenantBAssets = await request(baseUrl, "/api/patchforge/vendorlens/assets", {
      headers: { "x-tenant-id": "tenant-b" }
    });
    assert.equal(tenantBAssets.response.status, 200);
    assert.equal(tenantBAssets.body.assets.some((asset) => asset.asset_id === "disc-fw-juniper-1"), false);
  });
});

test("priority, patch compare, workflow, and action packs remain human approved", async () => {
  await withApi(async (baseUrl) => {
    const priority = await request(baseUrl, "/api/patchforge/priority/index", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        cve_id: "CVE-2026-0001",
        asset_id: "asset-a",
        confirmed_asset_match: true,
        kev: true,
        epss_probability: 0.72,
        cvss_score: 9.8,
        active_exploitation: true,
        internet_exposed: true,
        asset_criticality: "critical",
        patch_available: true,
        patch_maturity: "mature",
        evidence_confidence: 0.9
      })
    });
    assert.equal(priority.response.status, 200);
    assert.equal(priority.body.priority.posture, "Emergency action recommended");
    assert.equal(priority.body.priority.final_approval_issued, false);

    const compare = await request(baseUrl, "/api/patchforge/patch-compare", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        customer_id: "cust-a",
        asset_id: "asset-a",
        cve_id: "CVE-2026-0001",
        severity: "critical",
        kev: true,
        patch_available: true,
        evidence_refs: ["src-nvd-fixture"]
      })
    });
    assert.equal(compare.response.status, 200);
    assert.equal(compare.body.patch_compare_report.options.length, 6);
    assert.equal(compare.body.patch_compare_report.human_change_approval_required, true);
    assert.equal(compare.body.patch_compare_report.no_autonomous_production_approval, true);

    const workflow = await request(baseUrl, "/api/patchforge/workflow/items", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ cve_id: "CVE-2026-0001", asset_id: "asset-a", ciso_review_required: true })
    });
    assert.equal(workflow.response.status, 201);
    assert.equal(workflow.body.workflow_item.ciso_review_required, true);

    const transitioned = await request(baseUrl, `/api/patchforge/workflow/items/${workflow.body.workflow_item.id}/transition`, {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ status: "verified_fixed", owner: "security-lead" })
    });
    assert.equal(transitioned.body.workflow_item.status, "verified_fixed");
    assert.equal(transitioned.body.workflow_item.audit_trail.length, 2);

    const pack = await request(baseUrl, "/api/patchforge/action-packs", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ customer_id: "cust-a", report_type: "CAB Patch Decision Report", evidence_refs: ["src-nvd-fixture"], source_hashes: ["abc123"] })
    });
    assert.equal(pack.response.status, 201);
    assert.equal(pack.body.signed_action_pack.verifier_result.verified, true);
    const verified = await request(baseUrl, `/api/patchforge/action-packs/${pack.body.signed_action_pack.id}/verify`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(verified.body.verifier_result.verified, true);

    const legacyReportsEndpoint = await request(baseUrl, "/api/patchforge/reports", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ report_type: "Security Operations Action Plan" })
    });
    assert.equal(legacyReportsEndpoint.response.status, 404);
    assert.equal(legacyReportsEndpoint.body.error, "not_found");
  });
});

test("Ask PatchForge refuses offensive exploit requests and redirects to defence", async () => {
  await withApi(async (baseUrl) => {
    const answer = await request(baseUrl, "/api/patchforge/ask", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ question: "Can you write exploit code for this CVE?" })
    });
    assert.equal(answer.response.status, 200);
    assert.equal(answer.body.response.refused, true);
    assert.match(answer.body.response.short_answer, /cannot help/i);
    assert.match(answer.body.response.recommended_next_action, /defensive/i);
    assert.doesNotMatch(JSON.stringify(answer.body), /payload details|reverse shell/i);
  });
});

test("public source feeds ingest CISA KEV as source-bound pending-review intelligence", async () => {
  const sourceFeedClient = createSourceFeedClient({
    fetchImpl: async (url) => {
      assert.match(String(url), /known_exploited_vulnerabilities\.json/);
      return jsonResponse({
        catalogVersion: "2026.05.26",
        dateReleased: "2026-05-26T17:02:17Z",
        vulnerabilities: [{
          cveID: "CVE-2026-PF-LIVE-001",
          vendorProject: "Microsoft",
          product: "Example Gateway",
          vulnerabilityName: "Microsoft Example Gateway Authentication Bypass Vulnerability",
          dateAdded: "2026-05-26",
          shortDescription: "Example gateway contains an authentication bypass vulnerability.",
          requiredAction: "Apply mitigations per vendor instructions or discontinue use if mitigations are unavailable.",
          dueDate: "2026-05-29",
          knownRansomwareCampaignUse: "Unknown",
          notes: "https://example.invalid/advisory"
        }]
      });
    }
  });

  await withApi(async (baseUrl) => {
    const list = await request(baseUrl, "/api/patchforge/source-feeds", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(list.response.status, 200);
    assert.ok(list.body.feeds.some((feed) => feed.feed_id === "cisa-kev" && feed.source_bound === true));

    const refresh = await request(baseUrl, "/api/patchforge/source-feeds/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feed_id: "cisa-kev", limit: 1 })
    });
    assert.equal(refresh.response.status, 202);
    assert.equal(refresh.body.source_feed_run.records_ingested, 1);
    assert.equal(refresh.body.source_feed_run.can_close_hard_gates_alone, false);

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-PF-LIVE-001", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.response.status, 200);
    assert.equal(detail.body.vulnerability.known_exploited, true);
    assert.equal(detail.body.vulnerability.review_state, "pending_review");
    assert.equal(detail.body.vulnerability.sources[0].source_class, "kev_record");
    assert.equal(detail.body.vulnerability.usable_evidence_sources.length, 0);

    const landscape = await request(baseUrl, "/api/patchforge/threat-landscape/summary", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(landscape.body.metrics.active_exploitation_count, 1);
  }, { sourceFeedClient });
});

test("FIRST EPSS source feed enriches existing CVEs without approving gates", async () => {
  const sourceFeedClient = createSourceFeedClient({
    fetchImpl: async (url) => {
      assert.match(String(url), /api\.first\.org\/data\/v1\/epss/);
      assert.match(String(url), /CVE-2026-PF-LIVE-002/);
      return jsonResponse({
        status: "OK",
        total: 1,
        data: [{
          cve: "CVE-2026-PF-LIVE-002",
          epss: "0.944320000",
          percentile: "0.999860000",
          date: "2026-05-26"
        }]
      });
    }
  });

  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PF-LIVE-002",
        title: "Existing real queue CVE",
        severity: "high",
        sources: [{ source_record_id: "src-vendor-existing", source_class: "vendor_advisory", source_name: "vendor" }]
      })
    });

    const refresh = await request(baseUrl, "/api/patchforge/source-feeds/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feed_id: "first-epss", cve: "CVE-2026-PF-LIVE-002" })
    });
    assert.equal(refresh.response.status, 202);
    assert.equal(refresh.body.source_feed_run.records_enriched, 1);
    assert.equal(refresh.body.source_feed_run.review_required, true);

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-PF-LIVE-002", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.response.status, 200);
    assert.ok(detail.body.vulnerability.sources.some((source) => source.source_class === "epss_signal"));
    assert.equal(detail.body.vulnerability.usable_evidence_sources.length, 0);

    const blocked = await request(baseUrl, "/api/patchforge/source-feeds/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feed_id: "unknown-feed" })
    });
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "unsupported_source_feed");
  }, { sourceFeedClient });
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
    assert.equal(statusFor(health.body.checks, "MCP agent intake"), "governed");
    assert.equal(statusFor(health.body.checks, "Public source feeds"), "ready");
    assert.notEqual(statusFor(health.body.checks, "Worker health"), "planned");
    assert.notEqual(statusFor(health.body.checks, "Scheduler health"), "planned");

    const blocked = await request(baseUrl, "/api/patchforge/admin/config", {
      method: "PUT",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feature_flags: { azure_mutation_enabled: true } })
    });
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "live_azure_mutation_blocked");
  });
});

test("identical source refresh preserves review while changed content invalidates it", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-source-review-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  let description = "Original reviewed description";
  const sourceFeedClient = createSourceFeedClient({
    fetchImpl: async () => jsonResponse({
      catalogVersion: "test",
      vulnerabilities: [{
        cveID: "CVE-2026-REFRESH-001",
        vendorProject: "Example Vendor",
        product: "Gateway",
        vulnerabilityName: "Reviewed refresh item",
        shortDescription: description,
        dateAdded: "2026-01-01",
        dueDate: "2026-02-01"
      }]
    })
  });
  try {
    await sourceFeedClient.refresh({ storage, tenantId: "tenant-a", body: { feed_id: "cisa-kev", limit: 1 } });
    await storage.reviewVulnerability("tenant-a", "CVE-2026-REFRESH-001", {
      source_record_id: "src-cisa-kev-CVE-2026-REFRESH-001",
      reviewer: "security-lead",
      review_state: "reviewed",
      vulnerability_review_state: "reviewed",
      evidence_state: "accepted_positive_evidence"
    });

    await sourceFeedClient.refresh({ storage, tenantId: "tenant-a", body: { feed_id: "cisa-kev", limit: 1 } });
    const unchanged = await storage.getVulnerability("tenant-a", "CVE-2026-REFRESH-001");
    assert.equal(unchanged.review_state, "reviewed");
    assert.equal(unchanged.sources[0].evidence_state, "accepted_positive_evidence");

    description = "Materially changed upstream description";
    await sourceFeedClient.refresh({ storage, tenantId: "tenant-a", body: { feed_id: "cisa-kev", limit: 1 } });
    const changed = await storage.getVulnerability("tenant-a", "CVE-2026-REFRESH-001");
    assert.equal(changed.review_state, "pending_review");
    assert.equal(changed.sources[0].evidence_state, "referenced");
    assert.equal(changed.sources[0].review_invalidated_reason, "source_payload_changed");
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("server revision hashes prevent replayed client hashes and top-level changes from preserving review", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-source-hash-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await storage.ingestVulnerability("tenant-a", {
      vulnerability_id: "CVE-2026-HASH-001",
      title: "Original title",
      severity: "high",
      kev: true,
      patch_available: true,
      sources: [{
        source_record_id: "src-hash-001",
        source_class: "vendor_advisory",
        source_name: "Vendor",
        source_url: "https://vendor.example/advisory/1",
        payload_hash: "client-controlled-hash"
      }]
    });
    await storage.reviewVulnerability("tenant-a", "CVE-2026-HASH-001", {
      source_record_id: "src-hash-001",
      reviewer: "security-lead",
      review_state: "reviewed",
      vulnerability_review_state: "reviewed",
      evidence_state: "accepted_positive_evidence"
    });

    await storage.ingestVulnerability("tenant-a", {
      vulnerability_id: "CVE-2026-HASH-001",
      title: "Materially changed title",
      severity: "medium",
      kev: false,
      patch_available: false,
      sources: [{
        source_record_id: "src-hash-001",
        source_class: "vendor_advisory",
        source_name: "Vendor",
        source_url: "https://vendor.example/advisory/2",
        payload_hash: "client-controlled-hash"
      }]
    });
    const changed = await storage.getVulnerability("tenant-a", "CVE-2026-HASH-001");
    assert.equal(changed.review_state, "pending_review");
    assert.equal(changed.sources[0].evidence_state, "referenced");
    assert.notEqual(changed.sources[0].payload_hash, "client-controlled-hash");
    assert.equal(changed.kev, false);
    assert.equal(changed.patch_available, false);

    await storage.reviewVulnerability("tenant-a", "CVE-2026-HASH-001", {
      reviewer: "security-lead",
      review_state: "reviewed",
      vulnerability_review_state: "reviewed"
    });
    await storage.ingestVulnerability("tenant-a", {
      vulnerability_id: "CVE-2026-HASH-001",
      severity: "critical"
    });
    const topLevelChanged = await storage.getVulnerability("tenant-a", "CVE-2026-HASH-001");
    assert.equal(topLevelChanged.review_state, "pending_review");
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("admin health marks historical scheduler evidence as stale", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-health-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await withEnv({ PATCHFORGE_SCHEDULER_ENABLED: "true" }, async () => {
      await storage.append("source_feed_runs", {
        tenant_id: "tenant-a",
        run_id: "run-stale-1",
        scheduler_run_id: "scheduler-stale-1",
        feed_id: "cisa-kev",
        status: "completed",
        completed_at: "2000-01-01T00:00:00Z"
      });
      const health = await storage.adminHealth("tenant-a");
      assert.equal(statusFor(health.checks, "Scheduler health"), "stale");
    });
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("manual source refresh history does not prove that the scheduler is configured", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-manual-health-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await withEnv({ PATCHFORGE_SCHEDULER_ENABLED: undefined }, async () => {
      await storage.append("source_feed_runs", {
        tenant_id: "tenant-a",
        run_id: "manual-refresh-1",
        feed_id: "cisa-kev",
        status: "completed",
        completed_at: new Date().toISOString()
      });
      const health = await storage.adminHealth("tenant-a");
      assert.equal(statusFor(health.checks, "Scheduler health"), "pending");
    });
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("admin purge previews and requires typed confirmation before deleting records", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2099-PURGE-001",
        title: "Synthetic purge test",
        severity: "critical",
        sources: [{ source_name: "Synthetic", evidence_state: "accepted_positive_evidence" }]
      })
    });
    const pack = await request(baseUrl, "/api/patchforge/action-packs", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        report: { title: "Synthetic report" },
        selected_scope: { cves: ["CVE-2099-PURGE-001"] },
        source_evidence: [],
        cve_records: [],
        vendor_advisories: [],
        asset_matches: [],
        patch_compare: {},
        confidence: "synthetic",
        evidence_gaps: [],
        human_approval_state: "not_approved"
      })
    });
    assert.equal(pack.response.status, 201);

    const dryRun = await request(baseUrl, "/api/patchforge/admin/purge", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ reports: true, catalogue: true, dry_run: true })
    });
    assert.equal(dryRun.response.status, 200);
    assert.equal(dryRun.body.purge.dry_run, true);
    assert.ok(dryRun.body.purge.total_records >= 2);

    const blocked = await request(baseUrl, "/api/patchforge/admin/purge", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ reports: true, catalogue: true, dry_run: false, confirm: "DELETE CATALOGUE" })
    });
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "typed_confirmation_required");

    const confirmed = await request(baseUrl, "/api/patchforge/admin/purge", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ reports: true, catalogue: true, dry_run: false, confirm: "FACTORY_RESET_PATCHFORGE" })
    });
    assert.equal(confirmed.response.status, 202);
    assert.equal(confirmed.body.purge.dry_run, false);
    assert.equal(confirmed.body.purge.final_approval_issued, false);

    const vulnerabilities = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(vulnerabilities.body.vulnerabilities.length, 0);
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

test("professional decision pack reports export as specific DOCX and PDF decision packs", async () => {
  const sourceFeedClient = createSourceFeedClient({
    fetchImpl: async (url) => {
      assert.match(String(url), /api\.first\.org\/data\/v1\/epss/);
      return jsonResponse({
        status: "OK",
        total: 1,
        data: [{
          cve: "CVE-2026-PF-REPORT-001",
          epss: "0.000300000",
          percentile: "0.030000000",
          date: "2026-05-27"
        }]
      });
    }
  });

  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PF-REPORT-001",
        title: "Real source-bound report target",
        severity: "critical",
        known_exploited: true,
        patch_status: "patch_available",
        sources: [{
          source_record_id: "src-report-vendor-1",
          source_class: "vendor_advisory",
          source_name: "vendor advisory",
          evidence_state: "referenced",
          review_state: "pending_review"
        }]
      })
    });

    const epss = await request(baseUrl, "/api/patchforge/source-feeds/refresh", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({ feed_id: "first-epss", cve: "CVE-2026-PF-REPORT-001" })
    });
    assert.equal(epss.response.status, 202);

    const generated = await request(baseUrl, "/api/patchforge/decision-packs/generate", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PF-REPORT-001",
        requested_posture: "defer_pending_evidence"
      })
    });
    assert.equal(generated.response.status, 201);
    const customerContext = buildReportContext({
      reportType: "customer_patch_governance_pack",
      pack: generated.body.decision_pack
    });
    assert.match(customerContext.recommendation.customer_posture, /Urgent scope confirmation required/i);
    assert.equal(customerContext.finalApprovalIssued, false);
    assert.ok(customerContext.evidenceGapDetails.every((detail) => detail.why_it_matters && detail.required_evidence));
    assert.equal(customerContext.vendor.available, false);
    assert.equal(customerContext.exploitability.known_exploited, true);
    assert.match(customerContext.exploitability.kev_epss_interpretation, /Known exploited signal is present, but EPSS is low/);

    const catalog = await request(baseUrl, "/api/patchforge/reports/catalog", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(catalog.response.status, 200);
    const activeReportTypes = REPORT_CATALOG.map((report) => report.report_type);
    assert.deepEqual(catalog.body.reports.map((report) => report.report_type), activeReportTypes);
    for (const removedReportType of [
      "ciso_executive_risk_brief",
      "security_operations_action_plan",
      "vendor_exposure_report",
      "customer_estate_vulnerability_report",
      "patch_hotfix_decision_pack",
      "emergency_advisory_report",
      "monthly_vulnerability_governance_pack",
      "ciso_patch_version_comparison_report",
      "board_vulnerability_summary"
    ]) {
      assert.ok(!catalog.body.reports.some((report) => report.report_type === removedReportType));
    }

    const docx = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/board_vulnerability_remediation_summary.docx`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(docx.status, 200);
    assert.match(docx.headers.get("content-type"), /wordprocessingml/);
    assert.match(docx.headers.get("x-patchforge-artifact-sha256"), /^[a-f0-9]{64}$/);
    assert.match(docx.headers.get("x-patchforge-export-manifest-id"), /^PF-EXPORT-/);
    assert.equal(docx.headers.get("x-patchforge-export-verified"), "true");
    const boardDocxArtifactId = docx.headers.get("x-patchforge-artifact-id");
    const docxBytes = Buffer.from(await docx.arrayBuffer());
    assert.equal(docxBytes.subarray(0, 2).toString("utf8"), "PK");
    const boardDocxText = await extractDocxText(docxBytes);
    assert.match(boardDocxText, /Report Version Metadata/);
    assert.match(boardDocxText, /report_template_version/);
    assert.match(boardDocxText, /report_renderer_commit/);
    assert.match(boardDocxText, /report_renderer_image_tag/);
    assert.match(boardDocxText, /generated_from_pack_id/);
    assert.match(boardDocxText, /generated_at_utc/);
    assert.match(boardDocxText, /product_baseline/);
    assert.match(boardDocxText, /report_context_version/);
    assert.match(boardDocxText, /source_pack_id/);
    assert.match(boardDocxText, /report_type/);
    assert.match(boardDocxText, /report_audience/);
    assert.match(boardDocxText, /final_approval_issued/);
    assert.match(boardDocxText, /signing_provider/);
    assert.match(boardDocxText, /verification_state/);
    assert.match(boardDocxText, /PF-AZ11-CUSTOMER-DEMO-MATURITY/);
    assert.match(boardDocxText, /PF-TEST-0001/);
    assert.doesNotMatch(boardDocxText, /PF-20260526-8312f908/);
    assert.match(boardDocxText, /Executive Decision Summary/);
    assert.match(boardDocxText, /Top Risks/);
    assert.match(boardDocxText, /Affected Vendors \/ Products/);
    assert.match(boardDocxText, /Customer Exposure/);
    assert.match(boardDocxText, /Recommended Next Actions/);
    assert.match(boardDocxText, /Final approval[^A-Za-z0-9]+Not issued/i);
    assert.doesNotMatch(boardDocxText, new RegExp(["Autonomous", "Analysis", "Completed"].join(" ")));
    assert.doesNotMatch(boardDocxText, /not vulnerable/i);

    const repeatedDocx = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/board_vulnerability_remediation_summary.docx`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(repeatedDocx.status, 200);
    assert.equal(repeatedDocx.headers.get("x-patchforge-artifact-id"), boardDocxArtifactId);
    assert.deepEqual(Buffer.from(await repeatedDocx.arrayBuffer()), docxBytes);

    const docxManifest = await request(baseUrl, `/api/patchforge/decision-packs/PF-TEST-0001/exports/${encodeURIComponent(boardDocxArtifactId)}/manifest`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(docxManifest.response.status, 200);
    assert.equal(docxManifest.body.verification.verified, true);
    assert.equal(docxManifest.body.artifact.sha256, docx.headers.get("x-patchforge-artifact-sha256"));
    assert.equal(docxManifest.body.signed_manifest.artefacts[0].size_bytes, docxBytes.length);
    assert.equal(docxManifest.body.boundary.manifest_does_not_issue_approval, true);
    assert.equal(docxManifest.body.boundary.final_approval_issued, false);

    const pdf = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/board_vulnerability_remediation_summary.pdf`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(pdf.status, 200);
    assert.match(pdf.headers.get("content-type"), /pdf/);
    const pdfBytes = Buffer.from(await pdf.arrayBuffer());
    assert.equal(pdfBytes.subarray(0, 4).toString("utf8"), "%PDF");
    const pdfText = extractPdfText(pdfBytes);
    assert.match(pdfText, /Report Version Metadata/);
    assert.match(pdfText, /report_template_version/);
    assert.match(pdfText, /report_renderer_commit/);
    assert.match(pdfText, /generated_from_pack_id/);
    assert.match(pdfText, /product_baseline/);
    assert.match(pdfText, /Network Vendor Applicability/);
    assert.match(pdfText, /Customer Configuration Context/);

    const customerDocx = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/customer_patch_governance_pack.docx`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(customerDocx.status, 200);
    const customerDocxBytes = Buffer.from(await customerDocx.arrayBuffer());
    assert.equal(customerDocxBytes.subarray(0, 2).toString("utf8"), "PK");
    const customerDocxText = await extractDocxText(customerDocxBytes);
    assert.match(customerDocxText, /Customer Assurance Position/);
    assert.match(customerDocxText, /Report Version Metadata/);
    assert.match(customerDocxText, /generated_from_pack_id/);
    assert.match(customerDocxText, /final_approval_issued/);
    assert.match(customerDocxText, /Customer Device \/ Service Context/);
    assert.match(customerDocxText, /Applicability Assessment/);
    assert.match(customerDocxText, /Matching CVEs \/ Advisories/);
    assert.match(customerDocxText, /Evidence Needed/);
    assert.match(customerDocxText, /Final approval[^A-Za-z0-9]+Not issued/i);
    assert.doesNotMatch(customerDocxText, new RegExp(["Autonomous", "Analysis", "Completed"].join(" ")));
    assert.doesNotMatch(customerDocxText, /not vulnerable/i);

    const customerPdf = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/customer_patch_governance_pack.pdf`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(customerPdf.status, 200);
    const customerPdfBytes = Buffer.from(await customerPdf.arrayBuffer());
    assert.equal(customerPdfBytes.subarray(0, 4).toString("utf8"), "%PDF");
    const customerPdfText = extractPdfText(customerPdfBytes);
    assert.match(customerPdfText, /Evidence Needed/);

    const cabDocx = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/cab_patch_decision_report.docx`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(cabDocx.status, 200);
    const cabDocxText = await extractDocxText(Buffer.from(await cabDocx.arrayBuffer()));
    assert.match(cabDocxText, /Change Decision Request/);
    assert.match(cabDocxText, /Affected Devices/);
    assert.match(cabDocxText, /Patch Applicability/);
    assert.match(cabDocxText, /Patch Compare/);
    assert.match(cabDocxText, /Test \/ Rollback Evidence Needed/);
    assert.match(cabDocxText, /Approval Conditions/);
    assert.match(cabDocxText, /Report Version Metadata/);

    const cabPdf = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/cab_patch_decision_report.pdf`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(cabPdf.status, 200);
    assert.equal(Buffer.from(await cabPdf.arrayBuffer()).subarray(0, 4).toString("utf8"), "%PDF");

    const technicalDocx = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/technical_evidence_appendix.docx`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(technicalDocx.status, 200);
    const technicalDocxText = await extractDocxText(Buffer.from(await technicalDocx.arrayBuffer()));
    assert.match(technicalDocxText, /Technical Evidence Appendix/);
    assert.match(technicalDocxText, /Customer Device \/ Service Context/);
    assert.match(technicalDocxText, /Matching CVEs \/ Advisories/);
    assert.match(technicalDocxText, /Applicability Assessment/);
    assert.match(technicalDocxText, /Patch Compare Result/);
    assert.match(technicalDocxText, /Signed Pack Metadata/);

    const technicalPdf = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/reports/technical_evidence_appendix.pdf`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(technicalPdf.status, 200);
    const technicalPdfBytes = Buffer.from(await technicalPdf.arrayBuffer());
    assert.equal(technicalPdfBytes.subarray(0, 4).toString("utf8"), "%PDF");
    assert.match(extractPdfText(technicalPdfBytes), /Technical Evidence Appendix/);

    const signedZip = await fetch(`${baseUrl}/api/patchforge/decision-packs/PF-TEST-0001/export.zip`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(signedZip.status, 200);
    assert.match(signedZip.headers.get("content-type"), /application\/zip/);
    assert.equal(signedZip.headers.get("x-patchforge-export-verified"), "true");
    const signedZipBytes = Buffer.from(await signedZip.arrayBuffer());
    const signedZipArchive = await JSZip.loadAsync(signedZipBytes);
    const innerManifest = JSON.parse(await signedZipArchive.file("export_content_manifest.json").async("string"));
    assert.equal(innerManifest.pack_id, "PF-TEST-0001");
    assert.equal(innerManifest.final_approval_issued, false);
    assert.equal(innerManifest.human_approval_boundary.manifest_does_not_issue_approval, true);
    assert.ok(signedZipArchive.file("export_content_manifest.sig"));
    assert.ok(signedZipArchive.file("export_content_manifest.sigmeta.json"));
    assert.ok(signedZipArchive.file("export_content_verification.json"));

    const zipManifest = await request(baseUrl, `/api/patchforge/decision-packs/PF-TEST-0001/exports/${encodeURIComponent(signedZip.headers.get("x-patchforge-artifact-id"))}/manifest`, {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(zipManifest.response.status, 200);
    assert.equal(zipManifest.body.verification.byte_integrity_verified, true);
    assert.equal(zipManifest.body.signed_manifest.artefacts[0].sha256, signedZip.headers.get("x-patchforge-artifact-sha256"));

    const unknown = await request(baseUrl, "/api/patchforge/decision-packs/PF-TEST-0001/reports/not-a-report.pdf", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(unknown.response.status, 400);
    assert.equal(unknown.body.error, "unknown_report_type");
    assert.deepEqual(unknown.body.allowed_reports, activeReportTypes);
    for (const removedReportType of [
      "ciso_executive_risk_brief",
      "security_operations_action_plan",
      "vendor_exposure_report",
      "customer_estate_vulnerability_report",
      "patch_hotfix_decision_pack",
      "emergency_advisory_report",
      "monthly_vulnerability_governance_pack",
      "ciso_patch_version_comparison_report",
      "board_vulnerability_summary"
    ]) {
      const removed = await request(baseUrl, `/api/patchforge/decision-packs/PF-TEST-0001/reports/${removedReportType}.pdf`, {
        headers: { "x-tenant-id": "tenant-a" }
      });
      assert.equal(removed.response.status, 400, removedReportType);
      assert.equal(removed.body.error, "unknown_report_type");
      assert.deepEqual(removed.body.allowed_reports, activeReportTypes);
    }
  }, { sourceFeedClient });
});

test("finding intelligence explains queue records in human-readable governance terms", async () => {
  await withApi(async (baseUrl) => {
    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({
        vulnerability_id: "CVE-2026-PF-INTEL-001",
        title: "Customer gateway authentication bypass",
        description: "A customer gateway component can be bypassed under affected conditions.",
        severity: "critical",
        known_exploited: true,
        internet_exposed: true,
        patch_status: "patch_available",
        affected_service_ids: ["svc-gateway"],
        sources: [{
          source_record_id: "src-intel-1",
          source_class: "kev_record",
          source_name: "CISA KEV",
          evidence_state: "referenced",
          review_state: "pending_review"
        }]
      })
    });

    const analysis = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-PF-INTEL-001/analyse", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-a" },
      body: JSON.stringify({})
    });
    assert.equal(analysis.response.status, 200);
    assert.equal(analysis.body.intelligence.vulnerability_id, "CVE-2026-PF-INTEL-001");
    assert.equal(analysis.body.intelligence.boundary.no_exploit_code, true);
    assert.equal(analysis.body.intelligence.boundary.no_patch_deployment, true);
    assert.equal(analysis.body.intelligence.recommendation.posture, "defer_pending_evidence");
    assert.equal(analysis.body.intelligence.recommendation.display_posture, "urgent_scope_confirmation_required");
    assert.match(analysis.body.intelligence.recommendation.customer_posture, /Urgent scope confirmation required/i);
    assert.match(analysis.body.intelligence.summary.plain_english, /governance decision/i);
    assert.match(analysis.body.intelligence.summary.what_it_affects, /customer asset and service exposure are not yet confirmed/i);
    assert.doesNotMatch(analysis.body.intelligence.summary.executive_readout, /enterprise service exposure/i);
    assert.match(analysis.body.intelligence.exploitability.prohibited_detail, /procedural exploitation steps/i);
    assert.ok(analysis.body.intelligence.evidence.gap_details.every((detail) => detail.why_it_matters && detail.required_evidence));
    assert.ok(analysis.body.intelligence.decision_options.every((option) => option.current_status && option.reason));
    assert.equal(analysis.body.intelligence.recommendation.final_approval_issued, false);

    const detail = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-PF-INTEL-001/intelligence", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(detail.response.status, 200);
    assert.ok(detail.body.intelligence.automation.completed.includes("Bound source provenance"));

    const actionCenter = await request(baseUrl, "/api/patchforge/action-center", {
      headers: { "x-tenant-id": "tenant-a" }
    });
    assert.equal(actionCenter.response.status, 200);
    assert.equal(actionCenter.body.findings[0].vulnerability_id, "CVE-2026-PF-INTEL-001");
  });
});

test("scheduler performs real-source refresh without scanner or deployment actions", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-scheduler-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const sourceFeedClient = createSourceFeedClient({
    fetchImpl: async (url) => {
      const text = String(url);
      if (text.includes("known_exploited_vulnerabilities.json")) {
        return jsonResponse({
          catalogVersion: "2026.05.27",
          dateReleased: "2026-05-27T06:00:00Z",
          vulnerabilities: [{
            cveID: "CVE-2026-PF-SCHED-001",
            vendorProject: "Microsoft",
            product: "Example Gateway",
            vulnerabilityName: "Microsoft Example Gateway Source-Bound Vulnerability",
            dateAdded: "2026-05-27",
            shortDescription: "Example source-bound CISA KEV record.",
            requiredAction: "Apply vendor instructions.",
            dueDate: "2026-06-03",
            knownRansomwareCampaignUse: "Unknown"
          }]
        });
      }
      assert.match(text, /api\.first\.org\/data\/v1\/epss/);
      return jsonResponse({
        status: "OK",
        total: 1,
        data: [{
          cve: "CVE-2026-PF-SCHED-001",
          epss: "0.8123",
          percentile: "0.9922",
          date: "2026-05-27"
        }]
      });
    }
  });

  try {
    const result = await runSchedulerOnce({ storage, sourceFeedClient, tenantId: "tenant-a", cisaLimit: 1, epssLimit: 1 });
    assert.equal(result.status, "completed");
    assert.equal(result.boundary.no_scanner, true);
    assert.equal(result.boundary.no_patch_deployment, true);
    assert.equal(result.cisa_run.records_ingested, 1);
    assert.equal(result.epss_runs.length, 1);

    const vulnerabilities = await storage.list("vulnerabilities", "tenant-a");
    assert.equal(vulnerabilities.length, 1);
    assert.equal(vulnerabilities[0].review_state, "pending_review");

    const runs = await storage.list("source_feed_runs", "tenant-a");
    assert.equal(runs.length, 2);
    assert.ok(runs.every((run) => run.source_bound === true && run.can_close_hard_gates_alone === false));
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
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
          "vulnerability_intelligence_snapshot.json": {
            vulnerability_id: payload.vulnerability.vulnerability_id,
            title: payload.vulnerability.title,
            severity: payload.vulnerability.severity,
            known_exploited: payload.vulnerability.known_exploited,
            internet_exposed: payload.vulnerability.internet_exposed,
            patch_status: payload.vulnerability.patch_status,
            sources: payload.vulnerability.sources || []
          },
          "patch_decision_context.json": {
            decision_id: "decision-test-1",
            vulnerability_id: payload.vulnerability.vulnerability_id,
            decision_posture: payload.requested_posture || "defer_pending_evidence",
            evidence_refs: ["src-report-vendor-1"],
            readiness: {
              readiness_state: "blocked",
              readiness_score: 25,
              blockers: ["affected_asset_scope"],
              final_approval_issued: false
            },
            final_approval_issued: false
          },
          "governance_manifest.json": {
            pack_id: "PF-TEST-0001",
            source_pack_immutable: true
          },
          "verification_manifest.json": {
            pack_id: "PF-TEST-0001",
            governance_manifest_sha256: "test-hash"
          },
          "signed_export.sigmeta.json": {
            algorithm: "test",
            signing_provider: "test-signer",
            dev_key_hint: null
          },
          "bayesian_patch_risk_snapshot.json": {
            advisory_only: true,
            can_close_hard_gates_alone: false,
            recommended_governance_posture: payload.requested_posture || "defer_pending_evidence",
            exploit_probability_posterior: 0.44,
            business_impact_posterior: 0.53,
            patch_feasibility_posterior: 0.36,
            change_risk_posterior: 0.42,
            deferral_risk_posterior: 0.49
          },
          "finding_intelligence_snapshot.json": payload.finding_intelligence_snapshot || {
            available: false,
            advisory_only: true,
            human_approval_required: true,
            no_exploit_code: true,
            no_patch_deployment: true
          },
          "vendor_intelligence_snapshot.json": {
            source_bound: true,
            review_required: true,
            available: false
          },
          "threat_landscape_snapshot.json": {
            source_bound: true,
            review_required: true,
            metrics: {
              active_exploitation_count: 1,
              critical_open_advisory_count: 1,
              patch_maturity: "unknown"
            }
          },
          "network_vendor_profile_snapshot.json": payload.network_vendor_profile_snapshot || {
            available: false,
            source_bound: true,
            review_required: true
          },
          "customer_network_asset_snapshot.json": payload.customer_network_asset_snapshot || {
            available: false,
            source_bound: true,
            review_required: true
          },
          "vendor_security_advisory_snapshot.json": payload.vendor_security_advisory_snapshot || {
            available: false,
            source_bound: true,
            review_required: true
          },
          "config_applicability_assessment.json": payload.config_applicability_assessment || {
            available: false,
            advisory_only: true,
            human_review_required: true,
            final_approval_issued: false
          },
          "vendorlens_patch_comparison.json": payload.vendorlens_patch_comparison || {
            available: false,
            advisory_only: true,
            human_review_required: true,
            final_approval_issued: false,
            no_patch_deployment: true
          },
          "sra_config_chat_session.json": payload.sra_config_chat_session || {
            available: false,
            advisory_only: true,
            human_review_required: true,
            final_approval_issued: false
          },
          "vendorlens_decision_context.json": payload.vendorlens_decision_context || {
            available: false,
            advisory_only: true,
            human_review_required: true,
            final_approval_issued: false
          },
          "human_review_state.json": {
            final_approval_issued: false
          },
          "sra_trace.json": {
            advisory_only: true,
            can_close_hard_gates_alone: false
          }
        },
        boundary: { no_patch_deployment: true, no_exploit_generation: true }
      };
    },
    async createExportManifest(payload) {
      const artefacts = [...payload.artefacts].sort((left, right) => left.name.localeCompare(right.name));
      const unsigned = {
        manifest_version: "patchforge-export-manifest-v1",
        tenant_id: payload.tenant_id,
        pack_id: payload.pack_id,
        governance_manifest_sha256: payload.governance_manifest_sha256,
        artefact_count: artefacts.length,
        artefacts,
        source_pack_immutable: true,
        final_approval_issued: Boolean(payload.final_approval_issued),
        human_approval_boundary: {
          state_preserved_from_source_pack: true,
          no_autonomous_approval: true,
          manifest_does_not_issue_approval: true,
          human_review_required_when_not_approved: !payload.final_approval_issued
        },
        created_at: payload.created_at
      };
      const manifest = {
        manifest_id: `PF-EXPORT-${testSha256(testCanonicalJson(unsigned)).slice(0, 20)}`,
        ...unsigned
      };
      const manifestSha256 = testSha256(testCanonicalJson(manifest));
      const signedPayload = {
        manifest_id: manifest.manifest_id,
        manifest_sha256: manifestSha256,
        pack_id: payload.pack_id,
        governance_manifest_sha256: payload.governance_manifest_sha256
      };
      return {
        manifest,
        manifest_sha256: manifestSha256,
        signature: testSha256(testCanonicalJson(signedPayload)),
        signature_metadata: { algorithm: "test_sha256", key_id: "test", signed_payload: signedPayload, dev_key_hint: null },
        verification: { verified: true, manifest_ok: true, signature_ok: true, artefact_descriptors_ok: true }
      };
    }
  };
}

function jsonResponse(body, status = 200) {
  const bytes = Buffer.from(JSON.stringify(body));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => String(name).toLowerCase() === "content-length" ? String(bytes.length) : null },
    async arrayBuffer() {
      return bytes;
    },
    async json() {
      return body;
    }
  };
}

function testCanonicalJson(value) {
  return JSON.stringify(testSortValue(value));
}

function testSortValue(value) {
  if (Array.isArray(value)) return value.map(testSortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, testSortValue(nested)]));
  }
  return value;
}

function testSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function extractDocxText(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const documentXml = await zip.file("word/document.xml").async("string");
  return documentXml
    .replace(/<w:tab\/>/g, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractPdfText(buffer) {
  const raw = buffer.toString("latin1");
  return [...raw.matchAll(/<([0-9A-Fa-f]+)>/g)]
    .map((match) => Buffer.from(match[1], "hex").toString("utf8"))
    .join("");
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

test("triage role cannot use a signed-pack generation alias", async () => {
  await withAuthenticatedApi(async (baseUrl) => {
    const forbidden = await request(baseUrl, "/api/patchforge/reports/generate", {
      method: "POST",
      headers: { authorization: "Bearer triage" },
      body: JSON.stringify({ vulnerability_id: "CVE-2026-FORGED-PACK-001" })
    });
    assert.equal(forbidden.response.status, 403);
    assert.equal(forbidden.body.error, "insufficient_patchforge_role");
  }, async () => ({
    roles: ["PatchForge.TriageAnalyst"],
    tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    oid: "triage-oid",
    upn: "triage@diiac.io"
}));
});

test("finding evidence API requires exact immutable content and an accountable class reviewer", async () => {
  await withAuthenticatedApi(async (baseUrl) => {
    const ingested = await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ vulnerability_id: "CVE-2026-EVIDENCE-API-001", title: "Evidence API finding" })
    });
    assert.equal(ingested.response.status, 201);

    const submitted = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({
        evidence_class: "patch_feasibility",
        summary: "Pre-production validation completed.",
        evidence: { test_run_id: "run-42", outcome: "passed" }
      })
    });
    assert.equal(submitted.response.status, 201);
    assert.equal(submitted.body.evidence.server_owned, true);
    assert.equal(submitted.body.evidence.final_approval_issued, false);

    const invalidExpiry = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ evidence_class: "test_evidence", summary: "Invalid expiry.", expires_at: "2026-07-13 09:00:00" })
    });
    assert.equal(invalidExpiry.response.status, 400);
    assert.equal(invalidExpiry.body.error, "evidence_expiry_invalid");

    const forbidden = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/review`, {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ decision: "accept", expected_content_hash: submitted.body.evidence.content_hash })
    });
    assert.equal(forbidden.response.status, 403);

    const reviewed = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/review`, {
      method: "POST",
      headers: { authorization: "Bearer service-owner" },
      body: JSON.stringify({ decision: "accept", expected_content_hash: submitted.body.evidence.content_hash, rationale: "Reviewed against test run." })
    });
    assert.equal(reviewed.response.status, 200);
    assert.equal(reviewed.body.evidence.review.server_verified, true);
    assert.equal(reviewed.body.evidence.evidence_state, "accepted_positive_evidence");
    assert.equal(reviewed.body.final_approval_issued, false);

    const staleReopen = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/reopen`, {
      method: "POST",
      headers: { authorization: "Bearer service-owner" },
      body: JSON.stringify({
        expected_content_hash: submitted.body.evidence.content_hash,
        expected_event_hash: "stale-event-hash",
        rationale: "Evidence must be repeated."
      })
    });
    assert.equal(staleReopen.response.status, 409);
    assert.equal(staleReopen.body.error, "evidence_event_conflict");

    const forbiddenReopen = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/reopen`, {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({
        expected_content_hash: submitted.body.evidence.content_hash,
        expected_event_hash: reviewed.body.evidence_event.event_hash,
        rationale: "Unauthorized reopen."
      })
    });
    assert.equal(forbiddenReopen.response.status, 403);

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ vulnerability_id: "CVE-2026-EVIDENCE-API-OTHER", title: "Other finding" })
    });
    const crossFinding = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-OTHER/evidence/${submitted.body.evidence.evidence_id}/reopen`, {
      method: "POST",
      headers: { authorization: "Bearer service-owner" },
      body: JSON.stringify({
        expected_content_hash: submitted.body.evidence.content_hash,
        expected_event_hash: reviewed.body.evidence_event.event_hash,
        rationale: "Wrong finding."
      })
    });
    assert.equal(crossFinding.response.status, 409);
    assert.equal(crossFinding.body.error, "finding_evidence_scope_mismatch");

    const reopened = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/reopen`, {
      method: "POST",
      headers: { authorization: "Bearer service-owner" },
      body: JSON.stringify({
        expected_content_hash: submitted.body.evidence.content_hash,
        expected_event_hash: reviewed.body.evidence_event.event_hash,
        rationale: "Test environment changed; rerun required."
      })
    });
    assert.equal(reopened.response.status, 200);
    assert.equal(reopened.body.evidence.review_state, "reopened");
    assert.equal(reopened.body.evidence.evidence_state, "referenced");
    assert.equal(reopened.body.evidence_event.previous_event_hash, reviewed.body.evidence_event.event_hash);
    assert.equal(reopened.body.final_approval_issued, false);

    const listed = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence", {
      headers: { authorization: "Bearer reader" }
    });
    assert.equal(listed.response.status, 200);
    assert.equal(listed.body.evidence.length, 1);
    assert.equal(listed.body.boundary.exact_finding_scope, true);
    assert.equal(listed.body.evidence_events.length, 2);
    assert.equal(listed.body.audit_replay[0].replay_verified, true);
    assert.equal(listed.body.audit_replay[0].event_count, 2);

    await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ vulnerability_id: "CVE-2026-EVIDENCE-API-001", title: "Evidence API finding changed" })
    });
    const changedRevision = await request(baseUrl, `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${submitted.body.evidence.evidence_id}/review`, {
      method: "POST",
      headers: { authorization: "Bearer service-owner" },
      body: JSON.stringify({
        decision: "accept",
        expected_content_hash: submitted.body.evidence.content_hash,
        expected_event_hash: reopened.body.evidence_event.event_hash
      })
    });
    assert.equal(changedRevision.response.status, 409);
    assert.equal(changedRevision.body.error, "finding_revision_changed");

    const concurrentEvidence = await request(baseUrl, "/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence", {
      method: "POST",
      headers: { authorization: "Bearer submitter" },
      body: JSON.stringify({ evidence_class: "test_evidence", summary: "Concurrent review evidence." })
    });
    assert.equal(concurrentEvidence.response.status, 201);
    const reviewPath = `/api/patchforge/vulnerabilities/CVE-2026-EVIDENCE-API-001/evidence/${concurrentEvidence.body.evidence.evidence_id}/review`;
    const concurrentResults = await Promise.all([
      request(baseUrl, reviewPath, {
        method: "POST",
        headers: { authorization: "Bearer service-owner" },
        body: JSON.stringify({ decision: "accept", expected_content_hash: concurrentEvidence.body.evidence.content_hash })
      }),
      request(baseUrl, reviewPath, {
        method: "POST",
        headers: { authorization: "Bearer service-owner" },
        body: JSON.stringify({ decision: "reject", expected_content_hash: concurrentEvidence.body.evidence.content_hash })
      })
    ]);
    assert.deepEqual(concurrentResults.map((result) => result.response.status).sort(), [200, 409]);
    assert.ok(["evidence_event_conflict", "evidence_review_conflict"].includes(concurrentResults.find((result) => result.response.status === 409).body.error));
  }, async (token) => {
    const common = { tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da" };
    if (token === "submitter") return { ...common, oid: "submitter-1", upn: "submitter@diiac.io", roles: ["PatchForge.TriageAnalyst"] };
    if (token === "service-owner") return { ...common, oid: "service-owner-1", upn: "owner@diiac.io", roles: ["PatchForge.ServiceOwner"] };
    return { ...common, oid: "reader-1", upn: "reader@diiac.io", roles: ["PatchForge.Reader"] };
  });
});

test("auth config accepts both API identifier URI and API client ID audiences", () => {
  const config = createAuthConfigFromEnv();
  assert.ok(config.audiences.includes("api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736"));
  assert.ok(config.audiences.includes("ec30b0eb-cfc4-48cc-a5f2-2a1345d96736"));
});

test("production auth fails closed when auth is not explicitly required", async () => {
  await withEnv({ PATCHFORGE_ENV: "production", PATCHFORGE_AUTH_REQUIRED: "false", NODE_ENV: undefined }, async () => {
    assert.throws(() => createAuthConfigFromEnv(), /production startup blocked/i);
  });
});

test("production tenant context ignores normal user header override and records lineage", async () => {
  await withAuthenticatedApi(async (baseUrl) => {
    const ingest = await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-b", authorization: "Bearer triage" },
      body: JSON.stringify({ vulnerability_id: "REAL-TENANT-1", title: "Tenant guarded record" })
    });
    assert.equal(ingest.response.status, 201);
    assert.equal(ingest.body.vulnerability.tenant_id, "diiac.io");
    assert.equal(ingest.body.vulnerability.requested_tenant_id, "tenant-b");
    assert.equal(ingest.body.vulnerability.tenant_override_ignored, true);
    assert.equal(ingest.body.vulnerability.actor_upn, "triage@diiac.io");

    const tenantB = await request(baseUrl, "/api/patchforge/vulnerabilities", {
      headers: { "x-tenant-id": "tenant-b", authorization: "Bearer reader" }
    });
    assert.equal(tenantB.body.tenant_id, "diiac.io");
    assert.equal(tenantB.body.vulnerabilities.length, 1);
  }, async (token) => {
    if (token === "triage") {
      return { roles: ["PatchForge.TriageAnalyst"], tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da", oid: "triage-oid", upn: "triage@diiac.io" };
    }
    return { roles: ["PatchForge.Reader"], tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da", oid: "reader-oid", upn: "reader@diiac.io" };
  }, { production: true, allowTenantOverride: false, adminDiagnosticTenantOverride: false });
});

test("admin diagnostic tenant override works only when explicitly enabled", async () => {
  await withAuthenticatedApi(async (baseUrl) => {
    const ingest = await request(baseUrl, "/api/patchforge/vulnerabilities/ingest", {
      method: "POST",
      headers: { "x-tenant-id": "tenant-diagnostic", authorization: "Bearer admin" },
      body: JSON.stringify({ vulnerability_id: "REAL-DIAG-1" })
    });
    assert.equal(ingest.response.status, 201);
    assert.equal(ingest.body.vulnerability.tenant_id, "tenant-diagnostic");
    assert.equal(ingest.body.vulnerability.tenant_id_source, "admin_diagnostic_override");
    assert.equal(ingest.body.vulnerability.tenant_override_ignored, false);
  }, async () => ({
    roles: ["PatchForge.Admin"],
    tid: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    oid: "admin-oid",
    upn: "admin@diiac.io"
  }), { production: true, allowTenantOverride: true, adminDiagnosticTenantOverride: true });
});

test("malformed JSON bodies return 400 invalid_json, not 500", async () => {
  await withApi(async (baseUrl) => {
    const response = await fetch(`${baseUrl}/api/patchforge/vulnerabilities/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{ this is not valid json"
    });
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.equal(body.error, "invalid_json");
  });
});

test("oversized request bodies are rejected with 413 before processing", async () => {
  await withApi(async (baseUrl) => {
    const oversized = JSON.stringify({ filler: "x".repeat(2 * 1024 * 1024 + 16) });
    const response = await fetch(`${baseUrl}/api/patchforge/vulnerabilities/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: oversized
    });
    const body = await response.json();
    assert.equal(response.status, 413);
    assert.equal(body.error, "request_body_too_large");
  });
});

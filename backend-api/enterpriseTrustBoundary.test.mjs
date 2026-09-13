import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "./server.js";
import { PatchForgeJsonStorage } from "./patchforge/storage.js";
import { buildPriorityIndex, buildSignedActionPack, comparePatchActions, verifySignedActionPack } from "./patchforge/priority.js";

const BASE_DECISION = { cve_id: "CVE-2026-1234", asset_id: "asset-1", evidence_confidence: 1 };
const FALSE_VALUES = [false, 0, "false", " FALSE ", "0", "no", "off", "", null, [], ["known"], ["true"], [1], {}, Number.NaN];
const TRUE_VALUES = [true, 1, "true", " TRUE ", "1", "yes", "on"];

function legacyPack(payload = { action: "human_review_required", final_approval_issued: false }) {
  const sourceHashes = ["legacy-source-hash"];
  const hash = createHash("sha256").update(JSON.stringify({ payload, source_hashes: sourceHashes })).digest("hex");
  return {
    id: "legacy-pack-1",
    tenant_id: "tenant-a",
    payload,
    source_hashes: sourceHashes,
    pack_hash: hash,
    signature: `test-digest:${hash}`,
    verifier_result: { verified: true, signature_ok: true },
    replay_metadata: { replayable: true }
  };
}

test("auxiliary pack helpers never equate a recomputable digest with signature authenticity", () => {
  assert.throws(() => buildSignedActionPack({}), { publicError: "action_pack_issuance_unavailable", statusCode: 410 });
  const original = legacyPack();
  const checked = verifySignedActionPack(original);
  assert.equal(checked.integrity_ok, true);
  assert.equal(checked.verified, false);
  assert.equal(checked.signature_ok, false);
  assert.equal(checked.replayable, false);
  assert.equal(verifySignedActionPack({ ...original, payload: { action: "tampered" } }).integrity_ok, false);
  const forged = verifySignedActionPack(legacyPack({ action: "forged", final_approval_issued: true }));
  assert.equal(forged.integrity_ok, true, "any caller can recompute the historical digest");
  assert.equal(forged.verified, false);
  assert.equal(forged.signature_ok, false);
});

test("priority and comparison reject false-like flags without suppressing affirmative aliases", () => {
  const flaggedFields = ["confirmed_asset_match", "kev", "known_exploited", "cisa_kev", "active_exploitation", "exploit_signal", "internet_exposed", "sla_pressure", "patch_available", "workaround_available", "compensating_controls", "production_impacting", "defer", "accepted_risk", "ransomware_association"];
  const baseline = buildPriorityIndex(BASE_DECISION);
  const baselineComparison = comparePatchActions(BASE_DECISION);
  for (const value of FALSE_VALUES) {
    const input = { ...BASE_DECISION, ...Object.fromEntries(flaggedFields.map((field) => [field, value])) };
    const priority = buildPriorityIndex(input);
    assert.equal(priority.priority_score, baseline.priority_score, `false-like flag ${JSON.stringify(value)} must not affect score`);
    assert.deepEqual(priority.explainability, baseline.explainability);
    const comparison = comparePatchActions(input);
    assert.equal(comparison.selected_candidate, baselineComparison.selected_candidate);
    assert.deepEqual(comparison.options.map(optionValues), baselineComparison.options.map(optionValues));
  }
  for (const value of TRUE_VALUES) {
    const priority = buildPriorityIndex({ ...BASE_DECISION, kev: "false", known_exploited: value, active_exploitation: "false", exploit_signal: value });
    assert.equal(priority.priority_score, 33);
    assert.equal(comparePatchActions({ ...BASE_DECISION, defer: "false", accepted_risk: value }).selected_candidate, "defer_with_exception");
    assert.equal(buildPriorityIndex({ ...BASE_DECISION, confirmed_asset_match: true, workaround_available: "false", compensating_controls: value }).priority_score, 8);
  }
  assert.equal(buildPriorityIndex({ ...BASE_DECISION, ransomware_association: "known" }).priority_score, 10);
});

function optionValues(option) {
  return { ciso_approval_required: option.ciso_approval_required, risk_reduction: option.risk_reduction, service_impact: option.service_impact };
}

test("retired issuance preserves authorization and historical inspection never returns stored trust flags", async () => {
  await withApi(async ({ request, storage }) => {
    assert.equal((await request("/action-packs", "POST", {}, null)).status, 401);
    assert.equal((await request("/action-packs", "POST", {}, "triage-a")).status, 403);
    const unavailable = await request("/action-packs", "POST", {}, "security-a");
    assert.equal(unavailable.status, 410);
    assert.equal(unavailable.body.decision_pack_endpoint, "/api/patchforge/decision-packs/generate");
    assert.equal(unavailable.body.verified, false);
    assert.equal((await storage.list("signed_action_packs", "tenant-a")).length, 0);
    const stored = { ...legacyPack({ action: "legacy", final_approval_issued: true }), verified: true, signature_ok: true, final_approval_issued: true };
    await storage.append("signed_action_packs", stored);
    const checked = await request(`/action-packs/${stored.id}/verify`, "GET", undefined, "reader-a");
    assert.equal(checked.status, 200);
    assert.equal(checked.body.verifier_result.integrity_ok, true);
    assert.equal(checked.body.verifier_result.verified, false);
    assert.equal(checked.body.signed_action_pack.verifier_result.verified, false);
    assert.equal(checked.body.signed_action_pack.verifier_result.signature_ok, false);
    assert.equal(checked.body.signed_action_pack.signature_ok, false);
    assert.equal(checked.body.signed_action_pack.final_approval_issued, false);
    assert.equal(checked.body.signed_action_pack.legacy_content_untrusted, true);
    assert.deepEqual(checked.body.signed_action_pack.payload, stored.payload, "preserve historical payload for honest digest inspection; its approval claim is untrusted");
    assert.equal(checked.body.signed_action_pack.replay_metadata.replayable, false);
    assert.equal((await request(`/action-packs/${stored.id}/verify`, "GET", undefined, "reader-b")).status, 404);
    assert.deepEqual((await storage.list("signed_action_packs", "tenant-a"))[0], stored, "inspection must not rewrite historical evidence");
  });
});

test("workflow IDs and review states cannot bypass role or tenant boundaries", async () => {
  await withApi(async ({ request, storage }) => {
    for (const status of ["approved", "accepted_risk", "verified_fixed", "change_authorised", "custom-state", "", true]) {
      const rejected = await request("/workflow/items", "POST", { status }, "triage-a");
      assert.equal(rejected.status, 400);
      assert.equal(rejected.body.error, "unsupported_workflow_status");
    }
    assert.equal((await storage.list("workflow_items", "tenant-a")).length, 0);
    const created = await request("/workflow/items", "POST", {
      id: "caller-controlled-id", tenant_id: "tenant-b", ciso_review_required: "false", ciso_approval_required: "no",
      actor_oid: "spoofed", actor_upn: "spoofed@example.com", actor_roles: ["PatchForge.Admin"],
      audit_trail: [{ event: "approved" }], final_approval_issued: true
    }, "triage-a");
    assert.equal(created.status, 201);
    const item = created.body.workflow_item;
    assert.notEqual(item.id, "caller-controlled-id");
    assert.equal(item.tenant_id, "tenant-a");
    assert.equal(item.status, "triage");
    assert.equal(item.ciso_review_required, false);
    assert.equal(item.final_approval_issued, false);
    assert.equal(item.actor_oid, "triage-a");
    assert.equal(item.audit_trail[0].actor, "triage-a@example.com");
    const duplicate = await request("/workflow/items", "POST", { id: item.id, status: "ciso_review_required" }, "triage-a");
    assert.equal(duplicate.status, 201);
    assert.notEqual(duplicate.body.workflow_item.id, item.id);
    assert.equal((await storage.list("workflow_items", "tenant-a")).find(row => row.id === item.id).status, "triage");
    assert.equal((await request(`/workflow/items/${item.id}/transition`, "POST", { status: "ciso_review_required" }, "triage-a")).status, 403);
    assert.equal((await request(`/workflow/items/${item.id}/transition`, "POST", { status: "ciso_review_required" }, "security-b")).status, 404);
    for (const status of ["approved", "accepted_risk", "verified_fixed", "custom-state"]) {
      assert.equal((await request(`/workflow/items/${item.id}/transition`, "POST", { status }, "security-a")).status, 400);
    }
    const transitioned = await request(`/workflow/items/${item.id}/transition`, "POST", { status: "ciso_review_required", actor_upn: "spoofed" }, "security-a");
    assert.equal(transitioned.status, 200);
    assert.equal(transitioned.body.workflow_item.status, "ciso_review_required");
    assert.equal(transitioned.body.workflow_item.audit_trail.length, 2);
    assert.equal(transitioned.body.workflow_item.audit_trail[1].actor, "security-a@example.com");
    const returned = await request(`/workflow/items/${item.id}/transition`, "POST", { status: "triage" }, "security-a");
    assert.equal(returned.status, 200);
    assert.equal(returned.body.workflow_item.status, "triage");
    assert.equal(returned.body.workflow_item.final_approval_issued, false);
    const events = await storage.list("audit_events", "tenant-a");
    assert.equal(events.filter(event => event.event_type === "workflow_item_transitioned").length, 2);
    assert.equal(events.find(event => event.event_type === "workflow_item_created").details.actor_oid, "triage-a");
    assert.equal((await storage.list("workflow_items", "tenant-b")).length, 0);
  });
});

test("priority HTTP and patch comparison boundaries use semantic flags", async () => {
  await withApi(async ({ request }) => {
    const priority = await request("/priority/index", "POST", { ...BASE_DECISION, kev: "false", internet_exposed: "off", patch_available: "no" });
    assert.equal(priority.status, 200);
    assert.equal(priority.body.priority.priority_score, 0);
    const aliases = await request("/priority/index", "POST", { ...BASE_DECISION, kev: "false", known_exploited: "yes", active_exploitation: "no", exploit_signal: "true" });
    assert.equal(aliases.body.priority.priority_score, 33);
    const comparison = await request("/patch-compare", "POST", { ...BASE_DECISION, defer: "false", accepted_risk: "off", patch_available: "yes" });
    assert.equal(comparison.status, 200);
    assert.notEqual(comparison.body.patch_compare_report.selected_candidate, "defer_with_exception");
  });
});

async function withApi(run) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-enterprise-trust-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  const server = createServer({
    storage,
    auth: {
      required: true,
      production: true,
      defaultTenant: "tenant-a",
      tenantMappings: { "directory-a": "tenant-a", "directory-b": "tenant-b" },
      verifier: async token => {
        const [role, tenant] = token.split("-");
        const roles = { triage: "PatchForge.TriageAnalyst", security: "PatchForge.SecurityLead", reader: "PatchForge.Reader" };
        return { oid: token, upn: `${token}@example.com`, tid: `directory-${tenant}`, roles: [roles[role]] };
      }
    }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}/api/patchforge`;
  try {
    await run({ storage, request: async (route, method = "GET", body, token = "security-a") => {
      const response = await fetch(`${baseUrl}${route}`, {
        method,
        headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      return { status: response.status, body: await response.json() };
    } });
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
}

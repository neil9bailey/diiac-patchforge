import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { PatchForgeJsonStorage } from "./storage.js";
import {
  buildAskPatchForgeResponse,
  buildSecurityActionCenterIndex,
  extractCustomerAssetDescription,
  matchCustomerEstate,
  searchSecurityActionCenterIndex,
  summarizePatchComparison
} from "./searchIndex.js";
import { compareAndStorePatchVersion, ingestVendorSecurityAdvisory, upsertCustomerNetworkAsset } from "./vendorLens.js";

const TENANT = "tenant-a";

async function withStorage(run) {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-search-index-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await seed(storage);
    await run(storage);
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
}

async function seed(storage) {
  await storage.ensureReady();
  await ingestVendorSecurityAdvisory(storage, TENANT, {
    advisory_id: "FG-2026-SSLVPN",
    vendor_id: "fortinet",
    vendor_name: "Fortinet",
    cve: "CVE-2026-10001",
    title: "FortiOS SSL-VPN source-bound advisory",
    severity: "critical",
    product_family: "FortiGate",
    affected_versions: ["< 7.2.8"],
    fixed_versions: ["7.2.8"],
    affected_features: ["SSL-VPN"],
    known_exploited: true,
    patch_available: true,
    epss_score: 0.91,
    source_feed: "nvd-cve-2-catalogue",
    source_url: "https://example.invalid/fortinet"
  });
  await ingestVendorSecurityAdvisory(storage, TENANT, {
    advisory_id: "CISCO-ASA-ANYCONNECT",
    vendor_id: "cisco",
    vendor_name: "Cisco",
    cve: "CVE-2026-20002",
    title: "Cisco ASA AnyConnect advisory",
    severity: "high",
    product_family: "Cisco ASA",
    affected_versions: ["9.18.x"],
    affected_features: ["AnyConnect"],
    known_exploited: false,
    patch_available: false,
    epss_score: 0.42
  });
  await upsertCustomerNetworkAsset(storage, TENANT, {
    asset_id: "fw-100f",
    vendor_id: "fortinet",
    product_family: "FortiGate",
    model: "100F",
    firmware_version: "7.2.7",
    internet_facing: false,
    management_exposure: "internal",
    enabled_features: ["ipsec_vpn"],
    disabled_features: ["ssl_vpn"],
    review_state: "pending_review",
    evidence_state: "user_stated_unreviewed"
  });
}

test("security action center search covers CVE, vendor, product, feature, firmware, filters, and grouping", async () => {
  await withStorage(async (storage) => {
    await matchCustomerEstate({ storage, tenantId: TENANT, body: { asset_id: "fw-100f" } });
    const index = await buildSecurityActionCenterIndex({ storage, tenantId: TENANT });

    assert.ok(index.catalogue_rows.some((row) => row.cve_id === "CVE-2026-10001"));
    assert.equal(searchSecurityActionCenterIndex(index, { query: "CVE-2026-10001" }).count, 1);
    assert.equal(searchSecurityActionCenterIndex(index, { query: "Fortinet" }).catalogue_rows[0].vendor_name, "Fortinet");
    assert.ok(searchSecurityActionCenterIndex(index, { query: "FortiGate" }).catalogue_rows.some((row) => row.product_family === "FortiGate"));
    assert.ok(searchSecurityActionCenterIndex(index, { query: "SSL-VPN" }).catalogue_rows.some((row) => row.affected_feature === "SSL-VPN"));
    assert.ok(searchSecurityActionCenterIndex(index, { query: "7.2.7" }).catalogue_rows.some((row) => row.customer_match_count > 0));

    assert.equal(searchSecurityActionCenterIndex(index, { severity: "critical" }).catalogue_rows.length, 1);
    assert.equal(searchSecurityActionCenterIndex(index, { kev: "true" }).catalogue_rows[0].cve_id, "CVE-2026-10001");
    assert.equal(searchSecurityActionCenterIndex(index, { patch_available: "true" }).catalogue_rows[0].advisory_id, "FG-2026-SSLVPN");
    assert.equal(searchSecurityActionCenterIndex(index, { customer_match: "true" }).catalogue_rows[0].customer_match_count, 1);

    const fortinetGroup = index.groups.find((group) => group.vendor_name === "Fortinet");
    assert.ok(fortinetGroup);
    assert.ok(fortinetGroup.product_families.some((group) => group.product_family === "FortiGate"));
  });
});

test("customer estate extraction, matching, advisor, and patch compare remain advisory-only", async () => {
  await withStorage(async (storage) => {
    const extracted = extractCustomerAssetDescription("FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only.");
    assert.equal(extracted.vendor_id, "fortinet");
    assert.equal(extracted.model, "100F");
    assert.equal(extracted.firmware_version, "7.2.7");
    assert.deepEqual(extracted.disabled_features, ["ssl_vpn"]);
    assert.equal(extracted.evidence_state, "user_stated_unreviewed");

    const match = await matchCustomerEstate({ storage, tenantId: TENANT, body: { asset: { ...extracted, asset_id: "extracted-fw" } }, persist: false });
    assert.equal(match.final_approval_issued, false);
    assert.ok(match.matches.some((item) => item.cve === "CVE-2026-10001"));

    const answer = await buildAskPatchForgeResponse({
      storage,
      tenantId: TENANT,
      body: { question: "We use FortiGate 100F FortiOS 7.2.7 with SSL-VPN disabled. Does CVE-2026-10001 require urgent patching?" }
    });
    assert.equal(answer.response.final_approval_issued, false);
    assert.equal(answer.response.human_approval_required, true);
    assert.match(answer.response.decision_not_allowed_yet, /cannot issue final approval/i);
    assert.doesNotMatch(JSON.stringify(answer), /exploit instructions|procedural exploit|deploy patch/i);

    const comparison = await compareAndStorePatchVersion(storage, TENANT, {
      asset_id: "fw-100f",
      advisory_id: "FG-2026-SSLVPN",
      current_version: "7.2.7",
      target_version: "7.2.8"
    });
    const summary = summarizePatchComparison(comparison, {});
    assert.equal(summary.current_version_affected, "affected");
    assert.equal(summary.proposed_version_remediates, "unknown");
    assert.equal(summary.final_approval_issued, false);
    assert.equal(summary.no_patch_deployment, true);
  });
});

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { importDiscoveredAssets } from "./assetDiscovery.js";
import { PatchForgeJsonStorage } from "./storage.js";

const TENANT = "tenant-exposure";

// False-like, blank, absent, and structured values must never mark an asset exposed.
const FALSE_LIKE = [
  false,
  0,
  "false",
  "0",
  "no",
  "off",
  "",
  null,
  undefined,
  [],
  {},
  ["true"],
  { value: true },
  Number.NaN
];

test("discovery import boundary: only affirmative values may mark an asset internet-facing", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-discovery-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    // Register the collector the import expects.
    await storage.append("asset_collectors", {
      tenant_id: TENANT,
      collector_id: "collector-x",
      name: "Boundary test collector",
      enabled_categories: ["security_appliance", "network_device"],
      revoked: false
    });

    const assets = FALSE_LIKE.map((value, i) => ({
      asset_id: `asset-false-${i}`,
      category: "security_appliance",
      hostname: `edge-false-${i}`,
      vendor_name: "Example Vendor",
      product_family: "SRX",
      internet_facing: value
    }));

    const result = await importDiscoveredAssets(storage, TENANT, {
      collector_id: "collector-x",
      run_id: "run-exposure-false-1",
      discovery_method: "http_json",
      assets
    });

    assert.equal(result.imported_assets.length, assets.length);
    for (const asset of result.imported_assets) {
      assert.equal(
        asset.internet_facing,
        false,
        `expected ${asset.hostname} (input ${JSON.stringify(FALSE_LIKE[Number(asset.asset_id.split("-").pop())])}) to stay not exposed`
      );
    }

    // Affirmative values remain true.
    const affirmative = await importDiscoveredAssets(storage, TENANT, {
      collector_id: "collector-x",
      run_id: "run-exposure-true-1",
      discovery_method: "http_json",
      assets: [{
        asset_id: "asset-true-1",
        category: "security_appliance",
        hostname: "edge-true-1",
        vendor_name: "Example Vendor",
        product_family: "SRX",
        internet_facing: true
      }, {
        asset_id: "asset-true-2",
        category: "security_appliance",
        hostname: "edge-true-2",
        vendor_name: "Example Vendor",
        product_family: "SRX",
        internet_facing: "yes"
      }]
    });
    assert.deepEqual(
      affirmative.imported_assets.map((asset) => asset.internet_facing),
      [true, true]
    );
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

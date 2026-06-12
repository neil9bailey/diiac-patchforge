import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  collectLocalHost,
  mapHttpJsonAsset,
  normalizeConfig,
  runCollector
} from "./patchforge-collector.mjs";

test("collector rejects raw secret values in config", () => {
  assert.throws(() => normalizeConfig({
    apiBaseUrl: "http://127.0.0.1:3000",
    tenantId: "tenant-a",
    auth: { token: "do-not-store" }
  }), /Raw secret field/);

  assert.throws(() => normalizeConfig({
    apiBaseUrl: "http://127.0.0.1:3000",
    tenantId: "tenant-a",
    adapters: [{
      type: "http_json",
      url: "http://example.test/assets",
      headers: { Authorization: "Bearer literal-value" }
    }]
  }), /Sensitive header/);
});

test("collector maps CMDB or NMS JSON records into PatchForge asset snapshots", () => {
  const asset = mapHttpJsonAsset({
    id: "nms-juniper-edge-1",
    category: "security_appliance",
    hostname: "srx4100-edge-1",
    vendor: "Juniper",
    product: "SRX",
    model: "SRX4100",
    version: "22.4R3",
    ip: "10.10.0.10",
    features: ["ipsec_vpn", "ssl_vpn"]
  }, {}, 0, {
    tenantId: "tenant-a",
    collector: { collector_id: "collector-a", environment: "production", site: "London" }
  });

  assert.equal(asset.category, "security_appliance");
  assert.equal(asset.vendor_name, "Juniper");
  assert.equal(asset.product_family, "SRX");
  assert.deepEqual(asset.ip_addresses, ["10.10.0.10"]);
  assert.deepEqual(asset.enabled_features, ["ipsec_vpn", "ssl_vpn"]);
});

test("collector dry-run gathers local host evidence without pushing to API", async () => {
  const config = normalizeConfig({
    apiBaseUrl: "http://127.0.0.1:3000",
    tenantId: "tenant-a",
    collector: { collector_id: "collector-local", site: "Lab" },
    adapters: [{ type: "local_host" }]
  });
  const asset = await collectLocalHost({
    config,
    commandRunner: async () => ({ stdout: "none\n", stderr: "" }),
    startedAt: "2026-06-12T10:00:00Z"
  });

  assert.ok(asset.asset_id.startsWith("disc-"));
  assert.ok(["physical_server", "virtual_server"].includes(asset.category));
  assert.equal(asset.site, "Lab");
  assert.equal(asset.environment, "production");
});

test("collector registers, upserts policy, and imports JSON-source assets", async () => {
  const calls = [];
  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/nms/assets") {
      assert.equal(req.headers.authorization, "Bearer source-token");
      return sendJson(res, 200, {
        items: [{
          id: "nms-juniper-edge-1",
          category: "security_appliance",
          hostname: "srx4100-edge-1",
          vendor: "Juniper",
          product: "SRX",
          model: "SRX4100",
          version: "22.4R3",
          ip: "10.10.0.10"
        }]
      });
    }

    const body = await readJson(req);
    calls.push({ method: req.method, url: req.url, headers: req.headers, body });

    if (req.method === "POST" && req.url === "/api/patchforge/discovery/collectors") {
      assert.equal(req.headers.authorization, "Bearer collector-token");
      return sendJson(res, 201, { collector: body });
    }
    if (req.method === "POST" && req.url === "/api/patchforge/discovery/policies") {
      return sendJson(res, 201, { policy: body });
    }
    if (req.method === "POST" && req.url === "/api/patchforge/discovery/import") {
      return sendJson(res, 202, {
        run: {
          run_id: body.run_id,
          status: "completed",
          imported_asset_count: body.assets.length,
          rejected_asset_count: 0,
          final_approval_issued: false
        },
        imported_assets: body.assets,
        rejected_assets: [],
        boundary: {
          advisory_only: true,
          no_vulnerability_scanning: true,
          no_patch_deployment: true,
          final_approval_issued: false
        }
      });
    }
    return sendJson(res, 404, { error: "not_found" });
  });

  await listen(server);
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const result = await runCollector({
      config: {
        apiBaseUrl: baseUrl,
        tenantId: "tenant-a",
        collector: {
          collector_id: "collector-london-1",
          name: "London collector",
          site: "London",
          categories: ["security_appliance", "network_device"]
        },
        policy: {
          policy_id: "policy-london-network",
          categories: ["security_appliance", "network_device"],
          credential_reference: "customer-vault:patchforge/nms-readonly"
        },
        adapters: [{
          type: "http_json",
          url: `${baseUrl}/nms/assets`,
          headers: { Authorization: "Bearer env:NMS_TOKEN" },
          assetPath: "items"
        }]
      },
      env: {
        PATCHFORGE_COLLECTOR_TOKEN: "collector-token",
        NMS_TOKEN: "source-token"
      }
    });

    assert.equal(result.status, "completed");
    assert.equal(result.imported_asset_count, 1);
    assert.equal(calls.length, 3);
    assert.equal(calls[0].url, "/api/patchforge/discovery/collectors");
    assert.equal(calls[1].body.credential_reference, "customer-vault:patchforge/nms-readonly");
    assert.equal(calls[2].url, "/api/patchforge/discovery/import");
    assert.equal(calls[2].body.assets[0].category, "security_appliance");
    assert.equal(calls[2].body.assets[0].vendor_name, "Juniper");
    assert.equal(calls[2].body.assets[0].firmware_version, "22.4R3");
    assert.equal(calls[2].body.assets[0].confidence, 0.65);
  } finally {
    await close(server);
  }
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      resolve(body ? JSON.parse(body) : {});
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

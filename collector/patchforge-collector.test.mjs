import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertCollectorNotRevoked,
  collectLocalHost,
  mapHttpJsonAsset,
  normalizeConfig,
  replayCollectorSpool,
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
    collector: { collector_id: "collector-local", site: "Lab", package_channel: "windows_exe_day1" },
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
  assert.equal(config.collector.package_channel, "windows_exe_day1");
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
    assert.equal(calls.length, 4);
    assert.equal(calls[0].url, "/api/patchforge/discovery/collectors");
    assert.equal(calls[0].body.heartbeat_state, "running");
    assert.equal(calls[0].body.auth_mode, "environment_bearer");
    assert.equal(calls[0].body.credential_mode, "environment_or_managed_identity_only");
    assert.equal(calls[1].body.credential_reference, "customer-vault:patchforge/nms-readonly");
    assert.equal(calls[2].url, "/api/patchforge/discovery/import");
    assert.equal(calls[2].body.assets[0].category, "security_appliance");
    assert.equal(calls[2].body.assets[0].vendor_name, "Juniper");
    assert.equal(calls[2].body.assets[0].firmware_version, "22.4R3");
    assert.equal(calls[2].body.assets[0].confidence, 0.65);
    assert.equal(calls[3].body.heartbeat_state, "completed");
    assert.equal(calls[3].body.last_asset_count, 1);
  } finally {
    await close(server);
  }
});

test("collector can acquire PatchForge bearer token through Azure CLI", async () => {
  const calls = [];
  const commandCalls = [];
  const server = http.createServer(async (req, res) => {
    const body = await readJson(req);
    calls.push({ method: req.method, url: req.url, headers: req.headers, body });
    if (req.method === "POST" && req.url === "/api/patchforge/discovery/collectors") {
      assert.equal(req.headers.authorization, "Bearer azure-cli-token");
      return sendJson(res, 201, { collector: body });
    }
    if (req.method === "POST" && req.url === "/api/patchforge/discovery/policies") {
      assert.equal(req.headers.authorization, "Bearer azure-cli-token");
      return sendJson(res, 201, { policy: body });
    }
    if (req.method === "POST" && req.url === "/api/patchforge/discovery/import") {
      assert.equal(req.headers.authorization, "Bearer azure-cli-token");
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
        boundary: { advisory_only: true, final_approval_issued: false }
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
        auth: {
          azureCliScope: "api://patchforge-test/PatchForge.Access",
          azureTenantId: "tenant-guid"
        },
        collector: { collector_id: "collector-azure-cli", site: "Lab" },
        adapters: [{ type: "local_host" }]
      },
      env: {},
      commandRunner: async (command, args) => {
        commandCalls.push({ command, args });
        if (command === "az") {
          assert.deepEqual(args, [
            "account",
            "get-access-token",
            "--tenant",
            "tenant-guid",
            "--scope",
            "api://patchforge-test/PatchForge.Access",
            "--query",
            "accessToken",
            "-o",
            "tsv"
          ]);
          return { stdout: "azure-cli-token\n", stderr: "" };
        }
        return { stdout: "none\n", stderr: "" };
      }
    });

    assert.equal(result.status, "completed");
    assert.equal(calls.length, 4);
    assert.equal(commandCalls.filter((call) => call.command === "az").length, 1);
  } finally {
    await close(server);
  }
});

test("collector supports unattended Azure managed identity without secrets in config", async () => {
  const calls = [];
  const commandCalls = [];
  const server = http.createServer(async (req, res) => {
    const body = await readJson(req);
    calls.push({ url: req.url, headers: req.headers, body });
    if (req.url === "/api/patchforge/discovery/import") {
      return sendJson(res, 202, {
        run: { status: "completed", imported_asset_count: body.assets.length, rejected_asset_count: 0 },
        imported_assets: body.assets,
        boundary: { advisory_only: true, final_approval_issued: false }
      });
    }
    return sendJson(res, 201, {});
  });

  await listen(server);
  try {
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const result = await runCollector({
      config: {
        apiBaseUrl: baseUrl,
        tenantId: "tenant-a",
        auth: {
          azureCliScope: "api://patchforge-test/PatchForge.Access",
          azureTenantId: "tenant-guid",
          azureCliManagedIdentity: true,
          managedIdentityClientIdEnv: "COLLECTOR_IDENTITY_CLIENT_ID"
        },
        collector: { collector_id: "collector-managed", site: "Azure Arc site" },
        adapters: [{ type: "local_host" }]
      },
      env: { COLLECTOR_IDENTITY_CLIENT_ID: "managed-client-id" },
      commandRunner: async (command, args) => {
        commandCalls.push({ command, args });
        if (command === "az" && args[0] === "login") {
          assert.deepEqual(args, ["login", "--identity", "--client-id", "managed-client-id", "--allow-no-subscriptions", "--output", "none"]);
          return { stdout: "", stderr: "" };
        }
        if (command === "az") {
          return { stdout: "managed-token\n", stderr: "" };
        }
        return { stdout: "none\n", stderr: "" };
      }
    });

    assert.equal(result.status, "completed");
    assert.equal(commandCalls.filter((call) => call.command === "az" && call.args[0] === "login").length, 1);
    assert.equal(commandCalls.filter((call) => call.command === "az" && call.args[0] === "account").length, 1);
    assert.ok(calls.every((call) => call.headers.authorization === "Bearer managed-token"));
    assert.equal(calls[0].body.auth_mode, "azure_cli_managed_identity");
  } finally {
    await close(server);
  }
});

test("collector local revocation marker blocks every collection and API action", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-collector-revoke-"));
  const marker = path.join(root, "collector.revoked.json");
  try {
    await assertCollectorNotRevoked(marker);
    await writeFile(marker, JSON.stringify({ revoked: true }), "utf8");
    await assert.rejects(() => assertCollectorNotRevoked(marker), /locally revoked/i);
    await assert.rejects(() => runCollector({
      config: {
        apiBaseUrl: "https://api.patchforge.invalid",
        tenantId: "tenant-a",
        lifecycle: { revocationFile: marker },
        collector: { collector_id: "collector-revoked" }
      },
      env: {},
      fetchImpl: async () => assert.fail("revoked collector must not make network requests")
    }), /locally revoked/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("collector durably spools an offline submission and replays it oldest-first without credentials", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-collector-spool-"));
  const spoolDirectory = path.join(root, "spool");
  const heartbeatFile = path.join(root, "collector-heartbeat.json");
  const config = {
    apiBaseUrl: "https://api.patchforge.invalid",
    tenantId: "tenant-a",
    runId: "collector-run-offline-001",
    auth: { bearerTokenEnv: "PATCHFORGE_COLLECTOR_TOKEN" },
    lifecycle: {
      spoolDirectory,
      heartbeatFile,
      maxSpoolEntries: 5,
      maxSpoolEntryBytes: 1024 * 1024,
      maxReplayAttempts: 3
    },
    collector: { collector_id: "collector-offline", site: "Lab" },
    policy: { policy_id: "policy-collector-offline" },
    adapters: [{ type: "local_host" }]
  };
  try {
    const queued = await runCollector({
      config,
      env: { PATCHFORGE_COLLECTOR_TOKEN: "must-not-be-spooled" },
      fetchImpl: async () => {
        throw new Error("network unavailable");
      },
      commandRunner: async () => ({ stdout: "none\n", stderr: "" })
    });
    assert.equal(queued.status, "queued_offline");
    assert.equal(queued.spool.pending, 1);
    assert.equal(queued.imported_asset_count, 0);

    const files = (await readdir(spoolDirectory)).filter((name) => name.endsWith(".json"));
    assert.equal(files.length, 1);
    const spooledText = await readFile(path.join(spoolDirectory, files[0]), "utf8");
    assert.doesNotMatch(spooledText, /must-not-be-spooled/);
    const spooled = JSON.parse(spooledText);
    assert.equal(spooled.run_id, "collector-run-offline-001");
    assert.equal(spooled.import_payload.run_id, "collector-run-offline-001");
    assert.equal(spooled.import_payload.assets.length, 1);

    const calls = [];
    const replay = await replayCollectorSpool(normalizeConfig(config, { PATCHFORGE_COLLECTOR_TOKEN: "replacement-token" }), {
      env: { PATCHFORGE_COLLECTOR_TOKEN: "replacement-token" },
      fetchImpl: async (url, request) => {
        calls.push({ url, body: JSON.parse(request.body), authorization: request.headers.authorization });
        const isImport = url.endsWith("/api/patchforge/discovery/import");
        return {
          ok: true,
          status: isImport ? 202 : 201,
          json: async () => isImport
            ? { run: { status: "completed", imported_asset_count: 1, rejected_asset_count: 0 }, imported_assets: [{}] }
            : {}
        };
      }
    });
    assert.equal(replay.replayed, 1);
    assert.equal(replay.remaining, 0);
    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/api/patchforge/discovery/policies",
      "/api/patchforge/discovery/import",
      "/api/patchforge/discovery/collectors"
    ]);
    assert.ok(calls.every((call) => call.authorization === "Bearer replacement-token"));
    assert.equal((await readdir(spoolDirectory)).filter((name) => name.endsWith(".json")).length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
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

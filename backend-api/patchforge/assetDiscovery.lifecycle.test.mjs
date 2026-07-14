import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  importDiscoveredAssets,
  listAssetCollectors,
  recordAssetCollectorHeartbeat,
  registerAssetCollector,
  revokeAssetCollector
} from "./assetDiscovery.js";
import { PatchForgeJsonStorage } from "./storage.js";

test("collector heartbeats expose ready and stale lifecycle state", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-collector-lifecycle-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await registerAssetCollector(storage, "tenant-a", {
      collector_id: "collector-lifecycle-1",
      name: "Lifecycle collector",
      platform: "windows",
      package_channel: "windows_exe_day1"
    });
    const heartbeatAt = "2026-07-12T08:00:00.000Z";
    const heartbeat = await recordAssetCollectorHeartbeat(storage, "tenant-a", {
      collector_id: "collector-lifecycle-1",
      last_heartbeat_at: heartbeatAt,
      heartbeat_id: "heartbeat-1",
      heartbeat_state: "completed",
      last_run_id: "collector-run-1",
      last_asset_count: 12,
      collector_version: "20260712.abc12345",
      package_digest: "sha256:package",
      auth_mode: "azure_cli_managed_identity"
    });
    assert.equal(heartbeat.credential_mode, "environment_or_managed_identity_only");
    assert.equal(heartbeat.last_asset_count, 12);
    assert.equal(heartbeat.auth_mode, "azure_cli_managed_identity");

    const ready = await listAssetCollectors(storage, "tenant-a", {
      now: Date.parse("2026-07-12T09:00:00.000Z"),
      staleAfterMs: 8 * 60 * 60 * 1000
    });
    assert.equal(ready[0].health_status, "ready");
    assert.equal(ready[0].heartbeat_age_minutes, 60);

    const stale = await listAssetCollectors(storage, "tenant-a", {
      now: Date.parse("2026-07-12T17:00:01.000Z"),
      staleAfterMs: 8 * 60 * 60 * 1000
    });
    assert.equal(stale[0].health_status, "stale");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("revoked collectors cannot self-reactivate or import evidence", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-collector-revoked-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await registerAssetCollector(storage, "tenant-a", {
      collector_id: "collector-revoked-1",
      name: "Revoked collector"
    });
    const revoked = await revokeAssetCollector(storage, "tenant-a", {
      collector_id: "collector-revoked-1",
      reason: "Customer offboarding",
      actor_upn: "security.lead@example.test"
    });
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.final_approval_issued, false);
    assert.equal(revoked.no_production_mutation, true);

    await assert.rejects(() => recordAssetCollectorHeartbeat(storage, "tenant-a", {
      collector_id: "collector-revoked-1",
      heartbeat_state: "completed"
    }), (error) => error.code === "collector_revoked" && error.statusCode === 409);

    await assert.rejects(() => importDiscoveredAssets(storage, "tenant-a", {
      collector_id: "collector-revoked-1",
      assets: [{ category: "physical_server", hostname: "blocked-host" }]
    }), (error) => error.code === "collector_revoked" && error.statusCode === 409);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("collector import replay is idempotent and rejects run-id payload conflicts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-collector-replay-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await registerAssetCollector(storage, "tenant-a", {
      collector_id: "collector-replay-1",
      name: "Replay collector"
    });
    const payload = {
      run_id: "collector-run-replay-1",
      collector_id: "collector-replay-1",
      assets: [{ asset_id: "asset-replay-1", category: "physical_server", hostname: "server-a" }]
    };
    const first = await importDiscoveredAssets(storage, "tenant-a", payload);
    const replay = await importDiscoveredAssets(storage, "tenant-a", payload);
    assert.equal(first.run.run_id, payload.run_id);
    assert.equal(replay.idempotent_reuse, true);
    assert.equal(replay.run.idempotent_reuse, true);
    assert.equal(replay.imported_assets.length, 1);

    await assert.rejects(() => importDiscoveredAssets(storage, "tenant-a", {
      ...payload,
      assets: [{ asset_id: "asset-replay-2", category: "physical_server", hostname: "server-b" }]
    }), (error) => error.code === "collector_run_conflict" && error.statusCode === 409);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  automationHealth,
  enqueueSourceFeedWork,
  executeSourceFeedWork,
  reconcileAutomationWork
} from "./automationWork.js";
import { PatchForgeJsonStorage } from "./storage.js";
import { runWorkerOnce } from "./worker.js";
import { runSchedulerOnce } from "./scheduler.js";

test("automation work and distributed leases are idempotent", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-idempotent-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    const first = await enqueueSourceFeedWork(storage, "tenant-a", {
      cycleId: "cycle-1",
      feedId: "cisa-kev",
      limit: 10
    });
    const second = await enqueueSourceFeedWork(storage, "tenant-a", {
      cycleId: "cycle-1",
      feedId: "cisa-kev",
      limit: 10
    });
    assert.equal(second.work_id, first.work_id);
    assert.equal(second.idempotent_reuse, true);
    assert.equal((await storage.list("automation_work_items", "tenant-a")).length, 1);

    const acquired = await storage.acquireAutomationLease("tenant-a", "lease-a", "owner-a", 60000, new Date("2026-07-12T08:00:00Z"));
    assert.equal(acquired.owner_id, "owner-a");
    assert.equal(await storage.acquireAutomationLease("tenant-a", "lease-a", "owner-b", 60000, new Date("2026-07-12T08:00:30Z")), null);
    const recovered = await storage.acquireAutomationLease("tenant-a", "lease-a", "owner-b", 60000, new Date("2026-07-12T08:01:01Z"));
    assert.equal(recovered.owner_id, "owner-b");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("source-feed work retries with bounded backoff and records checkpoint", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-retry-"));
  const storage = new PatchForgeJsonStorage(root);
  let calls = 0;
  const delays = [];
  try {
    const work = await enqueueSourceFeedWork(storage, "tenant-a", {
      cycleId: "cycle-retry",
      feedId: "cisa-kev",
      maxAttempts: 3
    });
    const execution = await executeSourceFeedWork({
      storage,
      tenantId: "tenant-a",
      workItem: work,
      ownerId: "scheduler-retry",
      sourceFeedClient: {
        async refresh() {
          calls += 1;
          if (calls < 3) {
            throw new Error(`temporary failure ${calls}`);
          }
          return { status: "completed", catalog_version: "2026.07.12", completed_at: "2026-07-12T08:05:00Z" };
        }
      },
      sleep: async (ms) => delays.push(ms),
      random: () => 0,
      baseDelayMs: 100,
      maxDelayMs: 500,
      nowProvider: () => new Date("2026-07-12T08:00:00Z")
    });

    assert.equal(execution.work_item.status, "completed");
    assert.equal(execution.work_item.attempts, 3);
    assert.deepEqual(delays, [75, 150]);
    assert.equal((await storage.list("automation_failures", "tenant-a")).length, 2);
    assert.equal((await storage.list("automation_checkpoints", "tenant-a"))[0].cursor, "2026.07.12");

    const replay = await executeSourceFeedWork({
      storage,
      tenantId: "tenant-a",
      workItem: work,
      ownerId: "scheduler-retry",
      sourceFeedClient: { refresh: async () => assert.fail("completed work must not execute twice") }
    });
    assert.equal(replay.skipped, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("dead letters are bounded, reconciled, and processed by the worker", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-dead-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    const work = await enqueueSourceFeedWork(storage, "tenant-a", {
      cycleId: "cycle-dead",
      feedId: "first-epss",
      cve: "CVE-2026-1000",
      maxAttempts: 1
    });
    const failed = await executeSourceFeedWork({
      storage,
      tenantId: "tenant-a",
      workItem: work,
      ownerId: "scheduler-dead",
      sourceFeedClient: { refresh: async () => { throw new Error("upstream unavailable"); } },
      deadLetterRetryMs: 1000,
      nowProvider: () => new Date("2026-07-12T08:00:00Z")
    });
    assert.equal(failed.work_item.status, "dead_lettered");
    assert.equal(failed.dead_letter.status, "open");

    const reconciliation = await reconcileAutomationWork(storage, "tenant-a", {
      now: new Date("2026-07-12T08:00:02Z"),
      maxReplays: 1
    });
    assert.equal(reconciliation.requeued, 1);

    const worker = await runWorkerOnce({
      storage,
      tenantId: "tenant-a",
      workerId: "worker-test",
      now: new Date("2026-07-12T08:00:03Z"),
      sourceFeedClient: {
        refresh: async () => ({ status: "completed", completed_at: "2026-07-12T08:00:04Z", records_enriched: 1 })
      },
      sleep: async () => {},
      random: () => 0
    });
    assert.equal(worker.status, "completed");
    assert.equal(worker.processing.completed, 1);
    assert.equal(worker.no_patch_deployment, true);
    assert.equal(worker.no_production_mutation, true);
    const health = await automationHealth(storage, "tenant-a");
    assert.equal(health.status, "ready");
    assert.equal(health.pending_work_items, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("worker quarantines unsupported work instead of executing a production mutation", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-unsupported-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await storage.append("automation_work_items", {
      tenant_id: "tenant-a",
      work_id: "work-prohibited",
      work_kind: "patch_deployment",
      status: "pending",
      created_at: "2026-07-12T08:00:00Z"
    });
    const worker = await runWorkerOnce({
      storage,
      tenantId: "tenant-a",
      workerId: "worker-boundary-test",
      sourceFeedClient: { refresh: async () => assert.fail("unsupported work must never execute") }
    });
    assert.equal(worker.status, "completed_with_warnings");
    const work = (await storage.list("automation_work_items", "tenant-a"))[0];
    const dead = (await storage.list("automation_dead_letters", "tenant-a"))[0];
    assert.equal(work.status, "quarantined");
    assert.equal(dead.status, "quarantined");
    assert.equal(dead.no_patch_deployment, true);
    assert.equal(dead.no_production_mutation, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scheduler cycle is leased and idempotent across repeated invocation", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-scheduler-cycle-"));
  const storage = new PatchForgeJsonStorage(root);
  let calls = 0;
  try {
    await storage.ingestVulnerability("tenant-a", {
      vulnerability_id: "CVE-2026-2000",
      canonical_id: "CVE-2026-2000",
      title: "Scheduler test vulnerability",
      severity: "critical",
      review_state: "pending_review",
      sources: []
    });
    const sourceFeedClient = {
      async refresh({ body }) {
        calls += 1;
        return body.feed_id === "cisa-kev"
          ? { status: "completed", records_ingested: 1, catalog_version: "2026.07.12" }
          : { status: "completed", records_enriched: 1, completed_at: "2026-07-12T09:00:00Z" };
      }
    };
    const first = await runSchedulerOnce({
      storage,
      sourceFeedClient,
      tenantId: "tenant-a",
      cycleId: "cycle-fixed",
      schedulerRunId: "scheduler-fixed",
      leaseOwner: "scheduler-fixed:instance-a",
      cisaLimit: 1,
      epssLimit: 1,
      sleep: async () => {}
    });
    assert.equal(first.status, "completed");
    assert.equal(first.work_items.length, 2);
    assert.equal(calls, 2);

    const second = await runSchedulerOnce({
      storage,
      sourceFeedClient,
      tenantId: "tenant-a",
      cycleId: "cycle-fixed",
      schedulerRunId: "scheduler-fixed",
      leaseOwner: "scheduler-fixed:instance-b"
    });
    assert.equal(second.status, "skipped_idempotent");
    assert.equal(second.idempotent_reuse, true);
    assert.equal(calls, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("scheduler defers when another instance owns the tenant lease", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-scheduler-lease-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await storage.acquireAutomationLease("tenant-a", "scheduler:tenant-a", "other-instance", 60000, new Date());
    const result = await runSchedulerOnce({
      storage,
      tenantId: "tenant-a",
      cycleId: "cycle-contended",
      leaseOwner: "this-instance",
      sourceFeedClient: { refresh: async () => assert.fail("contended scheduler must not fetch") }
    });
    assert.equal(result.status, "lease_contended");
    assert.equal(result.deferred, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("automation health exposes backlog and checkpoint SLO alerts with operator actions", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-slo-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await storage.append("automation_work_items", {
      tenant_id: "tenant-a",
      work_id: "work-slo-breach",
      work_kind: "source_feed_refresh",
      feed_id: "cisa-kev",
      status: "pending",
      created_at: "2026-07-12T08:00:00Z"
    });
    await storage.append("automation_checkpoints", {
      tenant_id: "tenant-a",
      checkpoint_id: "checkpoint-slo-breach",
      feed_id: "cisa-kev",
      completed_at: "2026-07-12T07:00:00Z"
    });

    const health = await automationHealth(storage, "tenant-a", {
      now: new Date("2026-07-12T08:20:00Z"),
      backlogSloMs: 10 * 60 * 1000,
      checkpointSloMs: 30 * 60 * 1000
    });

    assert.equal(health.status, "degraded");
    assert.equal(health.operator_action_required, true);
    assert.equal(health.backlog_age_ms, 20 * 60 * 1000);
    assert.deepEqual(health.alerts.map((alert) => alert.code).sort(), ["backlog_slo_breached", "checkpoint_slo_breached"]);
    assert.ok(health.alerts.every((alert) => alert.operator_action));
    assert.equal(health.no_patch_deployment, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("automation health gives a new work item its checkpoint SLO window", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-automation-fresh-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await storage.append("automation_work_items", {
      tenant_id: "tenant-a",
      work_id: "work-fresh",
      work_kind: "source_feed_refresh",
      feed_id: "cisa-kev",
      status: "pending",
      created_at: "2026-07-12T08:00:00Z"
    });
    const health = await automationHealth(storage, "tenant-a", {
      now: new Date("2026-07-12T08:05:00Z"),
      backlogSloMs: 10 * 60 * 1000,
      checkpointSloMs: 30 * 60 * 1000
    });
    assert.equal(health.status, "ready");
    assert.deepEqual(health.alerts, []);
    assert.equal(health.work_history_age_ms, 5 * 60 * 1000);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

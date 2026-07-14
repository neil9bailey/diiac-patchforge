import { randomUUID } from "node:crypto";
import { createPatchForgeStorage } from "./storage.js";
import { createSourceFeedClient } from "./sourceFeeds.js";
import {
  AUTOMATION_BOUNDARY,
  automationHealth,
  reconcileAutomationWork,
  runPendingAutomationWork
} from "./automationWork.js";

const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io";
const DEFAULT_INTERVAL_MS = 60 * 1000;

export async function runWorkerOnce(options = {}) {
  const storage = options.storage || createPatchForgeStorage();
  const sourceFeedClient = options.sourceFeedClient || createSourceFeedClient();
  const tenantId = options.tenantId || DEFAULT_TENANT;
  const workerId = options.workerId
    || process.env.PATCHFORGE_WORKER_ID
    || `worker-${process.env.HOSTNAME || process.pid}-${randomUUID().slice(0, 8)}`;
  await storage.ensureReady();

  const lease = await storage.acquireAutomationLease(
    tenantId,
    `automation-worker:${tenantId}`,
    workerId,
    boundedNumber(options.leaseTtlMs || process.env.PATCHFORGE_WORKER_LEASE_TTL_MS, 5 * 60 * 1000, 30000, 30 * 60 * 1000),
    options.now || new Date()
  );
  if (!lease) {
    return {
      tenant_id: tenantId,
      worker_id: workerId,
      status: "lease_contended",
      deferred: true,
      ...AUTOMATION_BOUNDARY
    };
  }

  try {
    const reconciliation = await reconcileAutomationWork(storage, tenantId, {
      now: options.now,
      maxReplays: options.maxReplays ?? process.env.PATCHFORGE_WORKER_MAX_REPLAYS
    });
    const processing = await runPendingAutomationWork({
      ...options,
      storage,
      sourceFeedClient,
      tenantId,
      ownerId: workerId,
      limit: options.limit ?? process.env.PATCHFORGE_WORKER_BATCH_SIZE
    });
    const health = await automationHealth(storage, tenantId);
    const result = {
      tenant_id: tenantId,
      worker_id: workerId,
      status: processing.dead_lettered || health.status === "degraded" ? "completed_with_warnings" : "completed",
      completed_at: new Date().toISOString(),
      reconciliation,
      processing: {
        considered: processing.considered,
        completed: processing.completed,
        dead_lettered: processing.dead_lettered,
        deferred: processing.deferred
      },
      health,
      ...AUTOMATION_BOUNDARY
    };
    await storage.audit(tenantId, "automation_worker_cycle_completed", result);
    return result;
  } finally {
    await storage.releaseAutomationLease(tenantId, `automation-worker:${tenantId}`, workerId, new Date());
  }
}

export function startWorker(options = {}) {
  const intervalMs = boundedNumber(options.intervalMs ?? process.env.PATCHFORGE_WORKER_INTERVAL_MS, DEFAULT_INTERVAL_MS, 15000, 60 * 60 * 1000);
  const runOnStart = parseBoolean(options.runOnStart ?? process.env.PATCHFORGE_WORKER_RUN_ON_START, true);
  let running = false;

  async function tick() {
    if (running) {
      console.log(JSON.stringify({ component: "patchforge-worker", status: "local_overlap_skipped" }));
      return;
    }
    running = true;
    try {
      const result = await runWorkerOnce(options);
      console.log(JSON.stringify({
        component: "patchforge-worker",
        status: result.status,
        worker_id: result.worker_id,
        completed: result.processing?.completed || 0,
        dead_lettered: result.processing?.dead_lettered || 0,
        completed_at: result.completed_at || null,
        no_patch_deployment: true,
        no_production_mutation: true
      }));
    } catch (error) {
      console.error(JSON.stringify({
        component: "patchforge-worker",
        status: "failed",
        message: String(error.message || error).slice(0, 1000),
        no_patch_deployment: true,
        no_production_mutation: true
      }));
    } finally {
      running = false;
    }
  }

  if (runOnStart) {
    void tick();
  }
  const timer = setInterval(() => void tick(), intervalMs);
  return { timer, tick };
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, Math.floor(number))) : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

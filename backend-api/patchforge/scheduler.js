import { randomUUID } from "node:crypto";
import { createPatchForgeStorage } from "./storage.js";
import { createSourceFeedClient } from "./sourceFeeds.js";
import { enqueueSourceFeedWork, executeSourceFeedWork } from "./automationWork.js";

const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io";
const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;

export async function runSchedulerOnce(options = {}) {
  const storage = options.storage || createPatchForgeStorage();
  const sourceFeedClient = options.sourceFeedClient || createSourceFeedClient();
  const tenantId = options.tenantId || DEFAULT_TENANT;
  const cisaLimit = boundedNumber(options.cisaLimit ?? process.env.PATCHFORGE_SCHEDULER_CISA_LIMIT, 10, 1, 50);
  const epssLimit = boundedNumber(options.epssLimit ?? process.env.PATCHFORGE_SCHEDULER_EPSS_LIMIT, 10, 1, 50);
  const lineage = schedulerLineage(tenantId);
  const now = options.nowProvider || (() => new Date());
  const startedAt = now().toISOString();
  const intervalMs = boundedNumber(options.intervalMs ?? process.env.PATCHFORGE_SCHEDULER_INTERVAL_MS, DEFAULT_INTERVAL_MS, 60000, 24 * 60 * 60 * 1000);
  const cycleId = options.cycleId || `cycle-${Math.floor(Date.parse(startedAt) / intervalMs)}`;
  const schedulerRunId = options.schedulerRunId || `scheduler-${cycleId.replace(/[^a-zA-Z0-9-]+/g, "-")}`;
  const leaseOwner = options.leaseOwner || `${schedulerRunId}:${process.env.HOSTNAME || process.pid}:${randomUUID().slice(0, 8)}`;
  const result = {
    scheduler_run_id: schedulerRunId,
    cycle_id: cycleId,
    tenant_id: tenantId,
    started_at: startedAt,
    completed_at: null,
    cisa_run: null,
    epss_runs: [],
    work_items: [],
    failures: [],
    status: "running",
    boundary: {
      source_bound: true,
      advisory_only: true,
      no_scanner: true,
      no_exploit_generation: true,
      no_patch_deployment: true,
      no_production_mutation: true,
      no_autonomous_approval: true,
      no_autonomous_risk_acceptance: true
    }
  };

  await storage.ensureReady();
  const leaseId = `scheduler:${tenantId}`;
  const lease = await storage.acquireAutomationLease(
    tenantId,
    leaseId,
    leaseOwner,
    boundedNumber(options.leaseTtlMs ?? process.env.PATCHFORGE_SCHEDULER_LEASE_TTL_MS, 30 * 60 * 1000, 60000, 2 * 60 * 60 * 1000),
    new Date(startedAt)
  );
  if (!lease) {
    return { ...result, status: "lease_contended", deferred: true, completed_at: now().toISOString() };
  }

  const cycleCheckpointId = `scheduler-cycle-${cycleId}`;
  try {
    const existingCycle = (await storage.list("automation_checkpoints", tenantId))
      .find((checkpoint) => checkpoint.checkpoint_id === cycleCheckpointId && ["completed", "completed_with_warnings"].includes(checkpoint.result_status));
    if (existingCycle && !options.force) {
      return {
        ...result,
        status: "skipped_idempotent",
        idempotent_reuse: true,
        completed_at: now().toISOString(),
        checkpoint: existingCycle
      };
    }

    const cisaWork = await enqueueSourceFeedWork(storage, tenantId, {
      cycleId,
      scheduler_run_id: schedulerRunId,
      feedId: "cisa-kev",
      limit: cisaLimit,
      maxAttempts: options.maxAttempts ?? process.env.PATCHFORGE_SCHEDULER_MAX_ATTEMPTS,
      ...lineage
    });
    result.work_items.push(cisaWork.work_id);
    const cisaExecution = await executeSourceFeedWork({
      storage,
      sourceFeedClient,
      tenantId,
      workItem: cisaWork,
      ownerId: leaseOwner,
      sleep: options.sleep,
      random: options.random,
      baseDelayMs: options.baseDelayMs,
      maxDelayMs: options.maxDelayMs,
      nowProvider: now
    });
    result.cisa_run = cisaExecution.result;
    if (cisaExecution.error) {
      result.failures.push(cisaExecution.error);
    }

    const vulnerabilities = await storage.list("vulnerabilities", tenantId);
    const cves = prioritizedCves(vulnerabilities).slice(0, epssLimit);
    for (const cve of cves) {
      const epssWork = await enqueueSourceFeedWork(storage, tenantId, {
        cycleId,
        scheduler_run_id: schedulerRunId,
        feedId: "first-epss",
        cve,
        maxAttempts: options.maxAttempts ?? process.env.PATCHFORGE_SCHEDULER_MAX_ATTEMPTS,
        ...lineage
      });
      result.work_items.push(epssWork.work_id);
      const epssExecution = await executeSourceFeedWork({
        storage,
        sourceFeedClient,
        tenantId,
        workItem: epssWork,
        ownerId: leaseOwner,
        sleep: options.sleep,
        random: options.random,
        baseDelayMs: options.baseDelayMs,
        maxDelayMs: options.maxDelayMs,
        nowProvider: now
      });
      if (epssExecution.result) {
        result.epss_runs.push(epssExecution.result);
      }
      if (epssExecution.error) {
        result.failures.push(epssExecution.error);
      }
    }

    result.completed_at = now().toISOString();
    result.status = result.failures.length ? "completed_with_warnings" : "completed";
    await storage.append("automation_checkpoints", {
      tenant_id: tenantId,
      checkpoint_id: cycleCheckpointId,
      cycle_id: cycleId,
      scheduler_run_id: schedulerRunId,
      cursor: result.completed_at,
      completed_at: result.completed_at,
      result_status: result.status,
      work_item_count: result.work_items.length,
      failure_count: result.failures.length,
      ...result.boundary
    });
    await storage.audit(tenantId, "scheduler_source_refresh_completed", {
      scheduler_run_id: result.scheduler_run_id,
      cycle_id: cycleId,
      status: result.status,
      cisa_records_ingested: result.cisa_run?.records_ingested || 0,
      epss_runs: result.epss_runs.length,
      work_items: result.work_items.length,
      failures: result.failures.length,
      ...lineage
    });
    return result;
  } finally {
    await storage.releaseAutomationLease(tenantId, leaseId, leaseOwner, now());
  }
}

export function startScheduler(options = {}) {
  const intervalMs = boundedNumber(options.intervalMs ?? process.env.PATCHFORGE_SCHEDULER_INTERVAL_MS, DEFAULT_INTERVAL_MS, 60000, 24 * 60 * 60 * 1000);
  const runOnStart = parseBoolean(options.runOnStart ?? process.env.PATCHFORGE_SCHEDULER_RUN_ON_START, true);
  let running = false;

  async function tick() {
    if (running) {
      console.log("PatchForge scheduler skipped overlapping refresh run.", flushToken());
      return;
    }
    running = true;
    try {
      const result = await runSchedulerOnce(options);
      console.log(JSON.stringify({
        component: "patchforge-scheduler",
        status: result.status,
        scheduler_run_id: result.scheduler_run_id,
        cisa_records_ingested: result.cisa_run?.records_ingested || 0,
        epss_runs: result.epss_runs.length,
        completed_at: result.completed_at
      }));
    } catch (error) {
      console.error(JSON.stringify({
        component: "patchforge-scheduler",
        status: "failed",
        message: error.message,
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

function prioritizedCves(vulnerabilities) {
  return [...vulnerabilities]
    .filter((item) => item.vulnerability_id || item.canonical_id)
    .sort((a, b) => scoreVulnerability(b) - scoreVulnerability(a))
    .map((item) => String(item.canonical_id || item.vulnerability_id).toUpperCase());
}

function scoreVulnerability(item) {
  return [
    item.known_exploited ? 40 : 0,
    item.internet_exposed ? 25 : 0,
    String(item.severity || "").toLowerCase() === "critical" ? 20 : 0,
    String(item.patch_status || "").toLowerCase() === "patch_available" ? 10 : 0,
    item.ot_relevant ? 5 : 0
  ].reduce((sum, value) => sum + value, 0);
}

function schedulerLineage(tenantId) {
  return {
    actor_oid: "patchforge-scheduler",
    actor_upn: "patchforge-scheduler@diiac.io",
    actor_roles: ["PatchForge.SystemScheduler"],
    actor_tenant_id: process.env.PATCHFORGE_ENTRA_TENANT_ID || "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    effective_tenant_id: tenantId,
    requested_tenant_id: tenantId,
    tenant_id_source: "scheduler_config",
    tenant_override_ignored: false
  };
}

function boundedNumber(value, fallback, min, max) {
  const numeric = Number(value ?? fallback);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.floor(numeric)));
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function flushToken() {
  return "";
}

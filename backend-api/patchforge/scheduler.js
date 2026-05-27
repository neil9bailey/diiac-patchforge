import { createPatchForgeStorage } from "./storage.js";
import { createSourceFeedClient } from "./sourceFeeds.js";

const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io";
const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;

export async function runSchedulerOnce(options = {}) {
  const storage = options.storage || createPatchForgeStorage();
  const sourceFeedClient = options.sourceFeedClient || createSourceFeedClient();
  const tenantId = options.tenantId || DEFAULT_TENANT;
  const cisaLimit = boundedNumber(options.cisaLimit ?? process.env.PATCHFORGE_SCHEDULER_CISA_LIMIT, 10, 1, 50);
  const epssLimit = boundedNumber(options.epssLimit ?? process.env.PATCHFORGE_SCHEDULER_EPSS_LIMIT, 10, 1, 50);
  const lineage = schedulerLineage(tenantId);
  const startedAt = new Date().toISOString();
  const result = {
    scheduler_run_id: `scheduler-${Date.now()}`,
    tenant_id: tenantId,
    started_at: startedAt,
    completed_at: null,
    cisa_run: null,
    epss_runs: [],
    status: "running",
    boundary: {
      source_bound: true,
      advisory_only: true,
      no_scanner: true,
      no_exploit_generation: true,
      no_patch_deployment: true,
      no_autonomous_approval: true,
      no_autonomous_risk_acceptance: true
    }
  };

  await storage.ensureReady();
  result.cisa_run = await sourceFeedClient.refresh({
    storage,
    tenantId,
    body: {
      feed_id: "cisa-kev",
      limit: cisaLimit,
      scheduler_run_id: result.scheduler_run_id,
      ...lineage
    }
  });

  const vulnerabilities = await storage.list("vulnerabilities", tenantId);
  const cves = prioritizedCves(vulnerabilities).slice(0, epssLimit);
  for (const cve of cves) {
    const epssRun = await sourceFeedClient.refresh({
      storage,
      tenantId,
      body: {
        feed_id: "first-epss",
        cve,
        scheduler_run_id: result.scheduler_run_id,
        ...lineage
      }
    });
    result.epss_runs.push(epssRun);
  }

  result.completed_at = new Date().toISOString();
  result.status = "completed";
  await storage.audit(tenantId, "scheduler_source_refresh_completed", {
    scheduler_run_id: result.scheduler_run_id,
    cisa_records_ingested: result.cisa_run?.records_ingested || 0,
    epss_runs: result.epss_runs.length,
    ...lineage
  });
  return result;
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
        no_patch_deployment: true
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

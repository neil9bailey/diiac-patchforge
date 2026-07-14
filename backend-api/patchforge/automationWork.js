import { createHash, randomUUID } from "node:crypto";

const ALLOWED_WORK_KINDS = new Set(["source_feed_refresh"]);
const ALLOWED_FEEDS = new Set(["cisa-kev", "first-epss"]);

export const AUTOMATION_BOUNDARY = Object.freeze({
  advisory_only: true,
  source_bound: true,
  review_required: true,
  no_scanner: true,
  no_exploit_generation: true,
  no_patch_deployment: true,
  no_production_mutation: true,
  no_autonomous_approval: true,
  no_autonomous_risk_acceptance: true
});

export async function enqueueSourceFeedWork(storage, tenantId, options = {}) {
  await storage.ensureReady();
  const feedId = String(options.feedId || options.feed_id || "");
  if (!ALLOWED_FEEDS.has(feedId)) {
    throw new Error(`Unsupported source-feed work item: ${feedId}`);
  }
  const cve = options.cve ? String(options.cve).toUpperCase() : null;
  const cycleId = String(options.cycleId || options.cycle_id || "manual");
  const idempotencyKey = options.idempotencyKey || `source-feed:${tenantId}:${cycleId}:${feedId}:${cve || "catalogue"}`;
  const workId = `work-${hash(idempotencyKey).slice(0, 24)}`;
  const existing = (await storage.list("automation_work_items", tenantId)).find((item) => item.work_id === workId);
  if (existing) {
    return { ...existing, idempotent_reuse: true };
  }
  const checkpointId = `checkpoint-${hash(`${tenantId}:${feedId}:${cve || "catalogue"}`).slice(0, 24)}`;
  const previousCheckpoint = (await storage.list("automation_checkpoints", tenantId)).find((item) => item.checkpoint_id === checkpointId) || null;
  const now = timestamp(options.now);
  const work = {
    tenant_id: tenantId,
    work_id: workId,
    work_kind: "source_feed_refresh",
    idempotency_key: idempotencyKey,
    cycle_id: cycleId,
    scheduler_run_id: options.scheduler_run_id || options.schedulerRunId || null,
    feed_id: feedId,
    cve,
    requested_limit: options.limit || null,
    checkpoint_id: checkpointId,
    previous_cursor: previousCheckpoint?.cursor || null,
    status: "pending",
    attempts: 0,
    max_attempts: boundedNumber(options.maxAttempts, 3, 1, 8),
    replay_count: 0,
    created_at: now,
    updated_at: now,
    ...lineage(options),
    ...AUTOMATION_BOUNDARY
  };
  await storage.append("automation_work_items", work);
  return work;
}

export async function executeSourceFeedWork(options = {}) {
  const { storage, sourceFeedClient, tenantId } = options;
  if (!storage || !sourceFeedClient || !tenantId || !options.workItem) {
    throw new Error("storage, sourceFeedClient, tenantId, and workItem are required.");
  }
  const workItem = options.workItem;
  assertAllowedWork(workItem);
  const current = (await storage.list("automation_work_items", tenantId)).find((item) => item.work_id === workItem.work_id) || workItem;
  if (current.status === "completed") {
    return { work_item: { ...current, idempotent_reuse: true }, result: current.result || null, skipped: true };
  }

  const ownerId = options.ownerId || `worker-${process.pid}-${randomUUID().slice(0, 8)}`;
  const leaseId = `automation-work:${current.work_id}`;
  const leaseTtlMs = boundedNumber(options.leaseTtlMs, 5 * 60 * 1000, 30000, 30 * 60 * 1000);
  const lease = await storage.acquireAutomationLease(tenantId, leaseId, ownerId, leaseTtlMs, options.now || new Date());
  if (!lease) {
    return { work_item: current, result: null, deferred: true, reason: "lease_contended" };
  }

  const sleep = options.sleep || delay;
  const random = options.random || Math.random;
  const now = options.nowProvider || (() => new Date());
  const maxAttempts = boundedNumber(current.max_attempts, 3, 1, 8);
  let updated = { ...current, status: "running", lease_id: leaseId, lease_owner: ownerId, started_at: now().toISOString(), updated_at: now().toISOString() };
  await storage.append("automation_work_items", updated);

  try {
    for (let attempt = Number(current.attempts || 0) + 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const result = await sourceFeedClient.refresh({
          storage,
          tenantId,
          body: {
            feed_id: current.feed_id,
            ...(current.cve ? { cve: current.cve } : {}),
            ...(current.requested_limit ? { limit: current.requested_limit } : {}),
            automation_work_id: current.work_id,
            idempotency_key: current.idempotency_key,
            scheduler_run_id: current.scheduler_run_id,
            ...lineage(current)
          }
        });
        const completedAt = now().toISOString();
        const checkpoint = {
          tenant_id: tenantId,
          checkpoint_id: current.checkpoint_id,
          feed_id: current.feed_id,
          cve: current.cve,
          cursor: result.catalog_version || result.date_released || result.completed_at || completedAt,
          last_completed_work_id: current.work_id,
          completed_at: completedAt,
          result_status: result.status,
          ...AUTOMATION_BOUNDARY
        };
        await storage.append("automation_checkpoints", checkpoint);
        updated = {
          ...updated,
          status: "completed",
          attempts: attempt,
          completed_at: completedAt,
          updated_at: completedAt,
          next_retry_at: null,
          result
        };
        await storage.append("automation_work_items", updated);
        await storage.audit(tenantId, "automation_work_completed", {
          work_id: updated.work_id,
          feed_id: updated.feed_id,
          attempts: attempt,
          checkpoint_id: checkpoint.checkpoint_id,
          ...AUTOMATION_BOUNDARY
        });
        return { work_item: updated, result, checkpoint, skipped: false };
      } catch (error) {
        const failedAt = now().toISOString();
        const failure = {
          tenant_id: tenantId,
          failure_id: `failure-${current.work_id}-${attempt}`,
          work_id: current.work_id,
          work_kind: current.work_kind,
          feed_id: current.feed_id,
          cve: current.cve,
          attempt,
          error_class: error.code || error.name || "Error",
          message: String(error.message || error).slice(0, 1000),
          failed_at: failedAt,
          retryable: attempt < maxAttempts,
          ...AUTOMATION_BOUNDARY
        };
        await storage.append("automation_failures", failure);
        if (attempt < maxAttempts) {
          const backoffMs = retryDelay(attempt, options.baseDelayMs, options.maxDelayMs, random);
          updated = {
            ...updated,
            status: "retry_scheduled",
            attempts: attempt,
            last_failure_id: failure.failure_id,
            next_retry_at: new Date(now().getTime() + backoffMs).toISOString(),
            updated_at: failedAt
          };
          await storage.append("automation_work_items", updated);
          const renewedBeforeDelay = await storage.acquireAutomationLease(tenantId, leaseId, ownerId, leaseTtlMs, now());
          if (!renewedBeforeDelay) {
            return { work_item: updated, result: null, deferred: true, reason: "lease_lost_before_retry" };
          }
          await sleep(backoffMs);
          const renewedAfterDelay = await storage.acquireAutomationLease(tenantId, leaseId, ownerId, leaseTtlMs, now());
          if (!renewedAfterDelay) {
            return { work_item: updated, result: null, deferred: true, reason: "lease_lost_after_retry_delay" };
          }
          updated = { ...updated, status: "running", updated_at: now().toISOString() };
          await storage.append("automation_work_items", updated);
          continue;
        }

        const deadLetter = {
          tenant_id: tenantId,
          dead_letter_id: `dead-${current.work_id}`,
          work_id: current.work_id,
          work_kind: current.work_kind,
          feed_id: current.feed_id,
          cve: current.cve,
          status: "open",
          replay_count: Number(current.replay_count || 0),
          last_failure_id: failure.failure_id,
          last_error: failure.message,
          dead_lettered_at: failedAt,
          next_retry_at: new Date(now().getTime() + boundedNumber(options.deadLetterRetryMs, 15 * 60 * 1000, 1000, 24 * 60 * 60 * 1000)).toISOString(),
          ...AUTOMATION_BOUNDARY
        };
        await storage.append("automation_dead_letters", deadLetter);
        updated = {
          ...updated,
          status: "dead_lettered",
          attempts: attempt,
          last_failure_id: failure.failure_id,
          dead_letter_id: deadLetter.dead_letter_id,
          completed_at: failedAt,
          updated_at: failedAt
        };
        await storage.append("automation_work_items", updated);
        await storage.audit(tenantId, "automation_work_dead_lettered", {
          work_id: updated.work_id,
          feed_id: updated.feed_id,
          attempts: attempt,
          no_patch_deployment: true,
          no_production_mutation: true
        });
        return { work_item: updated, result: null, dead_letter: deadLetter, error: failure };
      }
    }
    return { work_item: updated, result: null };
  } finally {
    await storage.releaseAutomationLease(tenantId, leaseId, ownerId, now());
  }
}

export async function runPendingAutomationWork(options = {}) {
  const { storage, tenantId } = options;
  const limit = boundedNumber(options.limit, 10, 1, 100);
  const nowMs = timestampMs(options.now || new Date());
  const pending = (await storage.list("automation_work_items", tenantId))
    .filter((item) => item.status === "pending" || (item.status === "retry_scheduled" && timestampMs(item.next_retry_at) <= nowMs))
    .slice(0, limit);
  const results = [];
  for (const workItem of pending) {
    try {
      results.push(await executeSourceFeedWork({ ...options, workItem }));
    } catch (error) {
      const quarantinedAt = new Date().toISOString();
      const message = String(error.message || error).slice(0, 1000);
      const deadLetter = {
        tenant_id: tenantId,
        dead_letter_id: `dead-${workItem.work_id}`,
        work_id: workItem.work_id,
        work_kind: workItem.work_kind,
        status: "quarantined",
        replay_count: Number(workItem.replay_count || 0),
        last_error: message,
        quarantined_at: quarantinedAt,
        no_patch_deployment: true,
        no_production_mutation: true,
        no_autonomous_approval: true
      };
      await storage.append("automation_dead_letters", deadLetter);
      const quarantinedWork = { ...workItem, status: "quarantined", updated_at: quarantinedAt, dead_letter_id: deadLetter.dead_letter_id };
      await storage.append("automation_work_items", quarantinedWork);
      results.push({ work_item: quarantinedWork, result: null, dead_letter: deadLetter, error: { message } });
    }
  }
  return {
    tenant_id: tenantId,
    considered: pending.length,
    completed: results.filter((item) => item.work_item?.status === "completed").length,
    dead_lettered: results.filter((item) => item.work_item?.status === "dead_lettered").length,
    quarantined: results.filter((item) => item.work_item?.status === "quarantined").length,
    deferred: results.filter((item) => item.deferred).length,
    results,
    ...AUTOMATION_BOUNDARY
  };
}

export async function reconcileAutomationWork(storage, tenantId, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const maxReplays = boundedNumber(options.maxReplays, 2, 0, 10);
  const workItems = await storage.list("automation_work_items", tenantId);
  const deadLetters = await storage.list("automation_dead_letters", tenantId);
  const leases = await storage.list("automation_leases", tenantId);
  let requeued = 0;
  let quarantined = 0;
  let recoveredExpiredLeases = 0;

  for (const work of workItems.filter((item) => item.status === "running")) {
    const lease = leases.find((item) => item.lease_id === work.lease_id);
    if (!lease || timestampMs(lease.expires_at) <= now.getTime()) {
      await storage.append("automation_work_items", { ...work, status: "pending", lease_owner: null, updated_at: now.toISOString(), recovery_reason: "expired_or_missing_lease" });
      recoveredExpiredLeases += 1;
    }
  }

  for (const dead of deadLetters.filter((item) => item.status === "open" && timestampMs(item.next_retry_at) <= now.getTime())) {
    const work = workItems.find((item) => item.work_id === dead.work_id);
    if (!work || !ALLOWED_WORK_KINDS.has(work.work_kind)) {
      continue;
    }
    if (Number(dead.replay_count || 0) >= maxReplays) {
      await storage.append("automation_dead_letters", { ...dead, status: "quarantined", quarantined_at: now.toISOString() });
      quarantined += 1;
      continue;
    }
    await storage.append("automation_work_items", {
      ...work,
      status: "pending",
      attempts: 0,
      replay_count: Number(dead.replay_count || 0) + 1,
      updated_at: now.toISOString(),
      recovery_reason: "bounded_dead_letter_replay"
    });
    await storage.append("automation_dead_letters", {
      ...dead,
      status: "replay_scheduled",
      replay_count: Number(dead.replay_count || 0) + 1,
      replay_scheduled_at: now.toISOString()
    });
    requeued += 1;
  }

  const reconciliation = {
    tenant_id: tenantId,
    reconciliation_id: `reconcile-${Date.now()}-${randomUUID().slice(0, 8)}`,
    completed_at: now.toISOString(),
    recovered_expired_leases: recoveredExpiredLeases,
    requeued,
    quarantined,
    ...AUTOMATION_BOUNDARY
  };
  await storage.append("automation_reconciliation_runs", reconciliation);
  return reconciliation;
}

export async function automationHealth(storage, tenantId, options = {}) {
  const [workItems, deadLetters, checkpoints, reconciliationRuns] = await Promise.all([
    storage.list("automation_work_items", tenantId),
    storage.list("automation_dead_letters", tenantId),
    storage.list("automation_checkpoints", tenantId),
    storage.list("automation_reconciliation_runs", tenantId)
  ]);
  const pending = workItems.filter((item) => ["pending", "retry_scheduled", "running"].includes(item.status));
  const openDeadLetters = deadLetters.filter((item) => item.status === "open");
  const quarantined = deadLetters.filter((item) => item.status === "quarantined");
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const backlogSloMs = boundedNumber(options.backlogSloMs ?? process.env.PATCHFORGE_WORKER_BACKLOG_SLO_MS, 15 * 60 * 1000, 60000, 24 * 60 * 60 * 1000);
  const checkpointSloMs = boundedNumber(options.checkpointSloMs ?? process.env.PATCHFORGE_WORKER_CHECKPOINT_SLO_MS, 12 * 60 * 60 * 1000, 5 * 60 * 1000, 7 * 24 * 60 * 60 * 1000);
  const pendingTimes = pending
    .map((item) => timestampMs(item.created_at || item.updated_at))
    .filter((value) => value > 0);
  const oldestPendingAtMs = pendingTimes.length ? Math.min(...pendingTimes) : 0;
  const backlogAgeMs = oldestPendingAtMs ? Math.max(0, now.getTime() - oldestPendingAtMs) : 0;
  const lastCheckpointAt = checkpoints.map((item) => item.completed_at).filter(Boolean).sort().at(-1) || null;
  const checkpointAgeMs = lastCheckpointAt ? Math.max(0, now.getTime() - timestampMs(lastCheckpointAt)) : null;
  const workTimes = workItems.map((item) => timestampMs(item.created_at || item.updated_at)).filter((value) => value > 0);
  const workHistoryAgeMs = workTimes.length ? Math.max(0, now.getTime() - Math.min(...workTimes)) : 0;
  const alerts = [];
  if (openDeadLetters.length) {
    alerts.push({ code: "open_dead_letters", severity: "high", count: openDeadLetters.length, operator_action: "Inspect the recorded failure and upstream dependency before bounded replay." });
  }
  if (quarantined.length) {
    alerts.push({ code: "quarantined_work", severity: "critical", count: quarantined.length, operator_action: "Investigate poison work; do not delete the failure ledger to clear health." });
  }
  if (pending.length && backlogAgeMs > backlogSloMs) {
    alerts.push({ code: "backlog_slo_breached", severity: "high", observed_ms: backlogAgeMs, threshold_ms: backlogSloMs, operator_action: "Confirm worker lease ownership, upstream availability, and checkpoint progress." });
  }
  if ((lastCheckpointAt && checkpointAgeMs !== null && checkpointAgeMs > checkpointSloMs)
      || (!lastCheckpointAt && workItems.length && workHistoryAgeMs > checkpointSloMs)) {
    alerts.push({ code: lastCheckpointAt ? "checkpoint_slo_breached" : "checkpoint_missing", severity: "high", observed_ms: lastCheckpointAt ? checkpointAgeMs : workHistoryAgeMs, threshold_ms: checkpointSloMs, operator_action: "Review the scheduler and worker run ledger before claiming refresh success." });
  }
  return {
    tenant_id: tenantId,
    status: alerts.length ? "degraded" : "ready",
    pending_work_items: pending.length,
    open_dead_letters: openDeadLetters.length,
    quarantined_work_items: quarantined.length,
    checkpoint_count: checkpoints.length,
    last_checkpoint_at: lastCheckpointAt,
    last_reconciliation_at: reconciliationRuns.map((item) => item.completed_at).filter(Boolean).sort().at(-1) || null,
    backlog_age_ms: backlogAgeMs,
    backlog_slo_ms: backlogSloMs,
    checkpoint_age_ms: checkpointAgeMs,
    checkpoint_slo_ms: checkpointSloMs,
    work_history_age_ms: workHistoryAgeMs,
    alerts,
    operator_action_required: alerts.length > 0,
    ...AUTOMATION_BOUNDARY
  };
}

function assertAllowedWork(workItem) {
  if (!ALLOWED_WORK_KINDS.has(workItem.work_kind) || !ALLOWED_FEEDS.has(workItem.feed_id)) {
    throw new Error("Worker rejected unsupported or production-mutating work item.");
  }
}

function retryDelay(attempt, baseValue, maxValue, random) {
  const base = boundedNumber(baseValue, 1000, 1, 60000);
  const max = boundedNumber(maxValue, 30000, base, 10 * 60 * 1000);
  const exponential = Math.min(max, base * (2 ** Math.max(0, attempt - 1)));
  return Math.max(1, Math.floor(exponential * (0.75 + (Number(random()) || 0) * 0.5)));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, Math.floor(number))) : fallback;
}

function timestamp(value) {
  return (value instanceof Date ? value : new Date(value || Date.now())).toISOString();
}

function timestampMs(value) {
  const parsed = value instanceof Date ? value.getTime() : Date.parse(value || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function hash(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function lineage(value = {}) {
  return {
    actor_oid: value.actor_oid || null,
    actor_upn: value.actor_upn || null,
    actor_roles: Array.isArray(value.actor_roles) ? value.actor_roles : [],
    actor_tenant_id: value.actor_tenant_id || null,
    effective_tenant_id: value.effective_tenant_id || null,
    requested_tenant_id: value.requested_tenant_id || null,
    tenant_id_source: value.tenant_id_source || null,
    tenant_override_ignored: Boolean(value.tenant_override_ignored)
  };
}

import { createHmac, randomUUID } from "node:crypto";
import { logger } from "./logger.js";
import { validateBody, validationError } from "./validate.js";

// PF-AZ12 contract section 6: outbound webhook subscriptions.
// Governance boundary: webhooks are notification-only. They carry governed
// event metadata; they never trigger scanning, patch deployment, or approval.

export const WEBHOOK_EVENT_TYPES = [
  "decision_pack.generated",
  "vulnerability.ingested",
  "source_feed.completed",
  "risk_acceptance.expiring"
];

const DEFAULT_RETRY_BASE_MS = Number(process.env.PATCHFORGE_WEBHOOK_RETRY_BASE_MS || 200);
const MAX_ATTEMPTS = 3;

export async function createWebhookSubscription(storage, tenantId, body = {}) {
  validateBody(body, {
    url: { required: true, type: "string", maxLength: 2000 },
    event_types: { required: true, type: "array", items: "string" },
    secret: { type: "string", maxLength: 500 },
    description: { type: "string", maxLength: 500 }
  });
  let parsedUrl;
  try {
    parsedUrl = new URL(body.url);
  } catch {
    throw validationError("Must be a valid URL.", "url");
  }
  if (parsedUrl.protocol !== "https:") {
    throw validationError("Only https URLs are accepted for webhook deliveries.", "url");
  }
  const eventTypes = body.event_types.map((value) => String(value).trim()).filter(Boolean);
  const invalid = eventTypes.filter((value) => !WEBHOOK_EVENT_TYPES.includes(value));
  if (!eventTypes.length || invalid.length) {
    const error = validationError(`Allowed event types: ${WEBHOOK_EVENT_TYPES.join(", ")}.`, "event_types");
    error.allowedEventTypes = WEBHOOK_EVENT_TYPES;
    throw error;
  }
  const subscription = {
    tenant_id: tenantId,
    subscription_id: `wh-${randomUUID()}`,
    url: body.url,
    event_types: eventTypes,
    secret: body.secret || null,
    description: body.description || null,
    active: true,
    created_at: new Date().toISOString(),
    deleted_at: null
  };
  await storage.append("webhook_subscriptions", subscription);
  await storage.audit(tenantId, "webhook_subscription_created", {
    subscription_id: subscription.subscription_id,
    event_types: eventTypes
  });
  return maskSubscription(subscription);
}

export async function listWebhookSubscriptions(storage, tenantId) {
  const records = await storage.list("webhook_subscriptions", tenantId);
  return records.filter((record) => record.active !== false).map(maskSubscription);
}

export async function deleteWebhookSubscription(storage, tenantId, subscriptionId) {
  const updated = await storage.replace(
    "webhook_subscriptions",
    (record) => record.tenant_id === tenantId && record.subscription_id === subscriptionId && record.active !== false,
    (record) => ({ ...record, active: false, deleted_at: new Date().toISOString() })
  );
  if (!updated) {
    return null;
  }
  await storage.audit(tenantId, "webhook_subscription_deleted", { subscription_id: subscriptionId });
  return maskSubscription(updated);
}

export async function listWebhookDeliveries(storage, tenantId) {
  return storage.list("webhook_deliveries", tenantId);
}

// Fire-and-forget dispatch. Callers should invoke as
// `void dispatchWebhookEvent(...)` (or not await); this function never throws.
export async function dispatchWebhookEvent({
  storage,
  tenantId,
  eventType,
  data = {},
  fetchImpl = globalThis.fetch,
  baseDelayMs = DEFAULT_RETRY_BASE_MS
}) {
  try {
    const subscriptions = (await storage.list("webhook_subscriptions", tenantId))
      .filter((record) => record.active !== false && (record.event_types || []).includes(eventType));
    if (!subscriptions.length) {
      return [];
    }
    const payload = JSON.stringify({
      event_type: eventType,
      tenant_id: tenantId,
      occurred_at: new Date().toISOString(),
      boundary: {
        advisory_only: true,
        no_patch_deployment: true,
        no_autonomous_approval: true
      },
      data
    });
    const results = [];
    for (const subscription of subscriptions) {
      results.push(await deliverWithRetry({ storage, tenantId, subscription, eventType, payload, fetchImpl, baseDelayMs }));
    }
    return results;
  } catch (error) {
    logger.warn("webhook_dispatch_failed", { tenant: tenantId, event_type: eventType, message: error.message });
    return [];
  }
}

async function deliverWithRetry({ storage, tenantId, subscription, eventType, payload, fetchImpl, baseDelayMs }) {
  const headers = {
    "content-type": "application/json",
    "x-patchforge-event": eventType,
    "x-patchforge-delivery": `del-${randomUUID()}`
  };
  if (subscription.secret) {
    headers["x-patchforge-signature"] = `sha256=${createHmac("sha256", subscription.secret).update(payload).digest("hex")}`;
  }
  const attempts = [];
  let delivered = false;
  let responseStatus = null;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetchImpl(subscription.url, { method: "POST", headers, body: payload });
      responseStatus = response.status;
      attempts.push({ attempt, status: response.status, at: new Date().toISOString() });
      if (response.ok) {
        delivered = true;
        break;
      }
    } catch (error) {
      attempts.push({ attempt, status: null, error: error.message, at: new Date().toISOString() });
    }
    if (attempt < MAX_ATTEMPTS) {
      await sleep(baseDelayMs * 2 ** (attempt - 1));
    }
  }
  const delivery = {
    tenant_id: tenantId,
    delivery_id: headers["x-patchforge-delivery"],
    subscription_id: subscription.subscription_id,
    event_type: eventType,
    url: subscription.url,
    signed: Boolean(subscription.secret),
    status: delivered ? "delivered" : "failed",
    response_status: responseStatus,
    attempt_count: attempts.length,
    attempts,
    completed_at: new Date().toISOString()
  };
  try {
    await storage.append("webhook_deliveries", delivery);
  } catch (error) {
    logger.warn("webhook_delivery_record_failed", { tenant: tenantId, message: error.message });
  }
  return delivery;
}

function maskSubscription(subscription) {
  return {
    ...subscription,
    secret: subscription.secret ? "********" : null,
    has_secret: Boolean(subscription.secret)
  };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

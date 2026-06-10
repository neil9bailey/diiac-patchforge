import { randomUUID } from "node:crypto";
import { validateBody, validIsoDate, validationError } from "./validate.js";
import { dispatchWebhookEvent } from "./webhooks.js";

// PF-AZ12 contract section 3: governed risk acceptances.
// Boundary: PatchForge records human risk-acceptance decisions; it never
// accepts risk autonomously, and expired acceptances can never satisfy
// governance posture.

const REVIEW_ACTIONS = ["accept", "reject", "extend"];
const EXPIRING_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

export function riskAcceptanceBoundary() {
  return {
    advisory_only: true,
    human_decision_recorded_only: true,
    no_autonomous_risk_acceptance: true,
    no_patch_deployment: true,
    expired_acceptances_cannot_satisfy_posture: true
  };
}

export async function createRiskAcceptance(storage, tenantId, body = {}) {
  validateBody(body, {
    vulnerability_id: { required: true, type: "string", maxLength: 200 },
    scope_description: { required: true, type: "string", maxLength: 4000 },
    justification: { required: true, type: "string", maxLength: 4000 },
    owner_upn: { required: true, type: "string", maxLength: 320 },
    expires_at: { required: true, type: "string", maxLength: 64 },
    compensating_control_ids: { type: "array", items: "string" }
  });
  const expiresAt = validIsoDate(body.expires_at, "expires_at");
  const now = new Date().toISOString();
  const record = {
    tenant_id: tenantId,
    risk_acceptance_id: body.risk_acceptance_id || `ra-${randomUUID()}`,
    vulnerability_id: body.vulnerability_id,
    scope_description: body.scope_description,
    justification: body.justification,
    owner_upn: body.owner_upn,
    requested_by: body.requested_by || body.actor_upn || null,
    expires_at: expiresAt,
    status: "proposed",
    compensating_control_ids: Array.isArray(body.compensating_control_ids) ? body.compensating_control_ids : [],
    review_events: [],
    expiry_notified_at: null,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    created_at: now,
    updated_at: now
  };
  await storage.append("risk_acceptances", record);
  await storage.audit(tenantId, "risk_acceptance_created", {
    risk_acceptance_id: record.risk_acceptance_id,
    vulnerability_id: record.vulnerability_id,
    owner_upn: record.owner_upn,
    expires_at: record.expires_at,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null
  });
  return withDerivedStatus(record);
}

export async function listRiskAcceptances(storage, tenantId, { notifyExpiring = true, webhookFetchImpl } = {}) {
  const records = await storage.list("risk_acceptances", tenantId);
  const derived = records.map((record) => withDerivedStatus(record));
  if (notifyExpiring) {
    await notifyExpiringRiskAcceptances(storage, tenantId, derived, webhookFetchImpl);
  }
  return derived;
}

export async function getRiskAcceptance(storage, tenantId, riskAcceptanceId) {
  const records = await storage.list("risk_acceptances", tenantId);
  const record = records.find((item) => item.risk_acceptance_id === riskAcceptanceId);
  return record ? withDerivedStatus(record) : null;
}

export async function reviewRiskAcceptance(storage, tenantId, riskAcceptanceId, body = {}) {
  validateBody(body, {
    action: { required: true, type: "string", enum: REVIEW_ACTIONS },
    notes: { type: "string", maxLength: 4000 },
    expires_at: { type: "string", maxLength: 64 }
  });
  if (body.action === "extend" && !body.expires_at) {
    throw validationError("A new expires_at is required when extending a risk acceptance.", "expires_at");
  }
  const newExpiresAt = body.action === "extend" ? validIsoDate(body.expires_at, "expires_at") : null;
  const now = new Date().toISOString();
  const reviewEvent = {
    action: body.action,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    notes: body.notes || "",
    recorded_at: now
  };
  const updated = await storage.replace(
    "risk_acceptances",
    (record) => record.tenant_id === tenantId && record.risk_acceptance_id === riskAcceptanceId,
    (record) => ({
      ...record,
      status: body.action === "accept" ? "accepted" : body.action === "reject" ? "rejected" : record.status,
      expires_at: newExpiresAt || record.expires_at,
      expiry_notified_at: newExpiresAt ? null : record.expiry_notified_at,
      review_events: [...(record.review_events || []), reviewEvent],
      updated_at: now
    })
  );
  if (!updated) {
    return null;
  }
  await storage.audit(tenantId, "risk_acceptance_reviewed", {
    risk_acceptance_id: riskAcceptanceId,
    action: body.action,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    expires_at: updated.expires_at
  });
  return withDerivedStatus(updated);
}

// status is derived as "expired" whenever expires_at is in the past,
// regardless of stored state (contract section 3).
export function withDerivedStatus(record, now = Date.now()) {
  const expiresAt = Date.parse(record.expires_at || "");
  if (Number.isFinite(expiresAt) && expiresAt < now) {
    return { ...record, status: "expired", stored_status: record.status };
  }
  return { ...record };
}

async function notifyExpiringRiskAcceptances(storage, tenantId, records, webhookFetchImpl) {
  const now = Date.now();
  for (const record of records) {
    const expiresAt = Date.parse(record.expires_at || "");
    if (!Number.isFinite(expiresAt) || record.expiry_notified_at) {
      continue;
    }
    if (expiresAt - now > EXPIRING_WINDOW_MS) {
      continue;
    }
    await storage.replace(
      "risk_acceptances",
      (item) => item.tenant_id === tenantId && item.risk_acceptance_id === record.risk_acceptance_id,
      (item) => ({ ...item, expiry_notified_at: new Date().toISOString() })
    );
    void dispatchWebhookEvent({
      storage,
      tenantId,
      eventType: "risk_acceptance.expiring",
      fetchImpl: webhookFetchImpl,
      data: {
        risk_acceptance_id: record.risk_acceptance_id,
        vulnerability_id: record.vulnerability_id,
        owner_upn: record.owner_upn,
        expires_at: record.expires_at,
        status: record.status
      }
    });
  }
}

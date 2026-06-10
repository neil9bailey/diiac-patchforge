import { randomUUID } from "node:crypto";
import { validateBody } from "./validate.js";

// PF-AZ12 contract section 4: governed compensating controls.
// Boundary: PatchForge records control evidence for human review; it never
// deploys, verifies, or approves controls autonomously.

const REVIEW_ACTIONS = ["accept", "reject"];

export function compensatingControlBoundary() {
  return {
    advisory_only: true,
    human_review_required: true,
    no_autonomous_approval: true,
    no_patch_deployment: true,
    no_production_mutation: true
  };
}

export async function createCompensatingControl(storage, tenantId, body = {}) {
  validateBody(body, {
    name: { required: true, type: "string", maxLength: 300 },
    description: { required: true, type: "string", maxLength: 4000 },
    owner_upn: { required: true, type: "string", maxLength: 320 },
    mitigates_vulnerability_ids: { type: "array", items: "string" },
    evidence_refs: { type: "array", items: "string" },
    expires_at: { type: "string", maxLength: 64 }
  });
  const now = new Date().toISOString();
  const record = {
    tenant_id: tenantId,
    control_id: body.control_id || `cc-${randomUUID()}`,
    name: body.name,
    description: body.description,
    mitigates_vulnerability_ids: Array.isArray(body.mitigates_vulnerability_ids) ? body.mitigates_vulnerability_ids : [],
    owner_upn: body.owner_upn,
    evidence_refs: Array.isArray(body.evidence_refs) ? body.evidence_refs : [],
    review_state: "pending_review",
    expires_at: body.expires_at || null,
    review_events: [],
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    created_at: now,
    updated_at: now
  };
  await storage.append("compensating_controls", record);
  await storage.audit(tenantId, "compensating_control_created", {
    control_id: record.control_id,
    name: record.name,
    owner_upn: record.owner_upn,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null
  });
  return record;
}

export async function listCompensatingControls(storage, tenantId) {
  return storage.list("compensating_controls", tenantId);
}

export async function reviewCompensatingControl(storage, tenantId, controlId, body = {}) {
  validateBody(body, {
    action: { required: true, type: "string", enum: REVIEW_ACTIONS },
    notes: { type: "string", maxLength: 4000 }
  });
  const now = new Date().toISOString();
  const reviewEvent = {
    action: body.action,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    notes: body.notes || "",
    recorded_at: now
  };
  const updated = await storage.replace(
    "compensating_controls",
    (record) => record.tenant_id === tenantId && record.control_id === controlId,
    (record) => ({
      ...record,
      review_state: body.action === "accept" ? "accepted" : "rejected",
      review_events: [...(record.review_events || []), reviewEvent],
      updated_at: now
    })
  );
  if (!updated) {
    return null;
  }
  await storage.audit(tenantId, "compensating_control_reviewed", {
    control_id: controlId,
    action: body.action,
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null
  });
  return updated;
}

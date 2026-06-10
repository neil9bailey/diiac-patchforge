import { validateBody } from "./validate.js";

// PF-AZ12 contract section 5: named approval chain for decision packs.
// Boundary: approvals are recorded human decisions with named accountability.
// PatchForge never approves anything autonomously; final_approval_recorded is
// a derivation over recorded human approval events, not an approval action.

const ADMIN_ROLE = "PatchForge.Admin";

export const DEFAULT_APPROVAL_POLICY = Object.freeze({
  required_roles: Object.freeze(["PatchForge.SecurityLead", "PatchForge.CABApprover"]),
  distinct_approvers: true
});

export function approvalBoundary() {
  return {
    human_approval_records_only: true,
    no_autonomous_approval: true,
    no_patch_deployment: true,
    separation_of_duties_enforced: true
  };
}

export function resolveApprovalPolicy(adminConfig = {}) {
  const policy = adminConfig.approval_policy || {};
  const requiredRoles = Array.isArray(policy.required_roles) && policy.required_roles.length
    ? policy.required_roles.map((role) => String(role))
    : [...DEFAULT_APPROVAL_POLICY.required_roles];
  return {
    required_roles: requiredRoles,
    distinct_approvers: policy.distinct_approvers === undefined
      ? DEFAULT_APPROVAL_POLICY.distinct_approvers
      : Boolean(policy.distinct_approvers)
  };
}

export function buildApprovalEvent({ principal = null, body = {} }) {
  validateBody(body, {
    decision_posture: { required: true, type: "string", maxLength: 120 },
    notes: { type: "string", maxLength: 4000 }
  });
  const fromPrincipal = principal && !principal.auth_disabled ? principal : null;
  return {
    approver_oid: fromPrincipal?.oid || body.approver_oid || null,
    approver_upn: fromPrincipal?.upn || body.approver_upn || null,
    approver_roles: fromPrincipal?.roles || (Array.isArray(body.approver_roles) ? body.approver_roles : []),
    decision_posture: body.decision_posture,
    notes: body.notes || "",
    recorded_at: new Date().toISOString()
  };
}

// True only when every required role is covered by an approval event, and
// (when distinct_approvers) each required role is satisfied by a different
// approver. An Admin approval may stand in for any single required role, but
// one Admin cannot satisfy two required roles when distinct_approvers is set.
export function deriveFinalApprovalRecorded(approvalEvents = [], policy = DEFAULT_APPROVAL_POLICY) {
  const requiredRoles = policy.required_roles || [];
  if (!requiredRoles.length) {
    return approvalEvents.length > 0;
  }
  const events = approvalEvents.filter((event) => event && (event.approver_oid || event.approver_upn));
  if (!policy.distinct_approvers) {
    return requiredRoles.every((role) =>
      events.some((event) => eventSatisfiesRole(event, role)));
  }
  // Greedy assignment with backtracking over distinct approver identities.
  const approvers = new Map();
  for (const event of events) {
    const identity = event.approver_oid || event.approver_upn;
    if (!approvers.has(identity)) {
      approvers.set(identity, new Set());
    }
    for (const role of event.approver_roles || []) {
      approvers.get(identity).add(role);
    }
  }
  const identities = [...approvers.keys()];
  const assign = (roleIndex, used) => {
    if (roleIndex >= requiredRoles.length) {
      return true;
    }
    const role = requiredRoles[roleIndex];
    for (const identity of identities) {
      if (used.has(identity)) {
        continue;
      }
      const roles = approvers.get(identity);
      if (roles.has(role) || roles.has(ADMIN_ROLE)) {
        used.add(identity);
        if (assign(roleIndex + 1, used)) {
          return true;
        }
        used.delete(identity);
      }
    }
    return false;
  };
  return assign(0, new Set());
}

function eventSatisfiesRole(event, role) {
  const roles = event.approver_roles || [];
  return roles.includes(role) || roles.includes(ADMIN_ROLE);
}

export async function recordDecisionPackApproval(storage, tenantId, packId, { principal = null, body = {} }) {
  const approvalEvent = buildApprovalEvent({ principal, body });
  const adminConfig = await storage.readAdminConfig(tenantId);
  const policy = resolveApprovalPolicy(adminConfig);
  const updated = await storage.replace(
    "decision_packs",
    (record) => record.tenant_id === tenantId && (record.pack_id === packId || record.decision_pack_id === packId),
    (record) => {
      const approvalEvents = [...(record.approval_events || []), approvalEvent];
      return {
        ...record,
        approval_events: approvalEvents,
        final_approval_recorded: deriveFinalApprovalRecorded(approvalEvents, policy),
        updated_at: approvalEvent.recorded_at
      };
    }
  );
  if (!updated) {
    return null;
  }
  await storage.audit(tenantId, "decision_pack_approval_recorded", {
    pack_id: packId,
    approver_oid: approvalEvent.approver_oid,
    approver_upn: approvalEvent.approver_upn,
    decision_posture: approvalEvent.decision_posture,
    final_approval_recorded: updated.final_approval_recorded
  });
  return { pack: updated, policy };
}

export async function listDecisionPackApprovals(storage, tenantId, packId) {
  const packs = await storage.list("decision_packs", tenantId);
  const pack = packs.find((record) => record.pack_id === packId || record.decision_pack_id === packId);
  if (!pack) {
    return null;
  }
  const adminConfig = await storage.readAdminConfig(tenantId);
  const policy = resolveApprovalPolicy(adminConfig);
  return {
    approval_events: pack.approval_events || [],
    final_approval_recorded: Boolean(pack.final_approval_recorded),
    approval_policy: policy
  };
}

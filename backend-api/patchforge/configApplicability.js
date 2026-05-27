const REVIEWED_STATES = new Set(["reviewed", "accepted", "approved"]);
const POSITIVE_EVIDENCE_STATES = new Set(["accepted_positive_evidence", "reviewed", "attached"]);

export function assessConfigApplicability(input = {}) {
  const advisory = input.advisory || {};
  const asset = input.asset || {};
  const now = input.generated_at || new Date().toISOString();
  const affectedFeature = firstValue(advisory.affected_feature, advisory.affected_features, advisory.feature);
  const featureState = featureEnabledStatus(asset, affectedFeature);
  const reviewedAssetEvidence = isReviewed(asset.review_state) && isPositiveEvidence(asset.evidence_state);
  const reviewedConfigEvidence = reviewedAssetEvidence || hasReviewedConfigEvidence(asset);
  const versionStatus = affectedVersionStatus(advisory, asset);
  const productStatus = productMatchStatus(advisory, asset);
  const exposureStatus = exposureStatusFor(asset);
  const knownExploited = Boolean(advisory.known_exploited || advisory.kev || input.known_exploited);
  const patchAvailable = Boolean(advisory.patch_available || advisory.fixed_versions?.length || input.patch_available);
  const evidenceGaps = [];
  const evidenceRequired = new Set();

  if (!asset.asset_id && !asset.model && !asset.product_family) {
    evidenceGaps.push(gap("customer_network_asset", "Reviewed customer network asset inventory is not attached.", "CMDB, device inventory, asset owner confirmation, or network management export."));
    evidenceRequired.add("customer_network_asset_inventory");
  }
  if (productStatus === "unknown" || productStatus === "unmatched_pending_review") {
    evidenceGaps.push(gap("product_model_mapping", "Vendor product, model, or family cannot be matched with reviewed confidence.", "Vendor product family record, model inventory, and source advisory affected-product mapping."));
    evidenceRequired.add("reviewed_product_model_mapping");
  }
  if (versionStatus === "unknown") {
    evidenceGaps.push(gap("firmware_version", "Firmware or software version is missing or not comparable.", "Reviewed firmware version evidence from device inventory, show command output, controller inventory, or vendor console export."));
    evidenceRequired.add("reviewed_firmware_version");
  }
  if (affectedFeature && featureState === "disabled_unreviewed") {
    evidenceGaps.push(gap("feature_disabled_review", `${humanize(affectedFeature)} is recorded as disabled, but that configuration evidence is not reviewed.`, "Reviewed configuration export, change record, service owner attestation, or device configuration evidence."));
    evidenceRequired.add("reviewed_feature_configuration");
  }
  if (affectedFeature && featureState === "unknown") {
    evidenceGaps.push(gap("feature_state", `${humanize(affectedFeature)} feature state is not known for this asset.`, "Reviewed enabled/disabled feature list or configuration evidence."));
    evidenceRequired.add("reviewed_feature_state");
  }
  if (exposureStatus === "unknown") {
    evidenceGaps.push(gap("exposure_state", "Internet or management-plane exposure is not reviewed.", "Firewall rule evidence, public DNS/NAT record, management exposure record, or network owner confirmation."));
    evidenceRequired.add("reviewed_exposure_state");
  }
  if (!isReviewed(advisory.review_state) || !isPositiveEvidence(advisory.evidence_state)) {
    evidenceGaps.push(gap("advisory_source_review", "The vendor/CVE source record has not been accepted as positive evidence.", "Named reviewer event accepting the source record, affected versions, affected feature, and source provenance."));
    evidenceRequired.add("reviewed_vendor_advisory");
  }

  const applicabilityPosture = deriveApplicabilityPosture({
    advisory,
    asset,
    versionStatus,
    productStatus,
    featureState,
    reviewedAssetEvidence,
    reviewedConfigEvidence,
    evidenceGaps
  });
  const urgencyPosture = deriveUrgencyPosture({
    applicabilityPosture,
    versionStatus,
    featureState,
    exposureStatus,
    knownExploited,
    patchAvailable,
    reviewedConfigEvidence,
    evidenceGaps
  });

  return {
    assessment_id: input.assessment_id || `cfg-app-${Date.now()}`,
    generated_at: now,
    tenant_id: input.tenant_id || advisory.tenant_id || asset.tenant_id || null,
    advisory_id: advisory.advisory_id || input.advisory_id || null,
    cve: advisory.cve || firstValue(advisory.cves) || input.cve || null,
    asset_id: asset.asset_id || input.asset_id || null,
    vendor_id: advisory.vendor_id || asset.vendor_id || input.vendor_id || null,
    product_family: asset.product_family || firstValue(advisory.affected_products) || null,
    model: asset.model || null,
    firmware_version: asset.firmware_version || null,
    affected_feature: affectedFeature || null,
    affected_version_status: versionStatus,
    affected_feature_status: affectedFeature ? (featureState === "enabled" ? "affected_feature_present" : featureState) : "not_specified",
    feature_enabled_status: featureState,
    exposure_status: exposureStatus,
    applicability_posture: applicabilityPosture,
    urgency_posture: urgencyPosture,
    evidence_required: Array.from(evidenceRequired),
    evidence_gaps: evidenceGaps,
    evidence_used: evidenceUsed(advisory, asset),
    source_bound: true,
    advisory_only: true,
    human_review_required: true,
    can_close_hard_gates_alone: false,
    final_approval_issued: false,
    decision_not_allowed_yet: decisionNotAllowedYet(applicabilityPosture, evidenceGaps),
    boundary: {
      no_scanner: true,
      no_procedural_exploitation_steps: true,
      no_patch_deployment: true,
      no_production_mutation: true,
      no_autonomous_approval: true,
      no_autonomous_risk_acceptance: true
    }
  };
}

function deriveApplicabilityPosture({ advisory, asset, versionStatus, productStatus, featureState, reviewedAssetEvidence, reviewedConfigEvidence, evidenceGaps }) {
  if (asset.not_in_estate === true && reviewedAssetEvidence) {
    return "not_applicable";
  }
  if (asset.not_in_estate === true) {
    return "requires_review";
  }
  if (productStatus === "unmatched_reviewed" && reviewedAssetEvidence) {
    return "not_applicable";
  }
  if (versionStatus === "not_affected" && reviewedAssetEvidence) {
    return "not_applicable";
  }
  if (featureState === "disabled_reviewed" && reviewedConfigEvidence) {
    return "not_applicable";
  }
  if (featureState === "disabled_unreviewed") {
    return "requires_review";
  }
  if (versionStatus === "affected" && ["enabled", "not_specified"].includes(featureState)) {
    return "applicable";
  }
  if (versionStatus === "unknown" || productStatus === "unknown" || evidenceGaps.length) {
    return "requires_review";
  }
  if (advisory.cve || advisory.advisory_id) {
    return "conditional";
  }
  return "unknown";
}

function deriveUrgencyPosture({ applicabilityPosture, versionStatus, featureState, exposureStatus, knownExploited, patchAvailable, reviewedConfigEvidence, evidenceGaps }) {
  if (applicabilityPosture === "not_applicable" && reviewedConfigEvidence) {
    return "monitor";
  }
  if (featureState === "disabled_unreviewed") {
    return "urgent_scope_confirmation_required";
  }
  if (versionStatus === "unknown" || evidenceGaps.some((item) => ["customer_network_asset", "firmware_version", "feature_state"].includes(item.gap_id))) {
    return knownExploited ? "urgent_scope_confirmation_required" : "no_action_pending_review";
  }
  if (knownExploited && exposureStatus === "internet_or_management_exposed" && applicabilityPosture === "applicable") {
    return patchAvailable ? "emergency_patch_required" : "urgent_scope_confirmation_required";
  }
  if (applicabilityPosture === "applicable" && patchAvailable) {
    return "patch_required";
  }
  if (applicabilityPosture === "applicable") {
    return "mitigate_temporarily";
  }
  return "no_action_pending_review";
}

function affectedVersionStatus(advisory, asset) {
  const version = normalize(asset.firmware_version || asset.software_version);
  if (!version) {
    return "unknown";
  }
  const affected = list(advisory.affected_versions).map(normalize);
  const fixed = list(advisory.fixed_versions).map(normalize);
  if (fixed.includes(version)) {
    return "fixed_version_recorded_pending_review";
  }
  if (!affected.length) {
    return "unknown";
  }
  if (affected.includes(version) || affected.includes("*")) {
    return "affected";
  }
  return isReviewed(asset.review_state) ? "not_affected" : "not_listed_pending_review";
}

function productMatchStatus(advisory, asset) {
  const assetTerms = list(asset.product_family, asset.model, asset.product_id).map(normalize).filter(Boolean);
  const advisoryTerms = list(advisory.product_id, advisory.product_family, advisory.affected_products, advisory.affected_models).map(normalize).filter(Boolean);
  if (!assetTerms.length || !advisoryTerms.length) {
    return "unknown";
  }
  const matched = assetTerms.some((assetTerm) => advisoryTerms.some((term) => term === assetTerm || term.includes(assetTerm) || assetTerm.includes(term)));
  if (matched) {
    return "matched";
  }
  return isReviewed(asset.review_state) ? "unmatched_reviewed" : "unmatched_pending_review";
}

function featureEnabledStatus(asset, feature) {
  if (!feature) {
    return "not_specified";
  }
  const enabled = list(asset.enabled_features).map(normalize);
  const disabled = list(asset.disabled_features).map(normalize);
  const normalizedFeature = normalize(feature);
  if (enabled.includes(normalizedFeature)) {
    return "enabled";
  }
  if (disabled.includes(normalizedFeature)) {
    return hasReviewedConfigEvidence(asset) ? "disabled_reviewed" : "disabled_unreviewed";
  }
  return "unknown";
}

function exposureStatusFor(asset) {
  const management = normalize(asset.management_exposure || asset.exposure || "");
  if (asset.internet_facing === true || ["internet", "internet_facing", "public", "public_management", "external"].includes(management)) {
    return "internet_or_management_exposed";
  }
  if (asset.internet_facing === false || ["internal", "private", "none"].includes(management)) {
    return isReviewed(asset.review_state) ? "not_internet_exposed_reviewed" : "not_internet_exposed_pending_review";
  }
  return "unknown";
}

function evidenceUsed(advisory, asset) {
  return [
    advisory.source_url ? { evidence_type: "vendor_advisory", ref: advisory.advisory_id || advisory.source_url, review_state: advisory.review_state || "pending_review" } : null,
    asset.asset_id ? { evidence_type: "customer_network_asset", ref: asset.asset_id, review_state: asset.review_state || "pending_review" } : null,
    ...list(asset.config_evidence_refs).map((ref) => ({ evidence_type: "configuration_evidence", ref, review_state: asset.review_state || "pending_review" }))
  ].filter(Boolean);
}

function decisionNotAllowedYet(applicabilityPosture, evidenceGaps) {
  if (applicabilityPosture === "not_applicable" && !evidenceGaps.length) {
    return "Not-applicable status can be recommended for review, but final approval still requires a named human reviewer.";
  }
  return "Final remediation, risk acceptance, closure, and not-applicable decisions cannot be issued until the evidence gaps are resolved and a human reviewer approves the outcome.";
}

function hasReviewedConfigEvidence(asset) {
  return isReviewed(asset.review_state)
    && isPositiveEvidence(asset.evidence_state)
    && list(asset.config_evidence_refs).length > 0;
}

function isReviewed(value) {
  return REVIEWED_STATES.has(normalize(value));
}

function isPositiveEvidence(value) {
  return POSITIVE_EVIDENCE_STATES.has(normalize(value));
}

function gap(gapId, plainEnglishGap, requiredEvidence) {
  return {
    gap_id: gapId,
    plain_english_gap: plainEnglishGap,
    why_it_matters: "PatchForge cannot support an accountable customer/CAB decision without reviewed evidence for this point.",
    required_evidence: requiredEvidence,
    suggested_owner_role: ownerForGap(gapId),
    next_decision_gate: gateForGap(gapId)
  };
}

function ownerForGap(gapId) {
  if (gapId.includes("asset")) {
    return "Network asset owner";
  }
  if (gapId.includes("feature") || gapId.includes("config")) {
    return "Network engineering lead";
  }
  if (gapId.includes("advisory")) {
    return "Security lead";
  }
  return "Service owner";
}

function gateForGap(gapId) {
  if (gapId.includes("advisory")) {
    return "Source review";
  }
  if (gapId.includes("feature") || gapId.includes("config")) {
    return "Configuration applicability review";
  }
  return "Scope confirmation";
}

function firstValue(...values) {
  for (const value of values) {
    const items = list(value);
    if (items.length) {
      return items[0];
    }
  }
  return null;
}

function list(...values) {
  return values.flatMap((value) => {
    if (Array.isArray(value)) {
      return value.flatMap((item) => list(item));
    }
    if (value === undefined || value === null || value === "") {
      return [];
    }
    return String(value).split(",").map((item) => item.trim()).filter(Boolean);
  });
}

function normalize(value) {
  return String(value || "").trim().toLowerCase().replace(/\s+/g, "_");
}

function humanize(value) {
  return String(value || "").replace(/[_-]+/g, " ");
}

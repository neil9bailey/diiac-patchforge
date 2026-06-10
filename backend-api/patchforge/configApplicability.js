import {
  MATCH_BASIS,
  cpeEntriesMatchVendorProduct,
  extractCpes,
  versionCompare,
  versionSatisfiesAny
} from "./versionUtils.js";

const REVIEWED_STATES = new Set(["reviewed", "accepted", "approved"]);
const POSITIVE_EVIDENCE_STATES = new Set(["accepted_positive_evidence", "reviewed", "attached"]);

const PRODUCT_ALIAS_GROUPS = [
  ["fortigate", "fortios", "fortinet_firewall", "fortinet_firewall_platform"],
  ["pan_os", "panos", "palo_alto_firewall", "palo_alto_networks_firewall", "globalprotect_gateway"],
  ["cisco_asa", "asa", "firepower", "ftd", "firepower_threat_defense", "anyconnect_gateway"],
  ["citrix_adc", "netscaler_adc", "netscaler_gateway", "citrix_netscaler"],
  ["f5_big_ip", "big_ip", "bigip", "icontrol_rest"],
  ["junos", "junos_os", "srx", "juniper_srx"]
];

const FEATURE_ALIAS_GROUPS = [
  ["ssl_vpn", "ssl-vpn", "ssl vpn", "webvpn", "remote_access_vpn"],
  ["globalprotect", "global protect", "globalprotect_portal", "globalprotect_gateway"],
  ["anyconnect", "cisco_anyconnect", "anyconnect_vpn"],
  ["icontrol_rest", "icontrol rest", "i control rest"],
  ["web_management", "management_interface", "management interface", "api_management", "api management", "admin_web_ui"]
];

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
    evidenceGaps.push(gap("customer_network_asset", "Reviewed customer network asset inventory is not attached.", "CMDB, device inventory, asset owner confirmation, or network management export.", "Network asset owner", "Scope confirmation", ["CMDB export", "firewall manager inventory", "asset owner confirmation"], "missing"));
    evidenceRequired.add("customer_network_asset_inventory");
  }
  if (productStatus === "unknown" || productStatus === "unmatched_pending_review") {
    evidenceGaps.push(gap("product_model_mapping", "Vendor product, model, or family cannot be matched with reviewed confidence.", "Vendor product family record, model inventory, and source advisory affected-product mapping.", "Network asset owner", "Scope confirmation", ["vendor product family", "model inventory", "affected product list"], productStatus));
    evidenceRequired.add("reviewed_product_model_mapping");
  }
  if (["unknown", "fixed_version_pending_review", "not_listed_pending_review"].includes(versionStatus)) {
    evidenceGaps.push(gap("firmware_version", "Firmware or software version is missing, unreviewed, or not yet comparable against affected/fixed vendor ranges.", "Reviewed firmware version evidence from device inventory, show command output, controller inventory, or vendor console export.", "Network engineering lead", "Configuration applicability review", ["device inventory", "show version output", "controller export", "vendor console export"], versionStatus));
    evidenceRequired.add("reviewed_firmware_version");
  }
  if (affectedFeature && featureState === "disabled_unreviewed") {
    evidenceGaps.push(gap("feature_disabled_review", `${humanize(affectedFeature)} is recorded as disabled, but that configuration evidence is not reviewed.`, "Reviewed configuration export, change record, service owner attestation, or device configuration evidence.", "Network engineering lead", "Configuration applicability review", ["reviewed running configuration", "feature disable change record", "device configuration export"], featureState));
    evidenceRequired.add("reviewed_feature_configuration");
  }
  if (affectedFeature && featureState === "unknown") {
    evidenceGaps.push(gap("feature_state", `${humanize(affectedFeature)} feature state is not known for this asset.`, "Reviewed enabled/disabled feature list or configuration evidence.", "Network engineering lead", "Configuration applicability review", ["feature inventory", "running configuration", "firewall manager feature export"], featureState));
    evidenceRequired.add("reviewed_feature_state");
  }
  if (exposureStatus === "unknown") {
    evidenceGaps.push(gap("exposure_state", "Internet or management-plane exposure is not reviewed.", "Firewall rule evidence, public DNS/NAT record, management exposure record, or network owner confirmation.", "Network engineering lead", "Exposure review", ["firewall rule evidence", "public DNS/NAT record", "management exposure attestation"], exposureStatus));
    evidenceRequired.add("reviewed_exposure_state");
  }
  if (!isReviewed(advisory.review_state) || !isPositiveEvidence(advisory.evidence_state)) {
    evidenceGaps.push(gap("advisory_source_review", "The vendor/CVE source record has not been accepted as positive evidence.", "Named reviewer event accepting the source record, affected versions, affected feature, and source provenance.", "Security lead", "Source review", ["vendor advisory", "CVE record", "CISA KEV record", "review event"], advisory.review_state || "pending_review"));
    evidenceRequired.add("reviewed_vendor_advisory");
  }
  if (advisory.superseded === true && !isReviewed(advisory.supersedence_review_state || advisory.superseded_review_state)) {
    evidenceGaps.push(gap("superseded_advisory_review", "This advisory is marked superseded, but supersedence has not been reviewed.", "Reviewed superseding advisory reference, withdrawal/supersedence notice, and reviewer decision explaining which source remains authoritative.", "Security lead", "Source review", ["superseding advisory", "vendor supersedence notice", "review decision"], "superseded_pending_review"));
    evidenceRequired.add("reviewed_supersedence");
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
    match_basis: deriveMatchBasis({ advisory, asset, versionStatus }),
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

// PF-AZ12 section 9: expose match confidence so users can see whether an
// applicability assessment rests on CPE data, version ranges, identifiers, or
// plain string matching. Advisory-only metadata; it closes no gates.
function deriveMatchBasis({ advisory = {}, asset = {}, versionStatus = "unknown" }) {
  const advisoryCpes = extractCpes(advisory);
  const version = String(asset.firmware_version || asset.software_version || "").trim();
  if (advisoryCpes.length && cpeEntriesMatchVendorProduct(advisoryCpes, {
    vendor: asset.vendor_id || asset.vendor_name,
    product: asset.product_family || asset.model || asset.product_id,
    version: version || null
  })) {
    return MATCH_BASIS.CPE_VERSION_RANGE;
  }
  const hasVersionEvidence = Boolean(version)
    && (list(advisory.affected_versions).length || list(advisory.fixed_versions).length)
    && versionStatus !== "unknown";
  if (hasVersionEvidence) {
    return MATCH_BASIS.VERSION_RANGE;
  }
  if (advisory.cve || advisory.advisory_id) {
    return MATCH_BASIS.IDENTIFIER;
  }
  return MATCH_BASIS.STRING_FALLBACK;
}

function deriveApplicabilityPosture({ advisory, asset, versionStatus, productStatus, featureState, reviewedAssetEvidence, reviewedConfigEvidence, evidenceGaps }) {
  if (advisory.superseded === true && !isReviewed(advisory.supersedence_review_state || advisory.superseded_review_state)) {
    return "requires_review";
  }
  if (asset.not_in_estate === true && reviewedAssetEvidence) {
    return "not_applicable";
  }
  if (asset.not_in_estate === true) {
    return "requires_review";
  }
  if (productStatus === "unmatched_reviewed" && reviewedAssetEvidence) {
    return "not_applicable";
  }
  if (["not_affected", "fixed_version_reviewed"].includes(versionStatus) && reviewedAssetEvidence) {
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
  const version = String(asset.firmware_version || asset.software_version || "").trim();
  if (!version) {
    return "unknown";
  }
  const affected = list(advisory.affected_versions);
  const fixed = list(advisory.fixed_versions);
  const reviewedVersionEvidence = isReviewed(asset.review_state) && isPositiveEvidence(asset.evidence_state);
  if (fixed.some((fixedVersion) => versionCompare(version, fixedVersion) >= 0)) {
    return reviewedVersionEvidence ? "fixed_version_reviewed" : "fixed_version_pending_review";
  }
  if (fixed.length && fixed.every((fixedVersion) => versionCompare(version, fixedVersion) < 0)) {
    return "affected";
  }
  if (!affected.length) {
    return "unknown";
  }
  if (versionSatisfiesAny(version, affected)) {
    return "affected";
  }
  return reviewedVersionEvidence ? "not_affected" : "not_listed_pending_review";
}

function productMatchStatus(advisory, asset) {
  const assetTerms = expandProductTerms(list(asset.vendor_id, asset.product_family, asset.model, asset.product_id));
  const advisoryTerms = expandProductTerms(list(advisory.vendor_id, advisory.product_id, advisory.product_family, advisory.affected_products, advisory.affected_models));
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
  const enabled = expandFeatureTerms(list(asset.enabled_features));
  const disabled = expandFeatureTerms(list(asset.disabled_features));
  const featureTerms = expandFeatureTerms(list(feature));
  if (featureTerms.some((term) => enabled.includes(term))) {
    return "enabled";
  }
  if (featureTerms.some((term) => disabled.includes(term))) {
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

function gap(gapId, plainEnglishGap, requiredEvidence, ownerRole = null, decisionGate = null, evidenceExamples = [], currentState = "missing") {
  return {
    gap_id: gapId,
    plain_english_gap: plainEnglishGap,
    why_it_matters: whyGapMatters(gapId),
    required_evidence: requiredEvidence,
    evidence_examples: Array.isArray(evidenceExamples) ? evidenceExamples : list(evidenceExamples),
    suggested_owner_role: ownerRole || ownerForGap(gapId),
    next_decision_gate: decisionGate || gateForGap(gapId),
    current_state: currentState
  };
}

function whyGapMatters(gapId) {
  if (gapId.includes("advisory") || gapId.includes("vulnerability")) {
    return "The source record must be reviewed before PatchForge can treat CVE identity, affected product, affected versions, and provenance as accepted evidence.";
  }
  if (gapId.includes("asset") || gapId.includes("product_model")) {
    return "The organisation cannot determine whether the public advisory touches the customer estate until asset, product, and model scope are reviewed.";
  }
  if (gapId.includes("firmware")) {
    return "Affected and fixed-version comparisons are unreliable until the running firmware or software version is reviewed.";
  }
  if (gapId.includes("feature")) {
    return "A user-stated enabled or disabled feature cannot support not-applicable or urgent patch posture until configuration evidence is reviewed.";
  }
  if (gapId.includes("exposure")) {
    return "Internet and management-plane exposure change urgency, customer communication, and CAB timing, so exposure must be reviewed.";
  }
  if (gapId.includes("superseded")) {
    return "Superseded advisories need reviewer confirmation so PatchForge uses the authoritative source record.";
  }
  return "PatchForge cannot support an accountable customer/CAB decision without reviewed evidence for this point.";
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

function canonicalTerm(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function expandProductTerms(values) {
  return expandAliasTerms(values, PRODUCT_ALIAS_GROUPS);
}

function expandFeatureTerms(values) {
  return expandAliasTerms(values, FEATURE_ALIAS_GROUPS);
}

function expandAliasTerms(values, groups) {
  const terms = new Set(list(values).map(canonicalTerm).filter(Boolean));
  for (const term of Array.from(terms)) {
    for (const group of groups) {
      const normalizedGroup = group.map(canonicalTerm);
      if (normalizedGroup.includes(term)) {
        for (const alias of normalizedGroup) {
          terms.add(alias);
        }
      }
    }
  }
  return Array.from(terms);
}

// Version comparator helpers moved to ./versionUtils.js (PF-AZ12 contract
// section 9) and re-imported above with zero behaviour change.

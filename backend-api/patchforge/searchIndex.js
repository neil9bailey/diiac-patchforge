import { assessConfigApplicability } from "./configApplicability.js";

const SEVERITY_RANK = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
  info: 1,
  unknown: 0
};

const URGENCY_RANK = {
  emergency_patch_required: 6,
  urgent_scope_confirmation_required: 5,
  patch_required: 4,
  mitigate_temporarily: 3,
  no_action_pending_review: 2,
  monitor: 1,
  unknown: 0
};

const PRODUCT_ALIAS_GROUPS = [
  ["fortigate", "fortios", "fortinet_firewall", "fortinet_firewall_platform", "fortigate_firewall"],
  ["pan_os", "panos", "palo_alto_firewall", "palo_alto_networks_firewall", "globalprotect_gateway"],
  ["cisco_asa", "asa", "firepower", "ftd", "firepower_threat_defense", "anyconnect_gateway"],
  ["citrix_adc", "netscaler_adc", "netscaler_gateway", "citrix_netscaler"],
  ["f5_big_ip", "big_ip", "bigip", "icontrol_rest"],
  ["junos", "junos_os", "srx", "juniper_srx"]
];

const FEATURE_ALIAS_GROUPS = [
  ["ssl_vpn", "ssl-vpn", "ssl vpn", "webvpn", "remote_access_vpn"],
  ["ipsec", "ipsec_vpn", "ipsec vpn"],
  ["globalprotect", "global protect", "globalprotect_portal", "globalprotect_gateway"],
  ["anyconnect", "cisco_anyconnect", "anyconnect_vpn"],
  ["icontrol_rest", "icontrol rest", "i control rest"],
  ["web_management", "management_interface", "management interface", "api_management", "api management", "admin_web_ui"]
];

export async function buildSecurityActionCenterIndex({ storage, tenantId }) {
  const [
    vulnerabilities,
    vendorSecurityAdvisories,
    vendorAdvisories,
    vendorProfiles,
    networkVendors,
    customerAssets,
    configAssessments,
    sourceFeedRuns,
    sourceRecords
  ] = await Promise.all([
    storage.list("vulnerabilities", tenantId),
    storage.list("vendor_security_advisories", tenantId),
    storage.list("vendor_advisories", tenantId),
    storage.list("vendors", tenantId),
    storage.list("network_vendors", tenantId),
    storage.list("customer_network_assets", tenantId),
    storage.list("config_applicability_assessments", tenantId),
    storage.list("source_feed_runs", tenantId),
    storage.list("sources", tenantId)
  ]);

  const vendorLookup = buildVendorLookup([...vendorProfiles, ...networkVendors, ...vendorSecurityAdvisories, ...vendorAdvisories]);
  const rows = [
    ...vendorSecurityAdvisories.map((record) => rowFromVendorSecurityAdvisory(record, vendorLookup)),
    ...vendorAdvisories.map((record) => rowFromVendorAdvisory(record, vendorLookup)),
    ...vulnerabilities.map((record) => rowFromVulnerability(record, sourceRecords, vendorLookup))
  ].map((row) => enrichRowWithCustomerMatches(row, customerAssets, configAssessments));

  const sortedRows = rows
    .map((row) => ({ ...row, search_text: searchTextFor(row) }))
    .sort(defaultRowSort);

  return {
    tenant_id: tenantId,
    generated_at: new Date().toISOString(),
    catalogue_rows: sortedRows,
    groups: groupRows(sortedRows),
    vendors: vendorFacet(sortedRows, [...vendorProfiles, ...networkVendors]),
    filters: buildFacets(sortedRows),
    source_feed_status: sourceFeedStatus(sourceFeedRuns),
    summary: {
      total_records: sortedRows.length,
      critical_records: sortedRows.filter((row) => normalize(row.severity) === "critical").length,
      known_exploited_records: sortedRows.filter((row) => row.known_exploited).length,
      kev_records: sortedRows.filter((row) => row.kev).length,
      patch_available_records: sortedRows.filter((row) => row.patch_available).length,
      customer_match_records: sortedRows.filter((row) => row.customer_match_count > 0).length,
      final_approval_issued: sortedRows.filter((row) => row.final_approval_issued).length
    },
    boundary: governanceBoundary()
  };
}

export function searchSecurityActionCenterIndex(index, options = {}) {
  const filters = options.filters && typeof options.filters === "object" ? options.filters : options;
  const query = String(options.query || options.q || filters.query || filters.q || "").trim();
  const sort = String(options.sort || filters.sort || "urgency").toLowerCase();
  let rows = [...(index.catalogue_rows || [])];

  if (query) {
    const terms = queryTerms(query);
    rows = rows.filter((row) => terms.every((term) => row.search_text.includes(term)));
  }

  rows = rows.filter((row) => passesFilters(row, filters));
  rows.sort(sorterFor(sort));

  return {
    tenant_id: index.tenant_id,
    generated_at: index.generated_at,
    query,
    filters_applied: normalizedFilters(filters),
    count: rows.length,
    catalogue_rows: rows,
    groups: groupRows(rows),
    filters: buildFacets(rows),
    boundary: governanceBoundary()
  };
}

export async function securityActionCenterDetail({ storage, tenantId, id }) {
  const index = await buildSecurityActionCenterIndex({ storage, tenantId });
  const decoded = String(id || "");
  const row = index.catalogue_rows.find((item) =>
    [item.id, item.cve_id, item.advisory_id, item.vulnerability_id].filter(Boolean).some((value) => String(value).toLowerCase() === decoded.toLowerCase())
  );
  if (!row) {
    return null;
  }

  const [vulnerabilities, advisories, assessments, sources] = await Promise.all([
    storage.list("vulnerabilities", tenantId),
    storage.list("vendor_security_advisories", tenantId),
    storage.list("config_applicability_assessments", tenantId),
    storage.list("sources", tenantId)
  ]);

  return {
    tenant_id: tenantId,
    cve: row,
    vulnerability: vulnerabilities.find((item) => [row.vulnerability_id, row.cve_id, row.advisory_id].includes(item.vulnerability_id)) || null,
    advisory: advisories.find((item) => [row.advisory_id, row.cve_id].includes(item.advisory_id) || list(item.cves, item.cve).includes(row.cve_id)) || null,
    evidence_catalogue: sources.filter((source) =>
      [row.vulnerability_id, row.cve_id, row.advisory_id].filter(Boolean).includes(source.vulnerability_id)
    ),
    customer_assessments: assessments.filter((assessment) =>
      [row.advisory_id, row.cve_id].filter(Boolean).includes(assessment.advisory_id)
      || [row.cve_id, row.advisory_id].filter(Boolean).includes(assessment.cve)
    ),
    boundary: governanceBoundary()
  };
}

export function extractCustomerAssetDescription(description = "", overrides = {}) {
  const text = String(description || "");
  const lower = text.toLowerCase();
  const vendor = detectVendor(lower, overrides.vendor_id || overrides.vendor_name);
  const productFamily = overrides.product_family || detectProductFamily(text, lower, vendor);
  const model = overrides.model || detectModel(text, lower, productFamily);
  const firmwareVersion = overrides.firmware_version || detectFirmwareVersion(text);
  const disabledFeatures = unique([...list(overrides.disabled_features), ...detectFeatureStates(text, "disabled")]);
  const enabledFeatures = unique([
    ...list(overrides.enabled_features),
    ...detectFeatureStates(text, "enabled"),
    ...detectMentionedFeatures(text).filter((feature) => !disabledFeatures.includes(feature))
  ]);
  const managementExposure = overrides.management_exposure || detectManagementExposure(lower);
  const internetFacing = overrides.internet_facing ?? detectInternetFacing(lower, managementExposure);

  return {
    customer: overrides.customer || overrides.customer_name || null,
    site: overrides.site || null,
    vendor_id: vendor.vendor_id,
    vendor_name: vendor.vendor_name,
    product_family: productFamily,
    model,
    firmware_version: firmwareVersion,
    enabled_features: enabledFeatures,
    disabled_features: disabledFeatures,
    management_exposure: managementExposure,
    internet_facing: Boolean(internetFacing),
    evidence_state: "user_stated_unreviewed",
    review_state: "pending_review",
    source_state: "source_bound",
    extraction_confidence: extractionConfidence({ vendor, productFamily, model, firmwareVersion }),
    extracted_from: text,
    final_approval_issued: false,
    human_review_required: true
  };
}

export async function matchCustomerEstate({ storage, tenantId, body = {}, persist = true }) {
  const asset = await resolveAssetForMatch(storage, tenantId, body);
  if (!asset) {
    return {
      tenant_id: tenantId,
      asset: null,
      matches: [],
      match_count: 0,
      boundary: governanceBoundary(),
      message: "A customer asset or device description is required before matching can run."
    };
  }

  const advisories = await storage.list("vendor_security_advisories", tenantId);
  const selected = filterAdvisoriesForMatch(advisories, asset, body);
  const matches = [];
  for (const advisory of selected) {
    const assessment = assessConfigApplicability({
      tenant_id: tenantId,
      asset,
      advisory,
      advisory_id: advisory.advisory_id
    });
    if (persist && assessment.asset_id && assessment.advisory_id) {
      await storage.append("config_applicability_assessments", { tenant_id: tenantId, ...assessment });
    }
    matches.push(exposureMatchFromAssessment(assessment, advisory, asset));
  }

  matches.sort((a, b) => urgencyValue(b.urgency_posture) - urgencyValue(a.urgency_posture));
  return {
    tenant_id: tenantId,
    asset,
    matches,
    match_count: matches.length,
    highest_urgency: matches[0]?.urgency_posture || "unknown",
    final_approval_issued: false,
    human_review_required: true,
    boundary: governanceBoundary()
  };
}

export function summarizePatchComparison(comparison = {}, body = {}) {
  const currentStatus = String(comparison.current_version_status || "").toLowerCase();
  const targetStatus = String(comparison.target_version_status || "").toLowerCase();
  const evidenceReviewed = Boolean(body.reviewed_evidence || body.evidence_reviewed)
    || list(body.evidence_refs, body.reviewed_evidence_refs).length > 0
    || String(body.evidence_state || "").toLowerCase() === "accepted_positive_evidence";
  const currentVersionAffected = currentStatus.includes("potentially_affected") || currentStatus === "affected"
    ? "affected"
    : currentStatus.includes("not_listed") || currentStatus.includes("not_affected")
      ? "unknown"
      : "unknown";
  const proposedVersionRemediates = targetStatus.includes("recorded_as_fixed") && evidenceReviewed
    ? "remediates"
    : targetStatus.includes("not_in_fixed")
      ? "does_not_remediate"
      : "unknown";
  const recommendedPosture = proposedVersionRemediates === "remediates"
    ? "review_patch_change_with_human_approval"
    : targetStatus.includes("recorded_as_fixed")
      ? "review_fixed_version_evidence"
      : "complete_patch_applicability_evidence";

  return {
    ...comparison,
    proposed_version: body.proposed_version || comparison.target_version || null,
    current_version_affected: currentVersionAffected,
    proposed_version_remediates: proposedVersionRemediates,
    evidence_needed: comparison.evidence_required || [
      "Reviewed vendor advisory and release notes",
      "Current device firmware/version evidence",
      "Fixed-version evidence",
      "Testing and rollback evidence"
    ],
    recommended_posture: recommendedPosture,
    required_human_review: true,
    human_review_required: true,
    final_approval_issued: false,
    no_patch_deployment: true,
    boundary: governanceBoundary()
  };
}

export async function buildAskPatchForgeResponse({ storage, tenantId, body = {} }) {
  const question = String(body.question || body.prompt || body.message || "");
  const extracted = body.asset || extractCustomerAssetDescription(question, body);
  const matchResult = await matchCustomerEstate({ storage, tenantId, body: { ...body, asset: extracted }, persist: body.persist_matches === true });
  const unnamedSpecificReference = requiresNamedCveContext(question, body);
  const match = unnamedSpecificReference ? null : findRelevantMatch(matchResult.matches, body, question);
  const gaps = match?.evidence_gaps || [];
  const posture = unnamedSpecificReference ? "cve_or_advisory_required" : match?.urgency_posture || "urgent_scope_confirmation_required";
  const known = whatWeKnow(extracted, match, body);
  const unknown = gaps.length
    ? gaps.map((gap) => gap.plain_english_gap || gap.gap_id || "Reviewed evidence is missing.")
    : ["Reviewed source, asset, feature, exposure, and patch evidence must be attached before final approval."];
  if (unnamedSpecificReference) {
    unknown.unshift("The question refers to this CVE/advisory, but no CVE/advisory identifier or explicit selected advisory context was provided.");
  }
  const evidenceNeeded = evidenceNeededFromGaps(gaps);
  if (unnamedSpecificReference) {
    evidenceNeeded.unshift("Specific CVE/advisory ID or an explicitly selected advisory from the catalogue.");
  }

  return {
    response: {
      short_answer: shortAnswerFor(posture, match),
      current_governed_posture: posture,
      why: whyForAdvisor(posture, match),
      what_we_know: known,
      what_we_do_not_know: unknown,
      evidence_needed: unique(evidenceNeeded),
      recommended_next_action: nextActionForPosture(posture),
      decision_not_allowed_yet: "PatchForge cannot issue final approval, risk acceptance, closure, or not-applicable status without reviewed evidence and named human approval.",
      human_approval_required: true,
      final_approval_issued: false,
      advisory_only: true,
      boundary: governanceBoundary()
    },
    asset: extracted,
    matched_assessment: match || null,
    candidate_matches: matchResult.matches.slice(0, 5),
    final_approval_issued: false
  };
}

function rowFromVendorSecurityAdvisory(record, vendorLookup) {
  const cve = firstValue(record.cve, record.cves);
  const vendorId = normalizeVendorId(record.vendor_id || record.vendor_name);
  const vendorName = record.vendor_name || vendorLookup.get(vendorId)?.vendor_name || humanize(vendorId);
  return baseCatalogueRow({
    id: record.advisory_id || cve,
    record_type: "vendor_advisory",
    advisory_id: record.advisory_id || null,
    cve_id: cve || null,
    title: record.title || cve || "Vendor advisory",
    description: record.summary || record.description || "",
    vendor_id: vendorId,
    vendor_name: vendorName,
    vendor_aliases: vendorLookup.get(vendorId)?.aliases || [],
    product_family: record.product_family || firstValue(record.affected_products),
    product_aliases: list(record.affected_products),
    model: firstValue(record.affected_models),
    affected_models: list(record.affected_models),
    affected_versions: list(record.affected_versions),
    fixed_versions: list(record.fixed_versions),
    affected_feature: firstValue(record.affected_features, record.affected_feature),
    feature_aliases: list(record.affected_features, record.affected_feature),
    severity: record.severity || "unknown",
    cvss_score: record.cvss_score ?? record.cvss ?? null,
    epss_score: record.epss_score ?? null,
    epss_percentile: record.epss_percentile ?? null,
    kev: Boolean(record.kev || record.known_exploited),
    known_exploited: Boolean(record.known_exploited || record.kev),
    patch_available: Boolean(record.patch_available || list(record.fixed_versions).length),
    workaround_status: record.workaround_status || "unverified",
    source_url: record.source_url || null,
    source_name: record.source_name || record.vendor_name || vendorName,
    source_class: record.source_class || "vendor_advisory",
    source_feed: record.source_feed || record.feed_id || "vendor_advisory",
    source_state: record.source_state || "source_bound",
    review_state: record.review_state || "pending_review",
    urgency_posture: record.urgency_posture || null,
    applicability_posture: record.applicability_posture || null,
    final_approval_issued: Boolean(record.final_approval_issued),
    last_refreshed: record.last_modified_at || record.retrieved_at || record.updated_at || record.created_at || null,
    raw_record: record
  });
}

function rowFromVendorAdvisory(record, vendorLookup) {
  const vendorId = normalizeVendorId(record.vendor_id || record.vendor_name);
  return baseCatalogueRow({
    id: record.advisory_id,
    record_type: "vendor_group_advisory",
    advisory_id: record.advisory_id,
    cve_id: firstValue(record.cve, record.cves),
    title: record.title || record.advisory_id,
    description: record.description || record.summary || "",
    vendor_id: vendorId,
    vendor_name: record.vendor_name || vendorLookup.get(vendorId)?.vendor_name || humanize(vendorId),
    product_family: record.product_family || record.product_id || null,
    severity: record.severity || "unknown",
    kev: Boolean(record.known_exploited || record.kev),
    known_exploited: Boolean(record.known_exploited || record.kev),
    patch_available: Boolean(record.patch_available),
    source_url: record.source_url || null,
    source_name: record.source_name || "Vendor advisory",
    source_class: record.source_class || "vendor_advisory",
    source_feed: record.source_feed || "vendor_group",
    source_state: record.source_state || "source_bound",
    review_state: record.review_state || "pending_review",
    final_approval_issued: Boolean(record.final_approval_issued),
    last_refreshed: record.updated_at || record.created_at || null,
    raw_record: record
  });
}

function rowFromVulnerability(record, sourceRecords, vendorLookup) {
  const linkedSources = sourceRecords.filter((source) =>
    source.vulnerability_id === record.vulnerability_id || list(record.source_record_ids).includes(source.source_record_id)
  );
  const source = linkedSources[0] || {};
  const vendorId = normalizeVendorId(record.vendor_id || record.vendor_name || source.source_name || firstTag(record.tags));
  return baseCatalogueRow({
    id: record.vulnerability_id,
    record_type: "cve_record",
    vulnerability_id: record.vulnerability_id,
    advisory_id: record.advisory_id || null,
    cve_id: cveFrom(record.vulnerability_id) || record.canonical_id || record.vulnerability_id,
    title: record.title || record.vulnerability_id,
    description: record.description || "",
    vendor_id: vendorId,
    vendor_name: record.vendor_name || vendorLookup.get(vendorId)?.vendor_name || humanize(vendorId || "unknown vendor"),
    vendor_aliases: list(record.vendor_aliases),
    product_family: record.product_family || record.product || null,
    product_aliases: list(record.product_aliases, record.product),
    model: record.model || null,
    affected_models: list(record.affected_models),
    affected_versions: list(record.affected_versions),
    fixed_versions: list(record.fixed_versions),
    affected_feature: firstValue(record.affected_feature, record.affected_features),
    feature_aliases: list(record.feature_aliases, record.affected_feature, record.affected_features),
    severity: record.severity || "unknown",
    cvss_score: record.cvss_score ?? null,
    epss_score: record.epss_score ?? record.epss ?? null,
    epss_percentile: record.epss_percentile ?? null,
    kev: Boolean(record.kev || record.known_exploited || linkedSources.some((item) => String(item.source_class || "").includes("kev"))),
    known_exploited: Boolean(record.known_exploited),
    patch_available: Boolean(record.patch_available || ["patch_available", "patch_feasible", "overdue"].includes(String(record.patch_status || "").toLowerCase()) || list(record.fixed_versions).length),
    workaround_status: record.workaround_status || "unknown",
    source_url: record.source_url || source.source_url || null,
    source_name: record.source_name || source.source_name || "Source-bound record",
    source_class: record.source_class || source.source_class || "cve_record",
    source_feed: record.source_feed || source.feed_id || source.source_class || "vulnerability_record",
    source_state: record.source_state || "source_bound",
    review_state: record.review_state || "pending_review",
    urgency_posture: record.urgency_posture || null,
    applicability_posture: record.applicability_posture || null,
    final_approval_issued: Boolean(record.final_approval_issued),
    last_refreshed: record.updated_at || record.created_at || null,
    customer_asset_ids: list(record.affected_asset_ids),
    customer_service_ids: list(record.affected_service_ids),
    raw_record: record
  });
}

function baseCatalogueRow(input) {
  return {
    id: input.id || input.cve_id || input.advisory_id,
    record_type: input.record_type || "record",
    vulnerability_id: input.vulnerability_id || null,
    cve_id: input.cve_id || null,
    advisory_id: input.advisory_id || null,
    title: input.title || input.id || "PatchForge source record",
    description: input.description || "",
    vendor_id: input.vendor_id || "unknown-vendor",
    vendor_name: input.vendor_name || humanize(input.vendor_id || "unknown vendor"),
    vendor_aliases: list(input.vendor_aliases),
    product_family: input.product_family || "Product family pending",
    product_aliases: list(input.product_aliases),
    model: input.model || null,
    affected_models: list(input.affected_models),
    affected_versions: list(input.affected_versions),
    fixed_versions: list(input.fixed_versions),
    affected_feature: input.affected_feature || null,
    feature_aliases: list(input.feature_aliases),
    severity: normalize(input.severity || "unknown"),
    cvss_score: numberOrNull(input.cvss_score),
    epss_score: numberOrNull(input.epss_score),
    epss_percentile: numberOrNull(input.epss_percentile),
    kev: Boolean(input.kev),
    kev_status: input.kev ? "kev_or_known_exploited_signal" : "not_recorded",
    known_exploited: Boolean(input.known_exploited),
    patch_available: Boolean(input.patch_available),
    workaround_status: input.workaround_status || "unknown",
    source_url: input.source_url || null,
    source_name: input.source_name || null,
    source_class: input.source_class || "source_bound",
    source_feed: input.source_feed || "source_bound",
    source_state: input.source_state || "source_bound",
    review_state: input.review_state || "pending_review",
    urgency_posture: input.urgency_posture || "unknown",
    applicability_posture: input.applicability_posture || "unknown",
    final_approval_issued: Boolean(input.final_approval_issued),
    last_refreshed: input.last_refreshed || null,
    customer_asset_ids: list(input.customer_asset_ids),
    customer_service_ids: list(input.customer_service_ids),
    customer_matches: [],
    customer_match_count: 0,
    raw_record: input.raw_record || null
  };
}

function enrichRowWithCustomerMatches(row, assets, assessments) {
  const rowAdvisory = rowToAdvisory(row);
  const explicitAssessments = assessments.filter((assessment) =>
    [row.advisory_id, row.cve_id].filter(Boolean).includes(assessment.advisory_id)
    || [row.cve_id, row.advisory_id].filter(Boolean).includes(assessment.cve)
  );
  const matches = [];
  for (const asset of assets) {
    if (!assetMatchesRow(asset, row) && !explicitAssessments.some((assessment) => assessment.asset_id === asset.asset_id)) {
      continue;
    }
    const stored = explicitAssessments.find((assessment) => assessment.asset_id === asset.asset_id);
    const assessment = stored || assessConfigApplicability({ asset, advisory: rowAdvisory });
    matches.push(exposureMatchFromAssessment(assessment, rowAdvisory, asset));
  }
  const highest = matches.sort((a, b) => urgencyValue(b.urgency_posture) - urgencyValue(a.urgency_posture))[0];
  return {
    ...row,
    customer_matches: matches,
    customer_match_count: matches.length,
    urgency_posture: highest?.urgency_posture || row.urgency_posture || "unknown",
    applicability_posture: highest?.applicability_posture || row.applicability_posture || "unknown",
    customer_asset_ids: unique([...row.customer_asset_ids, ...matches.map((match) => match.asset_id).filter(Boolean)])
  };
}

function exposureMatchFromAssessment(assessment, advisory, asset) {
  return {
    assessment_id: assessment.assessment_id,
    advisory_id: assessment.advisory_id || advisory.advisory_id || null,
    cve: assessment.cve || advisory.cve || firstValue(advisory.cves) || null,
    asset_id: assessment.asset_id || asset.asset_id || null,
    customer: asset.customer || asset.customer_name || asset.tenant_id || null,
    site: asset.site || null,
    vendor_id: assessment.vendor_id || asset.vendor_id || advisory.vendor_id || null,
    product_family: assessment.product_family || asset.product_family || advisory.product_family || null,
    model: assessment.model || asset.model || null,
    firmware_version: assessment.firmware_version || asset.firmware_version || null,
    affected_feature: assessment.affected_feature || firstValue(advisory.affected_features),
    applicability_posture: assessment.applicability_posture || "unknown",
    urgency_posture: assessment.urgency_posture || "unknown",
    evidence_state: asset.evidence_state || assessment.evidence_state || "referenced",
    review_state: asset.review_state || assessment.review_state || "pending_review",
    evidence_gaps: assessment.evidence_gaps || [],
    evidence_required: assessment.evidence_required || [],
    final_approval_issued: false
  };
}

function rowToAdvisory(row) {
  return {
    tenant_id: row.tenant_id,
    advisory_id: row.advisory_id || row.cve_id || row.id,
    cve: row.cve_id,
    cves: list(row.cve_id),
    vendor_id: row.vendor_id,
    vendor_name: row.vendor_name,
    title: row.title,
    summary: row.description,
    severity: row.severity,
    product_family: row.product_family,
    affected_products: unique([row.product_family, ...row.product_aliases]),
    affected_models: row.affected_models,
    affected_versions: row.affected_versions,
    fixed_versions: row.fixed_versions,
    affected_features: unique([row.affected_feature, ...row.feature_aliases].filter(Boolean)),
    known_exploited: row.known_exploited || row.kev,
    patch_available: row.patch_available,
    epss_score: row.epss_score,
    review_state: row.review_state,
    evidence_state: row.raw_record?.evidence_state || "referenced",
    source_url: row.source_url,
    source_class: row.source_class,
    source_state: row.source_state,
    final_approval_issued: false
  };
}

function passesFilters(row, filters) {
  const severity = valueFor(filters, "severity");
  const vendor = valueFor(filters, "vendor", "vendor_id", "vendor_name");
  const product = valueFor(filters, "product_family", "product");
  const affectedFeature = valueFor(filters, "affected_feature", "feature");
  const reviewState = valueFor(filters, "review_state");
  const urgencyPosture = valueFor(filters, "urgency_posture", "urgency");
  const sourceFeed = valueFor(filters, "source_feed", "feed");
  const epssThreshold = numberOrNull(valueFor(filters, "epss_threshold", "epss"));
  const dateFrom = valueFor(filters, "date_from", "from");
  const dateTo = valueFor(filters, "date_to", "to");

  if (vendor && !matchesAny(row, [row.vendor_id, row.vendor_name, row.vendor_aliases], vendor)) return false;
  if (product && !matchesAny(row, [row.product_family, row.product_aliases, row.model, row.affected_models], product)) return false;
  if (severity && normalize(row.severity) !== normalize(severity)) return false;
  if (affectedFeature && !matchesAny(row, [row.affected_feature, row.feature_aliases], affectedFeature)) return false;
  if (reviewState && normalize(row.review_state) !== normalize(reviewState)) return false;
  if (urgencyPosture && normalize(row.urgency_posture) !== normalize(urgencyPosture)) return false;
  if (sourceFeed && !matchesAny(row, [row.source_feed, row.source_name, row.source_class], sourceFeed)) return false;
  if (epssThreshold !== null && Number(row.epss_score || 0) < epssThreshold) return false;
  if (filterBool(filters, "kev") !== null && Boolean(row.kev) !== filterBool(filters, "kev")) return false;
  if (filterBool(filters, "patch_available") !== null && Boolean(row.patch_available) !== filterBool(filters, "patch_available")) return false;
  if (filterBool(filters, "known_exploited") !== null && Boolean(row.known_exploited) !== filterBool(filters, "known_exploited")) return false;
  if (filterBool(filters, "customer_match") !== null && (row.customer_match_count > 0) !== filterBool(filters, "customer_match")) return false;
  if (dateFrom && row.last_refreshed && Date.parse(row.last_refreshed) < Date.parse(dateFrom)) return false;
  if (dateTo && row.last_refreshed && Date.parse(row.last_refreshed) > Date.parse(dateTo)) return false;
  return true;
}

function sorterFor(sort) {
  if (sort === "severity") {
    return (a, b) => severityValue(b.severity) - severityValue(a.severity) || defaultRowSort(a, b);
  }
  if (sort === "kev") {
    return (a, b) => Number(b.kev) - Number(a.kev) || defaultRowSort(a, b);
  }
  if (sort === "epss") {
    return (a, b) => Number(b.epss_score || 0) - Number(a.epss_score || 0) || defaultRowSort(a, b);
  }
  if (sort === "vendor") {
    return (a, b) => String(a.vendor_name).localeCompare(String(b.vendor_name)) || defaultRowSort(a, b);
  }
  if (sort === "date") {
    return (a, b) => Date.parse(b.last_refreshed || 0) - Date.parse(a.last_refreshed || 0) || defaultRowSort(a, b);
  }
  return defaultRowSort;
}

function defaultRowSort(a, b) {
  return urgencyValue(b.urgency_posture) - urgencyValue(a.urgency_posture)
    || severityValue(b.severity) - severityValue(a.severity)
    || Number(b.kev) - Number(a.kev)
    || Number(b.known_exploited) - Number(a.known_exploited)
    || Number(b.epss_score || 0) - Number(a.epss_score || 0)
    || String(b.last_refreshed || "").localeCompare(String(a.last_refreshed || ""))
    || String(a.vendor_name).localeCompare(String(b.vendor_name))
    || String(a.title).localeCompare(String(b.title));
}

function groupRows(rows) {
  const byVendor = new Map();
  for (const row of rows) {
    const vendorKey = row.vendor_id || normalizeVendorId(row.vendor_name);
    if (!byVendor.has(vendorKey)) {
      byVendor.set(vendorKey, {
        vendor_id: vendorKey,
        vendor_name: row.vendor_name,
        count: 0,
        customer_match_count: 0,
        known_exploited_count: 0,
        highest_urgency: "unknown",
        product_families: new Map()
      });
    }
    const vendor = byVendor.get(vendorKey);
    vendor.count += 1;
    vendor.customer_match_count += row.customer_match_count || 0;
    vendor.known_exploited_count += row.known_exploited ? 1 : 0;
    if (urgencyValue(row.urgency_posture) > urgencyValue(vendor.highest_urgency)) {
      vendor.highest_urgency = row.urgency_posture;
    }
    const productKey = row.product_family || "Product family pending";
    if (!vendor.product_families.has(productKey)) {
      vendor.product_families.set(productKey, {
        product_family: productKey,
        count: 0,
        customer_match_count: 0,
        items: []
      });
    }
    const product = vendor.product_families.get(productKey);
    product.count += 1;
    product.customer_match_count += row.customer_match_count || 0;
    product.items.push(row);
  }
  return Array.from(byVendor.values()).map((vendor) => ({
    ...vendor,
    product_families: Array.from(vendor.product_families.values()).sort((a, b) => b.count - a.count || a.product_family.localeCompare(b.product_family))
  })).sort((a, b) => b.count - a.count || a.vendor_name.localeCompare(b.vendor_name));
}

function buildFacets(rows) {
  return {
    vendors: countFacet(rows.map((row) => row.vendor_name)),
    product_families: countFacet(rows.map((row) => row.product_family)),
    severities: countFacet(rows.map((row) => row.severity)),
    affected_features: countFacet(rows.map((row) => row.affected_feature).filter(Boolean)),
    review_states: countFacet(rows.map((row) => row.review_state)),
    urgency_postures: countFacet(rows.map((row) => row.urgency_posture)),
    source_feeds: countFacet(rows.map((row) => row.source_feed))
  };
}

function countFacet(values) {
  const counts = new Map();
  for (const value of values.filter(Boolean)) {
    const key = String(value);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries()).map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
}

function vendorFacet(rows, vendors) {
  const byId = new Map();
  for (const vendor of vendors) {
    const vendorId = normalizeVendorId(vendor.vendor_id || vendor.vendor_name);
    byId.set(vendorId, {
      vendor_id: vendorId,
      vendor_name: vendor.vendor_name || humanize(vendorId),
      product_families: list(vendor.product_families),
      source_review_state: vendor.source_review_state || vendor.review_state || "reference_catalogue",
      advisory_source_url: vendor.advisory_source_url || vendor.source_url || null,
      count: 0
    });
  }
  for (const row of rows) {
    const vendorId = row.vendor_id || normalizeVendorId(row.vendor_name);
    const existing = byId.get(vendorId) || {
      vendor_id: vendorId,
      vendor_name: row.vendor_name,
      product_families: [],
      source_review_state: "source_bound",
      advisory_source_url: null,
      count: 0
    };
    byId.set(vendorId, {
      ...existing,
      count: existing.count + 1,
      product_families: unique([...existing.product_families, row.product_family].filter(Boolean))
    });
  }
  return Array.from(byId.values()).sort((a, b) => a.vendor_name.localeCompare(b.vendor_name));
}

function sourceFeedStatus(runs) {
  const latestByFeed = new Map();
  for (const run of runs) {
    const feedId = run.feed_id || "source-feed";
    const current = latestByFeed.get(feedId);
    if (!current || String(run.completed_at || run.started_at || "").localeCompare(String(current.completed_at || current.started_at || "")) > 0) {
      latestByFeed.set(feedId, run);
    }
  }
  return Array.from(latestByFeed.values()).sort((a, b) => String(b.completed_at || "").localeCompare(String(a.completed_at || "")));
}

async function resolveAssetForMatch(storage, tenantId, body) {
  if (body.asset) {
    return { tenant_id: tenantId, ...body.asset };
  }
  if (body.asset_id) {
    const assets = await storage.list("customer_network_assets", tenantId);
    const asset = assets.find((item) => String(item.asset_id) === String(body.asset_id));
    if (asset) {
      return asset;
    }
  }
  if (body.description || body.device_description || body.free_text) {
    return {
      tenant_id: tenantId,
      asset_id: body.asset_id || null,
      ...extractCustomerAssetDescription(body.description || body.device_description || body.free_text, body)
    };
  }
  return null;
}

function filterAdvisoriesForMatch(advisories, asset, body) {
  const selectedById = advisories.filter((advisory) =>
    [body.advisory_id, body.cve].filter(Boolean).some((id) =>
      String(advisory.advisory_id).toLowerCase() === String(id).toLowerCase()
      || list(advisory.cve, advisory.cves).some((cve) => String(cve).toLowerCase() === String(id).toLowerCase())
    )
  );
  if (selectedById.length) {
    return selectedById;
  }
  const matching = advisories.filter((advisory) => assetMatchesAdvisory(asset, advisory));
  return matching.length ? matching : advisories.slice(0, 12);
}

function assetMatchesRow(asset, row) {
  return assetMatchesAdvisory(asset, rowToAdvisory(row));
}

function assetMatchesAdvisory(asset, advisory) {
  const assetVendor = normalizeVendorId(asset.vendor_id || asset.vendor_name);
  const advisoryVendor = normalizeVendorId(advisory.vendor_id || advisory.vendor_name);
  const vendorMatches = assetVendor && advisoryVendor && (assetVendor === advisoryVendor || assetVendor.includes(advisoryVendor) || advisoryVendor.includes(assetVendor));
  const assetTerms = expandProductTerms(list(asset.product_family, asset.model, asset.product_id));
  const advisoryTerms = expandProductTerms(list(advisory.product_family, advisory.affected_products, advisory.affected_models, advisory.product_aliases));
  const productMatches = assetTerms.some((assetTerm) =>
    advisoryTerms.some((term) => term === assetTerm || term.includes(assetTerm) || assetTerm.includes(term))
  );
  return Boolean(vendorMatches || productMatches);
}

function findRelevantMatch(matches, body, question) {
  const cve = cveFrom(question);
  if (cve) {
    const exact = matches.find((match) => String(match.cve).toLowerCase() === cve.toLowerCase());
    if (exact) {
      return exact;
    }
    return null;
  }
  if (body.advisory_id || body.cve) {
    const requested = String(body.advisory_id || body.cve).toLowerCase();
    const exact = matches.find((match) =>
      [match.advisory_id, match.cve].filter(Boolean).some((id) => String(id).toLowerCase() === requested)
    );
    if (exact) {
      return exact;
    }
  }
  return [...matches].sort((a, b) => urgencyValue(b.urgency_posture) - urgencyValue(a.urgency_posture))[0] || null;
}

function requiresNamedCveContext(question, body) {
  if (body.advisory_id || body.cve || cveFrom(question)) {
    return false;
  }
  return /\b(this|that|the)\s+(cve|advisory|vendor advisory|finding)\b/i.test(String(question || ""));
}

function whatWeKnow(asset, match, body) {
  return [
    asset.vendor_name || asset.vendor_id || asset.product_family || asset.model ? `Vendor/product: ${assetProductSummary(asset)}` : null,
    asset.firmware_version ? `Version: ${asset.firmware_version}` : null,
    list(asset.enabled_features).length ? `Enabled features: ${list(asset.enabled_features).join(", ")}` : null,
    list(asset.disabled_features).length ? `Disabled features: ${list(asset.disabled_features).join(", ")}` : null,
    asset.management_exposure ? `Management exposure: ${humanize(asset.management_exposure)}` : null,
    match ? `Matched advisory/CVE: ${match.cve || match.advisory_id}` : "No exact advisory match was confirmed from reviewed evidence.",
    body.patch_compare ? `Patch compare posture: ${body.patch_compare.recommended_posture || "pending review"}` : null
  ].filter(Boolean);
}

function assetProductSummary(asset = {}) {
  const vendor = asset.vendor_name || humanize(asset.vendor_id);
  const productFamily = asset.product_family || "";
  const model = asset.model || "";
  const productWithoutVendor = vendor && productFamily.toLowerCase().startsWith(String(vendor).toLowerCase())
    ? productFamily
    : [vendor, productFamily].filter(Boolean).join(" ");
  const productTokens = productWithoutVendor.split(/\s+/).filter(Boolean);
  const modelTokens = model.split(/\s+/).filter(Boolean);
  if (productTokens.length && modelTokens.length && productTokens.at(-1)?.toLowerCase() === modelTokens[0].toLowerCase()) {
    return [...productTokens, ...modelTokens.slice(1)].join(" ");
  }
  return [productWithoutVendor, model].filter(Boolean).join(" ");
}

function shortAnswerFor(posture, match) {
  if (posture === "cve_or_advisory_required") {
    return "PatchForge needs the specific CVE/advisory ID or an explicitly selected advisory before it can answer whether this CVE requires urgent patching.";
  }
  if (!match) {
    return "PatchForge needs a matching advisory/CVE and reviewed customer evidence before it can recommend an urgency posture.";
  }
  if (posture === "emergency_patch_required") {
    return "Treat this as emergency patch governance pending human review of scope, version, feature, exposure, test, and rollback evidence.";
  }
  if (posture === "patch_required") {
    return "Patch governance is recommended, but final approval and change execution remain outside PatchForge.";
  }
  if (posture === "monitor") {
    return "Reviewed evidence may support monitoring or not-applicable review, but a named human reviewer must still approve the outcome.";
  }
  return "PatchForge cannot confirm the device is out of scope yet; complete source, asset, feature, version, and exposure evidence review first.";
}

function whyForAdvisor(posture, match) {
  if (posture === "cve_or_advisory_required") {
    return "The question refers to a specific CVE/advisory, but the governed advisor was not given a named CVE/advisory context to assess.";
  }
  if (!match) {
    return "The question did not resolve to enough governed source and customer-estate evidence.";
  }
  if (posture === "emergency_patch_required") {
    return "The current source-bound match indicates affected scope, exploitation signal or exposure, and available patch evidence may matter, but evidence gaps remain.";
  }
  if (posture === "monitor") {
    return "The assessment found reviewed evidence that may reduce urgency, while final decision authority remains with the accountable reviewer.";
  }
  return "One or more of vendor source, product/model, firmware, affected feature, exposure, or fixed-version evidence is incomplete or unreviewed.";
}

function evidenceNeededFromGaps(gaps) {
  const values = gaps.flatMap((gap) => list(gap.required_evidence, gap.evidence_examples));
  return unique(values).length ? unique(values) : [
    "Reviewed vendor advisory and affected-version evidence",
    "Reviewed customer asset and firmware evidence",
    "Reviewed affected-feature configuration evidence",
    "Reviewed exposure evidence",
    "Human approval event"
  ];
}

function nextActionForPosture(posture) {
  if (posture === "cve_or_advisory_required") {
    return "Enter the CVE/advisory ID, select a row in the Global Security Action Center, or run Customer Estate matching before asking whether urgent patching is required.";
  }
  if (posture === "emergency_patch_required") {
    return "Open human-led emergency CAB/security review and attach vendor patch, test, rollback, asset, feature, and exposure evidence.";
  }
  if (posture === "patch_required") {
    return "Prepare patch governance evidence and request accountable human approval.";
  }
  if (posture === "monitor") {
    return "Record the reviewed evidence that supports monitoring and request reviewer signoff.";
  }
  return "Confirm customer exposure, affected feature state, firmware/version, and vendor advisory source review.";
}

function governanceBoundary() {
  return {
    advisory_only: true,
    no_vulnerability_scanning: true,
    no_exploit_generation: true,
    no_procedural_exploit_steps: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    no_autonomous_cab_approval: true,
    no_autonomous_risk_acceptance: true,
    no_autonomous_evidence_gate_closure: true,
    final_approval_issued: false,
    human_approval_required: true
  };
}

function buildVendorLookup(records) {
  const vendors = new Map();
  for (const record of records) {
    const vendorId = normalizeVendorId(record.vendor_id || record.vendor_name);
    if (!vendorId) {
      continue;
    }
    const existing = vendors.get(vendorId) || {};
    vendors.set(vendorId, {
      vendor_id: vendorId,
      vendor_name: record.vendor_name || existing.vendor_name || humanize(vendorId),
      aliases: unique([...list(existing.aliases), record.vendor_id, record.vendor_name, record.name].filter(Boolean))
    });
  }
  return vendors;
}

function searchTextFor(row) {
  const customerMatchText = (Array.isArray(row.customer_matches) ? row.customer_matches : []).flatMap((match) => [
    match.asset_id,
    match.customer,
    match.site,
    match.vendor_id,
    match.product_family,
    match.model,
    match.firmware_version,
    match.affected_feature,
    match.urgency_posture,
    match.applicability_posture
  ]);
  return queryTerms([
    row.cve_id,
    row.advisory_id,
    row.vendor_name,
    row.vendor_aliases,
    row.product_family,
    row.product_aliases,
    row.model,
    row.affected_models,
    row.affected_versions,
    row.fixed_versions,
    row.affected_feature,
    row.feature_aliases,
    row.title,
    row.description,
    row.severity,
    row.cvss_score,
    row.epss_score,
    row.epss_percentile,
    row.kev_status,
    row.known_exploited ? "known exploited" : "",
    row.patch_available ? "patch available" : "",
    row.workaround_status,
    row.source_url,
    row.source_name,
    row.source_class,
    row.source_feed,
    row.customer_asset_ids,
    row.customer_service_ids,
    customerMatchText,
    row.urgency_posture,
    row.applicability_posture
  ].flat().join(" ")).join(" ");
}

function queryTerms(value) {
  return normalizeText(value).split(/\s+/).filter(Boolean);
}

function normalizedFilters(filters) {
  return Object.fromEntries(
    Object.entries(filters || {}).filter(([key, value]) => value !== undefined && value !== null && value !== "" && !["q", "query"].includes(key))
  );
}

function valueFor(source, ...keys) {
  for (const key of keys) {
    const value = source?.[key];
    if (value !== undefined && value !== null && value !== "") {
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return null;
}

function filterBool(source, key) {
  const value = valueFor(source, key);
  if (value === null) {
    return null;
  }
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = normalize(value);
  if (["true", "1", "yes", "y"].includes(normalized)) {
    return true;
  }
  if (["false", "0", "no", "n"].includes(normalized)) {
    return false;
  }
  return null;
}

function matchesAny(row, candidates, needle) {
  const normalizedNeedle = canonicalTerm(needle);
  return list(candidates).some((value) => {
    const term = canonicalTerm(value);
    return term === normalizedNeedle || term.includes(normalizedNeedle) || normalizedNeedle.includes(term);
  });
}

function detectVendor(lower, requested) {
  const normalized = normalizeVendorId(requested);
  if (normalized) {
    return { vendor_id: normalized, vendor_name: humanize(normalized) };
  }
  if (/fortinet|fortigate|fortios/.test(lower)) {
    return { vendor_id: "fortinet", vendor_name: "Fortinet" };
  }
  if (/cisco|asa|anyconnect/.test(lower)) {
    return { vendor_id: "cisco", vendor_name: "Cisco" };
  }
  if (/palo alto|paloalto|pan-os|panos|globalprotect/.test(lower)) {
    return { vendor_id: "palo-alto-networks", vendor_name: "Palo Alto Networks" };
  }
  if (/juniper|junos|srx/.test(lower)) {
    return { vendor_id: "juniper", vendor_name: "Juniper" };
  }
  if (/\bf5\b|big-?ip|icontrol/.test(lower)) {
    return { vendor_id: "f5", vendor_name: "F5" };
  }
  if (/citrix|netscaler/.test(lower)) {
    return { vendor_id: "citrix-netscaler", vendor_name: "Citrix / NetScaler" };
  }
  return { vendor_id: "unknown-vendor", vendor_name: "Unknown vendor" };
}

function detectProductFamily(text, lower, vendor) {
  if (/fortigate/i.test(text)) return "FortiGate";
  if (/fortios/i.test(text)) return "FortiOS";
  if (/cisco\s+asa|\basa\b/i.test(text)) return "Cisco ASA";
  if (/firepower|ftd/i.test(text)) return "Cisco Firepower";
  if (/pan-os|panos/i.test(text)) return "PAN-OS";
  if (/globalprotect/i.test(text)) return "GlobalProtect";
  if (/big-?ip/i.test(text)) return "BIG-IP";
  if (/netscaler|citrix adc/i.test(text)) return "NetScaler ADC";
  if (/\bsrx\s*\d*|srx[- ]?series/i.test(text)) return "Juniper SRX";
  if (/junos/i.test(text)) return "Junos OS";
  if (vendor.vendor_id === "fortinet") return "FortiGate";
  if (vendor.vendor_id === "cisco") return "Cisco ASA";
  if (vendor.vendor_id === "juniper") return "Juniper SRX";
  return lower ? "Product family pending" : null;
}

function detectModel(text, lower, productFamily) {
  const forti = text.match(/fortigate\s+([a-z0-9-]+)/i);
  if (forti) return forti[1].toUpperCase();
  const asa = text.match(/asa\s+([0-9]+[-a-z]*)/i);
  if (asa) return `ASA ${asa[1].toUpperCase()}`;
  const srx = text.match(/\bsrx[- ]?([0-9]{3,5}[a-z]*)\b/i);
  if (srx) return `SRX ${srx[1].toUpperCase()}`;
  const model = text.match(/\b(model|appliance)\s+([a-z0-9-]+)/i);
  if (model) return model[2].toUpperCase();
  if (productFamily && lower.includes("100f")) return "100F";
  return null;
}

function detectFirmwareVersion(text) {
  const named = text.match(/(?:fortios|pan-os|panos|sonicos|junos|fireware|firmware|version|running)\s+v?([0-9]+(?:\.[0-9a-z-]+){1,4})/i);
  if (named) return named[1];
  const version = text.match(/\bv?([0-9]+\.[0-9]+(?:\.[0-9a-z-]+){0,3})\b/i);
  return version ? version[1] : null;
}

function detectFeatureStates(text, state) {
  const features = [];
  const clauses = String(text || "").split(/[.;\r\n]+/).map((clause) => clause.trim()).filter(Boolean);
  const statePattern = new RegExp(`\\b${state}\\b`, "i");
  const patterns = [
    ["ssl_vpn", /ssl[- ]?vpn/i],
    ["ipsec_vpn", /ipsec/i],
    ["anyconnect", /anyconnect/i],
    ["globalprotect", /globalprotect|global protect/i],
    ["icontrol_rest", /icontrol\s*rest/i],
    ["web_management", /management|admin ui|web ui/i]
  ];
  for (const [feature, pattern] of patterns) {
    if (clauses.some((clause) => pattern.test(clause) && statePattern.test(clause))) {
      features.push(feature);
    }
  }
  return features;
}

function detectMentionedFeatures(text) {
  const patterns = [
    ["ssl_vpn", /ssl[- ]?vpn/i],
    ["ipsec_vpn", /ipsec|site[- ]?to[- ]?site\s+vpn/i],
    ["anyconnect", /anyconnect/i],
    ["globalprotect", /globalprotect|global protect/i],
    ["icontrol_rest", /icontrol\s*rest/i],
    ["web_management", /management|admin ui|web ui/i],
    ["internet_access_control", /internet\s+access\s+controls?|access\s+controls?/i],
    ["proxy", /\bproxy\b/i],
    ["azure_site_to_site_vpn", /azure.*site[- ]?to[- ]?site\s+vpn|site[- ]?to[- ]?site\s+vpn.*azure/i],
    ["ot_cloud_connectivity", /\bot\b|operational\s+technology|core\s+ot|azure\s+cloud/i]
  ];
  return patterns.filter(([, pattern]) => pattern.test(text)).map(([feature]) => feature);
}

function detectManagementExposure(lower) {
  if (/management\s+(internal|private)\s+only|management.*internal|internal\s+only/.test(lower)) {
    return "internal";
  }
  if (/management\s+(internet|public|external)|public\s+management|internet-facing\s+management/.test(lower)) {
    return "internet";
  }
  if (/internet[- ]facing|publicly\s+exposed/.test(lower)) {
    return "internet";
  }
  return "unknown";
}

function detectInternetFacing(lower, managementExposure) {
  if (["internet", "public", "external"].includes(normalize(managementExposure))) {
    return true;
  }
  if (/internet[- ]facing|publicly\s+exposed|public\s+ip|internet\s+gateway|internet\s+access\s+controls?|edge\s+firewall|perimeter\s+firewall/.test(lower)) {
    return true;
  }
  if (/internal\s+only|management\s+internal|not\s+internet[- ]facing/.test(lower)) {
    return false;
  }
  return false;
}

function extractionConfidence({ vendor, productFamily, model, firmwareVersion }) {
  const score = [
    vendor?.vendor_id && vendor.vendor_id !== "unknown-vendor" ? 0.3 : 0,
    productFamily && productFamily !== "Product family pending" ? 0.25 : 0,
    model ? 0.2 : 0,
    firmwareVersion ? 0.25 : 0
  ].reduce((sum, value) => sum + value, 0);
  return Math.round(score * 100) / 100;
}

function cveFrom(value) {
  const match = String(value || "").match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0].toUpperCase() : null;
}

function firstTag(tags) {
  return list(tags).find((tag) => !["agent_intelligence"].includes(normalize(tag))) || null;
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

function unique(values) {
  return Array.from(new Set(list(values))).filter(Boolean);
}

function normalize(value) {
  return String(value || "").trim().toLowerCase().replace(/\s+/g, "_");
}

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, " ")
    .trim();
}

function canonicalTerm(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function normalizeVendorId(value) {
  const canonical = canonicalTerm(value);
  if (!canonical) return "";
  if (canonical === "palo_alto" || canonical === "paloalto" || canonical === "palo_alto_networks") return "palo-alto-networks";
  if (canonical === "citrix" || canonical === "netscaler" || canonical === "citrix_netscaler") return "citrix-netscaler";
  return canonical.replace(/_/g, "-");
}

function humanize(value) {
  return String(value || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function numberOrNull(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function severityValue(value) {
  return SEVERITY_RANK[normalize(value)] ?? 0;
}

function urgencyValue(value) {
  return URGENCY_RANK[normalize(value)] ?? 0;
}

function expandProductTerms(values) {
  return expandAliasTerms(values, PRODUCT_ALIAS_GROUPS);
}

function expandAliasTerms(values, groups) {
  const expanded = new Set(list(values).map(canonicalTerm).filter(Boolean));
  let changed = true;
  while (changed) {
    changed = false;
    for (const group of groups) {
      const canonicalGroup = group.map(canonicalTerm);
      if (canonicalGroup.some((term) => expanded.has(term))) {
        for (const term of canonicalGroup) {
          if (!expanded.has(term)) {
            expanded.add(term);
            changed = true;
          }
        }
      }
    }
  }
  return Array.from(expanded);
}

import { createHash, randomUUID } from "node:crypto";
import { assessConfigApplicability } from "./configApplicability.js";

export const NETWORK_VENDOR_CATALOG = [
  vendor("cisco", "Cisco", "infrastructure_networking", "https://developer.cisco.com/psirt/", ["ASA", "Firepower", "IOS XE", "Catalyst", "AnyConnect"]),
  vendor("fortinet", "Fortinet", "infrastructure_networking", "https://www.fortiguard.com/psirt", ["FortiGate", "FortiOS", "FortiProxy", "FortiManager"]),
  vendor("palo-alto-networks", "Palo Alto Networks", "infrastructure_networking", "https://security.paloaltonetworks.com/", ["PAN-OS", "Prisma Access", "GlobalProtect"]),
  vendor("juniper", "Juniper", "infrastructure_networking", "https://supportportal.juniper.net/s/global-search/%40uri", ["Junos OS", "SRX", "MX", "EX"]),
  vendor("f5", "F5", "infrastructure_networking", "https://my.f5.com/manage/s/solutions", ["BIG-IP", "BIG-IQ", "NGINX"]),
  vendor("citrix-netscaler", "Citrix / NetScaler", "infrastructure_networking", "https://support.citrix.com/securitybulletins", ["NetScaler ADC", "NetScaler Gateway", "Citrix ADC"]),
  vendor("check-point", "Check Point", "infrastructure_networking", "https://support.checkpoint.com/results/sk/sk178280", ["Quantum Security Gateway", "Gaia", "Harmony"]),
  vendor("sophos", "Sophos", "infrastructure_networking", "https://www.sophos.com/en-us/security-advisories", ["Sophos Firewall", "UTM", "Central"]),
  vendor("sonicwall", "SonicWall", "infrastructure_networking", "https://psirt.global.sonicwall.com/vuln-list", ["SonicOS", "SMA", "NSa", "TZ"]),
  vendor("watchguard", "WatchGuard", "infrastructure_networking", "https://www.watchguard.com/wgrd-psirt", ["Firebox", "Fireware", "AuthPoint"]),
  vendor("aruba-hpe", "Aruba / HPE", "infrastructure_networking", "https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=hpesbhf03769en_us", ["ArubaOS", "AOS-CX", "ClearPass"]),
  vendor("ubiquiti", "Ubiquiti", "infrastructure_networking", "https://community.ui.com/releases", ["UniFi Network", "UniFi OS", "EdgeRouter"]),
  vendor("mikrotik", "MikroTik", "infrastructure_networking", "https://mikrotik.com/supportsec", ["RouterOS", "CHR", "Cloud Router Switch"]),
  vendor("barracuda", "Barracuda", "infrastructure_networking", "https://status.barracuda.com/security", ["CloudGen Firewall", "WAF", "Email Security Gateway"]),
  vendor("zscaler", "Zscaler", "identity_endpoint_cloud", "https://trust.zscaler.com/", ["ZIA", "ZPA", "ZDX"]),
  vendor("cloudflare", "Cloudflare", "identity_endpoint_cloud", "https://www.cloudflarestatus.com/", ["WAF", "Zero Trust", "Magic Transit"]),
  vendor("akamai", "Akamai", "identity_endpoint_cloud", "https://www.akamai.com/legal/compliance/security-advisories", ["App & API Protector", "Guardicore", "Edge DNS"])
];

export async function listNetworkVendors(storage, tenantId) {
  const stored = await storage.list("network_vendors", tenantId);
  const merged = new Map(NETWORK_VENDOR_CATALOG.map((item) => [item.vendor_id, { ...item, tenant_id: tenantId }]));
  for (const item of stored) {
    merged.set(item.vendor_id, { ...merged.get(item.vendor_id), ...item });
  }
  return Array.from(merged.values()).sort((a, b) => a.vendor_name.localeCompare(b.vendor_name));
}

export async function upsertNetworkVendor(storage, tenantId, body = {}) {
  const record = {
    tenant_id: tenantId,
    vendor_id: normalizeVendorId(body.vendor_id || body.vendor_name || body.name),
    vendor_name: body.vendor_name || body.name || body.vendor_id,
    vendor_category: body.vendor_category || body.category || "infrastructure_networking",
    advisory_source_type: body.advisory_source_type || "configured_public_source",
    advisory_source_url: body.advisory_source_url || body.source_url || null,
    product_families: list(body.product_families),
    source_review_state: body.source_review_state || "reference_catalogue",
    last_refresh_at: body.last_refresh_at || null,
    enabled: body.enabled !== false,
    source_bound: true,
    review_required: true,
    created_at: body.created_at || new Date().toISOString(),
    ...lineageFromBody(body)
  };
  await storage.append("network_vendors", record);
  await storage.audit(tenantId, "vendorlens_vendor_upserted", { vendor_id: record.vendor_id, ...lineageFromBody(body) });
  return record;
}

export async function listCustomerNetworkAssets(storage, tenantId) {
  return (await storage.list("customer_network_assets", tenantId)).sort((a, b) => String(a.vendor_id).localeCompare(String(b.vendor_id)));
}

export async function upsertCustomerNetworkAsset(storage, tenantId, body = {}) {
  const record = {
    tenant_id: tenantId,
    asset_id: body.asset_id || `net-asset-${randomUUID()}`,
    vendor_id: normalizeVendorId(body.vendor_id || body.vendor_name),
    product_family: body.product_family || null,
    model: body.model || null,
    firmware_version: body.firmware_version || null,
    serial_or_asset_ref: body.serial_or_asset_ref || null,
    environment: body.environment || "production",
    site: body.site || null,
    service_owner: body.service_owner || null,
    internet_facing: Boolean(body.internet_facing),
    management_exposure: body.management_exposure || "unknown",
    not_in_estate: Boolean(body.not_in_estate),
    enabled_features: list(body.enabled_features),
    disabled_features: list(body.disabled_features),
    config_evidence_refs: list(body.config_evidence_refs),
    review_state: body.review_state || "pending_review",
    evidence_state: body.evidence_state || "referenced",
    source_state: "source_bound",
    created_at: body.created_at || new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...lineageFromBody(body)
  };
  await storage.append("customer_network_assets", record);
  await storage.audit(tenantId, "vendorlens_customer_network_asset_upserted", { asset_id: record.asset_id, vendor_id: record.vendor_id, ...lineageFromBody(body) });
  return record;
}

export async function listVendorSecurityAdvisories(storage, tenantId) {
  return (await storage.list("vendor_security_advisories", tenantId))
    .sort((a, b) => String(b.published_at || b.created_at || "").localeCompare(String(a.published_at || a.created_at || "")));
}

export async function ingestVendorSecurityAdvisory(storage, tenantId, body = {}) {
  const vendorId = normalizeVendorId(body.vendor_id || body.vendor_name);
  const now = new Date().toISOString();
  const cve = firstValue(body.cve, body.cves);
  const record = {
    tenant_id: tenantId,
    advisory_id: body.advisory_id || `${vendorId}-${cve || hashObject(body).slice(0, 12)}`,
    vendor_id: vendorId,
    vendor_name: body.vendor_name || humanize(vendorId),
    source_class: body.source_class || "vendor_advisory",
    source_url: body.source_url || null,
    source_hash: body.source_hash || hashObject({
      source_url: body.source_url || null,
      cve,
      title: body.title || null,
      payload: body.source_payload || null
    }),
    retrieved_at: body.retrieved_at || now,
    cve: cve || null,
    cves: list(body.cves || cve),
    title: body.title || cve || "Vendor security advisory",
    summary: body.summary || body.description || "",
    severity: body.severity || "unknown",
    product_family: body.product_family || firstValue(body.affected_products) || null,
    affected_products: list(body.affected_products || body.product_family),
    affected_models: list(body.affected_models || body.model),
    affected_versions: list(body.affected_versions || body.firmware_version),
    fixed_versions: list(body.fixed_versions),
    affected_features: list(body.affected_features || body.affected_feature || body.feature),
    workaround_status: body.workaround_status || "unverified",
    known_exploited: Boolean(body.known_exploited || body.kev),
    epss_score: body.epss_score ?? null,
    patch_available: Boolean(body.patch_available || list(body.fixed_versions).length),
    superseded: Boolean(body.superseded || body.superseded_by),
    superseded_by: body.superseded_by || null,
    review_state: body.review_state || "pending_review",
    evidence_state: body.evidence_state || "referenced",
    source_state: "source_bound",
    advisory_only: true,
    can_close_hard_gates_alone: false,
    final_approval_issued: false,
    created_at: body.created_at || now,
    ...lineageFromBody(body)
  };
  await storage.append("vendor_security_advisories", record);
  await storage.audit(tenantId, "vendorlens_advisory_ingested", { advisory_id: record.advisory_id, vendor_id: record.vendor_id, cve: record.cve, ...lineageFromBody(body) });
  return record;
}

export async function assessAndStoreConfigApplicability(storage, tenantId, body = {}) {
  const asset = body.asset || await findById(storage, "customer_network_assets", tenantId, body.asset_id, "asset_id") || {};
  const advisory = body.advisory || await findById(storage, "vendor_security_advisories", tenantId, body.advisory_id, "advisory_id") || {};
  const assessment = assessConfigApplicability({
    tenant_id: tenantId,
    asset,
    advisory,
    ...body
  });
  await storage.append("config_applicability_assessments", {
    tenant_id: tenantId,
    ...assessment,
    ...lineageFromBody(body)
  });
  await storage.audit(tenantId, "vendorlens_config_applicability_assessed", {
    assessment_id: assessment.assessment_id,
    asset_id: assessment.asset_id,
    advisory_id: assessment.advisory_id,
    urgency_posture: assessment.urgency_posture,
    ...lineageFromBody(body)
  });
  return assessment;
}

export async function createVendorLensChatSession(storage, tenantId, body = {}) {
  const assessment = body.assessment || await assessAndStoreConfigApplicability(storage, tenantId, body);
  const question = String(body.question || "Assess this network vendor configuration.");
  const response = buildConfigChatResponse(question, assessment, body);
  const now = new Date().toISOString();
  const session = {
    tenant_id: tenantId,
    session_id: body.session_id || `vl-chat-${Date.now()}-${randomUUID().slice(0, 8)}`,
    title: body.title || question.slice(0, 96),
    advisory_id: assessment.advisory_id,
    asset_id: assessment.asset_id,
    assessment_id: assessment.assessment_id,
    advisory_only: true,
    human_review_required: true,
    final_approval_issued: false,
    created_at: now,
    updated_at: now,
    latest_response: response,
    ...lineageFromBody(body)
  };
  const userMessage = chatMessage(session, "user", question, { advisory_only: true });
  const assistantMessage = chatMessage(session, "assistant", response.short_answer, response);
  await storage.append("vendorlens_chat_sessions", session);
  await storage.append("vendorlens_chat_messages", userMessage);
  await storage.append("vendorlens_chat_messages", assistantMessage);
  await storage.audit(tenantId, "vendorlens_chat_session_created", { session_id: session.session_id, assessment_id: assessment.assessment_id, ...lineageFromBody(body) });
  return { session, messages: [userMessage, assistantMessage], response };
}

export async function getVendorLensChatSession(storage, tenantId, sessionId) {
  const session = await findById(storage, "vendorlens_chat_sessions", tenantId, sessionId, "session_id");
  if (!session) {
    return null;
  }
  const messages = (await storage.list("vendorlens_chat_messages", tenantId))
    .filter((message) => message.session_id === sessionId)
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
  return { session, messages };
}

export async function appendVendorLensChatMessage(storage, tenantId, sessionId, body = {}) {
  const existing = await getVendorLensChatSession(storage, tenantId, sessionId);
  if (!existing) {
    return null;
  }
  const assessment = await findById(storage, "config_applicability_assessments", tenantId, existing.session.assessment_id, "assessment_id");
  const question = String(body.message || body.question || "");
  const response = buildConfigChatResponse(question, assessment || existing.session.latest_response || {}, body);
  const userMessage = chatMessage(existing.session, "user", question, { advisory_only: true, ...lineageFromBody(body) });
  const assistantMessage = chatMessage(existing.session, "assistant", response.short_answer, response);
  const updatedSession = {
    ...existing.session,
    latest_response: response,
    updated_at: new Date().toISOString(),
    ...lineageFromBody(body)
  };
  await storage.append("vendorlens_chat_sessions", updatedSession);
  await storage.append("vendorlens_chat_messages", userMessage);
  await storage.append("vendorlens_chat_messages", assistantMessage);
  await storage.audit(tenantId, "vendorlens_chat_message_added", { session_id: sessionId, ...lineageFromBody(body) });
  return { session: updatedSession, messages: [...existing.messages, userMessage, assistantMessage], response };
}

export async function buildVendorLensDashboard(storage, tenantId) {
  const [vendors, assets, advisories, assessments] = await Promise.all([
    listNetworkVendors(storage, tenantId),
    listCustomerNetworkAssets(storage, tenantId),
    listVendorSecurityAdvisories(storage, tenantId),
    storage.list("config_applicability_assessments", tenantId)
  ]);
  return {
    tenant_id: tenantId,
    generated_at: new Date().toISOString(),
    source_bound: true,
    review_required: true,
    vendors_tracked: vendors.filter((item) => item.enabled !== false).length,
    active_advisories: advisories.filter((item) => item.review_state !== "closed").length,
    known_exploited_vendor_cves: advisories.filter((item) => item.known_exploited).length,
    customer_estate_matches: assessments.filter((item) => item.applicability_posture === "applicable").length,
    config_unknown_count: assessments.filter((item) => ["unknown", "requires_review", "conditional"].includes(item.applicability_posture)).length,
    emergency_attention_required: assessments.filter((item) => item.urgency_posture === "emergency_patch_required").length,
    recent_assessments: assessments.slice(-8).reverse()
  };
}

export async function refreshVendorLensSource({ storage, tenantId, body = {}, fetchImpl = globalThis.fetch }) {
  const adapter = String(body.adapter || body.source_type || body.feed_id || "nvd_cve_api").toLowerCase();
  try {
    if (adapter.includes("nvd")) {
      return await refreshNvdCve({ storage, tenantId, body, fetchImpl });
    }
    if (adapter.includes("cisco")) {
      return await refreshCiscoPsirt({ storage, tenantId, body, fetchImpl });
    }
    return await refreshGenericVendorSource({ storage, tenantId, body, fetchImpl });
  } catch (error) {
    return recordRun(storage, tenantId, {
      run_id: body.run_id || `run-vendorlens-${Date.now()}-${randomUUID().slice(0, 8)}`,
      feed_id: `vendorlens-${adapter}`,
      feed_name: "VendorLens source refresh",
      provider: body.provider || body.vendor_id || "VendorLens",
      source_class: "vendor_advisory",
      source_url: body.source_url || null,
      status: "failed",
      records_seen: 0,
      records_matched: 0,
      records_ingested: 0,
      records_enriched: 0,
      message: error.message,
      started_at: new Date().toISOString(),
      ...lineageFromBody(body)
    });
  }
}

async function refreshNvdCve({ storage, tenantId, body, fetchImpl }) {
  const cve = firstValue(body.cve, body.cves);
  const startedAt = new Date().toISOString();
  if (!cve) {
    return recordRun(storage, tenantId, runRecord(body, "nvd-cve-2", "NVD CVE 2.0", "NVD", "blocked", "NVD CVE enrichment requires a requested CVE identifier.", startedAt));
  }
  const requestUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`;
  const payload = await fetchJson(requestUrl, fetchImpl);
  const records = Array.isArray(payload.vulnerabilities) ? payload.vulnerabilities : [];
  let ingested = 0;
  for (const item of records.slice(0, 10)) {
    const advisory = advisoryFromNvd(item, requestUrl, body);
    if (!advisory.cve) {
      continue;
    }
    await ingestVendorSecurityAdvisory(storage, tenantId, advisory);
    ingested += 1;
  }
  return recordRun(storage, tenantId, {
    ...runRecord(body, "nvd-cve-2", "NVD CVE 2.0", "NVD", "completed", `${ingested} NVD CVE records ingested as source-bound pending-review vendor intelligence.`, startedAt, requestUrl),
    records_seen: records.length,
    records_matched: records.length,
    records_ingested: ingested
  });
}

async function refreshCiscoPsirt({ storage, tenantId, body, fetchImpl }) {
  const startedAt = new Date().toISOString();
  const sourceUrl = body.source_url || null;
  const credentialConfigured = Boolean(body.credentials_reference || body.access_token_reference || body.auth_required === false);
  if (!sourceUrl || !credentialConfigured || body.auth_required !== false) {
    return recordRun(storage, tenantId, runRecord(
      body,
      "vendorlens-cisco-psirt",
      "Cisco PSIRT openVuln",
      "Cisco",
      "blocked",
      "Cisco PSIRT refresh is configured as credentials-reference only. Attach a Key Vault credential reference or configure an unauthenticated source URL before refresh.",
      startedAt,
      sourceUrl
    ));
  }
  const payload = await fetchJson(sourceUrl, fetchImpl);
  const records = recordsFromJsonPayload(payload);
  let ingested = 0;
  for (const item of records.slice(0, boundedLimit(body.limit, 10, 1, 50))) {
    await ingestVendorSecurityAdvisory(storage, tenantId, normalizeGenericAdvisory({ ...item, vendor_id: "cisco", vendor_name: "Cisco", source_url: sourceUrl, source_payload: item, ...lineageFromBody(body) }));
    ingested += 1;
  }
  return recordRun(storage, tenantId, {
    ...runRecord(body, "vendorlens-cisco-psirt", "Cisco PSIRT openVuln", "Cisco", "completed", `${ingested} Cisco PSIRT records ingested as source-bound pending-review intelligence.`, startedAt, sourceUrl),
    records_seen: records.length,
    records_matched: records.length,
    records_ingested: ingested
  });
}

async function refreshGenericVendorSource({ storage, tenantId, body, fetchImpl }) {
  const startedAt = new Date().toISOString();
  const sourceUrl = body.source_url;
  if (!sourceUrl) {
    return recordRun(storage, tenantId, runRecord(body, "vendorlens-generic", "VendorLens generic vendor source", body.vendor_id || "Vendor", "blocked", "Generic vendor advisory refresh requires a configured source_url.", startedAt));
  }
  const responseText = await fetchText(sourceUrl, fetchImpl);
  const records = parseGenericSource(responseText);
  let ingested = 0;
  for (const item of records.slice(0, boundedLimit(body.limit, 10, 1, 50))) {
    await ingestVendorSecurityAdvisory(storage, tenantId, normalizeGenericAdvisory({ ...item, vendor_id: body.vendor_id, vendor_name: body.vendor_name, source_url: item.source_url || sourceUrl, source_payload: item, ...lineageFromBody(body) }));
    ingested += 1;
  }
  return recordRun(storage, tenantId, {
    ...runRecord(body, "vendorlens-generic", "VendorLens generic vendor source", body.vendor_id || "Vendor", "completed", `${ingested} generic vendor source records ingested as source-bound pending-review intelligence.`, startedAt, sourceUrl),
    records_seen: records.length,
    records_matched: records.length,
    records_ingested: ingested
  });
}

function buildConfigChatResponse(question, assessment = {}, body = {}) {
  const posture = assessment.urgency_posture || assessment.current_governed_posture || "urgent_scope_confirmation_required";
  const missing = Array.isArray(assessment.evidence_gaps) ? assessment.evidence_gaps : [];
  const shortAnswer = posture === "emergency_patch_required"
    ? "Treat this as emergency patch governance until a human reviewer confirms scope, patch applicability, and change evidence."
    : posture === "monitor"
      ? "Reviewed evidence may support monitoring or not-applicable review, but final approval is still not issued."
      : "PatchForge cannot safely declare this configuration unaffected yet; complete scope and configuration evidence review first.";
  return {
    short_answer: shortAnswer,
    current_governed_posture: posture,
    why: whyForPosture(assessment),
    evidence_used: assessment.evidence_used || [],
    evidence_missing: missing.map((item) => ({
      gap: item.plain_english_gap || item.gap_id,
      required_evidence: item.required_evidence,
      owner: item.suggested_owner_role
    })),
    configuration_assumptions: [
      body.question || question,
      assessment.affected_feature ? `Feature considered: ${humanize(assessment.affected_feature)}` : "Affected feature is not fully specified.",
      assessment.firmware_version ? `Firmware/version considered: ${assessment.firmware_version}` : "Firmware/version evidence is missing or unreviewed."
    ],
    recommended_next_action: nextActionForPosture(posture),
    decision_not_allowed_yet: assessment.decision_not_allowed_yet || "Final decision requires reviewed evidence and named human approval.",
    human_review_required: true,
    advisory_only: true,
    can_close_hard_gates_alone: false,
    final_approval_issued: false,
    boundary: {
      no_procedural_exploitation_steps: true,
      no_patch_deployment: true,
      no_autonomous_approval: true,
      no_autonomous_risk_acceptance: true
    }
  };
}

function whyForPosture(assessment) {
  if (assessment.urgency_posture === "emergency_patch_required") {
    return "The asset appears applicable, exposed, and linked to a known-exploited source signal. PatchForge still requires reviewed evidence and human approval.";
  }
  if (assessment.applicability_posture === "not_applicable") {
    return "Reviewed asset, version, or feature evidence indicates the advisory may not apply. A named reviewer must still approve not-applicable status.";
  }
  return "Customer product, version, feature, exposure, or advisory evidence is incomplete. PatchForge therefore keeps the decision in reviewed scope-confirmation mode.";
}

function nextActionForPosture(posture) {
  if (posture === "emergency_patch_required") {
    return "Open emergency CAB/security review, attach vendor patch evidence, rollback evidence, and customer exposure confirmation before approval.";
  }
  if (posture === "patch_required") {
    return "Attach patch availability, test, rollback, and service-impact evidence, then request accountable approval.";
  }
  if (posture === "mitigate_temporarily") {
    return "Attach compensating-control evidence and expiry owner before requesting mitigation approval.";
  }
  if (posture === "monitor") {
    return "Record the reviewed evidence that supports monitoring or not-applicable status, then request reviewer signoff.";
  }
  return "Confirm customer exposure, affected feature state, firmware/version, and vendor advisory source review.";
}

function chatMessage(session, role, content, payload) {
  return {
    tenant_id: session.tenant_id,
    message_id: `vl-msg-${Date.now()}-${randomUUID().slice(0, 8)}`,
    session_id: session.session_id,
    role,
    content,
    payload,
    advisory_only: true,
    final_approval_issued: false,
    created_at: new Date().toISOString()
  };
}

function advisoryFromNvd(item, sourceUrl, body) {
  const cve = item.cve || {};
  const descriptions = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const description = descriptions.find((entry) => entry.lang === "en")?.value || descriptions[0]?.value || "";
  const cveId = cve.id || body.cve;
  const cpeMatches = extractCpeMatches(cve.configurations || []);
  return normalizeGenericAdvisory({
    advisory_id: `nvd-${cveId}`,
    cve: cveId,
    cves: [cveId],
    vendor_id: body.vendor_id || vendorFromCpe(cpeMatches) || "unknown-vendor",
    vendor_name: body.vendor_name || humanize(body.vendor_id || vendorFromCpe(cpeMatches) || "unknown vendor"),
    title: `${cveId} NVD CVE metadata`,
    summary: description,
    severity: severityFromNvd(cve),
    source_class: "cve_record",
    source_url: sourceUrl,
    source_payload: item,
    affected_products: cpeMatches,
    affected_versions: [],
    fixed_versions: [],
    review_state: "pending_review",
    evidence_state: "referenced",
    ...lineageFromBody(body)
  });
}

function extractCpeMatches(configurations) {
  const matches = [];
  const visit = (node) => {
    if (!node || typeof node !== "object") {
      return;
    }
    for (const match of node.cpeMatch || []) {
      if (match.criteria) {
        matches.push(match.criteria);
      }
    }
    for (const child of node.nodes || []) {
      visit(child);
    }
  };
  for (const config of configurations) {
    for (const node of config.nodes || []) {
      visit(node);
    }
  }
  return matches.slice(0, 20);
}

function vendorFromCpe(cpeMatches) {
  const first = cpeMatches[0] || "";
  const parts = String(first).split(":");
  return parts[3] ? normalizeVendorId(parts[3]) : null;
}

function severityFromNvd(cve) {
  const metrics = cve.metrics || {};
  const candidates = [
    metrics.cvssMetricV31?.[0]?.cvssData?.baseSeverity,
    metrics.cvssMetricV30?.[0]?.cvssData?.baseSeverity,
    metrics.cvssMetricV2?.[0]?.baseSeverity
  ].filter(Boolean);
  return String(candidates[0] || "unknown").toLowerCase();
}

function normalizeGenericAdvisory(item = {}) {
  const title = item.title || item.name || item.summary || item.cve || item.advisory_id || "Vendor security advisory";
  const cves = extractCves([item.cve, item.cves, title, item.summary, item.description].flat().join(" "));
  return {
    ...item,
    advisory_id: item.advisory_id || `${normalizeVendorId(item.vendor_id || item.vendor_name)}-${cves[0] || hashObject(item).slice(0, 10)}`,
    cve: item.cve || cves[0] || null,
    cves: list(item.cves || cves),
    title,
    summary: item.summary || item.description || "",
    source_hash: item.source_hash || hashObject(item.source_payload || item),
    retrieved_at: item.retrieved_at || new Date().toISOString(),
    review_state: item.review_state || "pending_review",
    evidence_state: item.evidence_state || "referenced"
  };
}

function recordsFromJsonPayload(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }
  for (const key of ["advisories", "vulnerabilities", "items", "data", "results"]) {
    if (Array.isArray(payload?.[key])) {
      return payload[key];
    }
  }
  return payload && typeof payload === "object" ? [payload] : [];
}

function parseGenericSource(text) {
  try {
    return recordsFromJsonPayload(JSON.parse(text));
  } catch {
    const itemMatches = [...String(text).matchAll(/<item\b[\s\S]*?<\/item>/gi)];
    return itemMatches.map((match) => {
      const block = match[0];
      return {
        title: xmlValue(block, "title"),
        summary: xmlValue(block, "description"),
        source_url: xmlValue(block, "link"),
        published_at: xmlValue(block, "pubDate"),
        cves: extractCves(block)
      };
    }).filter((item) => item.title || item.cves.length);
  }
}

async function fetchJson(url, fetchImpl) {
  const response = await fetchImpl(url, {
    headers: {
      accept: "application/json",
      "user-agent": "DIIaC-PatchForge-VendorLens/1.0 source-bound-governance"
    }
  });
  if (!response.ok) {
    throw new Error(`VendorLens source request failed with HTTP ${response.status}`);
  }
  return response.json();
}

async function fetchText(url, fetchImpl) {
  const response = await fetchImpl(url, {
    headers: {
      accept: "application/json, application/rss+xml, application/xml, text/xml, text/plain",
      "user-agent": "DIIaC-PatchForge-VendorLens/1.0 source-bound-governance"
    }
  });
  if (!response.ok) {
    throw new Error(`VendorLens source request failed with HTTP ${response.status}`);
  }
  return response.text();
}

async function recordRun(storage, tenantId, run) {
  const completed = {
    tenant_id: tenantId,
    completed_at: new Date().toISOString(),
    source_bound: true,
    review_required: true,
    advisory_only: true,
    can_close_hard_gates_alone: false,
    no_autonomous_approval: true,
    no_patch_deployment: true,
    ...run
  };
  await storage.append("source_feed_runs", completed);
  await storage.audit(tenantId, "vendorlens_source_refreshed", {
    run_id: completed.run_id,
    feed_id: completed.feed_id,
    status: completed.status,
    records_ingested: completed.records_ingested,
    ...lineageFromBody(run)
  });
  return completed;
}

function runRecord(body, feedId, feedName, provider, status, message, startedAt, sourceUrl = body.source_url || null) {
  return {
    run_id: body.run_id || `run-${feedId}-${Date.now()}-${randomUUID().slice(0, 8)}`,
    feed_id: feedId,
    feed_name: feedName,
    provider,
    source_class: "vendor_advisory",
    source_url: sourceUrl,
    status,
    records_seen: 0,
    records_matched: 0,
    records_ingested: 0,
    records_enriched: 0,
    message,
    started_at: startedAt,
    ...lineageFromBody(body)
  };
}

async function findById(storage, collection, tenantId, id, idField) {
  if (!id) {
    return null;
  }
  return (await storage.list(collection, tenantId)).find((item) => String(item[idField]) === String(id)) || null;
}

function vendor(id, name, category, sourceUrl, productFamilies) {
  return {
    vendor_id: id,
    vendor_name: name,
    vendor_category: category,
    advisory_source_type: "public_vendor_advisory",
    advisory_source_url: sourceUrl,
    product_families: productFamilies,
    source_review_state: "reference_catalogue",
    last_refresh_at: null,
    enabled: true,
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false
  };
}

function extractCves(text) {
  return Array.from(new Set(String(text || "").toUpperCase().match(/CVE-\d{4}-[A-Z0-9-]+/g) || []));
}

function xmlValue(block, tag) {
  const match = String(block).match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? decodeXml(match[1].replace(/<!\[CDATA\[|\]\]>/g, "").trim()) : "";
}

function decodeXml(value) {
  return String(value)
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#39;/g, "'");
}

function boundedLimit(value, fallback, min, max) {
  const numeric = Number(value || fallback);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.floor(numeric)));
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

function list(value) {
  if (Array.isArray(value)) {
    return value.flatMap((item) => list(item));
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function normalizeVendorId(value) {
  return String(value || "unknown-vendor").toLowerCase().replace(/&/g, "and").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "unknown-vendor";
}

function hashObject(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function humanize(value) {
  return String(value || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function lineageFromBody(body = {}) {
  return {
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    actor_roles: Array.isArray(body.actor_roles) ? body.actor_roles : [],
    actor_tenant_id: body.actor_tenant_id || null,
    effective_tenant_id: body.effective_tenant_id || null,
    requested_tenant_id: body.requested_tenant_id || null,
    tenant_id_source: body.tenant_id_source || null,
    tenant_override_ignored: Boolean(body.tenant_override_ignored)
  };
}

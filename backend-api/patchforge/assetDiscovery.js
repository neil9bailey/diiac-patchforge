import { createHash, randomUUID } from "node:crypto";
import { upsertCustomerNetworkAsset } from "./vendorLens.js";

export const ASSET_DISCOVERY_CATEGORIES = [
  "network_device",
  "security_appliance",
  "physical_server",
  "virtual_server",
  "hypervisor",
  "cloud_resource",
  "endpoint",
  "storage",
  "application_platform",
  "unknown"
];

const DISCOVERY_METHODS = [
  "manual_snapshot",
  "cmdb_api",
  "snmpv3_read_only",
  "ssh_read_only",
  "winrm_read_only",
  "wmi_read_only",
  "vcenter_api",
  "hyperv_inventory",
  "cloud_inventory"
];

const RAW_SECRET_KEYS = [
  "password",
  "passphrase",
  "secret",
  "token",
  "api_key",
  "apikey",
  "private_key",
  "client_secret",
  "snmp_community",
  "community_string",
  "raw_credentials"
];

export async function listAssetCollectors(storage, tenantId, options = {}) {
  const now = options.now instanceof Date ? options.now.getTime() : Number(options.now || Date.now());
  const staleAfterMs = positiveNumber(options.staleAfterMs || process.env.PATCHFORGE_COLLECTOR_STALE_AFTER_MS, 8 * 60 * 60 * 1000);
  return (await storage.list("asset_collectors", tenantId))
    .map((collector) => collectorLifecycleState(collector, now, staleAfterMs))
    .sort((a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")));
}

export async function registerAssetCollector(storage, tenantId, body = {}) {
  assertNoRawSecrets(body);
  const now = new Date().toISOString();
  const collectorId = body.collector_id || `collector-${randomUUID().slice(0, 12)}`;
  const existing = (await storage.list("asset_collectors", tenantId)).find((item) => item.collector_id === collectorId) || null;
  if (existing?.status === "revoked" && body.status !== "revoked") {
    throw inputError("collector_revoked", "Collector is revoked and cannot heartbeat or import until an accountable reactivation is recorded.", 409);
  }
  const categories = normalizeCategories(body.categories || body.enabled_categories);
  const record = {
    ...(existing || {}),
    tenant_id: tenantId,
    collector_id: collectorId,
    name: body.name || body.collector_name || existing?.name || "PatchForge asset collector",
    platform: normalizePlatform(body.platform || existing?.platform),
    site: body.site ?? existing?.site ?? null,
    environment: body.environment || existing?.environment || "production",
    enabled_categories: categories.length ? categories : existing?.enabled_categories || ["network_device", "security_appliance", "physical_server", "virtual_server", "hypervisor"],
    connection_mode: "outbound_only",
    auth_mode: normalizeCollectorAuthMode(body.auth_mode || existing?.auth_mode),
    status: normalizeCollectorStatus(body.status || existing?.status || "registered"),
    last_seen_at: body.last_seen_at || body.last_heartbeat_at || existing?.last_seen_at || null,
    last_heartbeat_at: body.last_heartbeat_at || body.last_seen_at || existing?.last_heartbeat_at || null,
    heartbeat_id: body.heartbeat_id || existing?.heartbeat_id || null,
    heartbeat_state: body.heartbeat_state || existing?.heartbeat_state || "awaiting_first_run",
    last_run_id: body.last_run_id || existing?.last_run_id || null,
    last_message: body.last_message || null,
    last_asset_count: nonNegativeNumber(body.last_asset_count, existing?.last_asset_count || 0),
    last_warning_count: nonNegativeNumber(body.last_warning_count, existing?.last_warning_count || 0),
    collector_version: body.collector_version || existing?.collector_version || "unknown",
    package_digest: body.package_digest || existing?.package_digest || null,
    package_channel: body.package_channel || existing?.package_channel || "manual_mvp",
    credential_mode: "environment_or_managed_identity_only",
    advisory_only: true,
    review_required: true,
    no_vulnerability_scanning: true,
    no_exploit_execution: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    final_approval_issued: false,
    created_at: existing?.created_at || body.created_at || now,
    updated_at: now,
    ...lineageFromBody(body)
  };
  await storage.append("asset_collectors", record);
  await storage.audit(tenantId, "asset_collector_registered", {
    collector_id: record.collector_id,
    enabled_categories: record.enabled_categories,
    connection_mode: record.connection_mode,
    ...lineageFromBody(body)
  });
  return record;
}

export async function recordAssetCollectorHeartbeat(storage, tenantId, body = {}) {
  if (!body.collector_id) {
    throw inputError("collector_id_required", "collector_id is required for collector heartbeat.");
  }
  return registerAssetCollector(storage, tenantId, {
    ...body,
    status: body.status || "active",
    last_heartbeat_at: body.last_heartbeat_at || new Date().toISOString()
  });
}

export async function revokeAssetCollector(storage, tenantId, body = {}) {
  const collectorId = body.collector_id;
  if (!collectorId) {
    throw inputError("collector_id_required", "collector_id is required for collector revocation.");
  }
  const existing = (await storage.list("asset_collectors", tenantId)).find((item) => item.collector_id === collectorId);
  if (!existing) {
    throw inputError("collector_not_registered", "Collector is not registered for this tenant.", 404);
  }
  const now = new Date().toISOString();
  const revoked = {
    ...existing,
    status: "revoked",
    heartbeat_state: "revoked",
    revoked_at: now,
    revoked_reason: String(body.reason || "collector lifecycle revocation").slice(0, 500),
    revoked_by: body.actor_upn || body.submitted_by || null,
    updated_at: now,
    final_approval_issued: false,
    no_production_mutation: true
  };
  await storage.append("asset_collectors", revoked);
  await storage.audit(tenantId, "asset_collector_revoked", {
    collector_id: collectorId,
    reason: revoked.revoked_reason,
    ...lineageFromBody(body)
  });
  return revoked;
}

export async function listAssetDiscoveryPolicies(storage, tenantId) {
  return (await storage.list("asset_discovery_policies", tenantId))
    .sort((a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")));
}

export async function upsertAssetDiscoveryPolicy(storage, tenantId, body = {}) {
  assertNoRawSecrets(body);
  const now = new Date().toISOString();
  const categories = normalizeCategories(body.categories || body.asset_categories);
  const methods = normalizeMethods(body.discovery_methods || body.methods);
  const record = {
    tenant_id: tenantId,
    policy_id: body.policy_id || `discovery-policy-${randomUUID().slice(0, 12)}`,
    collector_id: body.collector_id || null,
    name: body.name || "PatchForge discovery policy",
    enabled: body.enabled !== false,
    categories: categories.length ? categories : ["network_device", "security_appliance"],
    discovery_methods: methods.length ? methods : ["manual_snapshot"],
    schedule: body.schedule || "manual",
    scope: normalizeScope(body.scope),
    credential_reference: body.credential_reference || body.credentials_reference || null,
    credential_mode: "reference_only",
    read_only: true,
    outbound_only: true,
    advisory_only: true,
    review_required: true,
    no_vulnerability_scanning: true,
    no_exploit_execution: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    final_approval_issued: false,
    created_at: body.created_at || now,
    updated_at: now,
    ...lineageFromBody(body)
  };
  await storage.append("asset_discovery_policies", record);
  await storage.audit(tenantId, "asset_discovery_policy_upserted", {
    policy_id: record.policy_id,
    collector_id: record.collector_id,
    categories: record.categories,
    discovery_methods: record.discovery_methods,
    ...lineageFromBody(body)
  });
  return record;
}

export async function listAssetDiscoveryRuns(storage, tenantId) {
  return (await storage.list("asset_discovery_runs", tenantId))
    .sort((a, b) => String(b.completed_at || b.started_at || "").localeCompare(String(a.completed_at || a.started_at || "")));
}

export async function buildAssetDiscoveryOverview(storage, tenantId) {
  const [collectors, policies, runs, assets] = await Promise.all([
    listAssetCollectors(storage, tenantId),
    listAssetDiscoveryPolicies(storage, tenantId),
    listAssetDiscoveryRuns(storage, tenantId),
    storage.list("customer_network_assets", tenantId)
  ]);
  const collectorImportedAssets = assets.filter((asset) => asset.discovery_source === "patchforge_collector");
  return {
    tenant_id: tenantId,
    generated_at: new Date().toISOString(),
    categories: ASSET_DISCOVERY_CATEGORIES,
    collectors,
    policies,
    recent_runs: runs.slice(0, 10),
    metrics: {
      collector_count: collectors.length,
      enabled_policy_count: policies.filter((policy) => policy.enabled !== false).length,
      collector_imported_asset_count: collectorImportedAssets.length,
      pending_review_asset_count: collectorImportedAssets.filter((asset) => asset.review_state !== "reviewed").length,
      last_import_at: runs[0]?.completed_at || null
    },
    boundary: discoveryBoundary()
  };
}

export async function importDiscoveredAssets(storage, tenantId, body = {}) {
  assertNoRawSecrets(body);
  const collectorId = body.collector_id;
  if (!collectorId) {
    throw inputError("collector_id_required", "collector_id is required for discovery imports.");
  }
  const assets = Array.isArray(body.assets) ? body.assets : [];
  if (!assets.length) {
    throw inputError("asset_snapshot_required", "At least one asset snapshot is required.");
  }
  const collectors = await storage.list("asset_collectors", tenantId);
  const collector = collectors.find((item) => item.collector_id === collectorId);
  if (!collector) {
    throw inputError("collector_not_registered", "Collector is not registered for this tenant.", 404);
  }
  if (collector.status === "revoked") {
    throw inputError("collector_revoked", "Collector is revoked and imports are blocked.", 409);
  }
  const policies = await listAssetDiscoveryPolicies(storage, tenantId);
  const policy = body.policy_id ? policies.find((item) => item.policy_id === body.policy_id) : null;
  if (body.policy_id && !policy) {
    throw inputError("policy_not_registered", "Discovery policy is not registered for this tenant.", 404);
  }
  if (policy?.collector_id && policy.collector_id !== collector.collector_id) {
    throw inputError("policy_collector_mismatch", "Discovery policy is not assigned to the importing collector.");
  }
  const now = new Date().toISOString();
  const runId = body.run_id || `discovery-run-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const sourceHash = hashObject({ collector_id: collector.collector_id, policy_id: policy?.policy_id || null, assets });
  const existingRun = (await storage.list("asset_discovery_runs", tenantId)).find((item) => item.run_id === runId);
  if (existingRun) {
    if (existingRun.collector_id !== collector.collector_id || existingRun.source_hash !== sourceHash) {
      throw inputError("collector_run_conflict", "The collector run_id was already used for a different source snapshot.", 409);
    }
    const importedAssets = (await storage.list("customer_network_assets", tenantId))
      .filter((asset) => asset.collector_run_id === runId);
    return {
      run: { ...existingRun, idempotent_reuse: true },
      imported_assets: importedAssets,
      rejected_assets: existingRun.rejected || [],
      idempotent_reuse: true,
      boundary: discoveryBoundary()
    };
  }
  const imported = [];
  const rejected = [];
  for (const [index, asset] of assets.entries()) {
    try {
      assertNoRawSecrets(asset);
      const normalized = normalizeCollectorAsset({
        tenantId,
        asset,
        index,
        collector,
        policy,
        runId,
        importedAt: now,
        method: body.discovery_method || body.method || policy?.discovery_methods?.[0] || "manual_snapshot"
      });
      const saved = await upsertCustomerNetworkAsset(storage, tenantId, normalized);
      imported.push(saved);
    } catch (error) {
      rejected.push({
        index,
        asset_ref: asset?.asset_id || asset?.hostname || asset?.name || null,
        error: error.code || "asset_import_rejected",
        message: error.message
      });
    }
  }
  const run = {
    tenant_id: tenantId,
    run_id: runId,
    collector_id: collector.collector_id,
    policy_id: policy?.policy_id || body.policy_id || null,
    started_at: body.started_at || now,
    completed_at: now,
    status: rejected.length && !imported.length ? "rejected" : rejected.length ? "partial" : "completed",
    received_asset_count: assets.length,
    imported_asset_count: imported.length,
    rejected_asset_count: rejected.length,
    categories: [...new Set(imported.map((asset) => asset.asset_category || "unknown"))],
    discovery_method: body.discovery_method || body.method || policy?.discovery_methods?.[0] || "manual_snapshot",
    source_hash: sourceHash,
    rejected,
    advisory_only: true,
    review_required: true,
    final_approval_issued: false,
    no_vulnerability_scanning: true,
    no_exploit_execution: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    ...lineageFromBody(body)
  };
  await storage.append("asset_discovery_runs", run);
  await storage.append("asset_collectors", {
    ...collector,
    status: "active",
    last_seen_at: now,
    updated_at: now
  });
  await storage.audit(tenantId, "asset_discovery_import_completed", {
    run_id: run.run_id,
    collector_id: collector.collector_id,
    imported_asset_count: imported.length,
    rejected_asset_count: rejected.length,
    ...lineageFromBody(body)
  });
  return {
    run,
    imported_assets: imported,
    rejected_assets: rejected,
    boundary: discoveryBoundary()
  };
}

export function discoveryBoundary() {
  return {
    advisory_only: true,
    source_bound: true,
    review_required: true,
    outbound_collector_only: true,
    no_vulnerability_scanning: true,
    no_exploit_execution: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    no_autonomous_approval: true,
    final_approval_issued: false
  };
}

function normalizeCollectorAsset({ tenantId, asset, index, collector, policy, runId, importedAt, method }) {
  const category = normalizeCategory(asset.asset_category || asset.category || asset.type);
  const allowedCategories = new Set(policy?.categories?.length ? policy.categories : collector.enabled_categories || ASSET_DISCOVERY_CATEGORIES);
  if (!allowedCategories.has(category) && category !== "unknown") {
    throw inputError("category_not_allowed", `Asset category ${category} is not enabled for this collector policy.`);
  }
  const hostname = asset.hostname || asset.name || asset.asset_name || null;
  const vendor = asset.vendor_id || asset.vendor_name || asset.vendor || null;
  const productFamily = asset.product_family || asset.product || asset.os_family || null;
  const model = asset.model || asset.instance_type || null;
  const version = asset.firmware_version || asset.os_version || asset.version || asset.hypervisor_version || null;
  const assetId = asset.asset_id || stableAssetId(tenantId, collector.collector_id, category, hostname, vendor, productFamily, model, asset.serial_or_asset_ref || asset.serial_number || asset.cloud_resource_id || index);
  return {
    asset_id: assetId,
    vendor_id: vendor || "unknown",
    vendor_name: asset.vendor_name || asset.vendor || null,
    product_family: productFamily,
    model,
    firmware_version: version,
    serial_or_asset_ref: asset.serial_or_asset_ref || asset.serial_number || asset.cloud_resource_id || null,
    environment: asset.environment || collector.environment || "production",
    site: asset.site || collector.site || null,
    service_owner: asset.service_owner || asset.owner || null,
    internet_facing: Boolean(asset.internet_facing),
    management_exposure: asset.management_exposure || asset.exposure || "unknown",
    enabled_features: list(asset.enabled_features || asset.features),
    disabled_features: list(asset.disabled_features),
    config_evidence_refs: list(asset.config_evidence_refs || asset.evidence_refs || runId),
    asset_category: category,
    discovery_source: "patchforge_collector",
    discovery_method: normalizeMethod(method),
    collector_id: collector.collector_id,
    collector_policy_id: policy?.policy_id || null,
    collector_run_id: runId,
    collector_imported_at: importedAt,
    collector_confidence: confidence(asset.confidence),
    hostname,
    ip_addresses: list(asset.ip_addresses || asset.ip_address || asset.management_ip),
    mac_addresses: list(asset.mac_addresses || asset.mac_address),
    cloud_resource_id: asset.cloud_resource_id || null,
    virtualization_host: asset.virtualization_host || asset.hypervisor_host || null,
    review_state: "pending_review",
    evidence_state: "collector_imported_unreviewed",
    source_state: "source_bound",
    advisory_only: true,
    review_required: true,
    final_approval_issued: false
  };
}

function normalizeScope(scope = {}) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) {
    return {};
  }
  return {
    sites: list(scope.sites),
    asset_groups: list(scope.asset_groups),
    ip_ranges: list(scope.ip_ranges),
    source_systems: list(scope.source_systems)
  };
}

function normalizePlatform(platform) {
  const value = String(platform || "unknown").toLowerCase();
  if (["windows", "linux", "container", "appliance"].includes(value)) {
    return value;
  }
  return "unknown";
}

function normalizeCollectorAuthMode(value) {
  const normalized = String(value || "collector_identity").toLowerCase().replace(/[^a-z0-9]+/g, "_");
  return ["environment_bearer", "azure_cli_managed_identity", "azure_cli_cached_identity", "collector_identity"].includes(normalized)
    ? normalized
    : "collector_identity";
}

function normalizeCollectorStatus(value) {
  const normalized = String(value || "registered").toLowerCase();
  return ["registered", "active", "degraded", "revoked"].includes(normalized) ? normalized : "registered";
}

function collectorLifecycleState(collector, now, staleAfterMs) {
  if (collector.status === "revoked") {
    return { ...collector, health_status: "revoked", heartbeat_age_minutes: null, next_heartbeat_due_at: null };
  }
  const heartbeatAt = Date.parse(collector.last_heartbeat_at || collector.last_seen_at || "");
  if (!Number.isFinite(heartbeatAt)) {
    return { ...collector, health_status: "pending", heartbeat_age_minutes: null, next_heartbeat_due_at: null };
  }
  const ageMs = Math.max(0, now - heartbeatAt);
  const failed = ["failed", "completed_with_rejections"].includes(String(collector.heartbeat_state || "").toLowerCase());
  return {
    ...collector,
    health_status: ageMs > staleAfterMs ? "stale" : failed || collector.status === "degraded" ? "degraded" : "ready",
    heartbeat_age_minutes: Math.floor(ageMs / 60000),
    next_heartbeat_due_at: new Date(heartbeatAt + staleAfterMs).toISOString()
  };
}

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function nonNegativeNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function normalizeCategories(value) {
  return list(value).map(normalizeCategory);
}

function normalizeCategory(value) {
  const normalized = String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  return ASSET_DISCOVERY_CATEGORIES.includes(normalized) ? normalized : "unknown";
}

function normalizeMethods(value) {
  return list(value).map(normalizeMethod);
}

function normalizeMethod(value) {
  const normalized = String(value || "manual_snapshot").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  return DISCOVERY_METHODS.includes(normalized) ? normalized : "manual_snapshot";
}

function confidence(value) {
  const number = Number(value);
  if (Number.isFinite(number)) {
    return Math.max(0, Math.min(1, number));
  }
  return 0.5;
}

function stableAssetId(...parts) {
  return `disc-${createHash("sha256").update(parts.map((part) => String(part || "")).join("|")).digest("hex").slice(0, 16)}`;
}

function hashObject(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function list(value) {
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return Array.isArray(value) ? value.map(String).filter(Boolean) : String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function assertNoRawSecrets(value, path = []) {
  if (!value || typeof value !== "object") {
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const currentPath = [...path, key];
    if ((normalized === "credential_reference" || normalized === "credentials_reference") && typeof child === "string") {
      continue;
    }
    if (RAW_SECRET_KEYS.includes(normalized)) {
      throw inputError("raw_secret_rejected", `Raw secret field is not allowed in collector payload: ${currentPath.join(".")}`);
    }
    if (child && typeof child === "object") {
      assertNoRawSecrets(child, currentPath);
    }
  }
}

function lineageFromBody(body = {}) {
  return {
    actor_upn: body.actor_upn || body.submitted_by || null,
    source: body.source || "patchforge-discovery",
    correlation_id: body.correlation_id || null
  };
}

function inputError(code, message, statusCode = 400) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  error.publicError = code;
  error.publicMessage = message;
  return error;
}

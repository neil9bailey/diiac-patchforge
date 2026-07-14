#!/usr/bin/env node
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, readFile, readdir, rename, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { isSea } from "node:sea";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const bearerTokenCache = new WeakMap();

const DEFAULT_CATEGORIES = [
  "network_device",
  "security_appliance",
  "physical_server",
  "virtual_server",
  "hypervisor",
  "cloud_resource",
  "endpoint",
  "storage",
  "application_platform"
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

const SENSITIVE_HEADER_KEYS = new Set([
  "authorization",
  "proxy_authorization",
  "x_api_key",
  "api_key",
  "x_auth_token"
]);

export async function runCollector(options = {}) {
  const env = options.env || process.env;
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const commandRunner = options.commandRunner || runCommand;
  if (!fetchImpl) {
    throw new Error("A fetch implementation is required.");
  }
  const config = options.config || await loadConfig(options.configPath || env.PATCHFORGE_COLLECTOR_CONFIG, env);
  const normalized = normalizeConfig(config, env);
  await assertCollectorNotRevoked(normalized.lifecycle.revocationFile);
  const now = options.now || (() => new Date());
  const startedAt = now().toISOString();
  const runId = normalized.runId || `collector-run-${Date.now()}-${hashValue(startedAt).slice(0, 8)}`;
  const dryRun = Boolean(options.dryRun || normalized.dryRun);
  const replay = dryRun
    ? emptyReplaySummary()
    : await replayCollectorSpool(normalized, { fetchImpl, env, commandRunner });
  const heartbeatBase = collectorHeartbeat(normalized, {
    runId,
    observedAt: startedAt,
    state: dryRun ? "dry_run" : "running",
    authMode: collectorAuthMode(normalized, env),
    spoolPending: replay.remaining
  });
  await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, heartbeatBase);

  if (!dryRun) {
    try {
      await postJson(normalized, "/api/patchforge/discovery/collectors", heartbeatBase, fetchImpl, env, commandRunner);
    } catch (error) {
      if (!normalized.lifecycle.spoolDirectory || !isRetryableDeliveryError(error)) {
        throw error;
      }
    }
  }

  let discovery;
  try {
    discovery = await collectAssets({
      config: normalized,
      env,
      fetchImpl,
      commandRunner,
      startedAt
    });
  } catch (error) {
    const failedHeartbeat = collectorHeartbeat(normalized, {
      runId,
      observedAt: now().toISOString(),
      state: "failed",
      authMode: collectorAuthMode(normalized, env),
      message: error.message
    });
    await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, failedHeartbeat);
    throw error;
  }
  const importPayload = {
    run_id: runId,
    collector_id: normalized.collector.collector_id,
    policy_id: normalized.policy.policy_id,
    discovery_method: discovery.discoveryMethod,
    started_at: startedAt,
    assets: discovery.assets,
    source: "patchforge-collector",
    correlation_id: runId
  };

  if (dryRun) {
    const completedHeartbeat = collectorHeartbeat(normalized, {
      runId,
      observedAt: now().toISOString(),
      state: "dry_run_completed",
      authMode: collectorAuthMode(normalized, env),
      assetCount: discovery.assets.length,
      warningCount: discovery.warnings.length
    });
    await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, completedHeartbeat);
    return {
      mode: "dry_run",
      collector: normalized.collector,
      policy: normalized.policy,
      assets: discovery.assets,
      warnings: discovery.warnings,
      boundary: collectorBoundary()
    };
  }

  const completedHeartbeat = collectorHeartbeat(normalized, {
    runId,
    observedAt: now().toISOString(),
    state: discovery.assets.length ? "completed" : "completed_no_assets",
    authMode: collectorAuthMode(normalized, env),
    assetCount: discovery.assets.length,
    warningCount: discovery.warnings.length,
    spoolPending: replay.remaining
  });

  const submission = {
    schema: "patchforge-collector-offline-submission-v1",
    spool_id: `submission-${hashValue(`${normalized.tenantId}|${normalized.collector.collector_id}|${runId}`).slice(0, 32)}`,
    tenant_id: normalized.tenantId,
    collector_id: normalized.collector.collector_id,
    run_id: runId,
    created_at: startedAt,
    attempts: 0,
    completed_steps: [],
    policy: normalized.policy,
    import_payload: discovery.assets.length ? importPayload : null,
    completed_heartbeat: completedHeartbeat
  };

  let delivery;
  try {
    delivery = await deliverCurrentSubmission(normalized, submission, replay, { fetchImpl, env, commandRunner });
  } catch (error) {
    const failedHeartbeat = collectorHeartbeat(normalized, {
      runId,
      observedAt: now().toISOString(),
      state: "failed",
      authMode: collectorAuthMode(normalized, env),
      assetCount: discovery.assets.length,
      warningCount: discovery.warnings.length,
      message: error.message,
      spoolPending: replay.remaining
    });
    await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, failedHeartbeat);
    throw error;
  }

  if (delivery.spooled) {
    const deliveryState = delivery.quarantined ? "quarantined" : "queued_offline";
    const queuedHeartbeat = collectorHeartbeat(normalized, {
      runId,
      observedAt: now().toISOString(),
      state: deliveryState,
      authMode: collectorAuthMode(normalized, env),
      assetCount: discovery.assets.length,
      warningCount: discovery.warnings.length,
      message: delivery.message,
      spoolPending: delivery.pending
    });
    await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, queuedHeartbeat);
    return {
      mode: "push",
      status: deliveryState,
      collector: normalized.collector.collector_id,
      policy: normalized.policy.policy_id,
      discovered_asset_count: discovery.assets.length,
      imported_asset_count: 0,
      rejected_asset_count: 0,
      spool: {
        queued: !delivery.quarantined,
        pending: delivery.pending,
        replayed: replay.replayed,
        quarantined: replay.quarantined + (delivery.quarantined ? 1 : 0)
      },
      warnings: discovery.warnings,
      boundary: collectorBoundary()
    };
  }

  const imported = delivery.imported || {};
  completedHeartbeat.heartbeat_state = imported.run?.status === "rejected" ? "completed_with_rejections" : completedHeartbeat.heartbeat_state;
  completedHeartbeat.last_asset_count = imported.run?.imported_asset_count ?? imported.imported_assets?.length ?? discovery.assets.length;
  await writeHeartbeatFile(normalized.lifecycle.heartbeatFile, completedHeartbeat);
  return {
    mode: "push",
    status: discovery.assets.length ? (imported.run?.status || "submitted") : "no_assets_collected",
    run: imported.run,
    imported_asset_count: imported.run?.imported_asset_count ?? imported.imported_assets?.length ?? 0,
    rejected_asset_count: imported.run?.rejected_asset_count ?? imported.rejected_assets?.length ?? 0,
    spool: {
      queued: false,
      pending: replay.remaining,
      replayed: replay.replayed,
      quarantined: replay.quarantined
    },
    warnings: discovery.warnings,
    boundary: imported.boundary || collectorBoundary()
  };
}

export async function loadConfig(configPath, env = process.env) {
  const path = configPath || "patchforge-collector.config.json";
  const text = await readFile(path, "utf8");
  return normalizeConfig(JSON.parse(text), env);
}

export function normalizeConfig(input = {}, env = process.env) {
  assertNoRawSecrets(input);
  const apiBaseUrl = stripTrailingSlash(input.apiBaseUrl || env.PATCHFORGE_API_BASE_URL || "");
  const tenantId = input.tenantId || env.PATCHFORGE_TENANT_ID || "";
  if (!apiBaseUrl) {
    throw new Error("apiBaseUrl or PATCHFORGE_API_BASE_URL is required.");
  }
  if (!tenantId) {
    throw new Error("tenantId or PATCHFORGE_TENANT_ID is required.");
  }
  const collectorId = input.collector?.collector_id
    || input.collector?.collectorId
    || env.PATCHFORGE_COLLECTOR_ID
    || `collector-${slug(os.hostname())}`;
  const platform = normalizePlatform(input.collector?.platform || os.platform());
  const categories = list(input.collector?.categories || input.collector?.enabled_categories || DEFAULT_CATEGORIES);
  const policyId = input.policy?.policy_id
    || input.policy?.policyId
    || env.PATCHFORGE_COLLECTOR_POLICY_ID
    || `policy-${collectorId}`;
  const adapters = (Array.isArray(input.adapters) ? input.adapters : [{ type: "local_host", enabled: true }])
    .filter((adapter) => adapter && adapter.enabled !== false)
    .map((adapter) => ({ ...adapter, type: normalizeAdapterType(adapter.type) }));
  const managedIdentityClientIdEnv = input.auth?.managedIdentityClientIdEnv
    || input.auth?.managed_identity_client_id_env
    || "PATCHFORGE_COLLECTOR_MANAGED_IDENTITY_CLIENT_ID";
  return {
    apiBaseUrl,
    tenantId,
    dryRun: Boolean(input.dryRun),
    auth: {
      bearerTokenEnv: input.auth?.bearerTokenEnv || input.auth?.bearer_token_env || env.PATCHFORGE_COLLECTOR_TOKEN_ENV || "PATCHFORGE_COLLECTOR_TOKEN",
      azureCliScope: input.auth?.azureCliScope || input.auth?.azure_cli_scope || env.PATCHFORGE_COLLECTOR_AZURE_SCOPE || "",
      azureTenantId: input.auth?.azureTenantId || input.auth?.azure_tenant_id || env.PATCHFORGE_COLLECTOR_AZURE_TENANT_ID || "",
      azureCliManagedIdentity: Boolean(input.auth?.azureCliManagedIdentity || input.auth?.azure_cli_managed_identity || parseBoolean(env.PATCHFORGE_COLLECTOR_AZURE_CLI_MANAGED_IDENTITY, false)),
      managedIdentityClientId: input.auth?.managedIdentityClientId || input.auth?.managed_identity_client_id || env[managedIdentityClientIdEnv] || "",
      managedIdentityClientIdEnv
    },
    lifecycle: {
      revocationFile: input.lifecycle?.revocationFile || input.lifecycle?.revocation_file || env.PATCHFORGE_COLLECTOR_REVOCATION_FILE || "",
      heartbeatFile: input.lifecycle?.heartbeatFile || input.lifecycle?.heartbeat_file || env.PATCHFORGE_COLLECTOR_HEARTBEAT_FILE || "",
      collectorVersion: input.lifecycle?.collectorVersion || input.lifecycle?.collector_version || env.PATCHFORGE_COLLECTOR_VERSION || "development",
      packageDigest: input.lifecycle?.packageDigest || input.lifecycle?.package_digest || env.PATCHFORGE_COLLECTOR_PACKAGE_DIGEST || null,
      spoolDirectory: input.lifecycle?.spoolDirectory || input.lifecycle?.spool_directory || env.PATCHFORGE_COLLECTOR_SPOOL_DIRECTORY || "",
      maxSpoolEntries: boundedNumber(input.lifecycle?.maxSpoolEntries || input.lifecycle?.max_spool_entries || env.PATCHFORGE_COLLECTOR_MAX_SPOOL_ENTRIES, 100, 1, 10000),
      maxSpoolEntryBytes: boundedNumber(input.lifecycle?.maxSpoolEntryBytes || input.lifecycle?.max_spool_entry_bytes || env.PATCHFORGE_COLLECTOR_MAX_SPOOL_ENTRY_BYTES, 8 * 1024 * 1024, 64 * 1024, 100 * 1024 * 1024),
      maxReplayAttempts: boundedNumber(input.lifecycle?.maxReplayAttempts || input.lifecycle?.max_replay_attempts || env.PATCHFORGE_COLLECTOR_MAX_REPLAY_ATTEMPTS, 5, 1, 20)
    },
    collector: {
      collector_id: collectorId,
      name: input.collector?.name || `PatchForge Collector ${os.hostname()}`,
      platform,
      site: input.collector?.site || env.PATCHFORGE_COLLECTOR_SITE || null,
      environment: input.collector?.environment || env.PATCHFORGE_COLLECTOR_ENVIRONMENT || "production",
      categories,
      package_channel: input.collector?.package_channel
        || input.collector?.packageChannel
        || env.PATCHFORGE_COLLECTOR_PACKAGE_CHANNEL
        || "node_cli_day1"
    },
    policy: {
      policy_id: policyId,
      collector_id: collectorId,
      name: input.policy?.name || "PatchForge collector policy",
      enabled: input.policy?.enabled !== false,
      categories: list(input.policy?.categories || categories),
      discovery_methods: adapterMethods(adapters),
      schedule: input.policy?.schedule || "collector_managed",
      credential_reference: input.policy?.credential_reference || input.policy?.credentials_reference || null,
      scope: input.policy?.scope || {}
    },
    adapters,
    runId: input.runId || input.run_id || null
  };
}

export async function collectAssets({ config, env = process.env, fetchImpl = globalThis.fetch, commandRunner = runCommand, startedAt = new Date().toISOString() }) {
  const assets = [];
  const warnings = [];
  for (const adapter of config.adapters) {
    try {
      if (adapter.type === "local_host") {
        assets.push(await collectLocalHost({ config, adapter, commandRunner, startedAt }));
      } else if (adapter.type === "hyperv") {
        assets.push(...await collectHyperV({ config, adapter, commandRunner }));
      } else if (adapter.type === "azure_cli") {
        assets.push(...await collectAzureCli({ config, adapter, commandRunner }));
      } else if (adapter.type === "http_json") {
        assets.push(...await collectHttpJson({ config, adapter, env, fetchImpl }));
      } else {
        warnings.push(`Unsupported adapter skipped: ${adapter.type}`);
      }
    } catch (error) {
      warnings.push(`${adapter.type} adapter skipped: ${error.message}`);
    }
  }
  const uniqueAssets = dedupeAssets(assets.filter(Boolean));
  return {
    assets: uniqueAssets,
    warnings,
    discoveryMethod: config.adapters.map((adapter) => adapter.type).join("+") || "collector"
  };
}

export async function collectLocalHost({ config, adapter = {}, commandRunner = runCommand, startedAt = new Date().toISOString() }) {
  const system = await systemProfile(commandRunner);
  const nics = networkFacts();
  const virtualized = Boolean(system.virtualization && system.virtualization !== "none");
  const category = adapter.category || (virtualized ? "virtual_server" : "physical_server");
  return normalizeAsset({
    asset_id: adapter.asset_id || stableAssetId(config.tenantId, config.collector.collector_id, os.hostname(), category),
    category,
    hostname: os.hostname(),
    vendor_name: system.vendor || os.type(),
    product_family: system.product_family || os.type(),
    model: system.model || os.machine?.() || os.arch(),
    os_version: `${os.platform()} ${os.release()}`,
    environment: config.collector.environment,
    site: config.collector.site,
    enabled_features: system.enabled_features || [],
    ip_addresses: nics.ip_addresses,
    mac_addresses: nics.mac_addresses,
    management_exposure: adapter.management_exposure || "unknown",
    confidence: 0.8,
    config_evidence_refs: [`collector:${config.collector.collector_id}`, `collected_at:${startedAt}`]
  });
}

export async function collectHyperV({ config, commandRunner = runCommand }) {
  if (os.platform() !== "win32") {
    return [];
  }
  const script = "Get-VM | Select-Object Name,State,ComputerName,Generation,Version,Id | ConvertTo-Json -Compress";
  const output = await commandRunner("powershell.exe", ["-NoProfile", "-Command", script], { timeout: 20000 });
  const records = asArray(parseJson(output.stdout));
  return records.map((vm) => normalizeAsset({
    asset_id: stableAssetId(config.tenantId, config.collector.collector_id, "hyperv", vm.Id || vm.Name),
    category: "virtual_server",
    hostname: vm.Name,
    vendor_name: "Microsoft",
    product_family: "Hyper-V VM",
    model: vm.Generation ? `Generation ${vm.Generation}` : null,
    firmware_version: vm.Version || null,
    virtualization_host: vm.ComputerName || os.hostname(),
    environment: config.collector.environment,
    site: config.collector.site,
    enabled_features: ["hyper-v"],
    confidence: 0.75
  }));
}

export async function collectAzureCli({ config, adapter = {}, commandRunner = runCommand }) {
  const args = ["resource", "list", "--output", "json"];
  if (adapter.subscription) {
    args.push("--subscription", String(adapter.subscription));
  }
  if (adapter.resourceGroup) {
    args.push("--resource-group", String(adapter.resourceGroup));
  }
  const output = await commandRunner("az", args, { timeout: Number(adapter.timeout_ms || 30000) });
  return asArray(parseJson(output.stdout)).map((resource) => normalizeAsset({
    asset_id: stableAssetId(config.tenantId, config.collector.collector_id, "azure", resource.id || resource.name),
    category: "cloud_resource",
    hostname: resource.name,
    vendor_name: "Microsoft",
    product_family: resource.type || "Azure resource",
    model: resource.kind || resource.sku?.name || null,
    cloud_resource_id: resource.id || null,
    environment: tagValue(resource.tags, "environment") || config.collector.environment,
    site: resource.location || config.collector.site,
    service_owner: tagValue(resource.tags, "owner") || tagValue(resource.tags, "service_owner") || null,
    confidence: 0.85
  }));
}

export async function collectHttpJson({ config, adapter = {}, env = process.env, fetchImpl = globalThis.fetch }) {
  if (!adapter.url) {
    throw new Error("http_json adapter requires url.");
  }
  const response = await fetchImpl(adapter.url, {
    method: "GET",
    headers: resolveHeaders(adapter.headers || {}, env)
  });
  if (!response.ok) {
    throw new Error(`HTTP source returned ${response.status}.`);
  }
  const payload = await response.json();
  const records = asArray(valueAtPath(payload, adapter.assetPath || adapter.asset_path || "items"));
  return records.map((item, index) => normalizeAsset(mapHttpJsonAsset(item, adapter, index, config)));
}

export function mapHttpJsonAsset(item = {}, adapter = {}, index = 0, config = {}) {
  const fieldMap = adapter.fieldMap || adapter.field_map || {};
  const read = (target, ...fallbacks) => {
    const mappedPath = fieldMap[target];
    if (mappedPath) {
      const mapped = valueAtPath(item, mappedPath);
      if (mapped !== undefined && mapped !== null && mapped !== "") {
        return mapped;
      }
    }
    for (const key of fallbacks) {
      const value = valueAtPath(item, key);
      if (value !== undefined && value !== null && value !== "") {
        return value;
      }
    }
    return null;
  };
  return {
    asset_id: read("asset_id", "asset_id", "assetId", "id") || stableAssetId(config.tenantId, config.collector?.collector_id, adapter.url, index),
    category: read("category", "asset_category", "category", "type") || adapter.category || "unknown",
    hostname: read("hostname", "hostname", "hostName", "name", "displayName"),
    vendor_name: read("vendor_name", "vendor_name", "vendor", "manufacturer"),
    vendor_id: read("vendor_id", "vendor_id", "vendor"),
    product_family: read("product_family", "product_family", "product", "os", "platform"),
    model: read("model", "model", "deviceModel", "sku"),
    firmware_version: read("firmware_version", "firmware_version", "version", "os_version", "softwareVersion"),
    serial_or_asset_ref: read("serial_or_asset_ref", "serial", "serial_number", "assetTag"),
    environment: read("environment", "environment") || config.collector?.environment,
    site: read("site", "site", "location") || config.collector?.site,
    service_owner: read("service_owner", "owner", "service_owner"),
    internet_facing: Boolean(read("internet_facing", "internet_facing", "public", "publiclyExposed")),
    management_exposure: read("management_exposure", "management_exposure", "exposure") || "unknown",
    enabled_features: list(read("enabled_features", "enabled_features", "features")),
    ip_addresses: list(read("ip_addresses", "ip_addresses", "ip", "ip_address", "management_ip")),
    mac_addresses: list(read("mac_addresses", "mac_addresses", "mac", "mac_address")),
    cloud_resource_id: read("cloud_resource_id", "cloud_resource_id", "resourceId"),
    virtualization_host: read("virtualization_host", "virtualization_host", "hypervisor_host"),
    confidence: Number(read("confidence", "confidence") || adapter.confidence || 0.65)
  };
}

export function normalizeAsset(asset = {}) {
  return {
    asset_id: String(asset.asset_id || stableAssetId(JSON.stringify(asset))).slice(0, 120),
    category: normalizeCategory(asset.category || asset.asset_category),
    hostname: asset.hostname || null,
    vendor_id: asset.vendor_id || asset.vendor_name || asset.vendor || "unknown",
    vendor_name: asset.vendor_name || asset.vendor || null,
    product_family: asset.product_family || asset.product || null,
    model: asset.model || null,
    firmware_version: asset.firmware_version || asset.os_version || asset.version || null,
    serial_or_asset_ref: asset.serial_or_asset_ref || asset.serial_number || null,
    environment: asset.environment || "production",
    site: asset.site || null,
    service_owner: asset.service_owner || asset.owner || null,
    internet_facing: Boolean(asset.internet_facing),
    management_exposure: asset.management_exposure || "unknown",
    enabled_features: list(asset.enabled_features),
    disabled_features: list(asset.disabled_features),
    config_evidence_refs: list(asset.config_evidence_refs),
    ip_addresses: list(asset.ip_addresses || asset.ip_address || asset.management_ip),
    mac_addresses: list(asset.mac_addresses || asset.mac_address),
    cloud_resource_id: asset.cloud_resource_id || null,
    virtualization_host: asset.virtualization_host || null,
    confidence: boundedNumber(asset.confidence, 0.5, 0, 1)
  };
}

export function assertNoRawSecrets(value, path = []) {
  if (!value || typeof value !== "object") {
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const currentPath = [...path, key];
    if (["credential_reference", "credentials_reference", "bearer_token_env"].includes(normalized)) {
      continue;
    }
    if (RAW_SECRET_KEYS.includes(normalized)) {
      throw new Error(`Raw secret field is not allowed in collector config: ${currentPath.join(".")}`);
    }
    if (path.at(-1) === "headers" && SENSITIVE_HEADER_KEYS.has(normalized) && typeof child === "string" && !child.includes("env:")) {
      throw new Error(`Sensitive header must reference an environment variable: ${currentPath.join(".")}`);
    }
    if (child && typeof child === "object") {
      assertNoRawSecrets(child, currentPath);
    }
  }
}

export function collectorBoundary() {
  return {
    advisory_only: true,
    outbound_collector_only: true,
    review_required: true,
    source_bound: true,
    no_vulnerability_scanning: true,
    no_exploit_execution: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    no_autonomous_approval: true,
    final_approval_issued: false
  };
}

function emptyReplaySummary() {
  return { attempted: 0, replayed: 0, quarantined: 0, remaining: 0, blocked: false };
}

async function deliverCurrentSubmission(config, submission, replay, dependencies) {
  if (!config.lifecycle.spoolDirectory) {
    const delivered = await deliverSubmissionEntry(config, submission, dependencies);
    return { spooled: false, imported: delivered.imported || null };
  }

  const queued = await enqueueCollectorSubmission(config, submission);
  if (replay.remaining > 0 || replay.blocked) {
    return {
      spooled: true,
      pending: await countCollectorSpool(config.lifecycle.spoolDirectory),
      message: "A prior offline submission remains pending; this run was queued in FIFO order."
    };
  }

  const outcome = await deliverSpoolFile(config, queued.path, dependencies);
  if (outcome.delivered) {
    return { spooled: false, imported: outcome.imported || null };
  }
  if (outcome.blocked) {
    throw outcome.error;
  }
  return {
    spooled: true,
    quarantined: Boolean(outcome.quarantined),
    pending: await countCollectorSpool(config.lifecycle.spoolDirectory),
    message: outcome.quarantined
      ? "The current submission exceeded bounded replay attempts and was quarantined for operator review."
      : `PatchForge API delivery is unavailable; the run is durably queued for replay. ${outcome.error?.message || ""}`.trim()
  };
}

export async function replayCollectorSpool(config, dependencies = {}) {
  const spoolDirectory = config.lifecycle?.spoolDirectory || "";
  if (!spoolDirectory) {
    return emptyReplaySummary();
  }
  await mkdir(spoolDirectory, { recursive: true, mode: 0o700 });
  const summary = emptyReplaySummary();
  const files = await collectorSpoolFiles(spoolDirectory);
  for (const file of files) {
    summary.attempted += 1;
    const outcome = await deliverSpoolFile(config, file, dependencies);
    if (outcome.delivered) {
      summary.replayed += 1;
      continue;
    }
    if (outcome.quarantined) {
      summary.quarantined += 1;
      continue;
    }
    summary.blocked = Boolean(outcome.blocked);
    break;
  }
  summary.remaining = await countCollectorSpool(spoolDirectory);
  return summary;
}

async function enqueueCollectorSubmission(config, submission) {
  const spoolDirectory = config.lifecycle.spoolDirectory;
  await mkdir(spoolDirectory, { recursive: true, mode: 0o700 });
  const fileName = `${submission.created_at.replace(/[^0-9A-Za-z]/g, "")}-${hashValue(submission.spool_id).slice(0, 24)}.json`;
  const filePath = path.join(spoolDirectory, fileName);
  try {
    const existing = JSON.parse(await readFile(filePath, "utf8"));
    const existingPayload = hashValue(JSON.stringify({ policy: existing.policy, import_payload: existing.import_payload }));
    const requestedPayload = hashValue(JSON.stringify({ policy: submission.policy, import_payload: submission.import_payload }));
    if (existing.spool_id !== submission.spool_id || existingPayload !== requestedPayload) {
      throw new Error(`Collector spool collision detected for ${submission.spool_id}.`);
    }
    return { path: filePath, entry: existing, reused: true };
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  const pending = await countCollectorSpool(spoolDirectory);
  if (pending >= config.lifecycle.maxSpoolEntries) {
    throw new Error(`Collector offline spool limit reached (${config.lifecycle.maxSpoolEntries}). Operator intervention is required before collecting more evidence.`);
  }
  await writeSpoolEntry(config, filePath, submission);
  return { path: filePath, entry: submission, reused: false };
}

async function deliverSpoolFile(config, filePath, dependencies) {
  let entry;
  try {
    entry = JSON.parse(await readFile(filePath, "utf8"));
    assertSpoolEntry(config, entry);
  } catch (error) {
    await quarantineSpoolFile(config, filePath, "invalid");
    return { delivered: false, quarantined: true, error };
  }

  try {
    const delivered = await deliverSubmissionEntry(config, entry, dependencies, async (updated) => {
      entry = updated;
      await writeSpoolEntry(config, filePath, updated);
    });
    await unlink(filePath);
    return { delivered: true, imported: delivered.imported || null };
  } catch (error) {
    entry = {
      ...entry,
      status: isRetryableDeliveryError(error) ? "pending_retry" : "blocked",
      attempts: Number(entry.attempts || 0) + 1,
      last_attempt_at: new Date().toISOString(),
      last_error: String(error.message || error).slice(0, 500)
    };
    await writeSpoolEntry(config, filePath, entry);
    if (isRetryableDeliveryError(error) && entry.attempts >= config.lifecycle.maxReplayAttempts) {
      await quarantineSpoolFile(config, filePath, "replay-limit");
      return { delivered: false, quarantined: true, error };
    }
    return { delivered: false, blocked: !isRetryableDeliveryError(error), error };
  }
}

async function deliverSubmissionEntry(config, entry, dependencies = {}, onProgress = null) {
  const fetchImpl = dependencies.fetchImpl || globalThis.fetch;
  const env = dependencies.env || process.env;
  const commandRunner = dependencies.commandRunner || runCommand;
  const completed = new Set(entry.completed_steps || []);
  let imported = null;

  if (!completed.has("policy")) {
    await postJson(config, "/api/patchforge/discovery/policies", entry.policy, fetchImpl, env, commandRunner);
    completed.add("policy");
    entry = await recordSpoolProgress(entry, completed, onProgress);
  }
  if (entry.import_payload && !completed.has("import")) {
    imported = await postJson(config, "/api/patchforge/discovery/import", entry.import_payload, fetchImpl, env, commandRunner);
    completed.add("import");
    const importedCount = imported.run?.imported_asset_count ?? imported.imported_assets?.length;
    entry = {
      ...entry,
      completed_heartbeat: {
        ...entry.completed_heartbeat,
        heartbeat_state: imported.run?.status === "rejected" ? "completed_with_rejections" : "completed",
        ...(Number.isFinite(Number(importedCount)) ? { last_asset_count: Number(importedCount) } : {})
      }
    };
    entry = await recordSpoolProgress(entry, completed, onProgress);
  }
  if (!completed.has("heartbeat")) {
    await postJson(config, "/api/patchforge/discovery/collectors", entry.completed_heartbeat, fetchImpl, env, commandRunner);
    completed.add("heartbeat");
    entry = await recordSpoolProgress(entry, completed, onProgress);
  }
  return { entry, imported };
}

async function recordSpoolProgress(entry, completed, onProgress) {
  const updated = {
    ...entry,
    status: "delivering",
    completed_steps: [...completed],
    updated_at: new Date().toISOString(),
    last_error: null
  };
  if (onProgress) {
    await onProgress(updated);
  }
  return updated;
}

function assertSpoolEntry(config, entry) {
  if (entry?.schema !== "patchforge-collector-offline-submission-v1"
      || !entry.spool_id
      || entry.tenant_id !== config.tenantId
      || entry.collector_id !== config.collector.collector_id
      || !entry.policy
      || !entry.completed_heartbeat) {
    throw new Error("Collector spool entry is malformed or belongs to a different tenant/collector.");
  }
}

async function writeSpoolEntry(config, filePath, entry) {
  const content = `${JSON.stringify(entry, null, 2)}\n`;
  if (Buffer.byteLength(content, "utf8") > config.lifecycle.maxSpoolEntryBytes) {
    throw new Error(`Collector submission exceeds the configured offline spool entry limit (${config.lifecycle.maxSpoolEntryBytes} bytes).`);
  }
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempPath, content, { encoding: "utf8", mode: 0o600 });
  await rename(tempPath, filePath);
}

async function quarantineSpoolFile(config, filePath, reason) {
  const quarantineDirectory = path.join(config.lifecycle.spoolDirectory, "quarantine");
  await mkdir(quarantineDirectory, { recursive: true, mode: 0o700 });
  const target = path.join(quarantineDirectory, `${path.basename(filePath, ".json")}.${reason}.${Date.now()}.json`);
  await rename(filePath, target);
  return target;
}

async function collectorSpoolFiles(spoolDirectory) {
  try {
    return (await readdir(spoolDirectory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
      .map((entry) => path.join(spoolDirectory, entry.name))
      .sort((left, right) => left.localeCompare(right));
  } catch (error) {
    if (error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
}

async function countCollectorSpool(spoolDirectory) {
  return (await collectorSpoolFiles(spoolDirectory)).length;
}

function isRetryableDeliveryError(error) {
  return error?.retryable !== false;
}

async function postJson(config, path, payload, fetchImpl, env, commandRunner) {
  let response;
  try {
    response = await fetchImpl(apiUrl(config, path), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-tenant-id": config.tenantId,
        ...await authHeader(config, env, commandRunner)
      },
      body: JSON.stringify(payload)
    });
  } catch (cause) {
    const error = new Error(`PatchForge API delivery failed. ${cause.message || cause}`);
    error.retryable = true;
    error.cause = cause;
    throw error;
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.message || body.error || `PatchForge API returned ${response.status}.`);
    error.status = response.status;
    error.retryable = response.status === 408 || response.status === 425 || response.status === 429 || response.status >= 500;
    throw error;
  }
  return body;
}

async function authHeader(config, env, commandRunner = runCommand) {
  const cached = bearerTokenCache.get(config);
  if (cached) {
    return { authorization: `Bearer ${cached}` };
  }
  const token = env[config.auth.bearerTokenEnv];
  if (token) {
    bearerTokenCache.set(config, token);
    return { authorization: `Bearer ${token}` };
  }
  const azureCliToken = await azureCliAccessToken(config, commandRunner);
  if (azureCliToken) {
    bearerTokenCache.set(config, azureCliToken);
  }
  return azureCliToken ? { authorization: `Bearer ${azureCliToken}` } : {};
}

async function azureCliAccessToken(config, commandRunner) {
  if (!config.auth.azureCliScope) {
    return null;
  }
  if (config.auth.azureCliManagedIdentity) {
    const managedIdentityClientId = config.auth.managedIdentityClientId || "";
    const loginArgs = ["login", "--identity", "--allow-no-subscriptions", "--output", "none"];
    if (managedIdentityClientId) {
      loginArgs.splice(2, 0, "--client-id", managedIdentityClientId);
    }
    await commandRunner("az", loginArgs, { timeout: 20000 });
  }
  const args = [
    "account",
    "get-access-token",
    "--scope",
    config.auth.azureCliScope,
    "--query",
    "accessToken",
    "-o",
    "tsv"
  ];
  if (config.auth.azureTenantId) {
    args.splice(2, 0, "--tenant", config.auth.azureTenantId);
  }
  try {
    const output = await commandRunner("az", args, { timeout: 20000 });
    const token = String(output.stdout || "").trim();
    if (!token) {
      throw new Error("Azure CLI returned an empty access token.");
    }
    return token;
  } catch (error) {
    throw new Error(`PatchForge collector token unavailable. Set ${config.auth.bearerTokenEnv} or sign in with Azure CLI for scope ${config.auth.azureCliScope}. ${error.message}`);
  }
}

export function collectorHeartbeat(config, options = {}) {
  const observedAt = options.observedAt || new Date().toISOString();
  return {
    ...config.collector,
    status: ["failed", "queued_offline", "quarantined"].includes(options.state) ? "degraded" : "active",
    last_seen_at: observedAt,
    last_heartbeat_at: observedAt,
    heartbeat_id: `heartbeat-${hashValue(`${config.collector.collector_id}|${options.runId}|${options.state}|${observedAt}`).slice(0, 20)}`,
    heartbeat_state: options.state || "running",
    last_run_id: options.runId || null,
    last_message: options.message ? String(options.message).slice(0, 500) : null,
    last_asset_count: Number(options.assetCount || 0),
    last_warning_count: Number(options.warningCount || 0),
    pending_spool_entries: Number(options.spoolPending || 0),
    collector_version: config.lifecycle.collectorVersion,
    package_digest: config.lifecycle.packageDigest,
    auth_mode: options.authMode || "unavailable",
    credential_mode: "environment_or_managed_identity_only",
    advisory_only: true,
    review_required: true,
    no_vulnerability_scanning: true,
    no_patch_deployment: true,
    no_production_mutation: true,
    final_approval_issued: false
  };
}

export async function assertCollectorNotRevoked(revocationFile) {
  if (!revocationFile) {
    return;
  }
  try {
    await access(revocationFile);
  } catch (error) {
    if (error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error(`PatchForge collector is locally revoked. Remove ${revocationFile} only through an approved reactivation workflow.`);
}

async function writeHeartbeatFile(heartbeatFile, heartbeat) {
  if (!heartbeatFile) {
    return;
  }
  await mkdir(path.dirname(heartbeatFile), { recursive: true });
  await writeFile(heartbeatFile, `${JSON.stringify(heartbeat, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function collectorAuthMode(config, env) {
  if (env[config.auth.bearerTokenEnv]) {
    return "environment_bearer";
  }
  if (config.auth.azureCliManagedIdentity) {
    return "azure_cli_managed_identity";
  }
  return config.auth.azureCliScope ? "azure_cli_cached_identity" : "unavailable";
}

function apiUrl(config, path) {
  const base = stripTrailingSlash(config.apiBaseUrl);
  if (base.endsWith("/api/patchforge")) {
    return `${base}${path.replace(/^\/api\/patchforge/, "")}`;
  }
  return `${base}${path}`;
}

async function systemProfile(commandRunner) {
  if (os.platform() === "win32") {
    try {
      const script = "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,HypervisorPresent | ConvertTo-Json -Compress";
      const output = await commandRunner("powershell.exe", ["-NoProfile", "-Command", script], { timeout: 10000 });
      const record = parseJson(output.stdout) || {};
      return {
        vendor: record.Manufacturer || "Microsoft",
        model: record.Model || null,
        product_family: "Windows Server",
        virtualization: record.HypervisorPresent ? "hyper-v" : "none",
        enabled_features: record.HypervisorPresent ? ["hyper-v"] : []
      };
    } catch {
      return { product_family: "Windows", virtualization: "unknown" };
    }
  }
  if (os.platform() === "linux") {
    let virtualization = "unknown";
    try {
      const output = await commandRunner("systemd-detect-virt", [], { timeout: 5000 });
      virtualization = String(output.stdout || "").trim() || "none";
    } catch {
      virtualization = "unknown";
    }
    return {
      vendor: "Linux",
      model: os.machine?.() || os.arch(),
      product_family: "Linux",
      virtualization
    };
  }
  return { product_family: os.type(), virtualization: "unknown" };
}

function networkFacts() {
  const interfaces = os.networkInterfaces();
  const ipAddresses = [];
  const macAddresses = [];
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (!entry.internal && entry.address) {
        ipAddresses.push(entry.address);
      }
      if (entry.mac && entry.mac !== "00:00:00:00:00:00") {
        macAddresses.push(entry.mac);
      }
    }
  }
  return {
    ip_addresses: [...new Set(ipAddresses)],
    mac_addresses: [...new Set(macAddresses)]
  };
}

async function runCommand(command, args = [], options = {}) {
  return execFileAsync(command, args, {
    timeout: options.timeout || 15000,
    windowsHide: true,
    maxBuffer: 1024 * 1024 * 8
  });
}

function resolveHeaders(headers, env) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, resolveEnvTemplate(String(value), env)]));
}

function resolveEnvTemplate(value, env) {
  return value.replace(/env:([A-Z0-9_]+)/gi, (_match, name) => env[name] || "");
}

function adapterMethods(adapters) {
  const methods = new Set(adapters.map((adapter) => {
    if (adapter.type === "local_host") return "manual_snapshot";
    if (adapter.type === "http_json") return "cmdb_api";
    if (adapter.type === "azure_cli") return "cloud_inventory";
    if (adapter.type === "hyperv") return "hyperv_inventory";
    return adapter.type;
  }));
  return Array.from(methods);
}

function normalizeAdapterType(value) {
  return String(value || "local_host").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}

function normalizePlatform(value) {
  const platform = String(value || "").toLowerCase();
  if (platform === "win32" || platform === "windows") return "windows";
  if (platform === "linux") return "linux";
  if (platform === "darwin") return "linux";
  return platform || "unknown";
}

function normalizeCategory(value) {
  const category = String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  return DEFAULT_CATEGORIES.includes(category) ? category : "unknown";
}

function dedupeAssets(assets) {
  const byId = new Map();
  for (const asset of assets) {
    byId.set(asset.asset_id, asset);
  }
  return Array.from(byId.values());
}

function valueAtPath(value, path) {
  if (!path) {
    return value;
  }
  return String(path).split(".").reduce((current, part) => current?.[part], value);
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
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

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function stableAssetId(...parts) {
  return `disc-${hashValue(parts.map((part) => String(part || "")).join("|")).slice(0, 16)}`;
}

function hashValue(value) {
  return createHash("sha256").update(String(value || "")).digest("hex");
}

function parseJson(value) {
  if (!String(value || "").trim()) {
    return null;
  }
  return JSON.parse(value);
}

function tagValue(tags, key) {
  if (!tags || typeof tags !== "object") {
    return null;
  }
  const found = Object.entries(tags).find(([tag]) => tag.toLowerCase() === key.toLowerCase());
  return found?.[1] || null;
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function slug(value) {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "unknown";
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const configArg = process.argv.find((arg) => arg.startsWith("--config="));
  const result = await runCollector({
    configPath: configArg ? configArg.split("=").slice(1).join("=") : undefined,
    dryRun: args.has("--dry-run")
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

function isDirectExecution() {
  if (isSea()) {
    return true;
  }

  if (!process.argv[1] || !import.meta.url) {
    return false;
  }

  return path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1]);
}

if (isDirectExecution()) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

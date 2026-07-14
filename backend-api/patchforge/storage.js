import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const COLLECTIONS = [
  "vulnerabilities",
  "sources",
  "assets",
  "services",
  "reviews",
  "finding_evidence",
  "finding_evidence_events",
  "decision_packs",
  "export_artifacts",
  "bayesian_assessments",
  "vendors",
  "vendor_advisories",
  "vendor_security_advisories",
  "threat_signals",
  "network_vendors",
  "network_product_families",
  "network_product_models",
  "network_firmware_versions",
  "customer_network_assets",
  "config_applicability_assessments",
  "vendorlens_patch_comparisons",
  "vendorlens_chat_sessions",
  "vendorlens_chat_messages",
  "agent_guidance_snapshots",
  "report_quality_reviews",
  "asset_collectors",
  "asset_discovery_policies",
  "asset_discovery_runs",
  "source_feed_runs",
  "automation_work_items",
  "automation_checkpoints",
  "automation_failures",
  "automation_dead_letters",
  "automation_leases",
  "automation_reconciliation_runs",
  "customers",
  "customer_estates",
  "customer_assets",
  "config_evidence",
  "exposure_matches",
  "patch_actions",
  "patch_compare_reports",
  "signed_action_packs",
  "workflow_items",
  "uat_cleanup_previews",
  "audit_events"
];

export const PATCHFORGE_PURGE_CONFIRMATION = "FACTORY_RESET_PATCHFORGE";
export const PATCHFORGE_UAT_IDENTIFIER_PREFIX = "UAT-PF-";

const PATCHFORGE_UAT_IDENTIFIER_PATTERN = /^UAT-PF-[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PATCHFORGE_UAT_CLEANUP_COLLECTIONS = COLLECTIONS.filter((collection) => ![
  "audit_events",
  "uat_cleanup_previews"
].includes(collection));
const PATCHFORGE_UAT_PREVIEW_TTL_MS = 15 * 60 * 1000;
const PATCHFORGE_UAT_FORBIDDEN_SELECTORS = [
  "all",
  "scope",
  "scopes",
  "collection",
  "collections",
  "reports",
  "catalogue",
  "assets",
  "uploads",
  "logs",
  "cache"
];

export const PATCHFORGE_PURGE_SCOPES = {
  reports: [
    "decision_packs",
    "export_artifacts",
    "signed_action_packs",
    "report_quality_reviews",
    "patch_compare_reports"
  ],
  catalogue: [
    "vulnerabilities",
    "sources",
    "vendors",
    "vendor_advisories",
    "vendor_security_advisories",
    "threat_signals",
    "network_vendors",
    "network_product_families",
    "network_product_models",
    "network_firmware_versions",
    "source_feed_runs"
  ],
  assets: [
    "assets",
    "services",
    "customers",
    "customer_estates",
    "customer_assets",
    "customer_network_assets",
    "asset_collectors",
    "asset_discovery_policies",
    "asset_discovery_runs",
    "config_applicability_assessments",
    "exposure_matches",
    "patch_actions",
    "workflow_items"
  ],
  uploads: [
    "finding_evidence",
    "finding_evidence_events",
    "config_evidence",
    "vendorlens_chat_sessions",
    "vendorlens_chat_messages",
    "agent_guidance_snapshots"
  ],
  logs: [
    "audit_events",
    "automation_failures",
    "automation_dead_letters",
    "automation_reconciliation_runs"
  ],
  cache: [
    "bayesian_assessments"
  ]
};

const COLLECTION_ID_FIELDS = {
  vulnerabilities: "vulnerability_id",
  sources: "source_record_id",
  assets: "asset_id",
  services: "service_id",
  reviews: "review_id",
  finding_evidence: "evidence_id",
  finding_evidence_events: "evidence_event_id",
  decision_packs: "decision_pack_id",
  export_artifacts: "artifact_id",
  bayesian_assessments: "assessment_id",
  vendors: "vendor_id",
  vendor_advisories: "advisory_id",
  vendor_security_advisories: "advisory_id",
  threat_signals: "signal_id",
  network_vendors: "vendor_id",
  network_product_families: "family_id",
  network_product_models: "model_id",
  network_firmware_versions: "firmware_id",
  customer_network_assets: "asset_id",
  config_applicability_assessments: "assessment_id",
  vendorlens_patch_comparisons: "comparison_id",
  vendorlens_chat_sessions: "session_id",
  vendorlens_chat_messages: "message_id",
  agent_guidance_snapshots: "snapshot_id",
  report_quality_reviews: "review_id",
  asset_collectors: "collector_id",
  asset_discovery_policies: "policy_id",
  asset_discovery_runs: "run_id",
  source_feed_runs: "run_id",
  automation_work_items: "work_id",
  automation_checkpoints: "checkpoint_id",
  automation_failures: "failure_id",
  automation_dead_letters: "dead_letter_id",
  automation_leases: "lease_id",
  automation_reconciliation_runs: "reconciliation_id",
  customers: "id",
  customer_estates: "id",
  customer_assets: "id",
  config_evidence: "id",
  exposure_matches: "id",
  patch_actions: "id",
  patch_compare_reports: "id",
  signed_action_packs: "id",
  workflow_items: "id",
  uat_cleanup_previews: "preview_id",
  audit_events: "audit_id"
};

const DEFAULT_ADMIN_CONFIG = {
  tenant_id: "diiac.io",
  general: {
    product_name: "DIIaC PatchForge",
    target_url: "https://patchforge.diiac.io",
    environment: "Production",
    governance_tier: "Enterprise Strict"
  },
  entra: {
    tenant_domain: "diiac.io",
    app_roles_enabled: true,
    required_roles: [
      "PatchForge.Reader",
      "PatchForge.TriageAnalyst",
      "PatchForge.SecurityLead",
      "PatchForge.ServiceOwner",
      "PatchForge.CABApprover",
      "PatchForge.RiskOwner",
      "PatchForge.Admin",
      "PatchForge.Auditor"
    ]
  },
  sra: {
    advisory_only: true,
    review_required: true,
    can_close_hard_gates_alone: false
  },
  agent_intelligence: {
    intake_model: "agent_led_human_approved",
    mcp_agent_findings_enabled: true,
    mythos_findings_enabled: true,
    agi_agent_findings_enabled: true,
    openai_native_agents_enabled: false,
    openai_model: process.env.PATCHFORGE_OPENAI_MODEL || "gpt-5.4",
    openai_key_source: "Azure Key Vault or environment only",
    advisory_only: true,
    review_required: true,
    can_close_hard_gates_alone: false,
    existing_llm_keys_only: true
  },
  bayesian: {
    enabled: true,
    prior_set: "patchforge-default-v1",
    dry_run_prior_update: true,
    live_prior_update_enabled: false,
    advisory_only: true,
    can_close_hard_gates_alone: false
  },
  vendor_intelligence: {
    enabled: true,
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false
  },
  vendorlens: {
    enabled: true,
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false,
    final_approval_requires_human: true,
    source_refresh: {
      nvd_cve_enabled: true,
      cisco_psirt_enabled: true,
      generic_vendor_sources_enabled: true
    },
    sources: [
      {
        source_id: "nvd-cve-2",
        provider: "NVD",
        source_type: "nvd_cve_api",
        source_url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
        auth_required: false,
        credentials_reference: null,
        enabled: true,
        refresh_cadence: "on_demand"
      },
      {
        source_id: "cisco-psirt-openvuln",
        provider: "Cisco",
        source_type: "cisco_psirt_openvuln",
        source_url: "https://developer.cisco.com/psirt/",
        auth_required: true,
        credentials_reference: "key-vault:cisco-psirt-api",
        enabled: true,
        refresh_cadence: "on_demand"
      }
    ]
  },
  integrations: {
    diiac_it_enabled: false,
    scanner_integrations: [],
    source_feeds: [
      {
        feed_id: "cisa-kev",
        provider: "CISA",
        mode: "public_source_bound",
        enabled: true,
        review_required: true
      },
      {
        feed_id: "first-epss",
        provider: "FIRST",
        mode: "public_source_bound",
        enabled: true,
        review_required: true
      }
    ]
  },
  signing: {
    trust_state: "dev-local",
    key_vault_uri: "https://kv-diiac-patchforge-prod.vault.azure.net/",
    production_signing_enabled: false
  },
  storage: {
    mode: "local-json",
    account_name: "stdiiacpatchforgeprod01"
  },
  telemetry: {
    health_checks_read_only: true,
    azure_mutation_enabled: false
  },
  retention: {
    evidence_days: 2555,
    audit_days: 2555
  },
  feature_flags: {
    sra_enabled: false,
    live_scanner_ingest_enabled: false,
    azure_mutation_enabled: false
  },
  updated_at: null
};

export function hashObject(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

const REVISION_METADATA_KEYS = new Set([
  "actor_oid",
  "actor_roles",
  "actor_tenant_id",
  "actor_upn",
  "completed_at",
  "content_hash",
  "created_at",
  "effective_tenant_id",
  "evidence_state",
  "fetched_at",
  "final_approval_issued",
  "ingested_at",
  "payload_hash",
  "previous_payload_hash",
  "requested_tenant_id",
  "review_invalidated_at",
  "review_invalidated_reason",
  "review_state",
  "reviewed_at",
  "reviewed_by",
  "server_payload_hash",
  "source_record_ids",
  "source_state",
  "tenant_id",
  "tenant_id_source",
  "tenant_override_ignored",
  "updated_at",
  "upstream_payload_hash"
]);

function canonicalRevisionValue(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalRevisionValue(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !REVISION_METADATA_KEYS.has(key))
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalRevisionValue(nested)])
    );
  }
  return value;
}

function sourceRevisionHash(payload, source) {
  const { sources: _sources, ...vulnerabilityPayload } = payload || {};
  return hashObject(canonicalRevisionValue({
    source,
    vulnerability: vulnerabilityPayload
  }));
}

function vulnerabilityContentHash(record) {
  return hashObject(canonicalRevisionValue(record || {}));
}

export class PatchForgeJsonStorage {
  constructor(rootDir = path.resolve("customer-config/default/patchforge")) {
    this.rootDir = rootDir;
    this.storageMode = "local-json";
    this.immutableAppendQueue = Promise.resolve();
  }

  async ensureReady() {
    await mkdir(this.rootDir, { recursive: true });
    await Promise.all(COLLECTIONS.map((collection) => this._ensureCollection(collection)));
  }

  async _ensureCollection(collection) {
    const file = this._file(collection);
    try {
      await readFile(file, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      await writeFile(file, "[]\n", "utf8");
    }
  }

  _file(collection) {
    return path.join(this.rootDir, `${collection}.json`);
  }

  async _read(collection) {
    await this.ensureReady();
    return JSON.parse(await readFile(this._file(collection), "utf8"));
  }

  async _write(collection, records) {
    await this.ensureReady();
    const file = this._file(collection);
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, `${JSON.stringify(records, null, 2)}\n`, "utf8");
    await rename(tmp, file);
  }

  _adminConfigFile() {
    return path.join(this.rootDir, "admin_config.json");
  }

  async _readAdminConfigFile() {
    await this.ensureReady();
    const file = this._adminConfigFile();
    try {
      return JSON.parse(await readFile(file, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      const initial = { "diiac.io": DEFAULT_ADMIN_CONFIG };
      await writeFile(file, `${JSON.stringify(initial, null, 2)}\n`, "utf8");
      return initial;
    }
  }

  async _writeAdminConfigFile(config) {
    await this.ensureReady();
    const file = this._adminConfigFile();
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    await rename(tmp, file);
  }

  async list(collection, tenantId) {
    const records = await this._read(collection);
    return records.filter((record) => record.tenant_id === tenantId);
  }

  // Local-json is single-writer only: this read-modify-write is not safe under
  // concurrent appends (the atomic rename in _write prevents file corruption but
  // not lost updates). Production runs on PatchForgePostgresStorage, which upserts.
  async append(collection, record) {
    const records = await this._read(collection);
    const idField = COLLECTION_ID_FIELDS[collection];
    const recordId = idField ? record[idField] || record.id : null;
    const existingIndex = recordId
      ? records.findIndex((item) => item.tenant_id === record.tenant_id && String(item[idField] || item.id) === String(recordId))
      : -1;
    if (existingIndex >= 0) {
      records[existingIndex] = record;
    } else {
      records.push(record);
    }
    await this._write(collection, records);
    return record;
  }

  async appendImmutable(collection, record) {
    const operation = this.immutableAppendQueue.then(async () => {
      const records = await this._read(collection);
      const idField = COLLECTION_ID_FIELDS[collection];
      const recordId = idField ? record[idField] || record.id : null;
      if (!recordId) {
        throw new Error(`Immutable collection ${collection} requires a stable record ID.`);
      }
      const existing = records.find((item) => item.tenant_id === record.tenant_id && String(item[idField] || item.id) === String(recordId));
      if (existing) {
        return { record: existing, created: false };
      }
      records.push(record);
      await this._write(collection, records);
      return { record, created: true };
    });
    this.immutableAppendQueue = operation.catch(() => undefined);
    return operation;
  }

  async replace(collection, predicate, updater) {
    const records = await this._read(collection);
    let updatedRecord = null;
    const updated = records.map((record) => {
      if (!predicate(record)) {
        return record;
      }
      updatedRecord = updater(record);
      return updatedRecord;
    });
    await this._write(collection, updated);
    return updatedRecord;
  }

  async acquireAutomationLease(tenantId, leaseName, ownerId, ttlMs, now = new Date()) {
    const observedAt = now instanceof Date ? now : new Date(now);
    const leases = await this.list("automation_leases", tenantId);
    const existing = leases.find((lease) => lease.lease_id === leaseName) || null;
    const existingExpiry = Date.parse(existing?.expires_at || "");
    if (existing && existing.owner_id !== ownerId && Number.isFinite(existingExpiry) && existingExpiry > observedAt.getTime() && existing.status === "active") {
      return null;
    }
    const lease = {
      tenant_id: tenantId,
      lease_id: leaseName,
      owner_id: ownerId,
      acquired_at: observedAt.toISOString(),
      expires_at: new Date(observedAt.getTime() + positiveNumber(ttlMs, 5 * 60 * 1000)).toISOString(),
      status: "active"
    };
    await this.append("automation_leases", lease);
    return lease;
  }

  async releaseAutomationLease(tenantId, leaseName, ownerId, now = new Date()) {
    return this.replace(
      "automation_leases",
      (lease) => lease.tenant_id === tenantId && lease.lease_id === leaseName && lease.owner_id === ownerId,
      (lease) => ({ ...lease, status: "released", released_at: (now instanceof Date ? now : new Date(now)).toISOString() })
    );
  }

  async purgePatchForgeData(tenantId, options = {}) {
    const plan = await buildPurgePlan(this, tenantId, options);
    if (plan.dry_run) {
      return plan;
    }
    if (options.confirm !== PATCHFORGE_PURGE_CONFIRMATION) {
      return {
        ...plan,
        blocked: true,
        error: "typed_confirmation_required",
        required_confirmation: PATCHFORGE_PURGE_CONFIRMATION
      };
    }

    const removed = {};
    for (const collection of plan.collections) {
      const records = await this._read(collection);
      const before = records.length;
      await this._write(collection, records.filter((record) => record.tenant_id !== tenantId));
      removed[collection] = before - (await this._read(collection)).length;
    }

    await this.audit(tenantId, "patchforge_factory_reset", {
      scopes: plan.scopes,
      collections: plan.collections,
      removed,
      dry_run: false,
      blueprint: "docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md"
    });

    return {
      ...plan,
      dry_run: false,
      removed,
      final_approval_issued: false,
      storage_mutation_executed: true,
      no_patch_deployment: true
    };
  }

  async cleanupUatRecords(tenantId, options = {}) {
    const plan = await buildUatCleanupPlan(this, tenantId, options);
    if (plan.dry_run) {
      return issueUatCleanupPreview(this, plan);
    }
    if (options.confirm !== plan.identifier) {
      return blockedUatCleanupPlan(plan);
    }
    const preview = await requireUatCleanupPreview(this, tenantId, plan, options.preview_token);

    const removed = {};
    for (const collection of plan.collections) {
      const selectedIds = new Set(plan.record_ids[collection] || []);
      const records = await this._read(collection);
      const retained = records.filter((record) => {
        if (record.tenant_id !== tenantId || !recordReferencesExactIdentifier(record, plan.identifier)) {
          return true;
        }
        return !selectedIds.has(recordIdFor(collection, record));
      });
      const removedCount = records.length - retained.length;
      if (removedCount > 0) {
        await this._write(collection, retained);
      }
      removed[collection] = removedCount;
    }

    await this.replace("uat_cleanup_previews", (record) => (
      record.tenant_id === tenantId && record.preview_id === preview.preview_id
    ), (record) => ({
      ...record,
      status: "consumed",
      consumed_at: new Date().toISOString()
    }));

    const auditRecord = await this.audit(
      tenantId,
      "patchforge_uat_cleanup_completed",
      buildUatCleanupAuditDetails(plan, removed, options.lineage, preview)
    );
    return completedUatCleanupPlan(plan, removed, auditRecord.audit_id, preview);
  }

  async ingestVulnerability(tenantId, payload) {
    const now = new Date().toISOString();
    const vulnerabilityId = payload.vulnerability_id || payload.canonical_id || `vuln-${randomUUID()}`;
    const sourceInputs = Array.isArray(payload.sources) ? payload.sources : [];
    const existingVulnerability = (await this.list("vulnerabilities", tenantId))
      .find((record) => record.vulnerability_id === vulnerabilityId) || null;
    const existingSources = await this.list("sources", tenantId);
    const sourceRecordIds = [];
    const sourceRevisionsUnchanged = [];
    const invalidatedSourceIds = [];

    for (const source of sourceInputs) {
      const sourceRecordId = source.source_record_id || `src-${randomUUID()}`;
      const payloadHash = sourceRevisionHash(payload, source);
      const existingSource = existingSources.find((record) => record.source_record_id === sourceRecordId) || null;
      const unchanged = Boolean(existingSource && existingSource.server_payload_hash === payloadHash);
      const sourceRecord = {
        ...(existingSource || {}),
        tenant_id: tenantId,
        source_record_id: sourceRecordId,
        vulnerability_id: vulnerabilityId,
        source_class: source.source_class || "scanner_output",
        source_name: source.source_name || "manual-ingest",
        source_url: source.source_url || null,
        payload_hash: payloadHash,
        server_payload_hash: payloadHash,
        upstream_payload_hash: source.payload_hash || null,
        ingested_at: now,
        review_state: unchanged ? existingSource.review_state : "pending_review",
        evidence_state: unchanged ? existingSource.evidence_state : "referenced",
        reviewed_by: unchanged ? existingSource.reviewed_by || null : null,
        reviewed_at: unchanged ? existingSource.reviewed_at || null : null,
        previous_payload_hash: existingSource && !unchanged ? existingSource.payload_hash || null : existingSource?.previous_payload_hash || null,
        review_invalidated_reason: existingSource && !unchanged ? "source_payload_changed" : null,
        review_invalidated_at: existingSource && !unchanged ? now : null,
        ...lineageFromPayload(payload)
      };
      sourceRecordIds.push(sourceRecord.source_record_id);
      sourceRevisionsUnchanged.push(unchanged);
      if (existingSource && !unchanged) {
        invalidatedSourceIds.push(sourceRecord.source_record_id);
      }
      await this.append("sources", sourceRecord);
    }

    const sourceRevisionsStable = sourceRevisionsUnchanged.every(Boolean);
    const mergedSourceRecordIds = Array.from(new Set([
      ...(existingVulnerability?.source_record_ids || []),
      ...sourceRecordIds
    ]));

    const record = {
      ...(existingVulnerability || {}),
      tenant_id: tenantId,
      vulnerability_id: vulnerabilityId,
      canonical_id: payload.canonical_id || vulnerabilityId,
      title: payload.title || existingVulnerability?.title || vulnerabilityId,
      description: payload.description ?? existingVulnerability?.description ?? "",
      advisory_id: payload.advisory_id ?? existingVulnerability?.advisory_id ?? null,
      vendor_id: payload.vendor_id ?? existingVulnerability?.vendor_id ?? null,
      vendor_name: payload.vendor_name ?? existingVulnerability?.vendor_name ?? null,
      vendor_aliases: payload.vendor_aliases ?? existingVulnerability?.vendor_aliases ?? [],
      product_family: payload.product_family || payload.product || existingVulnerability?.product_family || null,
      product_aliases: payload.product_aliases ?? existingVulnerability?.product_aliases ?? [],
      model: payload.model ?? existingVulnerability?.model ?? null,
      affected_models: payload.affected_models ?? existingVulnerability?.affected_models ?? [],
      affected_versions: payload.affected_versions ?? existingVulnerability?.affected_versions ?? [],
      fixed_versions: payload.fixed_versions ?? existingVulnerability?.fixed_versions ?? [],
      affected_feature: payload.affected_feature ?? existingVulnerability?.affected_feature ?? null,
      affected_features: payload.affected_features ?? existingVulnerability?.affected_features ?? [],
      feature_aliases: payload.feature_aliases ?? existingVulnerability?.feature_aliases ?? [],
      severity: payload.severity || existingVulnerability?.severity || "unknown",
      cvss_score: payload.cvss_score ?? existingVulnerability?.cvss_score ?? null,
      epss_score: payload.epss_score ?? payload.epss ?? existingVulnerability?.epss_score ?? null,
      epss_percentile: payload.epss_percentile ?? existingVulnerability?.epss_percentile ?? null,
      kev: Boolean(payload.kev ?? existingVulnerability?.kev ?? false),
      known_exploited: Boolean(payload.known_exploited ?? existingVulnerability?.known_exploited ?? false),
      internet_exposed: Boolean(payload.internet_exposed ?? existingVulnerability?.internet_exposed ?? false),
      ot_relevant: Boolean(payload.ot_relevant ?? existingVulnerability?.ot_relevant ?? false),
      affected_service_ids: payload.affected_service_ids ?? existingVulnerability?.affected_service_ids ?? [],
      affected_asset_ids: payload.affected_asset_ids ?? existingVulnerability?.affected_asset_ids ?? [],
      patch_status: payload.patch_status ?? existingVulnerability?.patch_status ?? "unknown",
      patch_available: Boolean(payload.patch_available ?? existingVulnerability?.patch_available ?? false),
      workaround_status: payload.workaround_status ?? existingVulnerability?.workaround_status ?? "unknown",
      source_feed: payload.source_feed ?? existingVulnerability?.source_feed ?? null,
      source_name: payload.source_name || sourceInputs[0]?.source_name || existingVulnerability?.source_name || null,
      source_url: payload.source_url || sourceInputs[0]?.source_url || existingVulnerability?.source_url || null,
      urgency_posture: payload.urgency_posture ?? existingVulnerability?.urgency_posture ?? null,
      applicability_posture: payload.applicability_posture ?? existingVulnerability?.applicability_posture ?? null,
      final_approval_issued: false,
      sla_due_at: payload.sla_due_at ?? existingVulnerability?.sla_due_at ?? null,
      source_state: "source_bound",
      review_state: "pending_review",
      source_record_ids: mergedSourceRecordIds,
      tags: Array.from(new Set([...(existingVulnerability?.tags || []), ...(payload.tags || [])])),
      ...lineageFromPayload(payload),
      created_at: existingVulnerability?.created_at || now,
      updated_at: existingVulnerability ? now : null
    };
    const contentHash = vulnerabilityContentHash(record);
    const previousContentHash = existingVulnerability ? vulnerabilityContentHash(existingVulnerability) : null;
    const preserveReviewState = Boolean(existingVulnerability)
      && sourceRevisionsStable
      && previousContentHash === contentHash;
    record.review_state = preserveReviewState ? existingVulnerability.review_state : "pending_review";
    record.content_hash = contentHash;

    await this.append("vulnerabilities", record);
    for (const sourceRecordId of invalidatedSourceIds) {
      await this.audit(tenantId, "source_review_invalidated", {
        vulnerability_id: vulnerabilityId,
        source_record_id: sourceRecordId,
        reason: "source_payload_changed"
      });
    }
    await this.audit(tenantId, "vulnerability_ingested", { vulnerability_id: vulnerabilityId });
    return record;
  }

  async getVulnerability(tenantId, vulnerabilityId) {
    const vulnerabilities = await this.list("vulnerabilities", tenantId);
    const vulnerability = vulnerabilities.find((record) => record.vulnerability_id === vulnerabilityId);
    if (!vulnerability) {
      return null;
    }

    const sources = await this.getSourcesForVulnerability(tenantId, vulnerability);
    return {
      ...vulnerability,
      sources,
      usable_evidence_sources: sources.filter((source) => isPositiveEvidence(source))
    };
  }

  async getSourcesForVulnerability(tenantId, vulnerability) {
    const sources = await this.list("sources", tenantId);
    const sourceIds = new Set(vulnerability.source_record_ids || []);
    return sources.filter(
      (source) => source.vulnerability_id === vulnerability.vulnerability_id || sourceIds.has(source.source_record_id)
    );
  }

  async reviewVulnerability(tenantId, vulnerabilityId, payload) {
    const now = new Date().toISOString();
    const reviewEvent = {
      tenant_id: tenantId,
      review_id: `review-${randomUUID()}`,
      vulnerability_id: vulnerabilityId,
      source_record_id: payload.source_record_id || null,
      reviewer: payload.reviewer || "unknown",
      review_state: payload.review_state || "reviewed",
      evidence_state: payload.evidence_state || null,
      notes: payload.notes || "",
      ...lineageFromPayload(payload),
      created_at: now
    };

    let updatedSource = null;
    if (payload.source_record_id) {
      updatedSource = await this.replace(
        "sources",
        (record) => record.tenant_id === tenantId && record.source_record_id === payload.source_record_id,
        (record) => ({
          ...record,
          review_state: payload.review_state || record.review_state,
          evidence_state: payload.evidence_state || record.evidence_state,
          reviewed_by: payload.reviewer || record.reviewed_by,
          reviewed_at: now
        })
      );
    }

    const updatedVulnerability = await this.replace(
      "vulnerabilities",
      (record) => record.tenant_id === tenantId && record.vulnerability_id === vulnerabilityId,
      (record) => ({
        ...record,
        review_state: payload.vulnerability_review_state || record.review_state,
        updated_at: now
      })
    );

    if (!updatedVulnerability) {
      return null;
    }

    await this.append("reviews", reviewEvent);
    await this.audit(tenantId, "vulnerability_reviewed", {
      vulnerability_id: vulnerabilityId,
      source_record_id: payload.source_record_id || null,
      review_state: reviewEvent.review_state
    });

    return {
      review: reviewEvent,
      source: updatedSource,
      vulnerability: await this.getVulnerability(tenantId, vulnerabilityId)
    };
  }

  async ingestAsset(tenantId, payload) {
    const record = {
      tenant_id: tenantId,
      asset_id: payload.asset_id || `asset-${randomUUID()}`,
      asset_name: payload.asset_name || payload.asset_id || "Unnamed asset",
      asset_class: payload.asset_class || "unknown",
      exposure: payload.exposure || "unknown",
      criticality: payload.criticality || "unknown",
      review_state: payload.review_state || "pending_review",
      source_state: "source_bound",
      ...lineageFromPayload(payload),
      created_at: new Date().toISOString()
    };
    await this.append("assets", record);
    await this.audit(tenantId, "asset_ingested", { asset_id: record.asset_id });
    return record;
  }

  async ingestService(tenantId, payload) {
    const record = {
      tenant_id: tenantId,
      service_id: payload.service_id || `service-${randomUUID()}`,
      service_name: payload.service_name || payload.service_id || "Unnamed service",
      service_tier: payload.service_tier || "unknown",
      customer_facing: Boolean(payload.customer_facing),
      owner: payload.owner || null,
      affected_asset_ids: payload.affected_asset_ids || [],
      vulnerability_ids: payload.vulnerability_ids || [],
      review_state: payload.review_state || "pending_review",
      source_state: "source_bound",
      ...lineageFromPayload(payload),
      created_at: new Date().toISOString()
    };
    await this.append("services", record);
    await this.audit(tenantId, "service_ingested", { service_id: record.service_id });
    return record;
  }

  async getServiceExposure(tenantId, serviceId) {
    const services = await this.list("services", tenantId);
    const service = services.find((record) => record.service_id === serviceId);
    if (!service) {
      return null;
    }

    const vulnerabilities = await this.list("vulnerabilities", tenantId);
    const relevant = vulnerabilities.filter((vulnerability) => {
      const serviceIds = new Set(vulnerability.affected_service_ids || []);
      const explicitIds = new Set(service.vulnerability_ids || []);
      return serviceIds.has(serviceId) || explicitIds.has(vulnerability.vulnerability_id);
    });

    return {
      service,
      vulnerabilities: relevant,
      exposure_summary: {
        critical: relevant.filter((item) => item.severity === "critical").length,
        known_exploited: relevant.filter((item) => item.known_exploited).length,
        internet_exposed: relevant.filter((item) => item.internet_exposed).length
      }
    };
  }

  async dashboardMetrics(tenantId) {
    const vulnerabilities = await this.list("vulnerabilities", tenantId);
    const sources = await this.list("sources", tenantId);
    const now = Date.now();
    const sourceFeedRuns = await this.list("source_feed_runs", tenantId);

    return {
      tenant_id: tenantId,
      vulnerability_count: vulnerabilities.length,
      critical_exposure: vulnerabilities.filter(
        (item) => item.severity === "critical" && item.internet_exposed && item.review_state !== "rejected"
      ).length,
      known_exploited: vulnerabilities.filter((item) => item.known_exploited && item.review_state !== "rejected").length,
      patch_overdue: vulnerabilities.filter((item) => {
        if (item.patch_status === "overdue") {
          return true;
        }
        return item.sla_due_at ? Date.parse(item.sla_due_at) < now : false;
      }).length,
      pending_review: vulnerabilities.filter((item) => item.review_state === "pending_review").length,
      accepted_positive_evidence_sources: sources.filter((source) => isPositiveEvidence(source)).length,
      rejected_sources: sources.filter((source) => source.review_state === "rejected" || source.evidence_state === "rejected").length,
      signed_packs: (await this.list("decision_packs", tenantId)).filter((pack) => pack.verification?.verified === true).length,
      source_feed_runs: sourceFeedRuns.length,
      last_source_feed_run_at: sourceFeedRuns[sourceFeedRuns.length - 1]?.completed_at || null
    };
  }

  async readAdminConfig(tenantId) {
    const allConfig = await this._readAdminConfigFile();
    const baseConfig = defaultAdminConfigForMode(this.storageMode);
    const config = normalizeAdminConfig(deepMerge(baseConfig, allConfig[tenantId] || {}, { tenant_id: tenantId }));
    return maskSecretValues(config);
  }

  async saveAdminConfig(tenantId, payload) {
    const allConfig = await this._readAdminConfigFile();
    const previous = normalizeAdminConfig(deepMerge(defaultAdminConfigForMode(this.storageMode), allConfig[tenantId] || {}, { tenant_id: tenantId }));
    const next = normalizeAdminConfig(deepMerge(previous, payload, {
      tenant_id: tenantId,
      telemetry: {
        ...(previous.telemetry || {}),
        ...(payload.telemetry || {}),
        health_checks_read_only: true,
        azure_mutation_enabled: false
      },
      feature_flags: {
        ...(previous.feature_flags || {}),
        ...(payload.feature_flags || {}),
        azure_mutation_enabled: false
      },
      updated_at: new Date().toISOString()
    }));

    const sanitized = maskSecretValues(next);
    allConfig[tenantId] = sanitized;
    await this._writeAdminConfigFile(allConfig);
    await this.audit(tenantId, "admin_config_updated", { sections: Object.keys(payload) });
    return sanitized;
  }

  async adminHealth(tenantId) {
    await this.ensureReady();
    const config = await this.readAdminConfig(tenantId);
    const sourceFeedRuns = await this.list("source_feed_runs", tenantId);
    const automationWorkItems = await this.list("automation_work_items", tenantId);
    const automationDeadLetters = await this.list("automation_dead_letters", tenantId);
    const networkVendors = await this.list("network_vendors", tenantId);
    const networkAssets = await this.list("customer_network_assets", tenantId);
    const agentSources = (await this.list("sources", tenantId)).filter((source) =>
      ["mcp_agent_finding", "mythos_finding", "agi_agent_finding", "sra_trace"].includes(source.source_class)
    );
    const publicSourceFeeds = configuredSourceFeeds(config);
    const agentReady = agentIntakeEnabled(config) || parseEnvBoolean(process.env.PATCHFORGE_AGENT_INTAKE_ENABLED, false);
    const sourceFeedsReady = publicSourceFeeds.length > 0 || parseEnvBoolean(process.env.PATCHFORGE_PUBLIC_SOURCE_FEEDS_ENABLED, false);
    const schedulerRuns = sourceFeedRuns.filter((run) =>
      Boolean(run.scheduler_run_id)
      || run.actor_oid === "patchforge-scheduler"
      || run.tenant_id_source === "scheduler_config"
    );
    const lastSchedulerRun = schedulerRuns[schedulerRuns.length - 1] || null;
    const schedulerConfigured = parseEnvBoolean(process.env.PATCHFORGE_SCHEDULER_ENABLED, false)
      || process.env.PATCHFORGE_COMPONENT === "scheduler";
    const schedulerHealth = sourceFeedSchedulerHealth(lastSchedulerRun, schedulerConfigured);
    const workerConfigured = parseEnvBoolean(process.env.PATCHFORGE_WORKER_ENABLED, false) || process.env.PATCHFORGE_COMPONENT === "ingest-export-worker";
    const pendingWork = automationWorkItems.filter((item) => ["pending", "retry_scheduled", "running"].includes(item.status));
    const openDeadLetters = automationDeadLetters.filter((item) => item.status === "open");
    const quarantinedWork = automationDeadLetters.filter((item) => item.status === "quarantined");
    const backlogSloMs = positiveNumber(process.env.PATCHFORGE_WORKER_BACKLOG_SLO_MS, 15 * 60 * 1000);
    const oldestPendingMs = pendingWork
      .map((item) => Date.parse(item.next_attempt_at || item.updated_at || item.created_at || ""))
      .filter(Number.isFinite)
      .sort((left, right) => left - right)[0] || 0;
    const backlogAgeMs = oldestPendingMs ? Math.max(0, Date.now() - oldestPendingMs) : 0;
    const backlogSloBreached = pendingWork.length > 0 && backlogAgeMs > backlogSloMs;
    const workerAlerts = [
      ...(openDeadLetters.length ? [`${openDeadLetters.length} open dead-letter item(s)`] : []),
      ...(quarantinedWork.length ? [`${quarantinedWork.length} quarantined item(s)`] : []),
      ...(backlogSloBreached ? [`backlog SLO breached at ${backlogAgeMs} ms (threshold ${backlogSloMs} ms)`] : [])
    ];
    const workerStatus = !workerConfigured ? "pending" : workerAlerts.length ? "degraded" : "ready";
    return {
      tenant_id: tenantId,
      live_azure_mutation_enabled: false,
      checks: [
        { name: "Frontend health", status: "ready", mode: "read-only" },
        { name: "Bridge health", status: "ready", mode: this.storageMode || "local-json" },
        { name: "Runtime health", status: "ready", mode: "local" },
        { name: "SRA health", status: config.sra?.advisory_only ? "advisory" : "disabled", mode: "advisory-only" },
        {
          name: "MCP agent intake",
          status: agentReady ? "governed" : "disabled",
          mode: agentSources.length ? `${agentSources.length} source-bound agent finding(s)` : "agent-led-human-approved"
        },
        {
          name: "Public source feeds",
          status: sourceFeedsReady ? "ready" : "disabled",
          mode: publicSourceFeeds.length ? publicSourceFeeds.map((feed) => feed.feed_id).join(" / ") : "not-configured"
        },
        {
          name: "VendorLens sources",
          status: config.vendorlens?.enabled === false ? "disabled" : "ready",
          mode: `${networkVendors.length || "catalogue"} vendor catalogue / ${networkAssets.length} customer network asset(s)`
        },
        {
          name: "Worker health",
          status: workerStatus,
          mode: workerConfigured
            ? `ingest-export-worker; ${pendingWork.length} pending/running; ${workerAlerts.length ? workerAlerts.join("; ") : "no active alerts"}`
            : "awaiting-worker-runtime-confirmation"
        },
        {
          name: "Scheduler health",
          status: schedulerHealth.status,
          mode: schedulerHealth.mode
        },
        {
          name: "Database health",
          status: this.storageMode === "postgresql" ? "ready" : "placeholder",
          mode: this.storageMode || config.storage?.mode || "local-json"
        },
        { name: "Storage health", status: "ready", mode: this.storageMode || config.storage?.mode || "local-json" },
        { name: "Key Vault health", status: config.signing?.production_signing_enabled ? "ready" : "planned", mode: "managed-identity" },
        { name: "Signing trust", status: config.signing?.trust_state || "dev-local", mode: config.signing?.production_signing_enabled ? "key-vault" : "no-production-key" }
      ]
    };
  }

  async audit(tenantId, eventType, details) {
    return this.append("audit_events", {
      tenant_id: tenantId,
      audit_id: `audit-${randomUUID()}`,
      event_type: eventType,
      details,
      created_at: new Date().toISOString()
    });
  }
}

export class PatchForgePostgresStorage extends PatchForgeJsonStorage {
  constructor(options = {}) {
    super(options.localFallbackRoot);
    this.storageMode = "postgresql";
    this.options = options;
    this.pool = options.pool || null;
    this.ready = false;
  }

  async ensureReady() {
    if (this.ready) {
      return;
    }
    if (!this.pool) {
      this.pool = await createPostgresPool(this.options);
    }
    await this.pool.query(`
      create table if not exists patchforge_records (
        tenant_id text not null,
        collection text not null,
        record_id text not null,
        record jsonb not null,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now(),
        primary key (tenant_id, collection, record_id)
      )
    `);
    await this.pool.query(`
      create index if not exists idx_patchforge_records_collection_tenant
      on patchforge_records (collection, tenant_id)
    `);
    await this.pool.query(`
      create table if not exists patchforge_admin_config (
        tenant_id text primary key,
        config jsonb not null,
        updated_at timestamptz not null default now()
      )
    `);
    await this.pool.query(
      `insert into patchforge_admin_config (tenant_id, config)
       values ($1, $2::jsonb)
       on conflict (tenant_id) do nothing`,
      [DEFAULT_ADMIN_CONFIG.tenant_id, JSON.stringify(productionAdminConfig())]
    );
    this.ready = true;
  }

  async list(collection, tenantId) {
    await this.ensureReady();
    assertKnownCollection(collection);
    const result = await this.pool.query(
      `select record
       from patchforge_records
       where tenant_id = $1 and collection = $2
       order by created_at asc`,
      [tenantId, collection]
    );
    return result.rows.map((row) => row.record);
  }

  async append(collection, record) {
    await this.ensureReady();
    assertKnownCollection(collection);
    const recordId = recordIdFor(collection, record);
    await this.pool.query(
      `insert into patchforge_records (tenant_id, collection, record_id, record)
       values ($1, $2, $3, $4::jsonb)
       on conflict (tenant_id, collection, record_id)
       do update set record = excluded.record, updated_at = now()`,
      [record.tenant_id, collection, recordId, JSON.stringify(record)]
    );
    return record;
  }

  async appendImmutable(collection, record) {
    await this.ensureReady();
    assertKnownCollection(collection);
    const recordId = recordIdFor(collection, record);
    const inserted = await this.pool.query(
      `insert into patchforge_records (tenant_id, collection, record_id, record)
       values ($1, $2, $3, $4::jsonb)
       on conflict (tenant_id, collection, record_id) do nothing
       returning record`,
      [record.tenant_id, collection, recordId, JSON.stringify(record)]
    );
    if (inserted.rows.length) {
      return { record: inserted.rows[0].record, created: true };
    }
    const existing = await this.pool.query(
      `select record from patchforge_records
       where tenant_id = $1 and collection = $2 and record_id = $3`,
      [record.tenant_id, collection, recordId]
    );
    if (!existing.rows.length) {
      throw new Error(`Immutable record ${recordId} could not be read after a concurrent insert.`);
    }
    return { record: existing.rows[0].record, created: false };
  }

  async replace(collection, predicate, updater) {
    await this.ensureReady();
    assertKnownCollection(collection);
    const result = await this.pool.query(
      `select tenant_id, record_id, record
       from patchforge_records
       where collection = $1
       order by created_at asc`,
      [collection]
    );
    let updatedRecord = null;
    for (const row of result.rows) {
      if (!predicate(row.record)) {
        continue;
      }
      updatedRecord = updater(row.record);
      await this.pool.query(
        `update patchforge_records
         set record = $1::jsonb, updated_at = now()
         where tenant_id = $2 and collection = $3 and record_id = $4`,
        [JSON.stringify(updatedRecord), row.tenant_id, collection, row.record_id]
      );
    }
    return updatedRecord;
  }

  async acquireAutomationLease(tenantId, leaseName, ownerId, ttlMs, now = new Date()) {
    await this.ensureReady();
    const observedAt = now instanceof Date ? now : new Date(now);
    const expiresAt = new Date(observedAt.getTime() + positiveNumber(ttlMs, 5 * 60 * 1000));
    const lease = {
      tenant_id: tenantId,
      lease_id: leaseName,
      owner_id: ownerId,
      acquired_at: observedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      status: "active"
    };
    const result = await this.pool.query(
      `insert into patchforge_records (tenant_id, collection, record_id, record)
       values ($1, 'automation_leases', $2, $3::jsonb)
       on conflict (tenant_id, collection, record_id)
       do update set record = excluded.record, updated_at = now()
       where patchforge_records.record->>'owner_id' = $4
          or patchforge_records.record->>'status' <> 'active'
          or nullif(patchforge_records.record->>'expires_at', '')::timestamptz <= $5::timestamptz
       returning record`,
      [tenantId, leaseName, JSON.stringify(lease), ownerId, observedAt.toISOString()]
    );
    return result.rows[0]?.record || null;
  }

  async releaseAutomationLease(tenantId, leaseName, ownerId, now = new Date()) {
    await this.ensureReady();
    const releasedAt = (now instanceof Date ? now : new Date(now)).toISOString();
    const result = await this.pool.query(
      `update patchforge_records
       set record = record || $1::jsonb, updated_at = now()
       where tenant_id = $2
         and collection = 'automation_leases'
         and record_id = $3
         and record->>'owner_id' = $4
       returning record`,
      [JSON.stringify({ status: "released", released_at: releasedAt }), tenantId, leaseName, ownerId]
    );
    return result.rows[0]?.record || null;
  }

  async purgePatchForgeData(tenantId, options = {}) {
    const plan = await buildPurgePlan(this, tenantId, options);
    if (plan.dry_run) {
      return plan;
    }
    if (options.confirm !== PATCHFORGE_PURGE_CONFIRMATION) {
      return {
        ...plan,
        blocked: true,
        error: "typed_confirmation_required",
        required_confirmation: PATCHFORGE_PURGE_CONFIRMATION
      };
    }

    const removed = {};
    for (const collection of plan.collections) {
      const before = plan.counts[collection] || 0;
      await this.pool.query(
        `delete from patchforge_records
         where tenant_id = $1 and collection = $2`,
        [tenantId, collection]
      );
      removed[collection] = before;
    }

    await this.audit(tenantId, "patchforge_factory_reset", {
      scopes: plan.scopes,
      collections: plan.collections,
      removed,
      dry_run: false,
      blueprint: "docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md"
    });

    return {
      ...plan,
      dry_run: false,
      removed,
      final_approval_issued: false,
      storage_mutation_executed: true,
      no_patch_deployment: true
    };
  }

  async cleanupUatRecords(tenantId, options = {}) {
    await this.ensureReady();
    validateUatCleanupOptions(options);
    const identifier = normalizeUatCleanupIdentifier(options.identifier);
    const dryRun = options.dry_run !== false;

    if (dryRun) {
      const rows = await listPostgresUatCleanupRows(this.pool, tenantId);
      const plan = buildUatCleanupPlanFromRows(tenantId, identifier, true, rows);
      return issueUatCleanupPreview(this, plan);
    }
    if (options.confirm !== identifier) {
      const rows = await listPostgresUatCleanupRows(this.pool, tenantId);
      return blockedUatCleanupPlan(buildUatCleanupPlanFromRows(tenantId, identifier, false, rows));
    }

    const ownsClient = typeof this.pool.connect === "function";
    const client = ownsClient ? await this.pool.connect() : this.pool;
    try {
      await client.query("begin");
      await client.query("lock table patchforge_records in share row exclusive mode");
      const preview = await requirePostgresUatCleanupPreview(client, tenantId, identifier, options.preview_token);
      const candidateRows = await listPostgresUatCleanupRows(client, tenantId);
      const candidatePlan = buildUatCleanupPlanFromRows(tenantId, identifier, false, candidateRows);
      const lockedRows = [];

      for (const collection of candidatePlan.collections) {
        const recordIds = candidatePlan.record_ids[collection] || [];
        if (!recordIds.length) {
          continue;
        }
        const result = await client.query(
          `select collection, record_id, record
           from patchforge_records
           where tenant_id = $1
             and collection = $2
             and record_id = any($3::text[])
           for update`,
          [tenantId, collection, recordIds]
        );
        lockedRows.push(...result.rows);
      }

      const plan = buildUatCleanupPlanFromRows(tenantId, identifier, false, lockedRows);
      assertUatCleanupPreviewMatches(preview, plan);
      const removed = {};
      for (const collection of plan.collections) {
        const recordIds = plan.record_ids[collection] || [];
        if (!recordIds.length) {
          continue;
        }
        const result = await client.query(
          `delete from patchforge_records
           where tenant_id = $1
             and collection = $2
             and record_id = any($3::text[])
           returning record_id`,
          [tenantId, collection, recordIds]
        );
        removed[collection] = result.rows?.length ?? result.rowCount ?? 0;
      }

      const consumedPreview = await client.query(
        `update patchforge_records
         set record = record || $1::jsonb, updated_at = now()
         where tenant_id = $2
           and collection = 'uat_cleanup_previews'
           and record_id = $3`,
        [JSON.stringify({ status: "consumed", consumed_at: new Date().toISOString() }), tenantId, preview.preview_id]
      );
      if (consumedPreview.rowCount !== 1) {
        throw new Error("UAT cleanup preview could not be consumed atomically.");
      }

      const auditRecord = buildUatCleanupAuditRecord(
        tenantId,
        plan,
        removed,
        options.lineage,
        preview
      );
      await client.query(
        `insert into patchforge_records (tenant_id, collection, record_id, record)
         values ($1, 'audit_events', $2, $3::jsonb)`,
        [tenantId, auditRecord.audit_id, JSON.stringify(auditRecord)]
      );
      await client.query("commit");
      return completedUatCleanupPlan(plan, removed, auditRecord.audit_id, preview);
    } catch (error) {
      try {
        await client.query("rollback");
      } catch {
        // Preserve the original failure if rollback also fails.
      }
      throw error;
    } finally {
      if (ownsClient) {
        client.release();
      }
    }
  }

  async querySecurityActionCatalogue(tenantId, options = {}) {
    await this.ensureReady();
    const collections = Array.isArray(options.collections) && options.collections.length
      ? options.collections
      : [
          "vulnerabilities",
          "vendor_security_advisories",
          "vendor_advisories",
          "vendors",
          "network_vendors",
          "customer_network_assets",
          "config_applicability_assessments",
          "source_feed_runs",
          "sources"
        ];
    const result = await this.pool.query(
      `select collection, record
       from patchforge_records
       where tenant_id = $1 and collection = any($2::text[])
       order by collection asc, created_at asc`,
      [tenantId, collections]
    );
    const grouped = Object.fromEntries(collections.map((collection) => [collection, []]));
    for (const row of result.rows) {
      if (!grouped[row.collection]) {
        grouped[row.collection] = [];
      }
      grouped[row.collection].push(row.record);
    }
    return {
      tenant_id: tenantId,
      generated_at: new Date().toISOString(),
      search_backend: "postgres_records_catalogue",
      tenant_isolation: "tenant_id predicate enforced by PostgreSQL query",
      collections: grouped
    };
  }

  async _readAdminConfigFile() {
    await this.ensureReady();
    const result = await this.pool.query(
      `select tenant_id, config
       from patchforge_admin_config
       order by tenant_id asc`
    );
    return Object.fromEntries(result.rows.map((row) => [row.tenant_id, row.config]));
  }

  async _writeAdminConfigFile(configByTenant) {
    await this.ensureReady();
    for (const [tenantId, config] of Object.entries(configByTenant)) {
      await this.pool.query(
        `insert into patchforge_admin_config (tenant_id, config, updated_at)
         values ($1, $2::jsonb, now())
         on conflict (tenant_id)
         do update set config = excluded.config, updated_at = now()`,
        [tenantId, JSON.stringify(config)]
      );
    }
  }
}

export function createPatchForgeStorage(options = {}) {
  const mode = (options.mode || process.env.PATCHFORGE_STORAGE_MODE || "local-json").toLowerCase();
  if (["postgres", "postgresql", "postgresql-flexible-server"].includes(mode)) {
    return new PatchForgePostgresStorage({
      host: process.env.PATCHFORGE_DATABASE_HOST,
      database: process.env.PATCHFORGE_DATABASE_NAME || "patchforge_prod",
      user: process.env.PATCHFORGE_DATABASE_USER || "patchforgeadmin",
      password: process.env.PATCHFORGE_DATABASE_PASSWORD,
      passwordSecretName: process.env.PATCHFORGE_DATABASE_PASSWORD_SECRET_NAME,
      keyVaultUri: process.env.PATCHFORGE_KEYVAULT_URI,
      azureClientId: process.env.AZURE_CLIENT_ID,
      ssl: process.env.PATCHFORGE_DATABASE_SSL !== "false",
      ...options
    });
  }
  return new PatchForgeJsonStorage(options.storageRoot || process.env.PATCHFORGE_STORAGE_ROOT);
}

async function buildPurgePlan(storage, tenantId, options = {}) {
  const scopes = resolvePurgeScopes(options);
  const collections = Array.from(new Set(scopes.flatMap((scope) => PATCHFORGE_PURGE_SCOPES[scope] || [])))
    .filter((collection) => COLLECTIONS.includes(collection));
  const counts = {};
  for (const collection of collections) {
    counts[collection] = (await storage.list(collection, tenantId)).length;
  }
  return {
    tenant_id: tenantId,
    generated_at: new Date().toISOString(),
    blueprint: "docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md",
    dry_run: options.dry_run !== false,
    scopes,
    collections,
    counts,
    total_records: Object.values(counts).reduce((total, count) => total + count, 0),
    required_confirmation: PATCHFORGE_PURGE_CONFIRMATION,
    preserves: [
      "Git history",
      "restore tags and branches",
      "signing/verifier/replay core",
      "auth/RBAC",
      "Azure deployment scripts",
      "test harnesses",
      "deployment evidence",
      "purge event documentation"
    ],
    boundary: {
      no_patch_deployment: true,
      no_autonomous_approval: true,
      final_approval_issued: false,
      human_confirmation_required: true
    }
  };
}

async function buildUatCleanupPlan(storage, tenantId, options = {}) {
  validateUatCleanupOptions(options);
  const identifier = normalizeUatCleanupIdentifier(options.identifier);
  const rows = [];
  for (const collection of PATCHFORGE_UAT_CLEANUP_COLLECTIONS) {
    const records = await storage.list(collection, tenantId);
    rows.push(...records.map((record) => ({
      collection,
      record_id: recordIdFor(collection, record),
      record
    })));
  }
  return buildUatCleanupPlanFromRows(
    tenantId,
    identifier,
    options.dry_run !== false,
    rows
  );
}

function buildUatCleanupPlanFromRows(tenantId, identifier, dryRun, rows = []) {
  const recordIds = {};
  for (const row of rows) {
    if (!PATCHFORGE_UAT_CLEANUP_COLLECTIONS.includes(row.collection)) {
      continue;
    }
    if (!recordReferencesExactIdentifier(row.record, identifier)) {
      continue;
    }
    const recordId = String(row.record_id || recordIdFor(row.collection, row.record));
    recordIds[row.collection] ||= [];
    if (!recordIds[row.collection].includes(recordId)) {
      recordIds[row.collection].push(recordId);
    }
  }

  const collections = PATCHFORGE_UAT_CLEANUP_COLLECTIONS
    .filter((collection) => (recordIds[collection] || []).length > 0);
  const counts = Object.fromEntries(
    collections.map((collection) => [collection, recordIds[collection].length])
  );
  return {
    tenant_id: tenantId,
    identifier,
    generated_at: new Date().toISOString(),
    dry_run: dryRun,
    selection_mode: "exact_identifier_value",
    scanned_collections: [...PATCHFORGE_UAT_CLEANUP_COLLECTIONS],
    scanned_collection_count: PATCHFORGE_UAT_CLEANUP_COLLECTIONS.length,
    collections,
    counts,
    record_ids: Object.fromEntries(
      collections.map((collection) => [collection, [...recordIds[collection]].sort()])
    ),
    total_records: Object.values(counts).reduce((total, count) => total + count, 0),
    required_confirmation: identifier,
    preserves: [
      "all records without an exact identifier value match",
      "all audit events, including earlier UAT references",
      "all other tenants",
      "Git and deployment history"
    ],
    boundary: {
      exact_identifier_required: true,
      required_prefix: PATCHFORGE_UAT_IDENTIFIER_PREFIX,
      collection_wide_selection_permitted: false,
      audit_events_preserved: true,
      human_confirmation_required: true,
      server_issued_preview_required: true,
      execution_rejected_on_preview_drift: true,
      no_patch_deployment: true,
      no_autonomous_approval: true,
      final_approval_issued: false
    }
  };
}

async function issueUatCleanupPreview(storage, plan) {
  const previewToken = randomUUID();
  const previewDigest = uatCleanupPlanDigest(plan);
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.getTime() + PATCHFORGE_UAT_PREVIEW_TTL_MS);
  const preview = {
    tenant_id: plan.tenant_id,
    preview_id: `PF-UAT-PREVIEW-${sha256Text(`${plan.tenant_id}\0${plan.identifier}`).slice(0, 24)}`,
    identifier: plan.identifier,
    preview_token_sha256: sha256Text(previewToken),
    preview_digest: previewDigest,
    record_ids: plan.record_ids,
    total_records: plan.total_records,
    status: "pending",
    issued_at: issuedAt.toISOString(),
    expires_at: expiresAt.toISOString()
  };
  await storage.append("uat_cleanup_previews", preview);
  return {
    ...plan,
    preview_token: previewToken,
    preview_digest: previewDigest,
    preview_expires_at: preview.expires_at
  };
}

async function requireUatCleanupPreview(storage, tenantId, plan, token) {
  const tokenHash = previewTokenHash(token);
  const preview = (await storage.list("uat_cleanup_previews", tenantId))
    .find((record) => record.preview_token_sha256 === tokenHash);
  validateUatCleanupPreviewRecord(preview, tenantId, plan.identifier);
  assertUatCleanupPreviewMatches(preview, plan);
  return preview;
}

async function requirePostgresUatCleanupPreview(client, tenantId, identifier, token) {
  const tokenHash = previewTokenHash(token);
  const result = await client.query(
    `select record
     from patchforge_records
     where tenant_id = $1
       and collection = 'uat_cleanup_previews'
       and record->>'preview_token_sha256' = $2
     for update`,
    [tenantId, tokenHash]
  );
  const preview = result.rows[0]?.record || null;
  validateUatCleanupPreviewRecord(preview, tenantId, identifier);
  return preview;
}

function previewTokenHash(value) {
  if (typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) {
    throw uatCleanupInputError(
      "uat_cleanup_preview_required",
      "Execute cleanup only from a current server-issued preview token. Preview this exact UAT identifier again.",
      400
    );
  }
  return sha256Text(value);
}

function validateUatCleanupPreviewRecord(preview, tenantId, identifier) {
  if (!preview || preview.tenant_id !== tenantId || preview.identifier !== identifier) {
    throw uatCleanupInputError(
      "uat_cleanup_preview_invalid",
      "The UAT cleanup preview is invalid for this tenant or identifier. Preview again.",
      409
    );
  }
  if (preview.status !== "pending") {
    throw uatCleanupInputError(
      "uat_cleanup_preview_consumed",
      "The UAT cleanup preview has already been used. Preview again.",
      409
    );
  }
  if (!preview.expires_at || Date.parse(preview.expires_at) <= Date.now()) {
    throw uatCleanupInputError(
      "uat_cleanup_preview_expired",
      "The UAT cleanup preview has expired. Preview again.",
      409
    );
  }
}

function assertUatCleanupPreviewMatches(preview, plan) {
  const currentDigest = uatCleanupPlanDigest(plan);
  if (preview.preview_digest !== currentDigest) {
    throw uatCleanupInputError(
      "uat_cleanup_preview_drift",
      "Records linked to this UAT identifier changed after preview. No records were removed; preview again.",
      409
    );
  }
}

function uatCleanupPlanDigest(plan) {
  return sha256Text(JSON.stringify({
    tenant_id: plan.tenant_id,
    identifier: plan.identifier,
    record_ids: plan.record_ids,
    total_records: plan.total_records
  }));
}

function sha256Text(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

function validateUatCleanupOptions(options = {}) {
  const selector = PATCHFORGE_UAT_FORBIDDEN_SELECTORS.find((key) => (
    Object.prototype.hasOwnProperty.call(options, key)
  ));
  if (selector) {
    throw uatCleanupInputError(
      "collection_wide_selection_forbidden",
      `UAT cleanup does not accept '${selector}'. Supply one exact UAT-PF- identifier only.`
    );
  }
}

function normalizeUatCleanupIdentifier(value) {
  if (typeof value !== "string" || !value) {
    throw uatCleanupInputError(
      "uat_identifier_required",
      `A single identifier beginning with ${PATCHFORGE_UAT_IDENTIFIER_PREFIX} is required.`
    );
  }
  if (!PATCHFORGE_UAT_IDENTIFIER_PATTERN.test(value)) {
    throw uatCleanupInputError(
      "invalid_uat_identifier",
      `The identifier must begin with ${PATCHFORGE_UAT_IDENTIFIER_PREFIX} and contain only letters, numbers, dot, underscore, colon, or hyphen.`
    );
  }
  return value;
}

function uatCleanupInputError(publicError, publicMessage, statusCode = 400) {
  const error = new Error(publicMessage);
  error.statusCode = statusCode;
  error.publicError = publicError;
  error.publicMessage = publicMessage;
  return error;
}

function recordReferencesExactIdentifier(value, identifier, seen = new WeakSet()) {
  if (typeof value === "string") {
    return value === identifier;
  }
  if (!value || typeof value !== "object") {
    return false;
  }
  if (seen.has(value)) {
    return false;
  }
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((item) => recordReferencesExactIdentifier(item, identifier, seen));
  }
  return Object.values(value)
    .some((item) => recordReferencesExactIdentifier(item, identifier, seen));
}

function blockedUatCleanupPlan(plan) {
  return {
    ...plan,
    blocked: true,
    error: "exact_identifier_confirmation_required",
    required_confirmation: plan.identifier,
    storage_mutation_executed: false
  };
}

function buildUatCleanupAuditDetails(plan, removed, lineage = {}, preview = null) {
  return {
    identifier: plan.identifier,
    selection_mode: plan.selection_mode,
    collections: plan.collections,
    record_ids: plan.record_ids,
    removed,
    total_removed: Object.values(removed).reduce((total, count) => total + count, 0),
    preview_id: preview?.preview_id || null,
    preview_digest: preview?.preview_digest || null,
    dry_run: false,
    boundary: plan.boundary,
    ...(lineage || {})
  };
}

function buildUatCleanupAuditRecord(tenantId, plan, removed, lineage = {}, preview = null) {
  return {
    tenant_id: tenantId,
    audit_id: `audit-${randomUUID()}`,
    event_type: "patchforge_uat_cleanup_completed",
    details: buildUatCleanupAuditDetails(plan, removed, lineage, preview),
    created_at: new Date().toISOString()
  };
}

function completedUatCleanupPlan(plan, removed, auditId, preview = null) {
  return {
    ...plan,
    dry_run: false,
    removed,
    total_removed: Object.values(removed).reduce((total, count) => total + count, 0),
    audit_id: auditId,
    preview_id: preview?.preview_id || null,
    preview_digest: preview?.preview_digest || null,
    final_approval_issued: false,
    storage_mutation_executed: true,
    no_patch_deployment: true
  };
}

async function listPostgresUatCleanupRows(client, tenantId) {
  const result = await client.query(
    `select collection, record_id, record
     from patchforge_records
     where tenant_id = $1
       and collection = any($2::text[])
     order by collection asc, created_at asc`,
    [tenantId, PATCHFORGE_UAT_CLEANUP_COLLECTIONS]
  );
  return result.rows;
}

function resolvePurgeScopes(options = {}) {
  if (options.all) {
    return Object.keys(PATCHFORGE_PURGE_SCOPES);
  }
  const requested = Array.isArray(options.scopes)
    ? options.scopes
    : Object.keys(PATCHFORGE_PURGE_SCOPES).filter((scope) => Boolean(options[scope]));
  return requested
    .map((scope) => String(scope).trim().toLowerCase())
    .filter((scope) => Object.prototype.hasOwnProperty.call(PATCHFORGE_PURGE_SCOPES, scope));
}

export function isPositiveEvidence(source) {
  return source.review_state !== "rejected" && source.evidence_state === "accepted_positive_evidence";
}

function lineageFromPayload(payload = {}) {
  return {
    actor_oid: payload.actor_oid || null,
    actor_upn: payload.actor_upn || null,
    actor_roles: Array.isArray(payload.actor_roles) ? payload.actor_roles : [],
    actor_tenant_id: payload.actor_tenant_id || null,
    effective_tenant_id: payload.effective_tenant_id || null,
    requested_tenant_id: payload.requested_tenant_id || null,
    tenant_id_source: payload.tenant_id_source || null,
    tenant_override_ignored: Boolean(payload.tenant_override_ignored)
  };
}

export function maskSecretValues(value) {
  if (Array.isArray(value)) {
    return value.map((item) => maskSecretValues(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => {
        if (isSecretKey(key) && nested) {
          return [key, "********"];
        }
        return [key, maskSecretValues(nested)];
      })
    );
  }
  return value;
}

function isSecretKey(key) {
  return /(^|_)(password|token|secret|apiKey|api_key|clientSecret|client_secret|signingSecret|signing_secret)$/i.test(key);
}

function productionAdminConfig() {
  return {
    ...DEFAULT_ADMIN_CONFIG,
    signing: {
      ...DEFAULT_ADMIN_CONFIG.signing,
      trust_state: "key-vault",
      production_signing_enabled: true
    },
    storage: {
      ...DEFAULT_ADMIN_CONFIG.storage,
      mode: "postgresql"
    },
    updated_at: new Date().toISOString()
  };
}

function defaultAdminConfigForMode(storageMode) {
  return storageMode === "postgresql" ? productionAdminConfig() : { ...DEFAULT_ADMIN_CONFIG };
}

function normalizeAdminConfig(config) {
  const next = deepMerge(DEFAULT_ADMIN_CONFIG, config || {});
  const feeds = configuredSourceFeeds(next);
  if (!feeds.length && next.vendor_intelligence?.enabled !== false) {
    next.integrations = {
      ...(next.integrations || {}),
      source_feeds: DEFAULT_ADMIN_CONFIG.integrations.source_feeds
    };
  }
  next.agent_intelligence = {
    ...DEFAULT_ADMIN_CONFIG.agent_intelligence,
    ...(next.agent_intelligence || {}),
    advisory_only: true,
    review_required: true,
    can_close_hard_gates_alone: false
  };
  next.vendorlens = {
    ...DEFAULT_ADMIN_CONFIG.vendorlens,
    ...(next.vendorlens || {}),
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false,
    final_approval_requires_human: true
  };
  next.telemetry = {
    ...(next.telemetry || {}),
    health_checks_read_only: true,
    azure_mutation_enabled: false
  };
  next.feature_flags = {
    ...(next.feature_flags || {}),
    azure_mutation_enabled: false
  };
  return next;
}

function configuredSourceFeeds(config) {
  return (config.integrations?.source_feeds || []).filter((feed) => feed && feed.enabled !== false);
}

function agentIntakeEnabled(config) {
  return Boolean(
    config.agent_intelligence?.review_required &&
    config.agent_intelligence?.advisory_only &&
    config.agent_intelligence?.can_close_hard_gates_alone === false &&
    (
      config.agent_intelligence?.mcp_agent_findings_enabled ||
      config.agent_intelligence?.mythos_findings_enabled ||
      config.agent_intelligence?.agi_agent_findings_enabled
    )
  );
}

function deepMerge(...values) {
  const output = {};
  for (const value of values) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      continue;
    }
    for (const [key, nested] of Object.entries(value)) {
      if (Array.isArray(nested)) {
        output[key] = nested.map((item) => deepClone(item));
      } else if (nested && typeof nested === "object") {
        output[key] = deepMerge(output[key] || {}, nested);
      } else if (nested !== undefined) {
        output[key] = nested;
      }
    }
  }
  return output;
}

function deepClone(value) {
  if (Array.isArray(value)) {
    return value.map((item) => deepClone(item));
  }
  if (value && typeof value === "object") {
    return deepMerge(value);
  }
  return value;
}

function parseEnvBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function sourceFeedSchedulerHealth(lastRun, configured) {
  if (!configured) {
    return { status: "pending", mode: "scheduler-not-confirmed" };
  }
  if (!lastRun?.completed_at) {
    return { status: "pending", mode: "scheduler-enabled-awaiting-first-run" };
  }
  const completedAt = Date.parse(lastRun.completed_at);
  if (!Number.isFinite(completedAt)) {
    return { status: "degraded", mode: "last source refresh timestamp is invalid" };
  }
  const staleAfterMs = positiveNumber(process.env.PATCHFORGE_SOURCE_FEED_STALE_AFTER_MS, 8 * 60 * 60 * 1000);
  const ageMs = Math.max(0, Date.now() - completedAt);
  const runStatus = String(lastRun.status || "unknown").toLowerCase();
  const ageMinutes = Math.floor(ageMs / 60000);
  const mode = `last source refresh ${lastRun.completed_at}; age ${ageMinutes} minute(s); expected within ${Math.floor(staleAfterMs / 3600000)} hour(s)`;
  if (!["completed", "completed_with_warnings"].includes(runStatus)) {
    return { status: "degraded", mode: `${mode}; last run ${runStatus}` };
  }
  if (ageMs > staleAfterMs) {
    return { status: "stale", mode };
  }
  return { status: runStatus === "completed_with_warnings" ? "degraded" : "ready", mode };
}

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function assertKnownCollection(collection) {
  if (!COLLECTIONS.includes(collection)) {
    throw new Error(`Unknown PatchForge collection: ${collection}`);
  }
}

function recordIdFor(collection, record) {
  const idField = COLLECTION_ID_FIELDS[collection];
  const recordId = record[idField] || record.id;
  if (!record.tenant_id) {
    throw new Error(`PatchForge ${collection} record is missing tenant_id.`);
  }
  if (!recordId) {
    throw new Error(`PatchForge ${collection} record is missing ${idField}.`);
  }
  return String(recordId);
}

async function createPostgresPool(options) {
  const { Pool } = await import("pg");
  const password = options.password || await resolvePostgresPassword(options);
  if (!options.host) {
    throw new Error("PATCHFORGE_DATABASE_HOST is required when PATCHFORGE_STORAGE_MODE=postgresql.");
  }
  if (!password) {
    throw new Error("PATCHFORGE_DATABASE_PASSWORD or PATCHFORGE_DATABASE_PASSWORD_SECRET_NAME is required for PostgreSQL storage.");
  }
  return new Pool({
    host: options.host,
    database: options.database || "patchforge_prod",
    user: options.user || "patchforgeadmin",
    password,
    port: Number(options.port || process.env.PATCHFORGE_DATABASE_PORT || 5432),
    max: Number(options.maxPoolSize || process.env.PATCHFORGE_DATABASE_POOL_MAX || 5),
    ssl: options.ssl === false ? false : { rejectUnauthorized: true }
  });
}

async function resolvePostgresPassword(options) {
  if (!options.passwordSecretName) {
    return null;
  }
  if (!options.keyVaultUri) {
    throw new Error("PATCHFORGE_KEYVAULT_URI is required when using a database password secret.");
  }
  const { DefaultAzureCredential } = await import("@azure/identity");
  const { SecretClient } = await import("@azure/keyvault-secrets");
  const credential = new DefaultAzureCredential(
    options.azureClientId ? { managedIdentityClientId: options.azureClientId } : undefined
  );
  const client = new SecretClient(options.keyVaultUri, credential);
  const secret = await client.getSecret(options.passwordSecretName);
  return secret.value;
}

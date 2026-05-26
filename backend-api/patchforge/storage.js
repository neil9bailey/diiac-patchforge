import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const COLLECTIONS = [
  "vulnerabilities",
  "sources",
  "assets",
  "services",
  "reviews",
  "audit_events"
];

const DEFAULT_ADMIN_CONFIG = {
  tenant_id: "diiac-demo",
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
  integrations: {
    diiac_it_enabled: false,
    scanner_integrations: [],
    source_feeds: []
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

export class PatchForgeJsonStorage {
  constructor(rootDir = path.resolve("customer-config/demo/patchforge")) {
    this.rootDir = rootDir;
  }

  async ensureReady() {
    await mkdir(this.rootDir, { recursive: true });
    await Promise.all(COLLECTIONS.map((collection) => this.#ensureCollection(collection)));
  }

  async #ensureCollection(collection) {
    const file = this.#file(collection);
    try {
      await readFile(file, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      await writeFile(file, "[]\n", "utf8");
    }
  }

  #file(collection) {
    return path.join(this.rootDir, `${collection}.json`);
  }

  async #read(collection) {
    await this.ensureReady();
    return JSON.parse(await readFile(this.#file(collection), "utf8"));
  }

  async #write(collection, records) {
    await this.ensureReady();
    const file = this.#file(collection);
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, `${JSON.stringify(records, null, 2)}\n`, "utf8");
    await rename(tmp, file);
  }

  #adminConfigFile() {
    return path.join(this.rootDir, "admin_config.json");
  }

  async #readAdminConfigFile() {
    await this.ensureReady();
    const file = this.#adminConfigFile();
    try {
      return JSON.parse(await readFile(file, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") {
        throw error;
      }
      const initial = { "diiac-demo": DEFAULT_ADMIN_CONFIG };
      await writeFile(file, `${JSON.stringify(initial, null, 2)}\n`, "utf8");
      return initial;
    }
  }

  async #writeAdminConfigFile(config) {
    await this.ensureReady();
    const file = this.#adminConfigFile();
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    await rename(tmp, file);
  }

  async list(collection, tenantId) {
    const records = await this.#read(collection);
    return records.filter((record) => record.tenant_id === tenantId);
  }

  async append(collection, record) {
    const records = await this.#read(collection);
    records.push(record);
    await this.#write(collection, records);
    return record;
  }

  async replace(collection, predicate, updater) {
    const records = await this.#read(collection);
    let updatedRecord = null;
    const updated = records.map((record) => {
      if (!predicate(record)) {
        return record;
      }
      updatedRecord = updater(record);
      return updatedRecord;
    });
    await this.#write(collection, updated);
    return updatedRecord;
  }

  async ingestVulnerability(tenantId, payload) {
    const now = new Date().toISOString();
    const vulnerabilityId = payload.vulnerability_id || payload.canonical_id || `vuln-${randomUUID()}`;
    const sourceInputs = Array.isArray(payload.sources) ? payload.sources : [];
    const sourceRecordIds = [];

    for (const source of sourceInputs) {
      const sourceRecord = {
        tenant_id: tenantId,
        source_record_id: source.source_record_id || `src-${randomUUID()}`,
        vulnerability_id: vulnerabilityId,
        source_class: source.source_class || "scanner_output",
        source_name: source.source_name || "manual-ingest",
        source_url: source.source_url || null,
        payload_hash: source.payload_hash || hashObject(source),
        ingested_at: now,
        review_state: source.review_state || "pending_review",
        evidence_state: source.evidence_state || "referenced",
        reviewed_by: null,
        reviewed_at: null
      };
      sourceRecordIds.push(sourceRecord.source_record_id);
      await this.append("sources", sourceRecord);
    }

    const record = {
      tenant_id: tenantId,
      vulnerability_id: vulnerabilityId,
      canonical_id: payload.canonical_id || vulnerabilityId,
      title: payload.title || vulnerabilityId,
      description: payload.description || "",
      severity: payload.severity || "unknown",
      cvss_score: payload.cvss_score ?? null,
      known_exploited: Boolean(payload.known_exploited),
      internet_exposed: Boolean(payload.internet_exposed),
      ot_relevant: Boolean(payload.ot_relevant),
      affected_service_ids: payload.affected_service_ids || [],
      affected_asset_ids: payload.affected_asset_ids || [],
      patch_status: payload.patch_status || "unknown",
      sla_due_at: payload.sla_due_at || null,
      source_state: "source_bound",
      review_state: payload.review_state || "pending_review",
      source_record_ids: sourceRecordIds,
      tags: payload.tags || [],
      created_at: now,
      updated_at: null
    };

    await this.append("vulnerabilities", record);
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
      rejected_sources: sources.filter((source) => source.review_state === "rejected" || source.evidence_state === "rejected").length
    };
  }

  async readAdminConfig(tenantId) {
    const allConfig = await this.#readAdminConfigFile();
    const config = allConfig[tenantId] || { ...DEFAULT_ADMIN_CONFIG, tenant_id: tenantId };
    return maskSecretValues(config);
  }

  async saveAdminConfig(tenantId, payload) {
    const allConfig = await this.#readAdminConfigFile();
    const previous = allConfig[tenantId] || { ...DEFAULT_ADMIN_CONFIG, tenant_id: tenantId };
    const next = {
      ...previous,
      ...payload,
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
    };

    const sanitized = maskSecretValues(next);
    allConfig[tenantId] = sanitized;
    await this.#writeAdminConfigFile(allConfig);
    await this.audit(tenantId, "admin_config_updated", { sections: Object.keys(payload) });
    return sanitized;
  }

  async adminHealth(tenantId) {
    await this.ensureReady();
    const config = await this.readAdminConfig(tenantId);
    return {
      tenant_id: tenantId,
      live_azure_mutation_enabled: false,
      checks: [
        { name: "Frontend health", status: "ready", mode: "read-only" },
        { name: "Bridge health", status: "ready", mode: "local-json" },
        { name: "Runtime health", status: "ready", mode: "local" },
        { name: "SRA health", status: config.sra?.advisory_only ? "advisory" : "disabled", mode: "advisory-only" },
        { name: "Worker health", status: "planned", mode: "not-deployed" },
        { name: "Scheduler health", status: "planned", mode: "not-deployed" },
        { name: "Database health", status: "placeholder", mode: config.storage?.mode || "local-json" },
        { name: "Storage health", status: "ready", mode: config.storage?.mode || "local-json" },
        { name: "Key Vault health", status: "planned", mode: "no-live-access" },
        { name: "Signing trust", status: config.signing?.trust_state || "dev-local", mode: "no-production-key" }
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

export function isPositiveEvidence(source) {
  return source.review_state !== "rejected" && source.evidence_state === "accepted_positive_evidence";
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

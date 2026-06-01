import { createHash, randomUUID } from "node:crypto";

const NOW_FALLBACK = "2026-06-01T00:00:00.000Z";

const ADAPTERS = [
  adapter("nvd-cve-api", "NVD CVE API", "NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0", "cve_record"),
  adapter("cisa-kev", "CISA Known Exploited Vulnerabilities", "CISA", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev_record"),
  adapter("first-epss", "FIRST EPSS", "FIRST", "https://api.first.org/data/v1/epss", "epss_signal"),
  adapter("cve-services", "CVE Program Services", "CVE Program", "https://cveawg.mitre.org/api/cve", "cve_program_record"),
  adapter("github-advisory", "GitHub Advisory Database", "GitHub", "https://api.github.com/advisories", "github_advisory"),
  adapter("vendor-advisory", "Vendor Advisory", "Vendor", "https://example.invalid/vendor-advisory", "vendor_advisory")
];

const FIXTURES = {
  "nvd-cve-api": [{
    cve_id: "CVE-2026-0001",
    title: "Synthetic NVD CVE metadata for PatchForge validation",
    description: "Synthetic source-bound CVE metadata used to verify defensive normalisation.",
    severity: "high",
    cvss_score: 8.8,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    vendor: "Fortinet",
    product: "FortiGate",
    affected_versions: ["< 7.2.8"],
    fixed_versions: ["7.2.8"],
    published_at: "2026-05-01T00:00:00.000Z",
    last_modified: "2026-05-20T00:00:00.000Z"
  }],
  "cisa-kev": [{
    cve_id: "CVE-2026-0001",
    title: "Synthetic known exploited vulnerability signal",
    description: "Synthetic KEV-style signal for defensive prioritisation only.",
    severity: "high",
    vendor: "Fortinet",
    product: "FortiGate",
    kev: true,
    active_exploitation: true,
    ransomware_association: "unknown",
    published_at: "2026-05-03T00:00:00.000Z",
    last_modified: "2026-05-03T00:00:00.000Z"
  }],
  "first-epss": [{
    cve_id: "CVE-2026-0001",
    title: "Synthetic EPSS probability signal",
    description: "Synthetic EPSS probability for defensive prioritisation tests.",
    severity: "high",
    epss_probability: 0.72,
    epss_percentile: 0.94,
    signal_date: "2026-05-21"
  }],
  "cve-services": [{
    cve_id: "CVE-2026-0002",
    title: "Synthetic CVE Program metadata record",
    description: "Synthetic CVE Program record for PatchForge adapter validation.",
    severity: "medium",
    vendor: "Cisco",
    product: "ASA",
    affected_versions: ["9.18.x"],
    fixed_versions: ["9.18.4"],
    published_at: "2026-05-10T00:00:00.000Z",
    last_modified: "2026-05-22T00:00:00.000Z"
  }],
  "github-advisory": [{
    cve_id: "CVE-2026-0003",
    advisory_id: "GHSA-pf26-demo",
    title: "Synthetic GitHub Advisory metadata",
    description: "Synthetic GitHub Advisory Database record without exploit mechanics.",
    severity: "critical",
    vendor: "Example OSS",
    product: "example-package",
    affected_versions: ["< 2.4.1"],
    fixed_versions: ["2.4.1"],
    published_at: "2026-05-12T00:00:00.000Z",
    last_modified: "2026-05-25T00:00:00.000Z"
  }],
  "vendor-advisory": [{
    cve_id: "CVE-2026-0004",
    advisory_id: "VENDOR-PF-2026-0004",
    title: "Synthetic vendor fixed-version advisory",
    description: "Synthetic vendor advisory with affected and fixed version evidence.",
    severity: "high",
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    affected_versions: ["< 11.1.3"],
    fixed_versions: ["11.1.3"],
    patch_urls: ["https://example.invalid/vendor/security/advisories/PF-2026-0004"],
    workaround: "Apply vendor-documented mitigation pending change approval.",
    published_at: "2026-05-13T00:00:00.000Z",
    last_modified: "2026-05-26T00:00:00.000Z"
  }]
};

export function listSourceAdapters() {
  return ADAPTERS.map((item) => ({ ...item }));
}

export async function syncSourceAdapter({ storage, tenantId, body = {} }) {
  const adapterId = String(body.adapter_id || body.feed_id || body.source_type || "nvd-cve-api").toLowerCase();
  const selected = ADAPTERS.find((candidate) => candidate.adapter_id === adapterId);
  if (!selected) {
    const error = new Error(`Unsupported PatchForge adapter: ${adapterId}`);
    error.code = "unsupported_source_adapter";
    error.allowedAdapters = ADAPTERS.map((item) => item.adapter_id);
    throw error;
  }

  const fetchedAt = body.fetched_at || new Date().toISOString();
  const fixtureRecords = Array.isArray(body.records) ? body.records : FIXTURES[selected.adapter_id] || [];
  const records = fixtureRecords.map((record) => normalizeSourceRecord(selected, record, fetchedAt));
  const limit = boundedLimit(body.limit, records.length || 10, 1, 100);
  const selectedRecords = records.slice(0, limit);
  let vulnerabilities = 0;
  let advisories = 0;
  let signals = 0;

  for (const record of selectedRecords) {
    const vulnerabilityId = record.cve_id || record.advisory_id;
    if (!vulnerabilityId) {
      continue;
    }
    await storage.ingestVulnerability(tenantId, {
      vulnerability_id: vulnerabilityId,
      canonical_id: record.cve_id || vulnerabilityId,
      advisory_id: record.advisory_id || null,
      title: record.title,
      description: record.description,
      severity: record.severity,
      cvss_score: record.cvss_score,
      cvss_vector: record.cvss_vector,
      vendor_id: slug(record.vendor),
      vendor_name: record.vendor,
      product_family: record.product,
      affected_versions: record.affected_versions,
      fixed_versions: record.fixed_versions,
      kev: record.kev,
      known_exploited: record.active_exploitation || record.kev,
      epss_score: record.epss_probability,
      epss_percentile: record.epss_percentile,
      patch_available: record.fixed_versions.length > 0 || record.patch_urls.length > 0,
      patch_status: record.fixed_versions.length > 0 || record.patch_urls.length > 0 ? "patch_available" : "unknown",
      source_name: selected.name,
      source_url: record.source_url,
      source_feed: selected.adapter_id,
      review_state: "pending_review",
      sources: [{
        source_record_id: record.source_record_id,
        source_class: selected.source_class,
        source_name: selected.name,
        source_url: record.source_url,
        payload_hash: record.source_hash,
        source: selected.provider,
        fetched_at: record.fetched_at,
        freshness: record.freshness,
        confidence: record.confidence,
        last_modified: record.last_modified,
        review_state: "pending_review",
        evidence_state: "referenced"
      }],
      ...lineageFromBody(body)
    });
    vulnerabilities += 1;

    if (["vendor_advisory", "github_advisory", "cve_record", "cve_program_record"].includes(selected.source_class)) {
      await storage.append("vendor_security_advisories", {
        tenant_id: tenantId,
        advisory_id: record.advisory_id || `${slug(record.vendor)}-${record.cve_id}`,
        vendor_id: slug(record.vendor),
        vendor_name: record.vendor,
        cve: record.cve_id,
        cves: record.cve_id ? [record.cve_id] : [],
        title: record.title,
        summary: record.description,
        severity: record.severity,
        product_family: record.product,
        affected_products: record.product ? [record.product] : [],
        affected_versions: record.affected_versions,
        fixed_versions: record.fixed_versions,
        patch_urls: record.patch_urls,
        workaround: record.workaround,
        known_exploited: Boolean(record.active_exploitation || record.kev),
        kev: Boolean(record.kev),
        epss_score: record.epss_probability,
        epss_percentile: record.epss_percentile,
        patch_available: record.fixed_versions.length > 0 || record.patch_urls.length > 0,
        source_url: record.source_url,
        source_hash: record.source_hash,
        source: selected.provider,
        fetched_at: record.fetched_at,
        freshness: record.freshness,
        confidence: record.confidence,
        last_modified_at: record.last_modified,
        review_state: "pending_review",
        evidence_state: "referenced",
        source_state: "source_bound",
        advisory_only: true,
        can_close_hard_gates_alone: false,
        final_approval_issued: false,
        created_at: fetchedAt,
        ...lineageFromBody(body)
      });
      advisories += 1;
    }

    if (record.kev || record.epss_probability !== null || record.active_exploitation) {
      await storage.append("threat_signals", {
        tenant_id: tenantId,
        signal_id: `signal-${selected.adapter_id}-${vulnerabilityId}-${record.source_hash.slice(0, 10)}`,
        cve_id: record.cve_id,
        vulnerability_id: record.cve_id,
        signal_type: record.kev ? "known_exploited" : "exploit_probability",
        source: selected.provider,
        source_url: record.source_url,
        fetched_at: record.fetched_at,
        source_hash: record.source_hash,
        freshness: record.freshness,
        confidence: record.confidence,
        last_modified: record.last_modified,
        signal_date: record.signal_date,
        active_exploitation: Boolean(record.active_exploitation),
        ransomware_association: record.ransomware_association,
        kev: Boolean(record.kev),
        epss_probability: record.epss_probability,
        epss_percentile: record.epss_percentile,
        review_state: "pending_review",
        advisory_only: true,
        no_exploit_mechanics: true,
        created_at: fetchedAt,
        ...lineageFromBody(body)
      });
      signals += 1;
    }
  }

  const run = {
    tenant_id: tenantId,
    run_id: body.run_id || `run-adapter-${selected.adapter_id}-${Date.now()}-${randomUUID().slice(0, 8)}`,
    adapter_id: selected.adapter_id,
    feed_id: selected.adapter_id,
    feed_name: selected.name,
    provider: selected.provider,
    source_class: selected.source_class,
    source_url: selected.source_url,
    status: "completed",
    records_seen: fixtureRecords.length,
    records_matched: selectedRecords.length,
    records_ingested: vulnerabilities,
    records_enriched: signals,
    vendor_advisories_ingested: advisories,
    message: `${selected.name} synced through fixture-backed source adapter as source-bound pending-review intelligence.`,
    source_bound: true,
    review_required: true,
    advisory_only: true,
    can_close_hard_gates_alone: false,
    no_exploit_payloads: true,
    completed_at: fetchedAt,
    ...lineageFromBody(body)
  };
  await storage.append("source_feed_runs", run);
  await storage.audit(tenantId, "source_adapter_synced", {
    adapter_id: selected.adapter_id,
    records_ingested: vulnerabilities,
    ...lineageFromBody(body)
  });
  return {
    adapter: selected,
    normalized_records: selectedRecords,
    source_feed_run: run
  };
}

export function normalizeSourceRecord(adapterInfo, input = {}, fetchedAt = new Date().toISOString()) {
  const cveId = first(input.cve_id, input.cve, input.id);
  const lastModified = first(input.last_modified, input.lastModified, input.updated_at, input.modified, input.published_at, fetchedAt);
  const sourceUrl = first(input.source_url, input.url, input.advisory_url, adapterInfo.source_url);
  const normalized = {
    source_record_id: input.source_record_id || `src-${adapterInfo.adapter_id}-${cveId || input.advisory_id || hash(input).slice(0, 10)}`,
    cve_id: cveId ? String(cveId).toUpperCase() : null,
    advisory_id: first(input.advisory_id, input.ghsa_id, input.id),
    title: first(input.title, input.summary, input.name, cveId, "Source-bound vulnerability record"),
    description: stripUnsafeDetail(first(input.description, input.details, input.summary, "")),
    severity: String(first(input.severity, input.baseSeverity, "unknown")).toLowerCase(),
    cvss_score: numberOrNull(first(input.cvss_score, input.cvss)),
    cvss_vector: first(input.cvss_vector, input.vectorString),
    vendor: first(input.vendor, input.vendor_name, input.vendorProject, "Unknown vendor"),
    product: first(input.product, input.product_name, input.product_family, "Unknown product"),
    affected_versions: list(input.affected_versions, input.vulnerable_versions),
    fixed_versions: list(input.fixed_versions, input.patched_versions),
    patch_urls: list(input.patch_urls, input.patch_url),
    workaround: first(input.workaround, input.mitigation, null),
    published_at: first(input.published_at, input.published, null),
    last_modified: lastModified,
    source: adapterInfo.provider,
    source_url: sourceUrl,
    fetched_at: fetchedAt,
    freshness: freshness(lastModified, fetchedAt),
    confidence: confidenceFor(adapterInfo, input),
    kev: Boolean(input.kev || input.known_exploited),
    active_exploitation: Boolean(input.active_exploitation || input.known_exploited || input.kev),
    ransomware_association: first(input.ransomware_association, input.knownRansomwareCampaignUse, "unknown"),
    epss_probability: numberOrNull(first(input.epss_probability, input.epss_score, input.epss)),
    epss_percentile: numberOrNull(first(input.epss_percentile, input.percentile)),
    signal_date: first(input.signal_date, input.date, fetchedAt.slice(0, 10))
  };
  normalized.source_hash = hash({
    adapter_id: adapterInfo.adapter_id,
    cve_id: normalized.cve_id,
    advisory_id: normalized.advisory_id,
    title: normalized.title,
    source_url: normalized.source_url,
    last_modified: normalized.last_modified
  });
  return normalized;
}

function adapter(adapterId, name, provider, sourceUrl, sourceClass) {
  return {
    adapter_id: adapterId,
    name,
    provider,
    source_url: sourceUrl,
    source_class: sourceClass,
    authentication: "public_or_fixture",
    production_extensible: true,
    fixture_backed: true,
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false
  };
}

function freshness(lastModified, fetchedAt) {
  const fetched = Date.parse(fetchedAt || NOW_FALLBACK);
  const modified = Date.parse(lastModified || fetchedAt || NOW_FALLBACK);
  if (!Number.isFinite(fetched) || !Number.isFinite(modified)) {
    return "unknown";
  }
  const ageDays = Math.max(0, Math.round((fetched - modified) / 86400000));
  if (ageDays <= 7) return "fresh";
  if (ageDays <= 30) return "current";
  if (ageDays <= 90) return "aging";
  return "stale";
}

function confidenceFor(adapterInfo, input) {
  let score = 0.55;
  if (input.cve_id || input.cve) score += 0.15;
  if (input.last_modified || input.lastModified) score += 0.1;
  if (input.source_url || adapterInfo.source_url) score += 0.1;
  if (input.fixed_versions || input.patch_urls) score += 0.05;
  if (adapterInfo.adapter_id === "cisa-kev") score += 0.05;
  return Math.round(Math.min(score, 0.95) * 100) / 100;
}

function stripUnsafeDetail(value) {
  return String(value || "")
    .replace(/\b(metasploit|reverse shell|payload|shellcode|bypass)\b/gi, "[DEFENSIVE_DETAIL_REMOVED]")
    .replace(/\b(step-by-step exploit|weaponized|weaponised)\b/gi, "[DEFENSIVE_DETAIL_REMOVED]");
}

function list(...values) {
  return values.flatMap((value) => {
    if (Array.isArray(value)) return value.flatMap((item) => list(item));
    if (value === undefined || value === null || value === "") return [];
    return String(value).split(",").map((item) => item.trim()).filter(Boolean);
  });
}

function first(...values) {
  for (const value of values) {
    if (Array.isArray(value)) {
      const nested = value.find((item) => item !== undefined && item !== null && item !== "");
      if (nested !== undefined) return nested;
    } else if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return null;
}

function numberOrNull(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function boundedLimit(value, fallback, min, max) {
  const numeric = Number(value || fallback);
  return Number.isFinite(numeric) ? Math.max(min, Math.min(max, Math.floor(numeric))) : fallback;
}

function slug(value) {
  return String(value || "unknown-vendor").toLowerCase().replace(/&/g, "and").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "unknown-vendor";
}

function hash(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
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

import { createHash, randomUUID } from "node:crypto";
import { guardedFetchJson } from "./outboundFetch.js";

export const CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss";

const PUBLIC_SOURCE_FEEDS = [
  {
    feed_id: "cisa-kev",
    feed_name: "CISA Known Exploited Vulnerabilities Catalog",
    source_class: "kev_record",
    source_url: CISA_KEV_FEED_URL,
    provider: "CISA",
    authentication: "public",
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false
  },
  {
    feed_id: "first-epss",
    feed_name: "FIRST Exploit Prediction Scoring System",
    source_class: "epss_signal",
    source_url: FIRST_EPSS_API_URL,
    provider: "FIRST",
    authentication: "public",
    source_bound: true,
    review_required: true,
    can_close_hard_gates_alone: false
  }
];

export function createSourceFeedClient(options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const outboundOptions = options.outboundOptions || {};
  return {
    listFeeds() {
      return listPublicSourceFeeds();
    },
    async refresh({ storage, tenantId, body = {} }) {
      return refreshSourceFeed({ storage, tenantId, body, fetchImpl, outboundOptions });
    }
  };
}

export function listPublicSourceFeeds() {
  return PUBLIC_SOURCE_FEEDS.map((feed) => ({ ...feed }));
}

export async function refreshSourceFeed({ storage, tenantId, body = {}, fetchImpl = globalThis.fetch, outboundOptions = {} }) {
  const feedId = body.feed_id || "cisa-kev";
  const feed = PUBLIC_SOURCE_FEEDS.find((candidate) => candidate.feed_id === feedId);
  if (!feed) {
    const allowed = PUBLIC_SOURCE_FEEDS.map((candidate) => candidate.feed_id);
    const error = new Error(`Unsupported PatchForge source feed: ${feedId}`);
    error.code = "unsupported_source_feed";
    error.allowedFeeds = allowed;
    throw error;
  }

  if (feed.feed_id === "cisa-kev") {
    return refreshCisaKev({ storage, tenantId, feed, body, fetchImpl, outboundOptions });
  }

  if (feed.feed_id === "first-epss") {
    return refreshFirstEpss({ storage, tenantId, feed, body, fetchImpl, outboundOptions });
  }

  throw new Error(`No handler registered for PatchForge source feed: ${feed.feed_id}`);
}

async function refreshCisaKev({ storage, tenantId, feed, body, fetchImpl, outboundOptions }) {
  const startedAt = new Date().toISOString();
  const runId = body.run_id || `run-cisa-kev-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const limit = boundedLimit(body.limit, 10, 1, 50);
  const requestedCve = normalizeCveList(body.cve || body.cves);
  const feedPayload = await fetchJson(feed.source_url, fetchImpl, outboundOptions);
  const vulnerabilities = Array.isArray(feedPayload.vulnerabilities) ? feedPayload.vulnerabilities : [];
  const filtered = requestedCve.length
    ? vulnerabilities.filter((item) => requestedCve.includes(String(item.cveID || "").toUpperCase()))
    : vulnerabilities;
  const selected = filtered.slice(0, limit);
  let recordsIngested = 0;

  for (const item of selected) {
    const cve = String(item.cveID || "").trim().toUpperCase();
    if (!cve) {
      continue;
    }
    const vendorProject = String(item.vendorProject || "Unknown vendor").trim();
    const product = String(item.product || "Unknown product").trim();
    const sourceRecordId = `src-cisa-kev-${cve}`;
    await storage.ingestVulnerability(tenantId, {
      vulnerability_id: cve,
      canonical_id: cve,
      title: item.vulnerabilityName || `${vendorProject} ${product} KEV record`,
      description: item.shortDescription || "",
      severity: severityFromKev(item),
      known_exploited: true,
      internet_exposed: Boolean(body.internet_exposed),
      ot_relevant: isOtVendor(vendorProject) || Boolean(body.ot_relevant),
      patch_status: "unknown",
      sla_due_at: item.dueDate || null,
      review_state: "pending_review",
      tags: ["live_source_feed", "cisa_kev", slug(vendorProject), slug(product)].filter(Boolean),
      sources: [{
        source_record_id: sourceRecordId,
        source_class: "kev_record",
        source_name: feed.feed_name,
        source_url: feed.source_url,
        payload_hash: hashValue(item),
        review_state: "pending_review",
        evidence_state: "referenced"
      }],
      ...lineageFromBody(body)
    });
    await storage.append("vendor_advisories", {
      tenant_id: tenantId,
      advisory_id: `cisa-kev-${cve}`,
      vendor_id: slug(vendorProject),
      product_id: slug(product),
      title: item.vulnerabilityName || `${vendorProject} ${product} KEV record`,
      severity: severityFromKev(item),
      source_class: "kev_record",
      source_url: feed.source_url,
      known_exploited: true,
      patch_available: false,
      superseded_by: null,
      superseded: false,
      review_state: "pending_review",
      evidence_state: "referenced",
      source_state: "source_bound",
      source_record_id: sourceRecordId,
      cve,
      date_added: item.dateAdded || null,
      due_date: item.dueDate || null,
      known_ransomware_campaign_use: item.knownRansomwareCampaignUse || "Unknown",
      required_action: item.requiredAction || null,
      created_at: new Date().toISOString(),
      ...lineageFromBody(body)
    });
    recordsIngested += 1;
  }

  return recordRun(storage, tenantId, {
    ...runBase(feed, runId, startedAt, body),
    status: "completed",
    catalog_version: feedPayload.catalogVersion || null,
    date_released: feedPayload.dateReleased || null,
    records_seen: vulnerabilities.length,
    records_matched: filtered.length,
    records_ingested: recordsIngested,
    records_enriched: 0,
    message: `${recordsIngested} CISA KEV records ingested as source-bound pending-review intelligence.`
  });
}

async function refreshFirstEpss({ storage, tenantId, feed, body, fetchImpl, outboundOptions }) {
  const startedAt = new Date().toISOString();
  const runId = body.run_id || `run-first-epss-${Date.now()}-${randomUUID().slice(0, 8)}`;
  const requestedCve = normalizeCveList(body.cve || body.cves);
  const knownVulnerabilities = requestedCve.length ? [] : await storage.list("vulnerabilities", tenantId);
  const cves = requestedCve.length
    ? requestedCve
    : knownVulnerabilities.map((item) => item.canonical_id || item.vulnerability_id).filter(Boolean).slice(0, 50);

  if (!cves.length) {
    return recordRun(storage, tenantId, {
      ...runBase(feed, runId, startedAt, body),
      status: "blocked",
      records_seen: 0,
      records_matched: 0,
      records_ingested: 0,
      records_enriched: 0,
      message: "FIRST EPSS refresh needs at least one CVE from the request or existing vulnerability queue."
    });
  }

  const params = new URLSearchParams({ cve: cves.join(",") });
  const requestUrl = `${feed.source_url}?${params.toString()}`;
  const epssPayload = await fetchJson(requestUrl, fetchImpl, outboundOptions);
  const records = Array.isArray(epssPayload.data) ? epssPayload.data : [];
  let recordsEnriched = 0;

  for (const item of records) {
    const cve = String(item.cve || "").trim().toUpperCase();
    if (!cve) {
      continue;
    }
    const date = item.date || item.created || new Date().toISOString().slice(0, 10);
    const sourceRecordId = `src-first-epss-${cve}-${date}`;
    const epss = Number(item.epss);
    const percentile = Number(item.percentile);
    await storage.append("threat_signals", {
      tenant_id: tenantId,
      signal_id: `epss-${cve}-${date}`,
      signal_type: "exploit_probability",
      source_class: "epss_signal",
      source_name: feed.feed_name,
      source_url: requestUrl,
      vulnerability_id: cve,
      cve,
      epss_score: Number.isFinite(epss) ? epss : null,
      percentile: Number.isFinite(percentile) ? percentile : null,
      signal_date: date,
      source_state: "source_bound",
      review_state: "pending_review",
      evidence_state: "referenced",
      advisory_only: true,
      can_close_hard_gates_alone: false,
      no_autonomous_approval: true,
      created_at: new Date().toISOString(),
      ...lineageFromBody(body)
    });
    await storage.append("sources", {
      tenant_id: tenantId,
      source_record_id: sourceRecordId,
      vulnerability_id: cve,
      source_class: "epss_signal",
      source_name: feed.feed_name,
      source_url: requestUrl,
      payload_hash: hashValue(item),
      ingested_at: new Date().toISOString(),
      review_state: "pending_review",
      evidence_state: "referenced",
      reviewed_by: null,
      reviewed_at: null,
      ...lineageFromBody(body)
    });
    recordsEnriched += 1;
  }

  return recordRun(storage, tenantId, {
    ...runBase(feed, runId, startedAt, body, requestUrl),
    status: "completed",
    records_seen: cves.length,
    records_matched: records.length,
    records_ingested: 0,
    records_enriched: recordsEnriched,
    message: `${recordsEnriched} FIRST EPSS signals attached as source-bound pending-review intelligence.`
  });
}

async function fetchJson(url, fetchImpl, outboundOptions = {}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("PatchForge source feed refresh requires a fetch implementation.");
  }
  return guardedFetchJson(url, { ...outboundOptions, fetchImpl,
    headers: {
      accept: "application/json",
      "user-agent": "DIIaC-PatchForge/1.0 source-bound-governance"
    }
  });
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
  await storage.audit(tenantId, "source_feed_refreshed", {
    run_id: completed.run_id,
    feed_id: completed.feed_id,
    status: completed.status,
    records_ingested: completed.records_ingested,
    records_enriched: completed.records_enriched,
    ...lineageFromBody(run)
  });
  return completed;
}

function runBase(feed, runId, startedAt, body, sourceUrl = feed.source_url) {
  return {
    run_id: runId,
    feed_id: feed.feed_id,
    feed_name: feed.feed_name,
    provider: feed.provider,
    source_class: feed.source_class,
    source_url: sourceUrl,
    requested_limit: body.limit || null,
    requested_cves: normalizeCveList(body.cve || body.cves),
    started_at: startedAt,
    ...lineageFromBody(body)
  };
}

function boundedLimit(value, fallback, min, max) {
  const numeric = Number(value || fallback);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, Math.floor(numeric)));
}

function normalizeCveList(value) {
  if (!value) {
    return [];
  }
  const values = Array.isArray(value) ? value : String(value).split(",");
  return values.map((item) => String(item).trim().toUpperCase()).filter(Boolean);
}

function severityFromKev(item) {
  const text = `${item.vulnerabilityName || ""} ${item.shortDescription || ""}`.toLowerCase();
  if (/remote code execution|privilege escalation|authentication bypass|command injection|deserialization/.test(text)) {
    return "critical";
  }
  return "high";
}

function isOtVendor(vendorProject) {
  return /siemens|schneider|rockwell|abb|honeywell|ge vernova|emerson|yokogawa|phoenix contact/i.test(String(vendorProject || ""));
}

function hashValue(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function slug(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
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

import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { authorizeRequest, createAuthConfigFromEnv } from "./auth.js";
import { createPatchForgeStorage } from "./patchforge/storage.js";
import { createSourceFeedClient } from "./patchforge/sourceFeeds.js";
import { runSraTool } from "./sra/securityResearchAgent.js";

const DEFAULT_PORT = Number(process.env.PORT || 8080);
const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io";
const DEFAULT_RUNTIME_URL = process.env.PATCHFORGE_RUNTIME_URL || "http://127.0.0.1:8081";
const AGENT_FINDING_SOURCE_CLASSES = new Set(["mcp_agent_finding", "mythos_finding", "agi_agent_finding", "sra_trace"]);
const DEFAULT_VENDOR_PROFILES = [
  ["microsoft", "Microsoft", "identity_endpoint_cloud"],
  ["cisco", "Cisco", "infrastructure_networking"],
  ["juniper", "Juniper", "infrastructure_networking"],
  ["fortinet", "Fortinet", "infrastructure_networking"],
  ["palo-alto", "Palo Alto", "infrastructure_networking"],
  ["citrix-netscaler", "Citrix / NetScaler", "infrastructure_networking"],
  ["f5", "F5", "infrastructure_networking"],
  ["vmware-broadcom", "VMware / Broadcom", "virtualization_platform"],
  ["red-hat", "Red Hat", "enterprise_apps"],
  ["canonical", "Canonical", "enterprise_apps"],
  ["suse", "SUSE", "enterprise_apps"],
  ["atlassian", "Atlassian", "enterprise_apps"],
  ["servicenow", "ServiceNow", "enterprise_apps"],
  ["sap", "SAP", "enterprise_apps"],
  ["oracle", "Oracle", "enterprise_apps"],
  ["okta", "Okta", "identity_endpoint_cloud"],
  ["crowdstrike", "CrowdStrike", "identity_endpoint_cloud"],
  ["sentinelone", "SentinelOne", "identity_endpoint_cloud"],
  ["trend-micro", "Trend Micro", "identity_endpoint_cloud"],
  ["siemens", "Siemens", "ot_industrial"],
  ["schneider-electric", "Schneider Electric", "ot_industrial"],
  ["rockwell-automation", "Rockwell Automation", "ot_industrial"],
  ["abb", "ABB", "ot_industrial"],
  ["honeywell", "Honeywell", "ot_industrial"],
  ["ge-vernova", "GE Vernova", "ot_industrial"],
  ["emerson", "Emerson", "ot_industrial"],
  ["yokogawa", "Yokogawa", "ot_industrial"],
  ["phoenix-contact", "Phoenix Contact", "ot_industrial"]
].map(([vendor_id, vendor_name, category]) => ({
  tenant_id: DEFAULT_TENANT,
  vendor_id,
  vendor_name,
  category,
  review_state: "reference_catalogue",
  source_state: "catalogue"
}));

export function createServer(options = {}) {
  const storage = options.storage || createPatchForgeStorage({ storageRoot: options.storageRoot });
  const authConfig = options.auth || createAuthConfigFromEnv();
  const runtimeClient = options.runtimeClient || createRuntimeClientFromEnv();
  const sourceFeedClient = options.sourceFeedClient || createSourceFeedClient();
  const corsConfig = options.cors || createCorsConfigFromEnv();

  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", "http://localhost");
      applyCors(req, res, corsConfig);
      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      await storage.ensureReady();
      const route = `${req.method || "GET"} ${url.pathname}`;
      const authorization = await authorizeRequest(req, url, authConfig);

      if (!authorization.ok) {
        return sendJson(res, authorization.statusCode, {
          error: authorization.error,
          message: authorization.message,
          required_roles: authorization.requiredRoles
        });
      }
      const baseTenantContext = resolveTenantContext(req, url, {}, authConfig, authorization.principal);
      const tenantId = baseTenantContext.effective_tenant_id;

      if (req.method === "GET" && url.pathname === "/health") {
        return sendJson(res, 200, {
          status: "ok",
          product: "DIIaC PatchForge",
          boundary: "governance-only"
        });
      }

      if (req.method === "GET" && url.pathname === "/readiness") {
        return sendJson(res, 200, {
          status: "ready",
          storage: storage.storageMode || "local-json",
          auth_required: Boolean(authConfig.required),
          tenant_required: true
        });
      }

      if (route === "GET /api/patchforge/vulnerabilities") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          vulnerabilities: await storage.list("vulnerabilities", tenantId)
        });
      }

      if (route === "POST /api/patchforge/vulnerabilities/ingest") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const record = await storage.ingestVulnerability(tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization));
        return sendJson(res, 201, { vulnerability: record });
      }

      if (route === "POST /api/patchforge/agent-findings/ingest") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const agentRecord = await ingestAgentFinding(storage, tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization));
        if (!agentRecord.ok) {
          return sendJson(res, agentRecord.statusCode, {
            error: agentRecord.error,
            message: agentRecord.message,
            allowed_source_classes: Array.from(AGENT_FINDING_SOURCE_CLASSES)
          });
        }
        return sendJson(res, 202, {
          tenant_id: agentRecord.tenantId,
          vulnerability: agentRecord.vulnerability,
          boundary: {
            source_bound: true,
            advisory_only: true,
            review_required: true,
            can_close_hard_gates_alone: false,
            no_autonomous_approval: true,
            no_patch_deployment: true
          }
        });
      }

      const vulnerabilityDetailMatch = url.pathname.match(/^\/api\/patchforge\/vulnerabilities\/([^/]+)$/);
      if (req.method === "GET" && vulnerabilityDetailMatch) {
        const vulnerability = await storage.getVulnerability(tenantId, decodeURIComponent(vulnerabilityDetailMatch[1]));
        return vulnerability ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, vulnerability }) : sendJson(res, 404, { error: "vulnerability_not_found" });
      }

      const vulnerabilityReviewMatch = url.pathname.match(/^\/api\/patchforge\/vulnerabilities\/([^/]+)\/review$/);
      if (req.method === "POST" && vulnerabilityReviewMatch) {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const result = await storage.reviewVulnerability(tenantContext.effective_tenant_id, decodeURIComponent(vulnerabilityReviewMatch[1]), withLineage(body, tenantContext, authorization));
        return result ? sendJson(res, 200, result) : sendJson(res, 404, { error: "vulnerability_not_found" });
      }

      if (route === "GET /api/patchforge/assets") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          assets: await storage.list("assets", tenantId)
        });
      }

      if (route === "POST /api/patchforge/assets/ingest") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const record = await storage.ingestAsset(tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization));
        return sendJson(res, 201, { asset: record });
      }

      if (route === "GET /api/patchforge/services") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          services: await storage.list("services", tenantId)
        });
      }

      if (route === "POST /api/patchforge/services/ingest") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const record = await storage.ingestService(tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization));
        return sendJson(res, 201, { service: record });
      }

      const serviceExposureMatch = url.pathname.match(/^\/api\/patchforge\/services\/([^/]+)\/exposure$/);
      if (req.method === "GET" && serviceExposureMatch) {
        const exposure = await storage.getServiceExposure(tenantId, decodeURIComponent(serviceExposureMatch[1]));
        return exposure ? sendJson(res, 200, exposure) : sendJson(res, 404, { error: "service_not_found" });
      }

      if (route === "GET /api/patchforge/dashboard/metrics") {
        return sendJson(res, 200, { ...(await storage.dashboardMetrics(tenantId)), tenant_context: baseTenantContext });
      }

      if (route === "GET /api/patchforge/source-feeds") {
        const runs = await storage.list("source_feed_runs", tenantId);
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          feeds: sourceFeedClient.listFeeds(),
          recent_runs: runs.slice(-20).reverse(),
          boundary: {
            source_bound: true,
            review_required: true,
            can_close_hard_gates_alone: false,
            no_autonomous_approval: true,
            no_scanner: true,
            no_patch_deployment: true
          }
        });
      }

      if (route === "POST /api/patchforge/source-feeds/refresh") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        try {
          const run = await sourceFeedClient.refresh({
            storage,
            tenantId: tenantContext.effective_tenant_id,
            body: withLineage(body, tenantContext, authorization)
          });
          return sendJson(res, 202, {
            tenant_id: tenantContext.effective_tenant_id,
            tenant_context: tenantContext,
            source_feed_run: run
          });
        } catch (error) {
          return sendJson(res, error.code === "unsupported_source_feed" ? 400 : 502, {
            error: error.code || "source_feed_refresh_failed",
            message: error.message,
            allowed_feeds: error.allowedFeeds || sourceFeedClient.listFeeds().map((feed) => feed.feed_id)
          });
        }
      }

      if (route === "GET /api/patchforge/decision-packs") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          decision_packs: await storage.list("decision_packs", tenantId)
        });
      }

      const decisionPackExportMatch = url.pathname.match(/^\/api\/patchforge\/decision-packs\/([^/]+)\/export$/);
      if (req.method === "GET" && decisionPackExportMatch) {
        const packId = decodeURIComponent(decisionPackExportMatch[1]);
        const packs = await storage.list("decision_packs", tenantId);
        const pack = packs.find((record) => record.pack_id === packId || record.decision_pack_id === packId);
        if (!pack) {
          return sendJson(res, 404, { error: "decision_pack_not_found" });
        }
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          pack_id: pack.pack_id,
          exported_at: new Date().toISOString(),
          source_pack_immutable: true,
          verification: pack.verification || null,
          decision_pack: pack,
          artefacts: pack.artefacts || null,
          boundary: {
            no_scanner: true,
            no_exploit_generation: true,
            no_patch_deployment: true,
            no_production_mutation: true,
            no_autonomous_approval: true
          }
        });
      }

      if (route === "POST /api/patchforge/decision-packs/generate") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const resolvedTenant = tenantContext.effective_tenant_id;
        const vulnerabilityId = body.vulnerability_id;
        if (!vulnerabilityId) {
          return sendJson(res, 400, {
            error: "vulnerability_id_required",
            message: "A real ingested vulnerability_id is required before a decision pack can be generated."
          });
        }

        const vulnerability = await storage.getVulnerability(resolvedTenant, vulnerabilityId);
        if (!vulnerability) {
          return sendJson(res, 404, {
            error: "vulnerability_not_found",
            message: "Decision packs can only be generated from tenant records already ingested into PatchForge."
          });
        }

        const runtimeResult = await runtimeClient.createDecisionPack({
          tenant_id: resolvedTenant,
          vulnerability,
          evidence_items: buildEvidenceItemsFromRecord(vulnerability, body.evidence_items),
          model_name: body.model_name || "vuln_patch_governance",
          requested_posture: body.requested_posture || body.decision_posture || null,
          patch_availability: body.patch_availability || null,
          patch_feasibility: body.patch_feasibility || null,
          bayesian_snapshot: body.bayesian_snapshot || buildBayesianAssessment({ vulnerability }),
          patch_prior_usage_manifest: buildPriorUsageManifest(),
          patch_prior_update_proposal: body.patch_prior_update_proposal || null,
          vendor_intelligence_snapshot: body.vendor_intelligence_snapshot || null,
          threat_landscape_snapshot: body.threat_landscape_snapshot || await buildThreatLandscapeSummary(storage, resolvedTenant),
          sra_trace: body.sra_trace || null,
          controls: body.controls || null,
          risk_acceptance: body.risk_acceptance || null,
          approval_events: body.approval_events || []
        });

        const decisionContext = runtimeResult.decision_context || {};
        const packRecord = {
          tenant_id: resolvedTenant,
          decision_pack_id: runtimeResult.pack_id,
          pack_id: runtimeResult.pack_id,
          vulnerability_id: vulnerability.vulnerability_id,
          decision_id: decisionContext.decision_id || null,
          decision_posture: decisionContext.decision_posture || body.requested_posture || "defer_pending_evidence",
          readiness: decisionContext.readiness || null,
          blockers: decisionContext.blockers || decisionContext.readiness?.blockers || [],
          final_approval_issued: Boolean(decisionContext.final_approval_issued),
          source_pack_immutable: true,
          verification: runtimeResult.verification || null,
          signing_provider: runtimeResult.signing_provider || null,
          artefacts: runtimeResult.artefacts || null,
          runtime_component: runtimeResult.runtime_component || "patchforge-runtime",
          ...lineageFields(tenantContext, authorization),
          created_at: runtimeResult.created_at || new Date().toISOString()
        };
        await storage.append("decision_packs", packRecord);
        await storage.audit(resolvedTenant, "decision_pack_generated", {
          pack_id: packRecord.pack_id,
          vulnerability_id: packRecord.vulnerability_id,
          decision_posture: packRecord.decision_posture
        });

        return sendJson(res, 201, {
          tenant_id: resolvedTenant,
          tenant_context: tenantContext,
          decision_pack: packRecord,
          runtime: {
            verification: runtimeResult.verification || null,
            boundary: runtimeResult.boundary || null
          }
        });
      }

      if (route === "GET /api/patchforge/admin/config") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          config: await storage.readAdminConfig(tenantId)
        });
      }

      if (route === "PUT /api/patchforge/admin/config") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        if (body.live_azure_mutation_enabled === true || body.feature_flags?.azure_mutation_enabled === true) {
          return sendJson(res, 400, {
            error: "live_azure_mutation_blocked",
            message: "Admin configuration cannot enable live Azure mutation in this phase."
          });
        }
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          config: await storage.saveAdminConfig(tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization))
        });
      }

      if (route === "GET /api/patchforge/admin/health") {
        return sendJson(res, 200, { ...(await storage.adminHealth(tenantId)), tenant_context: baseTenantContext });
      }

      if (route === "POST /api/patchforge/bayesian/assess") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const assessment = buildBayesianAssessment(withLineage(body, tenantContext, authorization));
        await storage.append("bayesian_assessments", {
          tenant_id: tenantContext.effective_tenant_id,
          assessment_id: assessment.assessment_id,
          ...assessment,
          ...lineageFields(tenantContext, authorization)
        });
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          bayesian: assessment
        });
      }

      if (route === "GET /api/patchforge/bayesian/priors") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          priors: defaultBayesianPriors(),
          live_prior_update_enabled: false
        });
      }

      if (route === "POST /api/patchforge/bayesian/prior-update-dry-run") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        if (body.live_update === true) {
          return sendJson(res, 400, {
            error: "live_prior_update_locked",
            message: "PatchForge Bayesian prior updates are proposal-only unless explicitly approved in a later controlled release."
          });
        }
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          proposal: buildPriorUpdateProposal(withLineage(body, tenantContext, authorization))
        });
      }

      if (route === "GET /api/patchforge/vendors") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          vendors: await listVendorProfiles(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/vendors/upsert") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const vendor = await upsertVendor(storage, tenantContext.effective_tenant_id, withLineage(body, tenantContext, authorization));
        return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, vendor });
      }

      const vendorDetailMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)$/);
      if (req.method === "GET" && vendorDetailMatch) {
        const vendor = await getVendorProfile(storage, tenantId, decodeURIComponent(vendorDetailMatch[1]));
        return vendor ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, vendor }) : sendJson(res, 404, { error: "vendor_not_found" });
      }

      const vendorAdvisoryMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)\/advisories\/ingest$/);
      if (req.method === "POST" && vendorAdvisoryMatch) {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const advisory = await ingestVendorAdvisory(storage, tenantContext.effective_tenant_id, decodeURIComponent(vendorAdvisoryMatch[1]), withLineage(body, tenantContext, authorization));
        return sendJson(res, 201, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, advisory });
      }

      const vendorLandscapeMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)\/threat-landscape$/);
      if (req.method === "GET" && vendorLandscapeMatch) {
        return sendJson(res, 200, await buildVendorThreatLandscape(storage, tenantId, decodeURIComponent(vendorLandscapeMatch[1]), baseTenantContext));
      }

      if (route === "GET /api/patchforge/threat-landscape/summary") {
        return sendJson(res, 200, await buildThreatLandscapeSummary(storage, tenantId, baseTenantContext));
      }

      const sraRoutes = {
        "POST /api/sra/research-cve": "research_cve",
        "POST /api/sra/exploit-risk": "assess_exploit_risk",
        "POST /api/sra/compensating-controls": "suggest_compensating_controls",
        "POST /api/sra/patch-feasibility": "assess_patch_feasibility",
        "POST /api/sra/ot-constraints": "assess_ot_patch_constraints",
        "POST /api/sra/govern-agent-finding": "govern_agent_finding"
      };

      if (sraRoutes[route]) {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        try {
          const result = runSraTool(sraRoutes[route], withLineage({ ...body, tenant_id: tenantContext.effective_tenant_id }, tenantContext, authorization));
          return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, sra: result });
        } catch (error) {
          return sendJson(res, 400, { error: "sra_boundary_violation", message: error.message });
        }
      }

      return sendJson(res, 404, {
        error: "not_found",
        boundary: "No scanner, exploit, patch deployment, or production mutation endpoint exists."
      });
    } catch (error) {
      return sendJson(res, 500, {
        error: "internal_error",
        message: error.message
      });
    }
  });
}

function resolveTenantContext(req, url, body = {}, authConfig = {}, principal = null) {
  const requestedTenant = req.headers["x-tenant-id"] || url.searchParams.get("tenant_id") || body.tenant_id || null;
  const mappedTenant = tenantFromPrincipal(principal, authConfig);
  const roles = Array.isArray(principal?.roles) ? principal.roles : [];
  const adminOverrideAllowed = Boolean(authConfig.adminDiagnosticTenantOverride)
    && Boolean(authConfig.allowTenantOverride)
    && roles.includes("PatchForge.Admin");
  const developmentOverrideAllowed = !authConfig.production && Boolean(requestedTenant);
  const overrideAllowed = developmentOverrideAllowed || adminOverrideAllowed;
  const tenantOverrideIgnored = Boolean(requestedTenant && requestedTenant !== mappedTenant && !overrideAllowed);
  const effectiveTenantId = overrideAllowed && requestedTenant ? String(requestedTenant) : mappedTenant;
  return {
    requested_tenant_id: requestedTenant ? String(requestedTenant) : null,
    effective_tenant_id: effectiveTenantId,
    token_tenant_id: principal?.tid || null,
    tenant_id_source: overrideAllowed && requestedTenant
      ? (authConfig.production ? "admin_diagnostic_override" : "development_override")
      : "token_mapping",
    tenant_override_ignored: tenantOverrideIgnored
  };
}

function tenantFromPrincipal(principal, authConfig = {}) {
  if (principal?.tid && authConfig.tenantMappings?.[principal.tid]) {
    return authConfig.tenantMappings[principal.tid];
  }
  return authConfig.defaultTenant || DEFAULT_TENANT;
}

function withLineage(payload, tenantContext, authorization) {
  return {
    ...payload,
    ...lineageFields(tenantContext, authorization)
  };
}

function lineageFields(tenantContext, authorization) {
  const principal = authorization?.principal || {};
  return {
    actor_oid: principal.oid || null,
    actor_upn: principal.upn || null,
    actor_roles: Array.isArray(principal.roles) ? principal.roles : [],
    actor_tenant_id: principal.tid || null,
    effective_tenant_id: tenantContext.effective_tenant_id,
    requested_tenant_id: tenantContext.requested_tenant_id,
    tenant_id_source: tenantContext.tenant_id_source,
    tenant_override_ignored: tenantContext.tenant_override_ignored
  };
}

async function ingestAgentFinding(storage, tenantId, body) {
  const sourceClass = String(body.source_class || body.agent_source_class || "mcp_agent_finding");
  if (!AGENT_FINDING_SOURCE_CLASSES.has(sourceClass)) {
    return {
      ok: false,
      statusCode: 400,
      error: "unsupported_agent_source_class",
      message: "Agent finding intake accepts MCP, Mythos, AGI-agent, or SRA advisory source classes only."
    };
  }

  const findingId = body.finding_id || body.vulnerability_id || body.advisory_id;
  if (!findingId) {
    return {
      ok: false,
      statusCode: 400,
      error: "finding_id_required",
      message: "A source-provided finding_id, vulnerability_id, or advisory_id is required for agent finding intake."
    };
  }

  const vulnerabilityId = String(body.vulnerability_id || findingId);
  const sourceName = String(body.source_name || body.agent_name || body.finding_source || "mcp-agent");
  const sourceRecordId = String(body.source_record_id || `src-${sourceClass}-${findingId}`).replace(/\s+/g, "-");
  const vulnerability = await storage.ingestVulnerability(tenantId, {
    vulnerability_id: vulnerabilityId,
    canonical_id: body.canonical_id || vulnerabilityId,
    title: body.title || body.summary || vulnerabilityId,
    description: body.description || body.finding_summary || "",
    severity: body.severity || "unknown",
    cvss_score: body.cvss_score ?? null,
    known_exploited: Boolean(body.known_exploited),
    internet_exposed: Boolean(body.internet_exposed),
    ot_relevant: Boolean(body.ot_relevant),
    affected_service_ids: Array.isArray(body.affected_service_ids) ? body.affected_service_ids : [],
    affected_asset_ids: Array.isArray(body.affected_asset_ids) ? body.affected_asset_ids : [],
    patch_status: body.patch_status || "unknown",
    review_state: "pending_review",
    tags: Array.isArray(body.tags) ? body.tags : ["agent_intelligence"],
    sources: [{
      source_record_id: sourceRecordId,
      source_class: sourceClass,
      source_name: sourceName,
      source_url: body.source_url || null,
      payload_hash: body.payload_hash || undefined,
      review_state: "pending_review",
      evidence_state: "referenced"
    }]
  });
  await storage.audit(tenantId, "agent_finding_ingested", {
    vulnerability_id: vulnerability.vulnerability_id,
    finding_id: String(findingId),
    source_class: sourceClass,
    source_record_id: sourceRecordId
  });
  return { ok: true, tenantId, vulnerability };
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(`${body}\n`);
}

function buildEvidenceItemsFromRecord(vulnerability, submittedItems = []) {
  const sourceEvidence = (vulnerability.sources || []).map((source) => ({
    evidence_ref: source.source_record_id,
    evidence_class: source.evidence_class || evidenceClassForSource(source),
    source_class: source.source_class || "unknown",
    review_state: source.review_state || "pending_review",
    evidence_state: source.evidence_state || "referenced",
    source_record_id: source.source_record_id,
    source_name: source.source_name || null,
    source_url: source.source_url || null
  }));

  const submittedEvidence = Array.isArray(submittedItems) ? submittedItems : [];
  return [...sourceEvidence, ...submittedEvidence];
}

function evidenceClassForSource(source) {
  const sourceClass = source.source_class || "";
  if (sourceClass === "asset_inventory") {
    return "affected_asset_scope";
  }
  if (sourceClass === "service_catalogue") {
    return "business_service_impact";
  }
  if (sourceClass === "vendor_advisory" || sourceClass === "cve_record" || sourceClass === "vendor_patch_note") {
    return "vulnerability_identity";
  }
  if ([
    "kev_record",
    "kev_signal",
    "epss_signal",
    "threat_intel_report",
    "exploitability_report",
    "cloud_provider_advisory",
    "ot_vendor_notice"
  ].includes(sourceClass) || AGENT_FINDING_SOURCE_CLASSES.has(sourceClass)) {
    return "threat_intelligence_context";
  }
  if (sourceClass === "scanner_finding") {
    return "affected_asset_scope";
  }
  return "vulnerability_identity";
}

function defaultBayesianPriors() {
  return {
    prior_set_id: "patchforge-default-v1",
    exploit_probability_prior: 0.18,
    business_impact_prior: 0.35,
    patch_feasibility_prior: 0.55,
    change_risk_prior: 0.32,
    deferral_risk_prior: 0.28,
    live_prior_mutation_enabled: false,
    advisory_only: true
  };
}

function buildPriorUsageManifest(priors = defaultBayesianPriors()) {
  return {
    prior_usage_id: `prior-${Date.now()}`,
    prior_set_id: priors.prior_set_id,
    advisory_only: true,
    live_prior_mutation_performed: false,
    dry_run_only: true
  };
}

function buildPriorUpdateProposal(body = {}) {
  return {
    proposal_id: `prior-proposal-${Date.now()}`,
    prior_set_id: body.prior_set_id || "patchforge-default-v1",
    dry_run: true,
    live_update_applied: false,
    admin_approval_required: true,
    proposed_adjustments: body.observed_outcomes ? {
      exploit_probability_prior: "+0.01",
      change_risk_prior: "+0.01"
    } : {},
    boundary: {
      advisory_only: true,
      no_live_prior_mutation: true
    }
  };
}

function buildBayesianAssessment(body = {}) {
  const vulnerability = body.vulnerability || body;
  const cvss = Number(vulnerability.cvss_score || body.cvss || 0);
  const epss = clamp(Number(body.epss || vulnerability.epss || 0), 0, 1);
  const priors = defaultBayesianPriors();
  const exploitSignals = [
    Boolean(vulnerability.known_exploited || body.known_exploited) ? 0.32 : 0,
    Boolean(body.exploit_code_available) ? 0.12 : 0,
    Boolean(body.active_exploitation_reports) ? 0.18 : 0,
    Boolean(vulnerability.internet_exposed || body.internet_exposed) ? 0.12 : 0,
    epss * 0.2,
    cvss >= 9 ? 0.06 : cvss >= 7 ? 0.03 : 0
  ].reduce((sum, value) => sum + value, priors.exploit_probability_prior);
  const businessImpact = priors.business_impact_prior
    + (Boolean(vulnerability.customer_facing || body.customer_facing) ? 0.2 : 0)
    + (String(body.service_tier || vulnerability.service_tier || "").toLowerCase().includes("1") ? 0.16 : 0)
    + (String(body.asset_criticality || vulnerability.asset_criticality || "").toLowerCase().includes("critical") ? 0.16 : 0)
    + (Boolean(vulnerability.ot_relevant || body.ot_relevant) ? 0.12 : 0);
  const patchFeasibility = priors.patch_feasibility_prior
    + (["patch_available", "patch_feasible"].includes(String(vulnerability.patch_status || body.patch_status)) ? 0.22 : -0.18)
    + (Boolean(body.test_evidence_complete) ? 0.1 : -0.05)
    + (Boolean(body.rollback_evidence) ? 0.08 : -0.05)
    + (Boolean(body.vendor_patch_note) ? 0.05 : 0);
  const changeRisk = priors.change_risk_prior
    + (Boolean(vulnerability.ot_relevant || body.ot_relevant) ? 0.2 : 0)
    + (Boolean(body.rollback_evidence) ? -0.08 : 0.12)
    + (Boolean(body.test_evidence_complete) ? -0.06 : 0.08);
  const deferralRisk = priors.deferral_risk_prior
    + exploitSignals * 0.35
    + businessImpact * 0.25
    - (Boolean(body.compensating_controls) ? 0.08 : 0);
  const assessment = {
    assessment_id: `bayes-${Date.now()}`,
    generated_at: new Date().toISOString(),
    advisory_only: true,
    can_close_hard_gates_alone: false,
    final_approval_issued: false,
    exploit_probability_posterior: round(clamp(exploitSignals, 0, 0.98)),
    business_impact_posterior: round(clamp(businessImpact, 0, 0.98)),
    patch_feasibility_posterior: round(clamp(patchFeasibility, 0.02, 0.98)),
    change_risk_posterior: round(clamp(changeRisk, 0.02, 0.98)),
    deferral_risk_posterior: round(clamp(deferralRisk, 0.02, 0.98)),
    prior_usage: buildPriorUsageManifest(priors),
    boundary: {
      no_autonomous_approval: true,
      no_patch_deployment: true,
      prior_update_dry_run_only: true
    }
  };
  assessment.recommended_governance_posture = recommendedPosture(assessment, vulnerability);
  return assessment;
}

function recommendedPosture(assessment, vulnerability) {
  if (assessment.exploit_probability_posterior >= 0.7 && vulnerability.patch_status === "patch_available") {
    return "emergency_change_required";
  }
  if (assessment.deferral_risk_posterior >= 0.65 && vulnerability.patch_status === "patch_available") {
    return "patch_required";
  }
  if (assessment.change_risk_posterior >= 0.7) {
    return "mitigate_temporarily";
  }
  return "defer_pending_evidence";
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, Number.isFinite(value) ? value : min));
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}

async function listVendorProfiles(storage, tenantId) {
  const stored = await storage.list("vendors", tenantId);
  const merged = new Map(DEFAULT_VENDOR_PROFILES.map((vendor) => [vendor.vendor_id, { ...vendor, tenant_id: tenantId }]));
  for (const vendor of stored) {
    merged.set(vendor.vendor_id, vendor);
  }
  return Array.from(merged.values());
}

async function getVendorProfile(storage, tenantId, vendorId) {
  const vendors = await listVendorProfiles(storage, tenantId);
  return vendors.find((vendor) => vendor.vendor_id === vendorId || vendor.vendor_name?.toLowerCase() === vendorId.toLowerCase()) || null;
}

async function upsertVendor(storage, tenantId, body) {
  const vendor = {
    tenant_id: tenantId,
    vendor_id: body.vendor_id || slug(body.vendor_name || body.name || "vendor"),
    vendor_name: body.vendor_name || body.name || body.vendor_id,
    category: body.category || "enterprise_apps",
    review_state: body.review_state || "pending_review",
    source_state: "source_bound",
    created_at: new Date().toISOString(),
    ...lineageFieldsFromBody(body)
  };
  await storage.append("vendors", vendor);
  await storage.audit(tenantId, "vendor_profile_upserted", { vendor_id: vendor.vendor_id, ...lineageFieldsFromBody(body) });
  return vendor;
}

async function ingestVendorAdvisory(storage, tenantId, vendorId, body) {
  const advisory = {
    tenant_id: tenantId,
    advisory_id: body.advisory_id || `${vendorId}-${Date.now()}`,
    vendor_id: vendorId,
    product_id: body.product_id || null,
    title: body.title || body.advisory_id || "Vendor advisory",
    severity: body.severity || "unknown",
    source_class: body.source_class || "vendor_advisory",
    source_url: body.source_url || null,
    known_exploited: Boolean(body.known_exploited),
    patch_available: Boolean(body.patch_available),
    superseded_by: body.superseded_by || null,
    superseded: Boolean(body.superseded || body.superseded_by),
    review_state: body.review_state || "pending_review",
    evidence_state: body.evidence_state || "referenced",
    source_state: "source_bound",
    created_at: new Date().toISOString(),
    ...lineageFieldsFromBody(body)
  };
  await storage.append("vendor_advisories", advisory);
  await storage.audit(tenantId, "vendor_advisory_ingested", { vendor_id: vendorId, advisory_id: advisory.advisory_id, ...lineageFieldsFromBody(body) });
  return advisory;
}

async function buildVendorThreatLandscape(storage, tenantId, vendorId, tenantContext = null) {
  const advisories = (await storage.list("vendor_advisories", tenantId)).filter((item) => item.vendor_id === vendorId);
  return {
    tenant_id: tenantId,
    tenant_context: tenantContext || undefined,
    vendor_id: vendorId,
    metrics: vendorMetrics(advisories),
    advisories
  };
}

async function buildThreatLandscapeSummary(storage, tenantId, tenantContext = null) {
  const advisories = await storage.list("vendor_advisories", tenantId);
  const vendors = await listVendorProfiles(storage, tenantId);
  const byVendor = new Map();
  for (const advisory of advisories) {
    byVendor.set(advisory.vendor_id, [...(byVendor.get(advisory.vendor_id) || []), advisory]);
  }
  return {
    tenant_id: tenantId,
    tenant_context: tenantContext || undefined,
    generated_at: new Date().toISOString(),
    source_bound: true,
    review_required: true,
    vendor_count: vendors.length,
    metrics: vendorMetrics(advisories),
    top_exposed_vendors: Array.from(byVendor.entries()).map(([vendor_id, records]) => ({
      vendor_id,
      open_customer_decision_count: records.length,
      active_exploitation_count: records.filter((item) => item.known_exploited).length
    })).sort((a, b) => b.active_exploitation_count - a.active_exploitation_count).slice(0, 8)
  };
}

function vendorMetrics(advisories) {
  const count = Math.max(advisories.length, 1);
  return {
    active_exploitation_count: advisories.filter((item) => item.known_exploited).length,
    critical_open_advisory_count: advisories.filter((item) => item.severity === "critical" && item.review_state !== "closed").length,
    patch_available_rate: round(advisories.filter((item) => item.patch_available).length / count),
    known_exploited_rate: round(advisories.filter((item) => item.known_exploited).length / count),
    customer_estate_exposure: advisories.filter((item) => item.customer_estate_exposure).length,
    internet_exposed_asset_count: advisories.filter((item) => item.internet_exposed).length,
    ot_relevance: advisories.filter((item) => item.ot_relevant).length,
    patch_maturity: advisories.some((item) => item.patch_available) ? "available" : "unknown",
    vendor_response_timeliness: "source_bound_pending_review",
    superseded_advisory_count: advisories.filter((item) => item.superseded).length,
    false_positive_history: advisories.filter((item) => item.review_state === "rejected").length,
    open_customer_decision_count: advisories.length
  };
}

function lineageFieldsFromBody(body) {
  return {
    actor_oid: body.actor_oid || null,
    actor_upn: body.actor_upn || null,
    actor_roles: body.actor_roles || [],
    actor_tenant_id: body.actor_tenant_id || null,
    effective_tenant_id: body.effective_tenant_id || null,
    requested_tenant_id: body.requested_tenant_id || null,
    tenant_id_source: body.tenant_id_source || null,
    tenant_override_ignored: Boolean(body.tenant_override_ignored)
  };
}

function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "vendor";
}

export function createRuntimeClientFromEnv() {
  const baseUrl = DEFAULT_RUNTIME_URL.replace(/\/+$/, "");
  return {
    async createDecisionPack(payload) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Number(process.env.PATCHFORGE_RUNTIME_TIMEOUT_MS || 45000));
      try {
        const response = await fetch(`${baseUrl}/api/runtime/decision-packs`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          const message = body.message || body.error || `Runtime returned HTTP ${response.status}`;
          throw new Error(message);
        }
        return body;
      } finally {
        clearTimeout(timer);
      }
    }
  };
}

function createCorsConfigFromEnv() {
  const origins = (process.env.PATCHFORGE_ALLOWED_ORIGINS || "https://patchforge.diiac.io,http://localhost:5173,http://127.0.0.1:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  return { origins };
}

function applyCors(req, res, corsConfig) {
  const origin = req.headers.origin;
  if (origin && corsConfig.origins.includes(origin)) {
    res.setHeader("access-control-allow-origin", origin);
    res.setHeader("vary", "Origin");
  }
  res.setHeader("access-control-allow-methods", "GET,POST,PUT,OPTIONS");
  res.setHeader("access-control-allow-headers", "authorization,content-type,x-tenant-id");
  res.setHeader("access-control-max-age", "600");
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const server = createServer();
  server.listen(DEFAULT_PORT, () => {
    console.log(`DIIaC PatchForge API listening on ${DEFAULT_PORT}`);
  });
}

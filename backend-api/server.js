import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { authorizeRequest, createAuthConfigFromEnv } from "./auth.js";
import { createPatchForgeStorage } from "./patchforge/storage.js";
import { runSraTool } from "./sra/securityResearchAgent.js";

const DEFAULT_PORT = Number(process.env.PORT || 8080);
const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io";
const DEFAULT_RUNTIME_URL = process.env.PATCHFORGE_RUNTIME_URL || "http://127.0.0.1:8081";
const AGENT_FINDING_SOURCE_CLASSES = new Set(["mcp_agent_finding", "mythos_finding", "agi_agent_finding", "sra_trace"]);

export function createServer(options = {}) {
  const storage = options.storage || createPatchForgeStorage({ storageRoot: options.storageRoot });
  const authConfig = options.auth || createAuthConfigFromEnv();
  const runtimeClient = options.runtimeClient || createRuntimeClientFromEnv();
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
      const tenantId = resolveTenant(req, url);
      const authorization = await authorizeRequest(req, url, authConfig);

      if (!authorization.ok) {
        return sendJson(res, authorization.statusCode, {
          error: authorization.error,
          message: authorization.message,
          required_roles: authorization.requiredRoles
        });
      }

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
          vulnerabilities: await storage.list("vulnerabilities", tenantId)
        });
      }

      if (route === "POST /api/patchforge/vulnerabilities/ingest") {
        const body = await readJson(req);
        const record = await storage.ingestVulnerability(resolveTenant(req, url, body), body);
        return sendJson(res, 201, { vulnerability: record });
      }

      if (route === "POST /api/patchforge/agent-findings/ingest") {
        const body = await readJson(req);
        const agentRecord = await ingestAgentFinding(storage, resolveTenant(req, url, body), body);
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
        return vulnerability ? sendJson(res, 200, { vulnerability }) : sendJson(res, 404, { error: "vulnerability_not_found" });
      }

      const vulnerabilityReviewMatch = url.pathname.match(/^\/api\/patchforge\/vulnerabilities\/([^/]+)\/review$/);
      if (req.method === "POST" && vulnerabilityReviewMatch) {
        const body = await readJson(req);
        const result = await storage.reviewVulnerability(resolveTenant(req, url, body), decodeURIComponent(vulnerabilityReviewMatch[1]), body);
        return result ? sendJson(res, 200, result) : sendJson(res, 404, { error: "vulnerability_not_found" });
      }

      if (route === "GET /api/patchforge/assets") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          assets: await storage.list("assets", tenantId)
        });
      }

      if (route === "POST /api/patchforge/assets/ingest") {
        const body = await readJson(req);
        const record = await storage.ingestAsset(resolveTenant(req, url, body), body);
        return sendJson(res, 201, { asset: record });
      }

      if (route === "GET /api/patchforge/services") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          services: await storage.list("services", tenantId)
        });
      }

      if (route === "POST /api/patchforge/services/ingest") {
        const body = await readJson(req);
        const record = await storage.ingestService(resolveTenant(req, url, body), body);
        return sendJson(res, 201, { service: record });
      }

      const serviceExposureMatch = url.pathname.match(/^\/api\/patchforge\/services\/([^/]+)\/exposure$/);
      if (req.method === "GET" && serviceExposureMatch) {
        const exposure = await storage.getServiceExposure(tenantId, decodeURIComponent(serviceExposureMatch[1]));
        return exposure ? sendJson(res, 200, exposure) : sendJson(res, 404, { error: "service_not_found" });
      }

      if (route === "GET /api/patchforge/dashboard/metrics") {
        return sendJson(res, 200, await storage.dashboardMetrics(tenantId));
      }

      if (route === "GET /api/patchforge/decision-packs") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
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
        const resolvedTenant = resolveTenant(req, url, body);
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
          config: await storage.readAdminConfig(tenantId)
        });
      }

      if (route === "PUT /api/patchforge/admin/config") {
        const body = await readJson(req);
        if (body.live_azure_mutation_enabled === true || body.feature_flags?.azure_mutation_enabled === true) {
          return sendJson(res, 400, {
            error: "live_azure_mutation_blocked",
            message: "Admin configuration cannot enable live Azure mutation in this phase."
          });
        }
        return sendJson(res, 200, {
          tenant_id: resolveTenant(req, url, body),
          config: await storage.saveAdminConfig(resolveTenant(req, url, body), body)
        });
      }

      if (route === "GET /api/patchforge/admin/health") {
        return sendJson(res, 200, await storage.adminHealth(tenantId));
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
        try {
          const result = runSraTool(sraRoutes[route], { ...body, tenant_id: resolveTenant(req, url, body) });
          return sendJson(res, 200, { sra: result });
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

function resolveTenant(req, url, body = {}) {
  return req.headers["x-tenant-id"] || url.searchParams.get("tenant_id") || body.tenant_id || DEFAULT_TENANT;
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
  if (sourceClass === "vendor_advisory" || sourceClass === "cve_record") {
    return "vulnerability_identity";
  }
  if (sourceClass === "kev_record" || sourceClass === "epss_signal" || AGENT_FINDING_SOURCE_CLASSES.has(sourceClass)) {
    return "threat_intelligence_context";
  }
  return "vulnerability_identity";
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

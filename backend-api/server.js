import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { PatchForgeJsonStorage } from "./patchforge/storage.js";
import { runSraTool } from "./sra/securityResearchAgent.js";

const DEFAULT_PORT = Number(process.env.PORT || 8080);
const DEFAULT_TENANT = process.env.PATCHFORGE_DEFAULT_TENANT || "diiac-demo";

export function createServer(options = {}) {
  const storage = options.storage || new PatchForgeJsonStorage(options.storageRoot);

  return http.createServer(async (req, res) => {
    try {
      await storage.ensureReady();
      const url = new URL(req.url || "/", "http://localhost");
      const route = `${req.method || "GET"} ${url.pathname}`;
      const tenantId = resolveTenant(req, url);

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
          storage: "local-json",
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
        "POST /api/sra/ot-constraints": "assess_ot_patch_constraints"
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

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const server = createServer();
  server.listen(DEFAULT_PORT, () => {
    console.log(`DIIaC PatchForge API listening on ${DEFAULT_PORT}`);
  });
}

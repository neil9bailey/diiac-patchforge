import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { authorizeRequest, createAuthConfigFromEnv } from "./auth.js";
import { PATCHFORGE_PURGE_CONFIRMATION, createPatchForgeStorage } from "./patchforge/storage.js";
import { createSourceFeedClient } from "./patchforge/sourceFeeds.js";
import { listSourceAdapters, syncSourceAdapter } from "./patchforge/sourceAdapters.js";
import { importAssetsFromCsv, parseConfigEvidence, redactConfigInput } from "./patchforge/configParsers.js";
import {
  buildPriorityIndex,
  buildSignedActionPack,
  comparePatchActions,
  createWorkflowItem,
  transitionWorkflowItem,
  verifySignedActionPack
} from "./patchforge/priority.js";
import { buildFindingIntelligence, buildIntelligenceForTenant } from "./patchforge/intelligence.js";
import {
  DEFAULT_IMAGE_TAG,
  DEFAULT_PRODUCT_BASELINE,
  DEFAULT_RENDERER_COMMIT,
  REPORT_CATALOG,
  REPORT_CONTEXT_VERSION,
  REPORT_TEMPLATE_VERSION,
  buildReportContentReview,
  generateDecisionPackReport
} from "./patchforge/reports.js";
import { getOpenAiAgentStatus, OPENAI_AGENT_NAMES, runOpenAiAgent } from "./patchforge/openaiAgentService.js";
import { startScheduler } from "./patchforge/scheduler.js";
import { handlePlatformRoutes } from "./routes/platformRoutes.js";
import {
  buildAssetDiscoveryOverview,
  importDiscoveredAssets,
  listAssetCollectors,
  listAssetDiscoveryPolicies,
  registerAssetCollector,
  upsertAssetDiscoveryPolicy
} from "./patchforge/assetDiscovery.js";
import {
  buildAskPatchForgeResponse,
  buildSecurityActionCenterIndex,
  extractCustomerAssetDescription,
  matchCustomerEstate,
  searchSecurityActionCenterIndex,
  securityActionCenterDetail,
  summarizePatchComparison
} from "./patchforge/searchIndex.js";
import {
  appendVendorLensChatMessage,
  assessAndStoreConfigApplicability,
  buildVendorLensDashboard,
  compareAndStorePatchVersion,
  createVendorLensChatSession,
  getVendorLensChatSession,
  ingestVendorSecurityAdvisory,
  listCustomerNetworkAssets,
  listNetworkVendors,
  listVendorLensPatchComparisons,
  listVendorSecurityAdvisories,
  refreshVendorLensSource,
  upsertCustomerNetworkAsset,
  upsertNetworkVendor
} from "./patchforge/vendorLens.js";
import { runSraTool } from "./sra/securityResearchAgent.js";

const DEFAULT_PORT = Number(process.env.PORT || 8080);
const MAX_REQUEST_BODY_BYTES = Number(process.env.PATCHFORGE_MAX_REQUEST_BODY_BYTES || 2 * 1024 * 1024);
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
  ["check-point", "Check Point", "infrastructure_networking"],
  ["sophos", "Sophos", "infrastructure_networking"],
  ["sonicwall", "SonicWall", "infrastructure_networking"],
  ["watchguard", "WatchGuard", "infrastructure_networking"],
  ["aruba-hpe", "Aruba / HPE", "infrastructure_networking"],
  ["ubiquiti", "Ubiquiti", "infrastructure_networking"],
  ["mikrotik", "MikroTik", "infrastructure_networking"],
  ["barracuda", "Barracuda", "infrastructure_networking"],
  ["vmware-broadcom", "VMware / Broadcom", "virtualization_platform"],
  ["ivanti", "Ivanti", "identity_endpoint_cloud"],
  ["red-hat", "Red Hat", "enterprise_apps"],
  ["canonical", "Canonical", "enterprise_apps"],
  ["suse", "SUSE", "enterprise_apps"],
  ["atlassian", "Atlassian", "enterprise_apps"],
  ["servicenow", "ServiceNow", "enterprise_apps"],
  ["sap", "SAP", "enterprise_apps"],
  ["oracle", "Oracle", "enterprise_apps"],
  ["okta", "Okta", "identity_endpoint_cloud"],
  ["zscaler", "Zscaler", "identity_endpoint_cloud"],
  ["cloudflare", "Cloudflare", "identity_endpoint_cloud"],
  ["akamai", "Akamai", "identity_endpoint_cloud"],
  ["crowdstrike", "CrowdStrike", "identity_endpoint_cloud"],
  ["sentinelone", "SentinelOne", "identity_endpoint_cloud"],
  ["trend-micro", "Trend Micro", "identity_endpoint_cloud"],
  ["dell", "Dell", "infrastructure_networking"],
  ["hp-enterprise", "HPE", "infrastructure_networking"],
  ["lenovo", "Lenovo", "infrastructure_networking"],
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
  const vendorLensFetchImpl = options.vendorLensFetchImpl || globalThis.fetch;
  const openAiAgentFetchImpl = options.openAiAgentFetchImpl || globalThis.fetch;
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

      if (await handlePlatformRoutes({ req, res, url, storage, authConfig, sendJson })) {
        return;
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
        const principal = authorization.principal || {};
        const reviewer = principal.upn || principal.oid || (principal.auth_disabled ? body.reviewer : null) || "unknown";
        const result = await storage.reviewVulnerability(
          tenantContext.effective_tenant_id,
          decodeURIComponent(vulnerabilityReviewMatch[1]),
          withLineage({ ...body, reviewer }, tenantContext, authorization)
        );
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

      if (route === "GET /api/patchforge/action-center") {
        const vulnerabilities = await storage.list("vulnerabilities", tenantId);
        const intelligence = await Promise.all(
          vulnerabilities.slice(0, 12).map((item) => buildIntelligenceForTenant({
            storage,
            tenantId,
            vulnerabilityId: item.vulnerability_id
          }))
        );
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          findings: intelligence.filter(Boolean).sort(compareFindingPriority),
          boundary: {
            automated_governance_analysis: true,
            human_approval_required: true,
            no_exploit_code: true,
            no_patch_deployment: true,
            no_autonomous_approval: true
          }
        });
      }

      if (route === "GET /api/patchforge/security-action-center") {
        return sendJson(res, 200, await buildSecurityActionCenterIndex({ storage, tenantId }));
      }

      if (route === "GET /api/patchforge/vendors-exploits-register") {
        return sendJson(res, 200, await buildSecurityActionCenterIndex({ storage, tenantId }));
      }

      if (route === "GET /api/patchforge/security-action-center/search") {
        const index = await buildSecurityActionCenterIndex({ storage, tenantId });
        return sendJson(res, 200, searchSecurityActionCenterIndex(index, Object.fromEntries(url.searchParams.entries())));
      }

      if (route === "GET /api/patchforge/vendors-exploits-register/search") {
        const index = await buildSecurityActionCenterIndex({ storage, tenantId });
        return sendJson(res, 200, searchSecurityActionCenterIndex(index, Object.fromEntries(url.searchParams.entries())));
      }

      if (route === "GET /api/patchforge/security-action-center/vendors") {
        const index = await buildSecurityActionCenterIndex({ storage, tenantId });
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          vendors: index.vendors,
          groups: index.groups,
          boundary: index.boundary
        });
      }

      const securityActionCenterCveMatch = url.pathname.match(/^\/api\/patchforge\/security-action-center\/cves\/([^/]+)$/);
      if (req.method === "GET" && securityActionCenterCveMatch) {
        const detail = await securityActionCenterDetail({
          storage,
          tenantId,
          id: decodeURIComponent(securityActionCenterCveMatch[1])
        });
        return detail ? sendJson(res, 200, { tenant_context: baseTenantContext, ...detail }) : sendJson(res, 404, { error: "cve_or_advisory_not_found" });
      }

      const vendorsExploitsCveMatch = url.pathname.match(/^\/api\/patchforge\/vendors-exploits-register\/cves\/([^/]+)$/);
      if (req.method === "GET" && vendorsExploitsCveMatch) {
        const detail = await securityActionCenterDetail({
          storage,
          tenantId,
          id: decodeURIComponent(vendorsExploitsCveMatch[1])
        });
        return detail ? sendJson(res, 200, { tenant_context: baseTenantContext, ...detail }) : sendJson(res, 404, { error: "cve_or_advisory_not_found" });
      }

      if (route === "GET /api/patchforge/customer-estate/assets" || route === "GET /api/patchforge/customer-operational-assets/assets") {
        const [assets, services, assessments, comparisons] = await Promise.all([
          listCustomerNetworkAssets(storage, tenantId),
          storage.list("services", tenantId),
          storage.list("config_applicability_assessments", tenantId),
          listVendorLensPatchComparisons(storage, tenantId)
        ]);
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          assets,
          services,
          exposure_matches: assessments,
          patch_comparisons: comparisons,
          boundary: {
            advisory_only: true,
            human_review_required: true,
            final_approval_issued: false,
            no_patch_deployment: true,
            no_production_mutation: true
          }
        });
      }

      if (route === "POST /api/patchforge/customer-estate/assets/extract" || route === "POST /api/patchforge/customer-operational-assets/assets/extract") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          extracted_asset: extractCustomerAssetDescription(body.description || body.device_description || body.text || "", body),
          review_required: true,
          final_approval_issued: false
        });
      }

      if (route === "POST /api/patchforge/customer-estate/assets/upsert" || route === "POST /api/patchforge/customer-operational-assets/assets/upsert") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const asset = await upsertCustomerNetworkAsset(storage, tenantContext.effective_tenant_id, withLineage(body.asset || body, tenantContext, authorization));
        return sendJson(res, 201, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          asset,
          final_approval_issued: false
        });
      }

      if (route === "POST /api/patchforge/customer-estate/match" || route === "POST /api/patchforge/customer-operational-assets/match") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const match = await matchCustomerEstate({
          storage,
          tenantId: tenantContext.effective_tenant_id,
          body: withLineage(body, tenantContext, authorization),
          persist: body.persist !== false
        });
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          ...match
        });
      }

      if (route === "POST /api/patchforge/customer-estate/patch-compare" || route === "POST /api/patchforge/customer-operational-assets/patch-compare") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const comparison = await compareAndStorePatchVersion(storage, tenantContext.effective_tenant_id, withLineage({
          ...body,
          target_version: body.target_version || body.proposed_version || body.proposedVersion
        }, tenantContext, authorization));
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          comparison: summarizePatchComparison(comparison, body)
        });
      }

      if (route === "GET /api/patchforge/customers") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          customers: await storage.list("customers", tenantId)
        });
      }

      if (route === "POST /api/patchforge/customers") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const customer = {
          tenant_id: tenantContext.effective_tenant_id,
          id: body.id || body.customer_id || `customer-${Date.now()}`,
          name: body.name || body.customer_name || "Customer pending",
          tenant_key: body.tenant_key || body.id || body.customer_id || null,
          service_tier: body.service_tier || "standard",
          status: body.status || "active",
          created_at: body.created_at || new Date().toISOString(),
          updated_at: new Date().toISOString(),
          ...lineageFields(tenantContext, authorization)
        };
        await storage.append("customers", customer);
        await storage.audit(tenantContext.effective_tenant_id, "customer_upserted", { customer_id: customer.id });
        return sendJson(res, 201, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, customer });
      }

      const customerAssetsMatch = url.pathname.match(/^\/api\/patchforge\/customers\/([^/]+)\/assets$/);
      if (req.method === "GET" && customerAssetsMatch) {
        const customerId = decodeURIComponent(customerAssetsMatch[1]);
        const assets = (await storage.list("customer_assets", tenantId)).filter((asset) => String(asset.customer_id) === customerId);
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          customer_id: customerId,
          assets
        });
      }

      if (req.method === "POST" && customerAssetsMatch) {
        const customerId = decodeURIComponent(customerAssetsMatch[1]);
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const assets = body.csv
          ? importAssetsFromCsv({ tenantId: tenantContext.effective_tenant_id, customerId, estateId: body.estate_id, csv: body.csv, source: body.source || "csv_import" })
          : [{
              tenant_id: tenantContext.effective_tenant_id,
              id: body.id || body.asset_id || `asset-${Date.now()}`,
              customer_id: customerId,
              estate_id: body.estate_id || null,
              site: body.site || null,
              hostname: body.hostname || body.name || null,
              asset_type: body.asset_type || "server_or_device",
              vendor: body.vendor || body.vendor_id || null,
              product: body.product || body.product_family || null,
              version: body.version || body.software_version || null,
              firmware_version: body.firmware_version || null,
              software_packages: Array.isArray(body.software_packages) ? body.software_packages : [],
              cpe: body.cpe || null,
              internet_exposed: Boolean(body.internet_exposed),
              criticality: body.criticality || "unknown",
              source: body.source || "manual",
              source_confidence: body.source_confidence ?? 0.75,
              parser_confidence: body.parser_confidence ?? 0.75,
              tags: Array.isArray(body.tags) ? body.tags : [],
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString()
            }];
        for (const asset of assets) {
          await storage.append("customer_assets", { ...asset, ...lineageFields(tenantContext, authorization) });
        }
        return sendJson(res, 201, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          customer_id: customerId,
          assets,
          imported: assets.length
        });
      }

      if (route === "POST /api/patchforge/config/redact") {
        const body = await readJson(req);
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          redaction: redactConfigInput(body.config || body.text || body.raw || "")
        });
      }

      if (route === "POST /api/patchforge/config/parse") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const evidence = parseConfigEvidence({
          tenantId: tenantContext.effective_tenant_id,
          customerId: body.customer_id || null,
          assetId: body.asset_id || null,
          input: body.config || body.text || body.raw || "",
          sourceType: body.source_type || "paste",
          parser: body.parser || "auto"
        });
        await storage.append("config_evidence", { ...evidence, ...lineageFields(tenantContext, authorization) });
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          config_evidence: evidence
        });
      }

      if (route === "POST /api/patchforge/exposure/match") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const match = await matchCustomerEstate({
          storage,
          tenantId: tenantContext.effective_tenant_id,
          body: withLineage(body, tenantContext, authorization),
          persist: body.persist !== false
        });
        for (const item of match.matches || []) {
          await storage.append("exposure_matches", {
            tenant_id: tenantContext.effective_tenant_id,
            id: item.id || item.assessment_id || `exposure-${Date.now()}`,
            customer_id: body.customer_id || null,
            asset_id: item.asset_id || body.asset_id || null,
            cve_id: item.cve || body.cve_id || null,
            vendor_id: item.vendor_id || body.vendor_id || null,
            product_id: item.product_id || item.product_family || body.product_id || null,
            match_confidence: item.match_confidence || (item.applicability_posture === "applicable" ? 0.85 : 0.55),
            match_reason: item.decision_not_allowed_yet || item.urgency_posture || "source-bound deterministic match",
            affected_version: item.firmware_version || body.version || null,
            fixed_version: body.fixed_version || null,
            evidence_refs: item.evidence_required || [],
            unresolved_gaps: item.evidence_gaps || [],
            created_at: new Date().toISOString(),
            ...lineageFields(tenantContext, authorization)
          });
        }
        return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, ...match });
      }

      if (route === "POST /api/patchforge/priority/index") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const priority = buildPriorityIndex(body);
        await storage.append("patch_actions", {
          tenant_id: tenantContext.effective_tenant_id,
          id: priority.id,
          cve_id: priority.cve_id,
          asset_id: priority.asset_id,
          action_type: "priority_index",
          recommended_action: priority.posture,
          risk_reduction: priority.priority_score,
          operational_risk: body.operational_risk || "unknown",
          service_impact: body.service_impact || "pending review",
          rollback_risk: body.rollback_risk || "pending review",
          change_window_suitability: body.change_window_suitability || "pending review",
          ciso_approval_required: priority.posture === "Emergency action recommended" || priority.posture === "Exception review required",
          human_change_approval_required: true,
          no_autonomous_production_approval: true,
          evidence_refs: body.evidence_refs || [],
          ...lineageFields(tenantContext, authorization)
        });
        return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, priority });
      }

      if (route === "POST /api/patchforge/patch-compare") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const report = comparePatchActions(body);
        await storage.append("patch_compare_reports", {
          tenant_id: tenantContext.effective_tenant_id,
          ...report,
          ...lineageFields(tenantContext, authorization)
        });
        return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, patch_compare_report: report });
      }

      if (route === "POST /api/patchforge/ask") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const answer = await buildAskPatchForgeResponse({
          storage,
          tenantId: tenantContext.effective_tenant_id,
          body: withLineage(body, tenantContext, authorization)
        });
        return sendJson(res, 200, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          ...answer
        });
      }

      if (route === "GET /api/patchforge/agents/status") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          openai_agent: getOpenAiAgentStatus()
        });
      }

      const agentMatch = url.pathname.match(/^\/api\/patchforge\/agents\/([^/]+)$/);
      if (req.method === "POST" && agentMatch) {
        const agentKey = decodeURIComponent(agentMatch[1]);
        if (!Object.prototype.hasOwnProperty.call(OPENAI_AGENT_NAMES, agentKey)) {
          return sendJson(res, 404, {
            error: "unknown_agent_type",
            allowed_agents: Object.keys(OPENAI_AGENT_NAMES)
          });
        }
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const result = await runOpenAiAgent({
          agentName: OPENAI_AGENT_NAMES[agentKey],
          prompt: body.question || body.prompt || body.message || "",
          evidence: {
            ...body.evidence,
            deterministic_answer: body.deterministic_answer || null,
            reviewed_exposure_evidence: Boolean(body.reviewed_exposure_evidence),
            reviewed_applicability_evidence: Boolean(body.reviewed_applicability_evidence),
            reviewed_customer_assurance_evidence: Boolean(body.reviewed_customer_assurance_evidence)
          },
          tenantId: tenantContext.effective_tenant_id,
          fetchImpl: openAiAgentFetchImpl
        });
        await storage.append("agent_guidance_snapshots", {
          tenant_id: tenantContext.effective_tenant_id,
          ...result,
          ...lineageFields(tenantContext, authorization)
        });
        return sendJson(res, result.status === "verified" ? 200 : 202, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          agent_guidance: result
        });
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

      if (route === "GET /api/patchforge/sources/adapters") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          adapters: listSourceAdapters(),
          boundary: {
            source_bound: true,
            fixture_backed_when_needed: true,
            no_exploit_payloads: true,
            review_required: true
          }
        });
      }

      if (route === "POST /api/patchforge/sources/sync") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        try {
          const result = await syncSourceAdapter({
            storage,
            tenantId: tenantContext.effective_tenant_id,
            body: withLineage(body, tenantContext, authorization)
          });
          return sendJson(res, 202, {
            tenant_id: tenantContext.effective_tenant_id,
            tenant_context: tenantContext,
            ...result
          });
        } catch (error) {
          return sendJson(res, error.code === "unsupported_source_adapter" ? 400 : 502, {
            error: error.code || "source_adapter_sync_failed",
            message: error.message,
            allowed_adapters: error.allowedAdapters || listSourceAdapters().map((adapterInfo) => adapterInfo.adapter_id)
          });
        }
      }

      if (route === "GET /api/patchforge/vendorlens/dashboard") {
        return sendJson(res, 200, {
          tenant_context: baseTenantContext,
          dashboard: await buildVendorLensDashboard(storage, tenantId)
        });
      }

      if (route === "GET /api/patchforge/vendorlens/vendors") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          vendors: await listNetworkVendors(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/vendorlens/vendors/upsert") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const vendor = await upsertNetworkVendor(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 200, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, vendor });
      }

      if (route === "GET /api/patchforge/vendorlens/assets") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          assets: await listCustomerNetworkAssets(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/vendorlens/assets") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const asset = await upsertCustomerNetworkAsset(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 201, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, asset });
      }

      if (route === "GET /api/patchforge/vendorlens/advisories") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          advisories: await listVendorSecurityAdvisories(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/vendorlens/advisories/ingest") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const advisory = await ingestVendorSecurityAdvisory(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 201, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, advisory });
      }

      if (route === "POST /api/patchforge/vendorlens/sources/refresh") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const run = await refreshVendorLensSource({
          storage,
          tenantId: tenantRequest.tenantId,
          body: tenantRequest.withLineage(),
          fetchImpl: vendorLensFetchImpl
        });
        return sendJson(res, 202, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          source_feed_run: run
        });
      }

      if (route === "POST /api/patchforge/vendorlens/applicability/assess") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const assessment = await assessAndStoreConfigApplicability(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 200, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          assessment
        });
      }

      if (route === "GET /api/patchforge/vendorlens/patch-comparisons") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          comparisons: await listVendorLensPatchComparisons(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/vendorlens/patch-compare") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const comparison = await compareAndStorePatchVersion(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 200, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          comparison
        });
      }

      if (route === "POST /api/patchforge/vendorlens/chat") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const chat = await createVendorLensChatSession(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 201, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          ...chat
        });
      }

      const vendorLensChatMatch = url.pathname.match(/^\/api\/patchforge\/vendorlens\/chat\/([^/]+)$/);
      if (req.method === "GET" && vendorLensChatMatch) {
        const chat = await getVendorLensChatSession(storage, tenantId, decodeURIComponent(vendorLensChatMatch[1]));
        return chat ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, ...chat }) : sendJson(res, 404, { error: "vendorlens_chat_not_found" });
      }

      if (req.method === "POST" && vendorLensChatMatch) {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const chat = await appendVendorLensChatMessage(storage, tenantRequest.tenantId, decodeURIComponent(vendorLensChatMatch[1]), tenantRequest.withLineage());
        return chat ? sendJson(res, 200, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, ...chat }) : sendJson(res, 404, { error: "vendorlens_chat_not_found" });
      }

      if (route === "GET /api/patchforge/reports-packs" || route === "GET /api/patchforge/reports/overview") {
        const decisionPacks = await storage.list("decision_packs", tenantId);
        const latestPack = decisionPacks.slice(-1)[0] || null;
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          reports: REPORT_CATALOG,
          decision_packs: decisionPacks,
          export_options: [
            "Customer Patch Governance Pack",
            "Board Vulnerability Summary",
            "CAB Patch Decision Report",
            "Technical Evidence Appendix",
            "Signed Decision Pack ZIP",
            "Verification"
          ],
          pre_export_state: latestPack ? reportPreExportState(latestPack) : null,
          boundary: {
            advisory_only: true,
            final_approval_issued: Boolean(latestPack?.final_approval_issued),
            no_patch_deployment: true,
            no_autonomous_cab_approval: true,
            human_review_required: true
          }
        });
      }

      if (route === "POST /api/patchforge/reports-packs/generate" || route === "POST /api/patchforge/reports/generate") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const result = await generateDecisionPackForRequest({ storage, runtimeClient, tenantContext, authorization, body });
        return sendJson(res, result.statusCode, result.payload);
      }

      if (route === "GET /api/patchforge/decision-packs") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          decision_packs: await storage.list("decision_packs", tenantId)
        });
      }

      if (route === "GET /api/patchforge/reports/catalog") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          reports: REPORT_CATALOG
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

      const decisionPackReportMatch = url.pathname.match(/^\/api\/patchforge\/decision-packs\/([^/]+)\/reports\/([^/.]+)\.(docx|pdf)$/);
      if (req.method === "GET" && decisionPackReportMatch) {
        const packId = decodeURIComponent(decisionPackReportMatch[1]);
        const reportType = decodeURIComponent(decisionPackReportMatch[2]);
        const format = decisionPackReportMatch[3];
        const packs = await storage.list("decision_packs", tenantId);
        const pack = packs.find((record) => record.pack_id === packId || record.decision_pack_id === packId);
        if (!pack) {
          return sendJson(res, 404, { error: "decision_pack_not_found" });
        }
        try {
          const vulnerability = await storage.getVulnerability(tenantId, pack.vulnerability_id);
          const sourceFeedRuns = await storage.list("source_feed_runs", tenantId);
          const intelligence = vulnerability ? await buildIntelligenceForTenant({
            storage,
            tenantId,
            vulnerabilityId: vulnerability.vulnerability_id,
            bayesianSnapshot: pack.artefacts?.["bayesian_patch_risk_snapshot.json"] || null
          }) : null;
          const report = await generateDecisionPackReport({
            reportType,
            format,
            pack,
            vulnerability,
            intelligence,
            sourceFeedRuns: sourceFeedRuns.slice(-10).reverse()
          });
          return sendBinary(res, 200, report.buffer, {
            contentType: report.contentType,
            fileName: report.fileName
          });
        } catch (error) {
          return sendJson(res, error.code === "unknown_report_type" ? 400 : 500, {
            error: error.code || "report_generation_failed",
            message: error.message,
            allowed_reports: REPORT_CATALOG.map((item) => item.report_type)
          });
        }
      }

      if (route === "POST /api/patchforge/decision-packs/generate") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const result = await generateDecisionPackForRequest({ storage, runtimeClient, tenantContext, authorization, body });
        return sendJson(res, result.statusCode, result.payload);
      }

      if (route === "POST /api/patchforge/action-packs") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const pack = buildSignedActionPack(body);
        await storage.append("signed_action_packs", {
          tenant_id: tenantContext.effective_tenant_id,
          ...pack,
          ...lineageFields(tenantContext, authorization)
        });
        return sendJson(res, 201, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          signed_action_pack: pack
        });
      }

      const actionPackVerifyMatch = url.pathname.match(/^\/api\/patchforge\/action-packs\/([^/]+)\/verify$/);
      if (req.method === "GET" && actionPackVerifyMatch) {
        const packId = decodeURIComponent(actionPackVerifyMatch[1]);
        const packs = await storage.list("signed_action_packs", tenantId);
        const pack = packs.find((item) => item.id === packId || item.pack_id === packId);
        return pack
          ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, verifier_result: verifySignedActionPack(pack), signed_action_pack: pack })
          : sendJson(res, 404, { error: "signed_action_pack_not_found" });
      }

      if (route === "GET /api/patchforge/workflow/items") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          workflow_items: await storage.list("workflow_items", tenantId)
        });
      }

      if (route === "POST /api/patchforge/workflow/items") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const item = createWorkflowItem({
          ...withLineage(body, tenantContext, authorization),
          tenant_id: tenantContext.effective_tenant_id
        });
        await storage.append("workflow_items", item);
        await storage.audit(tenantContext.effective_tenant_id, "workflow_item_created", { id: item.id, status: item.status });
        return sendJson(res, 201, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, workflow_item: item });
      }

      const workflowTransitionMatch = url.pathname.match(/^\/api\/patchforge\/workflow\/items\/([^/]+)\/transition$/);
      if (req.method === "POST" && workflowTransitionMatch) {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const itemId = decodeURIComponent(workflowTransitionMatch[1]);
        const existing = (await storage.list("workflow_items", tenantContext.effective_tenant_id)).find((item) => item.id === itemId);
        if (!existing) {
          return sendJson(res, 404, { error: "workflow_item_not_found" });
        }
        const item = transitionWorkflowItem(existing, withLineage(body, tenantContext, authorization));
        await storage.append("workflow_items", item);
        await storage.audit(tenantContext.effective_tenant_id, "workflow_item_transitioned", { id: item.id, status: item.status });
        return sendJson(res, 200, { tenant_id: tenantContext.effective_tenant_id, tenant_context: tenantContext, workflow_item: item });
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

      if (route === "GET /api/patchforge/admin/purge") {
        const scopes = (url.searchParams.get("scopes") || "")
          .split(",")
          .map((scope) => scope.trim())
          .filter(Boolean);
        const plan = await storage.purgePatchForgeData(tenantId, {
          scopes,
          all: url.searchParams.get("all") === "true",
          reports: url.searchParams.get("reports") === "true",
          catalogue: url.searchParams.get("catalogue") === "true",
          assets: url.searchParams.get("assets") === "true",
          uploads: url.searchParams.get("uploads") === "true",
          logs: url.searchParams.get("logs") === "true",
          cache: url.searchParams.get("cache") === "true",
          dry_run: true
        });
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          purge: plan
        });
      }

      if (route === "POST /api/patchforge/admin/purge") {
        const body = await readJson(req);
        const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
        const purge = await storage.purgePatchForgeData(tenantContext.effective_tenant_id, {
          ...body,
          dry_run: body.dry_run !== false,
          confirm: body.confirm
        });
        if (purge.blocked || purge.error === "typed_confirmation_required") {
          return sendJson(res, 400, {
            tenant_id: tenantContext.effective_tenant_id,
            tenant_context: tenantContext,
            error: "typed_confirmation_required",
            message: `Type ${PATCHFORGE_PURGE_CONFIRMATION} to run a destructive PatchForge purge.`,
            purge
          });
        }
        return sendJson(res, purge.dry_run ? 200 : 202, {
          tenant_id: tenantContext.effective_tenant_id,
          tenant_context: tenantContext,
          purge
        });
      }

      if (route === "GET /api/patchforge/discovery/overview") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          discovery: await buildAssetDiscoveryOverview(storage, tenantId)
        });
      }

      if (route === "GET /api/patchforge/discovery/collectors") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          collectors: await listAssetCollectors(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/discovery/collectors") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const collector = await registerAssetCollector(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 201, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          collector
        });
      }

      if (route === "GET /api/patchforge/discovery/policies") {
        return sendJson(res, 200, {
          tenant_id: tenantId,
          tenant_context: baseTenantContext,
          policies: await listAssetDiscoveryPolicies(storage, tenantId)
        });
      }

      if (route === "POST /api/patchforge/discovery/policies") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const policy = await upsertAssetDiscoveryPolicy(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 201, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          policy
        });
      }

      if (route === "POST /api/patchforge/discovery/import") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const result = await importDiscoveredAssets(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 202, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          ...result
        });
      }

      if (route === "POST /api/patchforge/bayesian/assess") {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const assessment = buildBayesianAssessment(tenantRequest.withLineage());
        await storage.append("bayesian_assessments", {
          tenant_id: tenantRequest.tenantId,
          assessment_id: assessment.assessment_id,
          ...assessment,
          ...tenantRequest.lineageFields()
        });
        return sendJson(res, 200, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
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
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        if (tenantRequest.body.live_update === true) {
          return sendJson(res, 400, {
            error: "live_prior_update_locked",
            message: "PatchForge Bayesian prior updates are proposal-only unless explicitly approved in a later controlled release."
          });
        }
        return sendJson(res, 200, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          proposal: buildPriorUpdateProposal(tenantRequest.withLineage())
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
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const vendor = await upsertVendor(storage, tenantRequest.tenantId, tenantRequest.withLineage());
        return sendJson(res, 200, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, vendor });
      }

      const vendorDetailMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)$/);
      if (req.method === "GET" && vendorDetailMatch) {
        const vendor = await getVendorProfile(storage, tenantId, decodeURIComponent(vendorDetailMatch[1]));
        return vendor ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, vendor }) : sendJson(res, 404, { error: "vendor_not_found" });
      }

      const vendorAdvisoryMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)\/advisories\/ingest$/);
      if (req.method === "POST" && vendorAdvisoryMatch) {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const advisory = await ingestVendorAdvisory(storage, tenantRequest.tenantId, decodeURIComponent(vendorAdvisoryMatch[1]), tenantRequest.withLineage());
        return sendJson(res, 201, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, advisory });
      }

      const vendorLandscapeMatch = url.pathname.match(/^\/api\/patchforge\/vendors\/([^/]+)\/threat-landscape$/);
      if (req.method === "GET" && vendorLandscapeMatch) {
        return sendJson(res, 200, await buildVendorThreatLandscape(storage, tenantId, decodeURIComponent(vendorLandscapeMatch[1]), baseTenantContext));
      }

      if (route === "GET /api/patchforge/threat-landscape/summary") {
        return sendJson(res, 200, await buildThreatLandscapeSummary(storage, tenantId, baseTenantContext));
      }

      const intelligenceMatch = url.pathname.match(/^\/api\/patchforge\/vulnerabilities\/([^/]+)\/intelligence$/);
      if (req.method === "GET" && intelligenceMatch) {
        const intelligence = await buildIntelligenceForTenant({
          storage,
          tenantId,
          vulnerabilityId: decodeURIComponent(intelligenceMatch[1])
        });
        return intelligence ? sendJson(res, 200, { tenant_id: tenantId, tenant_context: baseTenantContext, intelligence }) : sendJson(res, 404, { error: "vulnerability_not_found" });
      }

      const analyseMatch = url.pathname.match(/^\/api\/patchforge\/vulnerabilities\/([^/]+)\/analyse$/);
      if (req.method === "POST" && analyseMatch) {
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        const vulnerabilityIdForAnalysis = decodeURIComponent(analyseMatch[1]);
        const bayesianSnapshot = buildBayesianAssessment({ vulnerability: await storage.getVulnerability(tenantRequest.tenantId, vulnerabilityIdForAnalysis) || {}, ...tenantRequest.body });
        const intelligence = await buildIntelligenceForTenant({
          storage,
          tenantId: tenantRequest.tenantId,
          vulnerabilityId: vulnerabilityIdForAnalysis,
          bayesianSnapshot
        });
        if (!intelligence) {
          return sendJson(res, 404, { error: "vulnerability_not_found" });
        }
        await storage.audit(tenantRequest.tenantId, "finding_intelligence_generated", {
          vulnerability_id: vulnerabilityIdForAnalysis,
          intelligence_id: intelligence.intelligence_id,
          recommendation: intelligence.recommendation?.posture,
          ...tenantRequest.lineageFields()
        });
        return sendJson(res, 200, {
          tenant_id: tenantRequest.tenantId,
          tenant_context: tenantRequest.tenantContext,
          intelligence,
          bayesian: bayesianSnapshot,
          boundary: intelligence.boundary
        });
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
        const tenantRequest = await readTenantJson(req, url, authConfig, authorization);
        try {
          const result = runSraTool(sraRoutes[route], tenantRequest.withLineage({ ...tenantRequest.body, tenant_id: tenantRequest.tenantId }));
          return sendJson(res, 200, { tenant_id: tenantRequest.tenantId, tenant_context: tenantRequest.tenantContext, sra: result });
        } catch (error) {
          return sendJson(res, 400, { error: "sra_boundary_violation", message: error.message });
        }
      }

      return sendJson(res, 404, {
        error: "not_found",
        boundary: "No scanner, exploit, patch deployment, or production mutation endpoint exists."
      });
    } catch (error) {
      if (error && error.statusCode) {
        return sendJson(res, error.statusCode, {
          error: error.publicError || "request_error",
          message: error.publicMessage || "The request could not be processed."
        });
      }
      console.error("patchforge_internal_error", error);
      return sendJson(res, 500, {
        error: "internal_error",
        message: "An internal error occurred while processing the request."
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

async function readTenantJson(req, url, authConfig, authorization) {
  const body = await readJson(req);
  const tenantContext = resolveTenantContext(req, url, body, authConfig, authorization.principal);
  return {
    body,
    tenantContext,
    tenantId: tenantContext.effective_tenant_id,
    withLineage: (payload = body) => withLineage(payload, tenantContext, authorization),
    lineageFields: () => lineageFields(tenantContext, authorization)
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

export function bindApprovalEventsToPrincipal(events, authorization) {
  const principal = authorization?.principal || {};
  const roles = Array.isArray(principal.roles) ? principal.roles.map(String) : [];
  const actorId = principal.oid || principal.upn || null;
  const canIssueFinalApproval = Boolean(actorId)
    && roles.some((role) => ["PatchForge.CABApprover", "PatchForge.Admin"].includes(role));

  return (Array.isArray(events) ? events : []).map((event) => {
    const finalApprovalRequest = event?.approval_type === "final" && event?.approval_state === "approved";
    const serverVerified = finalApprovalRequest && canIssueFinalApproval;
    return {
      ...event,
      approver: serverVerified ? (principal.upn || principal.oid) : String(event?.approver || "unverified-client-claim"),
      approver_oid: serverVerified ? principal.oid || null : null,
      actor_roles: serverVerified ? roles : [],
      server_verified: serverVerified
    };
  });
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
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      const error = new Error(`Request body exceeds the ${MAX_REQUEST_BODY_BYTES}-byte limit.`);
      error.statusCode = 413;
      error.publicError = "request_body_too_large";
      error.publicMessage = error.message;
      throw error;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) {
    return {};
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Request body is not valid JSON.");
    error.statusCode = 400;
    error.publicError = "invalid_json";
    error.publicMessage = error.message;
    throw error;
  }
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(`${body}\n`);
}

function sendBinary(res, statusCode, buffer, { contentType, fileName }) {
  res.writeHead(statusCode, {
    "content-type": contentType,
    "content-length": buffer.length,
    "content-disposition": `attachment; filename="${fileName}"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  res.end(buffer);
}

export function buildEvidenceItemsFromRecord(vulnerability) {
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

  // Evidence state and class must be compiled from persisted tenant records.
  // Client-supplied evidence items are not trusted as hard-gate inputs.
  return sourceEvidence;
}

async function generateDecisionPackForRequest({ storage, runtimeClient, tenantContext, authorization, body }) {
  const resolvedTenant = tenantContext.effective_tenant_id;
  const vulnerabilityId = body.vulnerability_id || body.cve_id || body.cve;
  if (!vulnerabilityId) {
    return {
      statusCode: 400,
      payload: {
        error: "vulnerability_id_required",
        message: "A real ingested vulnerability_id or CVE is required before a signed report pack can be generated."
      }
    };
  }

  const vulnerability = await storage.getVulnerability(resolvedTenant, vulnerabilityId);
  if (!vulnerability) {
    return {
      statusCode: 404,
      payload: {
        error: "vulnerability_not_found",
        message: "Reports and packs can only be generated from tenant records already ingested into PatchForge."
      }
    };
  }

  const findingIntelligence = buildFindingIntelligence({
    vulnerability,
    vendorAdvisories: await storage.list("vendor_advisories", resolvedTenant),
    threatSignals: await storage.list("threat_signals", resolvedTenant),
    assets: await storage.list("assets", resolvedTenant),
    services: await storage.list("services", resolvedTenant),
    decisionPacks: await storage.list("decision_packs", resolvedTenant),
    sourceFeedRuns: await storage.list("source_feed_runs", resolvedTenant),
    reviews: await storage.list("reviews", resolvedTenant),
    bayesianSnapshot: body.bayesian_snapshot || buildBayesianAssessment({ vulnerability })
  });
  const vendorLensContext = await buildVendorLensPackContext(storage, resolvedTenant, body, vulnerability);

  const runtimeResult = await runtimeClient.createDecisionPack({
    tenant_id: resolvedTenant,
    vulnerability,
    evidence_items: buildEvidenceItemsFromRecord(vulnerability),
    model_name: body.model_name || "vuln_patch_governance",
    requested_posture: body.requested_posture || body.decision_posture || null,
    patch_availability: body.patch_availability || null,
    patch_feasibility: body.patch_feasibility || null,
    bayesian_snapshot: body.bayesian_snapshot || buildBayesianAssessment({ vulnerability }),
    patch_prior_usage_manifest: buildPriorUsageManifest(),
    patch_prior_update_proposal: body.patch_prior_update_proposal || null,
    vendor_intelligence_snapshot: body.vendor_intelligence_snapshot || null,
    threat_landscape_snapshot: body.threat_landscape_snapshot || await buildThreatLandscapeSummary(storage, resolvedTenant),
    finding_intelligence_snapshot: findingIntelligence,
    sra_trace: body.sra_trace || null,
    network_vendor_profile_snapshot: vendorLensContext.network_vendor_profile_snapshot,
    customer_network_asset_snapshot: vendorLensContext.customer_network_asset_snapshot,
    vendor_security_advisory_snapshot: vendorLensContext.vendor_security_advisory_snapshot,
    config_applicability_assessment: vendorLensContext.config_applicability_assessment,
    vendorlens_patch_comparison: vendorLensContext.vendorlens_patch_comparison,
    sra_config_chat_session: vendorLensContext.sra_config_chat_session,
    vendorlens_decision_context: vendorLensContext.vendorlens_decision_context,
    controls: body.controls || null,
    risk_acceptance: body.risk_acceptance || null,
    approval_events: bindApprovalEventsToPrincipal(body.approval_events, authorization)
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
    report_template_version: process.env.PATCHFORGE_REPORT_TEMPLATE_VERSION || REPORT_TEMPLATE_VERSION,
    report_renderer_commit: process.env.PATCHFORGE_RENDERER_COMMIT || process.env.PATCHFORGE_COMMIT_SHA || process.env.GIT_COMMIT || DEFAULT_RENDERER_COMMIT,
    report_renderer_image_tag: process.env.PATCHFORGE_IMAGE_TAG || process.env.CONTAINER_IMAGE_TAG || DEFAULT_IMAGE_TAG,
    generated_from_pack_id: runtimeResult.pack_id,
    product_baseline: process.env.PATCHFORGE_PRODUCT_BASELINE || DEFAULT_PRODUCT_BASELINE,
    report_context_version: process.env.PATCHFORGE_REPORT_CONTEXT_VERSION || REPORT_CONTEXT_VERSION,
    ...lineageFields(tenantContext, authorization),
    created_at: runtimeResult.created_at || new Date().toISOString()
  };
  await storage.append("decision_packs", packRecord);
  await storage.audit(resolvedTenant, "decision_pack_generated", {
    pack_id: packRecord.pack_id,
    vulnerability_id: packRecord.vulnerability_id,
    decision_posture: packRecord.decision_posture
  });

  return {
    statusCode: 201,
    payload: {
      tenant_id: resolvedTenant,
      tenant_context: tenantContext,
      decision_pack: packRecord,
      pre_export_state: reportPreExportState(packRecord),
      report_quality_reviews: reportPreExportState(packRecord).report_quality_reviews,
      runtime: {
        verification: runtimeResult.verification || null,
        boundary: runtimeResult.boundary || null
      }
    }
  };
}

function reportPreExportState(pack = {}) {
  const artefacts = pack.artefacts || {};
  const governance = artefacts["governance_manifest.json"] || {};
  const hasVendorLens = Boolean(
    artefacts["network_vendor_profile_snapshot.json"]
    || artefacts["vendor_security_advisory_snapshot.json"]
    || artefacts["config_applicability_assessment.json"]
    || artefacts["vendorlens_patch_comparison.json"]
  );
  const hasCustomerContext = Boolean(
    artefacts["customer_network_asset_snapshot.json"]
    || artefacts["affected_asset_scope.json"]
    || artefacts["affected_service_scope.json"]
  );
  const evidenceState = pack.blockers?.length ? "evidence_gaps_open" : "evidence_review_required";
  const staleWarning = pack.created_at && Date.now() - Date.parse(pack.created_at) > 24 * 60 * 60 * 1000
    ? "Report source pack is older than 24 hours; refresh current-state evidence before relying on it."
    : "Report is generated from the selected signed pack state.";
  return {
    pack_id: pack.pack_id || pack.decision_pack_id,
    baseline: pack.product_baseline || governance.product_baseline || "PF-AZ11-CUSTOMER-DEMO-MATURITY",
    renderer_commit: pack.report_renderer_commit || governance.report_renderer_commit || "not recorded",
    image_tag: pack.report_renderer_image_tag || governance.report_renderer_image_tag || "not recorded",
    final_approval_state: pack.final_approval_issued ? "issued" : "not_issued",
    final_approval_issued: Boolean(pack.final_approval_issued),
    evidence_state: evidenceState,
    vendorlens_context_included: hasVendorLens,
    customer_context_included: hasCustomerContext,
    report_current_stale_warning: staleWarning,
    signing_provider: pack.signing_provider || "not recorded",
    verification_state: pack.verification?.verified ? "verified" : "pending_or_not_recorded",
    report_quality_reviews: REPORT_CATALOG.map((report) => buildReportContentReview({ reportType: report.report_type, pack }))
  };
}

function compareFindingPriority(a, b) {
  return priorityScore(b) - priorityScore(a);
}

function priorityScore(finding = {}) {
  const severity = String(finding.severity || "").toLowerCase();
  const posture = String(finding.recommendation?.posture || "").toLowerCase();
  const displayPosture = String(finding.recommendation?.display_posture || "").toLowerCase();
  return [
    severity === "critical" ? 40 : severity === "high" ? 25 : severity === "medium" ? 10 : 0,
    finding.exploitability?.known_exploited ? 35 : 0,
    finding.exposure?.internet_exposed ? 20 : 0,
    finding.exposure?.customer_facing ? 15 : 0,
    displayPosture === "urgent_scope_confirmation_required" ? 24 : posture === "emergency_change_required" ? 30 : posture === "patch_required" ? 18 : 0,
    finding.evidence?.gaps?.length ? 6 : 0
  ].reduce((total, value) => total + value, 0);
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
  const epss = clamp(firstFiniteNumber(
    body.epss,
    body.epss_score,
    body.epss_probability,
    vulnerability.epss,
    vulnerability.epss_score,
    vulnerability.epss_probability,
    0
  ), 0, 1);
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

function firstFiniteNumber(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === "") {
      continue;
    }
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      return numeric;
    }
  }
  return 0;
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

async function buildVendorLensPackContext(storage, tenantId, body = {}, vulnerability = {}) {
  const assessments = await storage.list("config_applicability_assessments", tenantId);
  const advisories = await listVendorSecurityAdvisories(storage, tenantId);
  const assets = await listCustomerNetworkAssets(storage, tenantId);
  const chats = await storage.list("vendorlens_chat_sessions", tenantId);
  const comparisons = await listVendorLensPatchComparisons(storage, tenantId);
  const requested = {
    vulnerabilityIds: contextIdList(vulnerability.vulnerability_id, vulnerability.canonical_id, body.vulnerability_id, body.cve_id, body.cve),
    advisoryId: contextId(body.advisory_id),
    assetId: contextId(body.asset_id)
  };
  const advisory = firstContextMatch([
    body.vendor_security_advisory_snapshot,
    body.advisory,
    findRecord(advisories, "advisory_id", requested.advisoryId),
    advisories.filter((record) => recordMatchesVulnerability(record, requested.vulnerabilityIds))
  ], (record) => recordMatchesVulnerability(record, requested.vulnerabilityIds) || (!requested.vulnerabilityIds.length && sameContextId(record.advisory_id, requested.advisoryId)));
  const resolvedAdvisoryId = contextId(advisory?.advisory_id);
  const assessment = firstContextMatch([
    body.config_applicability_assessment,
    findRecord(assessments, "assessment_id", body.config_applicability_assessment_id),
    assessments.filter((record) => sameContextId(record.advisory_id, resolvedAdvisoryId)),
    assessments.filter((record) => recordMatchesVulnerability(record, requested.vulnerabilityIds)),
    assessments.filter((record) => requested.assetId && sameContextId(record.asset_id, requested.assetId))
  ], (record) => vendorLensRecordMatches(record, requested, resolvedAdvisoryId));
  const comparison = firstContextMatch([
    body.vendorlens_patch_comparison,
    findRecord(comparisons, "comparison_id", body.comparison_id),
    comparisons.filter((record) => sameContextId(record.advisory_id, resolvedAdvisoryId || assessment?.advisory_id)),
    comparisons.filter((record) => recordMatchesVulnerability(record, requested.vulnerabilityIds)),
    comparisons.filter((record) => requested.assetId && sameContextId(record.asset_id, requested.assetId))
  ], (record) => vendorLensRecordMatches(record, requested, resolvedAdvisoryId || assessment?.advisory_id));
  const contextAssetId = contextId(assessment?.asset_id || comparison?.asset_id);
  const asset = contextAssetId
    ? firstContextMatch([
      body.customer_network_asset_snapshot,
      body.asset,
      findRecord(assets, "asset_id", contextAssetId)
    ], (record) => sameContextId(record.asset_id, contextAssetId))
    : null;
  const vendorId = advisory?.vendor_id || asset?.vendor_id || assessment?.vendor_id || comparison?.vendor_id;
  const vendors = await listNetworkVendors(storage, tenantId);
  const vendor = vendorId
    ? firstContextMatch([
      body.network_vendor_profile_snapshot,
      findRecord(vendors, "vendor_id", vendorId)
    ], (record) => sameContextId(record.vendor_id, vendorId))
    : null;
  const chat = firstContextMatch([
    body.sra_config_chat_session,
    body.vendorlens_chat_session,
    findRecord(chats, "session_id", body.session_id),
    findRecord(chats, "assessment_id", assessment?.assessment_id),
    chats.filter((record) => sameContextId(record.advisory_id, resolvedAdvisoryId || assessment?.advisory_id)),
    chats.filter((record) => contextAssetId && sameContextId(record.asset_id, contextAssetId))
  ], (record) => vendorLensChatMatches(record, requested, assessment, resolvedAdvisoryId, contextAssetId));

  const vendorLensDecisionContext = assessment ? {
    ...(body.vendorlens_decision_context || {}),
    context_id: `vendorlens-${assessment.assessment_id}`,
    source_bound: true,
    advisory_only: true,
    human_review_required: true,
    final_approval_issued: false,
    applicability_posture: assessment.applicability_posture,
    urgency_posture: assessment.urgency_posture,
    decision_not_allowed_yet: assessment.decision_not_allowed_yet,
    recommended_next_action: nextActionForVendorLens(assessment.urgency_posture),
    evidence_gaps: assessment.evidence_gaps || []
  } : null;

  return {
    network_vendor_profile_snapshot: vendor,
    customer_network_asset_snapshot: asset,
    vendor_security_advisory_snapshot: advisory,
    config_applicability_assessment: assessment,
    vendorlens_patch_comparison: comparison,
    sra_config_chat_session: chat,
    vendorlens_decision_context: vendorLensDecisionContext
  };
}

function findRecord(records, field, value) {
  if (!value) {
    return null;
  }
  return records.find((record) => String(record[field]) === String(value)) || null;
}

function firstContextMatch(candidates, predicate) {
  const seen = new Set();
  for (const candidate of candidates.flat().filter(Boolean)) {
    const key = [
      candidate.assessment_id,
      candidate.comparison_id,
      candidate.session_id,
      candidate.advisory_id,
      candidate.asset_id,
      candidate.cve,
      candidate.vendor_id
    ].filter(Boolean).join("|") || JSON.stringify(candidate).slice(0, 160);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (predicate(candidate)) {
      return candidate;
    }
  }
  return null;
}

function vendorLensRecordMatches(record, requested, advisoryId) {
  if (!record) {
    return false;
  }
  const hasRequestedVulnerability = requested.vulnerabilityIds.length > 0;
  const vulnerabilityMatch = hasRequestedVulnerability && recordMatchesVulnerability(record, requested.vulnerabilityIds);
  const advisoryMatch = Boolean(advisoryId && sameContextId(record.advisory_id, advisoryId));
  if (hasRequestedVulnerability && recordCveIds(record).length && !vulnerabilityMatch) {
    return false;
  }
  if (!vulnerabilityMatch && !advisoryMatch) {
    return false;
  }
  if (requested.assetId && record.asset_id && !sameContextId(record.asset_id, requested.assetId)) {
    return false;
  }
  return true;
}

function vendorLensChatMatches(record, requested, assessment, advisoryId, assetId) {
  if (!record) {
    return false;
  }
  if (assessment?.assessment_id && sameContextId(record.assessment_id, assessment.assessment_id)) {
    return true;
  }
  const advisoryMatch = advisoryId && sameContextId(record.advisory_id, advisoryId);
  const assetMatch = assetId && sameContextId(record.asset_id, assetId);
  if (requested.vulnerabilityIds.length && recordCveIds(record).length && !recordMatchesVulnerability(record, requested.vulnerabilityIds)) {
    return false;
  }
  return Boolean(advisoryMatch && (!assetId || assetMatch));
}

function recordMatchesVulnerability(record, vulnerabilityIds) {
  if (!record || !vulnerabilityIds.length) {
    return false;
  }
  const wanted = new Set(vulnerabilityIds.map(contextId).filter(Boolean));
  return recordCveIds(record).some((id) => wanted.has(contextId(id)))
    || Boolean(record.advisory_id && wanted.has(contextId(record.advisory_id)));
}

function recordCveIds(record) {
  return contextIdList(record?.vulnerability_id, record?.canonical_id, record?.cve_id, record?.cve, record?.cves);
}

function contextIdList(...values) {
  return [...new Set(values.flatMap((value) => Array.isArray(value) ? value : [value]).map(contextId).filter(Boolean))];
}

function contextId(value) {
  return value === undefined || value === null || value === "" ? "" : String(value).trim().toLowerCase();
}

function sameContextId(left, right) {
  return Boolean(contextId(left) && contextId(left) === contextId(right));
}

function nextActionForVendorLens(posture) {
  if (posture === "emergency_patch_required") {
    return "Confirm exposure, attach patch and rollback evidence, and request emergency CAB/security approval.";
  }
  if (posture === "patch_required") {
    return "Attach reviewed patch feasibility evidence and request accountable approval.";
  }
  if (posture === "mitigate_temporarily") {
    return "Attach compensating-control evidence and owner/expiry before requesting mitigation approval.";
  }
  return "Confirm vendor advisory source, customer asset, firmware, feature, and exposure evidence.";
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
  if (process.env.PATCHFORGE_COMPONENT === "scheduler") {
    startScheduler();
  }
}

import type { Page } from "@playwright/test";

const generatedAt = "2026-07-12T09:00:00Z";

const catalogueRow = {
  id: "FG-PFAZ10-SSLVPN",
  record_type: "vendor_advisory",
  vulnerability_id: "CVE-2026-E2E-001",
  cve_id: "CVE-2026-E2E-001",
  advisory_id: "FG-PFAZ10-SSLVPN",
  title: "FortiOS SSL-VPN source-bound advisory",
  vendor_id: "fortinet",
  vendor_name: "Fortinet",
  product_family: "FortiGate",
  affected_feature: "SSL-VPN",
  severity: "critical",
  cvss_score: 9.8,
  epss_score: 0.91,
  epss_percentile: 0.98,
  kev: true,
  patch_available: true,
  known_exploited: true,
  source_state: "source_bound",
  review_state: "pending_review",
  evidence_state: "referenced",
  customer_match_count: 1,
  customer_matches: [{ asset_id: "edge-fw-01" }],
  urgency_posture: "urgent_scope_confirmation_required",
  applicability_posture: "requires_review",
  final_approval_issued: false,
  last_refreshed: generatedAt
};

const payloads: Record<string, unknown> = {
  "/api/patchforge/dashboard/metrics": {
    tenant_id: "diiac.io",
    vulnerability_count: 1,
    critical_exposure: 1,
    known_exploited: 1,
    patch_overdue: 0,
    pending_review: 1,
    accepted_positive_evidence_sources: 0,
    rejected_sources: 0,
    signed_packs: 0
  },
  "/api/patchforge/security-action-center": {
    tenant_id: "diiac.io",
    generated_at: generatedAt,
    catalogue_rows: [catalogueRow],
    groups: [],
    vendors: [{ vendor_id: "fortinet", vendor_name: "Fortinet" }],
    filters: {
      vendors: [{ value: "Fortinet", count: 1 }],
      severities: [{ value: "critical", count: 1 }]
    },
    source_feed_status: [],
    summary: {
      total_records: 1,
      critical_records: 1,
      known_exploited_records: 1,
      kev_records: 1,
      patch_available_records: 1,
      customer_match_records: 1,
      final_approval_issued: 0
    },
    boundary: { advisory_only: true, final_approval_issued: false }
  },
  "/api/patchforge/customer-operational-assets/assets": {
    tenant_id: "diiac.io",
    generated_at: generatedAt,
    assets: [],
    services: [],
    exposure_matches: [],
    patch_comparisons: []
  },
  "/api/patchforge/reports/overview": {
    tenant_id: "diiac.io",
    generated_at: generatedAt,
    reports: [],
    decision_packs: [],
    export_options: [],
    pre_export_state: {
      evidence_state: "evidence_review_required",
      final_approval_issued: false
    },
    top_exposed_vendors: []
  },
  "/api/patchforge/vulnerabilities": { vulnerabilities: [] },
  "/api/patchforge/action-center": { findings: [] },
  "/api/patchforge/assets": { assets: [] },
  "/api/patchforge/services": { services: [] },
  "/api/patchforge/decision-packs": { decision_packs: [] },
  "/api/patchforge/reports/catalog": { reports: [] },
  "/api/patchforge/threat-landscape/summary": {
    tenant_id: "diiac.io",
    generated_at: generatedAt,
    vendors_tracked: 1,
    advisories_tracked: 1,
    known_exploited_count: 1
  },
  "/api/patchforge/vendors": {
    vendors: [{
      vendor_id: "fortinet",
      vendor_name: "Fortinet",
      category: "networking",
      review_state: "reference_catalogue"
    }]
  },
  "/api/patchforge/source-feeds": { feeds: [], recent_runs: [] },
  "/api/patchforge/vendorlens/dashboard": {
    dashboard: {
      vendors_tracked: 1,
      active_advisories: 1,
      known_exploited_vendor_cves: 1,
      customer_estate_matches: 0,
      config_unknown_count: 0,
      emergency_attention_required: 0,
      recent_assessments: []
    }
  },
  "/api/patchforge/vendorlens/vendors": {
    vendors: [{
      vendor_id: "fortinet",
      vendor_name: "Fortinet",
      vendor_category: "infrastructure_networking",
      advisory_source_type: "public_vendor_advisory",
      advisory_source_url: "https://www.fortiguard.com/psirt",
      product_families: ["FortiGate"],
      source_review_state: "reference_catalogue",
      enabled: true
    }]
  },
  "/api/patchforge/vendorlens/assets": { assets: [] },
  "/api/patchforge/vendorlens/advisories": { advisories: [] },
  "/api/patchforge/discovery/overview": {
    discovery: {
      tenant_id: "diiac.io",
      generated_at: generatedAt,
      categories: [],
      collectors: [],
      policies: [],
      recent_runs: [],
      metrics: {
        collector_count: 0,
        enabled_policy_count: 0,
        collector_imported_asset_count: 0,
        pending_review_asset_count: 0
      },
      boundary: {
        advisory_only: true,
        outbound_collector_only: true,
        no_vulnerability_scanning: true,
        no_patch_deployment: true,
        final_approval_issued: false
      }
    }
  },
  "/api/patchforge/agents/status": {
    openai_agent: {
      enabled: false,
      configured: false,
      provider: "openai",
      model: "gpt-4o-mini",
      timeout_ms: 15_000,
      max_output_tokens: 1_000,
      verifier_required: true,
      advisory_only: true,
      final_approval_issued: false,
      can_close_hard_gates: false,
      can_approve: false,
      can_patch: false,
      can_accept_risk: false
    }
  },
  "/api/patchforge/admin/health": {
    tenant_id: "diiac.io",
    live_azure_mutation_enabled: false,
    checks: [
      { name: "Signing trust", status: "ready", mode: "key-vault" }
    ]
  },
  "/api/patchforge/admin/config": {
    config: {
      general: { environment: "Local preview", governance_tier: "Enterprise Strict" }
    }
  }
};

export async function installMockPatchForgeApi(page: Page) {
  await page.addInitScript(() => {
    const browserWindow = window as Window & {
      PATCHFORGE_CONFIG?: Record<string, unknown>;
    };
    browserWindow.PATCHFORGE_CONFIG = {
      apiBaseUrl: window.location.origin,
      tenantId: "diiac.io",
      scope: "api://patchforge/access_as_user"
    };
  });

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const headers = {
      "access-control-allow-headers": "authorization, content-type, x-tenant-id",
      "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
      "access-control-allow-origin": "*"
    };

    if (request.method() === "OPTIONS") {
      await route.fulfill({ status: 204, headers });
      return;
    }

    const path = new URL(request.url()).pathname;
    const body = payloads[path];
    if (body === undefined) {
      await route.fulfill({
        status: 501,
        contentType: "application/json",
        headers,
        body: JSON.stringify({ error: `No E2E mock registered for ${path}` })
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers,
      body: JSON.stringify(body)
    });
  });
}

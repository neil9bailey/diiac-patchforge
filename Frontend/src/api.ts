export type PatchForgeRuntimeConfig = {
  tenantId: string;
  clientId: string;
  apiBaseUrl: string;
  apiScope: string;
  tenantHeader: string;
  environmentLabel: string;
};

export type PatchForgeMetrics = {
  tenant_id: string;
  vulnerability_count: number;
  critical_exposure: number;
  known_exploited: number;
  patch_overdue: number;
  pending_review: number;
  accepted_positive_evidence_sources: number;
  rejected_sources: number;
  signed_packs: number;
  source_feed_runs?: number;
  last_source_feed_run_at?: string | null;
};

export type BayesianAssessment = {
  advisory_only: boolean;
  can_close_hard_gates_alone: boolean;
  exploit_probability_posterior: number;
  business_impact_posterior: number;
  patch_feasibility_posterior: number;
  change_risk_posterior: number;
  deferral_risk_posterior: number;
  recommended_governance_posture: string;
};

export type ThreatLandscapeSummary = {
  tenant_id: string;
  source_bound: boolean;
  review_required: boolean;
  vendor_count: number;
  metrics: {
    active_exploitation_count: number;
    critical_open_advisory_count: number;
    patch_available_rate: number;
    known_exploited_rate: number;
    customer_estate_exposure: number;
    internet_exposed_asset_count: number;
    ot_relevance: number;
    patch_maturity: string;
    vendor_response_timeliness: string;
    superseded_advisory_count: number;
    false_positive_history: number;
    open_customer_decision_count: number;
  };
  top_exposed_vendors: Array<{ vendor_id: string; open_customer_decision_count: number; active_exploitation_count: number }>;
};

export type VendorProfile = {
  vendor_id: string;
  vendor_name: string;
  category: string;
  review_state?: string;
};

export type SourceFeed = {
  feed_id: string;
  feed_name: string;
  source_class: string;
  source_url: string;
  provider: string;
  authentication: string;
  source_bound: boolean;
  review_required: boolean;
  can_close_hard_gates_alone: boolean;
};

export type SourceFeedRun = {
  run_id: string;
  feed_id: string;
  feed_name: string;
  status: string;
  source_url?: string;
  records_seen?: number;
  records_matched?: number;
  records_ingested?: number;
  records_enriched?: number;
  message?: string;
  completed_at?: string;
  source_bound?: boolean;
  review_required?: boolean;
  can_close_hard_gates_alone?: boolean;
};

export type SourceFeedState = {
  feeds: SourceFeed[];
  recent_runs: SourceFeedRun[];
};

export type VulnerabilityRecord = {
  tenant_id?: string;
  vulnerability_id: string;
  canonical_id?: string;
  title?: string;
  description?: string;
  severity?: string;
  cvss_score?: number | null;
  known_exploited?: boolean;
  internet_exposed?: boolean;
  ot_relevant?: boolean;
  affected_service_ids?: string[];
  affected_asset_ids?: string[];
  patch_status?: string;
  sla_due_at?: string | null;
  source_state?: string;
  review_state?: string;
  source_record_ids?: string[];
  sources?: EvidenceSource[];
  usable_evidence_sources?: EvidenceSource[];
  tags?: string[];
  created_at?: string;
};

export type EvidenceSource = {
  tenant_id?: string;
  source_record_id: string;
  vulnerability_id?: string;
  source_class?: string;
  source_name?: string;
  source_url?: string | null;
  review_state?: string;
  evidence_state?: string;
};

export type AssetRecord = {
  asset_id: string;
  asset_name?: string;
  asset_class?: string;
  exposure?: string;
  criticality?: string;
  review_state?: string;
};

export type ServiceRecord = {
  service_id: string;
  service_name?: string;
  service_tier?: string;
  customer_facing?: boolean;
  owner?: string | null;
  affected_asset_ids?: string[];
  vulnerability_ids?: string[];
  review_state?: string;
};

export type DecisionPackRecord = {
  decision_pack_id: string;
  pack_id: string;
  vulnerability_id: string;
  decision_posture?: string;
  readiness?: {
    readiness_state?: string;
    readiness_score?: number;
    blockers?: string[];
    final_approval_issued?: boolean;
  };
  blockers?: string[];
  final_approval_issued?: boolean;
  source_pack_immutable?: boolean;
  verification?: { verified?: boolean };
  signing_provider?: string | null;
  created_at?: string;
};

export type AdminHealth = {
  tenant_id: string;
  live_azure_mutation_enabled: boolean;
  checks: Array<{ name: string; status: string; mode: string }>;
};

export type AdminConfig = Record<string, unknown>;

export type PatchForgeApi = {
  metrics(tenantId: string): Promise<PatchForgeMetrics>;
  listVulnerabilities(tenantId: string): Promise<VulnerabilityRecord[]>;
  ingestVulnerability(tenantId: string, payload: Record<string, unknown>): Promise<VulnerabilityRecord>;
  listAssets(tenantId: string): Promise<AssetRecord[]>;
  listServices(tenantId: string): Promise<ServiceRecord[]>;
  listDecisionPacks(tenantId: string): Promise<DecisionPackRecord[]>;
  generateDecisionPack(tenantId: string, payload: Record<string, unknown>): Promise<DecisionPackRecord>;
  exportDecisionPack(tenantId: string, packId: string): Promise<Record<string, unknown>>;
  assessBayesianRisk(tenantId: string, payload: Record<string, unknown>): Promise<BayesianAssessment>;
  bayesianPriors(tenantId: string): Promise<Record<string, unknown>>;
  threatLandscapeSummary(tenantId: string): Promise<ThreatLandscapeSummary>;
  listVendors(tenantId: string): Promise<VendorProfile[]>;
  sourceFeeds(tenantId: string): Promise<SourceFeedState>;
  refreshSourceFeed(tenantId: string, payload: Record<string, unknown>): Promise<SourceFeedRun>;
  sraResearch(tenantId: string, path: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
  adminHealth(tenantId: string): Promise<AdminHealth>;
  adminConfig(tenantId: string): Promise<AdminConfig>;
  saveAdminConfig(tenantId: string, payload: AdminConfig): Promise<AdminConfig>;
};

declare global {
  interface Window {
    PATCHFORGE_CONFIG?: Partial<PatchForgeRuntimeConfig>;
  }
}

const DEFAULT_CONFIG: PatchForgeRuntimeConfig = {
  tenantId: "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
  clientId: "c4dfca53-14a5-4688-817d-6c6c7dd47407",
  apiBaseUrl: "https://api.patchforge.diiac.io",
  apiScope: "api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736/PatchForge.Access",
  tenantHeader: "diiac.io",
  environmentLabel: "Production"
};

export function getPatchForgeConfig(): PatchForgeRuntimeConfig {
  const viteConfig = {
    tenantId: import.meta.env.VITE_PATCHFORGE_ENTRA_TENANT_ID,
    clientId: import.meta.env.VITE_PATCHFORGE_ENTRA_CLIENT_ID,
    apiBaseUrl: import.meta.env.VITE_PATCHFORGE_API_BASE_URL,
    apiScope: import.meta.env.VITE_PATCHFORGE_API_SCOPE || import.meta.env.VITE_PATCHFORGE_API_AUDIENCE,
    tenantHeader: import.meta.env.VITE_PATCHFORGE_TENANT_HEADER,
    environmentLabel: import.meta.env.VITE_PATCHFORGE_ENVIRONMENT_LABEL
  };
  return {
    ...DEFAULT_CONFIG,
    ...Object.fromEntries(Object.entries(viteConfig).filter(([, value]) => Boolean(value))),
    ...(typeof window !== "undefined" ? window.PATCHFORGE_CONFIG || {} : {})
  };
}

export function createPatchForgeApi(getAccessToken: () => Promise<string>, config = getPatchForgeConfig()): PatchForgeApi {
  async function request<T>(path: string, tenantId: string, init: RequestInit = {}): Promise<T> {
    const token = await getAccessToken();
    const response = await fetch(`${config.apiBaseUrl}${path}`, {
      ...init,
      headers: {
        "content-type": "application/json",
        "x-tenant-id": tenantId,
        authorization: `Bearer ${token}`,
        ...(init.headers || {})
      }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = body.message || body.error || `PatchForge API returned HTTP ${response.status}`;
      throw new Error(message);
    }
    return body as T;
  }

  return {
    async metrics(tenantId) {
      return request<PatchForgeMetrics>("/api/patchforge/dashboard/metrics", tenantId);
    },
    async listVulnerabilities(tenantId) {
      const body = await request<{ vulnerabilities: VulnerabilityRecord[] }>("/api/patchforge/vulnerabilities", tenantId);
      return body.vulnerabilities || [];
    },
    async ingestVulnerability(tenantId, payload) {
      const body = await request<{ vulnerability: VulnerabilityRecord }>("/api/patchforge/vulnerabilities/ingest", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.vulnerability;
    },
    async listAssets(tenantId) {
      const body = await request<{ assets: AssetRecord[] }>("/api/patchforge/assets", tenantId);
      return body.assets || [];
    },
    async listServices(tenantId) {
      const body = await request<{ services: ServiceRecord[] }>("/api/patchforge/services", tenantId);
      return body.services || [];
    },
    async listDecisionPacks(tenantId) {
      const body = await request<{ decision_packs: DecisionPackRecord[] }>("/api/patchforge/decision-packs", tenantId);
      return body.decision_packs || [];
    },
    async generateDecisionPack(tenantId, payload) {
      const body = await request<{ decision_pack: DecisionPackRecord }>("/api/patchforge/decision-packs/generate", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.decision_pack;
    },
    async exportDecisionPack(tenantId, packId) {
      return request<Record<string, unknown>>(`/api/patchforge/decision-packs/${encodeURIComponent(packId)}/export`, tenantId);
    },
    async assessBayesianRisk(tenantId, payload) {
      const body = await request<{ bayesian: BayesianAssessment }>("/api/patchforge/bayesian/assess", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.bayesian;
    },
    async bayesianPriors(tenantId) {
      return request<Record<string, unknown>>("/api/patchforge/bayesian/priors", tenantId);
    },
    async threatLandscapeSummary(tenantId) {
      return request<ThreatLandscapeSummary>("/api/patchforge/threat-landscape/summary", tenantId);
    },
    async listVendors(tenantId) {
      const body = await request<{ vendors: VendorProfile[] }>("/api/patchforge/vendors", tenantId);
      return body.vendors || [];
    },
    async sourceFeeds(tenantId) {
      const body = await request<SourceFeedState>("/api/patchforge/source-feeds", tenantId);
      return {
        feeds: body.feeds || [],
        recent_runs: body.recent_runs || []
      };
    },
    async refreshSourceFeed(tenantId, payload) {
      const body = await request<{ source_feed_run: SourceFeedRun }>("/api/patchforge/source-feeds/refresh", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.source_feed_run;
    },
    async sraResearch(tenantId, path, payload) {
      return request<Record<string, unknown>>(path, tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
    },
    async adminHealth(tenantId) {
      return request<AdminHealth>("/api/patchforge/admin/health", tenantId);
    },
    async adminConfig(tenantId) {
      const body = await request<{ config: AdminConfig }>("/api/patchforge/admin/config", tenantId);
      return body.config || {};
    },
    async saveAdminConfig(tenantId, payload) {
      const body = await request<{ config: AdminConfig }>("/api/patchforge/admin/config", tenantId, {
        method: "PUT",
        body: JSON.stringify(payload)
      });
      return body.config || {};
    }
  };
}

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
  return {
    ...DEFAULT_CONFIG,
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

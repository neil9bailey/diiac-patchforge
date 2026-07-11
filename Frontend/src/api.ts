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

export type NetworkVendorProfile = {
  vendor_id: string;
  vendor_name: string;
  vendor_category: string;
  advisory_source_type?: string;
  advisory_source_url?: string | null;
  product_families?: string[];
  source_review_state?: string;
  last_refresh_at?: string | null;
  enabled?: boolean;
};

export type CustomerNetworkAsset = {
  tenant_id?: string;
  asset_id: string;
  customer?: string | null;
  customer_name?: string | null;
  vendor_id: string;
  vendor_name?: string | null;
  product_family?: string | null;
  model?: string | null;
  firmware_version?: string | null;
  environment?: string;
  site?: string | null;
  service_owner?: string | null;
  internet_facing?: boolean;
  management_exposure?: string;
  enabled_features?: string[];
  disabled_features?: string[];
  config_evidence_refs?: string[];
  review_state?: string;
  evidence_state?: string;
  asset_category?: string;
  discovery_source?: string;
  discovery_method?: string | null;
  collector_id?: string | null;
  collector_policy_id?: string | null;
  collector_run_id?: string | null;
  collector_imported_at?: string | null;
  collector_confidence?: number | null;
  hostname?: string | null;
  ip_addresses?: string[];
  mac_addresses?: string[];
  cloud_resource_id?: string | null;
  virtualization_host?: string | null;
  review_required?: boolean;
  final_approval_issued?: boolean;
  updated_at?: string;
};

export type AssetCollectorRecord = {
  collector_id: string;
  name: string;
  platform: string;
  site?: string | null;
  environment?: string;
  enabled_categories: string[];
  connection_mode: string;
  status: string;
  last_seen_at?: string | null;
  advisory_only: boolean;
  review_required: boolean;
  no_vulnerability_scanning: boolean;
  no_patch_deployment: boolean;
  final_approval_issued: boolean;
};

export type AssetDiscoveryPolicy = {
  policy_id: string;
  collector_id?: string | null;
  name: string;
  enabled: boolean;
  categories: string[];
  discovery_methods: string[];
  schedule: string;
  credential_reference?: string | null;
  read_only: boolean;
  outbound_only: boolean;
  advisory_only: boolean;
  review_required: boolean;
  final_approval_issued: boolean;
};

export type AssetDiscoveryRun = {
  run_id: string;
  collector_id: string;
  policy_id?: string | null;
  status: string;
  completed_at?: string | null;
  received_asset_count: number;
  imported_asset_count: number;
  rejected_asset_count: number;
  categories: string[];
  discovery_method: string;
  final_approval_issued: boolean;
};

export type AssetDiscoveryOverview = {
  tenant_id: string;
  generated_at: string;
  categories: string[];
  collectors: AssetCollectorRecord[];
  policies: AssetDiscoveryPolicy[];
  recent_runs: AssetDiscoveryRun[];
  metrics: {
    collector_count: number;
    enabled_policy_count: number;
    collector_imported_asset_count: number;
    pending_review_asset_count: number;
    last_import_at?: string | null;
  };
  boundary: Record<string, boolean>;
};

export type VendorSecurityAdvisory = {
  advisory_id: string;
  vendor_id: string;
  vendor_name?: string;
  cve?: string | null;
  title?: string;
  severity?: string;
  product_family?: string | null;
  affected_products?: string[];
  affected_models?: string[];
  affected_versions?: string[];
  fixed_versions?: string[];
  affected_features?: string[];
  known_exploited?: boolean;
  patch_available?: boolean;
  source_url?: string | null;
  review_state?: string;
  evidence_state?: string;
};

export type ConfigApplicabilityAssessment = {
  assessment_id: string;
  advisory_id?: string | null;
  asset_id?: string | null;
  cve?: string | null;
  vendor_id?: string | null;
  product_family?: string | null;
  model?: string | null;
  firmware_version?: string | null;
  affected_feature?: string | null;
  affected_version_status: string;
  feature_enabled_status: string;
  exposure_status: string;
  applicability_posture: string;
  urgency_posture: string;
  evidence_required: string[];
  evidence_gaps: Array<{
    gap_id?: string;
    plain_english_gap?: string;
    why_it_matters?: string;
    required_evidence?: string;
    evidence_examples?: string[];
    suggested_owner_role?: string;
    next_decision_gate?: string;
    current_state?: string;
  }>;
  decision_not_allowed_yet?: string;
  human_review_required: boolean;
  final_approval_issued: boolean;
};

export type VendorLensPatchComparison = {
  comparison_id: string;
  generated_at?: string;
  vendor_id?: string | null;
  vendor_name?: string | null;
  asset_id?: string | null;
  advisory_id?: string | null;
  cve?: string | null;
  product_family?: string | null;
  model?: string | null;
  current_version?: string | null;
  target_version?: string | null;
  fixed_versions?: string[];
  affected_versions?: string[];
  affected_features?: string[];
  current_version_status: string;
  target_version_status: string;
  current_version_affected?: string;
  proposed_version?: string | null;
  proposed_version_remediates?: string;
  evidence_needed?: string[];
  recommended_posture?: string;
  required_human_review?: boolean;
  security_delta: string;
  operational_delta: string[];
  evidence_required: string[];
  ciso_summary: string;
  human_review_required: boolean;
  advisory_only: boolean;
  final_approval_issued: boolean;
};

export type VendorLensChatResponse = {
  short_answer: string;
  current_governed_posture: string;
  why: string;
  evidence_used: Array<Record<string, unknown>>;
  evidence_missing: Array<Record<string, unknown>>;
  configuration_assumptions: string[];
  recommended_next_action: string;
  decision_not_allowed_yet: string;
  human_review_required: boolean;
  final_approval_issued: boolean;
};

export type VendorLensChatSession = {
  session_id: string;
  title?: string;
  advisory_id?: string | null;
  asset_id?: string | null;
  assessment_id?: string | null;
  latest_response?: VendorLensChatResponse;
};

export type VendorLensDashboard = {
  vendors_tracked: number;
  active_advisories: number;
  known_exploited_vendor_cves: number;
  customer_estate_matches: number;
  config_unknown_count: number;
  emergency_attention_required: number;
  recent_assessments?: ConfigApplicabilityAssessment[];
};

export type VendorLensState = {
  dashboard: VendorLensDashboard | null;
  vendors: NetworkVendorProfile[];
  assets: CustomerNetworkAsset[];
  advisories: VendorSecurityAdvisory[];
  latestAssessment: ConfigApplicabilityAssessment | null;
  latestChat: VendorLensChatSession | null;
  latestComparison: VendorLensPatchComparison | null;
};

export type FindingIntelligence = {
  intelligence_id: string;
  generated_at: string;
  vulnerability_id: string;
  title: string;
  severity: string;
  vendor?: string;
  product?: string;
  summary: {
    plain_english: string;
    why_now: string;
    what_it_affects: string;
    operational_risk: string;
    decision_required: string;
    executive_readout: string;
  };
  exploitability: {
    known_exploited: boolean;
    epss_score: number | null;
    epss_percentile: number | null;
    ransomware_use: string;
    safe_description: string;
    kev_epss_interpretation?: string;
    prohibited_detail: string;
  };
  exposure: {
    affected_service_count: number;
    affected_asset_count: number;
    internet_exposed: boolean;
    customer_facing: boolean;
    ot_relevant: boolean;
    unmapped_scope: boolean;
    interpretation: string[];
    affected_services: Array<{ service_id: string; service_name: string; owner: string; customer_facing: boolean; service_tier: string }>;
    affected_assets: Array<{ asset_id: string; asset_name: string; asset_class: string; criticality: string; exposure: string }>;
  };
  recommendation: {
    posture: string;
    next_best_action: string;
    confidence: string;
    rationale: string[];
    do_now: string[];
    do_next: string[];
    due_date?: string | null;
    advisory_only: boolean;
    final_approval_issued: boolean;
    customer_posture?: string;
    customer_posture_detail?: string;
    display_posture?: string;
    approval_notice?: string;
  };
  decision_options: Array<{
    posture: string;
    current_status?: string;
    reason?: string;
    required_evidence?: string[];
    required_approval?: string;
    when_to_choose: string;
    benefits: string;
    risks: string;
    evidence_needed: string[];
    approval_needed: boolean;
    recommended?: boolean;
  }>;
  evidence: {
    accepted_positive_evidence_count: number;
    pending_review_count: number;
    rejected_source_count: number;
    gaps: string[];
    gap_details?: Array<{
      gap: string;
      plain_english_gap?: string;
      why_it_matters: string;
      required_evidence: string;
      evidence_examples?: string[];
      suggested_owner_role?: string;
      next_decision_gate?: string;
    }>;
    warning: string;
  };
  automation: {
    completed: string[];
    remaining_human_decisions: string[];
    available_actions: string[];
  };
  latest_signed_pack?: {
    pack_id: string;
    decision_posture: string;
    readiness_state: string;
    verified: boolean;
    final_approval_issued: boolean;
  } | null;
  boundary: Record<string, boolean>;
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

export type SecurityActionCenterRow = {
  id: string;
  record_type: string;
  vulnerability_id?: string | null;
  cve_id?: string | null;
  advisory_id?: string | null;
  title: string;
  vendor_id: string;
  vendor_name: string;
  product_family: string;
  model?: string | null;
  affected_feature?: string | null;
  affected_versions?: string[];
  fixed_versions?: string[];
  severity: string;
  cvss_score?: number | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  kev?: boolean;
  patch_available?: boolean;
  known_exploited?: boolean;
  source_state?: string;
  review_state?: string;
  evidence_state?: string;
  customer_match_count: number;
  customer_matches?: Array<Record<string, unknown>>;
  urgency_posture?: string;
  applicability_posture?: string;
  final_approval_issued?: boolean;
  last_refreshed?: string | null;
};

export type SecurityActionCenterGroup = {
  vendor_id: string;
  vendor_name: string;
  count: number;
  customer_match_count: number;
  known_exploited_count: number;
  highest_urgency: string;
  product_families: Array<{
    product_family: string;
    count: number;
    customer_match_count: number;
    items: SecurityActionCenterRow[];
  }>;
};

export type SecurityActionCenterState = {
  tenant_id: string;
  generated_at: string;
  catalogue_rows: SecurityActionCenterRow[];
  groups: SecurityActionCenterGroup[];
  vendors?: Array<Record<string, unknown>>;
  filters?: Record<string, Array<{ value: string; count: number }>>;
  source_feed_status?: SourceFeedRun[];
  summary?: Record<string, number>;
  boundary?: Record<string, boolean>;
};

export type CustomerEstateState = {
  assets: CustomerNetworkAsset[];
  services: ServiceRecord[];
  exposure_matches: ConfigApplicabilityAssessment[];
  patch_comparisons: VendorLensPatchComparison[];
};

export type CustomerAssetExtraction = CustomerNetworkAsset & {
  customer?: string | null;
  vendor_name?: string | null;
  extraction_confidence?: number;
  extracted_from?: string;
  final_approval_issued?: boolean;
  human_review_required?: boolean;
};

export type CustomerEstateMatch = {
  asset: CustomerNetworkAsset | null;
  matches: Array<ConfigApplicabilityAssessment & Record<string, unknown>>;
  match_count: number;
  highest_urgency?: string;
  final_approval_issued: boolean;
  human_review_required: boolean;
};

export type AskPatchForgeAnswer = {
  response: {
    short_answer: string;
    current_governed_posture: string;
    why: string;
    what_we_know: string[];
    what_we_do_not_know: string[];
    evidence_needed: string[];
    recommended_next_action: string;
    decision_not_allowed_yet: string;
    human_approval_required: boolean;
    final_approval_issued: boolean;
    advisory_only: boolean;
  };
  asset?: CustomerAssetExtraction;
  matched_assessment?: Record<string, unknown> | null;
  candidate_matches?: Array<Record<string, unknown>>;
  final_approval_issued: boolean;
};

export type OpenAiAgentStatus = {
  enabled: boolean;
  configured: boolean;
  provider: string;
  model: string;
  timeout_ms: number;
  max_output_tokens: number;
  verifier_required: boolean;
  advisory_only: boolean;
  final_approval_issued: boolean;
  can_close_hard_gates: boolean;
  can_approve: boolean;
  can_patch: boolean;
  can_accept_risk: boolean;
  key_configured?: boolean;
  key_value_exposed?: boolean;
  agent_names?: Record<string, string>;
};

export type AgentGuidanceSnapshot = {
  snapshot_id: string;
  agent_name: string;
  status: "disabled" | "verified" | "blocked";
  verifier_status: "not_run" | "passed" | "blocked";
  output?: {
    recommended_next_action?: string;
    decision_not_allowed_yet?: string;
    evidence_missing?: Array<Record<string, unknown>>;
    source_bound_warnings?: string[];
    final_approval_issued?: boolean;
  } | null;
  fallback?: {
    message?: string;
    recommended_next_action?: string;
    decision_not_allowed_yet?: string;
    final_approval_issued?: boolean;
  } | null;
  verification_failures?: Array<{ code?: string; message?: string }>;
  final_approval_issued: boolean;
  can_close_hard_gates: boolean;
};

export type ReportQualityReview = {
  review_id: string;
  report_type: string;
  pack_id?: string | null;
  status: "PASS" | "FAIL";
  checks: Array<{ name: string; status: "pass" | "fail" }>;
  final_approval_issued: boolean;
};

export type ReportsPacksState = {
  reports: ReportCatalogItem[];
  decision_packs: DecisionPackRecord[];
  export_options: string[];
  pre_export_state?: (Record<string, unknown> & { report_quality_reviews?: ReportQualityReview[] }) | null;
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
  product_baseline?: string;
  report_template_version?: string;
  report_renderer_commit?: string;
  report_renderer_image_tag?: string;
  report_context_version?: string;
  artefacts?: Record<string, unknown>;
  created_at?: string;
};

export type ReportCatalogItem = {
  report_type: string;
  title: string;
  audience: string;
  formats: string[];
};

export type AdminHealth = {
  tenant_id: string;
  live_azure_mutation_enabled: boolean;
  checks: Array<{ name: string; status: string; mode: string }>;
};

export type AdminPurgePlan = {
  dry_run: boolean;
  scopes: string[];
  collections: string[];
  counts: Record<string, number>;
  total_records: number;
  removed?: Record<string, number>;
  required_confirmation: string;
  blocked?: boolean;
  error?: string;
  boundary?: Record<string, unknown>;
};

export type AdminConfig = Record<string, unknown>;

export type PatchForgeApi = {
  metrics(tenantId: string): Promise<PatchForgeMetrics>;
  securityActionCenter(tenantId: string): Promise<SecurityActionCenterState>;
  searchSecurityActionCenter(tenantId: string, params?: Record<string, string | number | boolean | undefined>): Promise<SecurityActionCenterState>;
  securityActionCenterVendors(tenantId: string): Promise<Array<Record<string, unknown>>>;
  cveDetail(tenantId: string, id: string): Promise<Record<string, unknown>>;
  customerEstate(tenantId: string): Promise<CustomerEstateState>;
  extractCustomerAsset(tenantId: string, description: string): Promise<CustomerAssetExtraction>;
  upsertCustomerEstateAsset(tenantId: string, payload: Record<string, unknown>): Promise<CustomerNetworkAsset>;
  matchCustomerEstate(tenantId: string, payload: Record<string, unknown>): Promise<CustomerEstateMatch>;
  compareCustomerEstatePatch(tenantId: string, payload: Record<string, unknown>): Promise<VendorLensPatchComparison>;
  askPatchForge(tenantId: string, payload: Record<string, unknown>): Promise<AskPatchForgeAnswer>;
  openAiAgentStatus(tenantId: string): Promise<OpenAiAgentStatus>;
  askOpenAiAgent(tenantId: string, payload: Record<string, unknown>): Promise<AgentGuidanceSnapshot>;
  reportsPacks(tenantId: string): Promise<ReportsPacksState>;
  generateReportsPack(tenantId: string, payload: Record<string, unknown>): Promise<DecisionPackRecord>;
  listVulnerabilities(tenantId: string): Promise<VulnerabilityRecord[]>;
  ingestVulnerability(tenantId: string, payload: Record<string, unknown>): Promise<VulnerabilityRecord>;
  listAssets(tenantId: string): Promise<AssetRecord[]>;
  listServices(tenantId: string): Promise<ServiceRecord[]>;
  listDecisionPacks(tenantId: string): Promise<DecisionPackRecord[]>;
  generateDecisionPack(tenantId: string, payload: Record<string, unknown>): Promise<DecisionPackRecord>;
  exportDecisionPack(tenantId: string, packId: string): Promise<Record<string, unknown>>;
  reportCatalog(tenantId: string): Promise<ReportCatalogItem[]>;
  downloadDecisionPackReport(tenantId: string, packId: string, reportType: string, format: "docx" | "pdf"): Promise<Blob>;
  assessBayesianRisk(tenantId: string, payload: Record<string, unknown>): Promise<BayesianAssessment>;
  bayesianPriors(tenantId: string): Promise<Record<string, unknown>>;
  threatLandscapeSummary(tenantId: string): Promise<ThreatLandscapeSummary>;
  listVendors(tenantId: string): Promise<VendorProfile[]>;
  sourceFeeds(tenantId: string): Promise<SourceFeedState>;
  refreshSourceFeed(tenantId: string, payload: Record<string, unknown>): Promise<SourceFeedRun>;
  vendorLensDashboard(tenantId: string): Promise<VendorLensDashboard>;
  listNetworkVendors(tenantId: string): Promise<NetworkVendorProfile[]>;
  listCustomerNetworkAssets(tenantId: string): Promise<CustomerNetworkAsset[]>;
  upsertCustomerNetworkAsset(tenantId: string, payload: Record<string, unknown>): Promise<CustomerNetworkAsset>;
  assetDiscoveryOverview(tenantId: string): Promise<AssetDiscoveryOverview>;
  registerAssetCollector(tenantId: string, payload: Record<string, unknown>): Promise<AssetCollectorRecord>;
  upsertAssetDiscoveryPolicy(tenantId: string, payload: Record<string, unknown>): Promise<AssetDiscoveryPolicy>;
  importDiscoveredAssets(tenantId: string, payload: Record<string, unknown>): Promise<{ run: AssetDiscoveryRun; imported_assets: CustomerNetworkAsset[]; rejected_assets: Array<Record<string, unknown>>; boundary: Record<string, boolean> }>;
  listVendorSecurityAdvisories(tenantId: string): Promise<VendorSecurityAdvisory[]>;
  ingestVendorSecurityAdvisory(tenantId: string, payload: Record<string, unknown>): Promise<VendorSecurityAdvisory>;
  refreshVendorLensSource(tenantId: string, payload: Record<string, unknown>): Promise<SourceFeedRun>;
  assessConfigApplicability(tenantId: string, payload: Record<string, unknown>): Promise<ConfigApplicabilityAssessment>;
  compareVendorLensPatch(tenantId: string, payload: Record<string, unknown>): Promise<VendorLensPatchComparison>;
  startVendorLensChat(tenantId: string, payload: Record<string, unknown>): Promise<{ session: VendorLensChatSession; response: VendorLensChatResponse }>;
  sendVendorLensChatMessage(tenantId: string, sessionId: string, payload: Record<string, unknown>): Promise<{ session: VendorLensChatSession; response: VendorLensChatResponse }>;
  actionCenter(tenantId: string): Promise<FindingIntelligence[]>;
  findingIntelligence(tenantId: string, vulnerabilityId: string): Promise<FindingIntelligence>;
  analyseFinding(tenantId: string, vulnerabilityId: string, payload?: Record<string, unknown>): Promise<{ intelligence: FindingIntelligence; bayesian?: BayesianAssessment }>;
  sraResearch(tenantId: string, path: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
  adminHealth(tenantId: string): Promise<AdminHealth>;
  adminPurge(tenantId: string, payload: Record<string, unknown>): Promise<AdminPurgePlan>;
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
  const localPreviewConfig = import.meta.env.DEV
    && typeof window !== "undefined"
    && new URLSearchParams(window.location.search).get("preview") === "1"
    ? {
        apiBaseUrl: viteConfig.apiBaseUrl || "http://127.0.0.1:8080",
        tenantHeader: viteConfig.tenantHeader || "diiac.io",
        environmentLabel: viteConfig.environmentLabel || "Local preview"
      }
    : {};
  return {
    ...DEFAULT_CONFIG,
    ...Object.fromEntries(Object.entries(viteConfig).filter(([, value]) => Boolean(value))),
    ...(typeof window !== "undefined" ? window.PATCHFORGE_CONFIG || {} : {}),
    ...localPreviewConfig
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

  async function requestBlob(path: string, tenantId: string): Promise<Blob> {
    const token = await getAccessToken();
    const response = await fetch(`${config.apiBaseUrl}${path}`, {
      headers: {
        "x-tenant-id": tenantId,
        authorization: `Bearer ${token}`
      }
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const message = body.message || body.error || `PatchForge API returned HTTP ${response.status}`;
      throw new Error(message);
    }
    return response.blob();
  }

  return {
    async metrics(tenantId) {
      return request<PatchForgeMetrics>("/api/patchforge/dashboard/metrics", tenantId);
    },
    async securityActionCenter(tenantId) {
      return request<SecurityActionCenterState>("/api/patchforge/security-action-center", tenantId);
    },
    async searchSecurityActionCenter(tenantId, params = {}) {
      const query = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
          query.set(key, String(value));
        }
      });
      const suffix = query.toString() ? `?${query.toString()}` : "";
      return request<SecurityActionCenterState>(`/api/patchforge/security-action-center/search${suffix}`, tenantId);
    },
    async securityActionCenterVendors(tenantId) {
      const body = await request<{ vendors: Array<Record<string, unknown>> }>("/api/patchforge/security-action-center/vendors", tenantId);
      return body.vendors || [];
    },
    async cveDetail(tenantId, id) {
      return request<Record<string, unknown>>(`/api/patchforge/security-action-center/cves/${encodeURIComponent(id)}`, tenantId);
    },
    async customerEstate(tenantId) {
      return request<CustomerEstateState>("/api/patchforge/customer-operational-assets/assets", tenantId);
    },
    async extractCustomerAsset(tenantId, description) {
      const body = await request<{ extracted_asset: CustomerAssetExtraction }>("/api/patchforge/customer-operational-assets/assets/extract", tenantId, {
        method: "POST",
        body: JSON.stringify({ description })
      });
      return body.extracted_asset;
    },
    async upsertCustomerEstateAsset(tenantId, payload) {
      const body = await request<{ asset: CustomerNetworkAsset }>("/api/patchforge/customer-operational-assets/assets/upsert", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.asset;
    },
    async matchCustomerEstate(tenantId, payload) {
      return request<CustomerEstateMatch>("/api/patchforge/customer-operational-assets/match", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
    },
    async compareCustomerEstatePatch(tenantId, payload) {
      const body = await request<{ comparison: VendorLensPatchComparison }>("/api/patchforge/customer-operational-assets/patch-compare", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.comparison;
    },
    async askPatchForge(tenantId, payload) {
      return request<AskPatchForgeAnswer>("/api/patchforge/ask", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
    },
    async openAiAgentStatus(tenantId) {
      const body = await request<{ openai_agent: OpenAiAgentStatus }>("/api/patchforge/agents/status", tenantId);
      return body.openai_agent;
    },
    async askOpenAiAgent(tenantId, payload) {
      const body = await request<{ agent_guidance: AgentGuidanceSnapshot }>("/api/patchforge/agents/ask", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.agent_guidance;
    },
    async reportsPacks(tenantId) {
      return request<ReportsPacksState>("/api/patchforge/reports/overview", tenantId);
    },
    async generateReportsPack(tenantId, payload) {
      const body = await request<{ decision_pack: DecisionPackRecord }>("/api/patchforge/reports/generate", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.decision_pack;
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
    async reportCatalog(tenantId) {
      const body = await request<{ reports: ReportCatalogItem[] }>("/api/patchforge/reports/catalog", tenantId);
      return body.reports || [];
    },
    async downloadDecisionPackReport(tenantId, packId, reportType, format) {
      return requestBlob(`/api/patchforge/decision-packs/${encodeURIComponent(packId)}/reports/${encodeURIComponent(reportType)}.${format}`, tenantId);
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
    async vendorLensDashboard(tenantId) {
      const body = await request<{ dashboard: VendorLensDashboard }>("/api/patchforge/vendorlens/dashboard", tenantId);
      return body.dashboard;
    },
    async listNetworkVendors(tenantId) {
      const body = await request<{ vendors: NetworkVendorProfile[] }>("/api/patchforge/vendorlens/vendors", tenantId);
      return body.vendors || [];
    },
    async listCustomerNetworkAssets(tenantId) {
      const body = await request<{ assets: CustomerNetworkAsset[] }>("/api/patchforge/vendorlens/assets", tenantId);
      return body.assets || [];
    },
    async upsertCustomerNetworkAsset(tenantId, payload) {
      const body = await request<{ asset: CustomerNetworkAsset }>("/api/patchforge/vendorlens/assets", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.asset;
    },
    async assetDiscoveryOverview(tenantId) {
      const body = await request<{ discovery: AssetDiscoveryOverview }>("/api/patchforge/discovery/overview", tenantId);
      return body.discovery;
    },
    async registerAssetCollector(tenantId, payload) {
      const body = await request<{ collector: AssetCollectorRecord }>("/api/patchforge/discovery/collectors", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.collector;
    },
    async upsertAssetDiscoveryPolicy(tenantId, payload) {
      const body = await request<{ policy: AssetDiscoveryPolicy }>("/api/patchforge/discovery/policies", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.policy;
    },
    async importDiscoveredAssets(tenantId, payload) {
      return request<{ run: AssetDiscoveryRun; imported_assets: CustomerNetworkAsset[]; rejected_assets: Array<Record<string, unknown>>; boundary: Record<string, boolean> }>("/api/patchforge/discovery/import", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
    },
    async listVendorSecurityAdvisories(tenantId) {
      const body = await request<{ advisories: VendorSecurityAdvisory[] }>("/api/patchforge/vendorlens/advisories", tenantId);
      return body.advisories || [];
    },
    async ingestVendorSecurityAdvisory(tenantId, payload) {
      const body = await request<{ advisory: VendorSecurityAdvisory }>("/api/patchforge/vendorlens/advisories/ingest", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.advisory;
    },
    async refreshVendorLensSource(tenantId, payload) {
      const body = await request<{ source_feed_run: SourceFeedRun }>("/api/patchforge/vendorlens/sources/refresh", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.source_feed_run;
    },
    async assessConfigApplicability(tenantId, payload) {
      const body = await request<{ assessment: ConfigApplicabilityAssessment }>("/api/patchforge/vendorlens/applicability/assess", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.assessment;
    },
    async compareVendorLensPatch(tenantId, payload) {
      const body = await request<{ comparison: VendorLensPatchComparison }>("/api/patchforge/vendorlens/patch-compare", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.comparison;
    },
    async startVendorLensChat(tenantId, payload) {
      const body = await request<{ session: VendorLensChatSession; response: VendorLensChatResponse }>("/api/patchforge/vendorlens/chat", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return { session: body.session, response: body.response };
    },
    async sendVendorLensChatMessage(tenantId, sessionId, payload) {
      const body = await request<{ session: VendorLensChatSession; response: VendorLensChatResponse }>(`/api/patchforge/vendorlens/chat/${encodeURIComponent(sessionId)}`, tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return { session: body.session, response: body.response };
    },
    async actionCenter(tenantId) {
      const body = await request<{ findings: FindingIntelligence[] }>("/api/patchforge/action-center", tenantId);
      return body.findings || [];
    },
    async findingIntelligence(tenantId, vulnerabilityId) {
      const body = await request<{ intelligence: FindingIntelligence }>(`/api/patchforge/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/intelligence`, tenantId);
      return body.intelligence;
    },
    async analyseFinding(tenantId, vulnerabilityId, payload = {}) {
      return request<{ intelligence: FindingIntelligence; bayesian?: BayesianAssessment }>(`/api/patchforge/vulnerabilities/${encodeURIComponent(vulnerabilityId)}/analyse`, tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
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
    async adminPurge(tenantId, payload) {
      const body = await request<{ purge: AdminPurgePlan }>("/api/patchforge/admin/purge", tenantId, {
        method: "POST",
        body: JSON.stringify(payload)
      });
      return body.purge;
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

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Archive,
  BadgeCheck,
  Bell,
  Binary,
  Blocks,
  BookOpenCheck,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  Clock3,
  Database,
  Download,
  FileCheck2,
  FileText,
  Gauge,
  KeyRound,
  Layers3,
  ListFilter,
  LockKeyhole,
  LogIn,
  LogOut,
  Network,
  PanelLeft,
  Radar,
  RefreshCw,
  MessageSquareText,
  Search,
  ServerCog,
  ShieldCheck,
  ShieldAlert,
  SlidersHorizontal,
  TriangleAlert,
  Upload,
  UserRound,
  Wrench,
  X
} from "lucide-react";
import {
  AdminConfig,
  AdminHealth,
  AdminPurgePlan,
  AssetDiscoveryOverview,
  AssetRecord,
  AgentGuidanceSnapshot,
  BayesianAssessment,
  ConfigApplicabilityAssessment,
  CustomerAssetExtraction,
  CustomerEstateMatch,
  CustomerEstateState,
  CustomerNetworkAsset,
  DecisionPackRecord,
  FindingIntelligence,
  NetworkVendorProfile,
  OpenAiAgentStatus,
  PatchForgeApi,
  PatchForgeMetrics,
  AskPatchForgeAnswer,
  ReportCatalogItem,
  ReportsPacksState,
  SecurityActionCenterRow,
  SecurityActionCenterState,
  ServiceRecord,
  SourceFeedState,
  ThreatLandscapeSummary,
  VendorLensChatSession,
  VendorLensPatchComparison,
  VendorLensState,
  VendorProfile,
  VendorSecurityAdvisory,
  VulnerabilityRecord,
  createPatchForgeApi,
  getPatchForgeConfig
} from "./api";
import { PatchForgeAuthSession, usePatchForgeAuth } from "./auth";

type PageKey =
  | "Patch & CVE Catalogue"
  | "Vendor Catalogue"
  | "Customer Estate"
  | "Ask PatchForge"
  | "Reports"
  | "Admin"
  | "Action Center"
  | "Finding Detail"
  | "Review & Approve"
  | "Command Center"
  | "Guide"
  | "Vulnerability Queue"
  | "Asset & Service Exposure"
  | "Decision Workbench"
  | "Emergency Patch"
  | "Risk Acceptances"
  | "Compensating Controls"
  | "SRA Research"
  | "Evidence Catalogue"
  | "Decision Packs"
  | "Source Feeds"
  | "Vendor & Threat Landscape"
  | "VendorLens";

type NavItem = {
  label: PageKey;
  icon: typeof Gauge;
};

type AppProps = {
  auth?: PatchForgeAuthSession;
  api?: PatchForgeApi;
  initialTenantId?: string;
};

type LiveState = {
  metrics: PatchForgeMetrics;
  securityActionCenter: SecurityActionCenterState;
  customerEstate: CustomerEstateState;
  reportsPacks: ReportsPacksState;
  findings: FindingIntelligence[];
  vulnerabilities: VulnerabilityRecord[];
  assets: AssetRecord[];
  services: ServiceRecord[];
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  bayesian: BayesianAssessment | null;
  threatSummary: ThreatLandscapeSummary | null;
  vendors: VendorProfile[];
  vendorLens: VendorLensState;
  latestCustomerMatch: CustomerEstateMatch | null;
  latestAskPatchForge: AskPatchForgeAnswer | null;
  openAiAgentStatus: OpenAiAgentStatus | null;
  latestAgentGuidance: AgentGuidanceSnapshot | null;
  sourceFeedState: SourceFeedState;
  adminHealth: AdminHealth | null;
  adminConfig: AdminConfig;
  discovery: AssetDiscoveryOverview | null;
};

const BRAND_MARK = "DIIaC\u2122";
const PRODUCT_MARK = `PatchForge Intelligence by ${BRAND_MARK}`;
const config = getPatchForgeConfig();
const discoveryCollectorCategories = [
  "network_device",
  "security_appliance",
  "physical_server",
  "virtual_server",
  "hypervisor",
  "cloud_resource"
];

const navItems: NavItem[] = [
  { label: "Patch & CVE Catalogue", icon: Gauge },
  { label: "Vendor Catalogue", icon: Radar },
  { label: "Customer Estate", icon: ServerCog },
  { label: "Ask PatchForge", icon: MessageSquareText },
  { label: "Reports", icon: FileText },
  { label: "Admin", icon: SlidersHorizontal }
];

const postures = [
  "patch_required",
  "emergency_change_required",
  "mitigate_temporarily",
  "risk_accept_temporarily",
  "defer_pending_evidence",
  "block_go_live",
  "patch_not_applicable",
  "close_verified"
];

type AdminCapability = {
  label: string;
  status: string;
  detail: string;
  tone: "amber" | "steel" | "teal" | "trust";
};

const adminSections: AdminCapability[] = [
  { label: "General Settings", status: "Config-backed", tone: "trust", detail: "Environment and governance tier save through the protected Admin API." },
  { label: "Tenant Configuration", status: "Config-backed", tone: "trust", detail: "Tenant context is explicit and carried into every protected API call." },
  { label: "Entra ID / RBAC", status: "Runtime checked", tone: "trust", detail: "App roles are enforced server-side for reader, analyst, lead, auditor, and admin paths." },
  { label: "SRA Configuration", status: "Advisory locked", tone: "teal", detail: "Security Research Agent output remains advisory-only and human-review required." },
  { label: "MCP Agent Connectors", status: "Governed intake", tone: "teal", detail: "Agent findings can enter as source-bound records pending review." },
  { label: "OpenAI Assistance", status: "Runtime gated", tone: "amber", detail: "Optional Ask PatchForge assistance depends on environment configuration and verifier pass." },
  { label: "DIIaC IT Service / Enterprise Build", status: "Harness-ready", tone: "teal", detail: "PatchForge can sit beside IT Service workflows as a signed governance module." },
  { label: "Scanner Integrations", status: "Out of scope", tone: "amber", detail: "PatchForge remains governance-only and does not scan customer environments." },
  { label: "Patch Deployment", status: "Blocked", tone: "amber", detail: "PatchForge does not deploy patches or mutate production systems." },
  { label: "Source Feeds", status: "Runtime-backed", tone: "trust", detail: "Public advisory refresh and run history are exposed in the live source feed surfaces." },
  { label: "VendorLens Sources", status: "Runtime-backed", tone: "trust", detail: "Vendor, product, advisory, and customer-estate intelligence feed the advisory workflow." },
  { label: "Evidence Models", status: "Runtime-backed", tone: "trust", detail: "Reviewed evidence, rejected evidence, and gaps stay visible before report export." },
  { label: "Policy Packs", status: "Baseline-bound", tone: "steel", detail: "Current policy behavior follows the approved PF-AZ12 governance baseline." },
  { label: "Decision State Rules", status: "Human-gated", tone: "amber", detail: "Final approval, closure, and assurance claims require reviewed evidence and a named human." },
  { label: "Risk Acceptance Rules", status: "Human-only", tone: "amber", detail: "PatchForge records posture guidance but does not autonomously accept risk." },
  { label: "SLA / Ageing Rules", status: "Visible", tone: "steel", detail: "Ageing and priority signals are surfaced in queue and reporting contexts." },
  { label: "Signing & Trust", status: "Runtime checked", tone: "trust", detail: "Signed packs and report metadata preserve verification state and final approval flags." },
  { label: "Key Vault", status: "Runtime checked", tone: "trust", detail: "Signing trust is included in Admin health when available from the bridge." },
  { label: "Storage", status: "Runtime checked", tone: "trust", detail: "Storage readiness is surfaced through protected Admin health checks." },
  { label: "Database", status: "Runtime checked", tone: "trust", detail: "Readiness reports the database storage mode returned by the protected API." },
  { label: "Telemetry", status: "Health-only", tone: "steel", detail: "Operational health is visible without exposing raw sensitive request payloads." },
  { label: "Health Checks", status: "Runtime checked", tone: "trust", detail: "Protected bridge health checks show readiness, signing, storage, and integration state." },
  { label: "Audit Logs", status: "Governed", tone: "teal", detail: "Write paths preserve actor, tenant, and lineage context for review." },
  { label: "Export Settings", status: "Report-bound", tone: "teal", detail: "DOCX/PDF output remains tied to signed packs and report QA metadata." },
  { label: "Backup / Restore", status: "Planned", tone: "steel", detail: "No self-service restore action is exposed in this production-demo surface." },
  { label: "Data Retention", status: "Guarded", tone: "amber", detail: "Cleanup is available only through typed purge confirmation and preview." },
  { label: "Feature Flags", status: "Runtime-only", tone: "steel", detail: "Unsafe or unavailable flags are not exposed as inert toggles." }
];

const purgeScopeOptions = [
  { key: "reports", label: "Generated reports" },
  { key: "catalogue", label: "Vulnerability catalogue" },
  { key: "assets", label: "Customer assets" },
  { key: "uploads", label: "Uploaded configs" },
  { key: "logs", label: "Logs" },
  { key: "cache", label: "Cache" }
] as const;

const emptyForm = {
  vulnerability_id: "",
  title: "",
  severity: "high",
  patch_status: "unknown",
  source_class: "vendor_advisory",
  source_name: "",
  source_url: "",
  affected_service_ids: "",
  affected_asset_ids: "",
  known_exploited: false,
  internet_exposed: false,
  ot_relevant: false
};

const emptyNetworkAssetForm = {
  vendor_id: "fortinet",
  product_family: "FortiGate",
  model: "",
  firmware_version: "",
  environment: "production",
  site: "",
  service_owner: "",
  management_exposure: "unknown",
  enabled_features: "",
  disabled_features: "",
  config_evidence_refs: "",
  internet_facing: false,
  review_state: "pending_review",
  evidence_state: "referenced"
};

const emptyVendorAdvisoryForm = {
  vendor_id: "fortinet",
  cve: "",
  title: "",
  severity: "high",
  product_family: "FortiGate",
  affected_versions: "",
  fixed_versions: "",
  affected_features: "",
  source_url: "",
  known_exploited: false,
  patch_available: false
};

export default function App({ auth, api, initialTenantId }: AppProps) {
  const contextAuth = usePatchForgeAuth();
  const session = auth || contextAuth;
  const liveApi = useMemo(() => api || createPatchForgeApi(session.getAccessToken), [api, session.getAccessToken]);
  const [activePage, setActivePage] = useState<PageKey>("Patch & CVE Catalogue");
  const [navigationCollapsed, setNavigationCollapsed] = useState(() => (
    typeof window !== "undefined"
    && typeof window.matchMedia === "function"
    && window.matchMedia("(max-width: 820px)").matches
  ));
  const [tenantId, setTenantId] = useState(initialTenantId || config.tenantHeader);
  const [state, setState] = useState<LiveState>(() => emptyLiveState(tenantId));
  const [refreshing, setRefreshing] = useState(false);
  const [operationMessage, setOperationMessage] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [vulnerabilityForm, setVulnerabilityForm] = useState(emptyForm);
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState("");
  const [selectedPosture, setSelectedPosture] = useState("defer_pending_evidence");
  const [adminEnvironment, setAdminEnvironment] = useState(config.environmentLabel);
  const [adminTier, setAdminTier] = useState("Enterprise Strict");
  const [sraResult, setSraResult] = useState<Record<string, unknown> | null>(null);
  const [networkAssetForm, setNetworkAssetForm] = useState(emptyNetworkAssetForm);
  const [vendorAdvisoryForm, setVendorAdvisoryForm] = useState(emptyVendorAdvisoryForm);
  const [vendorLensQuestion, setVendorLensQuestion] = useState("We use this firewall model and this feature is disabled. Do we urgently need to patch?");
  const [globalSearch, setGlobalSearch] = useState("");
  const [globalFilters, setGlobalFilters] = useState({ vendor: "", severity: "", customer_match: "", patch_available: "" });
  const [customerDeviceText, setCustomerDeviceText] = useState("FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only.");
  const [extractedCustomerAsset, setExtractedCustomerAsset] = useState<CustomerAssetExtraction | null>(null);
  const [selectedCustomerAssetId, setSelectedCustomerAssetId] = useState("");
  const [selectedAdvisoryId, setSelectedAdvisoryId] = useState("");
  const [patchCompareForm, setPatchCompareForm] = useState({ current_version: "7.2.7", proposed_version: "7.2.8" });
  const [askQuestion, setAskQuestion] = useState("We use FortiGate 100F FortiOS 7.2.7 with SSL-VPN disabled. Does this CVE require urgent patching?");
  const canWrite = hasAnyRole(session.roles, ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"]);
  const canGeneratePacks = hasAnyRole(session.roles, ["PatchForge.SecurityLead", "PatchForge.CABApprover", "PatchForge.Admin"]);
  const isAdmin = hasAnyRole(session.roles, ["PatchForge.Admin"]);
  const canReadAdmin = hasAnyRole(session.roles, ["PatchForge.Admin", "PatchForge.Auditor"]);
  const [purgeScopes, setPurgeScopes] = useState<Record<string, boolean>>({
    reports: false,
    catalogue: false,
    assets: false,
    uploads: false,
    logs: false,
    cache: false
  });
  const [purgeConfirm, setPurgeConfirm] = useState("");
  const [latestPurgePlan, setLatestPurgePlan] = useState<AdminPurgePlan | null>(null);
  const selectedFinding = useMemo(
    () => state.findings.find((item) => item.vulnerability_id === selectedVulnerabilityId) || state.findings[0] || null,
    [selectedVulnerabilityId, state.findings]
  );
  const selectedGlobalRecord = useMemo(
    () => {
      const catalogueRows = collapseCatalogueRows(state.securityActionCenter.catalogue_rows);
      return catalogueRows.find((row) =>
        [row.vulnerability_id, row.cve_id, row.advisory_id, row.id].filter(Boolean).includes(selectedVulnerabilityId)
        || [row.advisory_id, row.cve_id, row.id].filter(Boolean).includes(selectedAdvisoryId)
      ) || catalogueRows[0] || null;
    },
    [selectedAdvisoryId, selectedVulnerabilityId, state.securityActionCenter.catalogue_rows]
  );
  const visibleNav = useMemo(() => navItems, []);
  const activePatchComparison = useMemo(
    () => relevantPatchComparison(state.vendorLens.latestComparison, selectedAdvisoryId),
    [selectedAdvisoryId, state.vendorLens.latestComparison]
  );

  const loadLiveState = useCallback(async () => {
    if (session.status !== "authenticated") {
      return;
    }
    setRefreshing(true);
    setOperationError(null);
    try {
      const [metrics, securityActionCenter, customerEstate, reportsPacks, vulnerabilities, findings, assets, services, decisionPacks, reports, threatSummary, vendors, sourceFeedState, vendorLensDashboard, networkVendors, customerNetworkAssets, vendorSecurityAdvisories, discovery, openAiAgentStatus, adminHealth, adminConfig] = await Promise.all([
        liveApi.metrics(tenantId),
        liveApi.securityActionCenter(tenantId),
        liveApi.customerEstate(tenantId),
        liveApi.reportsPacks(tenantId),
        liveApi.listVulnerabilities(tenantId),
        liveApi.actionCenter(tenantId),
        liveApi.listAssets(tenantId),
        liveApi.listServices(tenantId),
        liveApi.listDecisionPacks(tenantId),
        liveApi.reportCatalog(tenantId),
        liveApi.threatLandscapeSummary(tenantId),
        liveApi.listVendors(tenantId),
        liveApi.sourceFeeds(tenantId),
        liveApi.vendorLensDashboard(tenantId),
        liveApi.listNetworkVendors(tenantId),
        liveApi.listCustomerNetworkAssets(tenantId),
        liveApi.listVendorSecurityAdvisories(tenantId),
        liveApi.assetDiscoveryOverview(tenantId),
        liveApi.openAiAgentStatus(tenantId),
        canReadAdmin ? liveApi.adminHealth(tenantId) : Promise.resolve(null),
        canReadAdmin ? liveApi.adminConfig(tenantId) : Promise.resolve({} as AdminConfig)
      ]);
      setState((current) => ({
        metrics,
        securityActionCenter,
        customerEstate,
        reportsPacks,
        findings,
        vulnerabilities,
        assets,
        services,
        decisionPacks,
        reports,
        threatSummary,
        vendors,
        sourceFeedState,
        vendorLens: {
          dashboard: vendorLensDashboard,
          vendors: networkVendors,
          assets: customerNetworkAssets,
          advisories: vendorSecurityAdvisories,
          latestAssessment: current.vendorLens.latestAssessment,
          latestChat: current.vendorLens.latestChat,
          latestComparison: current.vendorLens.latestComparison
        },
        latestCustomerMatch: current.latestCustomerMatch,
        latestAskPatchForge: current.latestAskPatchForge,
        openAiAgentStatus,
        latestAgentGuidance: openAiAgentStatus.enabled && openAiAgentStatus.configured ? current.latestAgentGuidance : null,
        bayesian: null,
        adminHealth,
        adminConfig,
        discovery
      }));
      setSelectedVulnerabilityId((current) => current || vulnerabilities[0]?.vulnerability_id || "");
      setSelectedCustomerAssetId((current) => current || customerEstate.assets[0]?.asset_id || customerNetworkAssets[0]?.asset_id || "");
      const general = adminConfig.general as { environment?: string; governance_tier?: string } | undefined;
      setAdminEnvironment(general?.environment || config.environmentLabel);
      setAdminTier(general?.governance_tier || "Enterprise Strict");
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "PatchForge API request failed.");
    } finally {
      setRefreshing(false);
    }
  }, [canReadAdmin, liveApi, session.status, tenantId]);

  useEffect(() => {
    void loadLiveState();
  }, [loadLiveState]);

  async function handleIngest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOperationMessage(null);
    setOperationError(null);
    const vulnerabilityId = vulnerabilityForm.vulnerability_id.trim();
    if (!vulnerabilityId) {
      setOperationError("A vulnerability, advisory, or risk identifier is required.");
      return;
    }

    const source = vulnerabilityForm.source_name.trim() || vulnerabilityForm.source_url.trim()
      ? [{
          source_class: vulnerabilityForm.source_class,
          source_name: vulnerabilityForm.source_name.trim() || "manual-source",
          source_url: vulnerabilityForm.source_url.trim() || null,
          review_state: "pending_review",
          evidence_state: "referenced"
        }]
      : [];

    try {
      await liveApi.ingestVulnerability(tenantId, {
        vulnerability_id: vulnerabilityId,
        canonical_id: vulnerabilityId,
        title: vulnerabilityForm.title.trim() || vulnerabilityId,
        severity: vulnerabilityForm.severity,
        patch_status: vulnerabilityForm.patch_status,
        known_exploited: vulnerabilityForm.known_exploited,
        internet_exposed: vulnerabilityForm.internet_exposed,
        ot_relevant: vulnerabilityForm.ot_relevant,
        affected_service_ids: parseList(vulnerabilityForm.affected_service_ids),
        affected_asset_ids: parseList(vulnerabilityForm.affected_asset_ids),
        sources: source
      });
      setOperationMessage(`Record ingested for ${vulnerabilityId}.`);
      setVulnerabilityForm(emptyForm);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Vulnerability ingest failed.");
    }
  }

  async function handleGeneratePack(context?: {
    vulnerabilityId?: string;
    assetId?: string;
    advisoryId?: string;
    strictContext?: boolean;
  }) {
    setOperationMessage(null);
    setOperationError(null);
    const vulnerabilityId = context?.vulnerabilityId || selectedVulnerabilityId;
    if (!vulnerabilityId) {
      setOperationError("Select a real ingested vulnerability before generating a decision pack.");
      return;
    }
    try {
      const requestedAssetId = context?.strictContext ? context.assetId || "" : selectedCustomerAssetId;
      const requestedAdvisoryId = context?.strictContext ? context.advisoryId || "" : selectedAdvisoryId;
      const selectedAsset = state.vendorLens.assets.find((item) => item.asset_id === requestedAssetId)
        || (!context?.strictContext ? state.vendorLens.assets[0] : null)
        || null;
      const selectedAdvisory = state.vendorLens.advisories.find((item) => item.advisory_id === requestedAdvisoryId)
        || (!context?.strictContext ? state.vendorLens.advisories[0] : null)
        || null;
      const assetId = context?.strictContext ? requestedAssetId : selectedAsset?.asset_id || "";
      const advisoryId = context?.strictContext ? requestedAdvisoryId : selectedAdvisory?.advisory_id || "";
      const assessment = recordMatchesContext(state.vendorLens.latestAssessment, assetId, advisoryId)
        ? state.vendorLens.latestAssessment
        : null;
      const comparison = recordMatchesContext(state.vendorLens.latestComparison, assetId, advisoryId)
        ? state.vendorLens.latestComparison
        : null;
      const chat = recordMatchesContext(state.vendorLens.latestChat, assetId, advisoryId)
        ? state.vendorLens.latestChat
        : null;
      const pack = await liveApi.generateReportsPack(tenantId, {
        vulnerability_id: vulnerabilityId,
        requested_posture: selectedPosture,
        bayesian_snapshot: state.bayesian,
        config_applicability_assessment: assessment,
        vendorlens_patch_comparison: comparison,
        sra_config_chat_session: chat,
        asset_id: assetId || undefined,
        advisory_id: advisoryId || undefined
      });
      setOperationMessage(`Signed decision pack ${pack.pack_id} generated.`);
      await loadLiveState();
      setActivePage("Reports");
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Decision pack generation failed.");
    }
  }

  async function handleBayesianAssess() {
    setOperationMessage(null);
    setOperationError(null);
    const vulnerability = state.vulnerabilities.find((item) => item.vulnerability_id === selectedVulnerabilityId) || state.vulnerabilities[0];
    if (!vulnerability) {
      setOperationError("Select or ingest a vulnerability before running Bayesian advisory assessment.");
      return;
    }
    try {
      const bayesian = await liveApi.assessBayesianRisk(tenantId, {
        vulnerability,
        ...vulnerability
      });
      setState((current) => ({ ...current, bayesian }));
      setOperationMessage(`Bayesian advisory recommends ${humanize(bayesian.recommended_governance_posture)}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Bayesian assessment failed.");
    }
  }

  function handleSelectFinding(vulnerabilityId: string, page: PageKey = "Finding Detail") {
    setSelectedVulnerabilityId(vulnerabilityId);
    setActivePage(page);
  }

  async function handleAnalyseFinding() {
    setOperationMessage(null);
    setOperationError(null);
    const vulnerabilityId = selectedVulnerabilityId || selectedFinding?.vulnerability_id || state.vulnerabilities[0]?.vulnerability_id;
    if (!vulnerabilityId) {
      setOperationError("Select or ingest a vulnerability before running PatchForge intelligence analysis.");
      return;
    }
    try {
      const result = await liveApi.analyseFinding(tenantId, vulnerabilityId);
      setState((current) => ({
        ...current,
        bayesian: result.bayesian || current.bayesian,
        findings: [result.intelligence, ...current.findings.filter((item) => item.vulnerability_id !== result.intelligence.vulnerability_id)]
      }));
      setSelectedVulnerabilityId(result.intelligence.vulnerability_id);
      setOperationMessage(`PatchForge intelligence analysis completed for ${result.intelligence.vulnerability_id}. Human approval remains required.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Finding intelligence analysis failed.");
    }
  }

  async function handleSraResearch() {
    setOperationMessage(null);
    setOperationError(null);
    const vulnerability = state.vulnerabilities.find((item) => item.vulnerability_id === selectedVulnerabilityId) || state.vulnerabilities[0];
    if (!vulnerability) {
      setOperationError("Select or ingest a vulnerability before running SRA advisory research.");
      return;
    }
    try {
      const result = await liveApi.sraResearch(tenantId, "/api/sra/exploit-risk", {
        vulnerability_id: vulnerability.vulnerability_id,
        source_refs: vulnerability.source_record_ids || []
      });
      setSraResult(result);
      setOperationMessage("SRA advisory research returned source-bound output.");
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "SRA advisory request failed.");
    }
  }

  async function handleRefreshSourceFeed(feedId: string, remainInCurrentArea = false) {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const payload: Record<string, unknown> = feedId === "cisa-kev"
        ? { feed_id: feedId, limit: 5 }
        : { feed_id: feedId, cve: selectedVulnerabilityId || state.vulnerabilities[0]?.vulnerability_id };
      const run = await liveApi.refreshSourceFeed(tenantId, payload);
      setOperationMessage(`${run.feed_name} ${run.status}: ${run.message || "source-bound refresh recorded."}`);
      await loadLiveState();
      if (!remainInCurrentArea) {
        setActivePage("Source Feeds");
      }
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Source feed refresh failed.");
    }
  }

  async function handleSearchSecurityActionCenter() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const securityActionCenter = await liveApi.searchSecurityActionCenter(tenantId, {
        q: globalSearch,
        ...globalFilters
      });
      setState((current) => ({ ...current, securityActionCenter }));
      setOperationMessage(`Global catalogue filtered to ${securityActionCenter.catalogue_rows.length} record(s).`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Security Action Center search failed.");
    }
  }

  async function handleGlobalSearchSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActivePage("Patch & CVE Catalogue");
    await handleSearchSecurityActionCenter();
  }

  async function handleExtractCustomerAsset() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const extracted = await liveApi.extractCustomerAsset(tenantId, customerDeviceText);
      setExtractedCustomerAsset(extracted);
      setNetworkAssetForm((current) => ({
        ...current,
        vendor_id: extracted.vendor_id || current.vendor_id,
        product_family: extracted.product_family || current.product_family,
        model: extracted.model || "",
        firmware_version: extracted.firmware_version || "",
        management_exposure: extracted.management_exposure || "unknown",
        enabled_features: (extracted.enabled_features || []).join(", "),
        disabled_features: (extracted.disabled_features || []).join(", "),
        internet_facing: Boolean(extracted.internet_facing),
        review_state: extracted.review_state || "pending_review",
        evidence_state: extracted.evidence_state || "user_stated_unreviewed"
      }));
      setOperationMessage("Device fields extracted for user confirmation.");
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Device extraction failed.");
    }
  }

  async function handleConfirmCustomerAsset() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const payload = {
        ...(extractedCustomerAsset || {}),
        ...networkAssetForm,
        enabled_features: parseList(networkAssetForm.enabled_features),
        disabled_features: parseList(networkAssetForm.disabled_features),
        config_evidence_refs: parseList(networkAssetForm.config_evidence_refs),
        evidence_state: networkAssetForm.evidence_state || "user_stated_unreviewed"
      };
      const asset = await liveApi.upsertCustomerEstateAsset(tenantId, payload);
      setSelectedCustomerAssetId(asset.asset_id);
      setOperationMessage(`Customer asset ${asset.asset_id} saved for governed matching.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Customer asset save failed.");
    }
  }

  async function handleMatchCustomerEstate() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const assetId = selectedCustomerAssetId || state.customerEstate.assets[0]?.asset_id || state.vendorLens.assets[0]?.asset_id;
      const match = await liveApi.matchCustomerEstate(tenantId, {
        asset_id: assetId,
        advisory_id: selectedAdvisoryId || undefined
      });
      setState((current) => ({ ...current, latestCustomerMatch: match }));
      setOperationMessage(`Customer estate matching found ${match.match_count} candidate advisory/CVE match(es).`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Customer estate match failed.");
    }
  }

  async function handleCustomerPatchCompare() {
    setOperationMessage(null);
    setOperationError(null);
    if (!selectedAdvisoryId) {
      setOperationError("Select a CVE/advisory before running Patch Compare.");
      return;
    }
    try {
      const comparison = await liveApi.compareCustomerEstatePatch(tenantId, {
        asset_id: selectedCustomerAssetId || state.customerEstate.assets[0]?.asset_id || state.vendorLens.assets[0]?.asset_id,
        advisory_id: selectedAdvisoryId,
        current_version: patchCompareForm.current_version,
        proposed_version: patchCompareForm.proposed_version
      });
      setState((current) => ({
        ...current,
        vendorLens: { ...current.vendorLens, latestComparison: comparison },
        customerEstate: {
          ...current.customerEstate,
          patch_comparisons: [comparison, ...current.customerEstate.patch_comparisons.filter((item) => item.comparison_id !== comparison.comparison_id)]
        }
      }));
      setOperationMessage(`Patch Compare prepared: current ${comparison.current_version_affected || comparison.current_version_status}, proposed ${comparison.proposed_version_remediates || comparison.target_version_status}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Patch Compare failed.");
    }
  }

  async function handleRegisterDiscoveryCollector() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const collector = await liveApi.registerAssetCollector(tenantId, {
        collector_id: "collector-customer-estate-mvp",
        name: "Customer estate collector MVP",
        platform: "windows",
        site: "Primary site",
        categories: discoveryCollectorCategories
      });
      setOperationMessage(`Collector ${collector.collector_id} registered as outbound-only.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Collector registration failed.");
    }
  }

  async function handleCreateDiscoveryPolicy() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const collectorId = state.discovery?.collectors[0]?.collector_id || "collector-customer-estate-mvp";
      const policy = await liveApi.upsertAssetDiscoveryPolicy(tenantId, {
        policy_id: "policy-customer-estate-mvp",
        collector_id: collectorId,
        name: "Read-only customer estate snapshot",
        categories: discoveryCollectorCategories,
        discovery_methods: ["manual_snapshot", "hyperv_inventory", "cloud_inventory", "cmdb_api"],
        credential_reference: "customer-vault:patchforge/read-only-discovery",
        scope: {
          sites: ["Primary site"],
          source_systems: ["local_host", "hyperv", "azure_cli", "http_json"]
        }
      });
      setOperationMessage(`Discovery policy ${policy.policy_id} saved as read-only and reference-only.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Discovery policy save failed.");
    }
  }

  function handleDownloadDiscoveryCollectorConfig() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const payload = buildDiscoveryCollectorConfig({
        apiBaseUrl: config.apiBaseUrl || window.location.origin,
        tenantId,
        discovery: state.discovery
      });
      downloadJson(`patchforge-collector-${safeFileStem(tenantId)}.config.json`, payload);
      setOperationMessage("Collector config downloaded. Set PATCHFORGE_COLLECTOR_TOKEN and run collector/patchforge-collector.mjs with this config.");
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Collector config download failed.");
    }
  }

  async function handleAskPatchForge() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const answer = await liveApi.askPatchForge(tenantId, {
        question: askQuestion,
        asset_id: selectedCustomerAssetId || undefined,
        advisory_id: selectedAdvisoryId || undefined,
        patch_compare: activePatchComparison || undefined
      });
      let agentGuidance: AgentGuidanceSnapshot | null = null;
      if (state.openAiAgentStatus?.enabled && state.openAiAgentStatus.configured) {
        try {
          agentGuidance = await liveApi.askOpenAiAgent(tenantId, {
            question: askQuestion,
            deterministic_answer: answer.response,
            evidence: {
              asset_id: selectedCustomerAssetId || undefined,
              advisory_id: selectedAdvisoryId || undefined,
              patch_compare: activePatchComparison || undefined
            }
          });
        } catch {
          agentGuidance = null;
        }
      }
      setState((current) => ({ ...current, latestAskPatchForge: answer, latestAgentGuidance: agentGuidance }));
      setOperationMessage(agentGuidance?.status === "verified"
        ? `Ask PatchForge answered with verified AI assistance: ${answer.response.short_answer}`
        : `Ask PatchForge answered deterministically: ${answer.response.short_answer}`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Ask PatchForge failed.");
    }
  }

  async function handleSaveNetworkAsset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOperationMessage(null);
    setOperationError(null);
    try {
      const asset = await liveApi.upsertCustomerNetworkAsset(tenantId, {
        ...networkAssetForm,
        enabled_features: parseList(networkAssetForm.enabled_features),
        disabled_features: parseList(networkAssetForm.disabled_features),
        config_evidence_refs: parseList(networkAssetForm.config_evidence_refs)
      });
      setOperationMessage(`VendorLens asset ${asset.asset_id} saved as source-bound customer evidence.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "VendorLens asset save failed.");
    }
  }

  async function handleIngestVendorLensAdvisory(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setOperationMessage(null);
    setOperationError(null);
    try {
      const advisory = await liveApi.ingestVendorSecurityAdvisory(tenantId, {
        ...vendorAdvisoryForm,
        affected_versions: parseList(vendorAdvisoryForm.affected_versions),
        fixed_versions: parseList(vendorAdvisoryForm.fixed_versions),
        affected_features: parseList(vendorAdvisoryForm.affected_features),
        review_state: "pending_review",
        evidence_state: "referenced"
      });
      setOperationMessage(`VendorLens advisory ${advisory.advisory_id} ingested as pending-review source intelligence.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "VendorLens advisory ingest failed.");
    }
  }

  async function handleAssessVendorLens(assetId?: string, advisoryId?: string) {
    setOperationMessage(null);
    setOperationError(null);
    const asset = state.vendorLens.assets.find((item) => item.asset_id === assetId)
      || state.vendorLens.assets.find((item) => item.asset_id === selectedCustomerAssetId)
      || state.vendorLens.assets[0];
    const advisory = state.vendorLens.advisories.find((item) => item.advisory_id === advisoryId)
      || state.vendorLens.advisories.find((item) => item.advisory_id === selectedAdvisoryId)
      || state.vendorLens.advisories[0];
    if (!asset || !advisory) {
      setOperationError("VendorLens needs at least one customer network asset and one vendor advisory before assessing applicability.");
      return;
    }
    try {
      setSelectedCustomerAssetId(asset.asset_id);
      setSelectedAdvisoryId(advisory.advisory_id);
      const assessment = await liveApi.assessConfigApplicability(tenantId, {
        asset_id: asset.asset_id,
        advisory_id: advisory.advisory_id
      });
      setState((current) => ({ ...current, vendorLens: { ...current.vendorLens, latestAssessment: assessment } }));
      setOperationMessage(`VendorLens assessed ${humanize(assessment.urgency_posture)}. Final approval remains human-controlled.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "VendorLens applicability assessment failed.");
    }
  }

  async function handleAskVendorLens(assetId?: string, advisoryId?: string) {
    setOperationMessage(null);
    setOperationError(null);
    const asset = state.vendorLens.assets.find((item) => item.asset_id === assetId)
      || state.vendorLens.assets.find((item) => item.asset_id === selectedCustomerAssetId)
      || state.vendorLens.assets[0];
    const advisory = state.vendorLens.advisories.find((item) => item.advisory_id === advisoryId)
      || state.vendorLens.advisories.find((item) => item.advisory_id === selectedAdvisoryId)
      || state.vendorLens.advisories[0];
    if (!asset || !advisory) {
      setOperationError("Add or select a network asset and vendor advisory before asking PatchForge.");
      return;
    }
    try {
      setSelectedCustomerAssetId(asset.asset_id);
      setSelectedAdvisoryId(advisory.advisory_id);
      const assessment = recordMatchesContext(state.vendorLens.latestAssessment, asset.asset_id, advisory.advisory_id)
        ? state.vendorLens.latestAssessment
        : state.vendorLens.dashboard?.recent_assessments?.find((item) => recordMatchesContext(item, asset.asset_id, advisory.advisory_id));
      const chat = await liveApi.startVendorLensChat(tenantId, {
        question: vendorLensQuestion,
        asset_id: asset.asset_id,
        advisory_id: advisory.advisory_id,
        assessment: assessment || undefined
      });
      setState((current) => ({
        ...current,
        vendorLens: {
          ...current.vendorLens,
          latestChat: chat.session
        }
      }));
      setOperationMessage(`Ask PatchForge response: ${chat.response.short_answer}`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Ask PatchForge request failed.");
    }
  }

  async function handleRefreshVendorLensSource(vendorIdOverride?: string) {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const run = await liveApi.refreshVendorLensSource(tenantId, {
        adapter: "nvd_cve_api",
        mode: "catalogue",
        vendor_id: vendorIdOverride || vendorAdvisoryForm.vendor_id || "all-vendors",
        max_vendors: 30,
        results_per_page: 100,
        max_pages: 1,
        max_keywords: 4
      });
      setOperationMessage(`${run.feed_name} ${run.status}: ${run.message || "VendorLens source refresh recorded."}`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "VendorLens source refresh failed.");
    }
  }

  async function handleCompareVendorLensPatch(assetId?: string, advisoryId?: string) {
    setOperationMessage(null);
    setOperationError(null);
    const asset = state.vendorLens.assets.find((item) => item.asset_id === assetId) || state.vendorLens.assets[0];
    const advisory = state.vendorLens.advisories.find((item) => item.advisory_id === advisoryId) || state.vendorLens.advisories[0];
    if (!asset || !advisory) {
      setOperationError("VendorLens needs at least one customer network asset and one vendor advisory before comparing patch versions.");
      return;
    }
    try {
      const comparison = await liveApi.compareVendorLensPatch(tenantId, {
        asset_id: asset.asset_id,
        advisory_id: advisory.advisory_id
      });
      setState((current) => ({
        ...current,
        vendorLens: {
          ...current.vendorLens,
          latestComparison: comparison
        }
      }));
      setOperationMessage(`Patch comparison prepared for CISO review: ${comparison.current_version || "current unknown"} to ${comparison.target_version || "target pending"}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "VendorLens patch comparison failed.");
    }
  }

  async function handleExportPack(packId: string) {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const exported = await liveApi.exportDecisionPack(tenantId, packId);
      downloadJson(`${packId}.json`, exported);
      setOperationMessage(`Decision pack ${packId} export prepared.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Decision pack export failed.");
    }
  }

  async function handleDownloadReport(packId: string, reportType: string, format: "docx" | "pdf") {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const blob = await liveApi.downloadDecisionPackReport(tenantId, packId, reportType, format);
      downloadBlob(`${packId}-${reportType}.${format}`, blob);
      setOperationMessage(`${format.toUpperCase()} report prepared for ${packId}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Report export failed.");
    }
  }

  async function handleSaveAdmin() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      await liveApi.saveAdminConfig(tenantId, {
        general: {
          environment: adminEnvironment,
          governance_tier: adminTier
        }
      });
      setOperationMessage("Admin configuration saved.");
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Admin configuration save failed.");
    }
  }

  async function handlePreviewPurge() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const purge = await liveApi.adminPurge(tenantId, { ...purgeScopes, dry_run: true });
      setLatestPurgePlan(purge);
      setOperationMessage(`Purge dry-run found ${purge.total_records} record(s) across ${purge.collections.length} collection(s).`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Purge preview failed.");
    }
  }

  async function handleExecutePurge() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const purge = await liveApi.adminPurge(tenantId, { ...purgeScopes, dry_run: false, confirm: purgeConfirm });
      setLatestPurgePlan(purge);
      setOperationMessage(`Confirmed purge completed for ${Object.values(purge.removed || {}).reduce((total, count) => total + count, 0)} record(s).`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Confirmed purge failed.");
    }
  }

  if (session.status !== "authenticated") {
    return <SignedOutShell session={session} />;
  }

  return (
    <main className={`app-shell${navigationCollapsed ? " nav-collapsed" : ""}`}>
      <aside id="patchforge-primary-navigation" className="side-nav" aria-label="PatchForge navigation" aria-hidden={navigationCollapsed}>
        <button type="button" className="icon-button nav-mobile-close" aria-label="Close navigation" tabIndex={navigationCollapsed ? -1 : 0} onClick={() => setNavigationCollapsed(true)}>
          <X size={18} aria-hidden />
        </button>
        <BrandLockup />
        <nav className="primary-navigation">
          {visibleNav.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={activePage === label ? "nav-button active" : "nav-button"}
              aria-current={activePage === label ? "page" : undefined}
              onClick={() => {
                setActivePage(label);
                if (typeof window.matchMedia === "function" && window.matchMedia("(max-width: 820px)").matches) {
                  setNavigationCollapsed(true);
                }
              }}
              tabIndex={navigationCollapsed ? -1 : 0}
              type="button"
            >
              <Icon size={18} aria-hidden />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="nav-footer">
          <div className="nav-assurance">
            <ShieldCheck size={17} aria-hidden />
            <span><strong>Human-approved</strong><small>Automation prepares evidence; people decide.</small></span>
          </div>
          <div className="tenant-context" aria-label="Current tenant and environment">
            <Database size={16} aria-hidden />
            <span><strong>{tenantId}</strong><small>{config.environmentLabel}</small></span>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="top-rail">
          <button
            className="icon-button"
            aria-label="Toggle navigation"
            aria-controls="patchforge-primary-navigation"
            aria-expanded={!navigationCollapsed}
            onClick={() => setNavigationCollapsed((current) => !current)}
            type="button"
          >
            <PanelLeft size={18} aria-hidden />
          </button>
          <form className="global-command" onSubmit={handleGlobalSearchSubmit} role="search" aria-label="Global PatchForge search">
            <Search size={17} aria-hidden />
            <label className="sr-only" htmlFor="patchforge-global-search">Search PatchForge</label>
            <input
              id="patchforge-global-search"
              value={globalSearch}
              onChange={(event) => setGlobalSearch(event.target.value)}
              placeholder="Search CVE, vendor, product or asset…"
            />
          </form>
          <button type="button" className="header-command" aria-label="Open Ask PatchForge" onClick={() => setActivePage("Ask PatchForge")}>
            <MessageSquareText size={17} aria-hidden /> Ask PatchForge
          </button>
          <div className="header-context" aria-label="Session and source context">
            <span className={`source-recency ${sourceRunTone(state.sourceFeedState)}`}>
              <span className="status-dot" aria-hidden /> {sourceRunLabel(state.sourceFeedState)}
            </span>
            <button type="button" className="icon-button header-icon" aria-label="Open help and guidance" onClick={() => setActivePage("Guide")}>
              <CircleHelp size={18} aria-hidden />
            </button>
            <button type="button" className="icon-button header-icon notification-button" aria-label="Open review queue" onClick={() => setActivePage("Review & Approve")}>
              <Bell size={18} aria-hidden />
              {state.metrics.pending_review > 0 && <span className="notification-count">{Math.min(state.metrics.pending_review, 99)}</span>}
            </button>
            <div className="account-control" aria-label="Signed-in account">
              <span className="account-avatar">{accountInitials(session.accountName)}</span>
              <span><strong>{accountDisplayName(session.accountName)}</strong><small>{displayRole(session.roles)}</small></span>
            </div>
            <button type="button" className="icon-button header-icon" aria-label="Sign out" onClick={() => void session.signOut()}>
              <LogOut size={17} aria-hidden />
            </button>
          </div>
        </header>

        <div className={`content-grid${activePage === "Patch & CVE Catalogue" ? " catalogue-layout" : ""}`}>
          <section className="primary-panel" aria-label={activePage}>
            {activePage !== "Patch & CVE Catalogue" && <h2 className="sr-only">{activePage}</h2>}
            <OperationMessages message={operationMessage} error={operationError} />
            {selectedFinding && ["Action Center", "Finding Detail", "Review & Approve", "Reports"].includes(activePage) && (
              <FindingContextBanner finding={selectedFinding} />
            )}
            {activePage === "Patch & CVE Catalogue" && (
              <GlobalSecurityActionCenter
                state={state.securityActionCenter}
                metrics={state.metrics}
                finding={selectedFinding}
                query={globalSearch}
                setQuery={setGlobalSearch}
                filters={globalFilters}
                setFilters={setGlobalFilters}
                selectedRow={selectedGlobalRecord}
                onSearch={handleSearchSecurityActionCenter}
                onSelectCve={(row) => {
                  setSelectedVulnerabilityId(row.vulnerability_id || row.cve_id || row.advisory_id || "");
                  setSelectedAdvisoryId(row.advisory_id || "");
                  setSelectedCustomerAssetId(catalogueMatchedAssetId(row));
                }}
                canWrite={canWrite}
                canGeneratePacks={canGeneratePacks}
                onRefreshSourceFeed={(feedId) => handleRefreshSourceFeed(feedId, true)}
                onOpenAsk={() => setActivePage("Ask PatchForge")}
                onOpenReview={() => setActivePage("Review & Approve")}
                onOpenComparison={() => setActivePage("Customer Estate")}
                onPreparePack={(row) => handleGeneratePack({
                  vulnerabilityId: row.vulnerability_id || row.cve_id || row.advisory_id || row.id,
                  advisoryId: row.advisory_id || "",
                  assetId: catalogueMatchedAssetId(row),
                  strictContext: true
                })}
              />
            )}
            {activePage === "Vendor Catalogue" && (
              <VendorLens
                vendorLens={state.vendorLens}
                assetForm={networkAssetForm}
                setAssetForm={setNetworkAssetForm}
                advisoryForm={vendorAdvisoryForm}
                setAdvisoryForm={setVendorAdvisoryForm}
                question={vendorLensQuestion}
                setQuestion={setVendorLensQuestion}
                selectedAssetId={selectedCustomerAssetId}
                setSelectedAssetId={setSelectedCustomerAssetId}
                selectedAdvisoryId={selectedAdvisoryId}
                setSelectedAdvisoryId={setSelectedAdvisoryId}
                onSaveAsset={handleSaveNetworkAsset}
                onIngestAdvisory={handleIngestVendorLensAdvisory}
                onAssess={handleAssessVendorLens}
                onAsk={handleAskVendorLens}
                onRefreshSource={handleRefreshVendorLensSource}
                onComparePatch={handleCompareVendorLensPatch}
                canWrite={canWrite}
              />
            )}
            {activePage === "Customer Estate" && (
              <CustomerEstate
                state={state.customerEstate}
                discovery={state.discovery}
                vendorLens={state.vendorLens}
                deviceText={customerDeviceText}
                setDeviceText={setCustomerDeviceText}
                extractedAsset={extractedCustomerAsset}
                assetForm={networkAssetForm}
                setAssetForm={setNetworkAssetForm}
                selectedAssetId={selectedCustomerAssetId}
                setSelectedAssetId={setSelectedCustomerAssetId}
                selectedAdvisoryId={selectedAdvisoryId}
                setSelectedAdvisoryId={setSelectedAdvisoryId}
                patchCompareForm={patchCompareForm}
                setPatchCompareForm={setPatchCompareForm}
                latestMatch={state.latestCustomerMatch}
                latestComparison={activePatchComparison}
                onExtract={handleExtractCustomerAsset}
                onConfirmAsset={handleConfirmCustomerAsset}
                onMatch={handleMatchCustomerEstate}
                onPatchCompare={handleCustomerPatchCompare}
                onRegisterCollector={handleRegisterDiscoveryCollector}
                onCreateDiscoveryPolicy={handleCreateDiscoveryPolicy}
                onDownloadCollectorConfig={handleDownloadDiscoveryCollectorConfig}
                canWrite={canWrite}
              />
            )}
            {activePage === "Ask PatchForge" && (
              <AskPatchForge
                question={askQuestion}
                setQuestion={setAskQuestion}
                answer={state.latestAskPatchForge}
                selectedAssetId={selectedCustomerAssetId}
                selectedAdvisoryId={selectedAdvisoryId}
                latestComparison={activePatchComparison}
                agentStatus={state.openAiAgentStatus}
                agentGuidance={state.latestAgentGuidance}
                selectedVulnerabilityId={selectedVulnerabilityId}
                onAsk={handleAskPatchForge}
                onPatchCompare={handleCustomerPatchCompare}
                onGenerateReportPack={handleGeneratePack}
                onOpenReports={() => setActivePage("Reports")}
                onOpenCustomerEstate={() => setActivePage("Customer Estate")}
                onOpenVendorCatalogue={() => setActivePage("Vendor Catalogue")}
                onSelectCandidate={(candidate) => {
                  const advisoryId = candidateValue(candidate, "advisory_id", "cve", "cve_id", "id");
                  const vulnerabilityId = candidateValue(candidate, "cve", "cve_id", "vulnerability_id", "advisory_id", "id");
                  if (advisoryId) {
                    setSelectedAdvisoryId(advisoryId);
                  }
                  if (vulnerabilityId) {
                    setSelectedVulnerabilityId(vulnerabilityId);
                  }
                  setOperationMessage(advisoryId
                    ? `Selected ${advisoryId} for Ask PatchForge and Patch Compare.`
                    : "Candidate selection did not include an advisory ID.");
                }}
                onRefreshCandidateCatalogue={(candidate) => handleRefreshVendorLensSource(candidateValue(candidate, "vendor_id") || undefined)}
                canWrite={canWrite}
              />
            )}
            {activePage === "Action Center" && (
              <ActionCenter
                metrics={state.metrics}
                findings={state.findings}
                vulnerabilities={state.vulnerabilities}
                decisionPacks={state.decisionPacks}
                sourceFeedState={state.sourceFeedState}
                canWrite={canWrite}
                onSelectFinding={handleSelectFinding}
                onRefreshSourceFeed={handleRefreshSourceFeed}
              />
            )}
            {activePage === "Finding Detail" && (
              <FindingDetail
                finding={selectedFinding}
                vulnerabilities={state.vulnerabilities}
                onSelectFinding={handleSelectFinding}
                onAnalyse={handleAnalyseFinding}
                canWrite={canWrite}
              />
            )}
            {activePage === "Review & Approve" && (
              <ReviewApprove
                finding={selectedFinding}
                vulnerabilities={state.vulnerabilities}
                selectedVulnerabilityId={selectedVulnerabilityId}
                setSelectedVulnerabilityId={setSelectedVulnerabilityId}
                selectedPosture={selectedPosture}
                setSelectedPosture={setSelectedPosture}
                decisionPacks={state.decisionPacks}
                reports={state.reports}
                onAnalyse={handleAnalyseFinding}
                onGenerate={handleGeneratePack}
                onSraResearch={handleSraResearch}
                onDownloadReport={handleDownloadReport}
                sraResult={sraResult}
                canWrite={canWrite}
              />
            )}
            {activePage === "Reports" && (
              <ReportsPacks
                findings={state.findings}
                decisionPacks={state.decisionPacks}
                reports={state.reports}
                reportsPacks={state.reportsPacks}
                onGenerate={handleGeneratePack}
                onExportPack={handleExportPack}
                onDownloadReport={handleDownloadReport}
                canWrite={canGeneratePacks}
              />
            )}
            {activePage === "Command Center" && (
              <CommandCenter
                metrics={state.metrics}
                vulnerabilities={state.vulnerabilities}
                decisionPacks={state.decisionPacks}
                bayesian={state.bayesian}
                threatSummary={state.threatSummary}
                sourceFeedState={state.sourceFeedState}
                setActivePage={setActivePage}
              />
            )}
            {activePage === "Guide" && <Guide />}
            {activePage === "Vulnerability Queue" && (
              <VulnerabilityQueue
                vulnerabilities={state.vulnerabilities}
                form={vulnerabilityForm}
                setForm={setVulnerabilityForm}
                onIngest={handleIngest}
                canWrite={canWrite}
              />
            )}
            {activePage === "Asset & Service Exposure" && <AssetExposure assets={state.assets} services={state.services} />}
            {activePage === "Decision Workbench" && (
              <DecisionWorkbench
                vulnerabilities={state.vulnerabilities}
                selectedVulnerabilityId={selectedVulnerabilityId}
                setSelectedVulnerabilityId={setSelectedVulnerabilityId}
                selectedPosture={selectedPosture}
                setSelectedPosture={setSelectedPosture}
                onGenerate={handleGeneratePack}
                onBayesianAssess={handleBayesianAssess}
                bayesian={state.bayesian}
                canWrite={canWrite}
              />
            )}
            {activePage === "Emergency Patch" && <EmergencyPatch vulnerabilities={state.vulnerabilities} />}
            {activePage === "Risk Acceptances" && <RiskAcceptances decisionPacks={state.decisionPacks} />}
            {activePage === "Compensating Controls" && <CompensatingControls />}
            {activePage === "SRA Research" && <SraResearch onRun={handleSraResearch} result={sraResult} canWrite={canWrite} />}
            {activePage === "Evidence Catalogue" && <EvidenceCatalogue vulnerabilities={state.vulnerabilities} />}
            {activePage === "Decision Packs" && <DecisionPacks decisionPacks={state.decisionPacks} reports={state.reports} onExportPack={handleExportPack} onDownloadReport={handleDownloadReport} />}
            {activePage === "Source Feeds" && <SourceFeeds sourceFeedState={state.sourceFeedState} onRefresh={handleRefreshSourceFeed} canWrite={canWrite} />}
            {activePage === "Vendor & Threat Landscape" && <VendorThreatLandscape vendors={state.vendors} threatSummary={state.threatSummary} />}
            {activePage === "VendorLens" && (
              <VendorLens
                vendorLens={state.vendorLens}
                assetForm={networkAssetForm}
                setAssetForm={setNetworkAssetForm}
                advisoryForm={vendorAdvisoryForm}
                setAdvisoryForm={setVendorAdvisoryForm}
                question={vendorLensQuestion}
                setQuestion={setVendorLensQuestion}
                selectedAssetId={selectedCustomerAssetId}
                setSelectedAssetId={setSelectedCustomerAssetId}
                selectedAdvisoryId={selectedAdvisoryId}
                setSelectedAdvisoryId={setSelectedAdvisoryId}
                onSaveAsset={handleSaveNetworkAsset}
                onIngestAdvisory={handleIngestVendorLensAdvisory}
                onAssess={handleAssessVendorLens}
                onAsk={handleAskVendorLens}
                onRefreshSource={handleRefreshVendorLensSource}
                onComparePatch={handleCompareVendorLensPatch}
                canWrite={canWrite}
              />
            )}
            {activePage === "Admin" && (
              isAdmin ? <Admin
                tenantId={tenantId}
                setTenantId={setTenantId}
                adminEnvironment={adminEnvironment}
                setAdminEnvironment={setAdminEnvironment}
                adminTier={adminTier}
                setAdminTier={setAdminTier}
                adminHealth={state.adminHealth}
                agentStatus={state.openAiAgentStatus}
                onSave={handleSaveAdmin}
                purgeScopes={purgeScopes}
                setPurgeScopes={setPurgeScopes}
                purgeConfirm={purgeConfirm}
                setPurgeConfirm={setPurgeConfirm}
                latestPurgePlan={latestPurgePlan}
                onPreviewPurge={handlePreviewPurge}
                onExecutePurge={handleExecutePurge}
              /> : <PageBand icon={LockKeyhole} title="Admin" lines={["PatchForge.Admin role required", "Admin controls are read-only for non-admin users", "API app roles are enforced server-side"]} />
            )}
          </section>

          {activePage !== "Patch & CVE Catalogue" && (
            <aside className="utility-rail" aria-label="PatchForge utility rail">
              <UtilityRail session={session} metrics={state.metrics} decisionPacks={state.decisionPacks} sourceFeedState={state.sourceFeedState} adminHealth={state.adminHealth} />
            </aside>
          )}
        </div>
      </section>
    </main>
  );
}

function SignedOutShell({ session }: { session: PatchForgeAuthSession }) {
  return (
    <main className="app-shell signed-out">
      <aside className="side-nav" aria-label="PatchForge product boundary">
        <BrandLockup />
        <BoundaryPanel />
      </aside>
      <section className="workspace auth-workspace">
        <div className="auth-panel">
          <div className="auth-mark"><LockKeyhole size={30} aria-hidden /></div>
          <p className="eyebrow">Production | diiac.io | Entra ID</p>
          <h2>{PRODUCT_MARK}</h2>
          <p className="muted-copy">Access is restricted to assigned PatchForge app roles.</p>
          <button type="button" className="action-button large-action" onClick={() => void session.signIn()} disabled={session.status === "loading"}>
            <LogIn size={18} aria-hidden /> {session.status === "loading" ? "Connecting" : "Sign in with Microsoft"}
          </button>
        </div>
      </section>
    </main>
  );
}

function BrandLockup() {
  return (
    <div className="brand-lockup">
      <div className="brand-mark">
        <Binary size={24} aria-hidden />
      </div>
      <div>
        <p>{BRAND_MARK}</p>
        <h1>PatchForge Intelligence</h1>
      </div>
    </div>
  );
}

function BoundaryPanel() {
  return (
    <div className="boundary-panel">
      <LockKeyhole size={18} aria-hidden />
      <p>Turns CVE, exploit signal, vendor, patch, hotfix, and estate evidence into governed, signed action packs. No scanning, exploit content, deployment, or autonomous approvals.</p>
    </div>
  );
}

function OperationMessages({ message, error }: { message: string | null; error: string | null }) {
  return (
    <>
      {message && <div className="notice success"><CheckCircle2 size={16} aria-hidden /> {message}</div>}
      {error && <div className="notice error"><TriangleAlert size={16} aria-hidden /> {error}</div>}
    </>
  );
}

function FindingContextBanner({ finding }: { finding: FindingIntelligence }) {
  const product = finding.product || "Product pending";
  const scope = finding.exposure.unmapped_scope ? "Customer exposure unconfirmed" : "Customer exposure mapped";
  const approval = finding.recommendation.final_approval_issued || finding.latest_signed_pack?.final_approval_issued ? "Final approval issued" : "Final approval not issued";
  return (
    <section className="context-banner" aria-label="Current finding context">
      <ShieldAlert size={18} aria-hidden />
      <strong>{finding.vulnerability_id}</strong>
      <span>{product}</span>
      <span>Source-bound</span>
      <span>{scope}</span>
      <span>{approval}</span>
    </section>
  );
}

function NextActionCards() {
  const cards = [
    ["Confirm customer exposure", "Map affected assets, services, owner, and customer-facing status before a final remediation decision."],
    ["Attach vendor patch evidence", "Add reviewed patch notes, affected version mapping, testing evidence, and rollback plan."],
    ["Review source intelligence", "Accept, reject, or supersede CISA/CVE/vendor/SRA/agent records with a named reviewer event."],
    ["Generate customer pack", "Export the customer assurance pack only after it clearly states what can and cannot be claimed."],
    ["Request approval only after blockers close", "CAB, risk acceptance, patch closure, and customer remediation assurance remain human-approved."]
  ];
  return (
    <section className="wide-band next-actions">
      <div className="section-title">
        <h3>Next Actions</h3>
        <span className="pill amber">Human approval required</span>
      </div>
      <div className="next-action-grid">
        {cards.map(([title, detail], index) => (
          <article className="next-action-card" key={title}>
            <strong>{index + 1}</strong>
            <div>
              <h4>{title}</h4>
              <p>{detail}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function GlobalSecurityActionCenter({
  state,
  metrics,
  finding,
  query,
  setQuery,
  filters,
  setFilters,
  selectedRow,
  onSearch,
  onSelectCve,
  canWrite,
  canGeneratePacks,
  onRefreshSourceFeed,
  onOpenAsk,
  onOpenReview,
  onOpenComparison,
  onPreparePack
}: {
  state: SecurityActionCenterState;
  metrics: PatchForgeMetrics;
  finding: FindingIntelligence | null;
  query: string;
  setQuery: (value: string) => void;
  filters: { vendor: string; severity: string; customer_match: string; patch_available: string };
  setFilters: (value: { vendor: string; severity: string; customer_match: string; patch_available: string }) => void;
  selectedRow: SecurityActionCenterRow | null;
  onSearch: () => void;
  onSelectCve: (row: SecurityActionCenterRow) => void;
  canWrite: boolean;
  canGeneratePacks: boolean;
  onRefreshSourceFeed: (feedId: string) => void | Promise<void>;
  onOpenAsk: () => void;
  onOpenReview: () => void;
  onOpenComparison: () => void;
  onPreparePack: (row: SecurityActionCenterRow) => void;
}) {
  const [quickFilter, setQuickFilter] = useState<"all" | "review" | "exploited" | "matched" | "patch">("all");
  const rows = useMemo(() => collapseCatalogueRows(state.catalogue_rows || []), [state.catalogue_rows]);
  const filteredRows = useMemo(() => rows.filter((row) => {
    if (quickFilter === "review") {
      return !catalogueEvidenceVerified(row);
    }
    if (quickFilter === "exploited") {
      return Boolean(row.known_exploited || row.kev);
    }
    if (quickFilter === "matched") {
      return row.customer_match_count > 0;
    }
    if (quickFilter === "patch") {
      return Boolean(row.patch_available);
    }
    return true;
  }), [quickFilter, rows]);
  const rowsPage = usePagination(filteredRows, 8, `global-security-action-center-${quickFilter}`);
  const vendorOptions = state.filters?.vendors || [];
  const severityOptions = state.filters?.severities || [];
  const urgentActions = rows.filter((row) => /urgent|critical/i.test(String(row.urgency_posture || ""))).length;
  const matchedKev = rows.filter((row) => row.kev && row.customer_match_count > 0).length;
  const customerMatchedRecords = rows.filter((row) => row.customer_match_count > 0).length;
  const recordsNeedingEvidenceReview = Math.max(metrics.pending_review, rows.filter((row) => !catalogueEvidenceVerified(row)).length);
  const selectedFinding = finding && selectedRow && finding.vulnerability_id === catalogueRecordId(selectedRow) ? finding : null;

  return (
    <div className="catalogue-workspace-grid">
      <div className="catalogue-main">
        <header className="catalogue-page-header">
          <div className="catalogue-breadcrumb"><span>Security operations</span><ChevronRight size={14} aria-hidden /><span>Catalogue</span></div>
          <div className="catalogue-headline">
            <div>
              <h2>What needs attention today?</h2>
              <p>Prioritised from source evidence, active exploitation and your customer estate.</p>
            </div>
            <div className="catalogue-actions">
              <button type="button" className="action-button" aria-label="Refresh KEV intelligence" onClick={() => onRefreshSourceFeed("cisa-kev")} disabled={!canWrite}>
                <RefreshCw size={16} aria-hidden /> Refresh KEV
              </button>
              <button type="button" className="action-button secondary-action" onClick={() => onRefreshSourceFeed("first-epss")} disabled={!canWrite || !selectedRow}>
                <Radar size={16} aria-hidden /> Update selected EPSS
              </button>
            </div>
          </div>
          <p className="catalogue-recency">{catalogueGeneratedLabel(state.generated_at)}</p>
        </header>

        <CatalogueRunway row={selectedRow} />

        <section className="summary-grid" aria-label="Catalogue summary">
          <CatalogueSummaryCard icon={TriangleAlert} label="Urgent postures" value={urgentActions} detail="Source-derived urgency requiring review" tone="danger" />
          <CatalogueSummaryCard icon={ShieldCheck} label="KEV matched" value={matchedKev} detail="Matched to customer context" tone="teal" />
          <CatalogueSummaryCard icon={Network} label="Customer-matched records" value={customerMatchedRecords} detail="Scope still requires review" tone="steel" />
          <CatalogueSummaryCard icon={ClipboardCheck} label="Records needing evidence review" value={recordsNeedingEvidenceReview} detail="Pending or incomplete review" tone="amber" />
        </section>

        <section className="priority-queue">
          <div className="queue-heading">
            <div>
              <p className="eyebrow">Governed work queue</p>
              <h3>Priority action queue</h3>
            </div>
            <span className="queue-count">{filteredRows.length} record{filteredRows.length === 1 ? "" : "s"}</span>
          </div>

          <div className="catalogue-toolbar">
            <form className="queue-search" onSubmit={(event) => { event.preventDefault(); onSearch(); }} role="search" aria-label="Priority queue search">
              <label>
                <span className="sr-only">Search</span>
                <Search size={16} aria-hidden />
                <input aria-label="Search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search the priority queue…" />
              </label>
              <button type="submit" className="action-button secondary-action">Search</button>
            </form>
            <div className="catalogue-filter-grid">
              <label>Vendor<select value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })}><option value="">All vendors</option>{vendorOptions.map((item) => <option key={item.value} value={item.value}>{item.value}</option>)}</select></label>
              <label>Severity<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option>{severityOptions.map((item) => <option key={item.value} value={item.value}>{humanize(item.value)}</option>)}</select></label>
              <label>Customer match<select value={filters.customer_match} onChange={(event) => setFilters({ ...filters, customer_match: event.target.value })}><option value="">All records</option><option value="true">Matched</option><option value="false">Not matched</option></select></label>
              <label>Patch available<select value={filters.patch_available} onChange={(event) => setFilters({ ...filters, patch_available: event.target.value })}><option value="">All states</option><option value="true">Available</option><option value="false">Unknown or unavailable</option></select></label>
            </div>
          </div>

          <div className="quick-filter-row" role="group" aria-label="Quick filters">
            {([
              ["all", "All priority"],
              ["review", "Needs review"],
              ["exploited", "Known exploited"],
              ["matched", "Customer matched"],
              ["patch", "Patch available"]
            ] as const).map(([key, label]) => (
              <button key={key} type="button" className={`quick-filter${quickFilter === key ? " active" : ""}`} aria-pressed={quickFilter === key} onClick={() => setQuickFilter(key)}>
                {label}
              </button>
            ))}
          </div>

          <div className="table-scroll priority-table-scroll">
            <table className="data-table priority-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Vendor / product</th>
                  <th>Priority</th>
                  <th>Exploit signal</th>
                  <th>Customer exposure</th>
                  <th>Remediation</th>
                  <th>Evidence</th>
                  <th>Next action</th>
                </tr>
              </thead>
              <tbody>
                {rowsPage.items.map((row) => {
                  const selected = selectedRow?.id === row.id;
                  const priority = cataloguePriority(row);
                  return (
                    <tr className={`priority-row${selected ? " selected" : ""}`} aria-selected={selected} key={`${row.record_type}-${row.id}`}>
                      <td><button type="button" className="link-button" onClick={() => onSelectCve(row)}>{catalogueRecordId(row)}</button></td>
                      <td><span className="cell-stack"><strong>{row.vendor_name || "Unknown vendor"}</strong><small>{row.product_family || "Product pending"}</small></span></td>
                      <td><span className={`queue-status ${priority.tone}`}>{priority.label}</span></td>
                      <td><span className="cell-stack"><strong>{catalogueExploitSignal(row)}</strong><small>{catalogueEpssLabel(row.epss_score)}</small></span></td>
                      <td><span className="cell-stack"><strong>{catalogueCustomerScope(row)}</strong><small>{row.customer_match_count ? "Review matched scope" : "Estate mapping required"}</small></span></td>
                      <td><span className="cell-stack"><strong>{row.patch_available ? "Patch recorded" : "No fix confirmed"}</strong><small>{(row.fixed_versions || []).join(", ") || "Version evidence pending"}</small></span></td>
                      <td><span className={`evidence-state ${catalogueEvidenceVerified(row) ? "verified" : "pending"}`}>{catalogueEvidenceVerified(row) ? <CheckCircle2 size={15} aria-hidden /> : <Clock3 size={15} aria-hidden />}{catalogueEvidenceLabel(row)}</span></td>
                      <td><span className="cell-stack"><strong>{catalogueNextAction(row)}</strong><small>{row.final_approval_issued ? "Approval issued" : "Approval not issued"}</small></span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <PaginationControls {...rowsPage} label="patch and CVE catalogue rows" />
          {!rowsPage.items.length && <EmptyState title="No matching catalogue records" detail="Adjust the filters or refresh source intelligence to repopulate this view." />}
        </section>
      </div>

      <CatalogueIntelligencePanel
        row={selectedRow}
        finding={selectedFinding}
        canGeneratePacks={canGeneratePacks}
        onOpenAsk={() => { if (selectedRow) onSelectCve(selectedRow); onOpenAsk(); }}
        onOpenReview={() => { if (selectedRow) onSelectCve(selectedRow); onOpenReview(); }}
        onOpenComparison={() => { if (selectedRow) onSelectCve(selectedRow); onOpenComparison(); }}
        onPreparePack={onPreparePack}
      />
    </div>
  );
}

function CatalogueSummaryCard({ icon: Icon, label, value, detail, tone }: { icon: typeof Gauge; label: string; value: number; detail: string; tone: string }) {
  return (
    <article className={`summary-card ${tone}`}>
      <div className="summary-card-icon"><Icon size={21} aria-hidden /></div>
      <div><strong className="summary-card-value">{value}</strong><span>{label}</span></div>
      <small>{detail}</small>
    </article>
  );
}

function CatalogueRunway({ row }: { row: SecurityActionCenterRow | null }) {
  const matched = Boolean(row?.customer_match_count);
  const reviewed = Boolean(row && catalogueEvidenceVerified(row));
  const approved = Boolean(row?.final_approval_issued);
  const steps = [
    { label: "Detect", detail: row ? "Complete" : "Awaiting record", state: row ? "complete" : "current" },
    { label: "Match", detail: matched ? "Complete" : "Scope needed", state: matched ? "complete" : row ? "current" : "locked" },
    { label: "Review", detail: reviewed ? "Complete" : "Human review", state: reviewed ? "complete" : matched ? "current" : "locked" },
    { label: "Decide", detail: approved ? "Approved" : "Locked", state: approved ? "complete" : "locked" },
    { label: "Report", detail: approved ? "Approved pack available" : row ? "Pack can be prepared" : "Record required", state: approved ? "complete" : row ? "current" : "locked" }
  ];
  return (
    <ol className="catalogue-runway" aria-label="Decision workflow">
      {steps.map((step, index) => (
        <li className={`runway-step ${step.state}`} key={step.label}>
          <span className="runway-marker">{step.state === "complete" ? <CheckCircle2 size={18} aria-hidden /> : step.state === "locked" ? <LockKeyhole size={16} aria-hidden /> : index + 1}</span>
          <span><strong>{step.label}</strong><small>{step.detail}</small></span>
        </li>
      ))}
    </ol>
  );
}

function CatalogueIntelligencePanel({
  row,
  finding,
  canGeneratePacks,
  onOpenAsk,
  onOpenReview,
  onOpenComparison,
  onPreparePack
}: {
  row: SecurityActionCenterRow | null;
  finding: FindingIntelligence | null;
  canGeneratePacks: boolean;
  onOpenAsk: () => void;
  onOpenReview: () => void;
  onOpenComparison: () => void;
  onPreparePack: (row: SecurityActionCenterRow) => void;
}) {
  if (!row) {
    return <aside className="catalogue-intelligence-panel"><EmptyState title="Select a catalogue record" detail="Choose a CVE or advisory to see its decision context, evidence gaps, and next permitted action." /></aside>;
  }
  const reviewed = catalogueEvidenceVerified(row);
  const matched = row.customer_match_count > 0;
  const approved = Boolean(row.final_approval_issued);
  const reason = finding?.summary.why_now || catalogueWhyPrioritised(row);
  const customerContext = finding?.summary.what_it_affects || (matched ? `${row.customer_match_count} customer-matched record${row.customer_match_count === 1 ? "" : "s"} require scope review.` : "No customer estate match is confirmed yet.");
  const nextStep = finding?.recommendation.next_best_action || catalogueNextAction(row);
  const confidence = finding?.recommendation.confidence
    ? humanize(finding.recommendation.confidence)
    : reviewed
      ? "Reviewed source evidence"
      : "Confidence not recorded";
  const posture = row.urgency_posture && row.urgency_posture.toLowerCase() !== "unknown"
    ? humanize(row.urgency_posture)
    : cataloguePriority(row).label;
  return (
    <aside className="catalogue-intelligence-panel" aria-label="Selected catalogue intelligence">
      <header className="intelligence-panel-header">
        <p className="eyebrow">Selected decision context</p>
        <h2>{catalogueRecordId(row)}</h2>
        <p>{row.vendor_name} · {row.product_family || "Product pending"}</p>
      </header>

      <section className={`selected-posture ${cataloguePriority(row).tone}`}>
        <ShieldAlert size={24} aria-hidden />
        <div><strong>{posture}</strong><p>{reason}</p></div>
      </section>

      <div className="context-facts">
        <article><span className="fact-icon steel"><Network size={17} aria-hidden /></span><div><strong>Customer context</strong><p>{customerContext}</p></div></article>
        <article><span className={`fact-icon ${reviewed ? "trust" : "amber"}`}><BadgeCheck size={17} aria-hidden /></span><div><strong>Confidence</strong><p>{confidence} · {catalogueEvidenceLabel(row)}</p></div></article>
        <article><span className="fact-icon teal"><UserRound size={17} aria-hidden /></span><div><strong>Recommended next step</strong><p>{nextStep}</p></div></article>
      </div>

      <section className="decision-gate">
        <h3>Human gate timeline</h3>
        <DecisionGateStep label={reviewed ? "Source evidence verified" : "Source evidence needs review"} detail={humanize(row.review_state || "pending_review")} state={reviewed ? "complete" : "current"} />
        <DecisionGateStep label={matched ? reviewed ? "Customer scope recorded" : "Customer scope needs review" : "Customer scope not mapped"} detail={matched ? `${row.customer_match_count} matched record${row.customer_match_count === 1 ? "" : "s"}` : "Estate mapping required"} state={matched ? reviewed ? "complete" : "current" : "locked"} />
        <DecisionGateStep label="Accountable owner decision" detail="Named human decision required" state={reviewed && matched && !approved ? "current" : approved ? "complete" : "locked"} />
        <DecisionGateStep label={approved ? "Final approval issued" : "Final decision not issued"} detail={approved ? "Recorded by accountable approver" : "Approval not issued"} state={approved ? "complete" : "locked"} />
      </section>

      <div className="panel-actions">
        <button type="button" className="action-button" onClick={onOpenReview}><ClipboardCheck size={16} aria-hidden /> Open evidence review</button>
        <button type="button" className="action-button secondary-action" onClick={onOpenComparison}><Wrench size={16} aria-hidden /> Compare remediation</button>
        <button type="button" className="action-button secondary-action" aria-label="Ask PatchForge about selected record" onClick={onOpenAsk}><MessageSquareText size={16} aria-hidden /> Ask PatchForge</button>
        <button type="button" className="action-button pack-action" onClick={() => onPreparePack(row)} disabled={!canGeneratePacks}><FileCheck2 size={16} aria-hidden /> Prepare decision pack</button>
      </div>

      <div className="governance-callout"><LockKeyhole size={16} aria-hidden /><p>PatchForge prepares the evidence. An accountable human approves the decision.</p></div>
    </aside>
  );
}

function DecisionGateStep({ label, detail, state }: { label: string; detail: string; state: "complete" | "current" | "locked" }) {
  return (
    <div className={`gate-step gate-${state}`}>
      <span className="gate-marker">{state === "complete" ? <CheckCircle2 size={17} aria-hidden /> : state === "locked" ? <LockKeyhole size={14} aria-hidden /> : <Clock3 size={16} aria-hidden />}</span>
      <span><strong>{label}</strong><small>{detail}</small></span>
    </div>
  );
}

function collapseCatalogueRows(rows: SecurityActionCenterRow[]): SecurityActionCenterRow[] {
  const records = new Map<string, SecurityActionCenterRow>();
  for (const row of rows) {
    const key = catalogueRecordId(row).toLowerCase();
    const current = records.get(key);
    if (!current) {
      records.set(key, { ...row });
      continue;
    }
    const fixedVersions = [...new Set([...(current.fixed_versions || []), ...(row.fixed_versions || [])])];
    const affectedVersions = [...new Set([...(current.affected_versions || []), ...(row.affected_versions || [])])];
    const matches = [...(current.customer_matches || []), ...(row.customer_matches || [])]
      .filter((match, index, all) => {
        const assetId = String(match.asset_id || "");
        return !assetId || all.findIndex((candidate) => String(candidate.asset_id || "") === assetId) === index;
      });
    const epssScores = [current.epss_score, row.epss_score].filter((value): value is number => typeof value === "number");
    const epssPercentiles = [current.epss_percentile, row.epss_percentile].filter((value): value is number => typeof value === "number");
    records.set(key, {
      ...current,
      vulnerability_id: current.vulnerability_id || row.vulnerability_id,
      cve_id: current.cve_id || row.cve_id,
      advisory_id: current.advisory_id || row.advisory_id,
      affected_feature: current.affected_feature || row.affected_feature,
      affected_versions: affectedVersions,
      fixed_versions: fixedVersions,
      cvss_score: Math.max(current.cvss_score || 0, row.cvss_score || 0) || null,
      epss_score: epssScores.length ? Math.max(...epssScores) : null,
      epss_percentile: epssPercentiles.length ? Math.max(...epssPercentiles) : null,
      kev: Boolean(current.kev || row.kev),
      patch_available: Boolean(current.patch_available || row.patch_available),
      known_exploited: Boolean(current.known_exploited || row.known_exploited),
      review_state: conservativeReviewState(current.review_state, row.review_state),
      evidence_state: conservativeReviewState(current.evidence_state, row.evidence_state),
      customer_match_count: Math.max(current.customer_match_count || 0, row.customer_match_count || 0),
      customer_matches: matches,
      urgency_posture: current.urgency_posture || row.urgency_posture,
      applicability_posture: current.applicability_posture || row.applicability_posture,
      final_approval_issued: Boolean(current.final_approval_issued || row.final_approval_issued),
      last_refreshed: newestTimestamp(current.last_refreshed, row.last_refreshed)
    });
  }
  return [...records.values()];
}

function conservativeReviewState(left?: string, right?: string): string | undefined {
  const values = [left, right].filter((value): value is string => Boolean(value));
  const trusted = new Set(["reviewed", "verified", "accepted", "accepted_positive", "accepted_positive_evidence"]);
  return values.find((value) => !trusted.has(value.trim().toLowerCase())) || values[0];
}

function newestTimestamp(left?: string | null, right?: string | null): string | null {
  if (!left) return right || null;
  if (!right) return left;
  return Date.parse(right) > Date.parse(left) ? right : left;
}

function catalogueRecordId(row: SecurityActionCenterRow): string {
  return row.cve_id || row.advisory_id || row.vulnerability_id || row.id;
}

function catalogueMatchedAssetId(row: SecurityActionCenterRow): string {
  const match = row.customer_matches?.find((item) => typeof item.asset_id === "string" && item.asset_id.trim());
  return match ? String(match.asset_id) : "";
}

function cataloguePriority(row: SecurityActionCenterRow): { key: "urgent" | "critical" | "high" | "medium" | "standard"; label: string; tone: string } {
  if ((row.known_exploited || row.kev) && row.customer_match_count > 0) {
    return { key: "urgent", label: "Urgent", tone: "danger" };
  }
  const severity = String(row.severity || "").toLowerCase();
  if (severity === "critical") {
    return { key: "critical", label: "Critical", tone: "danger" };
  }
  if (severity === "high") {
    return { key: "high", label: "High", tone: "amber" };
  }
  if (severity === "medium") {
    return { key: "medium", label: "Medium", tone: "steel" };
  }
  return { key: "standard", label: humanize(severity || "standard"), tone: "steel" };
}

function catalogueExploitSignal(row: SecurityActionCenterRow): string {
  if (row.known_exploited) {
    return "Known exploited";
  }
  if (row.kev) {
    return "KEV listed";
  }
  return row.epss_score !== null && row.epss_score !== undefined ? "EPSS signal" : "No reviewed signal";
}

function catalogueEpssLabel(value?: number | null): string {
  if (value === null || value === undefined) {
    return "EPSS not recorded";
  }
  const percent = value <= 1 ? value * 100 : value;
  return `EPSS ${percent.toFixed(percent >= 10 ? 0 : 1)}%`;
}

function catalogueCustomerScope(row: SecurityActionCenterRow): string {
  return row.customer_match_count ? `${row.customer_match_count} matched record${row.customer_match_count === 1 ? "" : "s"}` : "No confirmed match";
}

function catalogueEvidenceVerified(row: SecurityActionCenterRow): boolean {
  const states = [row.review_state, row.evidence_state]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  const trusted = new Set(["reviewed", "verified", "accepted", "accepted_positive", "accepted_positive_evidence"]);
  return states.length > 0 && states.every((state) => trusted.has(state));
}

function catalogueEvidenceLabel(row: SecurityActionCenterRow): string {
  if (catalogueEvidenceVerified(row)) {
    return "Verified evidence";
  }
  if (/rejected/i.test(String(row.review_state || row.evidence_state || ""))) {
    return "Evidence rejected";
  }
  return "Needs review";
}

function catalogueNextAction(row: SecurityActionCenterRow): string {
  if (!catalogueEvidenceVerified(row)) {
    return "Review evidence";
  }
  if (!row.customer_match_count) {
    return "Map estate scope";
  }
  if (!row.patch_available) {
    return "Confirm remediation";
  }
  return row.final_approval_issued ? "Monitor closure" : "Request human decision";
}

function catalogueWhyPrioritised(row: SecurityActionCenterRow): string {
  if ((row.known_exploited || row.kev) && row.customer_match_count) {
    return `Active exploitation evidence and ${row.customer_match_count} customer match${row.customer_match_count === 1 ? "" : "es"} make this a priority review.`;
  }
  if (row.known_exploited || row.kev) {
    return "Active exploitation evidence requires customer scope confirmation.";
  }
  return "PatchForge is waiting for reviewed evidence and confirmed customer scope before a decision can be issued.";
}

function catalogueGeneratedLabel(generatedAt: string): string {
  if (!generatedAt) {
    return "Catalogue refresh time is not available.";
  }
  const parsed = new Date(generatedAt);
  return Number.isNaN(parsed.getTime()) ? "Catalogue refresh time is not available." : `Catalogue generated ${parsed.toLocaleString()}`;
}

function VendorsExploitsRegister({
  state,
  query,
  setQuery,
  filters,
  setFilters,
  onSearch,
  onSelectCve
}: {
  state: SecurityActionCenterState;
  query: string;
  setQuery: (value: string) => void;
  filters: { vendor: string; severity: string; customer_match: string; patch_available: string };
  setFilters: (value: { vendor: string; severity: string; customer_match: string; patch_available: string }) => void;
  onSearch: () => void;
  onSelectCve: (row: SecurityActionCenterRow) => void;
}) {
  const rows = state.catalogue_rows || [];
  const rowsPage = usePagination(rows, 10, "vendors-exploits-register");
  const vendorOptions = state.filters?.vendors || [];
  const severityOptions = state.filters?.severities || [];
  return (
    <>
      <div className="metric-grid">
        <MetricCard icon={Database} label="Vendors" value={state.groups.length || state.vendors?.length || 0} tone="steel" />
        <MetricCard icon={ShieldAlert} label="Known exploited" value={rows.filter((row) => row.known_exploited).length} tone="amber" />
        <MetricCard icon={Radar} label="KEV records" value={rows.filter((row) => row.kev).length} tone="danger" />
        <MetricCard icon={Wrench} label="Patch available" value={rows.filter((row) => row.patch_available).length} tone="trust" />
      </div>

      <section className="wide-band search-console">
        <div className="section-title">
          <div>
            <p className="eyebrow">Defensive vendor, CVE, exploit-signal, patch, and hotfix evidence</p>
            <h3>Vendors & Exploits Register</h3>
          </div>
          <span className="pill amber">No exploit mechanics</span>
        </div>
        <div className="search-row">
          <label className="wide-input">
            <span>Search</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Vendor, product, CVE, KEV, EPSS, affected or fixed version" />
          </label>
          <button type="button" className="action-button" onClick={onSearch}>
            <Search size={16} aria-hidden /> Search
          </button>
        </div>
        <div className="filter-grid">
          <label>Vendor<select value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })}><option value="">All vendors</option>{vendorOptions.map((item) => <option key={item.value} value={item.value}>{item.value}</option>)}</select></label>
          <label>Severity<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option>{severityOptions.map((item) => <option key={item.value} value={item.value}>{humanize(item.value)}</option>)}</select></label>
          <label>Customer estate<select value={filters.customer_match} onChange={(event) => setFilters({ ...filters, customer_match: event.target.value })}><option value="">All</option><option value="true">Matched</option><option value="false">No match</option></select></label>
          <label>Fix state<select value={filters.patch_available} onChange={(event) => setFilters({ ...filters, patch_available: event.target.value })}><option value="">All</option><option value="true">Patch or hotfix</option><option value="false">No fix recorded</option></select></label>
        </div>
      </section>

      <section className="data-band table-band">
        <div className="section-title">
          <h3>Defensive Exploit Signals & Patch Evidence</h3>
          <span className="pill teal">{rows.length} source-bound record(s)</span>
        </div>
        <div className="table-scroll">
          <table className="data-table catalogue-table">
            <thead>
              <tr>
                <th>CVE / Advisory</th>
                <th>Vendor</th>
                <th>Product</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>Exploited</th>
                <th>Affected versions</th>
                <th>Fixed versions</th>
                <th>Patch status</th>
                <th>Customer estate</th>
                <th>Evidence confidence</th>
                <th>Unresolved gaps</th>
              </tr>
            </thead>
            <tbody>
              {rowsPage.items.map((row) => (
                <tr key={`${row.record_type}-${row.id}`}>
                  <td><button type="button" className="link-button" onClick={() => onSelectCve(row)}>{row.cve_id || row.advisory_id || row.id}</button></td>
                  <td>{row.vendor_name}</td>
                  <td>{row.product_family || "Pending"}</td>
                  <td><span className={`pill ${severityTone(row.severity)}`}>{humanize(row.severity)}</span></td>
                  <td>{row.cvss_score ?? "n/a"}</td>
                  <td>{row.epss_score ?? "n/a"}</td>
                  <td>{row.kev ? "Yes" : "No"}</td>
                  <td>{row.known_exploited ? "Active/known signal" : "No reviewed signal"}</td>
                  <td>{(row.affected_versions || []).join(", ") || "Pending"}</td>
                  <td>{(row.fixed_versions || []).join(", ") || "Pending"}</td>
                  <td>{row.patch_available ? "Patch/hotfix recorded" : "No fix recorded"}</td>
                  <td>{row.customer_match_count ? `${row.customer_match_count} match(es)` : "No match"}</td>
                  <td>{humanize(row.evidence_state || row.source_state || "referenced")}</td>
                  <td>{row.customer_match_count ? "Review exposure evidence" : "Map estate evidence"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationControls {...rowsPage} label="register records" />
        {!rows.length && <EmptyState title="No register records" detail="Sync public sources or ingest vendor advisories to populate the defensive register." />}
      </section>
    </>
  );
}

function PatchHotfixCompare({
  vendorLens,
  selectedAssetId,
  setSelectedAssetId,
  selectedAdvisoryId,
  setSelectedAdvisoryId,
  patchCompareForm,
  setPatchCompareForm,
  latestComparison,
  onPatchCompare,
  canWrite
}: {
  vendorLens: VendorLensState;
  selectedAssetId: string;
  setSelectedAssetId: (value: string) => void;
  selectedAdvisoryId: string;
  setSelectedAdvisoryId: (value: string) => void;
  patchCompareForm: { current_version: string; proposed_version: string };
  setPatchCompareForm: (value: { current_version: string; proposed_version: string }) => void;
  latestComparison: VendorLensPatchComparison | null;
  onPatchCompare: () => void;
  canWrite: boolean;
}) {
  const asset = vendorLens.assets.find((item) => item.asset_id === selectedAssetId) || vendorLens.assets[0] || null;
  const advisory = vendorLens.advisories.find((item) => item.advisory_id === selectedAdvisoryId) || vendorLens.advisories[0] || null;
  const options = [
    ["Direct patch", "High risk reduction", "Human CAB/change approval required"],
    ["Hotfix", "Targeted remediation", "CISO review required for severe exposure"],
    ["Major upgrade", "Broad remediation", "Planned window and rollback review required"],
    ["Workaround", "Temporary reduction", "Evidence and expiry required"],
    ["Compensating controls", "Exposure reduction", "Control owner and monitoring evidence required"],
    ["Defer with exception", "No remediation", "CISO approval and risk-owner expiry required"]
  ];
  return (
    <>
      <section className="wide-band review-runway">
        <div>
          <p className="eyebrow">Governed remediation comparison</p>
          <h3>Patch / Hotfix Compare</h3>
          <p className="muted-copy">Compare direct patch, hotfix, major upgrade, workaround, compensating controls, and exception deferral without approving or deploying production changes.</p>
        </div>
        <div className="finding-score">
          <strong>{latestComparison ? "Compared" : "Ready"}</strong>
          <small>No autonomous approval</small>
        </div>
      </section>

      <div className="split-grid">
        <section className="data-band">
          <h3>Inputs</h3>
          <div className="form-grid compact-form">
            <label>Asset<select value={selectedAssetId} onChange={(event) => setSelectedAssetId(event.target.value)}><option value="">Select asset</option>{vendorLens.assets.map((item) => <option key={item.asset_id} value={item.asset_id}>{item.asset_id} | {item.product_family} {item.firmware_version}</option>)}</select></label>
            <label>Advisory / CVE<select value={selectedAdvisoryId} onChange={(event) => setSelectedAdvisoryId(event.target.value)}><option value="">Select advisory</option>{vendorLens.advisories.map((item) => <option key={item.advisory_id} value={item.advisory_id}>{item.cve || item.advisory_id}</option>)}</select></label>
            <label>Current version<input value={patchCompareForm.current_version} onChange={(event) => setPatchCompareForm({ ...patchCompareForm, current_version: event.target.value })} /></label>
            <label>Proposed version<input value={patchCompareForm.proposed_version} onChange={(event) => setPatchCompareForm({ ...patchCompareForm, proposed_version: event.target.value })} /></label>
          </div>
          <button type="button" className="action-button" onClick={onPatchCompare} disabled={!canWrite || !selectedAssetId || !selectedAdvisoryId}>
            <Layers3 size={16} aria-hidden /> Run Patch Compare
          </button>
          <div className="insight-list">
            <StatusLine label="Selected asset" value={asset?.asset_id || "No asset selected"} tone="steel" />
            <StatusLine label="Selected advisory" value={advisory?.cve || advisory?.advisory_id || "No advisory selected"} tone="amber" />
            <StatusLine label="Human approval" value="Required" tone="amber" />
          </div>
        </section>
        <section className="data-band">
          <h3>Governed Candidate</h3>
          <StatusLine label="Current version" value={humanize(latestComparison?.current_version_status || "not compared")} tone="amber" />
          <StatusLine label="Target version" value={humanize(latestComparison?.target_version_status || "not compared")} tone="teal" />
          <StatusLine label="CISO approval" value={advisory?.known_exploited ? "Required" : "Conditional"} tone="amber" />
          <StatusLine label="Production approval" value="Never autonomous" tone="steel" />
          <p className="muted-copy">{latestComparison?.ciso_summary || "Run comparison to prepare a CISO/CAB summary from source-bound advisory and customer asset evidence."}</p>
        </section>
      </div>

      <section className="data-band">
        <div className="section-title">
          <h3>Action Options</h3>
          <span className="pill amber">All production-impacting options require human change approval</span>
        </div>
        <div className="decision-option-grid">
          {options.map(([title, value, detail]) => (
            <StatusLine key={title} label={title} value={value} detail={detail} tone={title === "Defer with exception" ? "amber" : "teal"} />
          ))}
        </div>
      </section>
    </>
  );
}

function CustomerEstate({
  state,
  discovery,
  vendorLens,
  deviceText,
  setDeviceText,
  extractedAsset,
  assetForm,
  setAssetForm,
  selectedAssetId,
  setSelectedAssetId,
  selectedAdvisoryId,
  setSelectedAdvisoryId,
  patchCompareForm,
  setPatchCompareForm,
  latestMatch,
  latestComparison,
  onExtract,
  onConfirmAsset,
  onMatch,
  onPatchCompare,
  onRegisterCollector,
  onCreateDiscoveryPolicy,
  onDownloadCollectorConfig,
  canWrite
}: {
  state: CustomerEstateState;
  discovery: AssetDiscoveryOverview | null;
  vendorLens: VendorLensState;
  deviceText: string;
  setDeviceText: (value: string) => void;
  extractedAsset: CustomerAssetExtraction | null;
  assetForm: typeof emptyNetworkAssetForm;
  setAssetForm: (value: typeof emptyNetworkAssetForm) => void;
  selectedAssetId: string;
  setSelectedAssetId: (value: string) => void;
  selectedAdvisoryId: string;
  setSelectedAdvisoryId: (value: string) => void;
  patchCompareForm: { current_version: string; proposed_version: string };
  setPatchCompareForm: (value: { current_version: string; proposed_version: string }) => void;
  latestMatch: CustomerEstateMatch | null;
  latestComparison: VendorLensPatchComparison | null;
  onExtract: () => void;
  onConfirmAsset: () => void;
  onMatch: () => void;
  onPatchCompare: () => void;
  onRegisterCollector: () => void;
  onCreateDiscoveryPolicy: () => void;
  onDownloadCollectorConfig: () => void;
  canWrite: boolean;
}) {
  const assetsPage = usePagination(state.assets.length ? state.assets : vendorLens.assets, 6, "customer-estate-assets");
  const matches = latestMatch?.matches || state.exposure_matches || [];
  const matchPage = usePagination(matches, 6, "customer-estate-matches");
  const assets = state.assets.length ? state.assets : vendorLens.assets;
  const advisories = vendorLens.advisories;

  return (
    <>
      <section className="wide-band">
        <div className="section-title">
          <div>
            <p className="eyebrow">Asset discovery</p>
            <h3>Collector Intake</h3>
          </div>
          <span className="pill teal">Outbound-only | review required</span>
        </div>
        <div className="split-grid">
          <StatusLine label="Collectors" value={String(discovery?.metrics.collector_count || 0)} tone={discovery?.metrics.collector_count ? "trust" : "amber"} />
          <StatusLine label="Enabled policies" value={String(discovery?.metrics.enabled_policy_count || 0)} tone={discovery?.metrics.enabled_policy_count ? "trust" : "steel"} />
          <StatusLine label="Imported assets" value={String(discovery?.metrics.collector_imported_asset_count || 0)} tone="teal" />
          <StatusLine label="Pending review" value={String(discovery?.metrics.pending_review_asset_count || 0)} tone="amber" />
        </div>
        <div className="report-actions">
          <button type="button" className="action-button" onClick={onRegisterCollector} disabled={!canWrite}>
            <ServerCog size={16} aria-hidden /> Register Collector
          </button>
          <button type="button" className="action-button secondary-action" onClick={onCreateDiscoveryPolicy} disabled={!canWrite}>
            <ListFilter size={16} aria-hidden /> Create Policy
          </button>
          <button type="button" className="action-button" onClick={onDownloadCollectorConfig} disabled={!canWrite}>
            <Download size={16} aria-hidden /> Download Collector Config
          </button>
        </div>
        <div className="split-grid">
          <section>
            <h4>Supported categories</h4>
            <p className="muted-copy">{(discovery?.categories || discoveryCollectorCategories).map(humanize).join(", ")}</p>
          </section>
          <section>
            <h4>Collector boundary</h4>
            <p className="muted-copy">Collector imports are source-bound evidence. PatchForge does not scan for exploits, deploy patches, mutate production systems, approve CAB, or accept risk.</p>
          </section>
        </div>
        {discovery?.recent_runs?.[0] && (
          <div className="insight-list">
            <StatusLine label="Latest import" value={`${discovery.recent_runs[0].imported_asset_count} imported / ${discovery.recent_runs[0].rejected_asset_count} rejected`} tone={discovery.recent_runs[0].rejected_asset_count ? "amber" : "trust"} />
            <StatusLine label="Run status" value={humanize(discovery.recent_runs[0].status)} tone="teal" />
          </div>
        )}
      </section>

      <section className="wide-band">
        <div className="section-title">
          <div>
            <p className="eyebrow">Minimal input assistant</p>
            <h3>Describe a Device</h3>
          </div>
          <span className="pill amber">Evidence state: user stated, unreviewed</span>
        </div>
        <label className="stacked-input">
          <span>Describe a device, product, version, features, and exposure.</span>
          <textarea rows={3} value={deviceText} onChange={(event) => setDeviceText(event.target.value)} />
        </label>
        <div className="report-actions">
          <button type="button" className="action-button" onClick={onExtract} disabled={!canWrite}>
            <Search size={16} aria-hidden /> Extract Fields
          </button>
          <button type="button" className="action-button secondary-action" onClick={onConfirmAsset} disabled={!canWrite}>
            <CheckCircle2 size={16} aria-hidden /> Confirm Asset
          </button>
          <button type="button" className="action-button" onClick={onMatch} disabled={!canWrite || !assets.length}>
            <Network size={16} aria-hidden /> Run CVE Match
          </button>
        </div>
      </section>

      <div className="split-grid">
        <section className="data-band">
          <h3>Confirm Extracted Fields</h3>
          <div className="form-grid compact-form">
            <label>Vendor<input value={assetForm.vendor_id} onChange={(event) => setAssetForm({ ...assetForm, vendor_id: event.target.value })} /></label>
            <label>Product family<input value={assetForm.product_family} onChange={(event) => setAssetForm({ ...assetForm, product_family: event.target.value })} /></label>
            <label>Model<input value={assetForm.model} onChange={(event) => setAssetForm({ ...assetForm, model: event.target.value })} /></label>
            <label>Firmware<input value={assetForm.firmware_version} onChange={(event) => setAssetForm({ ...assetForm, firmware_version: event.target.value })} /></label>
            <label>Management exposure<input value={assetForm.management_exposure} onChange={(event) => setAssetForm({ ...assetForm, management_exposure: event.target.value })} /></label>
            <label>Enabled features<input value={assetForm.enabled_features} onChange={(event) => setAssetForm({ ...assetForm, enabled_features: event.target.value })} /></label>
            <label>Disabled features<input value={assetForm.disabled_features} onChange={(event) => setAssetForm({ ...assetForm, disabled_features: event.target.value })} /></label>
            <label>Evidence state<select value={assetForm.evidence_state} onChange={(event) => setAssetForm({ ...assetForm, evidence_state: event.target.value })}><option>user_stated_unreviewed</option><option>referenced</option><option>accepted_positive_evidence</option></select></label>
          </div>
          {extractedAsset && (
            <div className="insight-list">
              <StatusLine label="Extraction confidence" value={String(extractedAsset.extraction_confidence ?? "n/a")} tone="teal" />
              <StatusLine label="Human review" value={extractedAsset.human_review_required ? "Required" : "Required"} tone="amber" />
              <StatusLine label="Final approval" value={extractedAsset.final_approval_issued ? "Issued" : "False" } tone="amber" />
            </div>
          )}
        </section>

        <section className="data-band">
          <h3>Patch Compare</h3>
          <div className="form-grid compact-form">
            <label>Asset<select value={selectedAssetId} onChange={(event) => setSelectedAssetId(event.target.value)}><option value="">Select asset</option>{assets.map((asset) => <option key={asset.asset_id} value={asset.asset_id}>{asset.asset_id} | {asset.product_family} {asset.firmware_version}</option>)}</select></label>
            <label>Advisory / CVE<select value={selectedAdvisoryId} onChange={(event) => setSelectedAdvisoryId(event.target.value)}><option value="">Select advisory</option>{advisories.map((advisory) => <option key={advisory.advisory_id} value={advisory.advisory_id}>{advisory.cve || advisory.advisory_id}</option>)}</select></label>
            <label>Current version<input value={patchCompareForm.current_version} onChange={(event) => setPatchCompareForm({ ...patchCompareForm, current_version: event.target.value })} /></label>
            <label>Proposed version<input value={patchCompareForm.proposed_version} onChange={(event) => setPatchCompareForm({ ...patchCompareForm, proposed_version: event.target.value })} /></label>
          </div>
          <button type="button" className="action-button" onClick={onPatchCompare} disabled={!canWrite || !selectedAssetId || !selectedAdvisoryId}>
            <Layers3 size={16} aria-hidden /> Run Patch Compare
          </button>
          {latestComparison && (
            <div className="insight-list">
              <StatusLine label="Current version" value={humanize(latestComparison.current_version_affected || latestComparison.current_version_status)} tone="amber" />
              <StatusLine label="Proposed version" value={humanize(latestComparison.proposed_version_remediates || latestComparison.target_version_status)} tone="teal" />
              <StatusLine label="Final approval" value={latestComparison.final_approval_issued ? "Issued" : "False"} tone="amber" />
            </div>
          )}
        </section>
      </div>

      <section className="data-band table-band">
        <div className="section-title">
          <h3>Devices & Assets</h3>
          <span className="pill teal">{assets.length} asset(s)</span>
        </div>
        <div className="table-scroll">
          <table className="data-table estate-assets-table">
            <thead><tr><th>Customer</th><th>Site</th><th>Vendor</th><th>Product family</th><th>Model</th><th>Firmware</th><th>Internet-facing</th><th>Management exposure</th><th>Enabled features</th><th>Disabled features</th><th>Evidence state</th><th>Matching CVEs</th><th>Highest urgency</th><th>Owner</th><th>Last checked</th></tr></thead>
            <tbody>
              {assetsPage.items.map((asset) => {
                const assetMatches = matches.filter((match) => String(match.asset_id) === String(asset.asset_id));
                return (
                  <tr key={asset.asset_id}>
                    <td>{asset.customer || asset.tenant_id || "Customer pending"}</td>
                    <td>{asset.site || "Not recorded"}</td>
                    <td>{asset.vendor_id}</td>
                    <td>{asset.product_family || "Pending"}</td>
                    <td>{asset.model || "Pending"}</td>
                    <td>{asset.firmware_version || "Pending"}</td>
                    <td>{asset.internet_facing ? "Yes" : "No"}</td>
                    <td>{humanize(asset.management_exposure || "unknown")}</td>
                    <td>{(asset.enabled_features || []).join(", ") || "None recorded"}</td>
                    <td>{(asset.disabled_features || []).join(", ") || "None recorded"}</td>
                    <td>{humanize(asset.evidence_state || "referenced")}</td>
                    <td>{assetMatches.length}</td>
                    <td>{humanize(assetMatches[0]?.urgency_posture || "unknown")}</td>
                    <td>{asset.service_owner || "Owner pending"}</td>
                    <td>{asset.updated_at ? new Date(asset.updated_at).toLocaleDateString() : "Pending"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <PaginationControls {...assetsPage} label="customer estate assets" />
      </section>

      <section className="data-band table-band">
        <div className="section-title">
          <h3>Exposure Matches</h3>
          <span className="pill amber">{matches.length} governed match(es)</span>
        </div>
        <div className="table-scroll">
          <table className="data-table exposure-table">
            <thead><tr><th>CVE / advisory</th><th>Asset</th><th>Product</th><th>Feature</th><th>Applicability</th><th>Urgency</th><th>Evidence required</th><th>Final approval</th></tr></thead>
            <tbody>
              {matchPage.items.map((match, index) => (
                <tr key={`${match.assessment_id || "match"}-${index}`}>
                  <td>{String(match.cve || match.advisory_id || "Pending")}</td>
                  <td>{String(match.asset_id || "Pending")}</td>
                  <td>{String(match.product_family || "Pending")}</td>
                  <td>{String(match.affected_feature || "Pending")}</td>
                  <td>{humanize(String(match.applicability_posture || "unknown"))}</td>
                  <td>{humanize(String(match.urgency_posture || "unknown"))}</td>
                  <td>{(match.evidence_required || []).join(", ") || "Reviewed evidence required"}</td>
                  <td>{match.final_approval_issued ? "Issued" : "False"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationControls {...matchPage} label="customer estate matches" />
        {!matches.length && <EmptyState title="No exposure matches yet" detail="Add or select a device, then run current CVE/advisory matching." />}
      </section>
    </>
  );
}

function AskPatchForge({
  question,
  setQuestion,
  answer,
  selectedAssetId,
  selectedAdvisoryId,
  latestComparison,
  agentStatus,
  agentGuidance,
  selectedVulnerabilityId,
  onAsk,
  onPatchCompare,
  onGenerateReportPack,
  onOpenReports,
  onOpenCustomerEstate,
  onOpenVendorCatalogue,
  onSelectCandidate,
  onRefreshCandidateCatalogue,
  canWrite
}: {
  question: string;
  setQuestion: (value: string) => void;
  answer: AskPatchForgeAnswer | null;
  selectedAssetId: string;
  selectedAdvisoryId: string;
  latestComparison: VendorLensPatchComparison | null;
  agentStatus: OpenAiAgentStatus | null;
  agentGuidance: AgentGuidanceSnapshot | null;
  selectedVulnerabilityId: string;
  onAsk: () => void;
  onPatchCompare: () => void;
  onGenerateReportPack: () => void;
  onOpenReports: () => void;
  onOpenCustomerEstate: () => void;
  onOpenVendorCatalogue: () => void;
  onSelectCandidate: (candidate: Record<string, unknown>) => void;
  onRefreshCandidateCatalogue: (candidate: Record<string, unknown>) => void;
  canWrite: boolean;
}) {
  const response = answer?.response;
  const candidateMatches = (answer?.candidate_matches || []).slice(0, 5);
  const agentReady = Boolean(agentStatus?.enabled && agentStatus.configured);
  const agentLabel = agentStatus?.enabled ? (agentStatus.configured ? "Ready" : "Unavailable") : "Runtime disabled";
  const agentTone = agentReady ? "teal" : agentStatus?.enabled ? "amber" : "steel";
  const answerMode = agentGuidance?.status === "verified" ? "Deterministic + verified AI" : "Deterministic";
  return (
    <>
      <section className="wide-band ask-panel">
        <div className="section-title">
          <div>
            <p className="eyebrow">Natural-language advisor</p>
            <h3>Ask PatchForge</h3>
          </div>
          <span className="pill amber">Advisory-only | human approval required</span>
        </div>
        <label className="stacked-input">
          <span>Ask about vendor, model, feature, CVE, patch, or evidence.</span>
          <textarea rows={4} value={question} onChange={(event) => setQuestion(event.target.value)} />
        </label>
        <p className="boundary-copy">
          {selectedAdvisoryId
            ? `Using selected advisory context ${selectedAdvisoryId}${selectedAssetId ? ` and asset ${selectedAssetId}` : ""}.`
            : "No CVE/advisory is selected. Include a CVE/advisory ID, select one in Patch & CVE Catalogue or Vendor Catalogue, or run Customer Estate matching first."}
        </p>
        <p className="boundary-copy">Defensive-use only: PatchForge can explain impact, exposure, patch, hotfix, mitigation, evidence, and reporting choices. It refuses exploit code, payloads, bypass steps, and attacker playbooks.</p>
        <div className="report-actions">
          <button type="button" className="action-button" onClick={onAsk} disabled={!canWrite}>
            <MessageSquareText size={16} aria-hidden /> Ask PatchForge
          </button>
          <button type="button" className="action-button secondary-action" onClick={onPatchCompare} disabled={!canWrite || !selectedAssetId || !selectedAdvisoryId}>
            <Layers3 size={16} aria-hidden /> Run Patch Compare
          </button>
        </div>
        {latestComparison && <p className="boundary-copy">Patch Compare attached: current {humanize(latestComparison.current_version_affected || latestComparison.current_version_status)}, proposed {humanize(latestComparison.proposed_version_remediates || latestComparison.target_version_status)}. Final approval false.</p>}
        <AskRunPlan
          selectedAssetId={selectedAssetId}
          selectedAdvisoryId={selectedAdvisoryId}
          selectedVulnerabilityId={selectedVulnerabilityId}
          hasAnswer={Boolean(response)}
          hasPatchComparison={Boolean(latestComparison)}
          candidateCount={candidateMatches.length}
          canWrite={canWrite}
          onOpenCustomerEstate={onOpenCustomerEstate}
          onOpenVendorCatalogue={onOpenVendorCatalogue}
          onPatchCompare={onPatchCompare}
          onGenerateReportPack={onGenerateReportPack}
          onOpenReports={onOpenReports}
        />
        <div className="agent-status-strip">
          <StatusLine label="Displayed answer" value={answerMode} tone={agentGuidance?.status === "verified" ? "teal" : "trust"} />
          <StatusLine label="OpenAI agent" value={agentLabel} tone={agentTone} detail={agentStatus?.model || "Status loads from protected API"} />
          <StatusLine label="Verifier" value={agentStatus?.verifier_required ? "Required" : "Required"} tone="amber" />
          <StatusLine label="Agent authority" value="Advisory only" tone="amber" />
        </div>
      </section>

      {response ? (
        <section className="data-band advisor-response">
          <div className="section-title">
            <h3>Response</h3>
            <span className="pill amber">Final approval false</span>
          </div>
          <AdvisorBlock title="Short Answer" content={response.short_answer} />
          <CandidateMatchList candidates={candidateMatches} onSelectCandidate={onSelectCandidate} onRefreshCandidateCatalogue={onRefreshCandidateCatalogue} canWrite={canWrite} />
          <AdvisorBlock title="Current Governed Posture" content={humanize(response.current_governed_posture)} />
          <AdvisorBlock title="Why" content={response.why} />
          <AdvisorList title="What We Know" items={response.what_we_know} />
          <AdvisorList title="What We Do Not Know" items={response.what_we_do_not_know} />
          <AdvisorList title="Evidence Needed" items={response.evidence_needed} />
          <AdvisorBlock title="Recommended Next Action" content={response.recommended_next_action} />
          <AdvisorBlock title="Decision Not Allowed Yet" content={response.decision_not_allowed_yet} />
          <div className="insight-list">
            <StatusLine label="Human Approval Required" value={response.human_approval_required ? "Yes" : "Yes"} tone="amber" />
            <StatusLine label="Final Approval Issued" value={response.final_approval_issued ? "True" : "False"} tone="amber" />
          </div>
          <section className="advisor-agent-panel">
            <div className="section-title compact-title">
              <h4>Optional AI-Assisted Answer</h4>
              <span className={`pill ${agentGuidance?.status === "verified" ? "teal" : "steel"}`}>{agentGuidance?.status ? humanize(agentGuidance.status) : "Not used"}</span>
            </div>
            {agentGuidance?.status === "verified" && agentGuidance.output ? (
              <>
                <AdvisorBlock title="Verifier Status" content={humanize(agentGuidance.verifier_status)} />
                <AdvisorBlock title="Recommended Next Action" content={agentGuidance.output.recommended_next_action || "Attach reviewed evidence and request human review."} />
                <AdvisorBlock title="Decision Not Allowed Yet" content={agentGuidance.output.decision_not_allowed_yet || response.decision_not_allowed_yet} />
              </>
            ) : (
              <div className="agent-readiness-grid">
                <StatusLine label="Customer-facing answer" value="Deterministic answer active" tone="trust" />
                <StatusLine label="AI assistance" value={agentLabel} tone={agentTone} />
                <StatusLine label="Fallback" value={agentGuidance?.fallback?.message ? "Recorded" : "Deterministic"} tone="steel" detail={agentGuidance?.fallback?.message || "Verified AI guidance appears only after runtime enablement and verifier pass."} />
              </div>
            )}
          </section>
        </section>
      ) : (
        <EmptyState title="No advisor response yet" detail="Ask a governed PatchForge question. The response will stay advisory-only and will not approve, deploy, or accept risk." />
      )}
    </>
  );
}

function AskRunPlan({
  selectedAssetId,
  selectedAdvisoryId,
  selectedVulnerabilityId,
  hasAnswer,
  hasPatchComparison,
  candidateCount,
  canWrite,
  onOpenCustomerEstate,
  onOpenVendorCatalogue,
  onPatchCompare,
  onGenerateReportPack,
  onOpenReports
}: {
  selectedAssetId: string;
  selectedAdvisoryId: string;
  selectedVulnerabilityId: string;
  hasAnswer: boolean;
  hasPatchComparison: boolean;
  candidateCount: number;
  canWrite: boolean;
  onOpenCustomerEstate: () => void;
  onOpenVendorCatalogue: () => void;
  onPatchCompare: () => void;
  onGenerateReportPack: () => void;
  onOpenReports: () => void;
}) {
  const selectedContext = selectedAdvisoryId || selectedVulnerabilityId;
  const runPlanItems: Array<{ title: string; detail: string; icon: typeof Search; actionLabel: string; onClick: () => void; disabled?: boolean }> = [
    {
      title: "Find the right CVE or patch",
      detail: selectedContext
        ? `Selected ${selectedContext}. PatchForge can now explain impact, urgency, evidence gaps, and next actions against that item.`
        : candidateCount
          ? `${candidateCount} candidate CVE, advisory, or patch scope matches are available below. Select one before comparing or reporting.`
          : "Use the catalogue or ask a vendor/product question. PatchForge will offer candidate CVEs, advisories, or patch scopes when it can match them.",
      icon: Search,
      actionLabel: "Open Catalogue",
      onClick: onOpenVendorCatalogue
    },
    {
      title: "Confirm customer impact",
      detail: selectedAssetId
        ? `Using estate asset ${selectedAssetId}. Feature, exposure, firmware, and management-plane evidence still need review.`
        : "Capture the customer device, firmware, enabled features, exposure, and evidence references so urgency is understandable.",
      icon: ServerCog,
      actionLabel: "Customer Estate",
      onClick: onOpenCustomerEstate
    },
    {
      title: "Compare the patch or mitigation",
      detail: hasPatchComparison
        ? "Patch Compare is attached, including current version, proposed version, security delta, operational delta, and evidence still needed."
        : "Run Patch Compare after selecting an advisory and asset to see fixed-version evidence, operational risk, rollback needs, and must-do posture.",
      icon: Layers3,
      actionLabel: "Run Patch Compare",
      onClick: onPatchCompare,
      disabled: !canWrite || !selectedAssetId || !selectedAdvisoryId
    },
    {
      title: "Create the decision pack",
      detail: hasAnswer
        ? "Generate the signed governance pack for customer, CAB, board, or steering group reporting. Final approval remains false until named human approval."
        : "Ask PatchForge first so the pack includes the latest governed explanation, impact, risks, evidence needs, and recommended next action.",
      icon: FileCheck2,
      actionLabel: "Generate Signed Pack",
      onClick: onGenerateReportPack,
      disabled: !canWrite || !selectedVulnerabilityId
    },
    {
      title: "Run stakeholder reports",
      detail: "Use Reports for customer packs, board vulnerability summaries, CAB decision reports, evidence appendices, and signed ZIP exports.",
      icon: FileText,
      actionLabel: "Reports",
      onClick: onOpenReports
    }
  ];

  return (
    <section className="wide-band next-actions ask-run-plan" aria-label="Ask PatchForge run plan">
      <div className="section-title compact-title">
        <div>
          <p className="eyebrow">End-to-end governed flow</p>
          <h3>Run Plan</h3>
        </div>
        <span className="pill amber">advisory-only</span>
      </div>
      <div className="next-action-grid vendorlens-next-grid">
        {runPlanItems.map(({ title, detail, icon: Icon, actionLabel, onClick, disabled }) => (
          <button key={title} type="button" className="next-action-card clickable-card" onClick={onClick} disabled={disabled}>
            <Icon size={18} aria-hidden />
            <span>
              <h4>{title}</h4>
              <p>{detail}</p>
              <small>{actionLabel}</small>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

function CandidateMatchList({
  candidates,
  onSelectCandidate,
  onRefreshCandidateCatalogue,
  canWrite
}: {
  candidates: Array<Record<string, unknown>>;
  onSelectCandidate: (candidate: Record<string, unknown>) => void;
  onRefreshCandidateCatalogue: (candidate: Record<string, unknown>) => void;
  canWrite: boolean;
}) {
  if (!candidates.length) {
    return null;
  }
  return (
    <div className="advisor-block candidate-match-panel">
      <h4>Candidate CVEs / Patches / Catalogue Scopes</h4>
      <div className="candidate-match-list">
        {candidates.map((candidate) => {
          const id = candidateValue(candidate, "advisory_id", "cve", "cve_id", "id") || "candidate advisory";
          const cve = candidateValue(candidate, "cve", "cve_id");
          const candidateType = candidateValue(candidate, "candidate_type");
          const selectable = candidate.selectable !== false && candidateType !== "vendor_catalogue" && Boolean(cve || candidateValue(candidate, "advisory_id"));
          const product = [candidateValue(candidate, "vendor_name"), candidateValue(candidate, "product_family"), candidateValue(candidate, "model")].filter(Boolean).join(" ");
          const fixedVersions = candidateList(candidate.fixed_versions);
          const patchAvailable = Boolean(candidate.patch_available);
          const patchText = patchAvailable
            ? `Patch evidence available${fixedVersions.length ? `: ${fixedVersions.join(", ")}` : ""}`
            : candidateType === "vendor_catalogue" ? "Refresh source-bound catalogue before selection" : "Patch evidence not confirmed";
          return (
            <article className="candidate-match-item" key={id}>
              <div>
                <strong>{cve || id}</strong>
                <span>{product || "Product pending"}{candidateValue(candidate, "affected_feature") ? ` | ${candidateValue(candidate, "affected_feature")}` : ""}</span>
                <small>{humanize(candidateValue(candidate, "severity") || "unknown")} severity | {humanize(candidateValue(candidate, "urgency_posture") || "unknown")} | {patchText}</small>
                {candidateValue(candidate, "selection_prompt") && <small>{candidateValue(candidate, "selection_prompt")}</small>}
              </div>
              {selectable ? (
                <button type="button" className="action-button secondary-action" onClick={() => onSelectCandidate(candidate)} disabled={!canWrite} aria-label={`Use advisory ${id}`}>
                  <CheckCircle2 size={16} aria-hidden /> Use
                </button>
              ) : (
                <button type="button" className="action-button secondary-action" onClick={() => onRefreshCandidateCatalogue(candidate)} disabled={!canWrite || !candidateValue(candidate, "vendor_id")} aria-label={`Refresh catalogue ${candidateValue(candidate, "vendor_name") || id}`}>
                  <RefreshCw size={16} aria-hidden /> Refresh
                </button>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
}

function AdvisorBlock({ title, content }: { title: string; content: string }) {
  return <div className="advisor-block"><h4>{title}</h4><p>{content}</p></div>;
}

function AdvisorList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="advisor-block">
      <h4>{title}</h4>
      {(items || []).length ? items.map((item) => <p key={item}>{item}</p>) : <p>Not recorded.</p>}
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, tone }: { icon: typeof Gauge; label: string; value: number | string; tone: string }) {
  return (
    <article className={`metric-card ${tone}`}>
      <Icon size={20} aria-hidden />
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function ActionCenter({
  metrics,
  findings,
  vulnerabilities,
  decisionPacks,
  sourceFeedState,
  canWrite,
  onSelectFinding,
  onRefreshSourceFeed
}: {
  metrics: PatchForgeMetrics;
  findings: FindingIntelligence[];
  vulnerabilities: VulnerabilityRecord[];
  decisionPacks: DecisionPackRecord[];
  sourceFeedState: SourceFeedState;
  canWrite: boolean;
  onSelectFinding: (vulnerabilityId: string, page?: PageKey) => void;
  onRefreshSourceFeed: (feedId: string) => void;
}) {
  const metricCards = [
    { label: "Findings to govern", value: metrics.vulnerability_count, tone: "steel", icon: ListFilter },
    { label: "Known exploited", value: metrics.known_exploited, tone: "amber", icon: ShieldAlert },
    { label: "Critical exposure", value: metrics.critical_exposure, tone: "danger", icon: TriangleAlert },
    { label: "Signed packs", value: metrics.signed_packs || decisionPacks.length, tone: "trust", icon: FileCheck2 }
  ];
  const findingsPage = usePagination(findings, 4, "action-findings");

  return (
    <>
      <div className="metric-grid">
        {metricCards.map(({ label, value, tone, icon: Icon }) => (
          <article className={`metric-card ${tone}`} key={label}>
            <Icon size={20} aria-hidden />
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>

      <section className="wide-band action-hero">
        <div>
          <p className="eyebrow">Automated governance analysis, human-approved decisions</p>
          <h3>PatchForge has already translated the queue into decision-ready work.</h3>
          <p className="muted-copy">
            The engine reviews source-bound intelligence, exposure signals, Bayesian advisory output, vendor context, and signed-pack state. The user journey is to understand the finding, approve or withhold the governance decision, then export a board/CAB pack.
          </p>
        </div>
        <div className="hero-actions">
          <button type="button" className="action-button" onClick={() => onRefreshSourceFeed("cisa-kev")} disabled={!canWrite}>
            <RefreshCw size={16} aria-hidden /> Refresh KEV
          </button>
          <button type="button" className="action-button secondary-action" onClick={() => onRefreshSourceFeed("first-epss")} disabled={!canWrite || !vulnerabilities.length}>
            <Radar size={16} aria-hidden /> Refresh EPSS
          </button>
        </div>
      </section>
      <NextActionCards />

      <div className="finding-grid">
        {findingsPage.items.map((finding) => (
          <article className="finding-card" key={finding.vulnerability_id}>
            <div className="finding-card-head">
              <span className={`pill ${severityTone(finding.severity)}`}>{humanize(finding.severity || "unknown")}</span>
              <span className="pill teal">{postureLabel(finding)}</span>
            </div>
            <h3>{finding.vulnerability_id}</h3>
            <p>{finding.summary.executive_readout}</p>
            <div className="insight-list">
              <StatusLine label="Next action" value={shortValue(finding.recommendation.next_best_action)} tone="trust" />
              <StatusLine label="Evidence gaps" value={String(finding.evidence.gaps.length)} tone={finding.evidence.gaps.length ? "amber" : "trust"} />
              <StatusLine label="Exploitability" value={finding.exploitability.known_exploited ? "Known exploited" : "Source-bound"} tone={finding.exploitability.known_exploited ? "danger" : "steel"} />
            </div>
            <div className="report-actions">
              <button type="button" className="action-button" onClick={() => onSelectFinding(finding.vulnerability_id, "Finding Detail")}>
                <ShieldAlert size={16} aria-hidden /> Understand
              </button>
              <button type="button" className="action-button secondary-action" onClick={() => onSelectFinding(finding.vulnerability_id, "Review & Approve")}>
                <ClipboardCheck size={16} aria-hidden /> Review
              </button>
            </div>
          </article>
        ))}
      </div>

      <PaginationControls {...findingsPage} label="findings" />

      {!findingsPage.items.length && (
        <EmptyState
          title="No governed findings yet"
          detail={`Refresh live public intelligence or ingest a real finding. ${sourceFeedState.feeds.length} public source feeds are configured and all outputs remain source-bound pending review.`}
        />
      )}
    </>
  );
}

function FindingDetail({
  finding,
  vulnerabilities,
  onSelectFinding,
  onAnalyse,
  canWrite
}: {
  finding: FindingIntelligence | null;
  vulnerabilities: VulnerabilityRecord[];
  onSelectFinding: (vulnerabilityId: string, page?: PageKey) => void;
  onAnalyse: () => void;
  canWrite: boolean;
}) {
  if (!finding) {
    return (
      <EmptyState
        title="No finding selected"
        detail={vulnerabilities.length ? "Select a finding from Action Center to open its plain-English decision view." : "Refresh live intelligence or ingest a real record first."}
      />
    );
  }

  return (
    <>
      <section className="wide-band finding-brief">
        <div>
          <p className="eyebrow">{finding.vendor || "Vendor pending"} | {finding.product || "Product pending"}</p>
          <h3>{finding.vulnerability_id}: {finding.title}</h3>
          <p>{finding.summary.plain_english}</p>
        </div>
        <div className="finding-score">
          <span className={`pill ${severityTone(finding.severity)}`}>{humanize(finding.severity)}</span>
          <strong>{postureLabel(finding)}</strong>
          <small>{humanize(finding.recommendation.confidence)} confidence</small>
        </div>
      </section>
      <NextActionCards />

      <div className="split-grid">
        <section className="data-band narrative-panel">
          <h3>Why This Matters</h3>
          <p>{finding.summary.why_now}</p>
          <p>{finding.summary.operational_risk}</p>
        </section>
        <section className="data-band narrative-panel">
          <h3>Exploitability Intelligence</h3>
          <p>{finding.exploitability.safe_description}</p>
          {finding.exploitability.kev_epss_interpretation && <p>{finding.exploitability.kev_epss_interpretation}</p>}
          <p className="boundary-copy">{finding.exploitability.prohibited_detail}</p>
        </section>
      </div>

      <section className="wide-band">
        <div className="section-title">
          <h3>Affected Scope</h3>
          <span className={finding.exposure.unmapped_scope ? "pill amber" : "pill trust"}>{finding.exposure.unmapped_scope ? "Mapping incomplete" : "Mapped"}</span>
        </div>
        <p className="muted-copy">{finding.summary.what_it_affects}</p>
        <div className="split-grid scope-readout">
          <section>
            <h4>Services</h4>
            {finding.exposure.affected_services.map((service) => (
              <StatusLine key={service.service_id} label={service.service_name} value={service.customer_facing ? "Customer-facing" : humanize(service.service_tier)} tone={service.customer_facing ? "amber" : "steel"} />
            ))}
            {!finding.exposure.affected_services.length && <p className="muted-copy">No reviewed service mapping attached.</p>}
          </section>
          <section>
            <h4>Assets</h4>
            {finding.exposure.affected_assets.map((asset) => (
              <StatusLine key={asset.asset_id} label={asset.asset_name} value={humanize(asset.exposure)} tone={asset.exposure?.toLowerCase().includes("internet") ? "amber" : "steel"} />
            ))}
            {!finding.exposure.affected_assets.length && <p className="muted-copy">No reviewed asset mapping attached.</p>}
          </section>
        </div>
      </section>

      <section className="wide-band">
        <div className="section-title">
          <h3>Decision Options</h3>
          <button type="button" className="action-button" onClick={onAnalyse} disabled={!canWrite}>
            <Radar size={16} aria-hidden /> Re-run Analysis
          </button>
        </div>
        <div className="decision-option-grid">
          {finding.decision_options.map((option) => (
            <article className={option.recommended ? "decision-option recommended" : "decision-option"} key={option.posture}>
              <span className={option.recommended ? "pill trust" : "pill steel"}>{humanize(option.current_status || (option.recommended ? "recommended" : "available"))}</span>
              <h4>{humanize(option.posture)}</h4>
              <p>{option.reason || option.when_to_choose}</p>
              <small>Evidence: {(option.required_evidence || option.evidence_needed).join(", ") || "Reviewed evidence required"}</small>
              <small>Approval: {option.required_approval || (option.approval_needed ? "Required" : "Not required at this stage")}</small>
            </article>
          ))}
        </div>
        <button type="button" className="action-button large-action" onClick={() => onSelectFinding(finding.vulnerability_id, "Review & Approve")}>
          <ClipboardCheck size={16} aria-hidden /> Continue to Review
        </button>
      </section>
    </>
  );
}

function ReviewApprove({
  finding,
  vulnerabilities,
  selectedVulnerabilityId,
  setSelectedVulnerabilityId,
  selectedPosture,
  setSelectedPosture,
  decisionPacks,
  reports,
  onAnalyse,
  onGenerate,
  onSraResearch,
  onDownloadReport,
  sraResult,
  canWrite
}: {
  finding: FindingIntelligence | null;
  vulnerabilities: VulnerabilityRecord[];
  selectedVulnerabilityId: string;
  setSelectedVulnerabilityId: (value: string) => void;
  selectedPosture: string;
  setSelectedPosture: (value: string) => void;
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  onAnalyse: () => void;
  onGenerate: () => void;
  onSraResearch: () => void;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
  sraResult: Record<string, unknown> | null;
  canWrite: boolean;
}) {
  const latestPack = finding?.latest_signed_pack
    ? decisionPacks.find((pack) => pack.pack_id === finding.latest_signed_pack?.pack_id) || null
    : decisionPacks.find((pack) => pack.vulnerability_id === finding?.vulnerability_id) || null;
  const boardReport = reports.find((report) => report.report_type === "board_vulnerability_remediation_summary") || reports[0];
  const cabReport = reports.find((report) => report.report_type === "cab_patch_decision_report") || reports[1] || boardReport;

  return (
    <>
      <section className="wide-band review-runway">
        <div>
          <p className="eyebrow">Decision runway</p>
          <h3>{finding ? `${finding.vulnerability_id}: ${postureLabel(finding)}` : "Select a finding to review"}</h3>
          <p className="muted-copy">
            PatchForge performs the analysis, keeps agent and source output advisory-only, and leaves the accountable decision to the user. Use this page to compile the signed pack and export professional DOCX/PDF reports.
          </p>
        </div>
        <div className="decision-controls compact-controls">
          <label>
            Finding
            <select value={selectedVulnerabilityId} onChange={(event) => setSelectedVulnerabilityId(event.target.value)}>
              <option value="">Select ingested record</option>
              {vulnerabilities.map((item) => <option key={item.vulnerability_id} value={item.vulnerability_id}>{item.vulnerability_id}</option>)}
            </select>
          </label>
          <label>
            Governance posture
            <select value={selectedPosture} onChange={(event) => setSelectedPosture(event.target.value)}>
              {postures.map((posture) => <option key={posture} value={posture}>{humanize(posture)}</option>)}
            </select>
          </label>
        </div>
      </section>
      {finding && <NextActionCards />}

      <div className="split-grid">
        <section className="data-band">
          <h3>Automated Governance Analysis Completed</h3>
          <p className="boundary-copy">{finding?.recommendation.approval_notice || "Human approval remains required. PatchForge does not approve CAB decisions, risk acceptance, patch deployment, or closure autonomously."}</p>
          {(finding?.automation.completed || ["Select a finding to load analysis."]).map((item) => (
            <p className="rail-note" key={item}><CheckCircle2 size={15} aria-hidden /> {item}</p>
          ))}
        </section>
        <section className="data-band">
          <h3>Human Decisions Required</h3>
          {(finding?.automation.remaining_human_decisions || ["Human approval cannot be automated."]).map((item) => (
            <p className="rail-note" key={item}><TriangleAlert size={15} aria-hidden /> {item}</p>
          ))}
        </section>
      </div>

      <section className="wide-band">
        <div className="section-title">
          <h3>Execute Governed Outputs</h3>
          <span className="pill trust">DOCX / PDF only</span>
        </div>
        <div className="report-actions">
          <button type="button" className="action-button" onClick={onAnalyse} disabled={!selectedVulnerabilityId || !canWrite}>
            <Radar size={16} aria-hidden /> Refresh Analysis
          </button>
          <button type="button" className="action-button secondary-action" onClick={onSraResearch} disabled={!selectedVulnerabilityId || !canWrite}>
            <Radar size={16} aria-hidden /> Run SRA Advisory
          </button>
          <button type="button" className="action-button" onClick={onGenerate} disabled={!selectedVulnerabilityId || !canWrite}>
            <FileCheck2 size={16} aria-hidden /> Generate Signed Pack
          </button>
          <button type="button" className="action-button" onClick={() => latestPack && boardReport && onDownloadReport(latestPack.pack_id, boardReport.report_type, "docx")} disabled={!latestPack || !boardReport}>
            <FileText size={16} aria-hidden /> Board DOCX
          </button>
          <button type="button" className="action-button" onClick={() => latestPack && cabReport && onDownloadReport(latestPack.pack_id, cabReport.report_type, "pdf")} disabled={!latestPack || !cabReport}>
            <Download size={16} aria-hidden /> CAB PDF
          </button>
        </div>
        <div className="split-grid">
          <StatusLine label="Latest signed pack" value={latestPack?.pack_id || "Generate after review"} tone={latestPack ? "trust" : "amber"} />
          <StatusLine label="Final approval" value={latestPack?.final_approval_issued ? "Issued" : "Not issued"} tone={latestPack?.final_approval_issued ? "trust" : "amber"} />
          <StatusLine label="SRA output" value={sraResult ? "Advisory returned" : "Not run this session"} tone="teal" />
          <StatusLine label="Automated approval" value="Blocked" tone="amber" />
        </div>
      </section>

      {!canWrite && <EmptyState title="Read-only role" detail="Review, pack generation, and report actions require a PatchForge write role." />}
    </>
  );
}

function ReportsPacks({
  findings,
  decisionPacks,
  reports,
  reportsPacks,
  onGenerate,
  onExportPack,
  onDownloadReport,
  canWrite
}: {
  findings: FindingIntelligence[];
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  reportsPacks: ReportsPacksState;
  onGenerate: () => void;
  onExportPack: (packId: string) => void;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
  canWrite: boolean;
}) {
  const preExport = reportsPacks.pre_export_state || {};
  const qualityReviews = preExport.report_quality_reviews || [];
  const sortedPacks = newestDecisionPacks(decisionPacks);
  const latestPack = sortedPacks[0];
  return (
    <>
      <section className="wide-band report-brief">
        <div>
          <p className="eyebrow">Reports</p>
          <h3>Board, CAB, customer, and technical evidence outputs generated from signed packs.</h3>
          <p className="muted-copy">Exports show pack ID, baseline, renderer commit, image tag, evidence state, customer context, VendorLens context, report currency, and final approval state before download.</p>
        </div>
        <div className="report-pack-selector">
          <button type="button" className="action-button" onClick={onGenerate} disabled={!canWrite || !findings.length}>
            <FileCheck2 size={16} aria-hidden /> Generate Signed Pack
          </button>
          <span className="pill trust">{sortedPacks.filter((pack) => pack.verification?.verified).length} verified packs</span>
          <span className="pill teal">{findings.length} analysed findings</span>
        </div>
      </section>
      <section className="data-band">
        <div className="section-title">
          <h3>Pre-Export Check</h3>
          <span className="pill amber">{latestPack?.final_approval_issued ? "Final approval issued" : "Final approval false"}</span>
        </div>
        <div className="split-grid">
          <StatusLine label="Pack ID" value={String(preExport.pack_id || latestPack?.pack_id || "Generate a pack")} tone={latestPack ? "trust" : "amber"} />
          <StatusLine label="Baseline" value={String(preExport.baseline || latestPack?.product_baseline || "Not recorded by runtime")} tone="steel" />
          <StatusLine label="Renderer commit" value={String(preExport.renderer_commit || latestPack?.report_renderer_commit || "not recorded")} tone="steel" />
          <StatusLine label="Image tag" value={String(preExport.image_tag || latestPack?.report_renderer_image_tag || "not recorded")} tone="steel" />
          <StatusLine label="Evidence state" value={humanize(String(preExport.evidence_state || "evidence_review_required"))} tone="amber" />
          <StatusLine label="VendorLens context" value={preExport.vendorlens_context_included ? "Included" : "Not attached"} tone={preExport.vendorlens_context_included ? "teal" : "amber"} />
          <StatusLine label="Customer context" value={preExport.customer_context_included ? "Included" : "Not attached"} tone={preExport.customer_context_included ? "teal" : "amber"} />
          <StatusLine label="Verification" value={humanize(String(preExport.verification_state || (latestPack?.verification?.verified ? "verified" : "pending_or_not_recorded")))} tone={latestPack?.verification?.verified ? "trust" : "amber"} />
        </div>
        <p className="boundary-copy">{String(preExport.report_current_stale_warning || "Reports are generated from the selected signed pack state and current evidence still requires review.")}</p>
      </section>
      <section className="data-band">
        <div className="section-title">
          <h3>Report Content QA</h3>
          <span className={`pill ${qualityReviews.every((review) => review.status === "PASS") && qualityReviews.length ? "trust" : "amber"}`}>{qualityReviews.length ? `${qualityReviews.filter((review) => review.status === "PASS").length}/${qualityReviews.length} PASS` : "Run after pack generation"}</span>
        </div>
        <div className="quality-grid">
          {qualityReviews.map((review) => (
            <article className="quality-item" key={review.review_id}>
              <strong>{humanize(review.report_type)}</strong>
              <span className={`pill ${review.status === "PASS" ? "trust" : "amber"}`}>{review.status}</span>
              <p>{review.checks.filter((check) => check.status === "pass").length} of {review.checks.length} deterministic content checks passed. Final approval {review.final_approval_issued ? "issued" : "false"}.</p>
            </article>
          ))}
        </div>
        {!qualityReviews.length && <p className="boundary-copy">Content QA appears after a signed pack exists. It checks audience fit, known/unknown clarity, specific evidence gaps, metadata, final approval state, and governance-safe wording.</p>}
      </section>
      <DecisionPacks decisionPacks={sortedPacks} reports={reports} onExportPack={onExportPack} onDownloadReport={onDownloadReport} />
      <Reports decisionPacks={sortedPacks} reports={reports} onDownloadReport={onDownloadReport} />
    </>
  );
}

function CommandCenter({
  metrics,
  vulnerabilities,
  decisionPacks,
  bayesian,
  threatSummary,
  sourceFeedState,
  setActivePage
}: {
  metrics: PatchForgeMetrics;
  vulnerabilities: VulnerabilityRecord[];
  decisionPacks: DecisionPackRecord[];
  bayesian: BayesianAssessment | null;
  threatSummary: ThreatLandscapeSummary | null;
  sourceFeedState: SourceFeedState;
  setActivePage: (page: PageKey) => void;
}) {
  const metricCards = [
    { label: "Critical exposure", value: metrics.critical_exposure, tone: "danger", icon: TriangleAlert },
    { label: "Known exploited", value: metrics.known_exploited, tone: "amber", icon: ShieldAlert },
    { label: "Patch overdue", value: metrics.patch_overdue, tone: "warning", icon: Clock3 },
    { label: "Pending review", value: metrics.pending_review, tone: "steel", icon: ListFilter },
    { label: "Signed packs", value: metrics.signed_packs, tone: "trust", icon: FileCheck2 },
    { label: "Live source runs", value: metrics.source_feed_runs ?? sourceFeedState.recent_runs.length, tone: "teal", icon: RefreshCw }
  ];
  const topQueue = vulnerabilities.slice(0, 3);

  return (
    <>
      <div className="metric-grid">
        {metricCards.map(({ label, value, tone, icon: Icon }) => (
          <article className={`metric-card ${tone}`} key={label}>
            <Icon size={20} aria-hidden />
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>

      <section className="wide-band">
        <div className="section-title">
          <h3>Top Governed Actions</h3>
          <div className="toolbar">
            <button type="button" className="action-button" onClick={() => setActivePage("Source Feeds")}>
              <RefreshCw size={16} aria-hidden /> Refresh Intelligence
            </button>
            <button type="button" className="action-button" onClick={() => setActivePage("Decision Workbench")}>
              <ClipboardCheck size={16} aria-hidden /> Create Patch Decision
            </button>
            <button type="button" className="action-button" onClick={() => setActivePage("Reports")}>
              <FileText size={16} aria-hidden /> Board Pack
            </button>
          </div>
        </div>
        {topQueue.length ? (
          <ol className="action-list">
            {topQueue.map((item) => (
              <li key={item.vulnerability_id}>
                <strong>{item.vulnerability_id}</strong> {humanize(item.severity || "unknown")} | {humanize(item.patch_status || "unknown")} | {item.review_state || "pending_review"}
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState title="No vulnerability records ingested" detail="Refresh live public intelligence or connect approved advisory, MCP, Mythos, AGI-agent, asset, or service records to populate the queue." />
        )}
      </section>

      <div className="split-grid">
        <section className="data-band reviewer-next">
          <h3>Reviewer Next Move</h3>
          {topQueue[0] ? (
            <>
              <StatusLine label="Record" value={topQueue[0].vulnerability_id} tone="amber" />
              <StatusLine label="Why now" value={signalLabel(topQueue[0])} tone="danger" />
              <StatusLine label="Human action" value="Review sources and compile" tone="trust" />
            </>
          ) : (
            <p className="muted-copy">Run live source feeds to populate the next reviewer action from public intelligence.</p>
          )}
        </section>
        <section className="data-band">
          <h3>Decision State</h3>
          <StatusLine label="All records" value={String(metrics.vulnerability_count)} tone="steel" />
          <StatusLine label="Accepted evidence" value={String(metrics.accepted_positive_evidence_sources)} tone="trust" />
          <StatusLine label="Pending review" value={String(metrics.pending_review)} tone="amber" />
          <StatusLine label="Signed packs" value={String(decisionPacks.length)} tone="trust" />
        </section>
        <section className="data-band">
          <h3>Recent Signed Packs</h3>
          {decisionPacks.slice(0, 4).map((pack) => (
            <StatusLine
              key={pack.pack_id}
              label={pack.pack_id}
              value={pack.verification?.verified ? "Verified" : "Pending"}
              tone={pack.verification?.verified ? "trust" : "amber"}
            />
          ))}
          {!decisionPacks.length && <p className="muted-copy">No signed packs have been generated for this tenant.</p>}
        </section>
      </div>
      <section className="wide-band">
        <div className="section-title">
          <h3>Bayesian Advisory</h3>
          <span className="pill teal">Advisory only</span>
        </div>
        <div className="split-grid">
          <StatusLine label="Recommended posture" value={bayesian ? humanize(bayesian.recommended_governance_posture) : "Awaiting assessment"} tone="teal" />
          <StatusLine label="Deferral risk posterior" value={bayesian ? String(bayesian.deferral_risk_posterior) : "Not assessed"} tone="amber" />
        </div>
      </section>
      <section className="wide-band">
        <div className="section-title">
          <h3>Live Source Intelligence</h3>
          <span className="pill amber">Source-bound pending review</span>
        </div>
        <div className="split-grid">
          <StatusLine label="Configured public feeds" value={String(sourceFeedState.feeds.length)} tone="steel" />
          <StatusLine label="Known exploited advisories" value={String(threatSummary?.metrics?.active_exploitation_count || 0)} tone="amber" />
          <StatusLine label="Latest refresh" value={sourceFeedState.recent_runs[0]?.completed_at ? new Date(sourceFeedState.recent_runs[0].completed_at).toLocaleString() : "No run yet"} tone="teal" />
        </div>
      </section>
    </>
  );
}

function Guide() {
  const workflow = [
    ["1", "Agent-led intake", "MCP agents, Mythos, SRA, scanners, and advisory feeds submit real findings through protected intake paths. Manual entry is the exception path."],
    ["2", "Evidence binding", "PatchForge normalises the finding, binds source provenance, and keeps every agent output source-bound pending review."],
    ["3", "Exposure mapping", "Assets and services are linked so leading-class findings are governed against operational reality, not severity alone."],
    ["4", "Human review", "The operator accepts, rejects, or supersedes sources and approves the decision. Agent output never approves risk or closes hard gates alone."],
    ["5", "Signed decision", "The runtime compiles readiness, blockers, and final posture into a signed pack for CAB, board, customer, audit, or service-owner review."]
  ];

  const intelligence = [
    "MCP Agent Intelligence researches, correlates, challenges, and enriches findings before human review.",
    "Mythos and other AGI-agent findings are accepted as leading-class intelligence inputs, not unreviewed truth.",
    "Agents can raise attention, expose contradictions, map likely exposure, and draft decision context.",
    "Final governance comes from reviewed evidence, deterministic policy, signed packs, and accountable human approval."
  ];

  const humanModel = [
    ["Human input", "Review, approve, reject, assign owner, record risk rationale"],
    ["Agent input", "Research, correlate, source-map, flag contradiction, propose posture"],
    ["Runtime input", "Apply evidence model, calculate readiness, preserve blockers, sign pack"],
    ["Boundary", "No exploit generation, no patch deployment, no autonomous risk acceptance"]
  ];

  return (
    <>
      <section className="wide-band">
        <div className="section-title">
          <h3>Operational Walkthrough</h3>
          <span className="pill trust">Real data only</span>
        </div>
        <div className="guide-flow">
          {workflow.map(([step, title, detail]) => (
            <article className="guide-step" key={step}>
              <strong>{step}</strong>
              <div>
                <h4>{title}</h4>
                <p>{detail}</p>
              </div>
            </article>
          ))}
        </div>
      </section>

      <div className="split-grid">
        <section className="data-band">
          <h3>MCP Agent Intelligence</h3>
          <div className="line-stack">
            {intelligence.map((line) => <p key={line}>{line}</p>)}
          </div>
        </section>
        <section className="data-band">
          <h3>Minimal Human Input Model</h3>
          <div className="guide-facts">
            {humanModel.map(([label, value]) => (
              <article className="guide-fact" key={label}>
                <strong>{label}</strong>
                <p>{value}</p>
              </article>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}

function VulnerabilityQueue({
  vulnerabilities,
  form,
  setForm,
  onIngest,
  canWrite
}: {
  vulnerabilities: VulnerabilityRecord[];
  form: typeof emptyForm;
  setForm: (next: typeof emptyForm) => void;
  onIngest: (event: FormEvent<HTMLFormElement>) => void;
  canWrite: boolean;
}) {
  const queuePage = usePagination(vulnerabilities, 8, "vulnerability-queue");
  return (
    <>
      <div className="section-title">
        <h3>Governed Vulnerability Queue</h3>
        <span className="pill steel">{vulnerabilities.length} live records</span>
      </div>

      <div className="table-wrap">
        <table className="data-table queue-table">
          <thead>
            <tr>
              <th>Vulnerability</th>
              <th>Severity</th>
              <th>Signals</th>
              <th>Services</th>
              <th>Assets</th>
              <th>Patch</th>
              <th>Review</th>
              <th>SLA</th>
            </tr>
          </thead>
          <tbody>
            {queuePage.items.map((item) => (
              <tr key={item.vulnerability_id}>
                <td>
                  <strong>{item.vulnerability_id}</strong>
                  <small>{item.title || item.canonical_id || item.vulnerability_id}</small>
                </td>
                <td><span className={`pill ${severityTone(item.severity)}`}>{humanize(item.severity || "unknown")}</span></td>
                <td>{signalLabel(item)}</td>
                <td>{(item.affected_service_ids || []).join(", ") || "Unmapped"}</td>
                <td>{(item.affected_asset_ids || []).join(", ") || "Unmapped"}</td>
                <td>{humanize(item.patch_status || "unknown")}</td>
                <td>{humanize(item.review_state || "pending_review")}</td>
                <td>{item.sla_due_at ? new Date(item.sla_due_at).toLocaleDateString() : "Not set"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!vulnerabilities.length && <EmptyState title="Queue is empty" detail="Use the ingest form below or the protected API to submit real tenant records." />}
      </div>
      <PaginationControls {...queuePage} label="vulnerabilities" />

      {canWrite ? <section className="wide-band">
        <div className="section-title">
          <h3>Manual Exception Ingest</h3>
          <span className="pill amber">Agent/API intake preferred</span>
        </div>
        <form className="ingest-form" onSubmit={onIngest}>
          <div className="field-grid">
            <label>
              Identifier
              <input value={form.vulnerability_id} onChange={(event) => setForm({ ...form, vulnerability_id: event.target.value })} required />
            </label>
            <label>
              Title
              <input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
            </label>
            <label>
              Severity
              <select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}>
                {["critical", "high", "medium", "low", "unknown"].map((severity) => <option key={severity} value={severity}>{humanize(severity)}</option>)}
              </select>
            </label>
            <label>
              Patch status
              <select value={form.patch_status} onChange={(event) => setForm({ ...form, patch_status: event.target.value })}>
                {["patch_available", "patch_feasible", "overdue", "no_patch_available", "mitigation_only", "unknown"].map((status) => <option key={status} value={status}>{humanize(status)}</option>)}
              </select>
            </label>
            <label>
              Source class
              <select value={form.source_class} onChange={(event) => setForm({ ...form, source_class: event.target.value })}>
                {["vendor_advisory", "cve_record", "scanner_output", "kev_record", "epss_signal", "mcp_agent_finding", "mythos_finding", "agi_agent_finding", "human_review"].map((source) => <option key={source} value={source}>{humanize(source)}</option>)}
              </select>
            </label>
            <label>
              Source name
              <input value={form.source_name} onChange={(event) => setForm({ ...form, source_name: event.target.value })} />
            </label>
            <label>
              Source URL
              <input value={form.source_url} onChange={(event) => setForm({ ...form, source_url: event.target.value })} />
            </label>
            <label>
              Affected services
              <input value={form.affected_service_ids} onChange={(event) => setForm({ ...form, affected_service_ids: event.target.value })} />
            </label>
            <label>
              Affected assets
              <input value={form.affected_asset_ids} onChange={(event) => setForm({ ...form, affected_asset_ids: event.target.value })} />
            </label>
          </div>
          <div className="checkbox-grid">
            <label><input type="checkbox" checked={form.known_exploited} onChange={(event) => setForm({ ...form, known_exploited: event.target.checked })} /> Known exploited</label>
            <label><input type="checkbox" checked={form.internet_exposed} onChange={(event) => setForm({ ...form, internet_exposed: event.target.checked })} /> Internet exposed</label>
            <label><input type="checkbox" checked={form.ot_relevant} onChange={(event) => setForm({ ...form, ot_relevant: event.target.checked })} /> OT relevant</label>
          </div>
          <button type="submit" className="action-button">
            <Upload size={16} aria-hidden /> Ingest Record
          </button>
        </form>
      </section> : <EmptyState title="Read-only role" detail="Write actions are hidden unless your token includes a PatchForge triage, security lead, or admin role." />}
    </>
  );
}

function AssetExposure({ assets, services }: { assets: AssetRecord[]; services: ServiceRecord[] }) {
  const assetPage = usePagination(assets, 8, "asset-exposure-assets");
  const servicePage = usePagination(services, 8, "asset-exposure-services");
  return (
    <div className="split-grid">
      <section className="data-band">
        <h3>Assets</h3>
        {assetPage.items.map((asset) => (
          <StatusLine key={asset.asset_id} label={asset.asset_name || asset.asset_id} value={humanize(asset.exposure || "unknown")} tone="steel" />
        ))}
        {!assets.length && <EmptyState title="No asset records" detail="Asset scope appears after real inventory records are ingested." />}
        <PaginationControls {...assetPage} label="assets" />
      </section>
      <section className="data-band">
        <h3>Services</h3>
        {servicePage.items.map((service) => (
          <StatusLine key={service.service_id} label={service.service_name || service.service_id} value={service.customer_facing ? "Customer-facing" : humanize(service.service_tier || "unknown")} tone={service.customer_facing ? "amber" : "steel"} />
        ))}
        {!services.length && <EmptyState title="No service records" detail="Service exposure appears after real service catalogue records are ingested." />}
        <PaginationControls {...servicePage} label="services" />
      </section>
    </div>
  );
}

function DecisionWorkbench({
  vulnerabilities,
  selectedVulnerabilityId,
  setSelectedVulnerabilityId,
  selectedPosture,
  setSelectedPosture,
  onGenerate,
  onBayesianAssess,
  bayesian,
  canWrite
}: {
  vulnerabilities: VulnerabilityRecord[];
  selectedVulnerabilityId: string;
  setSelectedVulnerabilityId: (value: string) => void;
  selectedPosture: string;
  setSelectedPosture: (value: string) => void;
  onGenerate: () => void;
  onBayesianAssess: () => void;
  bayesian: BayesianAssessment | null;
  canWrite: boolean;
}) {
  return (
    <section className="wide-band">
      <div className="section-title">
        <h3>Decision Compile</h3>
        <span className="pill trust">Runtime signed pack</span>
      </div>
      <div className="decision-controls">
        <label>
          Vulnerability
          <select value={selectedVulnerabilityId} onChange={(event) => setSelectedVulnerabilityId(event.target.value)}>
            <option value="">Select ingested record</option>
            {vulnerabilities.map((item) => (
              <option key={item.vulnerability_id} value={item.vulnerability_id}>{item.vulnerability_id}</option>
            ))}
          </select>
        </label>
        <label>
          Posture
          <select value={selectedPosture} onChange={(event) => setSelectedPosture(event.target.value)}>
            {postures.map((posture) => <option key={posture} value={posture}>{humanize(posture)}</option>)}
          </select>
        </label>
        <button type="button" className="action-button" onClick={onBayesianAssess} disabled={!selectedVulnerabilityId || !canWrite}>
          <Radar size={16} aria-hidden /> Run Bayesian Advisory
        </button>
        <button type="button" className="action-button" onClick={onGenerate} disabled={!selectedVulnerabilityId || !canWrite}>
          <FileCheck2 size={16} aria-hidden /> Generate Signed Pack
        </button>
      </div>
      <div className="split-grid">
        <section className="data-band">
          <h3>Bayesian Patch Risk</h3>
          <StatusLine label="Exploit probability" value={bayesian ? String(bayesian.exploit_probability_posterior) : "Not assessed"} tone="amber" />
          <StatusLine label="Patch feasibility" value={bayesian ? String(bayesian.patch_feasibility_posterior) : "Not assessed"} tone="teal" />
          <StatusLine label="Recommended posture" value={bayesian ? humanize(bayesian.recommended_governance_posture) : "Awaiting assessment"} tone="trust" />
        </section>
        <section className="data-band">
          <h3>Advisory Boundary</h3>
          <StatusLine label="Can close hard gates" value="No" tone="amber" />
          <StatusLine label="Can approve risk" value="No" tone="amber" />
          <StatusLine label="Human approval" value="Required" tone="trust" />
        </section>
      </div>
      {!vulnerabilities.length && <EmptyState title="No record available for compile" detail="Decision packs require a real ingested vulnerability record." />}
      {!canWrite && <EmptyState title="Read-only role" detail="Decision compile actions require an assigned PatchForge write role." />}
    </section>
  );
}

function EmergencyPatch({ vulnerabilities }: { vulnerabilities: VulnerabilityRecord[] }) {
  const emergency = vulnerabilities.filter((item) => item.known_exploited && item.internet_exposed);
  return (
    <PageBand
      icon={ShieldAlert}
      title="Emergency Patch"
      lines={[
        `${emergency.length} internet-exposed known-exploited records`,
        "Governance gates remain active",
        "Human approvals and rollback evidence required"
      ]}
    />
  );
}

function RiskAcceptances({ decisionPacks }: { decisionPacks: DecisionPackRecord[] }) {
  const riskPacks = decisionPacks.filter((pack) => pack.decision_posture === "risk_accept_temporarily");
  return <PageBand icon={Clock3} title="Risk Acceptances" lines={[`${riskPacks.length} signed risk-acceptance packs`, "Owner, rationale, expiry and controls required", "Final approval remains explicit"]} />;
}

function CompensatingControls() {
  return <PageBand icon={Wrench} title="Compensating Controls" lines={["Controls are evidence records", "Accepted controls require human review", "Controls do not mutate production systems"]} />;
}

function SraResearch({ onRun, result, canWrite }: { onRun: () => void; result: Record<string, unknown> | null; canWrite: boolean }) {
  return (
    <section className="wide-band">
      <div className="section-title">
        <h3>Agent Intelligence</h3>
        <span className="pill teal">Advisory only</span>
      </div>
      <div className="split-grid">
        <section className="data-band">
          <h3>SRA / MCP Controls</h3>
          <StatusLine label="Source state" value="Source-bound" tone="amber" />
          <StatusLine label="Can close hard gates" value="No" tone="amber" />
          <StatusLine label="Human review" value="Required" tone="trust" />
          <button type="button" className="action-button" onClick={onRun} disabled={!canWrite}>
            <Radar size={16} aria-hidden /> Run Exploit-Risk Advisory
          </button>
        </section>
        <section className="data-band">
          <h3>Latest Advisory</h3>
          {result ? <pre className="json-preview">{JSON.stringify(result, null, 2)}</pre> : <p className="muted-copy">No SRA advisory has been run in this session.</p>}
        </section>
      </div>
    </section>
  );
}

function EvidenceCatalogue({ vulnerabilities }: { vulnerabilities: VulnerabilityRecord[] }) {
  const sourceCount = vulnerabilities.reduce((total, item) => total + (item.source_record_ids?.length || item.sources?.length || 0), 0);
  return <PageBand icon={BookOpenCheck} title="Evidence Catalogue" lines={[`${sourceCount} source-bound evidence references`, "Scanner, SRA, MCP, Mythos, and AGI-agent output require review", "Rejected sources cannot count as positive evidence"]} />;
}

function SourceFeeds({
  sourceFeedState,
  onRefresh,
  canWrite
}: {
  sourceFeedState: SourceFeedState;
  onRefresh: (feedId: string) => void;
  canWrite: boolean;
}) {
  const feedPage = usePagination(sourceFeedState.feeds, 4, "source-feeds");
  const runPage = usePagination(sourceFeedState.recent_runs, 8, "source-feed-runs");

  return (
    <>
      <div className="section-title">
        <h3>Public Source Intelligence</h3>
        <span className="pill amber">Live feeds, source-bound</span>
      </div>

      <div className="split-grid">
        {feedPage.items.map((feed) => (
          <section className="data-band source-feed-panel" key={feed.feed_id}>
            <div className="section-title compact-title">
              <h3>{feed.feed_name}</h3>
              <span className="pill steel">{feed.provider}</span>
            </div>
            <StatusLine label="Source class" value={humanize(feed.source_class)} tone="steel" />
            <StatusLine label="Authentication" value={humanize(feed.authentication)} tone="teal" />
            <StatusLine label="Review required" value={feed.review_required ? "Yes" : "No"} tone="amber" />
            <StatusLine label="Can close gates" value={feed.can_close_hard_gates_alone ? "Yes" : "No"} tone="amber" />
            <button type="button" className="action-button" onClick={() => onRefresh(feed.feed_id)} disabled={!canWrite}>
              <RefreshCw size={16} aria-hidden /> Refresh {feed.provider}
            </button>
          </section>
        ))}
      </div>
      <PaginationControls {...feedPage} label="feeds" />

      <section className="wide-band">
        <div className="section-title">
          <h3>Recent Feed Runs</h3>
          <span className="pill teal">{sourceFeedState.recent_runs.length} recorded</span>
        </div>
        <div className="table-wrap">
          <table className="data-table feed-runs-table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Feed</th>
                <th>Status</th>
                <th>Seen</th>
                <th>Ingested</th>
                <th>Enriched</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {runPage.items.map((run) => (
                <tr key={run.run_id}>
                  <td>
                    <strong>{run.run_id}</strong>
                    <small>{run.message || "Source-bound refresh"}</small>
                  </td>
                  <td>{run.feed_name}</td>
                  <td><span className={`pill ${run.status === "completed" ? "trust" : "amber"}`}>{humanize(run.status)}</span></td>
                  <td>{run.records_seen ?? 0}</td>
                  <td>{run.records_ingested ?? 0}</td>
                  <td>{run.records_enriched ?? 0}</td>
                  <td>{run.completed_at ? new Date(run.completed_at).toLocaleString() : "Not recorded"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!sourceFeedState.recent_runs.length && <EmptyState title="No live source feed runs" detail="Refresh CISA KEV or FIRST EPSS to pull real public intelligence into the governed queue." />}
        </div>
        <PaginationControls {...runPage} label="feed runs" />
      </section>

      {!canWrite && <EmptyState title="Read-only role" detail="Source refresh actions require a PatchForge triage, security lead, or admin role." />}
    </>
  );
}

function VendorThreatLandscape({ vendors, threatSummary }: { vendors: VendorProfile[]; threatSummary: ThreatLandscapeSummary | null }) {
  const vendorPage = usePagination(vendors, 10, "vendor-threat-vendors");
  return (
    <>
      <div className="section-title">
        <h3>Vendor & Threat Landscape</h3>
        <span className="pill amber">Source-bound pending review</span>
      </div>
      <div className="split-grid">
        <section className="data-band">
          <h3>Landscape Metrics</h3>
          <StatusLine label="Tracked vendors" value={String(threatSummary?.vendor_count || vendors.length)} tone="steel" />
          <StatusLine label="Active exploitation" value={String(threatSummary?.metrics?.active_exploitation_count || 0)} tone="danger" />
          <StatusLine label="Critical advisories" value={String(threatSummary?.metrics?.critical_open_advisory_count || 0)} tone="amber" />
          <StatusLine label="Patch maturity" value={humanize(threatSummary?.metrics?.patch_maturity || "unknown")} tone="teal" />
        </section>
        <section className="data-band">
          <h3>Top Exposed Vendors</h3>
          {(threatSummary?.top_exposed_vendors || []).map((vendor) => (
            <StatusLine key={vendor.vendor_id} label={humanize(vendor.vendor_id)} value={`${vendor.active_exploitation_count} exploited`} tone="amber" />
          ))}
          {!threatSummary?.top_exposed_vendors?.length && <p className="muted-copy">No reviewed vendor exposure records are present yet.</p>}
        </section>
      </div>
      <div className="table-wrap">
        <table className="data-table compact-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Category</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            {vendorPage.items.map((vendor) => (
              <tr key={vendor.vendor_id}>
                <td>{vendor.vendor_name}</td>
                <td>{humanize(vendor.category)}</td>
                <td>{humanize(vendor.review_state || "pending_review")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <PaginationControls {...vendorPage} label="vendors" />
    </>
  );
}

const vendorLensTabs = [
  "Network Vendors",
  "Product Families",
  "Advisories & CVEs",
  "Customer Operational Asset Match",
  "Config Applicability",
  "Patch Compare",
  "Urgency & Recommended Posture",
  "Ask PatchForge",
  "Vendor Evidence Packs",
  "Admin: Vendor Sources"
];

function VendorLens({
  vendorLens,
  assetForm,
  setAssetForm,
  advisoryForm,
  setAdvisoryForm,
  question,
  setQuestion,
  selectedAssetId,
  setSelectedAssetId,
  selectedAdvisoryId,
  setSelectedAdvisoryId,
  onSaveAsset,
  onIngestAdvisory,
  onAssess,
  onAsk,
  onRefreshSource,
  onComparePatch,
  canWrite
}: {
  vendorLens: VendorLensState;
  assetForm: typeof emptyNetworkAssetForm;
  setAssetForm: (value: typeof emptyNetworkAssetForm) => void;
  advisoryForm: typeof emptyVendorAdvisoryForm;
  setAdvisoryForm: (value: typeof emptyVendorAdvisoryForm) => void;
  question: string;
  setQuestion: (value: string) => void;
  selectedAssetId: string;
  setSelectedAssetId: (value: string) => void;
  selectedAdvisoryId: string;
  setSelectedAdvisoryId: (value: string) => void;
  onSaveAsset: (event: FormEvent<HTMLFormElement>) => void;
  onIngestAdvisory: (event: FormEvent<HTMLFormElement>) => void;
  onAssess: (assetId?: string, advisoryId?: string) => void;
  onAsk: (assetId?: string, advisoryId?: string) => void;
  onRefreshSource: (vendorId?: string) => void;
  onComparePatch: (assetId?: string, advisoryId?: string) => void;
  canWrite: boolean;
}) {
  const [activeTab, setActiveTab] = useState(vendorLensTabs[0]);
  const [selectedVendorId, setSelectedVendorId] = useState(vendorLens.vendors[0]?.vendor_id || "");
  const asset = vendorLens.assets.find((item) => item.asset_id === selectedAssetId) || vendorLens.assets[0];
  const advisory = vendorLens.advisories.find((item) => item.advisory_id === selectedAdvisoryId) || vendorLens.advisories[0];
  const contextAssetId = asset?.asset_id || "";
  const contextAdvisoryId = advisory?.advisory_id || "";
  const assessment = [vendorLens.latestAssessment, ...(vendorLens.dashboard?.recent_assessments || [])]
    .find((item) => recordMatchesContext(item, contextAssetId, contextAdvisoryId)) || null;
  const chat = recordMatchesContext(vendorLens.latestChat, contextAssetId, contextAdvisoryId) ? vendorLens.latestChat : null;
  const comparison = recordMatchesContext(vendorLens.latestComparison, contextAssetId, contextAdvisoryId) ? vendorLens.latestComparison : null;
  const selectedVendor = vendorLens.vendors.find((vendor) => vendor.vendor_id === selectedVendorId) || vendorLens.vendors[0] || null;
  const cards = [
    { label: "Vendors tracked", value: vendorLens.dashboard?.vendors_tracked || vendorLens.vendors.length, tone: "steel", icon: Network },
    { label: "Active advisories", value: vendorLens.dashboard?.active_advisories || vendorLens.advisories.length, tone: "amber", icon: ShieldAlert },
    { label: "Known exploited CVEs", value: vendorLens.dashboard?.known_exploited_vendor_cves || 0, tone: "danger", icon: TriangleAlert },
    { label: "Estate matches", value: vendorLens.dashboard?.customer_estate_matches || 0, tone: "teal", icon: Layers3 },
    { label: "Config unknown", value: vendorLens.dashboard?.config_unknown_count || 0, tone: "amber", icon: ListFilter },
    { label: "Emergency attention", value: vendorLens.dashboard?.emergency_attention_required || 0, tone: "danger", icon: Clock3 }
  ];
  const vendorPage = usePagination(vendorLens.vendors, 8, "vendorlens-vendors");
  const productVendorPage = usePagination(vendorLens.vendors, 6, "vendorlens-products");
  const advisoryPage = usePagination(vendorLens.advisories, 8, "vendorlens-advisories");
  const assetPage = usePagination(vendorLens.assets, 8, "vendorlens-assets");
  const gapPage = usePagination(assessment?.evidence_gaps || [], 6, "vendorlens-gaps");
  const compareAssetPage = usePagination(vendorLens.assets, 6, "vendorlens-compare-assets");
  const compareAdvisoryPage = usePagination(vendorLens.advisories, 10, "vendorlens-compare-advisories");
  const nextActions: Array<{ number: string; title: string; detail: string; onClick?: () => void }> = [
    { number: "1", title: "Confirm customer exposure", detail: "Attach reviewed asset, service, internet exposure, and management-plane evidence.", onClick: () => setActiveTab("Customer Operational Asset Match") },
    { number: "2", title: "Attach vendor advisory evidence", detail: "Use source-bound vendor/CVE evidence with review state visible.", onClick: () => setActiveTab("Advisories & CVEs") },
    { number: "3", title: "Attach configuration evidence", detail: "Record firmware, enabled/disabled feature state, and evidence references.", onClick: () => setActiveTab("Customer Operational Asset Match") },
    { number: "4", title: "Run config applicability", detail: "Compare product, version, feature, and exposure to the advisory.", onClick: () => setActiveTab("Config Applicability") },
    { number: "5", title: "Ask PatchForge", detail: "Get advisory-only explanation of what the evidence means.", onClick: () => setActiveTab("Ask PatchForge") },
    { number: "6", title: "Generate signed pack", detail: "Move to Review & Approve and compile the source-bound signed pack." },
    { number: "7", title: "Export customer/board/CAB report", detail: "Use Reports after the signed pack is generated." }
  ];

  useEffect(() => {
    if (!selectedVendorId && vendorLens.vendors[0]?.vendor_id) {
      setSelectedVendorId(vendorLens.vendors[0].vendor_id);
    }
  }, [selectedVendorId, vendorLens.vendors]);

  useEffect(() => {
    if (vendorLens.assets[0]?.asset_id && !vendorLens.assets.some((item) => item.asset_id === selectedAssetId)) {
      setSelectedAssetId(vendorLens.assets[0].asset_id);
    }
  }, [selectedAssetId, vendorLens.assets]);

  useEffect(() => {
    if (vendorLens.advisories[0]?.advisory_id && !vendorLens.advisories.some((item) => item.advisory_id === selectedAdvisoryId)) {
      setSelectedAdvisoryId(vendorLens.advisories[0].advisory_id);
    }
  }, [selectedAdvisoryId, vendorLens.advisories]);

  return (
    <>
      <div className="section-title">
        <h3>Vendor Catalogue</h3>
        <span className="pill amber">Source-bound advisory intelligence</span>
      </div>

      <div className="context-banner vendorlens-context" aria-label="VendorLens context">
        <strong>{advisory?.cve || advisory?.advisory_id || "CVE pending"}</strong>
        <span><b>Vendor</b>{advisory?.vendor_name || asset?.vendor_id || "pending"}</span>
        <span><b>Product</b>{asset?.product_family || advisory?.product_family || "pending"}</span>
        <span><b>Model</b>{asset?.model || "pending"}</span>
        <span><b>Firmware</b>{asset?.firmware_version || "pending"}</span>
        <span><b>Feature</b>{assessment?.affected_feature || advisory?.affected_features?.[0] || "pending"}</span>
        <span><b>Exposure</b>{assessment?.exposure_status ? humanize(assessment.exposure_status) : "unconfirmed"}</span>
        <span><b>Review</b>{humanize(asset?.review_state || advisory?.review_state || "pending_review")}</span>
        <span><b>Final approval</b>{assessment?.final_approval_issued ? "issued" : "not issued"}</span>
      </div>

      <div className="metric-grid">
        {cards.map(({ label, value, tone, icon: Icon }) => (
          <article className={`metric-card ${tone}`} key={label}>
            <Icon size={20} aria-hidden />
            <span>{label}</span>
            <strong>{value}</strong>
          </article>
        ))}
      </div>

      <section className="wide-band action-hero">
        <div>
          <p className="eyebrow">Config-aware network vendor governance</p>
          <h3>Ask what the advisory means for a real firewall, gateway, or edge platform.</h3>
          <p className="muted-copy">
            VendorLens links public vendor/CVE intelligence to customer product, model, firmware, feature, and exposure evidence. It can recommend scope confirmation, patch governance, mitigation, or monitoring, but final decisions always require reviewed evidence and human approval.
          </p>
        </div>
        <div className="hero-actions">
          <button type="button" className="action-button" onClick={() => onRefreshSource("all-vendors")} disabled={!canWrite}>
            <RefreshCw size={16} aria-hidden /> Refresh All NVD Vendors
          </button>
          <button type="button" className="action-button secondary-action" onClick={() => onAssess(asset?.asset_id, advisory?.advisory_id)} disabled={!canWrite || !asset || !advisory}>
            <Gauge size={16} aria-hidden /> Assess
          </button>
          <button type="button" className="action-button secondary-action" onClick={() => onAsk(asset?.asset_id, advisory?.advisory_id)} disabled={!canWrite || !asset || !advisory}>
            <MessageSquareText size={16} aria-hidden /> Ask PatchForge
          </button>
          <button type="button" className="action-button secondary-action" onClick={() => onComparePatch(asset?.asset_id, advisory?.advisory_id)} disabled={!canWrite || !asset || !advisory}>
            <Layers3 size={16} aria-hidden /> Compare Patch
          </button>
        </div>
      </section>

      <section className="wide-band next-actions">
        <div className="section-title compact-title">
          <h3>Next Actions</h3>
          <span className="pill steel">human approval remains required</span>
        </div>
        <div className="next-action-grid vendorlens-next-grid">
          {nextActions.map(({ number, title, detail, onClick }) => (
            <button key={title} type="button" className="next-action-card clickable-card" onClick={onClick} disabled={!onClick}>
              <strong>{number}</strong>
              <span>
                <h4>{title}</h4>
                <p>{detail}</p>
              </span>
            </button>
          ))}
        </div>
      </section>

      <div className="vendorlens-tabs" role="tablist" aria-label="VendorLens tabs">
        {vendorLensTabs.map((tab) => (
          <button key={tab} type="button" className={activeTab === tab ? "vendorlens-tab active" : "vendorlens-tab"} onClick={() => setActiveTab(tab)}>
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "Network Vendors" && (
        <div className="split-grid">
          <section className="data-band">
            <div className="section-title compact-title">
              <h3>Reference Catalogue</h3>
              <span className="pill steel">{vendorLens.vendors.length} vendors</span>
            </div>
            <div className="reference-list">
              {vendorPage.items.map((vendor) => (
                <button key={vendor.vendor_id} type="button" className={selectedVendor?.vendor_id === vendor.vendor_id ? "reference-row active" : "reference-row"} onClick={() => setSelectedVendorId(vendor.vendor_id)}>
                  <strong>{vendor.vendor_name}</strong>
                  <span>{humanize(vendor.vendor_category)}</span>
                  <small>{(vendor.product_families || []).slice(0, 3).join(", ") || "Families pending"}</small>
                </button>
              ))}
            </div>
            <PaginationControls {...vendorPage} label="vendors" />
            {!vendorLens.vendors.length && <EmptyState title="Vendor catalogue unavailable" detail="VendorLens vendor catalogue loads from the protected PatchForge API." />}
          </section>
          <section className="data-band reference-detail">
            <h3>{selectedVendor?.vendor_name || "Reference detail"}</h3>
            <StatusLine label="Source type" value={humanize(selectedVendor?.advisory_source_type || "public_vendor_advisory")} tone="teal" />
            <StatusLine label="Review state" value={humanize(selectedVendor?.source_review_state || "reference_catalogue")} tone="amber" />
            <StatusLine label="Last refresh" value={selectedVendor?.last_refresh_at ? new Date(selectedVendor.last_refresh_at).toLocaleString() : "Not refreshed"} tone="steel" />
            <p className="muted-copy url-copy">{selectedVendor?.advisory_source_url || "Source URL is configured in Admin."}</p>
            <div className="report-actions">
              {selectedVendor?.advisory_source_url && <a className="action-button" href={selectedVendor.advisory_source_url} target="_blank" rel="noreferrer">Open Source</a>}
              <button type="button" className="action-button secondary-action" onClick={() => onRefreshSource(selectedVendor?.vendor_id)} disabled={!canWrite}>
                <RefreshCw size={16} aria-hidden /> Refresh NVD Catalogue
              </button>
            </div>
          </section>
        </div>
      )}

      {activeTab === "Product Families" && (
        <div className="report-grid">
          {productVendorPage.items.map((vendor) => (
            <section className="data-band report-card" key={vendor.vendor_id}>
              <div className="section-title compact-title">
                <h3>{vendor.vendor_name}</h3>
                <span className="pill steel">{humanize(vendor.vendor_category)}</span>
              </div>
              {(vendor.product_families || []).map((family) => <StatusLine key={family} label={family} value="Tracked" tone="teal" />)}
            </section>
          ))}
          <PaginationControls {...productVendorPage} label="vendor family cards" />
        </div>
      )}

      {activeTab === "Advisories & CVEs" && (
        <div className="split-grid">
          <section className="data-band">
            <h3>Ingest Vendor Advisory</h3>
            <form className="ingest-form" onSubmit={onIngestAdvisory}>
              <div className="field-grid">
                <label>Vendor<input value={advisoryForm.vendor_id} onChange={(event) => setAdvisoryForm({ ...advisoryForm, vendor_id: event.target.value })} /></label>
                <label>CVE<input value={advisoryForm.cve} onChange={(event) => setAdvisoryForm({ ...advisoryForm, cve: event.target.value })} placeholder="CVE-2026-..." /></label>
                <label>Severity<select value={advisoryForm.severity} onChange={(event) => setAdvisoryForm({ ...advisoryForm, severity: event.target.value })}><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label>
                <label>Product<input value={advisoryForm.product_family} onChange={(event) => setAdvisoryForm({ ...advisoryForm, product_family: event.target.value })} /></label>
                <label>Affected versions<input value={advisoryForm.affected_versions} onChange={(event) => setAdvisoryForm({ ...advisoryForm, affected_versions: event.target.value })} /></label>
                <label>Fixed versions<input value={advisoryForm.fixed_versions} onChange={(event) => setAdvisoryForm({ ...advisoryForm, fixed_versions: event.target.value })} /></label>
                <label>Affected features<input value={advisoryForm.affected_features} onChange={(event) => setAdvisoryForm({ ...advisoryForm, affected_features: event.target.value })} placeholder="ssl_vpn, web_management" /></label>
                <label>Source URL<input value={advisoryForm.source_url} onChange={(event) => setAdvisoryForm({ ...advisoryForm, source_url: event.target.value })} /></label>
              </div>
              <label>Title<input value={advisoryForm.title} onChange={(event) => setAdvisoryForm({ ...advisoryForm, title: event.target.value })} /></label>
              <div className="checkbox-grid">
                <label><input type="checkbox" checked={advisoryForm.known_exploited} onChange={(event) => setAdvisoryForm({ ...advisoryForm, known_exploited: event.target.checked })} /> Known exploited signal</label>
                <label><input type="checkbox" checked={advisoryForm.patch_available} onChange={(event) => setAdvisoryForm({ ...advisoryForm, patch_available: event.target.checked })} /> Patch available</label>
              </div>
              <button type="submit" className="action-button" disabled={!canWrite}>Ingest Advisory</button>
            </form>
          </section>
          <section className="data-band">
            <h3>Current Advisory Queue</h3>
            {advisoryPage.items.map((item) => (
              <StatusLine key={item.advisory_id} label={item.cve || item.advisory_id} value={humanize(item.review_state || "pending_review")} tone={item.known_exploited ? "danger" : "amber"} detail={item.title || item.vendor_name} />
            ))}
            {!vendorLens.advisories.length && <p className="muted-copy">No vendor advisories are attached yet.</p>}
            <PaginationControls {...advisoryPage} label="advisories" />
          </section>
        </div>
      )}

      {activeTab === "Customer Operational Asset Match" && (
        <div className="split-grid">
          <section className="data-band">
            <h3>Customer Network Asset</h3>
            <form className="ingest-form" onSubmit={onSaveAsset}>
              <div className="field-grid">
                <label>Vendor<input value={assetForm.vendor_id} onChange={(event) => setAssetForm({ ...assetForm, vendor_id: event.target.value })} /></label>
                <label>Product<input value={assetForm.product_family} onChange={(event) => setAssetForm({ ...assetForm, product_family: event.target.value })} /></label>
                <label>Model<input value={assetForm.model} onChange={(event) => setAssetForm({ ...assetForm, model: event.target.value })} /></label>
                <label>Firmware<input value={assetForm.firmware_version} onChange={(event) => setAssetForm({ ...assetForm, firmware_version: event.target.value })} /></label>
                <label>Site<input value={assetForm.site} onChange={(event) => setAssetForm({ ...assetForm, site: event.target.value })} /></label>
                <label>Owner<input value={assetForm.service_owner} onChange={(event) => setAssetForm({ ...assetForm, service_owner: event.target.value })} /></label>
                <label>Management exposure<select value={assetForm.management_exposure} onChange={(event) => setAssetForm({ ...assetForm, management_exposure: event.target.value })}><option>unknown</option><option>internet</option><option>public_management</option><option>internal</option><option>private</option></select></label>
                <label>Review state<select value={assetForm.review_state} onChange={(event) => setAssetForm({ ...assetForm, review_state: event.target.value })}><option>pending_review</option><option>reviewed</option><option>rejected</option></select></label>
              </div>
              <label>Enabled features<input value={assetForm.enabled_features} onChange={(event) => setAssetForm({ ...assetForm, enabled_features: event.target.value })} placeholder="ipsec_vpn, snmp" /></label>
              <label>Disabled features<input value={assetForm.disabled_features} onChange={(event) => setAssetForm({ ...assetForm, disabled_features: event.target.value })} placeholder="ssl_vpn, web_management" /></label>
              <label>Configuration evidence refs<input value={assetForm.config_evidence_refs} onChange={(event) => setAssetForm({ ...assetForm, config_evidence_refs: event.target.value })} /></label>
              <div className="checkbox-grid">
                <label><input type="checkbox" checked={assetForm.internet_facing} onChange={(event) => setAssetForm({ ...assetForm, internet_facing: event.target.checked })} /> Internet facing</label>
              </div>
              <button type="submit" className="action-button" disabled={!canWrite}>Save Asset Evidence</button>
            </form>
          </section>
          <section className="data-band">
            <h3>Customer Operational Asset Records</h3>
            {assetPage.items.map((item) => (
              <StatusLine key={item.asset_id} label={`${item.vendor_id} ${item.model || item.product_family || ""}`} value={humanize(item.review_state || "pending_review")} tone={item.internet_facing ? "amber" : "steel"} detail={`${item.firmware_version || "version pending"} | ${item.management_exposure || "exposure pending"}`} />
            ))}
            {!vendorLens.assets.length && <p className="muted-copy">No customer network assets are attached yet.</p>}
            <PaginationControls {...assetPage} label="assets" />
          </section>
        </div>
      )}

      {activeTab === "Config Applicability" && (
        <div className="split-grid">
          <section className="data-band">
            <h3>Latest Applicability Assessment</h3>
            <StatusLine label="Applicability" value={humanize(assessment?.applicability_posture || "not assessed")} tone="teal" />
            <StatusLine label="Urgency" value={humanize(assessment?.urgency_posture || "not assessed")} tone={assessment?.urgency_posture === "emergency_patch_required" ? "danger" : "amber"} />
            <StatusLine label="Version status" value={humanize(assessment?.affected_version_status || "not assessed")} tone="steel" />
            <StatusLine label="Feature status" value={humanize(assessment?.feature_enabled_status || "not assessed")} tone="steel" />
            <StatusLine label="Exposure status" value={humanize(assessment?.exposure_status || "not assessed")} tone="steel" />
            <StatusLine label="Final approval" value={assessment?.final_approval_issued ? "Issued" : "Not issued"} tone="amber" />
          </section>
          <section className="data-band">
            <h3>Evidence Gaps</h3>
            {gapPage.items.map((gap) => (
              <div className="guide-fact" key={gap.gap_id || gap.plain_english_gap}>
                <strong>{gap.plain_english_gap || humanize(gap.gap_id || "Evidence gap")}</strong>
                <p>{gap.required_evidence || "Reviewed evidence required."}</p>
              </div>
            ))}
            {!assessment?.evidence_gaps?.length && <p className="muted-copy">Run an applicability assessment to populate evidence gaps.</p>}
            <PaginationControls {...gapPage} label="evidence gaps" />
          </section>
        </div>
      )}

      {activeTab === "Patch Compare" && (
        <div className="split-grid">
          <section className="data-band">
            <h3>Current vs Target Patch</h3>
            <p className="muted-copy">Choose a reviewed customer device and a source-bound advisory. Large NVD catalogues stay paginated so the CISO comparison remains usable.</p>
            <h4 className="subhead">Customer device</h4>
            <div className="reference-list compact-reference-list">
              {compareAssetPage.items.map((item) => (
                <button key={item.asset_id} type="button" className={asset?.asset_id === item.asset_id ? "reference-row active" : "reference-row"} onClick={() => setSelectedAssetId(item.asset_id)}>
                  <strong>{`${item.vendor_id} ${item.model || item.product_family || item.asset_id}`}</strong>
                  <span>{item.firmware_version || "Version pending"}</span>
                  <small>{item.management_exposure || "Exposure pending"}</small>
                </button>
              ))}
            </div>
            {!vendorLens.assets.length && <p className="muted-copy">No customer network asset evidence is attached yet.</p>}
            <PaginationControls {...compareAssetPage} label="comparison assets" />
            <h4 className="subhead">Advisory or CVE</h4>
            <div className="reference-list compact-reference-list">
              {compareAdvisoryPage.items.map((item) => (
                <button key={item.advisory_id} type="button" className={advisory?.advisory_id === item.advisory_id ? "reference-row active" : "reference-row"} onClick={() => setSelectedAdvisoryId(item.advisory_id)}>
                  <strong>{item.cve || item.advisory_id}</strong>
                  <span>{item.vendor_name || item.vendor_id || "Vendor pending"}</span>
                  <small>{item.title || "Source-bound advisory pending review"}</small>
                </button>
              ))}
            </div>
            {!vendorLens.advisories.length && <p className="muted-copy">No source-bound vendor advisory records are attached yet.</p>}
            <PaginationControls {...compareAdvisoryPage} label="comparison advisories" />
            <StatusLine label="Asset" value={asset?.asset_id || "No asset selected"} tone="steel" />
            <StatusLine label="Advisory" value={advisory?.cve || advisory?.advisory_id || "No advisory selected"} tone="amber" />
            <StatusLine label="Running version" value={comparison?.current_version || asset?.firmware_version || "Version pending"} tone="steel" />
            <StatusLine label="Target fixed version" value={comparison?.target_version || advisory?.fixed_versions?.[0] || "Fixed version pending"} tone="teal" />
            <StatusLine label="Current status" value={humanize(comparison?.current_version_status || "not compared")} tone="amber" />
            <StatusLine label="Target status" value={humanize(comparison?.target_version_status || "not compared")} tone="teal" />
            <button type="button" className="action-button" onClick={() => onComparePatch(asset?.asset_id, advisory?.advisory_id)} disabled={!canWrite || !asset || !advisory}>
              <Layers3 size={16} aria-hidden /> Run Patch Compare
            </button>
          </section>
          <section className="data-band">
            <h3>CISO Review Summary</h3>
            <p className="muted-copy">{comparison?.ciso_summary || "Run patch compare to prepare a CISO-ready summary from source-bound advisory and customer asset evidence."}</p>
            <p className="boundary-copy">Export the CISO Patch Version Comparison Report from Reports after generating a signed pack with this comparison attached.</p>
            {(comparison?.evidence_required || []).slice(0, 6).map((item) => <p className="rail-note" key={item}><FileCheck2 size={15} aria-hidden /> {item}</p>)}
          </section>
        </div>
      )}

      {activeTab === "Urgency & Recommended Posture" && (
        <section className="wide-band review-runway">
          <div>
            <p className="eyebrow">Recommended posture remains advisory</p>
            <h3>{humanize(assessment?.urgency_posture || "Urgent scope confirmation required")}</h3>
            <p className="muted-copy">{assessment?.decision_not_allowed_yet || "PatchForge cannot approve patching, risk acceptance, closure, or not-applicable status without reviewed evidence and named human approval."}</p>
          </div>
          <div className="finding-score">
            <strong>{humanize(assessment?.applicability_posture || "requires_review")}</strong>
            <small>Applicability posture</small>
          </div>
        </section>
      )}

      {activeTab === "Ask PatchForge" && (
        <section className="wide-band">
          <div className="section-title">
            <h3>Ask PatchForge</h3>
            <span className="pill teal">SRA/AIP advisory only</span>
          </div>
          <div className="chat-layout">
            <label>
              Question
              <textarea value={question} onChange={(event) => setQuestion(event.target.value)} rows={4} />
            </label>
            <button type="button" className="action-button" onClick={() => onAsk(asset?.asset_id, advisory?.advisory_id)} disabled={!canWrite || !asset || !advisory}>
              <MessageSquareText size={16} aria-hidden /> Ask PatchForge
            </button>
          </div>
          <div className="data-band">
            <h3>Latest Answer</h3>
            <p className="muted-copy">{chat?.latest_response?.short_answer || "No VendorLens chat response yet."}</p>
            <StatusLine label="Governed posture" value={humanize(chat?.latest_response?.current_governed_posture || "not assessed")} tone="amber" />
            <StatusLine label="Human review" value={chat?.latest_response?.human_review_required === false ? "Not recorded" : "Required"} tone="trust" />
            <StatusLine label="Final approval" value={chat?.latest_response?.final_approval_issued ? "Issued" : "False"} tone="amber" />
          </div>
        </section>
      )}

      {activeTab === "Vendor Evidence Packs" && (
        <section className="wide-band">
          <h3>Vendor Evidence Pack Inputs</h3>
          <p className="muted-copy">Signed packs can now include network vendor profile, customer network asset, vendor advisory, config applicability, patch comparison, VendorLens decision context, and SRA/AIP chat artefacts.</p>
          <div className="decision-option-grid">
            {["network_vendor_profile_snapshot.json", "customer_network_asset_snapshot.json", "vendor_security_advisory_snapshot.json", "config_applicability_assessment.json", "vendorlens_patch_comparison.json", "sra_config_chat_session.json", "vendorlens_decision_context.json"].map((artefact) => (
              <div className="decision-option" key={artefact}>
                <h4>{artefact}</h4>
                <p>Preserved in signed pack when VendorLens context is attached to pack generation.</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {activeTab === "Admin: Vendor Sources" && (
        <section className="wide-band">
          <h3>VendorLens Sources</h3>
          <p className="muted-copy">NVD CVE 2.0 metadata enrichment, Cisco PSIRT with credentials reference, and configured vendor RSS/JSON sources are source-bound. Credentials are referenced only and secret values are never displayed.</p>
          <div className="decision-option-grid">
            <div className="decision-option"><h4>NVD CVE API</h4><p>On-demand CVE metadata enrichment. Public source-bound records start pending review.</p></div>
            <div className="decision-option"><h4>Cisco PSIRT</h4><p>Credential-reference gated. Refresh records run ledger entries when credentials or source URLs are missing.</p></div>
            <div className="decision-option"><h4>Generic Vendor RSS/JSON</h4><p>Admin-configured source URLs for Fortinet, Palo Alto, Juniper, F5, Citrix/NetScaler, Check Point, SonicWall, and other vendors.</p></div>
          </div>
        </section>
      )}

      {!canWrite && <EmptyState title="Read-only role" detail="VendorLens asset, advisory, refresh, assessment, and chat actions require a PatchForge write role." />}
    </>
  );
}

function DecisionPacks({
  decisionPacks,
  reports,
  onExportPack,
  onDownloadReport
}: {
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  onExportPack: (packId: string) => void;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
}) {
  const defaultReport = reports.find((report) => report.report_type === "board_vulnerability_remediation_summary") || reports[0];
  const sortedPacks = newestDecisionPacks(decisionPacks);
  const packPage = usePagination(sortedPacks, 8, "decision-packs");
  return (
    <>
      <div className="section-title">
        <h3>Decision Packs</h3>
        <span className="pill trust">{sortedPacks.filter((pack) => pack.verification?.verified).length} verified</span>
      </div>
      <div className="table-wrap">
        <table className="data-table decision-packs-table">
          <thead>
            <tr>
              <th>Pack ID</th>
              <th>Vulnerability</th>
              <th>Posture</th>
              <th>Readiness</th>
              <th>Verified</th>
              <th>Created</th>
              <th>Exports</th>
            </tr>
          </thead>
          <tbody>
            {packPage.items.map((pack) => (
              <tr key={pack.pack_id}>
                <td>{pack.pack_id}</td>
                <td>{pack.vulnerability_id}</td>
                <td>{humanize(pack.decision_posture || "unknown")}</td>
                <td>{humanize(pack.readiness?.readiness_state || "pending")}</td>
                <td>{pack.verification?.verified ? "Yes" : "Pending"}</td>
                <td>{pack.created_at ? new Date(pack.created_at).toLocaleString() : "Not recorded"}</td>
                <td>
                  <div className="export-actions">
                    <button type="button" className="icon-button" title="Export signed JSON pack" aria-label={`Export ${pack.pack_id}`} onClick={() => onExportPack(pack.pack_id)}>
                      <FileCheck2 size={16} aria-hidden />
                    </button>
                    <button type="button" className="icon-button" title={pack.verification?.verified ? "Download verified board DOCX" : "Verification required before report download"} aria-label={`Download DOCX ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "docx")} disabled={!defaultReport || !pack.verification?.verified}>
                      <FileText size={16} aria-hidden />
                    </button>
                    <button type="button" className="icon-button" title={pack.verification?.verified ? "Download verified board PDF" : "Verification required before report download"} aria-label={`Download PDF ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "pdf")} disabled={!defaultReport || !pack.verification?.verified}>
                      <Download size={16} aria-hidden />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!decisionPacks.length && <EmptyState title="No decision packs" detail="Signed packs appear after the workbench compiles a real tenant record." />}
      </div>
      <PaginationControls {...packPage} label="decision packs" />
    </>
  );
}

function Reports({
  decisionPacks,
  reports,
  onDownloadReport
}: {
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
}) {
  const sortedPacks = newestDecisionPacks(decisionPacks);
  const verifiedPacks = sortedPacks.filter((pack) => pack.verification?.verified);
  // Reports must never present or download an unverified pack as a signed output.
  // A dedicated pack selector remains required for deliberate historical selection.
  const latestPack = verifiedPacks[0] || null;
  const latestPackHasVendorLens = Boolean(latestPack?.artefacts && (
    latestPack.artefacts["config_applicability_assessment.json"]
    || latestPack.artefacts["customer_network_asset_snapshot.json"]
    || latestPack.artefacts["vendor_security_advisory_snapshot.json"]
    || latestPack.artefacts["sra_config_chat_session.json"]
  ));
  const latestBaseline = latestPack?.product_baseline || "Not recorded by runtime";
  const latestReportVersion = latestPack?.report_template_version || "Recorded when the pack is generated";
  const latestContextVersion = latestPack?.report_context_version || "Recorded when the pack is generated";
  const reportPage = usePagination(reports, 6, "reports-catalog");
  return (
    <>
      <div className="section-title">
        <h3>Decision Reports</h3>
        <span className="pill trust">DOCX / PDF only</span>
      </div>
      <section className="wide-band report-brief">
        <div>
          <p className="eyebrow">Signed governance outputs</p>
          <h3>Four practical reports for customer, board, CAB, and audit review</h3>
          <p className="muted-copy">
            Reports are generated from the signed decision-pack record, preserving the source-pack/current-state distinction, evidence readiness, advisory status, and no-autonomous-action boundary.
          </p>
        </div>
        <div className="report-pack-selector">
          <span className="pill steel">{verifiedPacks.length} verified packs</span>
          <span className="pill teal">{reports.length} active reports</span>
        </div>
      </section>

      <section className="data-band report-version-panel">
        <div className="section-title compact-title">
          <h3>Current Report Context</h3>
          <span className="pill teal">{latestBaseline}</span>
        </div>
        <div className="decision-option-grid compact-status-grid">
          <StatusLine label="Pack ID" value={latestPack?.pack_id || "No verified pack available"} tone={latestPack ? "trust" : "amber"} />
          <StatusLine label="Report version" value={latestReportVersion} tone="steel" />
          <StatusLine label="Context version" value={latestContextVersion} tone="steel" />
          <StatusLine label="Final approval" value={latestPack?.final_approval_issued ? "Issued" : "False"} tone="amber" />
          <StatusLine label="VendorLens context" value={latestPackHasVendorLens ? "Included in pack" : "Not attached to selected pack"} tone={latestPackHasVendorLens ? "teal" : "amber"} />
          <StatusLine label="Verification" value={latestPack?.verification?.verified ? "Verified" : "Required before report download"} tone={latestPack ? "trust" : "amber"} />
        </div>
        {!latestPackHasVendorLens && latestPack && <p className="boundary-copy">Selected pack can still export reports, but VendorLens sections will clearly state that network vendor applicability evidence was not attached.</p>}
      </section>

      <div className="report-grid">
        {reportPage.items.map((report) => (
          <section className="data-band report-card" key={report.report_type}>
            <div className="section-title compact-title">
              <h3>{report.title}</h3>
              <span className="pill steel">{report.audience}</span>
            </div>
            <StatusLine label="Source" value={latestPack ? "Verified signed decision pack" : "No verified pack selected"} tone={latestPack ? "trust" : "amber"} />
            <StatusLine label="Formats" value="DOCX and PDF" tone="teal" />
            <StatusLine label="Boundary" value="No deployment or approval" tone="amber" />
            <div className="report-actions">
              <button type="button" className="action-button" disabled={!latestPack} onClick={() => latestPack && onDownloadReport(latestPack.pack_id, report.report_type, "docx")}>
                <FileText size={16} aria-hidden /> DOCX
              </button>
              <button type="button" className="action-button secondary-action" disabled={!latestPack} onClick={() => latestPack && onDownloadReport(latestPack.pack_id, report.report_type, "pdf")}>
                <Download size={16} aria-hidden /> PDF
              </button>
            </div>
          </section>
        ))}
      </div>
      <PaginationControls {...reportPage} label="reports" />
      {!reports.length && <EmptyState title="No report catalogue" detail="Active report outputs load from the protected PatchForge API." />}
      {!decisionPacks.length && <EmptyState title="No signed pack available" detail="Generate a signed decision pack before producing board packs or customer reports." />}
      {decisionPacks.length > 0 && !verifiedPacks.length && <EmptyState title="No verified pack available" detail="Report downloads remain blocked until a decision pack passes signature verification." />}
    </>
  );
}

function Admin({
  tenantId,
  setTenantId,
  adminEnvironment,
  setAdminEnvironment,
  adminTier,
  setAdminTier,
  adminHealth,
  agentStatus,
  onSave,
  purgeScopes,
  setPurgeScopes,
  purgeConfirm,
  setPurgeConfirm,
  latestPurgePlan,
  onPreviewPurge,
  onExecutePurge
}: {
  tenantId: string;
  setTenantId: (tenantId: string) => void;
  adminEnvironment: string;
  setAdminEnvironment: (value: string) => void;
  adminTier: string;
  setAdminTier: (value: string) => void;
  adminHealth: AdminHealth | null;
  agentStatus: OpenAiAgentStatus | null;
  onSave: () => void;
  purgeScopes: Record<string, boolean>;
  setPurgeScopes: (value: Record<string, boolean>) => void;
  purgeConfirm: string;
  setPurgeConfirm: (value: string) => void;
  latestPurgePlan: AdminPurgePlan | null;
  onPreviewPurge: () => void;
  onExecutePurge: () => void;
}) {
  const healthPage = usePagination(adminHealth?.checks || [], 8, "admin-health");
  const sectionPage = usePagination(adminSections, 12, "admin-sections");
  const selectedPurgeScopeCount = Object.values(purgeScopes).filter(Boolean).length;
  const agentReady = Boolean(agentStatus?.enabled && agentStatus.configured);
  const agentLabel = agentStatus?.enabled ? (agentStatus.configured ? "Ready" : "Unavailable") : "Runtime disabled";
  const agentTone = agentReady ? "teal" : agentStatus?.enabled ? "amber" : "steel";

  return (
    <>
      <div className="section-title">
        <h3>System & Data Health</h3>
        <span className="pill trust">Production guarded</span>
      </div>

      <section className="wide-band">
        <div>
          <p className="eyebrow">Defensive-use boundary</p>
          <h3>Governed intelligence and human-reviewable action packs</h3>
          <p className="muted-copy">PatchForge sits above scanners, EDR, SIEM, SOAR, ITSM, CMDB, patch-management, cloud-management, and monitoring systems. It explains risk, maps exposure, compares patch or hotfix choices, and produces signed evidence packs without exploit mechanics, production mutation, or autonomous approval.</p>
        </div>
      </section>

      <div className="admin-layout">
        <section className="config-panel" aria-label="Admin configuration">
          <h4>Tenant Configuration</h4>
          <label>
            Tenant
            <input value={tenantId} onChange={(event) => setTenantId(event.target.value)} aria-label="Tenant name" />
          </label>
          <label>
            Environment
            <input value={adminEnvironment} onChange={(event) => setAdminEnvironment(event.target.value)} aria-label="Environment" />
          </label>
          <label>
            Governance tier
            <input value={adminTier} onChange={(event) => setAdminTier(event.target.value)} aria-label="Governance tier" />
          </label>
          <div className="toggle-row">
            <span>SRA advisory only</span>
            <strong className="pill teal">Locked</strong>
          </div>
          <div className="toggle-row">
            <span>Live Azure mutation</span>
            <strong className="pill amber">Blocked</strong>
          </div>
          <StatusLine label="Ask PatchForge deterministic" value="Active" tone="trust" />
          <StatusLine label="AI assistance" value={agentLabel} tone={agentTone} detail={agentStatus?.model || "Runtime status unavailable"} />
          <StatusLine label="AI verifier" value="Required" tone="amber" />
          <button type="button" className="action-button" onClick={onSave}>
            <CheckCircle2 size={16} aria-hidden /> Save Admin Configuration
          </button>
        </section>

        <section className="config-panel" aria-label="Admin health dashboard">
          <h4>Health Checks</h4>
          <div className="health-list">
            {healthPage.items.map((check) => (
              <StatusLine key={check.name} label={check.name} value={humanize(check.status)} tone={healthTone(check.status)} detail={check.mode} />
            ))}
            {!adminHealth?.checks?.length && <p className="muted-copy">Health checks load from the protected bridge API.</p>}
          </div>
          <PaginationControls {...healthPage} label="health checks" />
        </section>
      </div>

      <section className="wide-band">
        <div>
          <p className="eyebrow">Factory reset and purge</p>
          <h3>Typed confirmation required before destructive data cleanup</h3>
          <p className="muted-copy">Preview generated reports, catalogue, asset, upload, log, and cache cleanup before execution. Git history, restore tags, signing/verifier core, RBAC, Azure deployment scripts, tests, and release evidence are preserved.</p>
        </div>
        <div className="purge-panel">
          <div className="toggle-grid">
            {purgeScopeOptions.map((scope) => (
              <label className="check-option" key={scope.key}>
                <input
                  type="checkbox"
                  checked={Boolean(purgeScopes[scope.key])}
                  onChange={(event) => setPurgeScopes({ ...purgeScopes, [scope.key]: event.target.checked })}
                />
                <span>{scope.label}</span>
              </label>
            ))}
          </div>
          <label className="stacked-input">
            <span>Typed confirmation</span>
            <input value={purgeConfirm} onChange={(event) => setPurgeConfirm(event.target.value)} placeholder="FACTORY_RESET_PATCHFORGE" />
          </label>
          <div className="report-actions">
            <button type="button" className="action-button secondary-action" onClick={onPreviewPurge} disabled={!selectedPurgeScopeCount}>
              <Search size={16} aria-hidden /> Preview Purge
            </button>
            <button type="button" className="action-button" onClick={onExecutePurge} disabled={!selectedPurgeScopeCount || purgeConfirm !== "FACTORY_RESET_PATCHFORGE"}>
              <Archive size={16} aria-hidden /> Execute Confirmed Purge
            </button>
          </div>
          {latestPurgePlan && (
            <div className="insight-list">
              <StatusLine label="Dry run" value={latestPurgePlan.dry_run ? "Yes" : "No"} tone={latestPurgePlan.dry_run ? "steel" : "amber"} />
              <StatusLine label="Scopes" value={latestPurgePlan.scopes.join(", ") || "None selected"} tone="steel" />
              <StatusLine label="Records in scope" value={String(latestPurgePlan.total_records)} tone={latestPurgePlan.total_records ? "amber" : "teal"} />
              <StatusLine label="Confirmation" value={latestPurgePlan.required_confirmation} tone="trust" />
            </div>
          )}
        </div>
      </section>

      <div className="admin-grid admin-section-grid">
        {sectionPage.items.map((section) => (
          <article className="admin-tile admin-status-tile" key={section.label}>
            <KeyRound size={17} aria-hidden />
            <div>
              <strong>{section.label}</strong>
              <span className={`pill ${section.tone}`}>{section.status}</span>
              <p>{section.detail}</p>
            </div>
          </article>
        ))}
      </div>
      <PaginationControls {...sectionPage} label="admin sections" />
    </>
  );
}

function PageBand({ icon: Icon, title, lines }: { icon: typeof Gauge; title: string; lines: string[] }) {
  return (
    <section className="page-band">
      <Icon size={28} aria-hidden />
      <h3>{title}</h3>
      <div className="line-stack">
        {lines.map((line) => <p key={line}>{line}</p>)}
      </div>
    </section>
  );
}

function StatusLine({ label, value, tone, detail }: { label: string; value: string; tone: string; detail?: string }) {
  return (
    <div className="status-line">
      <span>
        {label}
        {detail && <small>{humanize(detail)}</small>}
      </span>
      <strong className={`pill ${tone}`}>{value}</strong>
    </div>
  );
}

type PaginationState<T> = {
  items: T[];
  page: number;
  pageCount: number;
  total: number;
  pageSize: number;
  start: number;
  end: number;
  setPage: (page: number) => void;
};

function usePagination<T>(items: T[], pageSize = 8, key = "page"): PaginationState<T> {
  const [pageByKey, setPageByKey] = useState<Record<string, number>>({});
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const requestedPage = pageByKey[key] || 1;
  const page = Math.min(Math.max(1, requestedPage), pageCount);
  useEffect(() => {
    if (requestedPage !== page) {
      setPageByKey((current) => ({ ...current, [key]: page }));
    }
  }, [key, page, requestedPage]);
  const start = (page - 1) * pageSize;
  const end = Math.min(start + pageSize, items.length);
  return {
    items: items.slice(start, end),
    page,
    pageCount,
    total: items.length,
    pageSize,
    start,
    end,
    setPage: (nextPage) => setPageByKey((current) => ({ ...current, [key]: Math.min(Math.max(1, nextPage), pageCount) }))
  };
}

function PaginationControls<T>({ page, pageCount, total, start, end, setPage, label }: PaginationState<T> & { label: string }) {
  if (total <= 0) {
    return null;
  }
  const pages = pageNumbers(page, pageCount);
  return (
    <nav className="pagination" aria-label={`${label} pagination`}>
      <span>{start + 1}-{end} of {total} {label}</span>
      <div>
        <button type="button" className="icon-button page-button" onClick={() => setPage(page - 1)} disabled={page <= 1} aria-label={`Previous ${label} page`}>Back</button>
        {pages.map((item, index) => item === "gap"
          ? <span className="page-gap" key={`${label}-${item}-${index}`}>...</span>
          : <button type="button" className={item === page ? "icon-button page-button active" : "icon-button page-button"} key={`${label}-${item}`} onClick={() => setPage(item)} aria-label={`${label} page ${item}`}>{item}</button>)}
        <button type="button" className="icon-button page-button" onClick={() => setPage(page + 1)} disabled={page >= pageCount} aria-label={`Next ${label} page`}>Next</button>
      </div>
    </nav>
  );
}

function pageNumbers(current: number, total: number): Array<number | "gap"> {
  if (total <= 7) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }
  const values = new Set([1, total, current - 1, current, current + 1]);
  const sorted = Array.from(values).filter((value) => value >= 1 && value <= total).sort((a, b) => a - b);
  return sorted.flatMap((value, index) => index > 0 && value - sorted[index - 1] > 1 ? ["gap" as const, value] : [value]);
}

function UtilityRail({
  session,
  metrics,
  decisionPacks,
  sourceFeedState,
  adminHealth
}: {
  session: PatchForgeAuthSession;
  metrics: PatchForgeMetrics;
  decisionPacks: DecisionPackRecord[];
  sourceFeedState: SourceFeedState;
  adminHealth: AdminHealth | null;
}) {
  const signing = adminHealth?.checks?.find((check) => check.name === "Signing trust");
  const signingStatus = signing?.status || "unknown";
  return (
    <>
      <section className="rail-section">
        <h3>Session</h3>
        <p className="rail-note"><BadgeCheck size={15} aria-hidden /> {session.accountName || "Signed in"}</p>
        <p className="rail-note"><LockKeyhole size={15} aria-hidden /> App roles enforced by API</p>
        <p className="rail-note"><KeyRound size={15} aria-hidden /> {session.roles.length ? session.roles.join(", ") : "No PatchForge role in token"}</p>
      </section>
      <section className="rail-section">
        <h3>Queue</h3>
        <StatusLine label="Records" value={String(metrics.vulnerability_count)} tone="steel" />
        <StatusLine label="Pending review" value={String(metrics.pending_review)} tone="amber" />
      </section>
      <section className="rail-section">
        <h3>Source Feeds</h3>
        <StatusLine label="Feeds" value={String(sourceFeedState.feeds.length)} tone="steel" />
        <StatusLine label="Runs" value={String(sourceFeedState.recent_runs.length)} tone="teal" />
      </section>
      <section className="rail-section">
        <h3>Signing Trust</h3>
        <StatusLine label="Verifier" value={decisionPacks.some((pack) => pack.verification?.verified) ? "Verified pack present" : "No verified pack"} tone={decisionPacks.some((pack) => pack.verification?.verified) ? "trust" : "amber"} />
        <StatusLine label="Trust" value={humanize(signingStatus)} tone={healthTone(signingStatus)} detail={signing?.mode || "Admin health status unavailable or restricted"} />
      </section>
      <section className="rail-section">
        <h3>Recent Packs</h3>
        {decisionPacks.slice(0, 3).map((pack) => (
          <p className="rail-note" key={pack.pack_id}><CheckCircle2 size={15} aria-hidden /> {pack.pack_id}</p>
        ))}
        {!decisionPacks.length && <p className="muted-copy">No packs yet.</p>}
      </section>
    </>
  );
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <Database size={22} aria-hidden />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function emptyLiveState(tenantId: string): LiveState {
  return {
    metrics: {
      tenant_id: tenantId,
      vulnerability_count: 0,
      critical_exposure: 0,
      known_exploited: 0,
      patch_overdue: 0,
      pending_review: 0,
      accepted_positive_evidence_sources: 0,
      rejected_sources: 0,
      signed_packs: 0
    },
    securityActionCenter: {
      tenant_id: tenantId,
      generated_at: "",
      catalogue_rows: [],
      groups: [],
      vendors: [],
      filters: {},
      source_feed_status: [],
      summary: {}
    },
    customerEstate: {
      assets: [],
      services: [],
      exposure_matches: [],
      patch_comparisons: []
    },
    reportsPacks: {
      reports: [],
      decision_packs: [],
      export_options: [],
      pre_export_state: null
    },
    findings: [],
    vulnerabilities: [],
    assets: [],
    services: [],
    decisionPacks: [],
    reports: [],
    bayesian: null,
    threatSummary: null,
    vendors: [],
    vendorLens: {
      dashboard: null,
      vendors: [],
      assets: [],
      advisories: [],
      latestAssessment: null,
      latestChat: null,
      latestComparison: null
    },
    latestCustomerMatch: null,
    latestAskPatchForge: null,
    openAiAgentStatus: null,
    latestAgentGuidance: null,
    sourceFeedState: { feeds: [], recent_runs: [] },
    adminHealth: null,
    adminConfig: {},
    discovery: null
  };
}

function parseList(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function candidateValue(candidate: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = candidate[key];
    if (value !== undefined && value !== null && value !== "") {
      return String(value);
    }
  }
  return "";
}

function candidateList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).filter(Boolean);
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return [String(value)];
}

function latestSourceRun(state: SourceFeedState) {
  return [...state.recent_runs]
    .filter((run) => Boolean(run.completed_at))
    .sort((left, right) => Date.parse(right.completed_at || "") - Date.parse(left.completed_at || ""))[0] || null;
}

function sourceRunLabel(state: SourceFeedState): string {
  const run = latestSourceRun(state);
  if (!run?.completed_at) {
    return "No source run recorded";
  }
  if (!/completed/i.test(run.status || "")) {
    return `Last source run ${humanize(run.status || "failed")}`;
  }
  const completedAt = Date.parse(run.completed_at);
  if (!Number.isFinite(completedAt)) {
    return "Source run time unavailable";
  }
  const minutes = Math.max(0, Math.floor((Date.now() - completedAt) / 60000));
  if (minutes < 1) {
    return "Last source run just now";
  }
  if (minutes < 60) {
    return `Last source run ${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `Last source run ${hours}h ago`;
  }
  return `Last source run ${Math.floor(hours / 24)}d ago`;
}

function sourceRunTone(state: SourceFeedState): string {
  const run = latestSourceRun(state);
  if (!run?.completed_at) {
    return "source-unknown";
  }
  const age = Date.now() - Date.parse(run.completed_at);
  if (!/completed/i.test(run.status || "") || !Number.isFinite(age) || age > 8 * 60 * 60 * 1000) {
    return "source-stale";
  }
  return "source-current";
}

function accountDisplayName(accountName: string | null): string {
  if (!accountName) {
    return "Signed in";
  }
  const localPart = accountName.split("@")[0];
  return localPart.split(/[._-]/).filter(Boolean).map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" ") || accountName;
}

function accountInitials(accountName: string | null): string {
  const displayName = accountDisplayName(accountName);
  return displayName.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part.charAt(0).toUpperCase()).join("") || "PF";
}

function displayRole(roles: string[]): string {
  const role = roles.find((item) => item.startsWith("PatchForge.")) || roles[0];
  return role ? role.replace("PatchForge.", "") : "Role pending";
}

function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}

function newestDecisionPacks(decisionPacks: DecisionPackRecord[]): DecisionPackRecord[] {
  return [...decisionPacks].sort((a, b) => {
    const byCreatedAt = decisionPackTime(b) - decisionPackTime(a);
    return byCreatedAt || String(b.pack_id || b.decision_pack_id || "").localeCompare(String(a.pack_id || a.decision_pack_id || ""));
  });
}

function decisionPackTime(pack: DecisionPackRecord): number {
  const parsed = Date.parse(pack.created_at || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function relevantPatchComparison(comparison: VendorLensPatchComparison | null, selectedAdvisoryId: string): VendorLensPatchComparison | null {
  if (!comparison || !selectedAdvisoryId) {
    return null;
  }
  const comparisonIds = [comparison.advisory_id, comparison.cve].filter(Boolean).map((value) => String(value).toLowerCase());
  return comparisonIds.includes(selectedAdvisoryId.toLowerCase()) ? comparison : null;
}

function recordMatchesContext(
  record: { asset_id?: string | null; advisory_id?: string | null; cve?: string | null } | null,
  assetId: string,
  advisoryId: string
): boolean {
  if (!record) {
    return false;
  }
  const recordAdvisoryIds = [record.advisory_id, record.cve]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());
  return (!assetId || record.asset_id === assetId)
    && (!advisoryId || recordAdvisoryIds.includes(advisoryId.toLowerCase()));
}

function severityTone(severity = "") {
  if (severity.toLowerCase() === "critical") {
    return "danger";
  }
  if (severity.toLowerCase() === "high") {
    return "amber";
  }
  if (severity.toLowerCase() === "medium") {
    return "steel";
  }
  return "teal";
}

function postureLabel(finding: FindingIntelligence) {
  return finding.recommendation.customer_posture || humanize(finding.recommendation.display_posture || finding.recommendation.posture || "defer_pending_evidence");
}

function hasAnyRole(actual: string[], required: string[]) {
  return actual.some((role) => required.includes(role));
}

function healthTone(status = "") {
  if (["ready", "verified", "advisory", "governed"].includes(status.toLowerCase())) {
    return "trust";
  }
  if (["planned", "pending", "placeholder", "unknown", "stale", "degraded", "failed"].includes(status.toLowerCase())) {
    return "amber";
  }
  return "steel";
}

function signalLabel(item: VulnerabilityRecord) {
  const signals = [];
  if (item.known_exploited) {
    signals.push("Known exploited");
  }
  if (item.internet_exposed) {
    signals.push("Internet exposed");
  }
  if (item.ot_relevant) {
    signals.push("OT");
  }
  return signals.join(", ") || "No reviewed signal";
}

function shortValue(value = "") {
  const text = String(value || "Not recorded");
  return text.length > 42 ? `${text.slice(0, 39)}...` : text;
}

function buildDiscoveryCollectorConfig({
  apiBaseUrl,
  tenantId,
  discovery
}: {
  apiBaseUrl: string;
  tenantId: string;
  discovery: AssetDiscoveryOverview | null;
}) {
  const collector = discovery?.collectors?.[0];
  const policy = discovery?.policies?.[0];
  const collectorId = collector?.collector_id || "collector-customer-estate-mvp";
  const categories = collector?.enabled_categories?.length
    ? collector.enabled_categories
    : policy?.categories?.length
      ? policy.categories
      : discoveryCollectorCategories;
  const site = collector?.site || "Primary site";

  return {
    apiBaseUrl: apiBaseUrl.replace(/\/+$/, ""),
    tenantId,
    collector: {
      collector_id: collectorId,
      name: collector?.name || "Customer estate collector MVP",
      site,
      environment: collector?.environment || "production",
      categories
    },
    policy: {
      policy_id: policy?.policy_id || "policy-customer-estate-mvp",
      collector_id: collectorId,
      name: policy?.name || "Read-only customer estate snapshot",
      categories: policy?.categories?.length ? policy.categories : categories,
      credential_reference: policy?.credential_reference || "customer-vault:patchforge/read-only-discovery",
      scope: {
        sites: [site],
        source_systems: ["local_host", "hyperv", "azure_cli", "http_json"]
      }
    },
    auth: {
      bearerTokenEnv: "PATCHFORGE_COLLECTOR_TOKEN"
    },
    adapters: [
      {
        type: "local_host",
        enabled: true
      },
      {
        type: "hyperv",
        enabled: true
      },
      {
        type: "azure_cli",
        enabled: false,
        subscription: "00000000-0000-0000-0000-000000000000"
      },
      {
        type: "http_json",
        enabled: false,
        url: "https://nms.example.test/api/assets",
        headers: {
          Authorization: "Bearer env:NMS_READONLY_TOKEN"
        },
        assetPath: "items",
        fieldMap: {
          asset_id: "id",
          category: "category",
          hostname: "hostname",
          vendor_name: "vendor",
          product_family: "product",
          model: "model",
          firmware_version: "version",
          ip_addresses: "ip"
        }
      }
    ]
  };
}

function safeFileStem(value: string) {
  return String(value || "tenant").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "tenant";
}

function downloadJson(fileName: string, payload: unknown) {
  const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: "application/json" });
  downloadBlob(fileName, blob);
}

function downloadBlob(fileName: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

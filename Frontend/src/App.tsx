import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Archive,
  BadgeCheck,
  Binary,
  Blocks,
  BookOpenCheck,
  CheckCircle2,
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
  ShieldAlert,
  SlidersHorizontal,
  TriangleAlert,
  Upload,
  Wrench
} from "lucide-react";
import {
  AdminConfig,
  AdminHealth,
  AssetRecord,
  BayesianAssessment,
  ConfigApplicabilityAssessment,
  CustomerAssetExtraction,
  CustomerEstateMatch,
  CustomerEstateState,
  CustomerNetworkAsset,
  DecisionPackRecord,
  FindingIntelligence,
  NetworkVendorProfile,
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
  | "Global Security Action Center"
  | "Customer Estate"
  | "Ask PatchForge"
  | "Action Center"
  | "Finding Detail"
  | "Review & Approve"
  | "Reports & Packs"
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
  | "Reports"
  | "Source Feeds"
  | "Vendor & Threat Landscape"
  | "VendorLens"
  | "Admin";

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
  sourceFeedState: SourceFeedState;
  adminHealth: AdminHealth | null;
  adminConfig: AdminConfig;
};

const PRODUCT_MARK = "DIIaC\u2122";
const ACTIVE_BASELINE = "PF-AZ10-SIMPLIFIED-EXPERIENCE";
const REPORT_TEMPLATE_VERSION = "patchforge-report-template.v2026-05-30.1";
const REPORT_CONTEXT_VERSION = "patchforge-report-context.v3";
const config = getPatchForgeConfig();

const navItems: NavItem[] = [
  { label: "Global Security Action Center", icon: Gauge },
  { label: "Customer Estate", icon: ServerCog },
  { label: "Ask PatchForge", icon: MessageSquareText },
  { label: "Reports & Packs", icon: FileText },
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

const adminSections = [
  "General Settings",
  "Tenant Configuration",
  "Entra ID / RBAC",
  "SRA Configuration",
  "MCP Agent Connectors",
  "Mythos / AGI Findings",
  "Agent Finding Rules",
  "KRA / DIIaC IT Integration",
  "Scanner Integrations",
  "Source Feeds",
  "VendorLens Sources",
  "Evidence Models",
  "Policy Packs",
  "Decision State Rules",
  "Risk Acceptance Rules",
  "SLA / Ageing Rules",
  "Signing & Trust",
  "Key Vault",
  "Storage",
  "Database",
  "Telemetry",
  "Health Checks",
  "Audit Logs",
  "Export Settings",
  "Backup / Restore",
  "Data Retention",
  "Feature Flags"
];

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
  const [activePage, setActivePage] = useState<PageKey>("Global Security Action Center");
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
  const isAdmin = hasAnyRole(session.roles, ["PatchForge.Admin"]);
  const canReadAdmin = hasAnyRole(session.roles, ["PatchForge.Admin", "PatchForge.Auditor"]);
  const selectedFinding = useMemo(
    () => state.findings.find((item) => item.vulnerability_id === selectedVulnerabilityId) || state.findings[0] || null,
    [selectedVulnerabilityId, state.findings]
  );
  const selectedGlobalRecord = useMemo(
    () => state.securityActionCenter.catalogue_rows.find((row) =>
      [row.vulnerability_id, row.cve_id, row.advisory_id, row.id].filter(Boolean).includes(selectedVulnerabilityId)
      || [row.advisory_id, row.cve_id, row.id].filter(Boolean).includes(selectedAdvisoryId)
    ) || state.securityActionCenter.catalogue_rows[0] || null,
    [selectedAdvisoryId, selectedVulnerabilityId, state.securityActionCenter.catalogue_rows]
  );
  const visibleNav = useMemo(
    () => navItems.filter((item) => item.label !== "Admin" || isAdmin),
    [isAdmin]
  );

  const loadLiveState = useCallback(async () => {
    if (session.status !== "authenticated") {
      return;
    }
    setRefreshing(true);
    setOperationError(null);
    try {
      const [metrics, securityActionCenter, customerEstate, reportsPacks, vulnerabilities, findings, assets, services, decisionPacks, reports, threatSummary, vendors, sourceFeedState, vendorLensDashboard, networkVendors, customerNetworkAssets, vendorSecurityAdvisories, adminHealth, adminConfig] = await Promise.all([
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
        bayesian: null,
        adminHealth,
        adminConfig
      }));
      setSelectedVulnerabilityId((current) => current || vulnerabilities[0]?.vulnerability_id || "");
      setSelectedCustomerAssetId((current) => current || customerEstate.assets[0]?.asset_id || customerNetworkAssets[0]?.asset_id || "");
      setSelectedAdvisoryId((current) => current || vendorSecurityAdvisories[0]?.advisory_id || "");
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

  async function handleGeneratePack() {
    setOperationMessage(null);
    setOperationError(null);
    if (!selectedVulnerabilityId) {
      setOperationError("Select a real ingested vulnerability before generating a decision pack.");
      return;
    }
    try {
      const pack = await liveApi.generateReportsPack(tenantId, {
        vulnerability_id: selectedVulnerabilityId,
        requested_posture: selectedPosture,
        bayesian_snapshot: state.bayesian,
        config_applicability_assessment: state.vendorLens.latestAssessment,
        vendorlens_patch_comparison: state.vendorLens.latestComparison,
        sra_config_chat_session: state.vendorLens.latestChat,
        asset_id: state.vendorLens.latestAssessment?.asset_id || selectedCustomerAssetId || state.vendorLens.assets[0]?.asset_id,
        advisory_id: state.vendorLens.latestAssessment?.advisory_id || selectedAdvisoryId || state.vendorLens.advisories[0]?.advisory_id,
        product_baseline: ACTIVE_BASELINE,
        report_template_version: REPORT_TEMPLATE_VERSION,
        report_context_version: REPORT_CONTEXT_VERSION
      });
      setOperationMessage(`Signed decision pack ${pack.pack_id} generated.`);
      await loadLiveState();
      setActivePage("Reports & Packs");
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

  async function handleRefreshSourceFeed(feedId: string) {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const payload: Record<string, unknown> = feedId === "cisa-kev"
        ? { feed_id: feedId, limit: 5 }
        : { feed_id: feedId, cve: selectedVulnerabilityId || state.vulnerabilities[0]?.vulnerability_id };
      const run = await liveApi.refreshSourceFeed(tenantId, payload);
      setOperationMessage(`${run.feed_name} ${run.status}: ${run.message || "source-bound refresh recorded."}`);
      await loadLiveState();
      setActivePage("Source Feeds");
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
    try {
      const comparison = await liveApi.compareCustomerEstatePatch(tenantId, {
        asset_id: selectedCustomerAssetId || state.customerEstate.assets[0]?.asset_id || state.vendorLens.assets[0]?.asset_id,
        advisory_id: selectedAdvisoryId || state.vendorLens.advisories[0]?.advisory_id,
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

  async function handleAskPatchForge() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const answer = await liveApi.askPatchForge(tenantId, {
        question: askQuestion,
        asset_id: selectedCustomerAssetId || undefined,
        advisory_id: selectedAdvisoryId || undefined,
        patch_compare: state.vendorLens.latestComparison || undefined
      });
      setState((current) => ({ ...current, latestAskPatchForge: answer }));
      setOperationMessage(`Ask PatchForge answered: ${answer.response.short_answer}`);
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

  async function handleAssessVendorLens() {
    setOperationMessage(null);
    setOperationError(null);
    const asset = state.vendorLens.assets[0];
    const advisory = state.vendorLens.advisories[0];
    if (!asset || !advisory) {
      setOperationError("VendorLens needs at least one customer network asset and one vendor advisory before assessing applicability.");
      return;
    }
    try {
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

  async function handleAskVendorLens() {
    setOperationMessage(null);
    setOperationError(null);
    const asset = state.vendorLens.assets[0];
    const advisory = state.vendorLens.advisories[0];
    if (!asset || !advisory) {
      setOperationError("Add or select a network asset and vendor advisory before asking PatchForge.");
      return;
    }
    try {
      const chat = await liveApi.startVendorLensChat(tenantId, {
        question: vendorLensQuestion,
        asset_id: asset.asset_id,
        advisory_id: advisory.advisory_id,
        assessment: state.vendorLens.latestAssessment || undefined
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
        max_vendors: 17,
        results_per_page: 100,
        max_pages: 1
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

  if (session.status !== "authenticated") {
    return <SignedOutShell session={session} />;
  }

  return (
    <main className="app-shell">
      <aside className="side-nav" aria-label="PatchForge navigation">
        <BrandLockup />
        <nav>
          {visibleNav.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={activePage === label ? "nav-button active" : "nav-button"}
              onClick={() => setActivePage(label)}
              type="button"
            >
              <Icon size={18} aria-hidden />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <BoundaryPanel />
      </aside>

      <section className="workspace">
        <header className="top-rail">
          <button className="icon-button" aria-label="Toggle navigation" type="button">
            <PanelLeft size={18} aria-hidden />
          </button>
          <div>
            <p className="eyebrow">{config.environmentLabel} | {tenantId} | Enterprise Strict</p>
            <h2>{activePage}</h2>
          </div>
          <div className="status-strip" aria-label="Runtime trust status">
            <span><BadgeCheck size={16} aria-hidden /> Entra protected</span>
            <span><Radar size={16} aria-hidden /> Agent-led intake</span>
            <span><FileCheck2 size={16} aria-hidden /> Signing trusted</span>
            <button type="button" className="pill-button" onClick={loadLiveState} disabled={refreshing}>
              <RefreshCw size={15} aria-hidden /> {refreshing ? "Refreshing" : "Refresh"}
            </button>
            <button type="button" className="pill-button" onClick={() => void session.signOut()}>
              <LogOut size={15} aria-hidden /> Sign out
            </button>
          </div>
        </header>

        <div className="content-grid">
          <section className="primary-panel" aria-label={activePage}>
            <OperationMessages message={operationMessage} error={operationError} />
            {selectedFinding && ["Global Security Action Center", "Action Center", "Finding Detail", "Review & Approve", "Reports & Packs"].includes(activePage) && (
              <FindingContextBanner finding={selectedFinding} />
            )}
            {activePage === "Global Security Action Center" && (
              <GlobalSecurityActionCenter
                state={state.securityActionCenter}
                query={globalSearch}
                setQuery={setGlobalSearch}
                filters={globalFilters}
                setFilters={setGlobalFilters}
                selectedRow={selectedGlobalRecord}
                onSearch={handleSearchSecurityActionCenter}
                onSelectCve={(row) => {
                  setSelectedVulnerabilityId(row.vulnerability_id || row.cve_id || row.advisory_id || "");
                  setSelectedAdvisoryId(row.advisory_id || selectedAdvisoryId);
                }}
                canWrite={canWrite}
                onRefreshSourceFeed={handleRefreshSourceFeed}
              />
            )}
            {activePage === "Customer Estate" && (
              <CustomerEstate
                state={state.customerEstate}
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
                latestComparison={state.vendorLens.latestComparison}
                onExtract={handleExtractCustomerAsset}
                onConfirmAsset={handleConfirmCustomerAsset}
                onMatch={handleMatchCustomerEstate}
                onPatchCompare={handleCustomerPatchCompare}
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
                latestComparison={state.vendorLens.latestComparison}
                onAsk={handleAskPatchForge}
                onPatchCompare={handleCustomerPatchCompare}
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
            {activePage === "Reports & Packs" && (
              <ReportsPacks
                findings={state.findings}
                decisionPacks={state.decisionPacks}
                reports={state.reports}
                reportsPacks={state.reportsPacks}
                onGenerate={handleGeneratePack}
                onExportPack={handleExportPack}
                onDownloadReport={handleDownloadReport}
                canWrite={canWrite}
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
            {activePage === "Reports" && <Reports decisionPacks={state.decisionPacks} reports={state.reports} onDownloadReport={handleDownloadReport} />}
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
                onSave={handleSaveAdmin}
              /> : <PageBand icon={LockKeyhole} title="Admin" lines={["PatchForge.Admin role required", "Admin controls are hidden for reader users", "API app roles are enforced server-side"]} />
            )}
          </section>

          <aside className="utility-rail" aria-label="PatchForge utility rail">
            <UtilityRail session={session} metrics={state.metrics} decisionPacks={state.decisionPacks} sourceFeedState={state.sourceFeedState} adminHealth={state.adminHealth} />
          </aside>
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
          <h2>{PRODUCT_MARK} PatchForge</h2>
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
        <p>{PRODUCT_MARK}</p>
        <h1>PatchForge</h1>
      </div>
    </div>
  );
}

function BoundaryPanel() {
  return (
    <div className="boundary-panel">
      <LockKeyhole size={18} aria-hidden />
      <p>Governance layer only. No scanning, no exploit content, no patch deployment, no autonomous approvals.</p>
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
  query,
  setQuery,
  filters,
  setFilters,
  selectedRow,
  onSearch,
  onSelectCve,
  canWrite,
  onRefreshSourceFeed
}: {
  state: SecurityActionCenterState;
  query: string;
  setQuery: (value: string) => void;
  filters: { vendor: string; severity: string; customer_match: string; patch_available: string };
  setFilters: (value: { vendor: string; severity: string; customer_match: string; patch_available: string }) => void;
  selectedRow: SecurityActionCenterRow | null;
  onSearch: () => void;
  onSelectCve: (row: SecurityActionCenterRow) => void;
  canWrite: boolean;
  onRefreshSourceFeed: (feedId: string) => void;
}) {
  const rowsPage = usePagination(state.catalogue_rows || [], 8, "global-security-action-center");
  const vendorOptions = state.filters?.vendors || [];
  const severityOptions = state.filters?.severities || [];
  const summary = state.summary || {};

  return (
    <>
      <div className="metric-grid">
        <MetricCard icon={ListFilter} label="Catalogue records" value={summary.total_records ?? state.catalogue_rows.length} tone="steel" />
        <MetricCard icon={ShieldAlert} label="Known exploited" value={summary.known_exploited_records ?? 0} tone="amber" />
        <MetricCard icon={TriangleAlert} label="Critical" value={summary.critical_records ?? 0} tone="danger" />
        <MetricCard icon={Network} label="Customer matches" value={summary.customer_match_records ?? 0} tone="trust" />
      </div>

      <section className="wide-band search-console">
        <div className="section-title">
          <div>
            <p className="eyebrow">Global CVE/advisory catalogue</p>
            <h3>Global Security Action Center</h3>
          </div>
          <div className="hero-actions">
            <button type="button" className="action-button" onClick={() => onRefreshSourceFeed("cisa-kev")} disabled={!canWrite}>
              <RefreshCw size={16} aria-hidden /> Refresh KEV
            </button>
            <button type="button" className="action-button secondary-action" onClick={() => onRefreshSourceFeed("first-epss")} disabled={!canWrite}>
              <Radar size={16} aria-hidden /> Refresh EPSS
            </button>
          </div>
        </div>
        <div className="search-row">
          <label className="wide-input">
            <span>Search</span>
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, advisory, vendor, product, feature, model, version, source" />
          </label>
          <button type="button" className="action-button" onClick={onSearch}>
            <Search size={16} aria-hidden /> Search
          </button>
        </div>
        <div className="filter-grid">
          <label>Vendor<select value={filters.vendor} onChange={(event) => setFilters({ ...filters, vendor: event.target.value })}><option value="">All vendors</option>{vendorOptions.map((item) => <option key={item.value} value={item.value}>{item.value}</option>)}</select></label>
          <label>Severity<select value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option>{severityOptions.map((item) => <option key={item.value} value={item.value}>{humanize(item.value)}</option>)}</select></label>
          <label>Customer match<select value={filters.customer_match} onChange={(event) => setFilters({ ...filters, customer_match: event.target.value })}><option value="">All</option><option value="true">Matched</option><option value="false">No match</option></select></label>
          <label>Patch available<select value={filters.patch_available} onChange={(event) => setFilters({ ...filters, patch_available: event.target.value })}><option value="">All</option><option value="true">Available</option><option value="false">Unknown / no</option></select></label>
        </div>
      </section>

      <section className="data-band">
        <div className="section-title">
          <h3>Vendor Groups</h3>
          <span className="pill teal">{state.groups.length} grouped vendor view(s)</span>
        </div>
        <div className="group-strip">
          {state.groups.slice(0, 8).map((group) => (
            <article className="mini-group" key={group.vendor_id}>
              <strong>{group.vendor_name}</strong>
              <span>{group.count} records</span>
              <small>{group.customer_match_count} customer matches</small>
            </article>
          ))}
        </div>
      </section>

      <section className="data-band table-band">
        <div className="section-title">
          <h3>Grouped CVE / Advisory Catalogue</h3>
          <span className="pill amber">Final approval false by default</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>CVE / Advisory ID</th>
                <th>Title</th>
                <th>Vendor</th>
                <th>Product family</th>
                <th>Affected feature</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th>Patch</th>
                <th>Known exploited</th>
                <th>Source state</th>
                <th>Review state</th>
                <th>Customer matches</th>
                <th>Urgency posture</th>
                <th>Final approval</th>
                <th>Last refreshed</th>
              </tr>
            </thead>
            <tbody>
              {rowsPage.items.map((row) => (
                <tr key={`${row.record_type}-${row.id}`}>
                  <td><button type="button" className="link-button" onClick={() => onSelectCve(row)}>{row.cve_id || row.advisory_id || row.id}</button></td>
                  <td>{row.title}</td>
                  <td>{row.vendor_name}</td>
                  <td>{row.product_family}</td>
                  <td>{row.affected_feature || "Pending"}</td>
                  <td><span className={`pill ${severityTone(row.severity)}`}>{humanize(row.severity)}</span></td>
                  <td>{row.cvss_score ?? "n/a"}</td>
                  <td>{row.epss_score ?? "n/a"}</td>
                  <td>{row.kev ? "Yes" : "No"}</td>
                  <td>{row.patch_available ? "Yes" : "Unknown"}</td>
                  <td>{row.known_exploited ? "Yes" : "No"}</td>
                  <td>{humanize(row.source_state || "source_bound")}</td>
                  <td>{humanize(row.review_state || "pending_review")}</td>
                  <td>{row.customer_match_count}</td>
                  <td>{humanize(row.urgency_posture || "unknown")}</td>
                  <td>{row.final_approval_issued ? "Issued" : "False"}</td>
                  <td>{row.last_refreshed ? new Date(row.last_refreshed).toLocaleDateString() : "Pending"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PaginationControls {...rowsPage} label="security action center rows" />
        {!rowsPage.items.length && <EmptyState title="No catalogue records" detail="Refresh source feeds or ingest vendor advisories to populate the global catalogue." />}
      </section>

      <div className="split-grid">
        <section className="data-band">
          <h3>CVE Detail</h3>
          {selectedRow ? (
            <div className="insight-list">
              <StatusLine label="CVE / Advisory" value={selectedRow.cve_id || selectedRow.advisory_id || selectedRow.id} tone="steel" />
              <StatusLine label="Vendor / Product" value={`${selectedRow.vendor_name} / ${selectedRow.product_family}`} tone="teal" />
              <StatusLine label="Affected feature" value={selectedRow.affected_feature || "Pending review"} tone="amber" />
              <StatusLine label="Severity" value={humanize(selectedRow.severity)} tone={severityTone(selectedRow.severity)} />
              <StatusLine label="Patch available" value={selectedRow.patch_available ? "Yes" : "Unknown"} tone={selectedRow.patch_available ? "trust" : "amber"} />
              <StatusLine label="Final approval" value={selectedRow.final_approval_issued ? "Issued" : "False"} tone="amber" />
            </div>
          ) : (
            <EmptyState title="No CVE selected" detail="Select a row from the grouped catalogue to review the governed detail." />
          )}
        </section>
        <section className="data-band">
          <h3>Evidence & Approval</h3>
          {selectedRow ? (
            <div className="insight-list">
              <StatusLine label="Source state" value={humanize(selectedRow.source_state || "source_bound")} tone="steel" />
              <StatusLine label="Review state" value={humanize(selectedRow.review_state || "pending_review")} tone="amber" />
              <StatusLine label="Customer matches" value={String(selectedRow.customer_match_count || 0)} tone={selectedRow.customer_match_count ? "trust" : "steel"} />
              <StatusLine label="Urgency posture" value={humanize(selectedRow.urgency_posture || "unknown")} tone="amber" />
              <StatusLine label="Human accountability" value="Required" tone="amber" />
              <StatusLine label="Evidence gate closure" value="Not autonomous" tone="steel" />
            </div>
          ) : (
            <EmptyState title="Evidence pending" detail="Evidence catalogue and approval state appear after a CVE/advisory is selected." />
          )}
        </section>
      </div>
    </>
  );
}

function CustomerEstate({
  state,
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
  canWrite
}: {
  state: CustomerEstateState;
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
          <table>
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
          <table>
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
  onAsk,
  onPatchCompare,
  canWrite
}: {
  question: string;
  setQuestion: (value: string) => void;
  answer: AskPatchForgeAnswer | null;
  selectedAssetId: string;
  selectedAdvisoryId: string;
  latestComparison: VendorLensPatchComparison | null;
  onAsk: () => void;
  onPatchCompare: () => void;
  canWrite: boolean;
}) {
  const response = answer?.response;
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
        <div className="report-actions">
          <button type="button" className="action-button" onClick={onAsk} disabled={!canWrite}>
            <MessageSquareText size={16} aria-hidden /> Ask PatchForge
          </button>
          <button type="button" className="action-button secondary-action" onClick={onPatchCompare} disabled={!canWrite || !selectedAssetId || !selectedAdvisoryId}>
            <Layers3 size={16} aria-hidden /> Run Patch Compare
          </button>
        </div>
        {latestComparison && <p className="boundary-copy">Patch Compare attached: current {humanize(latestComparison.current_version_affected || latestComparison.current_version_status)}, proposed {humanize(latestComparison.proposed_version_remediates || latestComparison.target_version_status)}. Final approval false.</p>}
      </section>

      {response ? (
        <section className="data-band advisor-response">
          <div className="section-title">
            <h3>Response</h3>
            <span className="pill amber">Final approval false</span>
          </div>
          <AdvisorBlock title="Short Answer" content={response.short_answer} />
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
        </section>
      ) : (
        <EmptyState title="No advisor response yet" detail="Ask a governed PatchForge question. The response will stay advisory-only and will not approve, deploy, or accept risk." />
      )}
    </>
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
  const sortedPacks = newestDecisionPacks(decisionPacks);
  const latestPack = sortedPacks[0];
  return (
    <>
      <section className="wide-band report-brief">
        <div>
          <p className="eyebrow">Reports & Packs</p>
          <h3>Customer, board, CAB, evidence appendix, signed ZIP, and verification in one place.</h3>
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
          <StatusLine label="Baseline" value={String(preExport.baseline || latestPack?.product_baseline || ACTIVE_BASELINE)} tone="steel" />
          <StatusLine label="Renderer commit" value={String(preExport.renderer_commit || latestPack?.report_renderer_commit || "not recorded")} tone="steel" />
          <StatusLine label="Image tag" value={String(preExport.image_tag || latestPack?.report_renderer_image_tag || "not recorded")} tone="steel" />
          <StatusLine label="Evidence state" value={humanize(String(preExport.evidence_state || "evidence_review_required"))} tone="amber" />
          <StatusLine label="VendorLens context" value={preExport.vendorlens_context_included ? "Included" : "Not attached"} tone={preExport.vendorlens_context_included ? "teal" : "amber"} />
          <StatusLine label="Customer context" value={preExport.customer_context_included ? "Included" : "Not attached"} tone={preExport.customer_context_included ? "teal" : "amber"} />
          <StatusLine label="Verification" value={humanize(String(preExport.verification_state || (latestPack?.verification?.verified ? "verified" : "pending_or_not_recorded")))} tone={latestPack?.verification?.verified ? "trust" : "amber"} />
        </div>
        <p className="boundary-copy">{String(preExport.report_current_stale_warning || "Reports are generated from the selected signed pack state and current evidence still requires review.")}</p>
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
        <table>
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
          <table>
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
        <table>
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
  "Customer Estate Match",
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
  onSaveAsset: (event: FormEvent<HTMLFormElement>) => void;
  onIngestAdvisory: (event: FormEvent<HTMLFormElement>) => void;
  onAssess: () => void;
  onAsk: () => void;
  onRefreshSource: (vendorId?: string) => void;
  onComparePatch: (assetId?: string, advisoryId?: string) => void;
  canWrite: boolean;
}) {
  const [activeTab, setActiveTab] = useState(vendorLensTabs[0]);
  const [selectedVendorId, setSelectedVendorId] = useState(vendorLens.vendors[0]?.vendor_id || "");
  const [selectedAssetId, setSelectedAssetId] = useState(vendorLens.assets[0]?.asset_id || "");
  const [selectedAdvisoryId, setSelectedAdvisoryId] = useState(vendorLens.advisories[0]?.advisory_id || "");
  const asset = vendorLens.assets.find((item) => item.asset_id === selectedAssetId) || vendorLens.assets[0];
  const advisory = vendorLens.advisories.find((item) => item.advisory_id === selectedAdvisoryId) || vendorLens.advisories[0];
  const assessment = vendorLens.latestAssessment || vendorLens.dashboard?.recent_assessments?.[0] || null;
  const chat = vendorLens.latestChat;
  const comparison = vendorLens.latestComparison;
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
    { number: "1", title: "Confirm customer exposure", detail: "Attach reviewed asset, service, internet exposure, and management-plane evidence.", onClick: () => setActiveTab("Customer Estate Match") },
    { number: "2", title: "Attach vendor advisory evidence", detail: "Use source-bound vendor/CVE evidence with review state visible.", onClick: () => setActiveTab("Advisories & CVEs") },
    { number: "3", title: "Attach configuration evidence", detail: "Record firmware, enabled/disabled feature state, and evidence references.", onClick: () => setActiveTab("Customer Estate Match") },
    { number: "4", title: "Run config applicability", detail: "Compare product, version, feature, and exposure to the advisory.", onClick: () => setActiveTab("Config Applicability") },
    { number: "5", title: "Ask PatchForge", detail: "Get advisory-only explanation of what the evidence means.", onClick: () => setActiveTab("Ask PatchForge") },
    { number: "6", title: "Generate signed pack", detail: "Move to Review & Approve and compile the source-bound signed pack." },
    { number: "7", title: "Export customer/board/CAB report", detail: "Use Reports & Packs after the signed pack is generated." }
  ];

  useEffect(() => {
    if (!selectedVendorId && vendorLens.vendors[0]?.vendor_id) {
      setSelectedVendorId(vendorLens.vendors[0].vendor_id);
    }
  }, [selectedVendorId, vendorLens.vendors]);

  useEffect(() => {
    if (!selectedAssetId && vendorLens.assets[0]?.asset_id) {
      setSelectedAssetId(vendorLens.assets[0].asset_id);
    }
  }, [selectedAssetId, vendorLens.assets]);

  useEffect(() => {
    if (!selectedAdvisoryId && vendorLens.advisories[0]?.advisory_id) {
      setSelectedAdvisoryId(vendorLens.advisories[0].advisory_id);
    }
  }, [selectedAdvisoryId, vendorLens.advisories]);

  return (
    <>
      <div className="section-title">
        <h3>VendorLens</h3>
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
          <button type="button" className="action-button secondary-action" onClick={onAssess} disabled={!canWrite || !asset || !advisory}>
            <Gauge size={16} aria-hidden /> Assess
          </button>
          <button type="button" className="action-button secondary-action" onClick={onAsk} disabled={!canWrite || !asset || !advisory}>
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

      {activeTab === "Customer Estate Match" && (
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
            <h3>Customer Estate Records</h3>
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
            <p className="boundary-copy">Export the CISO Patch Version Comparison Report from Reports & Packs after generating a signed pack with this comparison attached.</p>
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
            <button type="button" className="action-button" onClick={onAsk} disabled={!canWrite || !asset || !advisory}>
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
        <table>
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
                    <button type="button" className="icon-button" title="Download board DOCX" aria-label={`Download DOCX ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "docx")} disabled={!defaultReport}>
                      <FileText size={16} aria-hidden />
                    </button>
                    <button type="button" className="icon-button" title="Download board PDF" aria-label={`Download PDF ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "pdf")} disabled={!defaultReport}>
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
  const latestPack = verifiedPacks[0] || sortedPacks[0];
  const latestPackHasVendorLens = Boolean(latestPack?.artefacts && (
    latestPack.artefacts["config_applicability_assessment.json"]
    || latestPack.artefacts["customer_network_asset_snapshot.json"]
    || latestPack.artefacts["vendor_security_advisory_snapshot.json"]
    || latestPack.artefacts["sra_config_chat_session.json"]
  ));
  const latestBaseline = latestPack?.product_baseline || ACTIVE_BASELINE;
  const olderPackWarning = latestPack && latestBaseline !== ACTIVE_BASELINE
    ? `Older baseline detected: ${latestBaseline}. Current report renderer will stamp ${ACTIVE_BASELINE}.`
    : null;
  const reportPage = usePagination(reports, 6, "reports-catalog");
  return (
    <>
      <div className="section-title">
        <h3>Board Packs & Reports</h3>
        <span className="pill trust">DOCX / PDF only</span>
      </div>
      <section className="wide-band report-brief">
        <div>
          <p className="eyebrow">Customer demo operating pack</p>
          <h3>Professional outputs generated from live signed packs</h3>
          <p className="muted-copy">
            Reports are generated from the signed decision-pack record, preserving the source-pack/current-state distinction, evidence readiness, Bayesian advisory status, and no-autonomous-action boundary.
          </p>
        </div>
        <div className="report-pack-selector">
          <span className="pill steel">{verifiedPacks.length} verified packs</span>
          <span className="pill teal">{reports.length} report templates</span>
        </div>
      </section>

      <section className="data-band report-version-panel">
        <div className="section-title compact-title">
          <h3>Current Report Context</h3>
          <span className="pill teal">{ACTIVE_BASELINE}</span>
        </div>
        <div className="decision-option-grid compact-status-grid">
          <StatusLine label="Pack ID" value={latestPack?.pack_id || "No signed pack selected"} tone="trust" />
          <StatusLine label="Report version" value={REPORT_TEMPLATE_VERSION} tone="steel" />
          <StatusLine label="Context version" value={REPORT_CONTEXT_VERSION} tone="steel" />
          <StatusLine label="Final approval" value={latestPack?.final_approval_issued ? "Issued" : "False"} tone="amber" />
          <StatusLine label="VendorLens context" value={latestPackHasVendorLens ? "Included in pack" : "Not attached to selected pack"} tone={latestPackHasVendorLens ? "teal" : "amber"} />
          <StatusLine label="Verification" value={latestPack?.verification?.verified ? "Verified" : "Pending or not recorded"} tone="trust" />
        </div>
        {olderPackWarning && <p className="boundary-copy">{olderPackWarning}</p>}
        {!latestPackHasVendorLens && latestPack && <p className="boundary-copy">Selected pack can still export reports, but VendorLens sections will clearly state that network vendor applicability evidence was not attached.</p>}
      </section>

      <div className="report-grid">
        {reportPage.items.map((report) => (
          <section className="data-band report-card" key={report.report_type}>
            <div className="section-title compact-title">
              <h3>{report.title}</h3>
              <span className="pill steel">{report.audience}</span>
            </div>
            <StatusLine label="Source" value="Signed decision pack" tone="trust" />
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
      {!reports.length && <EmptyState title="No report catalogue" detail="Report templates load from the protected PatchForge API." />}
      {!decisionPacks.length && <EmptyState title="No signed pack available" detail="Generate a signed decision pack before producing board packs or customer reports." />}
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
  onSave
}: {
  tenantId: string;
  setTenantId: (tenantId: string) => void;
  adminEnvironment: string;
  setAdminEnvironment: (value: string) => void;
  adminTier: string;
  setAdminTier: (value: string) => void;
  adminHealth: AdminHealth | null;
  onSave: () => void;
}) {
  const healthPage = usePagination(adminHealth?.checks || [], 8, "admin-health");
  const sectionPage = usePagination(adminSections, 12, "admin-sections");

  return (
    <>
      <div className="section-title">
        <h3>Admin Control Surfaces</h3>
        <span className="pill trust">Production guarded</span>
      </div>

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

      <div className="admin-grid admin-section-grid">
        {sectionPage.items.map((section) => (
          <button className="admin-tile" type="button" key={section}>
            <KeyRound size={17} aria-hidden />
            <span>{section}</span>
          </button>
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
        <StatusLine label="Verifier" value={decisionPacks.some((pack) => pack.verification?.verified) ? "Verified" : "Ready"} tone="trust" />
        <StatusLine label="Trust" value={humanize(signing?.status || "ready")} tone="trust" />
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
    sourceFeedState: { feeds: [], recent_runs: [] },
    adminHealth: null,
    adminConfig: {}
  };
}

function parseList(value: string): string[] {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
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
  if (["planned", "pending", "placeholder"].includes(status.toLowerCase())) {
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

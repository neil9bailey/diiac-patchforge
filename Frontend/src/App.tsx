import { FormEvent, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  AdminUatCleanupPlan,
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
  FindingEvidenceQueue,
  FindingEvidenceRecord,
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

const CustomerEstate = lazy(() => import("./areas/GuidedAreas").then((module) => ({ default: module.CustomerEstate })));
const AskPatchForge = lazy(() => import("./areas/GuidedAreas").then((module) => ({ default: module.AskPatchForge })));
const VendorLens = lazy(() => import("./areas/GuidedAreas").then((module) => ({ default: module.VendorLens })));
const ReportsPacks = lazy(() => import("./areas/GovernanceAreas").then((module) => ({ default: module.ReportsPacks })));
const DecisionPacks = lazy(() => import("./areas/GovernanceAreas").then((module) => ({ default: module.DecisionPacks })));
const Admin = lazy(() => import("./areas/GovernanceAreas").then((module) => ({ default: module.Admin })));
const ActionCenter = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.ActionCenter })));
const FindingDetail = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.FindingDetail })));
const ReviewApprove = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.ReviewApprove })));
const CommandCenter = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.CommandCenter })));
const Guide = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.Guide })));
const VulnerabilityQueue = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.VulnerabilityQueue })));
const AssetExposure = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.AssetExposure })));
const DecisionWorkbench = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.DecisionWorkbench })));
const EmergencyPatch = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.EmergencyPatch })));
const RiskAcceptances = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.RiskAcceptances })));
const CompensatingControls = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.CompensatingControls })));
const SraResearch = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.SraResearch })));
const EvidenceCatalogue = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.EvidenceCatalogue })));
const SourceFeeds = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.SourceFeeds })));
const VendorThreatLandscape = lazy(() => import("./areas/LegacyAreas").then((module) => ({ default: module.VendorThreatLandscape })));
const UtilityRail = lazy(() => import("./areas/UtilityRail"));

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

type LiveLoadFailure = {
  key: string;
  label: string;
  message: string;
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
  { label: "Vulnerability Queue", icon: ListFilter },
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
  { label: "Data Retention", status: "Guarded", tone: "amber", detail: "Exact-ID UAT cleanup is bound to a tenant-scoped preview digest; broader purge remains separately previewed and typed-confirmed." },
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
  const navigationRef = useRef<HTMLElement>(null);
  const navigationToggleRef = useRef<HTMLButtonElement>(null);
  const [tenantId, setTenantId] = useState(initialTenantId || config.tenantHeader);
  const [state, setState] = useState<LiveState>(() => emptyLiveState(tenantId));
  const [refreshing, setRefreshing] = useState(false);
  const [loadFailures, setLoadFailures] = useState<LiveLoadFailure[]>([]);
  const [operationMessage, setOperationMessage] = useState<string | null>(null);
  const [operationError, setOperationError] = useState<string | null>(null);
  const [findingEvidenceQueue, setFindingEvidenceQueue] = useState<FindingEvidenceQueue | null>(null);
  const [findingEvidenceLoading, setFindingEvidenceLoading] = useState(false);
  const [findingEvidenceError, setFindingEvidenceError] = useState<string | null>(null);
  const [findingEvidenceConflict, setFindingEvidenceConflict] = useState<string | null>(null);
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
  const canSubmitEvidence = hasAnyRole(session.roles, ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.ServiceOwner", "PatchForge.Admin"]);
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
  const [uatCleanupIdentifier, setUatCleanupIdentifier] = useState("");
  const [uatCleanupConfirm, setUatCleanupConfirm] = useState("");
  const [latestUatCleanupPlan, setLatestUatCleanupPlan] = useState<AdminUatCleanupPlan | null>(null);
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
  const evidenceVulnerabilityId = selectedVulnerabilityId || selectedFinding?.vulnerability_id || "";

  const loadFindingEvidence = useCallback(async (vulnerabilityId: string, preserveConflict = false) => {
    if (!vulnerabilityId || session.status !== "authenticated") {
      return;
    }
    setFindingEvidenceLoading(true);
    setFindingEvidenceError(null);
    try {
      const queue = await liveApi.findingEvidence(tenantId, vulnerabilityId);
      setFindingEvidenceQueue(queue);
      if (!preserveConflict) {
        setFindingEvidenceConflict(null);
      }
    } catch (error) {
      setFindingEvidenceError(error instanceof Error ? error.message : "Finding evidence could not be loaded.");
    } finally {
      setFindingEvidenceLoading(false);
    }
  }, [liveApi, session.status, tenantId]);

  useEffect(() => {
    const isMobileNavigation = typeof window.matchMedia === "function" && window.matchMedia("(max-width: 820px)").matches;
    const navigation = navigationRef.current;
    if (navigationCollapsed || !isMobileNavigation || !navigation) {
      return;
    }

    const navigationElement = navigation;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const focusableSelector = 'button:not([disabled]):not([tabindex="-1"]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    navigationElement.querySelector<HTMLElement>(".nav-mobile-close")?.focus();

    function handleNavigationKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        setNavigationCollapsed(true);
        return;
      }
      if (event.key !== "Tab") {
        return;
      }
      const focusable = Array.from(navigationElement.querySelectorAll<HTMLElement>(focusableSelector));
      if (!focusable.length) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleNavigationKeyDown);
    return () => {
      document.removeEventListener("keydown", handleNavigationKeyDown);
      if (previousFocus?.isConnected) {
        previousFocus.focus();
      } else {
        navigationToggleRef.current?.focus();
      }
    };
  }, [navigationCollapsed]);

  const loadLiveState = useCallback(async (retryKeys?: string[]) => {
    if (session.status !== "authenticated") {
      return;
    }
    setRefreshing(true);
    setOperationError(null);
    try {
      const requests: Array<{ key: string; label: string; run: () => Promise<unknown> }> = [
        { key: "metrics", label: "Dashboard metrics", run: () => liveApi.metrics(tenantId) },
        { key: "securityActionCenter", label: "Patch & CVE catalogue", run: () => liveApi.securityActionCenter(tenantId) },
        { key: "customerEstate", label: "Customer estate", run: () => liveApi.customerEstate(tenantId) },
        { key: "reportsPacks", label: "Reports overview", run: () => liveApi.reportsPacks(tenantId) },
        { key: "vulnerabilities", label: "Vulnerability records", run: () => liveApi.listVulnerabilities(tenantId) },
        { key: "findings", label: "Action centre", run: () => liveApi.actionCenter(tenantId) },
        { key: "assets", label: "Asset records", run: () => liveApi.listAssets(tenantId) },
        { key: "services", label: "Service records", run: () => liveApi.listServices(tenantId) },
        { key: "decisionPacks", label: "Decision packs", run: () => liveApi.listDecisionPacks(tenantId) },
        { key: "reports", label: "Report catalogue", run: () => liveApi.reportCatalog(tenantId) },
        { key: "threatSummary", label: "Threat landscape", run: () => liveApi.threatLandscapeSummary(tenantId) },
        { key: "vendors", label: "Vendor catalogue", run: () => liveApi.listVendors(tenantId) },
        { key: "sourceFeedState", label: "Source feeds", run: () => liveApi.sourceFeeds(tenantId) },
        { key: "vendorLensDashboard", label: "VendorLens dashboard", run: () => liveApi.vendorLensDashboard(tenantId) },
        { key: "networkVendors", label: "Network vendors", run: () => liveApi.listNetworkVendors(tenantId) },
        { key: "customerNetworkAssets", label: "Customer network assets", run: () => liveApi.listCustomerNetworkAssets(tenantId) },
        { key: "vendorSecurityAdvisories", label: "Vendor advisories", run: () => liveApi.listVendorSecurityAdvisories(tenantId) },
        { key: "discovery", label: "Collector intake", run: () => liveApi.assetDiscoveryOverview(tenantId) },
        { key: "openAiAgentStatus", label: "Agent status", run: () => liveApi.openAiAgentStatus(tenantId) },
        { key: "adminHealth", label: "Admin health", run: () => canReadAdmin ? liveApi.adminHealth(tenantId) : Promise.resolve(null) },
        { key: "adminConfig", label: "Admin configuration", run: () => canReadAdmin ? liveApi.adminConfig(tenantId) : Promise.resolve({} as AdminConfig) }
      ];
      const selectedRequests = retryKeys?.length
        ? requests.filter((request) => retryKeys.includes(request.key))
        : requests;
      if (!selectedRequests.length) {
        return;
      }
      const results = await Promise.allSettled(selectedRequests.map((request) => request.run()));
      const values = new Map<string, unknown>();
      const failures: LiveLoadFailure[] = [];
      results.forEach((result, index) => {
        const request = selectedRequests[index];
        if (result.status === "fulfilled") {
          values.set(request.key, result.value);
        } else {
          failures.push({
            key: request.key,
            label: request.label,
            message: result.reason instanceof Error ? result.reason.message : "Request failed"
          });
        }
      });
      const value = <T,>(key: string, fallback: T): T => values.has(key) ? values.get(key) as T : fallback;
      setState((current) => ({
        metrics: value("metrics", current.metrics),
        securityActionCenter: value("securityActionCenter", current.securityActionCenter),
        customerEstate: value("customerEstate", current.customerEstate),
        reportsPacks: value("reportsPacks", current.reportsPacks),
        findings: value("findings", current.findings),
        vulnerabilities: value("vulnerabilities", current.vulnerabilities),
        assets: value("assets", current.assets),
        services: value("services", current.services),
        decisionPacks: value("decisionPacks", current.decisionPacks),
        reports: value("reports", current.reports),
        threatSummary: value("threatSummary", current.threatSummary),
        vendors: value("vendors", current.vendors),
        sourceFeedState: value("sourceFeedState", current.sourceFeedState),
        vendorLens: {
          dashboard: value("vendorLensDashboard", current.vendorLens.dashboard),
          vendors: value("networkVendors", current.vendorLens.vendors),
          assets: value("customerNetworkAssets", current.vendorLens.assets),
          advisories: value("vendorSecurityAdvisories", current.vendorLens.advisories),
          latestAssessment: current.vendorLens.latestAssessment,
          latestChat: current.vendorLens.latestChat,
          latestComparison: current.vendorLens.latestComparison
        },
        latestCustomerMatch: current.latestCustomerMatch,
        latestAskPatchForge: current.latestAskPatchForge,
        openAiAgentStatus: value("openAiAgentStatus", current.openAiAgentStatus),
        latestAgentGuidance: (() => {
          const agentStatus = value("openAiAgentStatus", current.openAiAgentStatus);
          return agentStatus?.enabled && agentStatus.configured ? current.latestAgentGuidance : null;
        })(),
        bayesian: null,
        adminHealth: value("adminHealth", current.adminHealth),
        adminConfig: value("adminConfig", current.adminConfig),
        discovery: value("discovery", current.discovery)
      }));
      setLoadFailures((current) => retryKeys?.length
        ? [
            ...current.filter((failure) => !retryKeys.includes(failure.key)),
            ...failures
          ]
        : failures);
      const vulnerabilities = values.get("vulnerabilities") as VulnerabilityRecord[] | undefined;
      const customerEstate = values.get("customerEstate") as CustomerEstateState | undefined;
      const customerNetworkAssets = values.get("customerNetworkAssets") as CustomerNetworkAsset[] | undefined;
      setSelectedVulnerabilityId((current) => current || vulnerabilities?.[0]?.vulnerability_id || "");
      setSelectedCustomerAssetId((current) => current || customerEstate?.assets[0]?.asset_id || customerNetworkAssets?.[0]?.asset_id || "");
      const adminConfig = values.get("adminConfig") as AdminConfig | undefined;
      if (adminConfig) {
        const general = adminConfig.general as { environment?: string; governance_tier?: string } | undefined;
        setAdminEnvironment(general?.environment || config.environmentLabel);
        setAdminTier(general?.governance_tier || "Enterprise Strict");
      }
      if (failures.length === selectedRequests.length) {
        setOperationError("Every PatchForge data source failed. Last-known workspace data has been retained.");
      }
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "PatchForge API request failed.");
    } finally {
      setRefreshing(false);
    }
  }, [canReadAdmin, liveApi, session.status, tenantId]);

  useEffect(() => {
    void loadLiveState();
  }, [loadLiveState]);

  useEffect(() => {
    if (activePage !== "Review & Approve" || !evidenceVulnerabilityId) {
      return;
    }
    if (findingEvidenceQueue?.vulnerability_id !== evidenceVulnerabilityId) {
      setFindingEvidenceQueue(null);
    }
    void loadFindingEvidence(evidenceVulnerabilityId);
  }, [activePage, evidenceVulnerabilityId, loadFindingEvidence]);

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

  function recordFindingEvidenceFailure(error: unknown, fallback: string) {
    const message = error instanceof Error ? error.message : fallback;
    const apiError = error as { status?: number; code?: string };
    setFindingEvidenceError(message);
    if (apiError?.status === 409 || /conflict|revision|changed|expired/i.test(message)) {
      setFindingEvidenceConflict(`${message} Refresh the queue before retrying against the current hashes.`);
    }
  }

  async function handleSubmitFindingEvidence(payload: Record<string, unknown>) {
    if (!evidenceVulnerabilityId) {
      setFindingEvidenceError("Select a persisted finding before submitting evidence.");
      return;
    }
    setFindingEvidenceError(null);
    setFindingEvidenceConflict(null);
    try {
      const evidence = await liveApi.submitFindingEvidence(tenantId, evidenceVulnerabilityId, payload);
      setOperationMessage(`Evidence ${evidence.evidence_id} submitted for review.`);
      await loadFindingEvidence(evidenceVulnerabilityId);
    } catch (error) {
      recordFindingEvidenceFailure(error, "Finding evidence submission failed.");
    }
  }

  async function handleReviewFindingEvidence(record: FindingEvidenceRecord, decision: "accept" | "reject", rationale: string) {
    setFindingEvidenceError(null);
    setFindingEvidenceConflict(null);
    try {
      await liveApi.reviewFindingEvidence(tenantId, record.vulnerability_id, record.evidence_id, {
        decision,
        rationale,
        expected_content_hash: record.content_hash,
        expected_event_hash: record.latest_event_hash || null
      });
      setOperationMessage(`Evidence ${record.evidence_id} ${decision === "accept" ? "accepted" : "rejected"}; final approval remains false.`);
      await loadFindingEvidence(record.vulnerability_id);
    } catch (error) {
      recordFindingEvidenceFailure(error, "Finding evidence review failed.");
      await loadFindingEvidence(record.vulnerability_id, true);
    }
  }

  async function handleReopenFindingEvidence(record: FindingEvidenceRecord, rationale: string) {
    setFindingEvidenceError(null);
    setFindingEvidenceConflict(null);
    try {
      await liveApi.reopenFindingEvidence(tenantId, record.vulnerability_id, record.evidence_id, {
        rationale,
        expected_content_hash: record.content_hash,
        expected_event_hash: record.latest_event_hash || null
      });
      setOperationMessage(`Evidence ${record.evidence_id} reopened for a new review event.`);
      await loadFindingEvidence(record.vulnerability_id);
    } catch (error) {
      recordFindingEvidenceFailure(error, "Finding evidence reopen failed.");
      await loadFindingEvidence(record.vulnerability_id, true);
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
      setOperationMessage(`Decision pack JSON prepared for ${packId}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Decision pack JSON export failed.");
    }
  }

  async function handleDownloadPackZip(packId: string) {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const blob = await liveApi.downloadDecisionPackZip(tenantId, packId);
      downloadBlob(`${packId}.zip`, blob);
      setOperationMessage(`Signed decision-pack ZIP prepared for ${packId}.`);
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Signed decision-pack ZIP export failed.");
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

  async function handlePreviewUatCleanup() {
    setOperationMessage(null);
    setOperationError(null);
    try {
      const cleanup = await liveApi.adminUatCleanup(tenantId, {
        identifier: uatCleanupIdentifier.trim(),
        dry_run: true
      });
      setLatestUatCleanupPlan(cleanup);
      setUatCleanupConfirm("");
      setOperationMessage(`UAT cleanup preview found ${cleanup.total_records} exact-linked record(s) across ${cleanup.collections.length} collection(s).`);
    } catch (error) {
      setLatestUatCleanupPlan(null);
      setOperationError(error instanceof Error ? error.message : "UAT cleanup preview failed.");
    }
  }

  async function handleExecuteUatCleanup() {
    setOperationMessage(null);
    setOperationError(null);
    const identifier = uatCleanupIdentifier.trim();
    if (!latestUatCleanupPlan || latestUatCleanupPlan.identifier !== identifier) {
      setOperationError("Preview this exact UAT identifier again before cleanup.");
      return;
    }
    try {
      const cleanup = await liveApi.adminUatCleanup(tenantId, {
        identifier,
        dry_run: false,
        confirm: uatCleanupConfirm,
        preview_token: latestUatCleanupPlan.preview_token
      });
      setLatestUatCleanupPlan(cleanup);
      setUatCleanupConfirm("");
      setOperationMessage(`Targeted UAT cleanup removed ${cleanup.total_removed || 0} record(s); audit event ${cleanup.audit_id || "recorded"}.`);
      await loadLiveState();
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : "Targeted UAT cleanup failed.");
    }
  }

  if (session.status !== "authenticated") {
    return <SignedOutShell session={session} />;
  }

  return (
    <main className={`app-shell${navigationCollapsed ? " nav-collapsed" : ""}`}>
      <aside ref={navigationRef} id="patchforge-primary-navigation" className="side-nav" aria-label="PatchForge navigation" aria-hidden={navigationCollapsed}>
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
      {!navigationCollapsed && (
        <button type="button" className="nav-scrim" aria-label="Close navigation overlay" onClick={() => setNavigationCollapsed(true)} />
      )}

      <section className="workspace">
        <header className="top-rail">
          <button
            ref={navigationToggleRef}
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
            <LiveLoadFailures failures={loadFailures} refreshing={refreshing} onRetry={(keys) => void loadLiveState(keys)} />
            <Suspense fallback={<AreaLoading label={activePage} />}>
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
                canGeneratePacks={canGeneratePacks}
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
                canGeneratePacks={canGeneratePacks}
                evidenceQueue={findingEvidenceQueue?.vulnerability_id === evidenceVulnerabilityId ? findingEvidenceQueue : null}
                evidenceLoading={findingEvidenceLoading}
                evidenceError={findingEvidenceError}
                evidenceConflict={findingEvidenceConflict}
                roles={session.roles}
                canSubmitEvidence={canSubmitEvidence}
                onRefreshEvidence={() => evidenceVulnerabilityId && void loadFindingEvidence(evidenceVulnerabilityId)}
                onSubmitEvidence={handleSubmitFindingEvidence}
                onReviewEvidence={handleReviewFindingEvidence}
                onReopenEvidence={handleReopenFindingEvidence}
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
                onDownloadPackZip={handleDownloadPackZip}
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
                canGeneratePacks={canGeneratePacks}
              />
            )}
            {activePage === "Emergency Patch" && <EmergencyPatch vulnerabilities={state.vulnerabilities} />}
            {activePage === "Risk Acceptances" && <RiskAcceptances decisionPacks={state.decisionPacks} />}
            {activePage === "Compensating Controls" && <CompensatingControls />}
            {activePage === "SRA Research" && <SraResearch onRun={handleSraResearch} result={sraResult} canWrite={canWrite} />}
            {activePage === "Evidence Catalogue" && <EvidenceCatalogue vulnerabilities={state.vulnerabilities} />}
            {activePage === "Decision Packs" && <DecisionPacks decisionPacks={state.decisionPacks} reports={state.reports} onExportPack={handleExportPack} onDownloadPackZip={handleDownloadPackZip} onDownloadReport={handleDownloadReport} />}
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
                setTenantId={(value) => {
                  setTenantId(value);
                  setLatestPurgePlan(null);
                  setPurgeConfirm("");
                  setLatestUatCleanupPlan(null);
                  setUatCleanupConfirm("");
                }}
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
                uatCleanupIdentifier={uatCleanupIdentifier}
                setUatCleanupIdentifier={(value) => {
                  setUatCleanupIdentifier(value);
                  setUatCleanupConfirm("");
                  setLatestUatCleanupPlan(null);
                }}
                uatCleanupConfirm={uatCleanupConfirm}
                setUatCleanupConfirm={setUatCleanupConfirm}
                latestUatCleanupPlan={latestUatCleanupPlan}
                onPreviewUatCleanup={handlePreviewUatCleanup}
                onExecuteUatCleanup={handleExecuteUatCleanup}
              /> : <PageBand icon={LockKeyhole} title="Admin" lines={["PatchForge.Admin role required", "Admin controls are read-only for non-admin users", "API app roles are enforced server-side"]} />
            )}
            </Suspense>
          </section>

          {activePage !== "Patch & CVE Catalogue" && (
            <aside className="utility-rail" aria-label="PatchForge utility rail">
              <Suspense fallback={<div className="rail-section utility-rail-loading" role="status" aria-live="polite">Loading operational context…</div>}>
                <UtilityRail session={session} metrics={state.metrics} decisionPacks={state.decisionPacks} sourceFeedState={state.sourceFeedState} adminHealth={state.adminHealth} />
              </Suspense>
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
      {message && <div className="notice success" role="status" aria-live="polite"><CheckCircle2 size={16} aria-hidden /> {message}</div>}
      {error && <div className="notice error" role="alert" aria-live="assertive"><TriangleAlert size={16} aria-hidden /> {error}</div>}
    </>
  );
}

function LiveLoadFailures({ failures, refreshing, onRetry }: { failures: LiveLoadFailure[]; refreshing: boolean; onRetry: (keys?: string[]) => void }) {
  if (!failures.length) {
    return null;
  }
  return (
    <section className="panel-load-warning" role="status" aria-live="polite" aria-label="Partially unavailable data sources">
      <div>
        <TriangleAlert size={17} aria-hidden />
        <span><strong>{failures.length} data source{failures.length === 1 ? "" : "s"} unavailable</strong><small>Last-known-good panel data is retained.</small></span>
      </div>
      <ul>
        {failures.map((failure) => (
          <li key={failure.key}>
            <span><strong>{failure.label}:</strong> {failure.message}</span>
            <button type="button" className="inline-retry" onClick={() => onRetry([failure.key])} disabled={refreshing} aria-label={`Retry ${failure.label}`}>
              Retry
            </button>
          </li>
        ))}
      </ul>
      <button type="button" className="action-button secondary-action" onClick={() => onRetry(failures.map((failure) => failure.key))} disabled={refreshing}>
        <RefreshCw size={16} aria-hidden /> {refreshing ? "Retrying…" : "Retry unavailable sources"}
      </button>
    </section>
  );
}

function AreaLoading({ label }: { label: string }) {
  return (
    <div className="area-loading" role="status" aria-live="polite" aria-label={`Loading ${label}`}>
      <span className="status-dot source-current" aria-hidden />
      <span>Loading {label}…</span>
    </div>
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
                      <td data-label="CVE"><button type="button" className="link-button" onClick={() => onSelectCve(row)}>{catalogueRecordId(row)}</button></td>
                      <td data-label="Vendor / product"><span className="cell-stack"><strong>{row.vendor_name || "Unknown vendor"}</strong><small>{row.product_family || "Product pending"}</small></span></td>
                      <td data-label="Priority"><span className={`queue-status ${priority.tone}`}>{priority.label}</span></td>
                      <td data-label="Exploit signal"><span className="cell-stack"><strong>{catalogueExploitSignal(row)}</strong><small>{catalogueEpssLabel(row.epss_score)}</small></span></td>
                      <td data-label="Customer exposure"><span className="cell-stack"><strong>{catalogueCustomerScope(row)}</strong><small>{row.customer_match_count ? "Review matched scope" : "Estate mapping required"}</small></span></td>
                      <td data-label="Remediation"><span className="cell-stack"><strong>{row.patch_available ? "Patch recorded" : "No fix confirmed"}</strong><small>{(row.fixed_versions || []).join(", ") || "Version evidence pending"}</small></span></td>
                      <td data-label="Evidence"><span className={`evidence-state ${catalogueEvidenceVerified(row) ? "verified" : "pending"}`}>{catalogueEvidenceVerified(row) ? <CheckCircle2 size={15} aria-hidden /> : <Clock3 size={15} aria-hidden />}{catalogueEvidenceLabel(row)}</span></td>
                      <td data-label="Next action"><span className="cell-stack"><strong>{catalogueNextAction(row)}</strong><small>{row.final_approval_issued ? "Approval issued" : "Approval not issued"}</small></span></td>
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

function MetricCard({ icon: Icon, label, value, tone }: { icon: typeof Gauge; label: string; value: number | string; tone: string }) {
  return (
    <article className={`metric-card ${tone}`}>
      <Icon size={20} aria-hidden />
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
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

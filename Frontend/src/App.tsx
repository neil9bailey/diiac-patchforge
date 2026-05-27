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
  DecisionPackRecord,
  FindingIntelligence,
  PatchForgeApi,
  PatchForgeMetrics,
  ReportCatalogItem,
  ServiceRecord,
  SourceFeedState,
  ThreatLandscapeSummary,
  VendorProfile,
  VulnerabilityRecord,
  createPatchForgeApi,
  getPatchForgeConfig
} from "./api";
import { PatchForgeAuthSession, usePatchForgeAuth } from "./auth";

type PageKey =
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
  findings: FindingIntelligence[];
  vulnerabilities: VulnerabilityRecord[];
  assets: AssetRecord[];
  services: ServiceRecord[];
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  bayesian: BayesianAssessment | null;
  threatSummary: ThreatLandscapeSummary | null;
  vendors: VendorProfile[];
  sourceFeedState: SourceFeedState;
  adminHealth: AdminHealth | null;
  adminConfig: AdminConfig;
};

const PRODUCT_MARK = "DIIaC\u2122";
const config = getPatchForgeConfig();

const navItems: NavItem[] = [
  { label: "Action Center", icon: Gauge },
  { label: "Finding Detail", icon: ShieldAlert },
  { label: "Review & Approve", icon: ClipboardCheck },
  { label: "Reports & Packs", icon: FileText },
  { label: "Guide", icon: BookOpenCheck },
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

export default function App({ auth, api, initialTenantId }: AppProps) {
  const contextAuth = usePatchForgeAuth();
  const session = auth || contextAuth;
  const liveApi = useMemo(() => api || createPatchForgeApi(session.getAccessToken), [api, session.getAccessToken]);
  const [activePage, setActivePage] = useState<PageKey>("Action Center");
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
  const canWrite = hasAnyRole(session.roles, ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"]);
  const isAdmin = hasAnyRole(session.roles, ["PatchForge.Admin"]);
  const canReadAdmin = hasAnyRole(session.roles, ["PatchForge.Admin", "PatchForge.Auditor"]);
  const selectedFinding = useMemo(
    () => state.findings.find((item) => item.vulnerability_id === selectedVulnerabilityId) || state.findings[0] || null,
    [selectedVulnerabilityId, state.findings]
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
      const [metrics, vulnerabilities, findings, assets, services, decisionPacks, reports, threatSummary, vendors, sourceFeedState, adminHealth, adminConfig] = await Promise.all([
        liveApi.metrics(tenantId),
        liveApi.listVulnerabilities(tenantId),
        liveApi.actionCenter(tenantId),
        liveApi.listAssets(tenantId),
        liveApi.listServices(tenantId),
        liveApi.listDecisionPacks(tenantId),
        liveApi.reportCatalog(tenantId),
        liveApi.threatLandscapeSummary(tenantId),
        liveApi.listVendors(tenantId),
        liveApi.sourceFeeds(tenantId),
        canReadAdmin ? liveApi.adminHealth(tenantId) : Promise.resolve(null),
        canReadAdmin ? liveApi.adminConfig(tenantId) : Promise.resolve({} as AdminConfig)
      ]);
      setState({ metrics, findings, vulnerabilities, assets, services, decisionPacks, reports, threatSummary, vendors, sourceFeedState, bayesian: null, adminHealth, adminConfig });
      setSelectedVulnerabilityId((current) => current || vulnerabilities[0]?.vulnerability_id || "");
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
      const pack = await liveApi.generateDecisionPack(tenantId, {
        vulnerability_id: selectedVulnerabilityId,
        requested_posture: selectedPosture,
        bayesian_snapshot: state.bayesian
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
                onExportPack={handleExportPack}
                onDownloadReport={handleDownloadReport}
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
  const topFindings = findings.slice(0, 6);

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
          <p className="eyebrow">Autonomous analysis, human-approved decisions</p>
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

      <div className="finding-grid">
        {topFindings.map((finding) => (
          <article className="finding-card" key={finding.vulnerability_id}>
            <div className="finding-card-head">
              <span className={`pill ${severityTone(finding.severity)}`}>{humanize(finding.severity || "unknown")}</span>
              <span className="pill teal">{humanize(finding.recommendation?.posture || "defer_pending_evidence")}</span>
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

      {!topFindings.length && (
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
          <strong>{humanize(finding.recommendation.posture)}</strong>
          <small>{humanize(finding.recommendation.confidence)} confidence</small>
        </div>
      </section>

      <div className="split-grid">
        <section className="data-band narrative-panel">
          <h3>Why This Matters</h3>
          <p>{finding.summary.why_now}</p>
          <p>{finding.summary.operational_risk}</p>
        </section>
        <section className="data-band narrative-panel">
          <h3>Exploitability Intelligence</h3>
          <p>{finding.exploitability.safe_description}</p>
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
              <span className={option.recommended ? "pill trust" : "pill steel"}>{option.recommended ? "Recommended" : "Available"}</span>
              <h4>{humanize(option.posture)}</h4>
              <p>{option.when_to_choose}</p>
              <small>Evidence: {option.evidence_needed.join(", ") || "Reviewed evidence required"}</small>
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
          <h3>{finding ? `${finding.vulnerability_id}: ${humanize(finding.recommendation.posture)}` : "Select a finding to review"}</h3>
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

      <div className="split-grid">
        <section className="data-band">
          <h3>Autonomous Analysis Completed</h3>
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
          <StatusLine label="Autonomous approval" value="Blocked" tone="amber" />
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
  onExportPack,
  onDownloadReport
}: {
  findings: FindingIntelligence[];
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  onExportPack: (packId: string) => void;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
}) {
  return (
    <>
      <section className="wide-band report-brief">
        <div>
          <p className="eyebrow">Professional decision outputs</p>
          <h3>Board, CAB, customer, risk, and OT packs generated from signed evidence.</h3>
          <p className="muted-copy">Reports use the intelligence narrative, evidence gaps, decision options, signed-pack metadata, and the no-exploit/no-deployment boundary.</p>
        </div>
        <div className="report-pack-selector">
          <span className="pill trust">{decisionPacks.filter((pack) => pack.verification?.verified).length} verified packs</span>
          <span className="pill teal">{findings.length} analysed findings</span>
        </div>
      </section>
      <DecisionPacks decisionPacks={decisionPacks} reports={reports} onExportPack={onExportPack} onDownloadReport={onDownloadReport} />
      <Reports decisionPacks={decisionPacks} reports={reports} onDownloadReport={onDownloadReport} />
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
            {vulnerabilities.map((item) => (
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
  return (
    <div className="split-grid">
      <section className="data-band">
        <h3>Assets</h3>
        {assets.map((asset) => (
          <StatusLine key={asset.asset_id} label={asset.asset_name || asset.asset_id} value={humanize(asset.exposure || "unknown")} tone="steel" />
        ))}
        {!assets.length && <EmptyState title="No asset records" detail="Asset scope appears after real inventory records are ingested." />}
      </section>
      <section className="data-band">
        <h3>Services</h3>
        {services.map((service) => (
          <StatusLine key={service.service_id} label={service.service_name || service.service_id} value={service.customer_facing ? "Customer-facing" : humanize(service.service_tier || "unknown")} tone={service.customer_facing ? "amber" : "steel"} />
        ))}
        {!services.length && <EmptyState title="No service records" detail="Service exposure appears after real service catalogue records are ingested." />}
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
  return (
    <>
      <div className="section-title">
        <h3>Public Source Intelligence</h3>
        <span className="pill amber">Live feeds, source-bound</span>
      </div>

      <div className="split-grid">
        {sourceFeedState.feeds.map((feed) => (
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
              {sourceFeedState.recent_runs.map((run) => (
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
      </section>

      {!canWrite && <EmptyState title="Read-only role" detail="Source refresh actions require a PatchForge triage, security lead, or admin role." />}
    </>
  );
}

function VendorThreatLandscape({ vendors, threatSummary }: { vendors: VendorProfile[]; threatSummary: ThreatLandscapeSummary | null }) {
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
            {vendors.map((vendor) => (
              <tr key={vendor.vendor_id}>
                <td>{vendor.vendor_name}</td>
                <td>{humanize(vendor.category)}</td>
                <td>{humanize(vendor.review_state || "pending_review")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
  return (
    <>
      <div className="section-title">
        <h3>Decision Packs</h3>
        <span className="pill trust">{decisionPacks.filter((pack) => pack.verification?.verified).length} verified</span>
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
            {decisionPacks.map((pack) => (
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
  const verifiedPacks = decisionPacks.filter((pack) => pack.verification?.verified);
  const latestPack = verifiedPacks[0] || decisionPacks[0];
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

      <div className="report-grid">
        {reports.map((report) => (
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
            {(adminHealth?.checks || []).map((check) => (
              <StatusLine key={check.name} label={check.name} value={humanize(check.status)} tone={healthTone(check.status)} />
            ))}
            {!adminHealth?.checks?.length && <p className="muted-copy">Health checks load from the protected bridge API.</p>}
          </div>
        </section>
      </div>

      <div className="admin-grid admin-section-grid">
        {adminSections.map((section) => (
          <button className="admin-tile" type="button" key={section}>
            <KeyRound size={17} aria-hidden />
            <span>{section}</span>
          </button>
        ))}
      </div>
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

function StatusLine({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="status-line">
      <span>{label}</span>
      <strong className={`pill ${tone}`}>{value}</strong>
    </div>
  );
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
    findings: [],
    vulnerabilities: [],
    assets: [],
    services: [],
    decisionPacks: [],
    reports: [],
    bayesian: null,
    threatSummary: null,
    vendors: [],
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

function hasAnyRole(actual: string[], required: string[]) {
  return actual.some((role) => required.includes(role));
}

function healthTone(status = "") {
  if (["ready", "verified", "advisory"].includes(status.toLowerCase())) {
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

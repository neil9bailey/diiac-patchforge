import { useState } from "react";
import type { FormEvent } from "react";
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
  MessageSquareText,
  Network,
  PanelLeft,
  Radar,
  RefreshCw,
  Search,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
  Upload,
  UserRound,
  Wrench,
  X
} from "lucide-react";
import type {
  AssetRecord,
  BayesianAssessment,
  DecisionPackRecord,
  FindingEvidenceQueue,
  FindingEvidenceRecord,
  FindingIntelligence,
  PatchForgeMetrics,
  ReportCatalogItem,
  ServiceRecord,
  SourceFeedState,
  ThreatLandscapeSummary,
  VendorProfile,
  VulnerabilityRecord
} from "../api";
import {
  EmptyState,
  PaginationControls,
  StatusLine,
  humanize,
  usePagination
} from "./AreaPrimitives";

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

function signalLabel(item: VulnerabilityRecord) {
  const signals = [];
  if (item.known_exploited) signals.push("Known exploited");
  if (item.internet_exposed) signals.push("Internet exposed");
  if (item.ot_relevant) signals.push("OT");
  return signals.join(", ") || "No reviewed signal";
}

function shortValue(value = "") {
  const text = String(value || "Not recorded");
  return text.length > 42 ? `${text.slice(0, 39)}...` : text;
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

function MetricCard({ icon: Icon, label, value, tone }: { icon: typeof Gauge; label: string; value: number | string; tone: string }) {
  return (
    <article className={`metric-card ${tone}`}>
      <Icon size={20} aria-hidden />
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

export function ActionCenter({
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

export function FindingDetail({
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

export function ReviewApprove({
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
  canWrite,
  evidenceQueue,
  evidenceLoading,
  evidenceError,
  evidenceConflict,
  roles,
  canSubmitEvidence,
  onRefreshEvidence,
  onSubmitEvidence,
  onReviewEvidence,
  onReopenEvidence
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
  evidenceQueue: FindingEvidenceQueue | null;
  evidenceLoading: boolean;
  evidenceError: string | null;
  evidenceConflict: string | null;
  roles: string[];
  canSubmitEvidence: boolean;
  onRefreshEvidence: () => void;
  onSubmitEvidence: (payload: Record<string, unknown>) => void;
  onReviewEvidence: (record: FindingEvidenceRecord, decision: "accept" | "reject", rationale: string) => void;
  onReopenEvidence: (record: FindingEvidenceRecord, rationale: string) => void;
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

      <FindingEvidencePanel
        finding={finding}
        queue={evidenceQueue}
        loading={evidenceLoading}
        error={evidenceError}
        conflict={evidenceConflict}
        roles={roles}
        canSubmit={canSubmitEvidence}
        onRefresh={onRefreshEvidence}
        onSubmit={onSubmitEvidence}
        onReview={onReviewEvidence}
        onReopen={onReopenEvidence}
      />

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

function FindingEvidencePanel({
  finding,
  queue,
  loading,
  error,
  conflict,
  roles,
  canSubmit,
  onRefresh,
  onSubmit,
  onReview,
  onReopen
}: {
  finding: FindingIntelligence | null;
  queue: FindingEvidenceQueue | null;
  loading: boolean;
  error: string | null;
  conflict: string | null;
  roles: string[];
  canSubmit: boolean;
  onRefresh: () => void;
  onSubmit: (payload: Record<string, unknown>) => void;
  onReview: (record: FindingEvidenceRecord, decision: "accept" | "reject", rationale: string) => void;
  onReopen: (record: FindingEvidenceRecord, rationale: string) => void;
}) {
  const supportedClasses = queue?.supported_evidence_classes || [];
  const [evidenceClass, setEvidenceClass] = useState("affected_asset_scope");
  const [summary, setSummary] = useState("");
  const [details, setDetails] = useState("");
  const [sourceRefs, setSourceRefs] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [rationales, setRationales] = useState<Record<string, string>>({});
  const selectedClass = supportedClasses.includes(evidenceClass) ? evidenceClass : supportedClasses[0] || evidenceClass;

  function submitEvidence() {
    const expiry = expiresAt ? new Date(expiresAt) : null;
    onSubmit({
      evidence_class: selectedClass,
      summary: summary.trim(),
      evidence: { details: details.trim() },
      source_refs: sourceRefs.split(",").map((item) => item.trim()).filter(Boolean),
      ...(expiry && !Number.isNaN(expiry.getTime()) ? { expires_at: expiry.toISOString() } : {})
    });
  }

  return (
    <section className="wide-band finding-evidence-panel" aria-label="Finding evidence queue">
      <div className="section-title">
        <div>
          <p className="eyebrow">Finding-scoped evidence</p>
          <h3>Submit, review, reject, and reopen immutable evidence</h3>
          <p className="muted-copy">Every action is bound to the exact finding revision, content hash, latest event hash, authenticated role, and server-evaluated expiry.</p>
        </div>
        <button type="button" className="action-button secondary-action" onClick={onRefresh} disabled={loading || !finding}>
          <RefreshCw size={16} aria-hidden /> {loading ? "Refreshing…" : "Refresh queue"}
        </button>
      </div>

      {conflict && <div className="evidence-conflict" role="alert"><TriangleAlert size={17} aria-hidden /><span><strong>Evidence conflict</strong>{conflict}</span></div>}
      {error && !conflict && <div className="notice error" role="alert"><TriangleAlert size={16} aria-hidden /> {error}</div>}
      {loading && <p className="boundary-copy" role="status" aria-live="polite">Loading current evidence revision and audit replay…</p>}

      <div className="evidence-submit-grid">
        <label>Evidence class
          <select value={selectedClass} onChange={(event) => setEvidenceClass(event.target.value)} disabled={!canSubmit || !supportedClasses.length}>
            {!supportedClasses.length && <option value={evidenceClass}>Load a finding to see supported classes</option>}
            {supportedClasses.map((item) => <option value={item} key={item}>{humanize(item)}</option>)}
          </select>
        </label>
        <label>Expiry (optional)
          <input type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} disabled={!canSubmit} />
        </label>
        <label className="evidence-summary-field">Concise evidence summary
          <input value={summary} onChange={(event) => setSummary(event.target.value)} placeholder="What was verified, where, and for which scope?" disabled={!canSubmit} />
        </label>
        <label className="evidence-summary-field">Evidence details
          <textarea rows={3} value={details} onChange={(event) => setDetails(event.target.value)} placeholder="Source-bound details only. Do not paste tokens, passwords, or secrets." disabled={!canSubmit} />
        </label>
        <label className="evidence-summary-field">Source references
          <input value={sourceRefs} onChange={(event) => setSourceRefs(event.target.value)} placeholder="Comma-separated ticket, advisory, test or asset references" disabled={!canSubmit} />
        </label>
      </div>
      <div className="report-actions">
        <button type="button" className="action-button" onClick={submitEvidence} disabled={!canSubmit || !finding || !selectedClass || !summary.trim()}>
          <Upload size={16} aria-hidden /> Submit immutable evidence
        </button>
        <span className="pill amber">Submission never issues final approval</span>
      </div>
      {!canSubmit && <p className="boundary-copy">Submission requires Triage Analyst, Security Lead, Service Owner, or Admin. Read-only users can inspect hashes, revisions, expiry, and audit replay.</p>}

      <div className="evidence-queue-list">
        {(queue?.evidence || []).map((record) => {
          const rationale = rationales[record.evidence_id] || "";
          const canReview = canReviewEvidence(roles, record.evidence_class);
          const reviewable = ["pending_review", "reopened"].includes(record.review_state) && !record.expired && record.replay_verified !== false;
          const reopenable = ["reviewed", "rejected", "expired"].includes(record.review_state) && canReview;
          const revisionConflict = ["invalidated", "stale"].includes(record.review_state) || record.replay_verified === false;
          return (
            <article className={`evidence-record-card ${evidenceTone(record)}`} key={record.evidence_id}>
              <div className="section-title compact-title">
                <div>
                  <p className="eyebrow">{humanize(record.evidence_class)}</p>
                  <h4>{record.summary}</h4>
                </div>
                <span className={`pill ${evidenceTone(record)}`}>{humanize(record.review_state)}</span>
              </div>
              <dl className="evidence-record-grid">
                <EvidenceFact label="Evidence ID" value={record.evidence_id} code />
                <EvidenceFact label="Content hash" value={record.content_hash} code />
                <EvidenceFact label="Finding revision" value={record.finding_revision_hash} code />
                <EvidenceFact label="Latest event hash" value={record.latest_event_hash || "No review event yet"} code />
                <EvidenceFact label="Expiry" value={record.expires_at ? formatEvidenceDate(record.expires_at) : "No expiry set"} detail={record.expired ? "Expired: refreshed evidence required" : record.expiry_evaluated_at ? `Evaluated ${formatEvidenceDate(record.expiry_evaluated_at)}` : undefined} />
                <EvidenceFact label="Audit replay" value={record.replay_verified === false ? "Conflict detected" : "Verified"} detail={`${record.event_count || 0} immutable event(s)`} />
              </dl>
              {(record.source_refs || []).length > 0 && <p className="boundary-copy"><strong>Source refs:</strong> {(record.source_refs || []).join(", ")}</p>}
              {record.review && <p className="boundary-copy"><strong>Latest review:</strong> {humanize(record.review.decision || "recorded")} by {record.review.reviewer_upn || record.review.reviewer_oid || "authenticated reviewer"}{record.review.rationale ? ` — ${record.review.rationale}` : ""}</p>}
              {revisionConflict && <p className="evidence-record-warning"><TriangleAlert size={15} aria-hidden /> Integrity/revision conflict: {(record.replay_failures || [record.review_state]).map(humanize).join(", ")}. Refresh and submit evidence against the current finding revision.</p>}
              {record.expired && <p className="evidence-record-warning"><Clock3 size={15} aria-hidden /> This immutable record is expired. A reopen event remains auditable, but current decisions require a refreshed evidence submission.</p>}
              {canReview && (reviewable || reopenable) && (
                <div className="evidence-review-controls">
                  <label>Reviewer rationale
                    <textarea rows={2} value={rationale} onChange={(event) => setRationales({ ...rationales, [record.evidence_id]: event.target.value })} placeholder="Record the evidence-based reason for this action." />
                  </label>
                  <div className="report-actions">
                    {reviewable && <>
                      <button type="button" className="action-button" disabled={!rationale.trim()} onClick={() => onReview(record, "accept", rationale)}><CheckCircle2 size={15} aria-hidden /> Accept</button>
                      <button type="button" className="action-button secondary-action" disabled={!rationale.trim()} onClick={() => onReview(record, "reject", rationale)}><X size={15} aria-hidden /> Reject</button>
                    </>}
                    {reopenable && <button type="button" className="action-button secondary-action" disabled={!rationale.trim()} onClick={() => onReopen(record, rationale)}><RefreshCw size={15} aria-hidden /> Reopen review</button>}
                  </div>
                </div>
              )}
              {!canReview && <p className="boundary-copy">Your role can inspect this record but cannot review its {humanize(record.evidence_class)} class.</p>}
            </article>
          );
        })}
        {!loading && queue && !queue.evidence.length && <EmptyState title="No evidence submitted for this finding" detail="Use the form above to create the first immutable, server-owned evidence record." />}
        {!loading && !queue && !error && <EmptyState title="Select a finding to load evidence" detail="The queue is always scoped to one persisted finding and its current revision." />}
      </div>
    </section>
  );
}

function EvidenceFact({ label, value, detail, code = false }: { label: string; value: string; detail?: string; code?: boolean }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{code ? <code title={value}>{value}</code> : value}</dd>
      {detail && <small>{detail}</small>}
    </div>
  );
}

const serviceEvidenceClasses = new Set(["affected_asset_scope", "affected_service_scope", "business_service_impact", "patch_feasibility", "test_evidence", "rollback_plan", "change_window", "customer_impact", "post_patch_validation", "maintenance_window", "vendor_support"]);
const riskEvidenceClasses = new Set(["risk_acceptance", "compensating_controls", "owner", "expiry_date", "rationale"]);

function canReviewEvidence(roles: string[], evidenceClass: string) {
  const roleSet = new Set(roles);
  if (roleSet.has("PatchForge.Admin")) return true;
  if (evidenceClass === "human_review_signoff") return roleSet.has("PatchForge.CABApprover");
  if (riskEvidenceClasses.has(evidenceClass)) return roleSet.has("PatchForge.RiskOwner");
  if (serviceEvidenceClasses.has(evidenceClass)) return roleSet.has("PatchForge.ServiceOwner") || roleSet.has("PatchForge.SecurityLead");
  return roleSet.has("PatchForge.SecurityLead");
}

function evidenceTone(record: FindingEvidenceRecord) {
  if (record.expired || ["rejected", "invalidated", "stale"].includes(record.review_state) || record.replay_verified === false) return "amber";
  if (record.review_state === "reviewed" && record.evidence_state === "accepted_positive_evidence") return "trust";
  if (record.review_state === "reopened") return "teal";
  return "steel";
}

function formatEvidenceDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function CommandCenter({
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

export function Guide() {
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

export function VulnerabilityQueue({
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

export function AssetExposure({ assets, services }: { assets: AssetRecord[]; services: ServiceRecord[] }) {
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

export function DecisionWorkbench({
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

export function EmergencyPatch({ vulnerabilities }: { vulnerabilities: VulnerabilityRecord[] }) {
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

export function RiskAcceptances({ decisionPacks }: { decisionPacks: DecisionPackRecord[] }) {
  const riskPacks = decisionPacks.filter((pack) => pack.decision_posture === "risk_accept_temporarily");
  return <PageBand icon={Clock3} title="Risk Acceptances" lines={[`${riskPacks.length} signed risk-acceptance packs`, "Owner, rationale, expiry and controls required", "Final approval remains explicit"]} />;
}

export function CompensatingControls() {
  return <PageBand icon={Wrench} title="Compensating Controls" lines={["Controls are evidence records", "Accepted controls require human review", "Controls do not mutate production systems"]} />;
}

export function SraResearch({ onRun, result, canWrite }: { onRun: () => void; result: Record<string, unknown> | null; canWrite: boolean }) {
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

export function EvidenceCatalogue({ vulnerabilities }: { vulnerabilities: VulnerabilityRecord[] }) {
  const sourceCount = vulnerabilities.reduce((total, item) => total + (item.source_record_ids?.length || item.sources?.length || 0), 0);
  return <PageBand icon={BookOpenCheck} title="Evidence Catalogue" lines={[`${sourceCount} source-bound evidence references`, "Scanner, SRA, MCP, Mythos, and AGI-agent output require review", "Rejected sources cannot count as positive evidence"]} />;
}

export function SourceFeeds({
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

export function VendorThreatLandscape({ vendors, threatSummary }: { vendors: VendorProfile[]; threatSummary: ThreatLandscapeSummary | null }) {
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

import { useEffect, useState } from "react";
import {
  Archive,
  CheckCircle2,
  Download,
  FileCheck2,
  FileText,
  KeyRound,
  Search
} from "lucide-react";
import type {
  AdminHealth,
  AdminPurgePlan,
  DecisionPackRecord,
  FindingIntelligence,
  OpenAiAgentStatus,
  ReportCatalogItem,
  ReportsPacksState
} from "../api";
import {
  EmptyState,
  PaginationControls,
  StatusLine,
  healthTone,
  humanize,
  newestDecisionPacks,
  usePagination
} from "./AreaPrimitives";

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

function formatPackDate(value?: string) {
  if (!value) {
    return "Not recorded";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function packFreshness(pack: DecisionPackRecord) {
  if (!pack.created_at) {
    return { label: "Age not recorded", detail: "The runtime did not return a pack creation timestamp." };
  }
  const createdAt = Date.parse(pack.created_at);
  if (!Number.isFinite(createdAt)) {
    return { label: "Age unknown", detail: `Creation value: ${pack.created_at}` };
  }
  const ageHours = Math.max(0, (Date.now() - createdAt) / 3_600_000);
  if (ageHours <= 24) {
    return { label: "Current pack", detail: `Created ${Math.max(0, Math.floor(ageHours))} hour(s) ago.` };
  }
  const ageDays = Math.floor(ageHours / 24);
  return { label: `${ageDays}d old`, detail: "Historical signed-pack context; review current evidence before relying on it." };
}

function packOptionLabel(pack: DecisionPackRecord) {
  const created = pack.created_at ? formatPackDate(pack.created_at) : "date not recorded";
  return `${pack.pack_id} | ${pack.vulnerability_id} | ${created}`;
}

export function ReportsPacks({
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
  const verifiedPacks = sortedPacks.filter((pack) => pack.verification?.verified);
  const [selectedPackId, setSelectedPackId] = useState("");
  const verifiedPackIds = verifiedPacks.map((pack) => pack.pack_id).join("|");
  useEffect(() => {
    setSelectedPackId((current) => (
      verifiedPacks.some((pack) => pack.pack_id === current)
        ? current
        : verifiedPacks[0]?.pack_id || ""
    ));
  }, [verifiedPackIds]);
  const selectedPack = verifiedPacks.find((pack) => pack.pack_id === selectedPackId) || verifiedPacks[0] || null;
  const selectedPreExport = !preExport.pack_id || preExport.pack_id === selectedPack?.pack_id;
  const selectedPackArtifacts = selectedPack?.artefacts || {};
  const selectedVendorLensContext = selectedPreExport
    ? Boolean(preExport.vendorlens_context_included)
    : Boolean(
        selectedPackArtifacts["config_applicability_assessment.json"]
        || selectedPackArtifacts["customer_network_asset_snapshot.json"]
        || selectedPackArtifacts["vendor_security_advisory_snapshot.json"]
        || selectedPackArtifacts["sra_config_chat_session.json"]
      );
  const selectedCustomerContext = selectedPreExport
    ? Boolean(preExport.customer_context_included)
    : Boolean(
        selectedPackArtifacts["customer_estate_snapshot.json"]
        || selectedPackArtifacts["customer_network_asset_snapshot.json"]
      );
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
          <span className="pill trust">{verifiedPacks.length} verified packs</span>
          <span className="pill teal">{findings.length} analysed findings</span>
        </div>
      </section>
      <section className="data-band verified-pack-selection" aria-label="Verified report pack selection">
        <div className="section-title compact-title">
          <div>
            <p className="eyebrow">Report source</p>
            <h3>Select a verified decision pack</h3>
          </div>
          <span className={`pill ${selectedPack ? "trust" : "amber"}`}>{selectedPack ? packFreshness(selectedPack).label : "No verified pack"}</span>
        </div>
        <label className="stacked-input">
          <span>Verified decision pack</span>
          <select
            aria-label="Verified decision pack"
            value={selectedPack?.pack_id || ""}
            onChange={(event) => setSelectedPackId(event.target.value)}
            disabled={!verifiedPacks.length}
          >
            {!verifiedPacks.length && <option value="">No verified pack available</option>}
            {verifiedPacks.map((pack) => (
              <option value={pack.pack_id} key={pack.pack_id}>{packOptionLabel(pack)}</option>
            ))}
          </select>
        </label>
        <div className="split-grid">
          <StatusLine label="Selected pack" value={selectedPack?.pack_id || "None"} tone={selectedPack ? "trust" : "amber"} />
          <StatusLine label="Finding context" value={selectedPack?.vulnerability_id || "No finding bound"} tone="teal" />
          <StatusLine label="Decision posture" value={humanize(selectedPack?.decision_posture || "not recorded")} tone="steel" />
          <StatusLine label="Created" value={formatPackDate(selectedPack?.created_at)} tone="steel" detail={selectedPack ? packFreshness(selectedPack).detail : undefined} />
        </div>
        {selectedPack && !selectedPreExport && (
          <p className="boundary-copy">Historical pack selected. The current pre-export runtime snapshot belongs to {String(preExport.pack_id)}; downloads below remain bound to {selectedPack.pack_id}.</p>
        )}
      </section>
      <section className="data-band">
        <div className="section-title">
          <h3>Pre-Export Check</h3>
          <span className="pill amber">{selectedPack?.final_approval_issued ? "Final approval issued" : "Final approval false"}</span>
        </div>
        <div className="split-grid">
          <StatusLine label="Pack ID" value={selectedPack?.pack_id || "Select or generate a verified pack"} tone={selectedPack ? "trust" : "amber"} />
          <StatusLine label="Baseline" value={String(selectedPack?.product_baseline || (selectedPreExport ? preExport.baseline : "") || "Not recorded by runtime")} tone="steel" />
          <StatusLine label="Renderer commit" value={String(selectedPack?.report_renderer_commit || (selectedPreExport ? preExport.renderer_commit : "") || "not recorded")} tone="steel" />
          <StatusLine label="Image tag" value={String(selectedPack?.report_renderer_image_tag || (selectedPreExport ? preExport.image_tag : "") || "not recorded")} tone="steel" />
          <StatusLine label="Evidence state" value={selectedPreExport ? humanize(String(preExport.evidence_state || "evidence_review_required")) : "Inspect selected pack"} tone="amber" />
          <StatusLine label="VendorLens context" value={selectedVendorLensContext ? "Included" : "Not attached"} tone={selectedVendorLensContext ? "teal" : "amber"} />
          <StatusLine label="Customer context" value={selectedCustomerContext ? "Included" : "Not attached"} tone={selectedCustomerContext ? "teal" : "amber"} />
          <StatusLine label="Verification" value={selectedPack?.verification?.verified ? "Verified" : "Required before report download"} tone={selectedPack ? "trust" : "amber"} />
        </div>
        <p className="boundary-copy">{String((selectedPreExport && preExport.report_current_stale_warning) || "Reports are generated from the deliberately selected signed pack; current evidence may still require review.")}</p>
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
      <DecisionPacks decisionPacks={sortedPacks} reports={reports} onExportPack={onExportPack} onDownloadReport={onDownloadReport} selectedPackId={selectedPack?.pack_id || ""} onSelectPack={setSelectedPackId} hideReportDownloads />
      <Reports decisionPacks={sortedPacks} reports={reports} selectedPackId={selectedPack?.pack_id || ""} onDownloadReport={onDownloadReport} />
    </>
  );
}

export function DecisionPacks({
  decisionPacks,
  reports,
  onExportPack,
  onDownloadReport,
  selectedPackId,
  onSelectPack,
  hideReportDownloads = false
}: {
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  onExportPack: (packId: string) => void;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
  selectedPackId?: string;
  onSelectPack?: (packId: string) => void;
  hideReportDownloads?: boolean;
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
              <tr key={pack.pack_id} className={selectedPackId === pack.pack_id ? "selected-pack-row" : undefined}>
                <td>{pack.pack_id}</td>
                <td>{pack.vulnerability_id}</td>
                <td>{humanize(pack.decision_posture || "unknown")}</td>
                <td>{humanize(pack.readiness?.readiness_state || "pending")}</td>
                <td>{pack.verification?.verified ? "Yes" : "Pending"}</td>
                <td>{pack.created_at ? new Date(pack.created_at).toLocaleString() : "Not recorded"}</td>
                <td>
                  <div className="export-actions">
                    {onSelectPack && pack.verification?.verified && (
                      <button type="button" className="action-button compact-action" aria-pressed={selectedPackId === pack.pack_id} onClick={() => onSelectPack(pack.pack_id)}>
                        {selectedPackId === pack.pack_id ? "Selected" : "Use for reports"}
                      </button>
                    )}
                    <button type="button" className="icon-button" title="Export signed JSON pack" aria-label={`Export ${pack.pack_id}`} onClick={() => onExportPack(pack.pack_id)}>
                      <FileCheck2 size={16} aria-hidden />
                    </button>
                    {!hideReportDownloads && <>
                      <button type="button" className="icon-button" title={pack.verification?.verified ? "Download verified board DOCX" : "Verification required before report download"} aria-label={`Download DOCX ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "docx")} disabled={!defaultReport || !pack.verification?.verified}>
                        <FileText size={16} aria-hidden />
                      </button>
                      <button type="button" className="icon-button" title={pack.verification?.verified ? "Download verified board PDF" : "Verification required before report download"} aria-label={`Download PDF ${pack.pack_id}`} onClick={() => defaultReport && onDownloadReport(pack.pack_id, defaultReport.report_type, "pdf")} disabled={!defaultReport || !pack.verification?.verified}>
                        <Download size={16} aria-hidden />
                      </button>
                    </>}
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
  selectedPackId,
  onDownloadReport
}: {
  decisionPacks: DecisionPackRecord[];
  reports: ReportCatalogItem[];
  selectedPackId: string;
  onDownloadReport: (packId: string, reportType: string, format: "docx" | "pdf") => void;
}) {
  const sortedPacks = newestDecisionPacks(decisionPacks);
  const verifiedPacks = sortedPacks.filter((pack) => pack.verification?.verified);
  // Reports must never present or download an unverified pack as a signed output.
  const selectedPack = verifiedPacks.find((pack) => pack.pack_id === selectedPackId) || null;
  const selectedPackHasVendorLens = Boolean(selectedPack?.artefacts && (
    selectedPack.artefacts["config_applicability_assessment.json"]
    || selectedPack.artefacts["customer_network_asset_snapshot.json"]
    || selectedPack.artefacts["vendor_security_advisory_snapshot.json"]
    || selectedPack.artefacts["sra_config_chat_session.json"]
  ));
  const selectedBaseline = selectedPack?.product_baseline || "Not recorded by runtime";
  const selectedReportVersion = selectedPack?.report_template_version || "Recorded when the pack is generated";
  const selectedContextVersion = selectedPack?.report_context_version || "Recorded when the pack is generated";
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
          <span className="pill teal">{selectedBaseline}</span>
        </div>
        <div className="decision-option-grid compact-status-grid">
          <StatusLine label="Pack ID" value={selectedPack?.pack_id || "No verified pack selected"} tone={selectedPack ? "trust" : "amber"} />
          <StatusLine label="Report version" value={selectedReportVersion} tone="steel" />
          <StatusLine label="Context version" value={selectedContextVersion} tone="steel" />
          <StatusLine label="Final approval" value={selectedPack?.final_approval_issued ? "Issued" : "False"} tone="amber" />
          <StatusLine label="VendorLens context" value={selectedPackHasVendorLens ? "Included in pack" : "Not attached to selected pack"} tone={selectedPackHasVendorLens ? "teal" : "amber"} />
          <StatusLine label="Verification" value={selectedPack?.verification?.verified ? "Verified" : "Required before report download"} tone={selectedPack ? "trust" : "amber"} />
        </div>
        {!selectedPackHasVendorLens && selectedPack && <p className="boundary-copy">Selected pack can still export reports, but VendorLens sections will clearly state that network vendor applicability evidence was not attached.</p>}
      </section>

      <div className="report-grid">
        {reportPage.items.map((report) => (
          <section className="data-band report-card" key={report.report_type}>
            <div className="section-title compact-title">
              <h3>{report.title}</h3>
              <span className="pill steel">{report.audience}</span>
            </div>
            <StatusLine label="Source" value={selectedPack ? `Verified pack ${selectedPack.pack_id}` : "No verified pack selected"} tone={selectedPack ? "trust" : "amber"} />
            <StatusLine label="Formats" value="DOCX and PDF" tone="teal" />
            <StatusLine label="Boundary" value="No deployment or approval" tone="amber" />
            <div className="report-actions">
              <button type="button" className="action-button" aria-label={`Download ${report.title} DOCX from ${selectedPack?.pack_id || "selected pack"}`} disabled={!selectedPack} onClick={() => selectedPack && onDownloadReport(selectedPack.pack_id, report.report_type, "docx")}>
                <FileText size={16} aria-hidden /> DOCX
              </button>
              <button type="button" className="action-button secondary-action" aria-label={`Download ${report.title} PDF from ${selectedPack?.pack_id || "selected pack"}`} disabled={!selectedPack} onClick={() => selectedPack && onDownloadReport(selectedPack.pack_id, report.report_type, "pdf")}>
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

export function Admin({
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

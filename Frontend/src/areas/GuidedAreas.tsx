import { useEffect, useState } from "react";
import type { FormEvent, KeyboardEvent } from "react";
import {
  CheckCircle2,
  Clock3,
  Download,
  FileCheck2,
  FileText,
  Gauge,
  Layers3,
  ListFilter,
  MessageSquareText,
  Network,
  RefreshCw,
  Search,
  ServerCog,
  ShieldAlert,
  TriangleAlert
} from "lucide-react";
import type {
  AgentGuidanceSnapshot,
  AskPatchForgeAnswer,
  AssetDiscoveryOverview,
  CustomerAssetExtraction,
  CustomerEstateMatch,
  CustomerEstateState,
  OpenAiAgentStatus,
  VendorLensPatchComparison,
  VendorLensState
} from "../api";
import {
  EmptyState,
  PaginationControls,
  StatusLine,
  candidateList,
  candidateValue,
  humanize,
  recordMatchesContext,
  usePagination
} from "./AreaPrimitives";

const discoveryCollectorCategories = [
  "network_device",
  "security_appliance",
  "physical_server",
  "virtual_server",
  "hypervisor",
  "cloud_resource"
];

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

function CollectorSetupStep({ step, title, detail, complete }: { step: number; title: string; detail: string; complete: boolean }) {
  return (
    <li className={complete ? "complete" : "pending"}>
      <span className="collector-step-marker" aria-hidden>{complete ? <CheckCircle2 size={18} /> : step}</span>
      <span>
        <strong>{title}</strong>
        <small>{detail}</small>
      </span>
      <span className={`pill ${complete ? "trust" : "amber"}`}>{complete ? "Complete" : "Action required"}</span>
    </li>
  );
}

function CollectorFact({ label, value, detail, code = false }: { label: string; value: string; detail?: string; code?: boolean }) {
  return (
    <div className="collector-fact">
      <span>{label}</span>
      {code ? <code title={value}>{value}</code> : <strong>{value}</strong>}
      {detail && detail !== "Never" && <small>{detail}</small>}
    </div>
  );
}

function collectorHealthTone(health: string) {
  if (health === "ready" || health === "active") {
    return "trust";
  }
  if (health === "revoked") {
    return "danger";
  }
  if (health === "stale" || health === "degraded") {
    return "amber";
  }
  return "steel";
}

function collectorRecoveryGuidance(health: string, lastMessage?: string | null) {
  if (health === "revoked") {
    return "This identity cannot self-reactivate. Register a new collector identity only after accountable approval and replace the old config/package assignment.";
  }
  if (health === "stale" || health === "degraded") {
    return `Verify the package signature and configured tenant/API values, confirm the environment token or managed identity, then retry the signed collector with the same collector ID${lastMessage ? ` after resolving: ${lastMessage}` : ""}. Revoke the identity if the host is retired or credentials may be compromised.`;
  }
  if (health === "pending" || health === "registered") {
    return "Complete policy/config setup, verify the signed package and digest, then run the collector. If the first heartbeat still does not appear, check the local verification output before retrying.";
  }
  return "Monitor the next heartbeat and package digest. Revoke the collector on offboarding or suspected identity compromise; revoked IDs cannot self-reactivate.";
}

function formatDateTime(value?: string | null) {
  if (!value) {
    return "Never";
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

export function CustomerEstate({
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
  const collectors = discovery?.collectors || [];
  const policies = discovery?.policies || [];
  const collectorRegistered = collectors.length > 0;
  const collectorConfigured = collectorRegistered && policies.some((policy) => (
    !policy.collector_id || collectors.some((collector) => collector.collector_id === policy.collector_id)
  ));
  const collectorVerified = collectors.some((collector) => (
    collector.health_status === "ready"
    && Boolean(collector.package_digest)
    && Boolean(collector.collector_version && collector.collector_version !== "unknown")
  ));

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
        <ol className="collector-setup-checklist" aria-label="Collector setup checklist">
          <CollectorSetupStep
            step={1}
            title="Register collector identity"
            detail="Create the tenant-scoped, outbound-only collector record. No raw credentials are stored."
            complete={collectorRegistered}
          />
          <CollectorSetupStep
            step={2}
            title="Create policy and download config"
            detail="Bind read-only categories and methods, then download the tenant-specific configuration."
            complete={collectorConfigured}
          />
          <CollectorSetupStep
            step={3}
            title="Install signed package and verify"
            detail="Verify the signed Windows package and digest, run it, then confirm a healthy heartbeat and recorded version below."
            complete={collectorVerified}
          />
        </ol>
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
        <div className="collector-lifecycle-list" aria-label="Registered collector lifecycle">
          {collectors.map((collector) => {
            const latestRun = discovery?.recent_runs.find((run) => run.collector_id === collector.collector_id);
            const health = collector.health_status || collector.status || "pending";
            const reason = collector.revoked_reason
              || collector.degraded_reason
              || collector.stale_reason
              || (health === "stale" ? `Heartbeat overdue${collector.next_heartbeat_due_at ? ` since ${formatDateTime(collector.next_heartbeat_due_at)}` : ""}.` : "")
              || (health === "degraded" ? collector.last_message || `Heartbeat state: ${humanize(collector.heartbeat_state || "unknown")}.` : "");
            return (
              <article className={`collector-lifecycle-card ${collectorHealthTone(health)}`} key={collector.collector_id}>
                <div className="section-title compact-title">
                  <div>
                    <p className="eyebrow">{collector.collector_id}</p>
                    <h4>{collector.name}</h4>
                  </div>
                  <span className={`pill ${collectorHealthTone(health)}`}>{humanize(health)}</span>
                </div>
                <div className="collector-lifecycle-grid">
                  <CollectorFact label="Lifecycle" value={`${humanize(collector.status)} / ${humanize(collector.heartbeat_state || "awaiting first run")}`} />
                  <CollectorFact label="Last seen" value={formatDateTime(collector.last_heartbeat_at || collector.last_seen_at)} />
                  <CollectorFact label="Last run" value={collector.last_run_id || latestRun?.run_id || "No run recorded"} detail={formatDateTime(collector.last_run_at || latestRun?.completed_at)} />
                  <CollectorFact label="Last message" value={collector.last_message || "No collector message recorded"} />
                  <CollectorFact label="Version" value={collector.collector_version || "Unknown"} detail={humanize(collector.package_channel || "package channel unknown")} />
                  <CollectorFact label="Package digest" value={collector.package_digest || "Not reported"} code />
                </div>
                {reason && <p className="collector-state-reason"><TriangleAlert size={16} aria-hidden /><span><strong>State reason:</strong> {reason}</span></p>}
                <p className="collector-guidance"><strong>Operator guidance:</strong> {collectorRecoveryGuidance(health, collector.last_message)}</p>
              </article>
            );
          })}
          {!collectors.length && (
            <EmptyState title="No collector registered" detail="Start with Register Collector, then create the policy/config and verify the signed package heartbeat." />
          )}
        </div>
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

export function AskPatchForge({
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
  canWrite,
  canGeneratePacks
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
  canGeneratePacks: boolean;
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
          canGeneratePacks={canGeneratePacks}
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
  canGeneratePacks,
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
  canGeneratePacks: boolean;
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
      disabled: !canGeneratePacks || !selectedVulnerabilityId
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

function vendorLensTabId(tab: string): string {
  return `vendorlens-tab-${tab.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "")}`;
}

export function VendorLens({
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

  function handleTabKeyDown(event: KeyboardEvent<HTMLButtonElement>, currentTab: string) {
    const currentIndex = vendorLensTabs.indexOf(currentTab);
    let nextIndex = currentIndex;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (currentIndex + 1) % vendorLensTabs.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (currentIndex - 1 + vendorLensTabs.length) % vendorLensTabs.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = vendorLensTabs.length - 1;
    } else {
      return;
    }
    event.preventDefault();
    const nextTab = vendorLensTabs[nextIndex];
    setActiveTab(nextTab);
    document.getElementById(vendorLensTabId(nextTab))?.focus();
  }

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

      <div className="vendorlens-tabs" role="tablist" aria-label="VendorLens tabs" aria-orientation="horizontal">
        {vendorLensTabs.map((tab) => (
          <button
            key={tab}
            id={vendorLensTabId(tab)}
            type="button"
            role="tab"
            className={activeTab === tab ? "vendorlens-tab active" : "vendorlens-tab"}
            aria-selected={activeTab === tab}
            aria-controls="vendorlens-active-panel"
            tabIndex={activeTab === tab ? 0 : -1}
            onClick={() => setActiveTab(tab)}
            onKeyDown={(event) => handleTabKeyDown(event, tab)}
          >
            {tab}
          </button>
        ))}
      </div>

      <div id="vendorlens-active-panel" role="tabpanel" aria-labelledby={vendorLensTabId(activeTab)} tabIndex={0}>

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
      </div>

      {!canWrite && <EmptyState title="Read-only role" detail="VendorLens asset, advisory, refresh, assessment, and chat actions require a PatchForge write role." />}
    </>
  );
}

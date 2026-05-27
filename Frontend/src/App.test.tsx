import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { FindingIntelligence, PatchForgeApi, PatchForgeMetrics } from "./api";
import { PatchForgeAuthSession } from "./auth";

const metrics: PatchForgeMetrics = {
  tenant_id: "diiac.io",
  vulnerability_count: 1,
  critical_exposure: 1,
  known_exploited: 1,
  patch_overdue: 0,
  pending_review: 1,
  accepted_positive_evidence_sources: 0,
  rejected_sources: 0,
  signed_packs: 0
};

const auth: PatchForgeAuthSession = {
  status: "authenticated",
  accountName: "n.bailey@diiac.io",
  roles: ["PatchForge.Admin"],
  signIn: vi.fn(async () => undefined),
  signOut: vi.fn(async () => undefined),
  getAccessToken: vi.fn(async () => "test-token")
};

const finding: FindingIntelligence = {
  intelligence_id: "intel-CVE-2026-REAL-001",
  generated_at: "2026-05-27T08:00:00Z",
  vulnerability_id: "CVE-2026-REAL-001",
  title: "Customer gateway authentication bypass",
  severity: "critical",
  vendor: "Microsoft",
  product: "Example Gateway",
  summary: {
    plain_english: "A customer gateway component can be bypassed under affected conditions. PatchForge treats this as a governance decision.",
    why_now: "It is flagged as known exploited in source-bound intelligence.",
    what_it_affects: "Mapped service impact: Orion Gateway.",
    operational_risk: "Delay could leave an exposed known-exploited condition unresolved.",
    decision_required: "Emergency change required is recommended, but human approval remains required.",
    executive_readout: "CVE-2026-REAL-001 should be handled as Emergency Change Required because PatchForge sees customer-facing service exposure."
  },
  exploitability: {
    known_exploited: true,
    epss_score: 0.82,
    epss_percentile: 0.97,
    ransomware_use: "Unknown",
    safe_description: "Source-bound intelligence indicates this vulnerability is known to be exploited in the wild.",
    prohibited_detail: "Exploit code, exploit payloads, and procedural exploitation steps are intentionally not provided."
  },
  exposure: {
    affected_service_count: 1,
    affected_asset_count: 0,
    internet_exposed: true,
    customer_facing: true,
    ot_relevant: false,
    unmapped_scope: false,
    interpretation: ["Customer-facing service impact."],
    affected_services: [{ service_id: "svc-orion", service_name: "Orion Gateway", owner: "Service Owner", customer_facing: true, service_tier: "tier_1" }],
    affected_assets: []
  },
  recommendation: {
    posture: "emergency_change_required",
    next_best_action: "Open CAB/security-lead emergency review and confirm rollback evidence before approval.",
    confidence: "high",
    rationale: ["Known exploitation, patch availability, and exposed service context indicate emergency change governance."],
    do_now: ["Open CAB/security-lead emergency review."],
    do_next: ["Attach rollback evidence."],
    due_date: "2026-06-03",
    advisory_only: true,
    final_approval_issued: false
  },
  decision_options: [{
    posture: "emergency_change_required",
    when_to_choose: "Use when known exploitation and customer-facing impact make normal change cadence too slow.",
    benefits: "Fast accountable response.",
    risks: "Higher change risk if evidence is incomplete.",
    evidence_needed: ["Rollback plan", "Human approval"],
    approval_needed: true,
    recommended: true
  }],
  evidence: {
    accepted_positive_evidence_count: 0,
    pending_review_count: 1,
    rejected_source_count: 0,
    gaps: ["Affected asset scope", "Rollback plan"],
    warning: "Source and agent outputs remain source-bound until reviewed."
  },
  automation: {
    completed: ["Normalised finding identity", "Bound source provenance", "Applied governance boundary"],
    remaining_human_decisions: ["Issue or withhold CAB/security/service-owner approval."],
    available_actions: ["Open Finding Detail", "Generate signed decision pack"]
  },
  latest_signed_pack: null,
  boundary: {
    advisory_only: true,
    no_exploit_code: true,
    no_patch_deployment: true
  }
};

function createApi(overrides: Partial<PatchForgeApi> = {}): PatchForgeApi {
  return {
    metrics: vi.fn(async () => metrics),
    listVulnerabilities: vi.fn(async () => [{
      tenant_id: "diiac.io",
      vulnerability_id: "CVE-2026-REAL-001",
      severity: "critical",
      patch_status: "patch_available",
      known_exploited: true,
      internet_exposed: true
    }]),
    ingestVulnerability: vi.fn(async (_tenantId, payload) => ({
      tenant_id: "diiac.io",
      vulnerability_id: String(payload.vulnerability_id)
    })),
    listAssets: vi.fn(async () => []),
    listServices: vi.fn(async () => []),
    listDecisionPacks: vi.fn(async () => []),
    generateDecisionPack: vi.fn(async () => ({
      decision_pack_id: "PF-TEST-0001",
      pack_id: "PF-TEST-0001",
      vulnerability_id: "CVE-2026-REAL-001",
      verification: { verified: true }
    })),
    exportDecisionPack: vi.fn(async () => ({ pack_id: "PF-TEST-0001", source_pack_immutable: true })),
    reportCatalog: vi.fn(async () => [{
      report_type: "board_vulnerability_remediation_summary",
      title: "Board Vulnerability Remediation Summary",
      audience: "Board and senior leadership",
      formats: ["docx", "pdf"]
    }, {
      report_type: "cab_patch_decision_report",
      title: "CAB Patch Decision Report",
      audience: "Change Advisory Board",
      formats: ["docx", "pdf"]
    }]),
    downloadDecisionPackReport: vi.fn(async () => new Blob(["report"], { type: "application/pdf" })),
    assessBayesianRisk: vi.fn(async () => ({
      advisory_only: true,
      can_close_hard_gates_alone: false,
      exploit_probability_posterior: 0.82,
      business_impact_posterior: 0.71,
      patch_feasibility_posterior: 0.64,
      change_risk_posterior: 0.42,
      deferral_risk_posterior: 0.76,
      recommended_governance_posture: "emergency_change_required"
    })),
    bayesianPriors: vi.fn(async () => ({ live_prior_update_enabled: false })),
    threatLandscapeSummary: vi.fn(async () => ({
      tenant_id: "diiac.io",
      source_bound: true,
      review_required: true,
      vendor_count: 28,
      metrics: {
        active_exploitation_count: 1,
        critical_open_advisory_count: 1,
        patch_available_rate: 0,
        known_exploited_rate: 0,
        customer_estate_exposure: 0,
        internet_exposed_asset_count: 0,
        ot_relevance: 0,
        patch_maturity: "unknown",
        vendor_response_timeliness: "source_bound_pending_review",
        superseded_advisory_count: 0,
        false_positive_history: 0,
        open_customer_decision_count: 0
      },
      top_exposed_vendors: []
    })),
    listVendors: vi.fn(async () => [{ vendor_id: "microsoft", vendor_name: "Microsoft", category: "identity_endpoint_cloud", review_state: "reference_catalogue" }]),
    sourceFeeds: vi.fn(async () => ({
      feeds: [{
        feed_id: "cisa-kev",
        feed_name: "CISA Known Exploited Vulnerabilities Catalog",
        source_class: "kev_record",
        source_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        provider: "CISA",
        authentication: "public",
        source_bound: true,
        review_required: true,
        can_close_hard_gates_alone: false
      }, {
        feed_id: "first-epss",
        feed_name: "FIRST Exploit Prediction Scoring System",
        source_class: "epss_signal",
        source_url: "https://api.first.org/data/v1/epss",
        provider: "FIRST",
        authentication: "public",
        source_bound: true,
        review_required: true,
        can_close_hard_gates_alone: false
      }],
      recent_runs: []
    })),
    refreshSourceFeed: vi.fn(async () => ({
      run_id: "run-cisa-kev-test",
      feed_id: "cisa-kev",
      feed_name: "CISA Known Exploited Vulnerabilities Catalog",
      status: "completed",
      records_seen: 1,
      records_ingested: 1,
      records_enriched: 0,
      message: "1 CISA KEV records ingested as source-bound pending-review intelligence.",
      completed_at: "2026-05-27T08:00:00Z",
      can_close_hard_gates_alone: false
    })),
    actionCenter: vi.fn(async () => [finding]),
    findingIntelligence: vi.fn(async () => finding),
    analyseFinding: vi.fn(async () => ({ intelligence: finding })),
    sraResearch: vi.fn(async () => ({ sra: { advisory_only: true, can_close_evidence_gates_alone: false } })),
    adminHealth: vi.fn(async () => ({
      tenant_id: "diiac.io",
      live_azure_mutation_enabled: false,
      checks: [{ name: "Signing trust", status: "ready", mode: "key-vault" }]
    })),
    adminConfig: vi.fn(async () => ({
      general: { environment: "Production", governance_tier: "Enterprise Strict" }
    })),
    saveAdminConfig: vi.fn(async (_tenantId, payload) => payload),
    ...overrides
  };
}

describe("PatchForge guided shell", () => {
  it("renders the action center from live API intelligence", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    await waitFor(() => expect(api.actionCenter).toHaveBeenCalled());
    expect(screen.getByText("PatchForge has already translated the queue into decision-ready work.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Action Center" })).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-REAL-001")).toBeInTheDocument();
    expect(screen.getByText(/customer-facing service exposure/i)).toBeInTheDocument();
  });

  it("opens a finding detail page with human-readable exploitability intelligence", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    await waitFor(() => expect(api.actionCenter).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Understand" }));
    expect(screen.getByRole("heading", { name: "Finding Detail" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Exploitability Intelligence" })).toBeInTheDocument();
    expect(screen.getByText(/procedural exploitation steps are intentionally not provided/i)).toBeInTheDocument();
    expect(screen.getByText("Affected Scope")).toBeInTheDocument();
  });

  it("shows review actions after analysis and generates a signed pack", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    await waitFor(() => expect(api.actionCenter).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Review" }));
    expect(screen.getByRole("heading", { name: "Review & Approve" })).toBeInTheDocument();
    expect(screen.getByText("Autonomous Analysis Completed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Generate Signed Pack" }));
    await waitFor(() => expect(api.generateDecisionPack).toHaveBeenCalled());
  });

  it("refreshes live public intelligence from the action center", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    await waitFor(() => expect(api.actionCenter).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Refresh KEV" }));
    await waitFor(() => expect(api.refreshSourceFeed).toHaveBeenCalledWith("diiac.io", expect.objectContaining({ feed_id: "cisa-kev", limit: 5 })));
  });

  it("renders reports and downloads DOCX from signed packs", async () => {
    const api = createApi({
      listDecisionPacks: vi.fn(async () => [{
        decision_pack_id: "PF-TEST-0001",
        pack_id: "PF-TEST-0001",
        vulnerability_id: "CVE-2026-REAL-001",
        decision_posture: "emergency_change_required",
        readiness: { readiness_state: "blocked" },
        verification: { verified: true }
      }])
    });
    render(<App auth={auth} api={api} />);
    await waitFor(() => expect(api.actionCenter).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Reports & Packs" }));
    expect(screen.getByRole("heading", { name: "Reports & Packs" })).toBeInTheDocument();
    expect(screen.getByText("Board Packs & Reports")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "DOCX" })[0]);
    await waitFor(() => expect(api.downloadDecisionPackReport).toHaveBeenCalledWith("diiac.io", "PF-TEST-0001", "board_vulnerability_remediation_summary", "docx"));
  });

  it("renders the guide for agent-led human-approved operation", async () => {
    render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Guide" }));
    expect(screen.getByRole("heading", { name: "Operational Walkthrough" })).toBeInTheDocument();
    expect(screen.getByText("Minimal Human Input Model")).toBeInTheDocument();
  });

  it("hides admin navigation and disables write actions without privileged roles", async () => {
    render(<App auth={{ ...auth, roles: ["PatchForge.Reader"] }} api={createApi()} />);
    expect(screen.queryByRole("button", { name: "Admin" })).not.toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Refresh KEV" })).toBeDisabled();
  });

  it("renders the admin route and avoids prohibited wording", async () => {
    const { container } = render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Admin" }));
    expect(screen.getByRole("heading", { name: "Admin" })).toBeInTheDocument();
    expect(screen.getByText("Entra ID / RBAC")).toBeInTheDocument();
    expect(screen.getByText("Signing & Trust")).toBeInTheDocument();
    expect(container.textContent?.toLowerCase()).not.toContain("autonomous patching");
    expect(container.textContent?.toLowerCase()).not.toContain("exploit generation");
  });

  it("shows the Entra sign-in gate when unauthenticated", () => {
    render(<App auth={{ ...auth, status: "unauthenticated", accountName: null }} api={createApi()} />);
    expect(screen.getByRole("button", { name: "Sign in with Microsoft" })).toBeInTheDocument();
  });

  it("renders API auth errors clearly", async () => {
    render(<App auth={auth} api={createApi({ metrics: vi.fn(async () => { throw new Error("insufficient_patchforge_role"); }) })} />);
    expect(await screen.findByText("insufficient_patchforge_role")).toBeInTheDocument();
  });
});

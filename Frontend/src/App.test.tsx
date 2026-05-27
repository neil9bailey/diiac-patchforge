import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { PatchForgeApi, PatchForgeMetrics } from "./api";
import { PatchForgeAuthSession } from "./auth";

const metrics: PatchForgeMetrics = {
  tenant_id: "diiac.io",
  vulnerability_count: 0,
  critical_exposure: 0,
  known_exploited: 0,
  patch_overdue: 0,
  pending_review: 0,
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

function createApi(overrides: Partial<PatchForgeApi> = {}): PatchForgeApi {
  return {
    metrics: vi.fn(async () => metrics),
    listVulnerabilities: vi.fn(async () => []),
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
      vulnerability_id: "REAL-RECORD-1",
      verification: { verified: true }
    })),
    exportDecisionPack: vi.fn(async () => ({
      pack_id: "PF-TEST-0001",
      source_pack_immutable: true
    })),
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
        active_exploitation_count: 0,
        critical_open_advisory_count: 0,
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
      completed_at: "2026-05-26T22:00:00Z",
      can_close_hard_gates_alone: false
    })),
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

describe("PatchForge shell", () => {
  it("renders the authenticated command center from live API state", async () => {
    render(<App auth={auth} api={createApi()} />);
    expect(await screen.findByText("DIIaC™")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Command Center" })).toBeInTheDocument();
    expect(screen.getByText("Critical exposure")).toBeInTheDocument();
    expect(screen.getByText("No vulnerability records ingested")).toBeInTheDocument();
  });

  it("does not render static vulnerability records", async () => {
    const { container } = render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Vulnerability Queue" }));
    expect(screen.getByRole("heading", { name: "Vulnerability Queue" })).toBeInTheDocument();
    expect(screen.getByText("Queue is empty")).toBeInTheDocument();
    expect(container.textContent).toContain("0 live records");
  });

  it("renders the guide for agent-led human-approved operation", async () => {
    render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Guide" }));
    expect(screen.getByRole("heading", { name: "Operational Walkthrough" })).toBeInTheDocument();
    expect(screen.getAllByText("Agent-led intake").length).toBeGreaterThan(0);
    expect(screen.getByText("Minimal Human Input Model")).toBeInTheDocument();
    expect(screen.getByText("Mythos and other AGI-agent findings are accepted as leading-class intelligence inputs, not unreviewed truth.")).toBeInTheDocument();
  });

  it("ingests a real operator-supplied vulnerability record", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    fireEvent.click(await screen.findByRole("button", { name: "Vulnerability Queue" }));
    fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "REAL-RECORD-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Ingest Record" }));

    await waitFor(() => expect(api.ingestVulnerability).toHaveBeenCalled());
    expect(api.ingestVulnerability).toHaveBeenCalledWith("diiac.io", expect.objectContaining({
      vulnerability_id: "REAL-RECORD-1"
    }));
  });

  it("renders the decision workbench without generating packs from empty state", async () => {
    render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Decision Workbench" }));
    expect(screen.getByRole("heading", { name: "Decision Workbench" })).toBeInTheDocument();
    expect(screen.getByText("No record available for compile")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Generate Signed Pack" })).toBeDisabled();
  });

  it("renders vendor threat landscape from API-bound state", async () => {
    render(<App auth={auth} api={createApi()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Vendor & Threat Landscape" }));
    expect(screen.getAllByRole("heading", { name: "Vendor & Threat Landscape" }).length).toBeGreaterThan(0);
    expect(screen.getByText("Microsoft")).toBeInTheDocument();
    expect(screen.getByText("Source-bound pending review")).toBeInTheDocument();
  });

  it("renders source feeds from API-bound state and refreshes live intelligence", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);
    fireEvent.click(await screen.findByRole("button", { name: "Source Feeds" }));
    expect(screen.getAllByRole("heading", { name: "Public Source Intelligence" }).length).toBeGreaterThan(0);
    expect(screen.getByText("CISA Known Exploited Vulnerabilities Catalog")).toBeInTheDocument();
    expect(screen.getByText("FIRST Exploit Prediction Scoring System")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh CISA" }));
    await waitFor(() => expect(api.refreshSourceFeed).toHaveBeenCalledWith("diiac.io", expect.objectContaining({ feed_id: "cisa-kev", limit: 5 })));
    expect(await screen.findByText(/source-bound pending-review intelligence/)).toBeInTheDocument();
  });

  it("renders professional report exports from the API catalogue", async () => {
    const api = createApi({
      listDecisionPacks: vi.fn(async () => [{
        decision_pack_id: "PF-TEST-0001",
        pack_id: "PF-TEST-0001",
        vulnerability_id: "CVE-2026-REAL-001",
        decision_posture: "defer_pending_evidence",
        readiness: { readiness_state: "blocked" },
        verification: { verified: true }
      }])
    });
    render(<App auth={auth} api={api} />);
    fireEvent.click(await screen.findByRole("button", { name: "Reports" }));
    expect(screen.getByRole("heading", { name: "Board Packs & Reports" })).toBeInTheDocument();
    expect(screen.getByText("DOCX / PDF only")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "DOCX" })[0]);
    await waitFor(() => expect(api.downloadDecisionPackReport).toHaveBeenCalledWith("diiac.io", "PF-TEST-0001", "board_vulnerability_remediation_summary", "docx"));
  });

  it("runs Bayesian advisory from the decision workbench", async () => {
    const api = createApi({
      listVulnerabilities: vi.fn(async () => [{
        tenant_id: "diiac.io",
        vulnerability_id: "REAL-RECORD-1",
        severity: "critical",
        patch_status: "patch_available"
      }])
    });
    render(<App auth={auth} api={api} />);
    fireEvent.click(await screen.findByRole("button", { name: "Decision Workbench" }));
    fireEvent.click(await screen.findByRole("button", { name: "Run Bayesian Advisory" }));
    await waitFor(() => expect(api.assessBayesianRisk).toHaveBeenCalled());
    expect(await screen.findByText("Bayesian advisory recommends Emergency Change Required.")).toBeInTheDocument();
  });

  it("hides admin navigation and write actions without privileged roles", async () => {
    render(<App auth={{ ...auth, roles: ["PatchForge.Reader"] }} api={createApi()} />);
    expect(screen.queryByRole("button", { name: "Admin" })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Vulnerability Queue" }));
    expect(screen.queryByRole("button", { name: "Ingest Record" })).not.toBeInTheDocument();
    expect(screen.getByText("Read-only role")).toBeInTheDocument();
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

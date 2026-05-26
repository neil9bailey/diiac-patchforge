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
});

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("PatchForge shell", () => {
  it("renders the command center by default", () => {
    render(<App />);
    expect(screen.getByText("DIIaC™")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Command Center" })).toBeInTheDocument();
    expect(screen.getByText("Critical exposure")).toBeInTheDocument();
    expect(screen.getByText("Known exploited")).toBeInTheDocument();
    expect(screen.getByText("Signed packs")).toBeInTheDocument();
  });

  it("navigates to the vulnerability queue", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Vulnerability Queue" }));
    expect(screen.getByRole("heading", { name: "Vulnerability Queue" })).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-10421")).toBeInTheDocument();
    expect(screen.getByText("Emergency change required")).toBeInTheDocument();
  });

  it("renders the decision workbench", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Decision Workbench" }));
    expect(screen.getByRole("heading", { name: "Decision Workbench" })).toBeInTheDocument();
    expect(screen.getByText("Patch required")).toBeInTheDocument();
    expect(screen.getByText("Risk accept temporarily")).toBeInTheDocument();
  });

  it("renders the admin route", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Admin" }));
    expect(screen.getByRole("heading", { name: "Admin" })).toBeInTheDocument();
    expect(screen.getByText("Entra ID / RBAC")).toBeInTheDocument();
    expect(screen.getByText("Signing & Trust")).toBeInTheDocument();
  });

  it("labels SRA as advisory only and avoids prohibited wording", () => {
    const { container } = render(<App />);
    expect(screen.getByText(/SRA advisory only/i)).toBeInTheDocument();
    expect(container.textContent?.toLowerCase()).not.toContain("autonomous patching");
    expect(container.textContent?.toLowerCase()).not.toContain("exploit generation");
  });
});


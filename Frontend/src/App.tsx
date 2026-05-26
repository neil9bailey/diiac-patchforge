import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Archive,
  BadgeCheck,
  Bell,
  Binary,
  Blocks,
  BookOpenCheck,
  CheckCircle2,
  ClipboardCheck,
  Clock3,
  Database,
  FileCheck2,
  Gauge,
  KeyRound,
  Layers3,
  ListFilter,
  LockKeyhole,
  Network,
  PanelLeft,
  Radar,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
  Wrench
} from "lucide-react";

type PageKey =
  | "Command Center"
  | "Vulnerability Queue"
  | "Asset & Service Exposure"
  | "Decision Workbench"
  | "Emergency Patch"
  | "Risk Acceptances"
  | "Compensating Controls"
  | "SRA Research"
  | "Evidence Catalogue"
  | "Decision Packs"
  | "Admin";

type NavItem = {
  label: PageKey;
  icon: typeof Gauge;
};

const navItems: NavItem[] = [
  { label: "Command Center", icon: Gauge },
  { label: "Vulnerability Queue", icon: ListFilter },
  { label: "Asset & Service Exposure", icon: Network },
  { label: "Decision Workbench", icon: ClipboardCheck },
  { label: "Emergency Patch", icon: ShieldAlert },
  { label: "Risk Acceptances", icon: Clock3 },
  { label: "Compensating Controls", icon: Blocks },
  { label: "SRA Research", icon: Radar },
  { label: "Evidence Catalogue", icon: Archive },
  { label: "Decision Packs", icon: FileCheck2 },
  { label: "Admin", icon: SlidersHorizontal }
];

const vulnerabilities = [
  {
    id: "CVE-2026-10421",
    severity: "Critical",
    exploited: "Known exploited",
    exposure: "External-facing",
    service: "Orion Gateway",
    patch: "Patch available",
    state: "Emergency change required",
    owner: "Security Lead",
    age: "4h",
    sla: "T-20h"
  },
  {
    id: "CVE-2026-08214",
    severity: "High",
    exploited: "Elevated likelihood",
    exposure: "Customer-facing",
    service: "Billing API",
    patch: "Patch feasible",
    state: "Patch required",
    owner: "Service Owner",
    age: "2d",
    sla: "T-3d"
  },
  {
    id: "OT-ADV-2026-017",
    severity: "High",
    exploited: "No active signal",
    exposure: "OT site",
    service: "Line Control",
    patch: "Window constrained",
    state: "Mitigate temporarily",
    owner: "OT Governance",
    age: "6d",
    sla: "T-1d"
  }
];

const metrics = [
  { label: "Critical exposure", value: "14", tone: "danger", icon: TriangleAlert },
  { label: "Known exploited", value: "6", tone: "amber", icon: ShieldAlert },
  { label: "Patch overdue", value: "9", tone: "warning", icon: Clock3 },
  { label: "Expiring acceptances", value: "3", tone: "steel", icon: Bell },
  { label: "Signed packs", value: "41", tone: "trust", icon: FileCheck2 },
  { label: "SRA queue", value: "8", tone: "teal", icon: Radar }
];

const adminSections = [
  "General Settings",
  "Tenant Configuration",
  "Entra ID / RBAC",
  "SRA Configuration",
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

export default function App() {
  const [activePage, setActivePage] = useState<PageKey>("Command Center");
  const pageTitle = useMemo(() => activePage, [activePage]);

  return (
    <main className="app-shell">
      <aside className="side-nav" aria-label="PatchForge navigation">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Binary size={24} aria-hidden />
          </div>
          <div>
            <p>DIIaC™</p>
            <h1>PatchForge</h1>
          </div>
        </div>

        <nav>
          {navItems.map(({ label, icon: Icon }) => (
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

        <div className="boundary-panel">
          <LockKeyhole size={18} aria-hidden />
          <p>Governance layer only. No scanning, no exploit content, no patch deployment.</p>
        </div>
      </aside>

      <section className="workspace">
        <header className="top-rail">
          <button className="icon-button" aria-label="Toggle navigation" type="button">
            <PanelLeft size={18} aria-hidden />
          </button>
          <div>
            <p className="eyebrow">Production | diiac.io | Enterprise Strict</p>
            <h2>{pageTitle}</h2>
          </div>
          <div className="status-strip" aria-label="Runtime trust status">
            <span><BadgeCheck size={16} aria-hidden /> Trust verified</span>
            <span><Radar size={16} aria-hidden /> SRA advisory only</span>
            <span><FileCheck2 size={16} aria-hidden /> Signing ready</span>
          </div>
        </header>

        <div className="content-grid">
          <section className="primary-panel" aria-label={pageTitle}>
            {activePage === "Command Center" && <CommandCenter />}
            {activePage === "Vulnerability Queue" && <VulnerabilityQueue />}
            {activePage === "Asset & Service Exposure" && <AssetExposure />}
            {activePage === "Decision Workbench" && <DecisionWorkbench />}
            {activePage === "Emergency Patch" && <EmergencyPatch />}
            {activePage === "Risk Acceptances" && <RiskAcceptances />}
            {activePage === "Compensating Controls" && <CompensatingControls />}
            {activePage === "SRA Research" && <SraResearch />}
            {activePage === "Evidence Catalogue" && <EvidenceCatalogue />}
            {activePage === "Decision Packs" && <DecisionPacks />}
            {activePage === "Admin" && <Admin />}
          </section>

          <aside className="utility-rail" aria-label="PatchForge utility rail">
            <UtilityRail />
          </aside>
        </div>
      </section>
    </main>
  );
}

function CommandCenter() {
  return (
    <>
      <div className="metric-grid">
        {metrics.map(({ label, value, tone, icon: Icon }) => (
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
          <button type="button" className="action-button"><ClipboardCheck size={16} aria-hidden /> Create Patch Decision</button>
        </div>
        <ol className="action-list">
          <li><strong>Emergency patch required:</strong> Orion Gateway CVE-2026-10421, rollback evidence pending.</li>
          <li><strong>OT controller patch deferred:</strong> risk acceptance expires in 7 days.</li>
          <li><strong>Customer-facing API:</strong> compensating controls pending review.</li>
        </ol>
      </section>

      <div className="split-grid">
        <section className="data-band">
          <h3>Exposure by Service</h3>
          <StatusLine label="Customer Portal" value="High" tone="warning" />
          <StatusLine label="Identity Gateway" value="Critical" tone="danger" />
          <StatusLine label="OT Line Control" value="High" tone="warning" />
          <StatusLine label="Billing API" value="Medium" tone="steel" />
        </section>
        <section className="data-band">
          <h3>Decision State</h3>
          <StatusLine label="Patch required" value="12" tone="trust" />
          <StatusLine label="Mitigate temporarily" value="5" tone="teal" />
          <StatusLine label="Risk accepted" value="4" tone="amber" />
          <StatusLine label="Closed verified" value="21" tone="steel" />
        </section>
      </div>
    </>
  );
}

function VulnerabilityQueue() {
  return (
    <>
      <div className="section-title">
        <h3>Governed Vulnerability Queue</h3>
        <div className="toolbar">
          <button type="button" className="icon-button" aria-label="Filter queue"><ListFilter size={18} aria-hidden /></button>
          <button type="button" className="action-button"><ClipboardCheck size={16} aria-hidden /> Govern Decision</button>
        </div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Vulnerability</th>
              <th>Severity</th>
              <th>Exploitability</th>
              <th>Exposure</th>
              <th>Service</th>
              <th>Patch</th>
              <th>State</th>
              <th>Owner</th>
              <th>SLA</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map((item) => (
              <tr key={item.id}>
                <td>{item.id}</td>
                <td><span className="pill danger">{item.severity}</span></td>
                <td>{item.exploited}</td>
                <td>{item.exposure}</td>
                <td>{item.service}</td>
                <td>{item.patch}</td>
                <td>{item.state}</td>
                <td>{item.owner}</td>
                <td>{item.sla}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function AssetExposure() {
  return <PageBand icon={Layers3} title="Asset & Service Exposure" lines={["Customer-facing service mapping", "Affected asset scope review", "Business service impact evidence"]} />;
}

function DecisionWorkbench() {
  return (
    <div className="decision-grid">
      {["Patch required", "Emergency change required", "Mitigate temporarily", "Risk accept temporarily", "Defer pending evidence", "Block go-live", "Patch not applicable", "Close verified"].map((label) => (
        <button className="decision-tile" key={label} type="button">
          <ClipboardCheck size={18} aria-hidden />
          <span>{label}</span>
        </button>
      ))}
    </div>
  );
}

function EmergencyPatch() {
  return <PageBand icon={ShieldAlert} title="Emergency Patch" lines={["Fast path enabled", "Governance gates remain active", "Human approvals and rollback evidence required"]} />;
}

function RiskAcceptances() {
  return <PageBand icon={Clock3} title="Risk Acceptances" lines={["3 acceptances expire within 7 days", "Owner, rationale, expiry and controls required", "Expired acceptance affects internet-facing service"]} />;
}

function CompensatingControls() {
  return <PageBand icon={Wrench} title="Compensating Controls" lines={["Network segmentation", "Identity restrictions", "Monitoring and operational controls"]} />;
}

function SraResearch() {
  return <PageBand icon={Radar} title="SRA Research" lines={["Research queue", "Source map", "Findings pending review", "Advisory output cannot close gates alone"]} />;
}

function EvidenceCatalogue() {
  return <PageBand icon={BookOpenCheck} title="Evidence Catalogue" lines={["Scanner output source-bound", "Vendor advisory attached", "Human review accepted positive evidence"]} />;
}

function DecisionPacks() {
  return <PageBand icon={FileCheck2} title="Decision Packs" lines={["PF-2026-00041 verified", "PF-2026-00040 verified", "Replay certificates available"]} />;
}

function Admin() {
  return (
    <>
      <div className="section-title">
        <h3>Admin Control Surfaces</h3>
        <span className="pill trust">Read-only Azure phase</span>
      </div>
      <div className="admin-grid">
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

function UtilityRail() {
  return (
    <>
      <section className="rail-section">
        <h3>SRA Health</h3>
        <StatusLine label="Mode" value="Advisory" tone="teal" />
        <StatusLine label="Queue" value="8" tone="steel" />
      </section>
      <section className="rail-section">
        <h3>Signing Trust</h3>
        <StatusLine label="Pack verifier" value="Ready" tone="trust" />
        <StatusLine label="Source pack" value="Immutable" tone="steel" />
      </section>
      <section className="rail-section">
        <h3>Admin Warnings</h3>
        <StatusLine label="Azure" value="No live mutation" tone="amber" />
        <StatusLine label="DNS" value="Pending" tone="steel" />
      </section>
      <section className="rail-section">
        <h3>Recent Packs</h3>
        <p className="rail-note"><CheckCircle2 size={15} aria-hidden /> PF-2026-00041 verified</p>
        <p className="rail-note"><CheckCircle2 size={15} aria-hidden /> PF-2026-00040 verified</p>
      </section>
    </>
  );
}

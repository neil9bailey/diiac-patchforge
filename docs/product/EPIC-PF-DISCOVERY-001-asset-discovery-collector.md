# EPIC-PF-DISCOVERY-001: Asset Discovery Collector

## Objective

Add a governed PatchForge Asset Discovery & Collector capability so customers can securely import categorized asset evidence from their environments into PatchForge Core.

PatchForge remains advisory and governance-only. The collector is an asset-evidence intake component, not a vulnerability scanner, exploit tool, deployment agent, or autonomous approval path.

## User Outcomes

- Users can register customer-side collectors.
- Users can define discovery policies by asset category.
- Users can run a Windows/Linux PatchForge collector that imports discovered asset snapshots into PatchForge.
- Imported assets appear in the existing customer estate and VendorLens workflows.
- CVE/advisory applicability checks can use reviewed collector-imported assets.
- Reports and decision packs can include collector provenance once reviewed.

## MVP Scope

- Collector registry in PatchForge Core.
- Discovery policy registry.
- Runnable Windows/Linux collector CLI.
- Collector local JSON configuration with environment-backed token reference.
- Day-1 adapters for local host inventory, Hyper-V inventory where available, Azure CLI read-only inventory where configured, and HTTP JSON CMDB/NMS pull where configured.
- Collector import run ledger.
- Normalisation into `customer_network_assets`.
- UI visibility and collector configuration export in the Customer Estate flow.
- Tests for safe import, categorisation, dedupe/upsert, tenant scoping, and advisory boundary.

## Future Increments

1. Signed Windows collector package.
2. Signed Linux collector package.
3. SNMPv3 read-only network device discovery with secure credential handling.
4. SSH read-only network/firewall discovery with secure credential handling.
5. Windows Server inventory via WMI/WinRM.
6. Linux inventory via SSH.
7. VMware vCenter and ESXi inventory.
8. Cloud connectors for AWS/GCP read-only inventory.
9. Customer vault integration for credential references.
10. Collector auto-update and package signature verification.
11. Collector health, heartbeat, and stale-asset alerts.

## Success Criteria

- Imported assets are source-bound and pending review by default.
- No raw credentials are accepted or stored.
- Collector configuration must reference tokens/secrets through environment variable names or external vault references, not literal values.
- No exploit, patch deployment, or production mutation capability is introduced.
- Asset category, source method, collector ID, policy ID, run ID, and import timestamp are preserved.
- PatchForge can show which CVEs/advisories have candidate customer asset matches once the asset catalogue is populated.

## Value

The collector reduces manual asset gathering and lowers the time to answer: "Does this advisory affect our estate?"

Expected savings:

- Less spreadsheet and CMDB reconciliation.
- Faster CVE triage.
- Better evidence for CAB, board, customer, and audit reports.
- Fewer irrelevant CVEs sent to engineering teams.
- Stronger asset/version/feature evidence for Patch Compare and VendorLens.

## Non-Goals

- Vulnerability exploitation.
- Active intrusive vulnerability scanning.
- Patch deployment.
- Configuration mutation.
- Autonomous CAB approval.
- Autonomous risk acceptance.
- Automatic not-vulnerable or closure decisions.

# ADR-PF-DISCOVERY-001: Agent Collector and Asset Discovery Intake

Status: Approved

Date: 2026-06-11

Epic: EPIC-PF-DISCOVERY-001-asset-discovery-collector

## Context

PatchForge currently works best when users provide or import customer asset evidence. This limits the speed and reliability of CVE/advisory applicability checks because asset inventory, firmware/version, feature state, and exposure context are often incomplete.

The requested addition is a governed customer-side discovery collector that can run on Windows or Linux, discover categorized assets, and securely import those asset facts into PatchForge Core running in Azure.

This changes the architecture boundary. PatchForge remains governance/advisory software, but it gains a controlled asset-discovery intake path. The collector must not become an exploit scanner, intrusive vulnerability scanner, patch deployment agent, or autonomous approval mechanism.

## Decision

PatchForge will add an Asset Discovery & Collector capability with these baseline components:

1. PatchForge Core collector registry and policy APIs.
2. Collector import API for categorized asset snapshots.
3. Asset staging into the existing `customer_network_assets` model as source-bound, pending-review evidence.
4. Collector records, policies, and import runs stored as first-class audit objects.
5. A day-1 Windows collector distributed as a customer-installable EXE, with the existing Node CLI kept as the source implementation and Linux packaging deferred.

The first implementation increment is the governed intake foundation plus a working collector path:

- Register/list collectors.
- Register/list discovery policies by asset category.
- Run a Windows collector EXE using a generated local JSON configuration and environment-backed bearer token.
- Provide PowerShell configuration and installation scripts that create the config from PatchForge Azure endpoint defaults, collector/site details, and selected adapters instead of requiring users to hand-author JSON.
- Keep the source Node CLI runnable for development and tests, but make the supported customer-side packaging path Windows EXE first.
- Discover assets from local host inventory, Hyper-V where available, Azure CLI read-only inventory where configured, and HTTP JSON CMDB/NMS sources where configured.
- Import collector asset snapshots into PatchForge automatically from the collector; the UI must not depend on a manual/sample import path.
- Normalize imported assets into `customer_network_assets`.
- Mark imported assets `pending_review` and `collector_imported_unreviewed`.
- Preserve category, collector, policy, method, timestamp, lineage, and advisory boundary.
- Expose the capability in the UI as collector readiness, policy, configuration, and run-status evidence.

## Active Asset Categories

- `network_device`
- `security_appliance`
- `physical_server`
- `virtual_server`
- `hypervisor`
- `cloud_resource`
- `endpoint`
- `storage`
- `application_platform`
- `unknown`

## Security Boundary

Collectors are outbound-only and customer-controlled. PatchForge Core must not expose an inbound customer-network control channel.

Collector imports are evidence inputs only. They cannot:

- scan for vulnerabilities using exploit checks
- run payloads
- deploy patches
- mutate production systems
- approve CAB decisions
- accept risk
- close evidence gates
- mark an asset not vulnerable without reviewed evidence

Secrets must not be imported. Credential references are allowed; raw credentials are not.

## Acceptance Criteria

- Backend exposes governed collector list/register, policy list/upsert, and import endpoints.
- A Windows collector EXE can register/update itself, create/update a read-only policy, collect supported asset categories, and push the resulting run into PatchForge Core.
- PowerShell helper scripts can build the EXE package, generate a customer config, test-run the collector, and install it as a scheduled task.
- Collector imports create a run ledger and source-bound customer network assets.
- Imported assets are review-required and cannot close gates automatically.
- Tests prove imports are categorized, deduplicated/upserted, and secret-safe.
- UI shows collector status, supported categories, configuration export, and recent import results.
- Documentation describes the epic, phases, expected value, and non-goals.

## Consequences

PatchForge can move from purely user-entered inventory toward continuously refreshed customer asset evidence. Applicability checks become faster and more credible once collector imports are reviewed.

The tradeoff is increased security responsibility: collector identity, package signing, credential handling, tenant isolation, EXE packaging provenance, and audit evidence must be treated as high-risk product areas.

## Verification Expectations

- Backend API tests for collector registration, policy, import, asset staging, and boundary flags.
- Collector tests for config validation, adapter normalization, dry-run output, and API push behavior against a real local HTTP server.
- Windows packaging tests or script syntax checks for EXE build, config generation, and scheduled-task installation helpers.
- Frontend tests for collector visibility and configuration action states.
- Security review for tenant isolation, raw-secret rejection, outbound-only boundary, and no autonomous decision behavior.
- Live UAT with a signed-in user registering a collector, downloading configuration, running the collector, and seeing imported assets in Customer Estate before release acceptance.

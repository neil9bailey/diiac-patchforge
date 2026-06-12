# PatchForge Intelligence by DIIaC™ - Rebuild Blueprint

## Document control

| Field | Value |
| --- | --- |
| Product | PatchForge Intelligence by DIIaC™ |
| Document | Rebuild Blueprint |
| Status | Canonical implementation blueprint |
| Audience | Engineering, Codex, Product, Security, Enterprise Architecture |
| Local repo | `F:\code\diiac\patchforge` |
| Protected repo boundary | Do not modify `F:\code\diiac\Pharma\diiac_v1.8.0_pharma_ui` |
| Primary principle | Catalogue first, estate second, exposure matching third, patch intelligence fourth, user-driven reports last |

## Product thesis

PatchForge Intelligence by DIIaC™ is a governed vulnerability, exploit-signal, patch, hotfix, and customer operational asset intelligence platform for IT service providers, MSPs, enterprise security teams, and CISOs.

PatchForge turns fragmented CVE, vendor advisory, exploit-signal, patch, hotfix, workaround, configuration, and customer asset evidence into searchable intelligence, estate-specific exposure mapping, patch/hotfix comparison, and signed action packs.

Core positioning:

> From CVE noise to governed security action.

Core user question:

> What is vulnerable in my estate, is it being exploited, which patch or hotfix should I trust, what should I do first, and how do I prove the decision?

## Rebuild reason

PatchForge must stop behaving as a report-first product. Reports are only credible after the catalogue, source records, customer operational assets, exposure matching, patch comparison, and evidence model are trustworthy.

The current failure mode to eliminate is:

```text
Prompt -> random report -> weak value -> confusing blocked output
```

The rebuild returns PatchForge to the drawing board as a catalogue-first, operational-asset-aware intelligence product.

## Architecture principle

PatchForge is built around a deterministic operating sequence:

```text
Source-bound catalogue -> customer operational assets -> exposure matching -> patch/hotfix intelligence -> Ask PatchForge -> user-scoped reports -> signed action packs
```

The product must keep internal implementation details out of the main user journey. Raw JSON, schema IDs, internal execution IDs, Bayesian internals, policy rigour selectors, internal governance modes, low-level diagnostics, dead admin links, and DB/cache/prior controls belong only in Admin or advanced diagnostic surfaces.

The product must keep visible the information that drives operational action: critical vulnerabilities, active exploitation, affected assets, patch status, CISA KEV status, EPSS score, CVSS, vendor advisory status, evidence confidence, unresolved evidence gaps, CISO review required, customer exposure, and signed pack verification status.

## Navigation model

The main user navigation is:

1. Security Action Center
2. Vendors & Exploits Register
3. Customer Operational Assets
4. Patch / Hotfix Compare
5. Ask PatchForge
6. Reports
7. Admin

The Security Action Center is the landing page and answers: what needs action today?

The Security Action Center shows:

- Critical Exploitable
- KEV Matched
- Patch Available
- No Patch / Workaround
- Affected Assets
- Emergency Change Required
- Overdue Remediation
- CISO Review Required
- Source Refresh Health
- Evidence Gaps

Core landing sections:

- What changed today
- Top exploited vulnerabilities
- Customer operational exposure
- Patch action queue
- Exceptions requiring review
- Recent reports
- Ask PatchForge panel

## Data model

Required domain objects:

- Source Record: `source_id`, `source_name`, `source_type`, `source_url`, `fetched_at`, `source_hash`, `freshness`, `confidence`, `review_status`
- Vendor: `vendor_id`, `canonical_name`, `aliases`, `product_families`, `advisory_urls`, `psirt_url`, `support_url`, `trust_level`
- Product: `product_id`, `vendor_id`, `product_name`, `aliases`, `cpe_names`, `platform_type`, `version_scheme`, `support_status`
- CVE: `cve_id`, `description`, `published`, `last_modified`, `cvss_v3`, `cvss_v4`, `cwe`, `cpe_matches`, `references`, `nvd_status`, `kev_status`, `epss_score`, `epss_percentile`, `exploit_signals`
- Exploit Signal: `signal_id`, `cve_id`, `source`, `signal_type`, `confidence`, `observed_date`, `ransomware_known`, `active_exploitation`, `reference_url`
- Vendor Advisory: `advisory_id`, `vendor_id`, `product_ids`, `cve_ids`, `affected_versions`, `fixed_versions`, `workarounds`, `patch_links`, `known_issues`, `release_date`, `last_updated`, `evidence_hash`
- Customer: `customer_id`, `name`, `tenant`, `service_tier`, `reporting_contact`, `data_boundary`
- Customer Operational Asset: `asset_id`, `customer_id`, `hostname`, `vendor`, `product`, `model`, `firmware`, `software_version`, `serial_hash`, `role`, `location`, `internet_exposed`, `business_criticality`, `owner`, `source`, `source_confidence`
- Config Evidence: `asset_id`, `config_source`, `raw_upload_hash`, `redacted_config`, `parsed_facts`, `secret_redaction_status`, `parser_confidence`
- Exposure Match: `asset_id`, `cve_id`, `match_confidence`, `match_reason`, `affected_version`, `fixed_version`, `evidence_refs`, `exposure_status`
- Patch Action: `action_id`, `asset_id`, `cve_id`, `recommended_action`, `priority`, `patch_option`, `rollback_required`, `change_window`, `owner`, `due_date`, `approval_required`, `status`

## Intelligence sources

Minimum source adapters:

- NVD CVE API
- CISA KEV
- FIRST EPSS
- GitHub Advisory Database
- CVE Program / CVE Services metadata
- Vendor advisory fixture adapter

Vendor advisory support by adapter or fixture model:

- Microsoft MSRC
- Cisco PSIRT
- Fortinet PSIRT
- Palo Alto advisories
- Juniper advisories
- VMware/Broadcom advisories
- Ivanti advisories
- Citrix advisories
- Linux distribution advisories
- Apple security updates
- CISA alerts
- NCSC advisories

Every source record includes `source`, `source_url`, `fetched_at`, `source_hash`, `freshness`, `confidence`, and `review_status`.

Restricted scraping, paywall bypass, and unauthorised sources are not allowed.

## Vendors & Exploits Register

The Vendors & Exploits Register is the core intelligence catalogue. It contains vendors, products, product families, CVEs, exploit signals, CISA KEV entries, EPSS records, CVSS data, vendor advisories, affected versions, fixed versions, patches, hotfixes, workarounds, known patch issues, evidence confidence, and last refreshed timestamp.

Users can search by CVE, vendor, and product, and filter by KEV, EPSS threshold, CVSS, exploited status, ransomware signal, patch available, no fix, workaround only, affected customer assets, and internet exposure.

The CVE detail page shows plain-English explanation, affected vendors/products, affected versions, fixed versions, CVSS, EPSS, KEV status, exploit status, known exploit signal summary, patch/hotfix availability, workarounds, known patch risks, customer operational asset matches, evidence sources, source confidence, last refreshed, and recommended next action posture.

CVE detail pages must not show exploit code or attack instructions.

## Customer Operational Assets

Customer Estate is renamed to Customer Operational Assets.

This section manages the customer's actual operational devices, software, services, and configurations.

Asset onboarding methods:

- Manual entry
- Device config upload
- CLI/log paste
- Scanner CSV import
- CMDB CSV import
- Cloud asset export where supported

Manual asset fields:

- customer
- hostname
- vendor
- product
- model
- firmware/software version
- serial/hash
- role
- location/site
- business criticality
- internet exposure
- owner
- service provided
- maintenance window
- support status
- source confidence

Users must be able to upload or paste device/config/CLI data. Initial parsers include generic key/value, Cisco, Fortinet, Palo Alto, Juniper, Windows basic inventory, Linux package/version list, and VMware basic parser.

Parser outputs include vendor, product, model, version, firmware, hostname, interfaces, management exposure, VPN features, enabled services, HA mode, routing/security features, internet-facing indicators, package/application versions, parser confidence, and proposed asset record.

## Secret redaction

Config upload must include secret detection and redaction.

PatchForge detects and redacts passwords, enable secrets, SNMP communities, API keys, tokens, private keys, pre-shared keys, VPN secrets, LDAP bind passwords, RADIUS secrets, TACACS secrets, and certificate private material.

PatchForge never stores raw secrets. It stores only `raw_upload_hash`, `redacted_config`, `parsed_facts`, `secret_redaction_status`, `parser_confidence`, and `proposed_asset_record`.

## Exposure matching

Once assets exist, PatchForge dynamically matches them against the vulnerability catalogue.

Match methods:

- CPE
- vendor alias
- product alias
- version range
- firmware version
- package version
- scanner finding
- config fingerprint
- manual confirmation

Exposure output:

- affected: yes / no / unknown / needs_review
- match confidence
- match reason
- affected version
- fixed version
- patch available
- workaround available
- evidence refs
- unresolved gaps

No customer asset match means no customer exposure claim.

## Patch / Hotfix Compare

PatchForge models remediation options: patch available, hotfix available, fixed version, workaround, mitigation only, no fix, superseded patch, withdrawn patch, known patch issues, reboot required, service impact, rollback complexity, vendor advisory confidence, and test evidence required.

Users select vendor, product, CVE, affected assets, current version, and candidate patch/hotfix/upgrade.

PatchForge compares current version, fixed version, direct patch, hotfix, major version upgrade, workaround, compensating controls, and defer/exception.

The comparison explains what changes, vulnerability addressed, expected service impact, reboot requirement, config changes, rollback complexity, known patch issues, compatibility concerns, change-window suitability, test evidence required, confidence level, and evidence gaps.

Output postures:

- Current governed remediation candidate
- Emergency action recommended
- Priority patch candidate
- Scheduled remediation
- Mitigate and monitor
- Exception review required
- Insufficient evidence

PatchForge must not output approved, deploy now, risk accepted, or change authorised unless a human approval workflow explicitly records that decision.

## Ask PatchForge

Ask PatchForge is the main intelligence interface.

Users can paste config, CLI output, logs, scanner output, asset export snippets, CVE questions, and patch comparison requests.

Ask PatchForge must parse user input, detect device facts, propose asset catalogue entries, ask clarifying questions, map CVEs to assets, explain patch options, cite sources, show confidence, show gaps, generate report scopes, and require user acceptance for catalogue changes.

Ask PatchForge must not provide exploit steps, provide payloads, approve production changes, accept risk, silently modify catalogue, or silently close evidence gaps.

## Reports

Reports must be user-driven. Users choose report type, customer, vendor, product, CVE set, asset group, severity, KEV only, EPSS threshold, patch status, time period, and audience.

Active report types:

- Customer Patch Governance Pack
- Board Vulnerability Summary
- CAB Patch Decision Report
- Technical Evidence Appendix

Future stakeholder, monthly, vendor, exception, or remediation-progress reports require their own scoped template, audience-specific sections, and verification coverage before being added to the active catalogue.

Every report includes user-selected scope, evidence sources, affected assets, relevant CVEs, patch options, confidence levels, risks, evidence gaps, recommended next actions, human approval requirements, and signed/verifiable export.

Random report generation is not allowed.

Signed action packs use the DIIaC governance core and include report, selected scope, source evidence, CVE records, vendor advisories, asset matches, patch compare, confidence, evidence gaps, human approval state, verification manifest, and replay/verifier metadata where available.

## Admin redesign

Admin becomes System & Data Health.

The Admin dashboard shows source ingestion status, CVE count, vendor count, product count, advisory count, exploit signal count, KEV count, EPSS refresh status, customer asset count, config uploads, parser failures, evidence gaps, report count, signed pack count, storage usage, last refresh, failed jobs, and search index status.

Admin actions:

- purge generated reports
- purge uploaded configs
- purge customer assets
- purge vulnerability catalogue
- purge logs
- purge cache
- rebuild CVE catalogue
- re-index search
- clear failed jobs

All destructive actions require typed confirmation:

- `DELETE REPORTS`
- `DELETE ASSETS`
- `DELETE CATALOGUE`
- `FACTORY RESET PATCHFORGE`

No dead links or non-functional admin controls are allowed.

## Purge strategy

Implement `scripts/patchforge_factory_reset.py`.

Options:

- `--reports`
- `--catalogue`
- `--assets`
- `--uploads`
- `--logs`
- `--cache`
- `--all`
- `--dry-run`
- `--confirm FACTORY_RESET_PATCHFORGE`

Purge generated reports, bad demo records, old vulnerability mock records, old uploads, old report jobs, stale catalogues, cache, and logs if selected.

Preserve Git history, restore branch/tag, signing/verifier/replay core, auth/RBAC, Azure deployment scripts, test harnesses, deployment evidence, and documentation of purge event.

## PatchForge Priority Index

Create deterministic priority scoring based on confirmed asset match, CISA KEV, EPSS probability, EPSS percentile, CVSS, exploit signal, active exploitation, ransomware association, internet exposure, asset criticality, patch availability, patch maturity, workaround availability, operational risk, SLA pressure, compensating controls, and evidence confidence.

Priority output postures:

- Emergency action recommended
- Priority patch candidate
- Scheduled remediation
- Mitigate and monitor
- Exception review required
- Insufficient evidence

The score must be explained in human-readable language.

## Defensive-use boundary

PatchForge is advisory, defensive, source-bound, and human-accountable.

PatchForge must not add vulnerability scanning, exploit generation, exploit code, payloads, procedural exploit steps, bypass instructions, patch deployment, production mutation, autonomous CAB approval, autonomous risk acceptance, or autonomous evidence-gate closure.

PatchForge must not claim a device is safe, not vulnerable, accepted, approved, closed, or remediated without reviewed evidence and named human approval.

## Epics

PF0 - Repo, Azure, restore point, and blueprint:

- confirm repo path
- confirm git remote
- confirm branch/commit
- inspect Azure config
- create restore point
- create this blueprint file
- add README/docs links
- create blueprint validation script

PF1 - Product shell and navigation:

- implement simplified product shell
- remove/hide legacy clutter
- create new nav
- make Security Action Center landing page

PF2 - Factory reset and purge:

- implement reset script
- add admin purge controls
- add dry-run and typed confirmations
- purge bad demo/generated data

PF3 - Vulnerability source ingestion:

- implement source adapters/fixtures
- normalise NVD/KEV/EPSS/GitHub/vendor advisory data
- persist source records with hashes/freshness

PF4 - Vendors & Exploits Register:

- implement search
- implement filters
- implement CVE/vendor/product/advisory detail pages

PF5 - Customer Operational Assets:

- implement asset catalogue
- manual add
- config upload
- CLI/log paste
- asset detail pages

PF6 - Config parsers and redaction:

- implement parsers
- implement secret redaction
- produce proposed asset records

PF7 - Exposure matching:

- implement asset-to-CVE matching
- confidence and match reasons
- unresolved gaps

PF8 - Patch and hotfix intelligence:

- model patch/hotfix/workaround/no-fix states
- ingest advisory patch details

PF9 - Patch / Hotfix Compare:

- compare remediation options
- produce governed remediation candidate
- explain impact and confidence

PF10 - Ask PatchForge:

- chat interface
- parse pasted data
- propose asset updates
- answer CVE/patch questions defensively
- require user acceptance

PF11 - User-driven report builder:

- scoped report generation
- CISO, ops, customer, vendor, emergency, monthly reports
- no random reports

PF12 - Signed action packs:

- signed/verifiable pack for reports
- include scope, evidence, matches, patch compare, confidence, gaps

PF13 - Admin and data health:

- clean admin page
- source health
- counts/metrics
- purge controls
- re-indexing
- failed jobs

PF14 - Tests, Azure, and live UI validation:

- local tests
- Playwright/live UI validation after deploy
- live health checks
- end-user workflow validation

Every implementation commit after PF0 must reference this blueprint.

## Azure and live validation

PatchForge is Azure-hosted for live use.

Before deployment, understand ACR, Container Apps environment, runtime app, bridge app, frontend app, public UI domain, bridge health endpoint, Key Vault references, managed identity, image tags, build/push script, deployment plan/apply script, and live verification evidence.

Do not deploy unless explicitly instructed.

If deployment is instructed, validation must include build/push, plan, apply after plan review, revision/image verification, health endpoint checks, live UI test, and browser/Playwright validation.

Live UI validation must prove:

- public UI loads
- no blank page
- no console-breaking errors
- Security Action Center visible
- Vendors & Exploits Register visible
- CVE search works
- CVE detail works
- Customer Operational Assets visible
- manual asset add works
- config paste/upload works with synthetic data
- synthetic secrets are redacted
- exposure matching works
- Patch / Hotfix Compare works
- Ask PatchForge responds defensively
- report builder generates scoped report
- export/download works
- signed pack verifies
- admin dashboard works
- no dead admin links in main admin view

## Definition of done

The rebuild is not complete until:

- blueprint exists and is linked from docs
- restore point exists
- old report-first UX is removed or hidden
- Vendors & Exploits Register is searchable
- CVE detail pages are useful
- Customer Operational Assets can be onboarded
- config upload/paste redacts secrets
- assets can match to CVEs
- patch/hotfix compare works
- Ask PatchForge can help profile devices and explain CVEs defensively
- reports are user-scoped
- signed action packs verify
- Admin page is useful and has no dead links
- local tests pass
- live UI validation passes if deployed
- no offensive guidance is emitted

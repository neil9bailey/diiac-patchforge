# PatchForge Open Gaps Register

Date: 2026-05-27

| Gap | Status | Notes |
| --- | --- | --- |
| Live scanner integrations | Open | Product remains governance-only; no scanner connector is live unless separately integrated. |
| Public source intelligence feeds | Closed for PF-AZ6 | CISA KEV and FIRST EPSS public feeds were validated through the live UI as source-bound pending-review inputs. |
| Patch deployment | Permanently excluded | PatchForge does not deploy patches or mutate production systems. |
| Exploit generation | Permanently excluded | PatchForge does not generate exploit code or procedural exploit steps. |
| Live prior mutation | Locked | Bayesian prior updates are dry-run/proposal-only. |
| Vendor source truth | Controlled | Vendor/threat signals remain source-bound pending review. |
| Live UI validation | Closed for PF-AZ6 | Browser/MSAL workflow completed against `https://patchforge.diiac.io` on 2026-05-26. |
| Synthetic validation data | Closed for PF-AZ6 | Earlier PF-AZ5 synthetic record `CVE-2026-PF-DEMO-001` and linked production PostgreSQL records were removed and verified absent. |
| Professional DOCX/PDF board packs | Closed for PF-AZ7 | Protected report APIs, UI export actions, live downloads, and DOCX/PDF visual QA were validated against signed pack `PF-20260527-54588be9`. |
| Guided intelligence workflow | Closed for PF-AZ8 | Action Center, Finding Detail, Review & Approve, Reports & Packs, finding intelligence API, improved DOCX/PDF reports, live signed pack generation, and protected report export passed Azure live UI validation. |
| Operational Admin health checks | Closed for PF-AZ9 | MCP agent intake is governed, public source feeds are ready, worker health is ready, and scheduler health is ready in the live Admin UI/API. |
| Customer report specificity and guided decision-usefulness | Closed for PF-AZ8A | Safer automation wording, urgent scope confirmation posture, KEV/EPSS explanation, customer-specific pack sections, specific evidence gaps, UI context guidance, live signed-pack generation, and live customer/board/CAB DOCX/PDF export passed Azure live UI validation. |
| VendorLens network vendor intelligence | Closed for PF-AZ9 VendorLens | Vendor catalogue, config-aware applicability, source-bound advisory ingest foundations, Ask PatchForge SRA/AIP chat, VendorLens UI, signed-pack artefacts, DOCX/PDF report sections, Azure rollout, signed pack verification, and live UI validation passed. PF-AZ9 validation records were removed from production PostgreSQL after evidence capture. |
| Scheduled live public-source refresh | Closed for PF-AZ7 | Scheduler Container App is running one replica and completed CISA KEV/FIRST EPSS refresh as `patchforge-scheduler@diiac.io`. |
| Customer production validation | Not claimed | Evidence covers DIIaC live platform validation, not third-party customer signoff. |
| Azure CLI custom API token consent | Open | Azure CLI token acquisition for the PatchForge API returned AADSTS65001; browser/MSAL validation succeeded and was used for the live user workflow. |

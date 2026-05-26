# PatchForge Open Gaps Register

Date: 2026-05-26

| Gap | Status | Notes |
| --- | --- | --- |
| Live scanner integrations | Open | Product remains governance-only; no scanner connector is live unless separately integrated. |
| Public source intelligence feeds | PF-AZ6 local validated, Azure rollout pending | CISA KEV and FIRST EPSS public feeds are implemented as source-bound pending-review inputs. Live Azure browser validation is pending. |
| Patch deployment | Permanently excluded | PatchForge does not deploy patches or mutate production systems. |
| Exploit generation | Permanently excluded | PatchForge does not generate exploit code or procedural exploit steps. |
| Live prior mutation | Locked | Bayesian prior updates are dry-run/proposal-only. |
| Vendor source truth | Controlled | Vendor/threat signals remain source-bound pending review. |
| Live UI validation | Closed for PF-AZ5 | Browser/MSAL workflow completed against `https://patchforge.diiac.io` on 2026-05-26. |
| Customer production validation | Not claimed | Evidence covers DIIaC live platform validation, not third-party customer signoff. |
| Azure CLI custom API token consent | Open | Azure CLI token acquisition for the PatchForge API returned AADSTS65001; browser/MSAL validation succeeded and was used for the live user workflow. |

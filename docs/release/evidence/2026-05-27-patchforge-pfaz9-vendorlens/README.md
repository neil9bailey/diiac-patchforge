# PF-AZ9 VendorLens Evidence

Date: 2026-05-27

This folder records PF-AZ9 VendorLens Network Vendor Intelligence and Config-Aware Patch Advisor evidence.

## Current State

PF-AZ9 VendorLens is deployed to Azure and live validated through the production UI/API as `n.bailey@diiac.io` with `PatchForge.Admin`.

## Local Evidence

- `local-reports/` contains locally generated DOCX and PDF reports with VendorLens sections.
- `local-reports/local-report-qa.json` records structural report checks and the local DOCX render limitation.

## Azure And Live Evidence

- `build-push/` records ACR build/push and tag verification for image tag `pfaz9-20260527-e8a0de2`.
- `deploy-plan/` records the Bicep what-if evidence captured before the targeted image rollout.
- `deploy-apply/` records active Container Apps revisions before and after the image update.
- `live-ui/` records live HTTP/API smoke, MSAL browser validation, screenshots, signed-pack verification, Key Vault signing evidence, PostgreSQL evidence, report QA, and production validation data cleanup.

## Boundary

VendorLens remains source-bound advisory intelligence. It does not scan environments, provide exploit steps, deploy patches, mutate production systems, approve CAB decisions, or accept risk autonomously.

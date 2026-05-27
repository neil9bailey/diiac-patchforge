# PF-AZ9 VendorLens Evidence

Date: 2026-05-27

This folder records PF-AZ9 VendorLens Network Vendor Intelligence and Config-Aware Patch Advisor evidence.

## Current State

Local implementation and validation gates are complete. Azure rollout and live UI validation are pending the PF-AZ9 VendorLens image build, push, and Container Apps update.

## Local Evidence

- `local-reports/` contains locally generated DOCX and PDF reports with VendorLens sections.
- `local-reports/local-report-qa.json` records structural report checks and the local DOCX render limitation.

## Boundary

VendorLens remains source-bound advisory intelligence. It does not scan environments, provide exploit steps, deploy patches, mutate production systems, approve CAB decisions, or accept risk autonomously.

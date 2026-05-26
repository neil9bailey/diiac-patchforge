# PF-AZ5 Production Readiness Summary

Date: 2026-05-26

## State

PatchForge is live on Azure Container Apps with custom domains, PostgreSQL storage, Entra-protected API routes, and Key Vault production signing support.

PF-AZ5 adds production intelligence hardening:

- fail-closed production auth guard
- production tenant-context hardening
- actor and tenant lineage on writes
- Bayesian Patch Risk Inference
- vendor and threat landscape intelligence
- source-bound agent finding governance
- live API-bound UI pages
- board-grade report sections
- signed pack intelligence artefacts

## Required Final Gate

PF-AZ5 is not complete until the post-deployment live UI user validation is recorded under the PF-AZ5 rollout evidence directory.

## Honest Gaps

- Live scanner integrations are not implemented.
- Patch deployment remains prohibited and not implemented.
- Exploit generation remains prohibited and not implemented.
- Bayesian output is advisory-only and cannot approve or close gates.
- Vendor and threat intelligence remains source-bound until reviewed.
- Live customer validation is not claimed unless explicitly evidenced.

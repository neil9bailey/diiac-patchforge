# PF-AZ8A Production Readiness Summary

Date: 2026-05-27

Status: PASS. Azure rollout and live UI validation are complete.

## Purpose

PF-AZ8A refines PatchForge customer decision outputs so a customer, CAB, service owner, or board reviewer can understand what is known, what is not yet proven, what decision can be made today, and what evidence is required before approval.

## Changes

- Replaced risky autonomous-analysis wording with `Automated Governance Analysis Completed`.
- Added the required human approval notice below automated-governance wording.
- Added urgent scope confirmation language for known-exploited public-source records where customer asset/service exposure is not reviewed.
- Added KEV and EPSS plain-English interpretation, including low-EPSS/known-exploited tension.
- Added missing vendor-advisory evidence wording and source-bound threat metric labelling.
- Expanded evidence gaps with why it matters, required evidence, examples, suggested owner role, and next decision gate.
- Added customer assurance, impact, evidence, communication, shareable-position, and not-yet-claimable sections to the customer pack.
- Added decision-option status, reason, evidence requirement, and approval requirement.
- Added persistent UI context banner and next-action cards.

## Local Gates

- Backend syntax and tests: PASS.
- Frontend tests and build: PASS.
- Python runtime tests: PASS.
- IaC validation and Bicep build: PASS.
- Docker build smoke for frontend, bridge/API, and runtime: PASS.
- DOCX structural/open QA and PDF render QA: PASS.

Evidence:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/local-report-qa/`

## Azure Gates

- GitHub push: PASS, commit `4f3bbe8`.
- Image tag: `pfaz8a-20260527-4f3bbe8`.
- ACR image build/push: PASS for frontend, bridge/API, runtime, SRA, worker, and scheduler.
- Azure Container Apps image update: PASS.
- Active revisions:
  - UI: `ca-patchforge-ui-prod--0000012`.
  - Bridge/API: `ca-patchforge-bridge-prod--0000011`.
  - Runtime: `ca-patchforge-runtime-prod--0000010`.
  - SRA: `ca-patchforge-sra-prod--0000009`.
  - Worker: `ca-patchforge-worker-prod--0000009`.
  - Scheduler: `ca-patchforge-scheduler-prod--0000009`.

## Live Gates

- Live API smoke: PASS.
- Browser/MSAL live UI validation as `PatchForge.Admin`: PASS.
- Context banner for `CVE-2026-48172`: PASS.
- Live signed pack generation and verification: PASS, `PF-20260527-934d6e60`.
- Key Vault signing: PASS, `pf-pack-signing-prod`, ES256, `azure_key_vault`.
- PostgreSQL readiness: PASS.
- Live customer, board, and CAB DOCX/PDF export validation: PASS.
- Live DOCX wording checks and PDF render QA: PASS.

Evidence:

- `docs/release/evidence/2026-05-27-patchforge-pfaz8a-report-specificity/live-ui/`

## Boundary

PF-AZ8A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance.

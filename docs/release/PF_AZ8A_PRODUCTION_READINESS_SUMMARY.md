# PF-AZ8A Production Readiness Summary

Date: 2026-05-27

Status: local validation complete. Azure rollout and live UI validation are pending.

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

## Pending Gates

- GitHub push.
- ACR image build/push.
- Azure Container Apps update.
- Live API smoke.
- Browser/MSAL live UI validation as PatchForge.Admin.
- Live signed pack generation and verification.
- Live customer, board, and CAB DOCX/PDF export validation.

## Boundary

PF-AZ8A does not add scanning, exploit generation, procedural exploit steps, patch deployment, production mutation, autonomous CAB approval, or autonomous risk acceptance.

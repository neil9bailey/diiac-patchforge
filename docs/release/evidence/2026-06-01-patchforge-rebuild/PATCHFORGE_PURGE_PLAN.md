# PatchForge Purge Plan

Date: 2026-06-01

Blueprint: `docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md`

## Purpose

PatchForge is being rebuilt as a catalogue-first, customer-operational-asset-aware intelligence product. The purge plan removes confusing generated data, old report-first artefacts, stale mocks, and uploaded operational data while preserving the deployment, signing, verification, RBAC, audit, and test foundations needed for the rebuild.

## Scope

Purge candidates:

- generated reports
- bad demo records
- old vulnerability mock records
- old uploads
- old report jobs
- stale catalogues
- cache
- logs when explicitly selected

Preserve:

- Git history
- restore tags and branches
- signing, verifier, and replay core
- auth and RBAC configuration
- Azure deployment scripts
- infrastructure-as-code files
- test harnesses
- deployment evidence
- purge event documentation

## Required implementation

PF2 must implement `scripts/patchforge_factory_reset.py` with:

- `--reports`
- `--catalogue`
- `--assets`
- `--uploads`
- `--logs`
- `--cache`
- `--all`
- `--dry-run`
- `--confirm FACTORY_RESET_PATCHFORGE`

The script must default to dry-run style reporting unless a destructive scope and typed confirmation are present.

## Admin controls

Admin purge controls must be placed under System & Data Health and require typed confirmation:

- `DELETE REPORTS`
- `DELETE ASSETS`
- `DELETE CATALOGUE`
- `FACTORY RESET PATCHFORGE`

No destructive action may run from a dead link, hidden auto-action, background job, or ambiguous button.

## Production boundary

No production purge is authorised by this plan alone. Production mutation requires an explicit user instruction, a current plan, evidence capture, and post-action verification.

## PF0 status

This plan documents the purge strategy only. No purge command has been run during PF0.

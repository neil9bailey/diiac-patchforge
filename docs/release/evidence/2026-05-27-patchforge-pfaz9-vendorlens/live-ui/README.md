# PF-AZ9-VENDORLENS Live UI Evidence

Release: PF-AZ9-VENDORLENS Network Vendor Intelligence and Config-Aware Patch Advisor
Image tag: pfaz9-20260527-e8a0de2
Commit: e8a0de2
Validation timestamp: 2026-05-27T13:22:02.3981966Z

## Result

PASS. The deployed UI at https://patchforge.diiac.io loaded successfully, Microsoft Entra sign-in completed as n.bailey@diiac.io with PatchForge.Admin, VendorLens rendered, a customer network asset and source-bound vendor advisory were created through the live UI, config applicability assessment ran, Ask PatchForge returned advisory-only guidance, and signed pack PF-20260527-2d9f160a was generated and verified.

## Evidence Files

- ui-smoke-summary.json
- live-api-smoke.json
- live-auth-smoke.json
- live-pack-verification.json
- live-pack-verification.txt
- keyvault-signing-smoke.json
- postgres-smoke.json
- live-report-qa.json
- containerapp-active-revisions.json
- console-log.txt
- browser-screenshots/
- exports/

## Boundary Confirmed

VendorLens remained source-bound and advisory-only. No scanner, exploit generation, procedural exploit steps, patch deployment, production system mutation, autonomous CAB approval, or autonomous risk acceptance capability was created or exercised.

## Validation Data Cleanup

The live UI validation records used to prove the VendorLens workflow were removed from production PostgreSQL after evidence capture. `production-validation-data-cleanup.json` verifies the validation asset, advisory, applicability assessment, chat session, decision pack, and linked audit events are absent. Downloaded evidence artefacts remain under this release evidence folder only.

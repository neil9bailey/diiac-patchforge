# PatchForge PF-AZ5 Live Product Evidence

Date: 2026-05-26

## Scope

PF-AZ5 converts the customer-facing PatchForge surface from a static shell into a live Entra-protected product workflow:

- Microsoft Entra sign-in at `https://patchforge.diiac.io/`
- protected browser API client for `https://api.patchforge.diiac.io`
- no seeded, demo, or synthetic vulnerability data
- real operator-supplied vulnerability ingest
- PostgreSQL-backed tenant state
- bridge-to-runtime decision pack generation
- runtime signed pack verification
- production CORS for the UI/API split domain

## Evidence Files

- `acr-images-pfaz5.json` confirms `pfaz5-20260526` image tags exist in ACR.
- `containerapp-state-pfaz5.json` records running Container App revisions and deployed images.
- `bridge-live-env-sanitized-pfaz5.json` records non-secret live bridge settings.
- `http-smoke-pfaz5.json` records UI/API/CORS live smoke results.
- `local-operational-smoke-pfaz5.json` records the end-to-end local operational smoke against a temporary store.
- `validation-pfaz5.json` records local validation gates.
- `patchforge-pfaz5-signin.png` records the live Entra sign-in page rendered by Playwright.
- `ui-hotfix-pfaz5.json` records the UI layout hotfix revision and asset checks.
- `deployment-pfaz5-agent.json` records the live UI, bridge, and runtime revisions for the agent-intelligence increment.
- `http-smoke-pfaz5-agent.json` records live custom-domain smoke checks after the agent-intelligence deployment.
- `validation-pfaz5-agent.json` records local validation gates for the Guide, agent-finding intake, and advisory evidence controls.
- `patchforge-pfaz5-authenticated-ui.png` records the live authenticated command-center layout after the UI formatting pass.

## Boundary

PatchForge remains governance-only. PF-AZ5 adds no scanner, exploit-generation, patch-deployment, production-mutation, autonomous CAB, autonomous risk-acceptance, or unreviewed agent-source truth capability.

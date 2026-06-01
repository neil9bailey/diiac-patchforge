# PatchForge Rebuild Live Deploy Summary

Date: 2026-06-01

Branch: `codex/patchforge-rebuild-20260601`

Commit deployed: `43f953c`

Image tag: `pfrebuild-20260601-43f953c`

## Scope

This evidence records the live Azure update for the canonical PatchForge rebuild. The update was applied as targeted Container Apps image updates to avoid replaying unrelated Bicep drift found during subscription what-if.

## Image Build

Local Docker build was attempted first but Docker Desktop was unavailable. Azure Container Registry remote builds were then used.

Images built/present in `acrdiiacpatchforgeprod`:

- `diiac/patchforge-frontend:pfrebuild-20260601-43f953c`
- `diiac/patchforge-bridge:pfrebuild-20260601-43f953c`
- `diiac/patchforge-runtime:pfrebuild-20260601-43f953c`
- `diiac/patchforge-sra-agent:pfrebuild-20260601-43f953c`
- `diiac/patchforge-ingest-worker:pfrebuild-20260601-43f953c`
- `diiac/patchforge-scheduler:pfrebuild-20260601-43f953c`

## Azure Update

All six production Container Apps were updated to `pfrebuild-20260601-43f953c`:

- `ca-patchforge-ui-prod`
- `ca-patchforge-bridge-prod`
- `ca-patchforge-runtime-prod`
- `ca-patchforge-sra-prod`
- `ca-patchforge-worker-prod`
- `ca-patchforge-scheduler-prod`

The after snapshot confirms all active revisions run the new image tag with 100% traffic.

## Live Smoke

Passed:

- `https://patchforge.diiac.io/` returned HTTP 200.
- `https://api.patchforge.diiac.io/health` returned HTTP 200.
- `https://api.patchforge.diiac.io/readiness` returned HTTP 200 with PostgreSQL storage and auth required.
- Unauthenticated `GET /api/patchforge/security-action-center` returned HTTP 401 as expected.

Browser validation:

- The in-app browser loaded the live site and confirmed the PatchForge sign-in screen.
- Browser/MSAL protected UI validation could not continue because the tab stopped at Microsoft interactive sign-in.

Protected API validation:

- Azure CLI access-token attempts for the PatchForge API were blocked by Entra consent for the Azure CLI application.

## Purge Status

Production purge was not executed.

The rebuild implements a destructive purge gate requiring the exact confirmation phrase `FACTORY_RESET_PATCHFORGE`. That phrase has not been provided in the conversation, so production records remain intact.

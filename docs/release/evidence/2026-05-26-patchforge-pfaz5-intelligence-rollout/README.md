# PF-AZ5 Intelligence Rollout Evidence

Date: 2026-05-26

Image tag: `pfaz5-20260526-8a145e8`

Commit: `8a145e849a2c57fed3bc00440f2f2f8b29585f72`

## Contents

- `build-push/`: ACR login, Docker build, Docker push, and ACR tag evidence.
- `deploy-plan/`: pre-update Container Apps snapshot, full Bicep what-if, and targeted image-only update plan.
- `deploy-apply/`: Container Apps update outputs, post-update image snapshot, traffic, and active revisions.
- `live-ui/`: live API smoke, browser/MSAL user validation, screenshots, exported signed pack, Key Vault signing smoke, PostgreSQL smoke, and console notes.

## Notes

The full Bicep what-if was captured but not applied because it included broader drift/noise than the PF-AZ5 image rollout required. The production update was therefore performed as targeted image-only Container Apps updates to preserve custom domains, managed certificates, Entra auth, managed identities, PostgreSQL, and Key Vault signing.

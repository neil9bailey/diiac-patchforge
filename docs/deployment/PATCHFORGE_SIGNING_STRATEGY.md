# PatchForge Signing Strategy

## Local Baseline

The current runtime supports local signed decision packs with a development/test signature path. This is suitable for tests and demos only.

## Production State

Azure Key Vault production signing key has been created:

- Vault: `kv-diiac-patchforge-prod`
- Key: `pf-pack-signing-prod`
- Key ID: `https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod/2e348fdeaaaf448ebba206130ef86b52`
- Key type: EC P-256
- Algorithm smoke-tested: ES256
- Operations: sign, verify

Smoke verification result: passed.

Evidence: `docs/release/evidence/2026-05-26-patchforge-gates/keyvault-signing-smoke.json`

## Production Direction

Production signing should use Azure Key Vault-backed signing trust.

Production design requirements:

- signing keys stored in Key Vault or approved HSM-backed equivalent
- managed identity access for runtime only
- no signing keys in repository
- no signing keys in environment variables
- clear trust bundle in each pack
- verification manifest per pack
- replay certificate per pack

## Remaining Access Gate

Before production signing is enabled in runtime decision-pack generation, confirm:

- runtime managed identity permissions
- signing key rotation policy
- recovery and purge protection expectations
- verification key publication strategy
- production pack verifier behavior against the Key Vault public key material

## Trust Boundary

A signature proves artefact integrity and replay state. It does not prove that all source evidence is true.

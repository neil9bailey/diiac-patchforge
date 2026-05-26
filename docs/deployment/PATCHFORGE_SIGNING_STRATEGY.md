# PatchForge Signing Strategy

## Local Baseline

The current runtime supports local signed decision packs with a development/test signature path. This is suitable for tests and demos only.

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

## Access Gate

Before production signing is enabled, confirm:

- Key Vault name and region
- key type and algorithm
- runtime managed identity permissions
- signing key rotation policy
- recovery and purge protection expectations
- verification key publication strategy

## Trust Boundary

A signature proves artefact integrity and replay state. It does not prove that all source evidence is true.


from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = REPO_ROOT / "scripts" / "publish_patchforge_production.ps1"


def publisher_source() -> str:
    return PUBLISHER.read_text(encoding="utf-8")


def test_attestation_verification_requires_json_evidence_and_release_identity():
    source = publisher_source()

    assert '"--format", "json"' in source
    assert '"--signer-workflow", "$ApprovalRepository/.github/workflows/production-release-approval.yml"' in source
    assert '"--source-ref", $ApprovedRef' in source
    assert '"--source-digest", [string]$runJson.headSha' in source
    assert "[string]::IsNullOrWhiteSpace($attestationResult.StdOut)" in source
    assert "$verifiedAttestations = $attestationResult.StdOut | ConvertFrom-Json" in source
    assert "attestation-verification.json" in source
    assert "attestation-verification.txt" not in source


def test_pre_update_failure_does_not_claim_that_rollback_ran():
    source = publisher_source()

    assert "$containerAppUpdateAttempted = $attemptedApps.Count -gt 0" in source
    assert '"failed_before_containerapp_update"' in source
    assert "No application rollback is required." in source


def test_key_vault_parsing_supports_current_and_legacy_cli_schemas():
    source = publisher_source()

    assert "function Get-KeyVaultSignatureValue" in source
    assert '@("signature", "result", "value")' in source
    assert "function Test-KeyVaultVerificationResult" in source
    assert '@("isValid", "value", "result")' in source
    assert source.count("Get-KeyVaultSignatureValue -SignResult $signResult") == 2
    assert source.count("Test-KeyVaultVerificationResult -VerifyResult $verifyResult") == 2

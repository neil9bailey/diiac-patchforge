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


def test_registry_login_precedes_signing_and_rollback_image_capture():
    source = publisher_source()

    registry_login = source.index('"acr", "login"')
    signing_preflight = source.index("$record.signing_preflight = Assert-KeyVaultSigningPreflight")
    rollback_capture = source.index("Backup-CurrentImages -BeforeSnapshots")

    assert registry_login < signing_preflight < rollback_capture
    assert '"--name", $RegistryName' in source[registry_login:signing_preflight]


def test_readiness_accepts_serving_at_capacity_without_weakening_other_gates():
    source = publisher_source()

    assert '@("Running", "RunningAtMaxScale", "ScaledToZero") -notcontains $revision.runningState' in source
    assert '$revision.healthState -ne "Healthy"' in source
    assert '$revision.provisioningState -ne "Provisioned"' in source
    assert '$revision.image -cne $ExpectedImage' in source
    assert '$revision.name -ne $state.latestReadyRevisionName' in source
    assert '[int]$target.weight -ne 100' in source


def test_rollback_capture_returns_only_structured_records():
    source = publisher_source()

    assert 'Invoke-NativeStreaming -Command "docker" -Arguments @("pull", $image) | Out-Host' in source
    assert (
        'Invoke-NativeStreaming -Command "docker" -Arguments '
        '@("save", "--output", $archivePath, $image) | Out-Host'
    ) in source

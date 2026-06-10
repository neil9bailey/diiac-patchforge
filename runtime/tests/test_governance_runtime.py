import json
from pathlib import Path

import pytest

from runtime.governance_runtime import (
    GovernanceRuntimeError,
    apply_evidence_model,
    build_evidence_register,
    build_patch_decision_context,
    canonical_json,
    create_signed_decision_pack,
    verify_pack_locally,
    verify_pack_payload,
)
from runtime.health_server import _read_pack_artefacts
from runtime.bayesian_patch_risk import assess_patch_risk, propose_prior_update

VERIFY_RESPONSE_KEYS = {
    "verified",
    "algorithm",
    "artefact_hash_check",
    "manifest_hash_check",
    "signature_check",
    "failed_artefacts",
}


def sample_vulnerability(**overrides):
    base = {
        "tenant_id": "tenant-a",
        "vulnerability_id": "REAL-RECORD-1",
        "canonical_id": "REAL-RECORD-1",
        "title": "Customer supplied critical exposure",
        "severity": "critical",
        "known_exploited": True,
        "internet_exposed": True,
        "patch_status": "patch_available",
    }
    base.update(overrides)
    return base


def accepted(ref, evidence_class, source_class="human_review"):
    return {
        "evidence_ref": ref,
        "evidence_class": evidence_class,
        "source_class": source_class,
        "review_state": "reviewed",
        "evidence_state": "accepted_positive_evidence",
    }


def test_rejected_evidence_does_not_close_blockers():
    evidence = [
        {
            "evidence_ref": "scanner-vuln-id",
            "evidence_class": "vulnerability_identity",
            "source_class": "scanner_output",
            "review_state": "rejected",
            "evidence_state": "rejected",
        }
    ]
    register = build_evidence_register(evidence)
    evaluation = apply_evidence_model("vuln_patch_governance", register)
    assert "vulnerability_identity" in evaluation.blockers
    assert "scanner-vuln-id" in evaluation.rejected_refs


def test_sra_and_scanner_output_cannot_close_hard_gates_alone():
    evidence = [
        {
            "evidence_ref": "sra-vuln-id",
            "evidence_class": "vulnerability_identity",
            "source_class": "sra_trace",
            "review_state": "reviewed",
            "evidence_state": "accepted_positive_evidence",
            "advisory_only": True,
        },
        {
            "evidence_ref": "scanner-asset",
            "evidence_class": "affected_asset_scope",
            "source_class": "scanner_output",
            "review_state": "reviewed",
            "evidence_state": "accepted_positive_evidence",
        },
    ]
    evaluation = apply_evidence_model("vuln_patch_governance", build_evidence_register(evidence))
    assert "vulnerability_identity" in evaluation.blockers
    assert "affected_asset_scope" in evaluation.blockers
    assert "sra-vuln-id" in evaluation.advisory_only_refs


def test_agent_findings_are_advisory_and_cannot_close_hard_gates_alone():
    evidence = [
        {
            "evidence_ref": "mythos-vuln-id",
            "evidence_class": "vulnerability_identity",
            "source_class": "mythos_finding",
            "review_state": "reviewed",
            "evidence_state": "accepted_positive_evidence",
        },
        {
            "evidence_ref": "mcp-asset-scope",
            "evidence_class": "affected_asset_scope",
            "source_class": "mcp_agent_finding",
            "review_state": "reviewed",
            "evidence_state": "accepted_positive_evidence",
        },
        {
            "evidence_ref": "agi-patch",
            "evidence_class": "patch_availability",
            "source_class": "agi_agent_finding",
            "review_state": "reviewed",
            "evidence_state": "accepted_positive_evidence",
        },
    ]
    evaluation = apply_evidence_model("vuln_patch_governance", build_evidence_register(evidence))
    assert {"vulnerability_identity", "affected_asset_scope", "patch_availability"} <= set(evaluation.blockers)
    assert {"mythos-vuln-id", "mcp-asset-scope", "agi-patch"} <= set(evaluation.advisory_only_refs)


def test_bayesian_patch_risk_is_deterministic_and_advisory_only():
    inputs = {
        "cvss": 9.8,
        "epss": 0.82,
        "known_exploited": True,
        "internet_exposed": True,
        "patch_status": "patch_available",
        "customer_facing": True,
        "service_tier": "tier_1",
        "rollback_evidence": False,
    }
    first = assess_patch_risk(inputs)
    second = assess_patch_risk(inputs)
    assert first["exploit_probability_posterior"] == second["exploit_probability_posterior"]
    assert first["recommended_governance_posture"] == "emergency_change_required"
    assert first["advisory_only"] is True
    assert first["can_close_hard_gates_alone"] is False
    assert first["final_approval_issued"] is False


def test_prior_update_is_proposal_only():
    proposal = propose_prior_update([{"posture": "patch_required", "outcome": "successful"}])
    assert proposal["dry_run"] is True
    assert proposal["live_update_applied"] is False
    assert proposal["admin_approval_required"] is True


def test_final_approval_false_by_default_for_emergency_patch():
    context = build_patch_decision_context(
        vulnerability=sample_vulnerability(),
        evidence_items=[
            accepted("human-vuln-id", "vulnerability_identity"),
            accepted("human-asset", "affected_asset_scope"),
            accepted("vendor-patch", "patch_availability"),
            accepted("human-review", "human_review_signoff"),
        ],
        requested_posture="emergency_change_required",
    )
    assert context["final_approval_issued"] is False
    assert "emergency_human_approval" in context["blockers"]


def test_generate_and_verify_signed_decision_pack(tmp_path: Path):
    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack",
        vulnerability=sample_vulnerability(),
        evidence_items=[
            accepted("human-vuln-id", "vulnerability_identity"),
            accepted("human-asset", "affected_asset_scope"),
            accepted("vendor-patch", "patch_availability"),
            accepted("human-review", "human_review_signoff"),
        ],
        patch_availability={"status": "patch_available"},
        bayesian_snapshot=assess_patch_risk({
            "known_exploited": True,
            "internet_exposed": True,
            "patch_status": "patch_available",
        }),
        vendor_intelligence_snapshot={
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
            "vendor_id": "microsoft",
        },
        network_vendor_profile_snapshot={
            "vendor_id": "fortinet",
            "vendor_name": "Fortinet",
            "source_bound": True,
            "review_required": True,
        },
        customer_network_asset_snapshot={
            "asset_id": "net-fw-1",
            "vendor_id": "fortinet",
            "model": "100F",
            "firmware_version": "7.2.7",
            "review_state": "pending_review",
        },
        vendor_security_advisory_snapshot={
            "advisory_id": "FG-ADV-CVE-2026-REAL-001",
            "cve": "CVE-2026-REAL-001",
            "source_bound": True,
            "review_required": True,
        },
        config_applicability_assessment={
            "assessment_id": "cfg-app-1",
            "applicability_posture": "requires_review",
            "urgency_posture": "urgent_scope_confirmation_required",
            "human_review_required": True,
            "final_approval_issued": False,
        },
        sra_config_chat_session={
            "session_id": "vl-chat-1",
            "advisory_only": True,
            "final_approval_issued": False,
        },
        vendorlens_decision_context={
            "context_id": "vendorlens-cfg-app-1",
            "advisory_only": True,
            "human_review_required": True,
            "final_approval_issued": False,
        },
        approval_events=[
            {"approval_type": "final", "approval_state": "approved", "approver": "cab-chair"}
        ],
    )

    assert result["decision_context"]["final_approval_issued"] is True
    assert result["verification"]["verified"] is True

    verification = verify_pack_locally(result["pack_dir"])
    assert verification["verified"] is True

    expected_files = {
        "vulnerability_intelligence_snapshot.json",
        "patch_decision_context.json",
        "affected_asset_scope.json",
        "exploitability_assessment.json",
        "patch_feasibility_assessment.json",
        "compensating_controls_plan.json",
        "patch_change_readiness.json",
        "patch_risk_acceptance_state.json",
        "human_review_state.json",
        "bayesian_patch_risk_snapshot.json",
        "patch_prior_usage_manifest.json",
        "patch_prior_update_proposal.json",
        "vendor_intelligence_snapshot.json",
        "threat_landscape_snapshot.json",
        "network_vendor_profile_snapshot.json",
        "customer_network_asset_snapshot.json",
        "vendor_security_advisory_snapshot.json",
        "config_applicability_assessment.json",
        "sra_config_chat_session.json",
        "vendorlens_decision_context.json",
        "sra_trace.json",
        "governance_manifest.json",
        "verification_manifest.json",
        "signed_export.sigmeta.json",
        "signed_export.sig",
        "trust_bundle.json",
        "replay_certificate.json",
    }
    assert expected_files <= {path.name for path in Path(result["pack_dir"]).iterdir()}


def test_generate_and_verify_es256_signed_decision_pack(tmp_path: Path):
    cryptography = pytest.importorskip("cryptography")
    assert cryptography

    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-es256",
        vulnerability=sample_vulnerability(),
        evidence_items=[
            accepted("human-vuln-id", "vulnerability_identity"),
            accepted("human-asset", "affected_asset_scope"),
            accepted("vendor-patch", "patch_availability"),
            accepted("human-review", "human_review_signoff"),
        ],
        approval_events=[
            {"approval_type": "final", "approval_state": "approved", "approver": "cab-chair"}
        ],
        key_vault_key_id="https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod/test",
        signing_provider=make_es256_signer(),
        dev_mode=False,
    )

    assert result["verification"]["verified"] is True
    sigmeta = (Path(result["pack_dir"]) / "signed_export.sigmeta.json").read_text(encoding="utf-8")
    assert "azure_key_vault" in sigmeta


def baseline_evidence():
    return [
        accepted("human-vuln-id", "vulnerability_identity"),
        accepted("human-asset", "affected_asset_scope"),
        accepted("vendor-patch", "patch_availability"),
        accepted("human-review", "human_review_signoff"),
    ]


def pack_payload_from_result(result) -> dict:
    """Mirror the pack object shape returned by POST /api/runtime/decision-packs."""
    return {
        "pack_id": result["pack_id"],
        "decision_context": result["decision_context"],
        "verification": result["verification"],
        "artefacts": _read_pack_artefacts(Path(result["pack_dir"])),
    }


def ed25519_private_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def make_es256_signer():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private_key.public_key().public_numbers()

    class FakeKeyVaultSigner:
        def sign(self, signed_payload):
            payload = canonical_json(signed_payload)
            der_signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
            r, s = utils.decode_dss_signature(der_signature)
            raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            return (
                base64url(raw_signature),
                {
                    "algorithm": "ES256",
                    "key_id": "https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod/test",
                    "signed_payload": signed_payload,
                    "signature_encoding": "base64url_raw_ecdsa",
                    "public_jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": base64url(public_numbers.x.to_bytes(32, "big")),
                        "y": base64url(public_numbers.y.to_bytes(32, "big")),
                    },
                    "dev_key_hint": None,
                    "signing_provider": "azure_key_vault",
                },
            )

    return FakeKeyVaultSigner()


def test_ed25519_sign_and_verify_roundtrip(tmp_path: Path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.delenv("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID", raising=False)

    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-ed25519",
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
        signing_key=ed25519_private_key_pem(),
        dev_mode=False,
    )

    sigmeta = json.loads((Path(result["pack_dir"]) / "signed_export.sigmeta.json").read_text(encoding="utf-8"))
    assert sigmeta["algorithm"] == "Ed25519"
    assert sigmeta["public_key"]

    assert result["verification"]["verified"] is True
    assert result["verification"]["signature_ok"] is True
    assert verify_pack_locally(result["pack_dir"])["verified"] is True

    payload_verification = verify_pack_payload(pack_payload_from_result(result))
    assert set(payload_verification) == VERIFY_RESPONSE_KEYS
    assert payload_verification["verified"] is True
    assert payload_verification["algorithm"] == "Ed25519"
    assert payload_verification["failed_artefacts"] == []


def test_ed25519_verification_detects_tampered_artefact(tmp_path: Path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.delenv("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID", raising=False)

    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-ed25519-tamper",
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
        signing_key=ed25519_private_key_pem(),
        dev_mode=False,
    )
    pack_dir = Path(result["pack_dir"])

    artefact_path = pack_dir / "patch_feasibility_assessment.json"
    tampered = json.loads(artefact_path.read_text(encoding="utf-8"))
    tampered["tampered"] = True
    artefact_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert verify_pack_locally(pack_dir)["verified"] is False

    # Tampering with the signed payload must break the Ed25519 signature itself.
    sigmeta_path = pack_dir / "signed_export.sigmeta.json"
    sigmeta = json.loads(sigmeta_path.read_text(encoding="utf-8"))
    sigmeta["signed_payload"]["pack_id"] = "PF-FORGED-PACK"
    sigmeta_path.write_text(json.dumps(sigmeta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verification = verify_pack_locally(pack_dir)
    assert verification["signature_ok"] is False
    assert verification["verified"] is False


def test_ed25519_verification_handles_missing_or_invalid_public_key(tmp_path: Path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.delenv("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID", raising=False)

    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-ed25519-nokey",
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
        signing_key=ed25519_private_key_pem(),
        dev_mode=False,
    )
    pack = pack_payload_from_result(result)

    pack["artefacts"]["signed_export.sigmeta.json"]["public_key"] = None
    assert verify_pack_payload(pack)["signature_check"] is False

    pack["artefacts"]["signed_export.sigmeta.json"]["public_key"] = "not-valid-base64!!"
    assert verify_pack_payload(pack)["signature_check"] is False


def test_verify_pack_payload_dev_hmac_success_and_failure(tmp_path: Path):
    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-dev",
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
    )
    pack = pack_payload_from_result(result)
    # _read_pack_artefacts nulls dev_key_hint, so this exercises stateless dev verification.
    assert pack["artefacts"]["signed_export.sigmeta.json"]["dev_key_hint"] is None

    verification = verify_pack_payload(pack)
    assert set(verification) == VERIFY_RESPONSE_KEYS
    assert verification == {
        "verified": True,
        "algorithm": "dev_hmac_sha256",
        "artefact_hash_check": True,
        "manifest_hash_check": True,
        "signature_check": True,
        "failed_artefacts": [],
    }

    pack["artefacts"]["patch_decision_context.json"]["decision_posture"] = "close_verified"
    failed = verify_pack_payload(pack)
    assert failed["verified"] is False
    assert failed["artefact_hash_check"] is False
    assert failed["failed_artefacts"] == ["patch_decision_context.json"]
    assert failed["signature_check"] is True


def test_verify_pack_payload_es256_success_and_failure(tmp_path: Path):
    pytest.importorskip("cryptography")
    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack-es256-payload",
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
        key_vault_key_id="https://kv-diiac-patchforge-prod.vault.azure.net/keys/pf-pack-signing-prod/test",
        signing_provider=make_es256_signer(),
        dev_mode=False,
    )
    pack = pack_payload_from_result(result)

    verification = verify_pack_payload(pack)
    assert set(verification) == VERIFY_RESPONSE_KEYS
    assert verification["verified"] is True
    assert verification["algorithm"] == "ES256"
    assert verification["failed_artefacts"] == []

    # Tampering with the governance manifest breaks the manifest hash chain.
    pack["artefacts"]["governance_manifest.json"]["final_approval_issued"] = True
    failed = verify_pack_payload(pack)
    assert failed["verified"] is False
    assert failed["manifest_hash_check"] is False

    # Tampering with the signature value breaks the signature check.
    fresh = pack_payload_from_result(result)
    fresh["artefacts"]["signed_export.sig"] = base64url(b"\x00" * 64)
    assert verify_pack_payload(fresh)["signature_check"] is False
    assert verify_pack_payload(fresh)["verified"] is False


def test_verify_pack_payload_rejects_malformed_payloads():
    with pytest.raises(GovernanceRuntimeError):
        verify_pack_payload({"artefacts": "not-an-object"})
    with pytest.raises(GovernanceRuntimeError):
        verify_pack_payload({"artefacts": {}})


def test_expired_risk_acceptance_blocks_posture_derivation():
    context = build_patch_decision_context(
        vulnerability=sample_vulnerability(),
        evidence_items=baseline_evidence(),
        requested_posture="risk_accept_temporarily",
        risk_acceptance={
            "owner": "risk-owner",
            "expiry_date": "2020-01-01",
            "rationale": "Expired acceptance must not satisfy governance posture.",
        },
        approval_events=[
            {"approval_type": "final", "approval_state": "approved", "approver": "cab-chair"}
        ],
    )
    assert "risk_acceptance_expired" in context["blockers"]
    assert context["readiness"]["readiness_state"] == "blocked"


def test_forbidden_boundary_keys_are_rejected(tmp_path: Path):
    with pytest.raises(GovernanceRuntimeError):
        create_signed_decision_pack(
            output_dir=tmp_path / "pack",
            vulnerability=sample_vulnerability(exploit_steps=["not allowed"]),
            evidence_items=[],
        )


def base64url(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

from pathlib import Path

import pytest

from runtime.governance_runtime import (
    GovernanceRuntimeError,
    apply_evidence_model,
    build_evidence_register,
    build_patch_decision_context,
    create_signed_decision_pack,
    verify_pack_locally,
)


def sample_vulnerability(**overrides):
    base = {
        "tenant_id": "tenant-a",
        "vulnerability_id": "CVE-2026-10421",
        "canonical_id": "CVE-2026-10421",
        "title": "Orion Gateway critical exposure",
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
        "governance_manifest.json",
        "verification_manifest.json",
        "signed_export.sigmeta.json",
        "signed_export.sig",
        "trust_bundle.json",
        "replay_certificate.json",
    }
    assert expected_files <= {path.name for path in Path(result["pack_dir"]).iterdir()}


def test_forbidden_boundary_keys_are_rejected(tmp_path: Path):
    with pytest.raises(GovernanceRuntimeError):
        create_signed_decision_pack(
            output_dir=tmp_path / "pack",
            vulnerability=sample_vulnerability(exploit_steps=["not allowed"]),
            evidence_items=[],
        )


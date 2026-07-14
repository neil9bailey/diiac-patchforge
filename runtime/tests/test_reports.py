from pathlib import Path

from runtime.governance_runtime import create_signed_decision_pack
import pytest

from runtime.reports import REPORT_SECTION_GROUPS, REPORT_TYPES, render_all_reports, render_report


REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_SEED_FILE = REPO_ROOT / "docs" / "release" / "evidence" / "patchforge-customer-demonstration" / "demo_scenarios.json"


def test_reports_render_required_sections():
    report = render_report(
        "cab_patch_decision_report",
        {
            "vulnerability_id": "REAL-RECORD-1",
            "service": "Customer Service",
            "decision_posture": "emergency_change_required",
            "bayesian_patch_risk_snapshot": {
                "recommended_governance_posture": "emergency_change_required",
                "exploit_probability_posterior": 0.82,
            },
            "vendor_intelligence_snapshot": {"vendor_id": "microsoft"},
            "threat_landscape_snapshot": {"metrics": {"active_exploitation_count": 1}},
            "signed_pack": {"pack_id": "PF-TEST", "verified": True},
        },
    )
    assert "# CAB Patch Decision Report" in report
    assert "## Report Version Metadata" in report
    assert "report_template_version:" in report
    assert "report_renderer_commit:" in report
    assert "report_renderer_image_tag:" in report
    assert "generated_from_pack_id: PF-TEST" in report
    assert "generated_at_utc:" in report
    assert "product_baseline: PF-AZ11-CUSTOMER-DEMO-MATURITY" in report
    assert "report_context_version:" in report
    assert "source_pack_id:" in report
    assert "report_type: cab_patch_decision_report" in report
    assert "final_approval_issued: false" in report
    assert "signing_provider:" in report
    assert "verification_state:" in report
    for section in REPORT_SECTION_GROUPS["cab_patch_decision_report"]:
        assert f"## {section}" in report
    assert "## What Can Be Shared With Customer" not in report
    assert "## Executive Decision Summary" not in report


def test_all_report_types_render_without_boundary_violations():
    reports = render_all_reports({
        "vulnerability_id": "REAL-RECORD-1",
        "service": "Customer Service",
        "decision_posture": "patch_required",
    })
    assert set(reports) == set(REPORT_TYPES)
    combined = "\n".join(reports.values()).lower()
    assert "exploit instructions" not in combined
    assert "autonomous patch approval" not in combined
    assert "does not" in combined
    assert "does not scan" in combined
    assert "signed pack metadata" in combined


def test_removed_report_types_are_rejected():
    for report_type in [
        "ciso_executive_risk_brief",
        "security_operations_action_plan",
        "vendor_exposure_report",
        "customer_estate_vulnerability_report",
        "patch_hotfix_decision_pack",
        "emergency_advisory_report",
        "monthly_vulnerability_governance_pack",
        "ciso_patch_version_comparison_report",
        "board_vulnerability_summary",
    ]:
        with pytest.raises(ValueError, match="Unknown PatchForge report type"):
            render_report(report_type, {"vulnerability_id": "REAL-RECORD-1"})


def test_signed_pack_verifies_for_report_context(tmp_path):
    result = create_signed_decision_pack(
        output_dir=tmp_path / "pack",
        vulnerability={
            "tenant_id": "tenant-a",
            "vulnerability_id": "REAL-RECORD-1",
            "canonical_id": "REAL-RECORD-1",
            "title": "Customer supplied critical exposure",
            "severity": "critical",
            "known_exploited": True,
            "internet_exposed": True,
            "patch_status": "patch_available",
        },
        evidence_items=[
            {
                "evidence_ref": "ev-vuln",
                "evidence_class": "vulnerability_identity",
                "source_class": "human_review",
                "review_state": "reviewed",
                "evidence_state": "accepted_positive_evidence",
            },
            {
                "evidence_ref": "ev-asset",
                "evidence_class": "affected_asset_scope",
                "source_class": "human_review",
                "review_state": "reviewed",
                "evidence_state": "accepted_positive_evidence",
            },
            {
                "evidence_ref": "ev-patch",
                "evidence_class": "patch_availability",
                "source_class": "human_review",
                "review_state": "reviewed",
                "evidence_state": "accepted_positive_evidence",
            },
            {
                "evidence_ref": "ev-human",
                "evidence_class": "human_review_signoff",
                "source_class": "human_review",
                "review_state": "reviewed",
                "evidence_state": "accepted_positive_evidence",
            },
        ],
        approval_events=[{"approval_type": "final", "approval_state": "approved", "approver": "cab-chair"}],
        bayesian_snapshot={
            "advisory_only": True,
            "can_close_hard_gates_alone": False,
            "recommended_governance_posture": "patch_required",
        },
        vendor_intelligence_snapshot={
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
        },
    )
    assert result["verification"]["verified"] is True
    pack_dir = Path(result["pack_dir"])
    assert (pack_dir / "bayesian_patch_risk_snapshot.json").exists()
    assert (pack_dir / "vendor_intelligence_snapshot.json").exists()


def test_no_demo_seed_file_is_shipped():
    assert not FORBIDDEN_SEED_FILE.exists()

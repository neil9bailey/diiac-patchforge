from pathlib import Path

from runtime.governance_runtime import create_signed_decision_pack
from runtime.reports import REPORT_SECTIONS, REPORT_TYPES, render_all_reports, render_report


REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_SEED_FILE = REPO_ROOT / "docs" / "release" / "evidence" / "patchforge-customer-demonstration" / "demo_scenarios.json"


def test_reports_render_required_sections():
    report = render_report(
        "cab_patch_decision_report",
        {
            "vulnerability_id": "REAL-RECORD-1",
            "service": "Customer Service",
            "decision_posture": "emergency_change_required",
        },
    )
    assert "# CAB Patch Decision Report" in report
    for section in REPORT_SECTIONS:
        assert f"## {section}" in report


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
    assert "deploy patches" in combined
    assert "does not scan" in combined


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
    )
    assert result["verification"]["verified"] is True


def test_no_demo_seed_file_is_shipped():
    assert not FORBIDDEN_SEED_FILE.exists()

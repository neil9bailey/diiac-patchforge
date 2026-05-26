import json
from pathlib import Path

from runtime.governance_runtime import create_signed_decision_pack
from runtime.reports import REPORT_SECTIONS, REPORT_TYPES, render_all_reports, render_report


REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SEEDS = REPO_ROOT / "docs" / "release" / "evidence" / "patchforge-demo-pack" / "demo_scenarios.json"


def test_reports_render_required_sections():
    report = render_report(
        "cab_patch_decision_report",
        {
            "vulnerability_id": "CVE-2026-10421",
            "service": "Orion Gateway",
            "decision_posture": "emergency_change_required",
        },
    )
    assert "# CAB Patch Decision Report" in report
    for section in REPORT_SECTIONS:
        assert f"## {section}" in report


def test_all_report_types_render_without_boundary_violations():
    reports = render_all_reports({
        "vulnerability_id": "CVE-2026-10421",
        "service": "Orion Gateway",
        "decision_posture": "patch_required",
    })
    assert set(reports) == set(REPORT_TYPES)
    combined = "\n".join(reports.values()).lower()
    assert "exploit instructions" not in combined
    assert "autonomous patch approval" not in combined
    assert "deploy patches" in combined
    assert "does not scan" in combined


def test_signed_pack_verifies_for_demo_report_context(tmp_path):
    result = create_signed_decision_pack(
        output_dir=tmp_path / "demo-pack",
        vulnerability={
            "tenant_id": "tenant-a",
            "vulnerability_id": "CVE-2026-10421",
            "canonical_id": "CVE-2026-10421",
            "title": "Orion Gateway critical exposure",
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


def test_demo_scenarios_parse():
    with DEMO_SEEDS.open("r", encoding="utf-8") as handle:
        scenarios = json.load(handle)

    assert len(scenarios["scenarios"]) == 5
    assert {scenario["id"] for scenario in scenarios["scenarios"]} == {
        "critical-exploited-orion-gateway",
        "emergency-patch-rollback-uncertainty",
        "ot-controller-patch-deferral",
        "service-transition-known-exploited-block",
        "msp-monthly-customer-pack",
    }


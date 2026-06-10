from datetime import date

import pytest

from runtime.decision_control_center import (
    DecisionControlError,
    compile_source_pack,
    record_event,
    risk_acceptance_expired,
)


def test_source_pack_blocked_before_evidence():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-1",
        decision_posture="patch_required",
        evidence_refs=[],
    )

    assert source_pack.immutable is True
    assert source_pack.signed_source_pack_preserved is True
    assert "evidence_required" in current_state.blockers
    assert current_state.final_approval_issued is False


def test_dcc_evidence_events_close_blockers_only_with_valid_refs():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-2",
        decision_posture="patch_required",
        evidence_refs=["ev-test-1"],
        required_blockers=["test_evidence"],
    )

    with pytest.raises(DecisionControlError):
        record_event(source_pack, current_state, {
            "event_type": "evidence_accepted",
            "evidence_ref": "ev-not-in-pack",
            "blocker": "test_evidence",
            "evidence_state": "accepted_positive_evidence",
        })

    next_state = record_event(source_pack, current_state, {
        "event_type": "evidence_accepted",
        "evidence_ref": "ev-test-1",
        "blocker": "test_evidence",
        "evidence_state": "accepted_positive_evidence",
    })
    assert "test_evidence" not in next_state.blockers
    assert "test_evidence" in current_state.blockers


def test_risk_acceptance_requires_owner_expiry_and_rationale():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-3",
        decision_posture="risk_accept_temporarily",
        evidence_refs=["ev-risk"],
        required_blockers=["risk_acceptance"],
    )

    with pytest.raises(DecisionControlError):
        record_event(source_pack, current_state, {
            "event_type": "risk_acceptance_recorded",
            "owner": "risk-owner",
            "expiry_date": "2026-06-30",
        })

    next_state = record_event(source_pack, current_state, {
        "event_type": "risk_acceptance_recorded",
        "owner": "risk-owner",
        "expiry_date": "2026-06-30",
        "rationale": "Maintenance window constrained.",
    })
    assert next_state.risk_acceptance["owner"] == "risk-owner"
    assert next_state.risk_acceptance["expired"] is False


def test_risk_acceptance_expiry_works():
    assert risk_acceptance_expired("2026-05-25", today=date(2026, 5, 26)) is True
    assert risk_acceptance_expired("2026-05-27", today=date(2026, 5, 26)) is False
    assert risk_acceptance_expired("2026-05-25T10:00:00Z", today=date(2026, 5, 26)) is True
    with pytest.raises(DecisionControlError):
        risk_acceptance_expired("not-a-date")


def test_expired_risk_acceptance_is_rejected_at_recording_time():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-expired",
        decision_posture="risk_accept_temporarily",
        evidence_refs=["ev-risk"],
        required_blockers=["risk_acceptance"],
    )

    with pytest.raises(DecisionControlError):
        record_event(source_pack, current_state, {
            "event_type": "risk_acceptance_recorded",
            "owner": "risk-owner",
            "expiry_date": "2020-01-01",
            "rationale": "Expired acceptance must not enter governed state.",
        })

    # Expired acceptances never reach posture/readiness/state derivation.
    assert current_state.risk_acceptance is None
    assert "risk_acceptance" in current_state.blockers
    assert current_state.event_ledger == []


def test_risk_acceptance_accepts_expires_at_alias():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-alias",
        decision_posture="risk_accept_temporarily",
        evidence_refs=["ev-risk"],
        required_blockers=["risk_acceptance"],
    )

    next_state = record_event(source_pack, current_state, {
        "event_type": "risk_acceptance_recorded",
        "owner": "risk-owner",
        "expires_at": "2099-12-31T00:00:00Z",
        "rationale": "Future-dated acceptance recorded via expires_at alias.",
    })
    assert next_state.risk_acceptance["expired"] is False
    assert next_state.risk_acceptance["expiry_date"] == "2099-12-31T00:00:00Z"
    assert "risk_acceptance" not in next_state.blockers

    with pytest.raises(DecisionControlError):
        record_event(source_pack, current_state, {
            "event_type": "risk_acceptance_recorded",
            "owner": "risk-owner",
            "expires_at": "2020-01-01T00:00:00Z",
            "rationale": "Past expires_at must raise.",
        })


def test_current_state_is_separate_from_signed_source_state():
    source_pack, current_state = compile_source_pack(
        decision_id="decision-4",
        decision_posture="close_verified",
        evidence_refs=["ev-validation"],
        required_blockers=["post_patch_validation", "human_approval"],
    )

    after_validation = record_event(source_pack, current_state, {
        "event_type": "post_patch_validation_recorded",
        "validation_evidence_ref": "ev-validation",
        "outcome_state": "implemented",
        "reviewed_by": "service-owner",
    })
    after_approval = record_event(source_pack, after_validation, {
        "event_type": "human_approval",
        "approval_type": "final",
        "approval_state": "approved",
        "approver": "cab-chair",
    })

    assert source_pack.blockers == ("post_patch_validation", "human_approval")
    assert after_approval.blockers == []
    assert after_approval.final_approval_issued is True
    assert len(after_approval.event_ledger) == 2


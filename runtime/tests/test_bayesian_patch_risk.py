import pytest

from runtime.bayesian_patch_risk import (
    MODEL_TYPE,
    RECOGNIZED_RISK_INPUTS,
    assess_patch_risk,
    build_prior_usage_manifest,
    propose_prior_update,
    record_patch_outcome,
)


FULL_INPUTS = {
    "cvss": 9.8,
    "epss": 0.82,
    "known_exploited": True,
    "active_exploitation_reports": True,
    "exploit_code_available": False,
    "internet_exposed": True,
    "customer_facing": True,
    "service_tier": "tier_1",
    "asset_criticality": "critical",
    "ot_relevant": False,
    "patch_status": "patch_available",
    "test_evidence_complete": True,
    "rollback_evidence": True,
    "vendor_patch_note": True,
    "compensating_controls": False,
}

POSTERIOR_FACTORS = [
    "exploit_probability",
    "business_impact",
    "patch_feasibility",
    "change_risk",
    "deferral_risk",
]


def test_snapshot_self_describes_as_weighted_heuristic_not_bayesian():
    snapshot = assess_patch_risk(FULL_INPUTS)
    assert snapshot["model_type"] == MODEL_TYPE == "weighted_heuristic_risk_model"
    assert snapshot["is_bayesian_inference"] is False

    manifest = build_prior_usage_manifest()
    assert manifest["model_type"] == MODEL_TYPE
    assert manifest["is_bayesian_inference"] is False

    proposal = propose_prior_update([])
    assert proposal["model_type"] == MODEL_TYPE
    assert proposal["is_bayesian_inference"] is False


def test_uncertainty_bands_present_for_every_posterior_and_clamped():
    snapshot = assess_patch_risk(FULL_INPUTS)
    assert set(snapshot["posterior_uncertainty"]) == set(POSTERIOR_FACTORS)
    for factor in POSTERIOR_FACTORS:
        band = snapshot["posterior_uncertainty"][factor]
        point = snapshot[f"{factor}_posterior"]
        assert 0 <= band["low"] <= point <= band["high"] <= 1


def test_uncertainty_bands_widen_with_fewer_supplied_inputs():
    full = assess_patch_risk(FULL_INPUTS)
    sparse = assess_patch_risk({"cvss": 9.8, "patch_status": "patch_available"})

    assert full["uncertainty"]["unknown_input_count"] == 0
    assert full["uncertainty"]["band_half_width"] == pytest.approx(0.05)
    assert sparse["uncertainty"]["unknown_input_count"] == len(RECOGNIZED_RISK_INPUTS) - 2
    expected = 0.05 + 0.30 * ((len(RECOGNIZED_RISK_INPUTS) - 2) / len(RECOGNIZED_RISK_INPUTS))
    assert sparse["uncertainty"]["band_half_width"] == pytest.approx(expected, abs=0.001)
    assert sparse["uncertainty"]["band_half_width"] > full["uncertainty"]["band_half_width"]

    full_band = full["posterior_uncertainty"]["change_risk"]
    sparse_band = sparse["posterior_uncertainty"]["change_risk"]
    assert (sparse_band["high"] - sparse_band["low"]) > (full_band["high"] - full_band["low"])


def test_cvss_score_alias_counts_as_supplied_input():
    by_alias = assess_patch_risk({"cvss_score": 9.8})
    assert "cvss" not in by_alias["uncertainty"]["unknown_inputs"]


def test_point_posteriors_unchanged_by_uncertainty_band_addition():
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
    snapshot = assess_patch_risk(inputs)
    # Existing point values stay backward compatible (bands are additive only).
    assert snapshot["exploit_probability_posterior"] == pytest.approx(0.844, abs=0.001)
    assert snapshot["recommended_governance_posture"] == "emergency_change_required"


def test_record_patch_outcome_appends_governed_observations():
    state: dict = {}
    observation = record_patch_outcome(state, "patched_successfully")
    record_patch_outcome(state, "rolled_back")
    record_patch_outcome(state, "no_action")

    assert len(state["outcome_observations"]) == 3
    assert observation["outcome"] == "patched_successfully"
    assert observation["recorded_at"]
    assert observation["live_prior_mutation_performed"] is False

    with pytest.raises(ValueError):
        record_patch_outcome(state, "deployed_patch")
    assert len(state["outcome_observations"]) == 3


def test_prior_proposal_uses_outcomes_but_remains_dry_run_only():
    state: dict = {}
    for outcome in ["patched_successfully", "patched_successfully", "patch_failed", "no_action"]:
        record_patch_outcome(state, outcome)

    proposal = propose_prior_update(state["outcome_observations"])
    assert proposal["dry_run"] is True
    assert proposal["live_update_applied"] is False
    assert proposal["admin_approval_required"] is True
    assert proposal["observed_outcome_count"] == 4
    assert proposal["outcome_counts"] == {
        "no_action": 1,
        "patch_failed": 1,
        "patched_successfully": 2,
        "rolled_back": 0,
    }
    assert proposal["proposed_prior_deltas"]["patch_feasibility_prior"] == pytest.approx(0.025, abs=0.001)
    assert proposal["proposed_prior_deltas"]["change_risk_prior"] == pytest.approx(0.0, abs=0.001)
    assert proposal["proposed_prior_deltas"]["deferral_risk_prior"] == pytest.approx(0.0125, abs=0.001)


def test_prior_proposal_with_no_observations_proposes_zero_deltas():
    proposal = propose_prior_update()
    assert proposal["observed_outcome_count"] == 0
    assert all(delta == 0.0 for delta in proposal["proposed_prior_deltas"].values())
    assert proposal["dry_run"] is True
    assert proposal["live_update_applied"] is False

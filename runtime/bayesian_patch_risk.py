from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


MODEL_TYPE = "weighted_heuristic_risk_model"

VALID_PATCH_OUTCOMES = {"patched_successfully", "rolled_back", "patch_failed", "no_action"}

# Full recognized input set consumed by assess_patch_risk. Inputs absent from the
# supplied evidence dict count as unknown and widen the posterior uncertainty bands.
RECOGNIZED_RISK_INPUTS = (
    "cvss",
    "epss",
    "known_exploited",
    "active_exploitation_reports",
    "exploit_code_available",
    "internet_exposed",
    "customer_facing",
    "service_tier",
    "asset_criticality",
    "ot_relevant",
    "patch_status",
    "test_evidence_complete",
    "rollback_evidence",
    "vendor_patch_note",
    "compensating_controls",
)

# Input aliases: any alias present counts the canonical input as supplied.
_INPUT_ALIASES = {"cvss": ("cvss", "cvss_score")}


@dataclass(frozen=True)
class PatchRiskPriors:
    prior_set_id: str = "patchforge-default-v1"
    exploit_probability_prior: float = 0.18
    business_impact_prior: float = 0.35
    patch_feasibility_prior: float = 0.55
    change_risk_prior: float = 0.32
    deferral_risk_prior: float = 0.28


def assess_patch_risk(inputs: dict[str, Any], priors: PatchRiskPriors | None = None) -> dict[str, Any]:
    """Return deterministic advisory patch risk posteriors.

    Honesty note: this is a weighted heuristic risk model, not Bayesian
    inference. Every snapshot self-describes with
    ``model_type: "weighted_heuristic_risk_model"`` and
    ``is_bayesian_inference: False``, and carries per-posterior uncertainty
    bands that widen as more recognized inputs are missing.
    """
    priors = priors or PatchRiskPriors()
    cvss = float(inputs.get("cvss") or inputs.get("cvss_score") or 0)
    epss = _clamp(float(inputs.get("epss") or 0), 0, 1)
    exploit_probability = priors.exploit_probability_prior + sum(
        [
            0.32 if inputs.get("known_exploited") else 0,
            0.18 if inputs.get("active_exploitation_reports") else 0,
            0.12 if inputs.get("exploit_code_available") else 0,
            0.12 if inputs.get("internet_exposed") else 0,
            epss * 0.2,
            0.06 if cvss >= 9 else 0.03 if cvss >= 7 else 0,
        ]
    )
    business_impact = priors.business_impact_prior + sum(
        [
            0.2 if inputs.get("customer_facing") else 0,
            0.16 if "1" in str(inputs.get("service_tier", "")).lower() else 0,
            0.16 if "critical" in str(inputs.get("asset_criticality", "")).lower() else 0,
            0.12 if inputs.get("ot_relevant") else 0,
        ]
    )
    patch_status = str(inputs.get("patch_status", "unknown"))
    patch_feasibility = priors.patch_feasibility_prior + sum(
        [
            0.22 if patch_status in {"patch_available", "patch_feasible"} else -0.18,
            0.1 if inputs.get("test_evidence_complete") else -0.05,
            0.08 if inputs.get("rollback_evidence") else -0.05,
            0.05 if inputs.get("vendor_patch_note") else 0,
        ]
    )
    change_risk = priors.change_risk_prior + sum(
        [
            0.2 if inputs.get("ot_relevant") else 0,
            -0.08 if inputs.get("rollback_evidence") else 0.12,
            -0.06 if inputs.get("test_evidence_complete") else 0.08,
        ]
    )
    deferral_risk = priors.deferral_risk_prior + exploit_probability * 0.35 + business_impact * 0.25
    if inputs.get("compensating_controls"):
        deferral_risk -= 0.08

    unknown_inputs = _unknown_inputs(inputs)
    half_width = _uncertainty_half_width(unknown_inputs)
    posteriors = {
        "exploit_probability": _round(_clamp(exploit_probability, 0, 0.98)),
        "business_impact": _round(_clamp(business_impact, 0, 0.98)),
        "patch_feasibility": _round(_clamp(patch_feasibility, 0.02, 0.98)),
        "change_risk": _round(_clamp(change_risk, 0.02, 0.98)),
        "deferral_risk": _round(_clamp(deferral_risk, 0.02, 0.98)),
    }

    snapshot = {
        "snapshot_id": f"bayes-{uuid4()}",
        "generated_at": _now(),
        "model_type": MODEL_TYPE,
        "is_bayesian_inference": False,
        "advisory_only": True,
        "can_close_hard_gates_alone": False,
        "final_approval_issued": False,
        **{f"{factor}_posterior": value for factor, value in posteriors.items()},
        "posterior_uncertainty": {
            factor: _uncertainty_band(value, half_width) for factor, value in posteriors.items()
        },
        "uncertainty": {
            "band_half_width": _round(half_width),
            "unknown_inputs": unknown_inputs,
            "unknown_input_count": len(unknown_inputs),
            "total_input_count": len(RECOGNIZED_RISK_INPUTS),
        },
        "prior_usage": build_prior_usage_manifest(priors),
        "boundary": {
            "no_autonomous_approval": True,
            "no_patch_deployment": True,
            "prior_update_dry_run_only": True,
        },
    }
    snapshot["recommended_governance_posture"] = _recommended_posture(snapshot, patch_status)
    return snapshot


def _unknown_inputs(inputs: dict[str, Any]) -> list[str]:
    unknown = []
    for name in RECOGNIZED_RISK_INPUTS:
        aliases = _INPUT_ALIASES.get(name, (name,))
        if not any(alias in inputs for alias in aliases):
            unknown.append(name)
    return unknown


def _uncertainty_half_width(unknown_inputs: list[str]) -> float:
    return 0.05 + 0.30 * (len(unknown_inputs) / len(RECOGNIZED_RISK_INPUTS))


def _uncertainty_band(posterior: float, half_width: float) -> dict[str, float]:
    return {
        "low": _round(_clamp(posterior - half_width, 0, 1)),
        "high": _round(_clamp(posterior + half_width, 0, 1)),
    }


def build_prior_usage_manifest(priors: PatchRiskPriors | None = None) -> dict[str, Any]:
    priors = priors or PatchRiskPriors()
    return {
        "prior_usage_id": f"prior-{uuid4()}",
        "prior_set_id": priors.prior_set_id,
        "model_type": MODEL_TYPE,
        "is_bayesian_inference": False,
        "advisory_only": True,
        "dry_run_only": True,
        "live_prior_mutation_performed": False,
    }


def record_patch_outcome(state: dict[str, Any], outcome: str) -> dict[str, Any]:
    """Append a governed patch outcome observation to ``state["outcome_observations"]``.

    GOVERNANCE LOCK: outcome observations are evidence only. Recording an
    outcome never mutates live priors; priors only ever change through a
    human-approved process outside this module. ``outcome`` must be one of
    VALID_PATCH_OUTCOMES.
    """
    if not isinstance(state, dict):
        raise ValueError("Patch outcome state must be a dict.")
    if outcome not in VALID_PATCH_OUTCOMES:
        raise ValueError(
            f"Unknown patch outcome: {outcome}. Expected one of {sorted(VALID_PATCH_OUTCOMES)}."
        )
    observation = {
        "observation_id": f"outcome-{uuid4()}",
        "outcome": outcome,
        "recorded_at": _now(),
        "model_type": MODEL_TYPE,
        "is_bayesian_inference": False,
        "advisory_only": True,
        "live_prior_mutation_performed": False,
    }
    state.setdefault("outcome_observations", []).append(observation)
    return observation


def propose_prior_update(observed_outcomes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Propose prior deltas from accumulated outcome observations.

    GOVERNANCE LOCK: this is dry-run/proposal-only by design. The proposal
    computes simple frequency-based deltas from observed outcomes but never
    applies them: ``live_update_applied`` is always False, ``dry_run`` is
    always True, and admin approval is always required before any human
    applies a prior change elsewhere.
    """
    observations = observed_outcomes or []
    counts = {outcome: 0 for outcome in sorted(VALID_PATCH_OUTCOMES)}
    for observation in observations:
        outcome = observation.get("outcome") if isinstance(observation, dict) else None
        if outcome in counts:
            counts[outcome] += 1
    total = sum(counts.values())

    deltas = {
        "exploit_probability_prior": 0.0,
        "business_impact_prior": 0.0,
        "patch_feasibility_prior": 0.0,
        "change_risk_prior": 0.0,
        "deferral_risk_prior": 0.0,
    }
    if total:
        success_rate = counts["patched_successfully"] / total
        failure_rate = (counts["patch_failed"] + counts["rolled_back"]) / total
        no_action_rate = counts["no_action"] / total
        deltas["patch_feasibility_prior"] = _round(0.10 * success_rate - 0.10 * failure_rate)
        deltas["change_risk_prior"] = _round(0.10 * failure_rate - 0.05 * success_rate)
        deltas["deferral_risk_prior"] = _round(0.05 * no_action_rate)

    return {
        "proposal_id": f"prior-proposal-{uuid4()}",
        "generated_at": _now(),
        "model_type": MODEL_TYPE,
        "is_bayesian_inference": False,
        "dry_run": True,
        "live_update_applied": False,
        "admin_approval_required": True,
        "observed_outcome_count": len(observations),
        "outcome_counts": counts,
        "proposed_prior_deltas": deltas,
        "proposed_adjustments": {
            prior: f"{delta:+.3f}" if delta else "0.000" for prior, delta in deltas.items()
        },
        "governance_lock": "Dry-run proposal only. Live prior mutation is never performed by the runtime.",
    }


def _recommended_posture(snapshot: dict[str, Any], patch_status: str) -> str:
    if snapshot["exploit_probability_posterior"] >= 0.7 and patch_status == "patch_available":
        return "emergency_change_required"
    if snapshot["deferral_risk_posterior"] >= 0.65 and patch_status == "patch_available":
        return "patch_required"
    if snapshot["change_risk_posterior"] >= 0.7:
        return "mitigate_temporarily"
    return "defer_pending_evidence"


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def _round(value: float) -> float:
    return round(value, 3)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

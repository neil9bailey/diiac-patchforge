from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class PatchRiskPriors:
    prior_set_id: str = "patchforge-default-v1"
    exploit_probability_prior: float = 0.18
    business_impact_prior: float = 0.35
    patch_feasibility_prior: float = 0.55
    change_risk_prior: float = 0.32
    deferral_risk_prior: float = 0.28


def assess_patch_risk(inputs: dict[str, Any], priors: PatchRiskPriors | None = None) -> dict[str, Any]:
    """Return deterministic advisory Bayesian-style patch risk posteriors."""
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

    snapshot = {
        "snapshot_id": f"bayes-{uuid4()}",
        "generated_at": _now(),
        "advisory_only": True,
        "can_close_hard_gates_alone": False,
        "final_approval_issued": False,
        "exploit_probability_posterior": _round(_clamp(exploit_probability, 0, 0.98)),
        "business_impact_posterior": _round(_clamp(business_impact, 0, 0.98)),
        "patch_feasibility_posterior": _round(_clamp(patch_feasibility, 0.02, 0.98)),
        "change_risk_posterior": _round(_clamp(change_risk, 0.02, 0.98)),
        "deferral_risk_posterior": _round(_clamp(deferral_risk, 0.02, 0.98)),
        "prior_usage": build_prior_usage_manifest(priors),
        "boundary": {
            "no_autonomous_approval": True,
            "no_patch_deployment": True,
            "prior_update_dry_run_only": True,
        },
    }
    snapshot["recommended_governance_posture"] = _recommended_posture(snapshot, patch_status)
    return snapshot


def build_prior_usage_manifest(priors: PatchRiskPriors | None = None) -> dict[str, Any]:
    priors = priors or PatchRiskPriors()
    return {
        "prior_usage_id": f"prior-{uuid4()}",
        "prior_set_id": priors.prior_set_id,
        "advisory_only": True,
        "dry_run_only": True,
        "live_prior_mutation_performed": False,
    }


def propose_prior_update(observed_outcomes: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "proposal_id": f"prior-proposal-{uuid4()}",
        "generated_at": _now(),
        "dry_run": True,
        "live_update_applied": False,
        "admin_approval_required": True,
        "observed_outcome_count": len(observed_outcomes or []),
        "proposed_adjustments": {
            "exploit_probability_prior": "+0.01" if observed_outcomes else "0.00",
            "change_risk_prior": "+0.01" if observed_outcomes else "0.00",
        },
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

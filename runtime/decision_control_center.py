from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any
from uuid import uuid4


class DecisionControlError(ValueError):
    """Raised when a DCC event violates PatchForge governance rules."""


@dataclass(frozen=True)
class SourcePack:
    source_pack_id: str
    decision_id: str
    evidence_refs: tuple[str, ...]
    blockers: tuple[str, ...]
    immutable: bool = True
    signed_source_pack_preserved: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat())


@dataclass
class CurrentState:
    decision_id: str
    decision_posture: str
    blockers: list[str]
    final_approval_issued: bool = False
    risk_acceptance: dict[str, Any] | None = None
    post_patch_validation: dict[str, Any] | None = None
    event_ledger: list[dict[str, Any]] = field(default_factory=list)


def compile_source_pack(
    decision_id: str,
    decision_posture: str,
    evidence_refs: list[str] | None = None,
    required_blockers: list[str] | None = None,
) -> tuple[SourcePack, CurrentState]:
    refs = tuple(evidence_refs or [])
    blockers = tuple(required_blockers or (["evidence_required"] if not refs else []))
    source_pack = SourcePack(
        source_pack_id=f"source-pack-{uuid4()}",
        decision_id=decision_id,
        evidence_refs=refs,
        blockers=blockers,
    )
    current_state = CurrentState(
        decision_id=decision_id,
        decision_posture=decision_posture,
        blockers=list(blockers),
        final_approval_issued=False,
    )
    return source_pack, current_state


def record_event(source_pack: SourcePack, current_state: CurrentState, event: dict[str, Any]) -> CurrentState:
    if not source_pack.immutable or not source_pack.signed_source_pack_preserved:
        raise DecisionControlError("Signed source pack must remain immutable and preserved.")
    if source_pack.decision_id != current_state.decision_id:
        raise DecisionControlError("Current state does not belong to the supplied source pack.")

    next_state = deepcopy(current_state)
    event_type = event.get("event_type")
    ledger_event = {
        **event,
        "event_id": event.get("event_id", f"event-{uuid4()}"),
        "created_at": event.get("created_at", datetime.now(timezone.utc).replace(microsecond=0).isoformat()),
    }

    if event_type == "evidence_accepted":
        close_evidence_blocker(source_pack, next_state, event)
    elif event_type == "human_approval":
        record_human_approval(next_state, event)
    elif event_type == "risk_acceptance_recorded":
        record_risk_acceptance(next_state, event)
    elif event_type == "post_patch_validation_recorded":
        record_post_patch_validation(source_pack, next_state, event)
    else:
        raise DecisionControlError(f"Unsupported DCC event type: {event_type}")

    next_state.event_ledger.append(ledger_event)
    return next_state


def close_evidence_blocker(source_pack: SourcePack, current_state: CurrentState, event: dict[str, Any]) -> None:
    evidence_ref = event.get("evidence_ref")
    blocker = event.get("blocker", "evidence_required")
    if evidence_ref not in source_pack.evidence_refs:
        raise DecisionControlError("Evidence events can close blockers only when the evidence ref exists in the signed source pack.")
    if event.get("evidence_state") != "accepted_positive_evidence":
        raise DecisionControlError("Evidence blocker requires accepted positive evidence.")
    if blocker in current_state.blockers:
        current_state.blockers.remove(blocker)


def record_human_approval(current_state: CurrentState, event: dict[str, Any]) -> None:
    if not event.get("approver") or event.get("approval_state") != "approved":
        raise DecisionControlError("Human approval requires approver and approved state.")
    if event.get("approval_type") == "final":
        current_state.final_approval_issued = True
        if "human_approval" in current_state.blockers:
            current_state.blockers.remove("human_approval")


def record_risk_acceptance(current_state: CurrentState, event: dict[str, Any]) -> None:
    required = ["owner", "expiry_date", "rationale"]
    missing = [field for field in required if not event.get(field)]
    if missing:
        raise DecisionControlError(f"Risk acceptance missing required fields: {', '.join(missing)}")
    current_state.risk_acceptance = {
        "owner": event["owner"],
        "expiry_date": event["expiry_date"],
        "rationale": event["rationale"],
        "expired": risk_acceptance_expired(event["expiry_date"]),
        "compensating_control_refs": event.get("compensating_control_refs", []),
    }
    if "risk_acceptance" in current_state.blockers and not current_state.risk_acceptance["expired"]:
        current_state.blockers.remove("risk_acceptance")


def record_post_patch_validation(source_pack: SourcePack, current_state: CurrentState, event: dict[str, Any]) -> None:
    evidence_ref = event.get("validation_evidence_ref")
    if evidence_ref not in source_pack.evidence_refs:
        raise DecisionControlError("Post-patch validation must reference evidence preserved in the signed source pack.")
    current_state.post_patch_validation = {
        "validation_evidence_ref": evidence_ref,
        "outcome_state": event.get("outcome_state", "implemented"),
        "reviewed_by": event.get("reviewed_by"),
    }
    if "post_patch_validation" in current_state.blockers:
        current_state.blockers.remove("post_patch_validation")


def risk_acceptance_expired(expiry_date: str, today: date | None = None) -> bool:
    check_date = today or date.today()
    return date.fromisoformat(expiry_date) < check_date


from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Protocol
from typing import Any
from uuid import uuid4
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_MODELS_PATH = REPO_ROOT / "contracts" / "evidence_models.json"
ADVISORY_SOURCE_CLASSES = {"sra_trace", "mcp_agent_finding", "mythos_finding", "agi_agent_finding"}

DECISION_POSTURES = {
    "patch_required",
    "emergency_change_required",
    "mitigate_temporarily",
    "risk_accept_temporarily",
    "defer_pending_evidence",
    "block_go_live",
    "patch_not_applicable",
    "close_verified",
}

PACK_ARTEFACTS = [
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
    "finding_intelligence_snapshot.json",
    "vendor_intelligence_snapshot.json",
    "threat_landscape_snapshot.json",
    "network_vendor_profile_snapshot.json",
    "customer_network_asset_snapshot.json",
    "vendor_security_advisory_snapshot.json",
    "config_applicability_assessment.json",
    "vendorlens_patch_comparison.json",
    "sra_config_chat_session.json",
    "vendorlens_decision_context.json",
    "sra_trace.json",
    "governance_manifest.json",
    "verification_manifest.json",
    "trust_bundle.json",
    "replay_certificate.json",
]

FORBIDDEN_ACTION_KEYS = {
    "exploit_code",
    "exploit_steps",
    "exploit_payload",
    "deployment_action",
    "patch_deployment_action",
    "production_mutation",
    "autonomous_approval",
}


class GovernanceRuntimeError(ValueError):
    """Raised when PatchForge governance input violates the product boundary."""


@dataclass(frozen=True)
class EvidenceEvaluation:
    model_name: str
    satisfied: list[str]
    blockers: list[str]
    rejected_refs: list[str]
    advisory_only_refs: list[str]
    readiness_score: int


class SigningProvider(Protocol):
    def sign(self, signed_payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        ...


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_evidence_models(path: Path = EVIDENCE_MODELS_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def ensure_boundary_safe(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in FORBIDDEN_ACTION_KEYS:
                raise GovernanceRuntimeError(f"Forbidden PatchForge boundary key: {key}")
            ensure_boundary_safe(nested)
    elif isinstance(value, list):
        for item in value:
            ensure_boundary_safe(item)


def classify_patch_decision_type(
    vulnerability: dict[str, Any],
    patch_availability: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
    requested_posture: str | None = None,
) -> str:
    if requested_posture:
        if requested_posture not in DECISION_POSTURES:
            raise GovernanceRuntimeError(f"Unknown decision posture: {requested_posture}")
        return requested_posture

    patch_status = (patch_availability or {}).get("status", vulnerability.get("patch_status", "unknown"))
    known_exploited = bool(vulnerability.get("known_exploited"))
    internet_exposed = bool(vulnerability.get("internet_exposed"))

    if known_exploited and internet_exposed and patch_status == "patch_available":
        return "emergency_change_required"
    if patch_status == "patch_available":
        return "patch_required"
    if patch_status in {"mitigation_only", "no_patch_available"} and controls:
        return "mitigate_temporarily"
    if vulnerability.get("go_live_blocker"):
        return "block_go_live"
    return "defer_pending_evidence"


def build_evidence_register(evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
    register: dict[str, Any] = {
        "items": [],
        "by_class": {},
        "rejected_refs": [],
        "advisory_only_refs": [],
    }

    for item in evidence_items:
        ensure_boundary_safe(item)
        evidence_ref = item.get("evidence_ref") or item.get("id") or f"evidence-{uuid4()}"
        evidence_class = item.get("evidence_class", "unknown")
        source_class = item.get("source_class", "unknown")
        review_state = item.get("review_state", "pending_review")
        evidence_state = item.get("evidence_state", "referenced")
        normalized = {
            **item,
            "evidence_ref": evidence_ref,
            "evidence_class": evidence_class,
            "source_class": source_class,
            "review_state": review_state,
            "evidence_state": evidence_state,
        }
        register["items"].append(normalized)
        register["by_class"].setdefault(evidence_class, []).append(normalized)

        if review_state == "rejected" or evidence_state == "rejected":
            register["rejected_refs"].append(evidence_ref)
        if source_class in ADVISORY_SOURCE_CLASSES or item.get("advisory_only") is True:
            register["advisory_only_refs"].append(evidence_ref)

    return register


def _accepted_positive(item: dict[str, Any], disallowed_sources: set[str]) -> bool:
    if item.get("review_state") == "rejected" or item.get("evidence_state") == "rejected":
        return False
    if item.get("expired") is True or item.get("review_state") in {"expired", "reopened", "stale", "invalidated"}:
        return False
    if item.get("server_owned") is True and item.get("source_class") == "human_evidence_submission" and item.get("replay_verified") is not True:
        return False
    if item.get("source_class") in disallowed_sources:
        return False
    if item.get("advisory_only") is True:
        return False
    return item.get("evidence_state") in {"accepted_positive_evidence", "reviewed", "attached"}


def _gate_closed(gate: str, register: dict[str, Any], disallowed_sources: set[str]) -> bool:
    items = register["by_class"].get(gate, [])
    return any(_accepted_positive(item, disallowed_sources) for item in items)


def apply_evidence_model(
    model_name: str,
    evidence_register: dict[str, Any],
    evidence_models: dict[str, Any] | None = None,
) -> EvidenceEvaluation:
    models = evidence_models or load_evidence_models()
    if model_name not in models["models"]:
        raise GovernanceRuntimeError(f"Unknown evidence model: {model_name}")

    model = models["models"][model_name]
    disallowed_sources = set(models.get("hard_gate_sources_disallowed_alone", []))
    satisfied: list[str] = []
    blockers: list[str] = []

    for gate in model.get("hard_gates", []):
        if _gate_closed(gate, evidence_register, disallowed_sources):
            satisfied.append(gate)
        else:
            blockers.append(gate)

    total = max(len(model.get("hard_gates", [])), 1)
    readiness_score = round((len(satisfied) / total) * 100)

    return EvidenceEvaluation(
        model_name=model_name,
        satisfied=satisfied,
        blockers=blockers,
        rejected_refs=evidence_register["rejected_refs"],
        advisory_only_refs=evidence_register["advisory_only_refs"],
        readiness_score=readiness_score,
    )


def has_final_approval(approval_events: list[dict[str, Any]] | None) -> bool:
    return any(
        event.get("approval_type") == "final"
        and event.get("approval_state") == "approved"
        and bool(event.get("approver"))
        and event.get("server_verified") is True
        and bool({"PatchForge.CABApprover", "PatchForge.Admin"} & set(event.get("actor_roles") or []))
        for event in (approval_events or [])
    )


def apply_policy_pack(
    decision_posture: str,
    evaluation: EvidenceEvaluation,
    approval_events: list[dict[str, Any]] | None = None,
    risk_acceptance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blockers = list(evaluation.blockers)
    trusted_final_approval_recorded = has_final_approval(approval_events)
    untrusted_final_approval_present = any(
        event.get("approval_type") == "final"
        and event.get("approval_state") == "approved"
        and not (
            event.get("server_verified") is True
            and bool({"PatchForge.CABApprover", "PatchForge.Admin"} & set(event.get("actor_roles") or []))
        )
        for event in (approval_events or [])
    )

    if untrusted_final_approval_present:
        blockers.append("untrusted_final_approval_event")

    if decision_posture == "emergency_change_required" and not trusted_final_approval_recorded:
        blockers.append("emergency_human_approval")

    if decision_posture == "risk_accept_temporarily":
        required = ["owner", "expiry_date", "rationale"]
        missing = [field for field in required if not (risk_acceptance or {}).get(field)]
        blockers.extend([f"risk_acceptance_{field}" for field in missing])
        expiry_date = (risk_acceptance or {}).get("expiry_date")
        if expiry_date and risk_acceptance_expired(expiry_date):
            blockers.append("risk_acceptance_expired")
        if not trusted_final_approval_recorded:
            blockers.append("risk_acceptance_human_approval")

    if decision_posture == "close_verified" and "post_patch_validation" not in evaluation.satisfied:
        blockers.append("post_patch_validation")

    blockers = sorted(set(blockers))
    final_approval_issued = trusted_final_approval_recorded and not blockers

    return {
        "decision_posture": decision_posture,
        "readiness_score": evaluation.readiness_score,
        "blockers": blockers,
        "satisfied": evaluation.satisfied,
        "final_approval_recorded": trusted_final_approval_recorded,
        "final_approval_issued": final_approval_issued,
        "rejected_refs": evaluation.rejected_refs,
        "advisory_only_refs": evaluation.advisory_only_refs,
    }


def risk_acceptance_expired(expiry_date: str, today: date | None = None) -> bool:
    try:
        expiry = date.fromisoformat(str(expiry_date))
    except (TypeError, ValueError):
        return True
    return expiry < (today or datetime.now(timezone.utc).date())


def calculate_readiness(policy_result: dict[str, Any]) -> dict[str, Any]:
    blockers = policy_result.get("blockers", [])
    if blockers:
        state = "blocked"
    elif policy_result.get("readiness_score", 0) >= 100:
        state = "ready"
    else:
        state = "ready_with_conditions"

    return {
        "readiness_state": state,
        "readiness_score": policy_result.get("readiness_score", 0),
        "blockers": blockers,
        "final_approval_issued": bool(policy_result.get("final_approval_issued", False)),
    }


def evidence_model_for_posture(decision_posture: str, requested_model: str) -> str:
    posture_models = {
        "emergency_change_required": "emergency_patch_change",
        "risk_accept_temporarily": "patch_risk_acceptance",
        "block_go_live": "service_transition_patch_readiness",
        "close_verified": "service_transition_patch_readiness",
    }
    return posture_models.get(decision_posture, requested_model)


def build_patch_decision_context(
    vulnerability: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    model_name: str = "vuln_patch_governance",
    patch_availability: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
    approval_events: list[dict[str, Any]] | None = None,
    risk_acceptance: dict[str, Any] | None = None,
    requested_posture: str | None = None,
) -> dict[str, Any]:
    ensure_boundary_safe(vulnerability)
    decision_posture = classify_patch_decision_type(vulnerability, patch_availability, controls, requested_posture)
    evidence_register = build_evidence_register(evidence_items)
    effective_model_name = evidence_model_for_posture(decision_posture, model_name)
    evaluation = apply_evidence_model(effective_model_name, evidence_register)
    policy_result = apply_policy_pack(decision_posture, evaluation, approval_events, risk_acceptance)
    readiness = calculate_readiness(policy_result)

    return {
        "tenant_id": vulnerability.get("tenant_id", "unknown"),
        "decision_id": f"decision-{uuid4()}",
        "vulnerability_id": vulnerability.get("vulnerability_id") or vulnerability.get("canonical_id"),
        "decision_posture": decision_posture,
        "evidence_model": effective_model_name,
        "evidence_refs": [item["evidence_ref"] for item in evidence_register["items"]],
        "blockers": readiness["blockers"],
        "readiness": readiness,
        "human_review_state": "approved" if readiness["final_approval_issued"] else "pending",
        "final_approval_issued": readiness["final_approval_issued"],
        "decision_rationale": "Deterministic PatchForge governance context compiled from source-bound evidence.",
        "created_at": now_utc(),
    }


def create_signed_decision_pack(
    output_dir: str | Path,
    vulnerability: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    model_name: str = "vuln_patch_governance",
    patch_availability: dict[str, Any] | None = None,
    patch_feasibility: dict[str, Any] | None = None,
    controls: dict[str, Any] | None = None,
    risk_acceptance: dict[str, Any] | None = None,
    approval_events: list[dict[str, Any]] | None = None,
    requested_posture: str | None = None,
    bayesian_snapshot: dict[str, Any] | None = None,
    patch_prior_usage_manifest: dict[str, Any] | None = None,
    patch_prior_update_proposal: dict[str, Any] | None = None,
    finding_intelligence_snapshot: dict[str, Any] | None = None,
    vendor_intelligence_snapshot: dict[str, Any] | None = None,
    threat_landscape_snapshot: dict[str, Any] | None = None,
    network_vendor_profile_snapshot: dict[str, Any] | None = None,
    customer_network_asset_snapshot: dict[str, Any] | None = None,
    vendor_security_advisory_snapshot: dict[str, Any] | None = None,
    config_applicability_assessment: dict[str, Any] | None = None,
    vendorlens_patch_comparison: dict[str, Any] | None = None,
    sra_config_chat_session: dict[str, Any] | None = None,
    vendorlens_decision_context: dict[str, Any] | None = None,
    sra_trace: dict[str, Any] | None = None,
    signing_key: bytes | str | None = None,
    key_vault_key_id: str | None = None,
    signing_provider: SigningProvider | None = None,
    dev_mode: bool = True,
) -> dict[str, Any]:
    pack_dir = Path(output_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)

    decision_context = build_patch_decision_context(
        vulnerability=vulnerability,
        evidence_items=evidence_items,
        model_name=model_name,
        patch_availability=patch_availability,
        controls=controls,
        approval_events=approval_events,
        risk_acceptance=risk_acceptance,
        requested_posture=requested_posture,
    )
    pack_id = f"PF-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid4().hex[:8]}"

    human_review_state = {
      "approval_events": approval_events or [],
      "final_approval_issued": decision_context["final_approval_issued"],
      "no_autonomous_approval": True
    }
    ensure_boundary_safe({**decision_context, "human_review_state_payload": human_review_state})

    artefact_payloads = {
        "vulnerability_intelligence_snapshot.json": vulnerability,
        "patch_decision_context.json": decision_context,
        "affected_asset_scope.json": {"evidence": _items_by_class(evidence_items, "affected_asset_scope")},
        "exploitability_assessment.json": {"evidence": _items_by_class(evidence_items, "exploitability_signal")},
        "patch_feasibility_assessment.json": patch_feasibility or {},
        "compensating_controls_plan.json": controls or {},
        "patch_change_readiness.json": decision_context["readiness"],
        "patch_risk_acceptance_state.json": risk_acceptance or {"final_approval_issued": False},
        "human_review_state.json": human_review_state,
        "bayesian_patch_risk_snapshot.json": bayesian_snapshot or {
            "available": False,
            "advisory_only": True,
            "can_close_hard_gates_alone": False,
            "final_approval_issued": False,
        },
        "patch_prior_usage_manifest.json": patch_prior_usage_manifest or {
            "prior_set_id": "not-generated",
            "advisory_only": True,
            "dry_run_only": True,
            "live_prior_mutation_performed": False,
        },
        "patch_prior_update_proposal.json": patch_prior_update_proposal or {
            "proposal_id": "not-generated",
            "dry_run": True,
            "live_update_applied": False,
            "admin_approval_required": True,
        },
        "finding_intelligence_snapshot.json": finding_intelligence_snapshot or {
            "available": False,
            "advisory_only": True,
            "human_approval_required": True,
            "no_exploit_code": True,
            "no_patch_deployment": True,
        },
        "vendor_intelligence_snapshot.json": vendor_intelligence_snapshot or {
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
            "available": False,
        },
        "threat_landscape_snapshot.json": threat_landscape_snapshot or {
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
            "available": False,
        },
        "network_vendor_profile_snapshot.json": network_vendor_profile_snapshot or {
            "available": False,
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
        },
        "customer_network_asset_snapshot.json": customer_network_asset_snapshot or {
            "available": False,
            "source_bound": True,
            "review_required": True,
        },
        "vendor_security_advisory_snapshot.json": vendor_security_advisory_snapshot or {
            "available": False,
            "source_bound": True,
            "review_required": True,
            "can_close_hard_gates_alone": False,
        },
        "config_applicability_assessment.json": config_applicability_assessment or {
            "available": False,
            "advisory_only": True,
            "human_review_required": True,
            "can_close_hard_gates_alone": False,
            "final_approval_issued": False,
        },
        "vendorlens_patch_comparison.json": vendorlens_patch_comparison or {
            "available": False,
            "advisory_only": True,
            "human_review_required": True,
            "can_close_hard_gates_alone": False,
            "final_approval_issued": False,
            "no_patch_deployment": True,
        },
        "sra_config_chat_session.json": sra_config_chat_session or {
            "available": False,
            "advisory_only": True,
            "human_review_required": True,
            "final_approval_issued": False,
        },
        "vendorlens_decision_context.json": vendorlens_decision_context or {
            "available": False,
            "source_bound": True,
            "advisory_only": True,
            "human_review_required": True,
            "final_approval_issued": False,
        },
        "sra_trace.json": sra_trace or {
            "advisory_only": True,
            "can_close_hard_gates_alone": False,
            "available": False,
        },
        "trust_bundle.json": {
            "signing_mode": "dev" if dev_mode else "azure_key_vault",
            "key_id": key_vault_key_id or ("dev-test-only" if dev_mode else None),
            "signature_scope": "artefact_integrity_not_source_truth"
        },
        "replay_certificate.json": {
            "pack_id": pack_id,
            "created_at": now_utc(),
            "source_pack_immutable": True
        }
    }

    for file_name, payload in artefact_payloads.items():
        _write_json(pack_dir / file_name, payload)

    artefacts = _hash_artefacts(pack_dir, artefact_payloads.keys())
    governance_manifest = {
        "tenant_id": decision_context["tenant_id"],
        "pack_id": pack_id,
        "decision_id": decision_context["decision_id"],
        "decision_posture": decision_context["decision_posture"],
        "source_pack_immutable": True,
        "final_approval_issued": decision_context["final_approval_issued"],
        "artefacts": artefacts,
        "boundary": {
            "no_scanner": True,
            "no_exploit_generation": True,
            "no_patch_deployment": True,
            "no_production_mutation": True,
            "no_autonomous_approval": True
        },
        "created_at": now_utc()
    }
    _write_json(pack_dir / "governance_manifest.json", governance_manifest)

    verification_manifest = {
        "pack_id": pack_id,
        "governance_manifest_sha256": _sha256_file(pack_dir / "governance_manifest.json"),
        "expected_artefacts": PACK_ARTEFACTS,
        "verification_scope": "local_artefact_hashes_and_signature"
    }
    _write_json(pack_dir / "verification_manifest.json", verification_manifest)

    signed_payload = {
        "pack_id": pack_id,
        "governance_manifest_sha256": verification_manifest["governance_manifest_sha256"],
        "verification_manifest_sha256": _sha256_file(pack_dir / "verification_manifest.json")
    }
    signature, sigmeta = _sign_payload(
        signed_payload,
        signing_key=signing_key,
        key_vault_key_id=key_vault_key_id,
        signing_provider=signing_provider,
        dev_mode=dev_mode,
    )
    _write_json(pack_dir / "signed_export.sigmeta.json", sigmeta)
    (pack_dir / "signed_export.sig").write_text(signature, encoding="utf-8")

    return {
        "pack_id": pack_id,
        "pack_dir": str(pack_dir),
        "decision_context": decision_context,
        "verification": verify_pack_locally(pack_dir, dev_key=sigmeta.get("dev_key_hint"))
    }


def verify_pack_locally(pack_dir: str | Path, dev_key: str | None = None) -> dict[str, Any]:
    pack_path = Path(pack_dir)
    governance_manifest = _read_json(pack_path / "governance_manifest.json")
    verification_manifest = _read_json(pack_path / "verification_manifest.json")
    sigmeta = _read_json(pack_path / "signed_export.sigmeta.json")
    signature = (pack_path / "signed_export.sig").read_text(encoding="utf-8")

    artefact_results = []
    for artefact in governance_manifest["artefacts"]:
        actual = _sha256_file(pack_path / artefact["name"])
        artefact_results.append({
            "name": artefact["name"],
            "expected": artefact["sha256"],
            "actual": actual,
            "ok": actual == artefact["sha256"]
        })

    manifest_ok = _sha256_file(pack_path / "governance_manifest.json") == verification_manifest["governance_manifest_sha256"]
    signature_ok = _verify_signature(sigmeta, signature, dev_key=dev_key)

    return {
        "verified": bool(manifest_ok and signature_ok and all(item["ok"] for item in artefact_results)),
        "manifest_ok": manifest_ok,
        "signature_ok": signature_ok,
        "artefacts": artefact_results
    }


def create_signed_export_manifest(
    pack_id: str,
    tenant_id: str,
    artefacts: list[dict[str, Any]],
    governance_manifest_sha256: str,
    final_approval_issued: bool = False,
    created_at: str | None = None,
    signing_key: bytes | str | None = None,
    key_vault_key_id: str | None = None,
    signing_provider: SigningProvider | None = None,
    dev_mode: bool = True,
) -> dict[str, Any]:
    """Sign exact exported-file descriptors without changing governance state."""
    if not pack_id or not tenant_id:
        raise GovernanceRuntimeError("Export manifests require tenant_id and pack_id.")
    if not _is_sha256(governance_manifest_sha256):
        raise GovernanceRuntimeError("Export manifests require a valid governance manifest SHA-256.")
    if not isinstance(final_approval_issued, bool):
        raise GovernanceRuntimeError("Export manifest final_approval_issued must be a boolean copied from the source pack.")
    normalized_artefacts = _validate_export_artefacts(artefacts)
    unsigned_manifest = {
        "manifest_version": "patchforge-export-manifest-v1",
        "tenant_id": str(tenant_id),
        "pack_id": str(pack_id),
        "governance_manifest_sha256": governance_manifest_sha256.lower(),
        "artefact_count": len(normalized_artefacts),
        "artefacts": normalized_artefacts,
        "source_pack_immutable": True,
        "final_approval_issued": final_approval_issued,
        "human_approval_boundary": {
            "state_preserved_from_source_pack": True,
            "no_autonomous_approval": True,
            "manifest_does_not_issue_approval": True,
            "human_review_required_when_not_approved": not final_approval_issued,
        },
        "created_at": created_at or now_utc(),
    }
    manifest_id = f"PF-EXPORT-{sha256_json(unsigned_manifest)[:20]}"
    manifest = {"manifest_id": manifest_id, **unsigned_manifest}
    manifest_sha256 = sha256_json(manifest)
    signed_payload = {
        "manifest_id": manifest_id,
        "manifest_sha256": manifest_sha256,
        "pack_id": str(pack_id),
        "governance_manifest_sha256": governance_manifest_sha256.lower(),
    }
    signature, sigmeta = _sign_payload(
        signed_payload,
        signing_key=signing_key,
        key_vault_key_id=key_vault_key_id,
        signing_provider=signing_provider,
        dev_mode=dev_mode,
    )
    result = {
        "manifest": manifest,
        "manifest_sha256": manifest_sha256,
        "signature": signature,
        "signature_metadata": sigmeta,
    }
    result["verification"] = verify_signed_export_manifest(result, dev_key=sigmeta.get("dev_key_hint"))
    return result


def verify_signed_export_manifest(bundle: dict[str, Any], dev_key: str | None = None) -> dict[str, Any]:
    manifest = bundle.get("manifest") if isinstance(bundle, dict) else None
    sigmeta = bundle.get("signature_metadata") if isinstance(bundle, dict) else None
    signature = bundle.get("signature") if isinstance(bundle, dict) else None
    if not isinstance(manifest, dict) or not isinstance(sigmeta, dict) or not isinstance(signature, str):
        return {"verified": False, "manifest_ok": False, "signature_ok": False, "artefact_descriptors_ok": False}
    try:
        normalized = _validate_export_artefacts(manifest.get("artefacts"))
        descriptors_ok = normalized == manifest.get("artefacts") and manifest.get("artefact_count") == len(normalized)
    except GovernanceRuntimeError:
        descriptors_ok = False
    actual_manifest_hash = sha256_json(manifest)
    signed_payload = sigmeta.get("signed_payload") if isinstance(sigmeta.get("signed_payload"), dict) else {}
    manifest_ok = bool(
        bundle.get("manifest_sha256") == actual_manifest_hash
        and signed_payload.get("manifest_sha256") == actual_manifest_hash
        and signed_payload.get("manifest_id") == manifest.get("manifest_id")
        and signed_payload.get("pack_id") == manifest.get("pack_id")
        and signed_payload.get("governance_manifest_sha256") == manifest.get("governance_manifest_sha256")
    )
    signature_ok = _verify_signature(sigmeta, signature, dev_key=dev_key) if manifest_ok else False
    return {
        "verified": bool(manifest_ok and signature_ok and descriptors_ok),
        "manifest_ok": manifest_ok,
        "signature_ok": signature_ok,
        "artefact_descriptors_ok": descriptors_ok,
        "manifest_sha256": actual_manifest_hash,
    }


def _validate_export_artefacts(artefacts: Any) -> list[dict[str, Any]]:
    if not isinstance(artefacts, list) or not artefacts:
        raise GovernanceRuntimeError("Export manifests require at least one artefact descriptor.")
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    media_by_extension = {
        ".zip": {"application/zip"},
        ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        ".pdf": {"application/pdf"},
        ".json": {"application/json"},
        ".sig": {"text/plain", "application/octet-stream"},
    }
    for item in artefacts:
        if not isinstance(item, dict):
            raise GovernanceRuntimeError("Export artefact descriptors must be objects.")
        name = str(item.get("name") or "")
        if not name or len(name) > 180 or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
            raise GovernanceRuntimeError(f"Unsafe export artefact name: {name or 'missing'}")
        if name in names:
            raise GovernanceRuntimeError(f"Duplicate export artefact name: {name}")
        extension = Path(name).suffix.lower()
        media_type = str(item.get("media_type") or "").lower()
        if extension not in media_by_extension or media_type not in media_by_extension[extension]:
            raise GovernanceRuntimeError(f"Unsupported export artefact media type for {name}.")
        digest = str(item.get("sha256") or "").lower()
        if not _is_sha256(digest):
            raise GovernanceRuntimeError(f"Invalid SHA-256 for export artefact {name}.")
        size_bytes = item.get("size_bytes")
        if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0 or size_bytes > 64 * 1024 * 1024:
            raise GovernanceRuntimeError(f"Invalid size for export artefact {name}.")
        names.add(name)
        normalized.append({"name": name, "media_type": media_type, "sha256": digest, "size_bytes": size_bytes})
    return sorted(normalized, key=lambda item: item["name"])


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdefABCDEF" for character in text)


def _items_by_class(evidence_items: list[dict[str, Any]], evidence_class: str) -> list[dict[str, Any]]:
    return [item for item in evidence_items if item.get("evidence_class") == evidence_class]


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _hash_artefacts(pack_dir: Path, file_names: Any) -> list[dict[str, str]]:
    return [{"name": name, "sha256": _sha256_file(pack_dir / name)} for name in sorted(file_names)]


def _sign_payload(
    signed_payload: dict[str, Any],
    signing_key: bytes | str | None,
    key_vault_key_id: str | None,
    signing_provider: SigningProvider | None,
    dev_mode: bool,
) -> tuple[str, dict[str, Any]]:
    payload = canonical_json(signed_payload)

    if signing_provider:
        return signing_provider.sign(signed_payload)

    key_vault_key_id = key_vault_key_id or os.getenv("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID")
    if key_vault_key_id and not dev_mode:
        return _sign_payload_with_key_vault(signed_payload, key_vault_key_id)

    if signing_key and not dev_mode:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:  # pragma: no cover - optional production path
            raise GovernanceRuntimeError("Ed25519 signing requires the cryptography package.") from exc

        key_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise GovernanceRuntimeError("Production signing key must be Ed25519.")
        signature = private_key.sign(payload).hex()
        sigmeta = {
            "algorithm": "Ed25519",
            "key_id": "external-ed25519",
            "signed_payload": signed_payload,
            "dev_key_hint": None
        }
        return signature, sigmeta

    if not dev_mode:
        raise GovernanceRuntimeError("Production signing requires a Key Vault key ID or an Ed25519 signing key.")

    dev_key = os.getenv("PATCHFORGE_DEV_SIGNING_KEY", "patchforge-dev-test-key")
    signature = hmac.new(dev_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    sigmeta = {
        "algorithm": "dev_hmac_sha256",
        "key_id": "dev-test-only",
        "signed_payload": signed_payload,
        "dev_key_hint": dev_key,
        "warning": "Development/test signature only. Do not use as production signing trust."
    }
    return signature, sigmeta


def _verify_signature(sigmeta: dict[str, Any], signature: str, dev_key: str | None) -> bool:
    payload = canonical_json(sigmeta["signed_payload"])
    if sigmeta["algorithm"] == "dev_hmac_sha256":
        key = dev_key or sigmeta.get("dev_key_hint")
        if not key:
            return False
        expected = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    if sigmeta["algorithm"] == "Ed25519":  # pragma: no cover - verification needs public key plumbing later
        return False

    if sigmeta["algorithm"] == "ES256":
        return _verify_es256_signature(sigmeta, signature, payload)

    return False


def _sign_payload_with_key_vault(
    signed_payload: dict[str, Any],
    key_vault_key_id: str,
) -> tuple[str, dict[str, Any]]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
    except ImportError as exc:  # pragma: no cover - optional production path
        raise GovernanceRuntimeError(
            "Azure Key Vault signing requires azure-identity and azure-keyvault-keys."
        ) from exc

    payload = canonical_json(signed_payload)
    digest = hashlib.sha256(payload).digest()
    credential_kwargs = {}
    managed_identity_client_id = os.getenv("AZURE_CLIENT_ID")
    if managed_identity_client_id:
        credential_kwargs["managed_identity_client_id"] = managed_identity_client_id
    credential = DefaultAzureCredential(**credential_kwargs)
    crypto_client = CryptographyClient(key_vault_key_id, credential)
    sign_result = crypto_client.sign(SignatureAlgorithm.es256, digest)

    vault_url, key_name, key_version = _parse_key_vault_key_id(key_vault_key_id)
    key_client = KeyClient(vault_url=vault_url, credential=credential)
    key = key_client.get_key(key_name, key_version)
    public_jwk = _public_jwk_from_key_vault_key(key)

    sigmeta = {
        "algorithm": "ES256",
        "key_id": sign_result.key_id or key_vault_key_id,
        "signed_payload": signed_payload,
        "signature_encoding": "base64url_raw_ecdsa",
        "public_jwk": public_jwk,
        "dev_key_hint": None,
        "signing_provider": "azure_key_vault"
    }
    return _base64url_encode(sign_result.signature), sigmeta


def _parse_key_vault_key_id(key_id: str) -> tuple[str, str, str | None]:
    parsed = urlparse(key_id)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or parts[0] != "keys":
        raise GovernanceRuntimeError("Key Vault key ID must use the form https://<vault>/keys/<name>/<version>.")
    vault_url = f"{parsed.scheme}://{parsed.netloc}"
    key_name = parts[1]
    key_version = parts[2] if len(parts) > 2 else None
    return vault_url, key_name, key_version


def _public_jwk_from_key_vault_key(key: Any) -> dict[str, str]:
    jwk = key.key
    x_value = getattr(jwk, "x", None)
    y_value = getattr(jwk, "y", None)
    if x_value is None or y_value is None:
        raise GovernanceRuntimeError("Key Vault signing key must expose EC public key coordinates for local verification.")
    key_type = _azure_enum_value(getattr(jwk, "kty", None) or getattr(jwk, "key_type", None))
    curve = _azure_enum_value(getattr(jwk, "crv", None) or getattr(jwk, "curve", None))
    if key_type not in {"EC", "EC-HSM", "KeyType.ec", "KeyType.ec_hsm"}:
        raise GovernanceRuntimeError("Key Vault ES256 signing requires an EC key.")
    if curve not in {"P-256", "KeyCurveName.p_256"}:
        raise GovernanceRuntimeError("Key Vault ES256 signing requires the P-256 curve.")
    x_bytes = _bytes_from_key_material(x_value)
    y_bytes = _bytes_from_key_material(y_value)
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise GovernanceRuntimeError("Key Vault ES256 public key coordinates must each contain 32 bytes.")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url_encode(x_bytes),
        "y": _base64url_encode(y_bytes),
    }


def _azure_enum_value(value: Any) -> str:
    return str(getattr(value, "value", value)) if value is not None else ""


def _verify_es256_signature(sigmeta: dict[str, Any], signature: str, payload: bytes) -> bool:
    public_jwk = sigmeta.get("public_jwk")
    if not public_jwk or sigmeta.get("signature_encoding") != "base64url_raw_ecdsa":
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as exc:  # pragma: no cover - optional production path
        raise GovernanceRuntimeError("ES256 verification requires the cryptography package.") from exc

    try:
        normalized_jwk = _normalize_es256_public_jwk(public_jwk)
        x = int.from_bytes(_strict_base64url_decode(normalized_jwk["x"], 32), "big")
        y = int.from_bytes(_strict_base64url_decode(normalized_jwk["y"], 32), "big")
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        raw_signature = _strict_base64url_decode(signature, 64)
        r = int.from_bytes(raw_signature[:32], "big")
        s = int.from_bytes(raw_signature[32:], "big")
        signature_to_verify = utils.encode_dss_signature(r, s)
        public_key.verify(signature_to_verify, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, GovernanceRuntimeError, KeyError, TypeError, ValueError):
        return False


def _normalize_es256_public_jwk(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise GovernanceRuntimeError("ES256 public JWK is required.")
    key_type = str(value.get("kty") or "")
    curve = str(value.get("crv") or "")
    if key_type not in {"EC", "KeyType.ec", "KeyType.ec_hsm"}:
        raise GovernanceRuntimeError("ES256 public JWK must use an EC key.")
    if curve not in {"P-256", "KeyCurveName.p_256"}:
        raise GovernanceRuntimeError("ES256 public JWK must use the P-256 curve.")
    return {**value, "kty": "EC", "crv": "P-256"}


def _strict_base64url_decode(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise GovernanceRuntimeError("ES256 material must use unpadded base64url encoding.")
    decoded = _base64url_decode(value)
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise GovernanceRuntimeError("ES256 material has an invalid encoded length or noncanonical form.")
    return decoded


def _bytes_from_key_material(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return _base64url_decode(value)
    if isinstance(value, int):
        return value.to_bytes(32, "big")
    return bytes(value)


def _base64url_encode(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    import base64

    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

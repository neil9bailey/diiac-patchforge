import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = REPO_ROOT / "contracts" / "domain-models" / "patchforge"
EVIDENCE_MODELS = REPO_ROOT / "contracts" / "evidence_models.json"

EXPECTED_SCHEMAS = {
    "vulnerability_record.schema.json",
    "vulnerability_source_record.schema.json",
    "affected_asset_scope.schema.json",
    "affected_service_scope.schema.json",
    "exploitability_assessment.schema.json",
    "threat_intelligence_context.schema.json",
    "patch_availability.schema.json",
    "patch_feasibility_assessment.schema.json",
    "compensating_controls_plan.schema.json",
    "patch_change_readiness.schema.json",
    "patch_risk_acceptance_state.schema.json",
    "patch_decision_context.schema.json",
    "patch_outcome_feedback.schema.json",
    "sra_mcp_call_manifest.schema.json",
    "sra_research_trace.schema.json",
    "patch_decision_pack_manifest.schema.json",
    "bayesian_patch_risk_snapshot.schema.json",
    "patch_prior_usage_manifest.schema.json",
    "patch_prior_update_proposal.schema.json",
    "patch_learning_telemetry_snapshot.schema.json",
    "vendor_profile.schema.json",
    "product_profile.schema.json",
    "vendor_advisory.schema.json",
    "threat_landscape_signal.schema.json",
    "vendor_intelligence_snapshot.schema.json",
    "network_vendor_profile.schema.json",
    "network_product_family.schema.json",
    "network_product_model.schema.json",
    "network_firmware_version.schema.json",
    "vendor_security_advisory.schema.json",
    "vendor_cve_mapping.schema.json",
    "customer_network_asset.schema.json",
    "network_config_feature.schema.json",
    "config_applicability_assessment.schema.json",
    "network_vendor_patch_posture.schema.json",
    "sra_config_chat_session.schema.json",
    "sra_config_chat_message.schema.json",
    "vendorlens_decision_context.schema.json",
}

COMMON_REQUIRED_CLASSES = {
    "vulnerability_identity",
    "affected_asset_scope",
    "exploitability_signal",
    "threat_intelligence_context",
    "business_service_impact",
    "patch_availability",
    "patch_feasibility",
    "test_evidence",
    "rollback_plan",
    "compensating_controls",
    "change_window",
    "customer_impact",
    "risk_acceptance",
    "human_review_signoff",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def test_expected_schemas_exist_and_load():
    actual = {path.name for path in SCHEMA_DIR.glob("*.schema.json")}
    assert EXPECTED_SCHEMAS <= actual

    for schema_name in EXPECTED_SCHEMAS:
        schema = load_json(SCHEMA_DIR / schema_name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["type"] == "object"
        assert schema["title"].startswith("PatchForge")
        assert schema["required"]
        assert isinstance(schema["properties"], dict)


def test_risk_acceptance_schema_requires_owner_expiry_and_rationale():
    schema = load_json(SCHEMA_DIR / "patch_risk_acceptance_state.schema.json")
    required = set(schema["required"])
    assert {"owner", "expiry_date", "rationale", "approval_state"} <= required
    assert schema["properties"]["final_approval_issued"]["default"] is False


def test_sra_schemas_are_advisory_only_and_pending_review():
    manifest = load_json(SCHEMA_DIR / "sra_mcp_call_manifest.schema.json")
    trace = load_json(SCHEMA_DIR / "sra_research_trace.schema.json")

    assert manifest["properties"]["advisory_only"]["const"] is True
    assert manifest["properties"]["no_exploit_content"]["const"] is True
    assert manifest["properties"]["no_deployment_action"]["const"] is True
    assert manifest["properties"]["review_state"]["default"] == "pending_review"
    assert trace["properties"]["advisory_only"]["const"] is True
    assert trace["properties"]["cannot_close_hard_gates_alone"]["const"] is True


def test_final_approval_defaults_false():
    for schema_name in [
        "patch_change_readiness.schema.json",
        "patch_risk_acceptance_state.schema.json",
        "patch_decision_context.schema.json",
        "patch_decision_pack_manifest.schema.json",
    ]:
        schema = load_json(SCHEMA_DIR / schema_name)
        assert schema["properties"]["final_approval_issued"]["default"] is False


def test_evidence_models_load_and_include_required_classes():
    evidence_models = load_json(EVIDENCE_MODELS)
    assert evidence_models["schema_version"] == "0.1.0"
    assert COMMON_REQUIRED_CLASSES <= set(evidence_models["common_required_evidence_classes"])

    expected_models = {
        "vuln_patch_governance",
        "emergency_patch_change",
        "patch_risk_acceptance",
        "service_transition_patch_readiness",
        "ot_vuln_patch_governance",
    }
    assert expected_models == set(evidence_models["models"])


def test_raw_sra_scanner_and_agent_output_cannot_close_hard_gates_alone():
    evidence_models = load_json(EVIDENCE_MODELS)
    blocked = set(evidence_models["hard_gate_sources_disallowed_alone"])
    agent_sources = {"mcp_agent_finding", "mythos_finding", "agi_agent_finding"}
    assert {"scanner_output", "scanner_finding", "vendor_advisory", "threat_intel_report", "sra_trace", *agent_sources} <= blocked

    source_defaults = evidence_models["source_defaults"]
    assert source_defaults["scanner_output"]["can_close_hard_gate_alone"] is False
    assert source_defaults["scanner_finding"]["can_close_hard_gate_alone"] is False
    assert source_defaults["vendor_advisory"]["can_close_hard_gate_alone"] is False
    assert source_defaults["sra_trace"]["can_close_hard_gate_alone"] is False
    assert source_defaults["sra_trace"]["advisory_only"] is True
    assert source_defaults["sra_trace"]["initial_review_state"] == "pending_review"
    for source in agent_sources:
        assert source_defaults[source]["can_close_hard_gate_alone"] is False
        assert source_defaults[source]["advisory_only"] is True
        assert source_defaults[source]["initial_review_state"] == "pending_review"


def test_ot_model_requires_safety_window_and_vendor_support():
    evidence_models = load_json(EVIDENCE_MODELS)
    ot_required = set(evidence_models["models"]["ot_vuln_patch_governance"]["required_evidence_classes"])
    assert {"safety_impact", "maintenance_window", "vendor_support"} <= ot_required


def test_vendorlens_schemas_are_advisory_and_human_reviewed():
    assessment = load_json(SCHEMA_DIR / "config_applicability_assessment.schema.json")
    chat = load_json(SCHEMA_DIR / "sra_config_chat_session.schema.json")
    advisory = load_json(SCHEMA_DIR / "vendor_security_advisory.schema.json")

    assert assessment["properties"]["human_review_required"]["const"] is True
    assert assessment["properties"]["advisory_only"]["const"] is True
    assert assessment["properties"]["can_close_hard_gates_alone"]["const"] is False
    assert assessment["properties"]["final_approval_issued"]["default"] is False
    assert chat["properties"]["final_approval_issued"]["default"] is False
    assert advisory["properties"]["review_state"]["default"] == "pending_review"
    assert advisory["properties"]["can_close_hard_gates_alone"]["const"] is False

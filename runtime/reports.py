from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


REPORT_TYPES = {
    "executive_vulnerability_remediation_one_pager": "Executive Vulnerability Remediation One-Pager",
    "cab_patch_decision_report": "CAB Patch Decision Report",
    "board_vulnerability_remediation_summary": "Board Vulnerability Remediation Summary",
    "customer_patch_governance_pack": "Customer Patch Governance Pack",
    "risk_acceptance_report": "Risk Acceptance Report",
    "ot_patch_deferral_report": "OT Patch Deferral Report",
}

REPORT_SECTIONS = [
    "Vulnerability Remediation Summary",
    "Affected Services / Assets",
    "Exploitability and Threat Context",
    "Patch Availability",
    "Patch Feasibility",
    "Change Readiness",
    "Compensating Controls",
    "Risk Acceptance",
    "Customer Impact",
    "Human Review State",
    "Bayesian Advisory Snapshot",
    "Vendor and Threat Landscape",
    "Network Vendor Applicability",
    "SRA Advisory Trace",
    "Signed Pack Metadata",
    "Source Pack / Current State",
    "Blockers and Next Actions",
    "Decision Boundary",
]

REPORT_TEMPLATE_VERSION = "patchforge-report-template.v2026-05-27.2"
REPORT_CONTEXT_VERSION = "patchforge-report-context.v2"


def render_report(report_type: str, context: dict[str, Any]) -> str:
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Unknown PatchForge report type: {report_type}")

    title = REPORT_TYPES[report_type]
    vulnerability_id = context.get("vulnerability_id", "Unscoped vulnerability")
    service = context.get("service", "Unscoped service")
    posture = context.get("decision_posture", "defer_pending_evidence")
    pack = context.get("signed_pack", {})
    readiness = context.get("readiness", {})
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    generated_from_pack_id = context.get("generated_from_pack_id") or pack.get("pack_id", "not recorded")

    lines = [
        f"# {title}",
        "",
        f"Generated: {generated_at}",
        "",
        "## Report Version Stamp",
        "",
        f"report_template_version: {context.get('report_template_version', REPORT_TEMPLATE_VERSION)}",
        f"renderer_commit: {context.get('renderer_commit', 'local')}",
        f"image_tag: {context.get('image_tag', 'local')}",
        f"generated_from_pack_id: {generated_from_pack_id}",
        f"generated_at: {generated_at}",
        f"product_baseline: {context.get('product_baseline', 'PF-AZ9-VENDORLENS')}",
        f"report_context_version: {context.get('report_context_version', REPORT_CONTEXT_VERSION)}",
        "",
        f"Vulnerability: {vulnerability_id}",
        f"Service: {service}",
        f"Decision posture: {posture}",
        f"Signed pack: {pack.get('pack_id', 'not recorded')}",
        f"Readiness: {readiness.get('readiness_state', 'pending evidence')}",
        "",
    ]

    for section in REPORT_SECTIONS:
        lines.extend(_render_section(section, context))

    return "\n".join(lines).strip() + "\n"


def render_all_reports(context: dict[str, Any]) -> dict[str, str]:
    return {report_type: render_report(report_type, context) for report_type in REPORT_TYPES}


def _render_section(section: str, context: dict[str, Any]) -> list[str]:
    summary = context.get("summary", {})
    boundary = (
        "PatchForge governs vulnerability and patch decisions. It does not scan, provide procedural exploitation detail, "
        "deploy patches, mutate production systems, or approve risk without accountable human review."
    )
    content = {
        "Vulnerability Remediation Summary": summary.get("remediation", "Governed decision context compiled from source-bound evidence."),
        "Affected Services / Assets": summary.get("scope", "Affected service and asset scope requires reviewed evidence."),
        "Exploitability and Threat Context": summary.get("threat", "Threat context is presented at governance level only."),
        "Patch Availability": summary.get("patch_availability", "Patch availability must be source-bound and reviewed."),
        "Patch Feasibility": summary.get("patch_feasibility", "Patch feasibility depends on change window, testing, rollback, and service constraints."),
        "Change Readiness": summary.get("change_readiness", "Readiness remains blocked while required evidence or approval is missing."),
        "Compensating Controls": summary.get("controls", "Compensating controls must be reviewed, owned, and time-bound where applicable."),
        "Risk Acceptance": summary.get("risk_acceptance", "Risk acceptance requires owner, rationale, expiry, and human approval."),
        "Customer Impact": summary.get("customer_impact", "Customer impact must be recorded before customer-facing decisions are closed."),
        "Human Review State": summary.get("human_review", "Final approval is false until an explicit approval event is recorded."),
        "Bayesian Advisory Snapshot": _bayesian_summary(context.get("bayesian_patch_risk_snapshot")),
        "Vendor and Threat Landscape": _vendor_summary(context.get("vendor_intelligence_snapshot"), context.get("threat_landscape_snapshot")),
        "Network Vendor Applicability": _vendorlens_summary(context.get("config_applicability_assessment"), context.get("customer_network_asset_snapshot"), context.get("vendor_security_advisory_snapshot")),
        "SRA Advisory Trace": summary.get("sra", "SRA output is advisory only and cannot close hard gates alone."),
        "Signed Pack Metadata": _signed_pack_summary(context.get("signed_pack", {})),
        "Source Pack / Current State": "Signed source-pack state is preserved separately from current-state overlays and post-pack evidence events.",
        "Blockers and Next Actions": _blocker_summary(context.get("blockers", []), context.get("next_actions", [])),
        "Decision Boundary": boundary,
    }
    return [f"## {section}", "", content[section], ""]


def _bayesian_summary(snapshot: dict[str, Any] | None) -> str:
    if not snapshot:
        return "Bayesian patch risk advisory has not been attached to this report."
    return (
        f"Advisory only. Recommended posture: {snapshot.get('recommended_governance_posture', 'not recorded')}. "
        f"Exploit probability posterior: {snapshot.get('exploit_probability_posterior', 'n/a')}. "
        "This output cannot approve, risk accept, close hard gates, or deploy patches."
    )


def _vendor_summary(vendor: dict[str, Any] | None, threat: dict[str, Any] | None) -> str:
    if not vendor and not threat:
        return "Reviewed vendor advisory evidence has not yet been attached. Patch maturity, affected versions, workaround guidance, and remediation applicability remain unverified."
    return (
        "Vendor and threat signals are source-bound and pending review unless explicitly accepted. "
        f"Vendor: {(vendor or {}).get('vendor_id', 'not recorded')}. "
        f"Active exploitation signals: {((threat or {}).get('metrics') or {}).get('active_exploitation_count', 'n/a')}."
    )


def _vendorlens_summary(assessment: dict[str, Any] | None, asset: dict[str, Any] | None, advisory: dict[str, Any] | None) -> str:
    if not assessment:
        return "VendorLens network vendor applicability context has not been attached. Customer configuration, feature state, firmware version, and exposure remain unverified."
    return (
        "VendorLens is source-bound advisory intelligence. "
        f"Asset: {(asset or {}).get('asset_id', 'not recorded')}. "
        f"Advisory/CVE: {(advisory or {}).get('cve', (advisory or {}).get('advisory_id', 'not recorded'))}. "
        f"Applicability posture: {assessment.get('applicability_posture', 'not assessed')}. "
        f"Urgency posture: {assessment.get('urgency_posture', 'not assessed')}. "
        "Final approval not issued unless a named human approval event exists."
    )


def _signed_pack_summary(pack: dict[str, Any]) -> str:
    if not pack:
        return "No signed pack metadata was supplied."
    return (
        f"Pack {pack.get('pack_id', 'unknown')} verification state: {pack.get('verified', 'not recorded')}. "
        "Artefact references must point to actual signed pack artefacts."
    )


def _blocker_summary(blockers: list[str], next_actions: list[str]) -> str:
    blocker_text = ", ".join(blockers) if blockers else "No blockers recorded in supplied context."
    action_text = ", ".join(next_actions) if next_actions else "Next actions require accountable owner review."
    return f"Blockers: {blocker_text}. Next actions: {action_text}."

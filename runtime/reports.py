from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


REPORT_TYPES = {
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
    "SRA Advisory Trace",
    "Decision Boundary",
]


def render_report(report_type: str, context: dict[str, Any]) -> str:
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Unknown PatchForge report type: {report_type}")

    title = REPORT_TYPES[report_type]
    vulnerability_id = context.get("vulnerability_id", "Unscoped vulnerability")
    service = context.get("service", "Unscoped service")
    posture = context.get("decision_posture", "defer_pending_evidence")
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    lines = [
        f"# {title}",
        "",
        f"Generated: {generated_at}",
        "",
        f"Vulnerability: {vulnerability_id}",
        f"Service: {service}",
        f"Decision posture: {posture}",
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
        "SRA Advisory Trace": summary.get("sra", "SRA output is advisory only and cannot close hard gates alone."),
        "Decision Boundary": boundary,
    }
    return [f"## {section}", "", content[section], ""]


from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


REPORT_TYPES = {
    "customer_patch_governance_pack": "Customer Patch Governance Pack",
    "board_vulnerability_remediation_summary": "Board Vulnerability Summary",
    "cab_patch_decision_report": "CAB Patch Decision Report",
    "technical_evidence_appendix": "Technical Evidence Appendix",
}

REPORT_SECTIONS = [
    "Customer Assurance Position",
    "Customer Device / Service Context",
    "Matching CVEs / Advisories",
    "Applicability Assessment",
    "Patch Compare Result",
    "Evidence Needed",
    "What Can Be Shared With Customer",
    "What Cannot Yet Be Claimed",
    "Executive Decision Summary",
    "Top Risks",
    "Affected Vendors / Products",
    "Customer Exposure",
    "Recommended Next Actions",
    "Evidence Gaps",
    "Change Decision Request",
    "Affected Devices",
    "Patch Applicability",
    "Test / Rollback Evidence Needed",
    "Approval Conditions",
    "Final Approval State",
    "Signed Pack Metadata",
    "Decision Boundary",
]

REPORT_TEMPLATE_VERSION = "patchforge-report-template.v2026-05-30.1"
REPORT_CONTEXT_VERSION = "patchforge-report-context.v3"


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
        "## Report Version Metadata",
        "",
        f"report_template_version: {context.get('report_template_version', REPORT_TEMPLATE_VERSION)}",
        f"report_renderer_commit: {context.get('report_renderer_commit', context.get('renderer_commit', 'local'))}",
        f"report_renderer_image_tag: {context.get('report_renderer_image_tag', context.get('image_tag', 'local'))}",
        f"generated_from_pack_id: {generated_from_pack_id}",
        f"generated_at_utc: {generated_at}",
        f"product_baseline: {context.get('product_baseline', 'PF-AZ10-SIMPLIFIED-EXPERIENCE')}",
        f"report_context_version: {context.get('report_context_version', REPORT_CONTEXT_VERSION)}",
        f"source_pack_id: {context.get('source_pack_id', pack.get('pack_id', 'not recorded'))}",
        f"report_type: {report_type}",
        f"report_audience: {context.get('report_audience', 'not recorded')}",
        f"final_approval_issued: {str(context.get('final_approval_issued', False)).lower()}",
        f"signing_provider: {context.get('signing_provider', pack.get('signing_provider', 'not recorded'))}",
        f"verification_state: {context.get('verification_state', pack.get('verification_state', 'pending_or_not_recorded'))}",
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
        "Customer Assurance Position": summary.get("customer_assurance", "Customer assurance remains limited until reviewed customer scope and patch applicability evidence are attached."),
        "Customer Device / Service Context": summary.get("customer_context", "Customer device and service context requires reviewed asset, owner, site, firmware, feature, and exposure evidence."),
        "Matching CVEs / Advisories": summary.get("matching_cves", "Matching CVEs and advisories are source-bound pending review."),
        "Applicability Assessment": _vendorlens_summary(context.get("config_applicability_assessment"), context.get("customer_network_asset_snapshot"), context.get("vendor_security_advisory_snapshot")),
        "Patch Compare Result": summary.get("patch_compare", "Patch Compare requires reviewed current and proposed version evidence before it can support a CAB decision."),
        "Evidence Needed": _blocker_summary(context.get("blockers", []), context.get("next_actions", [])),
        "What Can Be Shared With Customer": "Source-bound governance status, reviewed evidence state, open evidence gaps, accountable owner, and decision timeline can be shared where approved.",
        "What Cannot Yet Be Claimed": "Do not claim confirmed exposure, remediation, closure, final approval, or risk acceptance unless reviewed evidence and human approval record those facts.",
        "Executive Decision Summary": summary.get("executive", "Executive decision context compiled from source-bound evidence."),
        "Top Risks": summary.get("top_risks", "Top risks depend on severity, KEV/EPSS signals, patch availability, and customer exposure evidence."),
        "Affected Vendors / Products": _vendor_summary(context.get("vendor_intelligence_snapshot"), context.get("threat_landscape_snapshot")),
        "Customer Exposure": summary.get("customer_exposure", "Customer exposure must be reviewed before customer-facing assurance is issued."),
        "Recommended Next Actions": _blocker_summary(context.get("blockers", []), context.get("next_actions", [])),
        "Evidence Gaps": _blocker_summary(context.get("blockers", []), context.get("next_actions", [])),
        "Change Decision Request": summary.get("change_request", "CAB decision request remains human approved and evidence bound."),
        "Affected Devices": summary.get("affected_devices", "Affected device evidence must identify customer, site, vendor, model, firmware, feature, and exposure."),
        "Patch Applicability": summary.get("patch_applicability", "Patch applicability requires reviewed vendor advisory, affected-version, fixed-version, and customer configuration evidence."),
        "Test / Rollback Evidence Needed": "Testing evidence, rollback plan, maintenance window, and implementation owner must be recorded before CAB approval.",
        "Approval Conditions": "Final approval requires an explicit named human approval event.",
        "Final Approval State": summary.get("human_review", "Final approval is false until an explicit approval event is recorded."),
        "Signed Pack Metadata": _signed_pack_summary(context.get("signed_pack", {})),
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

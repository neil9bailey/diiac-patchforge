from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


CONFIRMATION = "FACTORY_RESET_PATCHFORGE"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STORAGE_ROOT = REPO_ROOT / "customer-config" / "default" / "patchforge"

PURGE_SCOPES = {
    "reports": [
        "decision_packs",
        "signed_action_packs",
        "report_quality_reviews",
        "patch_compare_reports",
    ],
    "catalogue": [
        "vulnerabilities",
        "sources",
        "vendors",
        "vendor_advisories",
        "vendor_security_advisories",
        "threat_signals",
        "network_vendors",
        "network_product_families",
        "network_product_models",
        "network_firmware_versions",
        "source_feed_runs",
    ],
    "assets": [
        "assets",
        "services",
        "customers",
        "customer_estates",
        "customer_assets",
        "customer_network_assets",
        "config_applicability_assessments",
        "exposure_matches",
        "patch_actions",
        "workflow_items",
    ],
    "uploads": [
        "config_evidence",
        "vendorlens_chat_sessions",
        "vendorlens_chat_messages",
        "agent_guidance_snapshots",
    ],
    "logs": [
        "audit_events",
    ],
    "cache": [
        "bayesian_assessments",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PatchForge local JSON factory reset and purge tool.")
    parser.add_argument("--tenant", default="diiac.io", help="Tenant ID to purge from local JSON records.")
    parser.add_argument("--storage-root", default=str(DEFAULT_STORAGE_ROOT), help="Local JSON storage root.")
    parser.add_argument("--reports", action="store_true", help="Purge generated reports and signed pack records.")
    parser.add_argument("--catalogue", action="store_true", help="Purge vulnerability catalogue and source records.")
    parser.add_argument("--assets", action="store_true", help="Purge customer asset and exposure records.")
    parser.add_argument("--uploads", action="store_true", help="Purge uploaded config and chat/input records.")
    parser.add_argument("--logs", action="store_true", help="Purge audit/log records, preserving a new purge event.")
    parser.add_argument("--cache", action="store_true", help="Purge cache and advisory calculation records.")
    parser.add_argument("--all", action="store_true", help="Purge all supported data scopes.")
    parser.add_argument("--dry-run", action="store_true", help="Preview records that would be purged.")
    parser.add_argument("--confirm", default="", help=f"Required for destructive execution: {CONFIRMATION}")
    return parser.parse_args()


def selected_scopes(args: argparse.Namespace) -> list[str]:
    if args.all:
        return list(PURGE_SCOPES)
    return [scope for scope in PURGE_SCOPES if getattr(args, scope)]


def load_records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8") or "[]")


def write_records(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


def build_plan(storage_root: Path, tenant: str, scopes: list[str]) -> dict:
    collections = []
    for scope in scopes:
        collections.extend(PURGE_SCOPES[scope])
    collections = sorted(set(collections))
    counts = {}
    for collection in collections:
        records = load_records(storage_root / f"{collection}.json")
        counts[collection] = sum(1 for record in records if record.get("tenant_id") == tenant)
    return {
        "tenant_id": tenant,
        "storage_root": str(storage_root),
        "blueprint": "docs/product/PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md",
        "scopes": scopes,
        "collections": collections,
        "counts": counts,
        "total_records": sum(counts.values()),
        "required_confirmation": CONFIRMATION,
        "preserves": [
            "Git history",
            "restore tags and branches",
            "signing/verifier/replay core",
            "auth/RBAC",
            "Azure deployment scripts",
            "test harnesses",
            "deployment evidence",
            "purge event documentation",
        ],
    }


def execute_purge(storage_root: Path, tenant: str, plan: dict) -> dict:
    removed = {}
    for collection in plan["collections"]:
        path = storage_root / f"{collection}.json"
        records = load_records(path)
        keep = [record for record in records if record.get("tenant_id") != tenant]
        removed[collection] = len(records) - len(keep)
        write_records(path, keep)

    audit_path = storage_root / "audit_events.json"
    audit_records = load_records(audit_path)
    audit_records.append(
        {
            "tenant_id": tenant,
            "audit_id": f"audit-{uuid4()}",
            "event_type": "patchforge_factory_reset",
            "details": {
                "scopes": plan["scopes"],
                "collections": plan["collections"],
                "removed": removed,
                "dry_run": False,
                "blueprint": plan["blueprint"],
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    write_records(audit_path, audit_records)
    return removed


def main() -> int:
    args = parse_args()
    storage_root = Path(args.storage_root).resolve()
    scopes = selected_scopes(args)
    if not scopes:
        print(json.dumps({"error": "no_purge_scope_selected", "available_scopes": list(PURGE_SCOPES)}, indent=2))
        return 2

    plan = build_plan(storage_root, args.tenant, scopes)
    should_execute = not args.dry_run and args.confirm == CONFIRMATION
    if not should_execute:
        plan["dry_run"] = True
        if not args.dry_run:
            plan["blocked"] = True
            plan["error"] = "typed_confirmation_required"
        print(json.dumps(plan, indent=2))
        return 0 if args.dry_run else 2

    plan["dry_run"] = False
    plan["removed"] = execute_purge(storage_root, args.tenant, plan)
    plan["final_approval_issued"] = False
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

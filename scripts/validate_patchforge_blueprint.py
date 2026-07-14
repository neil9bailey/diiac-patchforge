from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT = REPO_ROOT / "docs" / "product" / "PATCHFORGE_INTELLIGENCE_REBUILD_BLUEPRINT.md"

REQUIRED_HEADINGS = [
    "Product thesis",
    "Rebuild reason",
    "Architecture principle",
    "Navigation model",
    "Data model",
    "Intelligence sources",
    "Customer Operational Assets",
    "Patch / Hotfix Compare",
    "Ask PatchForge",
    "Reports",
    "Admin redesign",
    "Purge strategy",
    "Defensive-use boundary",
    "Epics",
    "Azure and live validation",
    "Definition of done",
]


def main() -> int:
    if not BLUEPRINT.exists():
        print(f"Missing blueprint: {BLUEPRINT}", file=sys.stderr)
        return 1

    text = BLUEPRINT.read_text(encoding="utf-8")
    missing = [heading for heading in REQUIRED_HEADINGS if f"## {heading}" not in text]
    if missing:
        print("Blueprint is missing required headings:", file=sys.stderr)
        for heading in missing:
            print(f"- {heading}", file=sys.stderr)
        return 1

    print(f"Blueprint validation passed: {BLUEPRINT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

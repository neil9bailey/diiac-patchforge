from __future__ import annotations

import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from runtime.governance_runtime import GovernanceRuntimeError, create_signed_decision_pack


class PatchForgeRuntimeHandler(BaseHTTPRequestHandler):
    server_version = "PatchForgeRuntime/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "component": "patchforge-runtime"})
            return
        if self.path == "/readiness":
            self._send_json(
                200,
                {
                    "status": "ready",
                    "runtime": "deterministic-governance",
                    "no_patch_deployment": True,
                    "no_exploit_content": True,
                },
            )
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path == "/api/runtime/decision-packs":
            try:
                payload = self._read_json_body()
                pack = self._create_decision_pack(payload)
                self._send_json(201, pack)
            except GovernanceRuntimeError as exc:
                self._send_json(400, {"error": "governance_boundary_violation", "message": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive runtime boundary
                self._send_json(500, {"error": "runtime_error", "message": str(exc)})
            return
        self._send_json(404, {"error": "not_found"})

    def log_message(self, format: str, *args: object) -> None:
        return

    def _read_json_body(self) -> dict[str, object]:
        length = int(self.headers.get("content-length", "0") or "0")
        if length <= 0:
            return {}
        if length > int(os.environ.get("PATCHFORGE_RUNTIME_MAX_BODY_BYTES", "1048576")):
            raise GovernanceRuntimeError("Runtime request body exceeds PatchForge limit.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _create_decision_pack(self, payload: dict[str, object]) -> dict[str, object]:
        vulnerability = payload.get("vulnerability")
        if not isinstance(vulnerability, dict):
            raise GovernanceRuntimeError("A real vulnerability record is required.")

        output_root = Path(os.environ.get("PATCHFORGE_PACK_OUTPUT_DIR", "/tmp/patchforge-packs"))
        output_dir = output_root / str(uuid4())
        key_vault_key_id = os.environ.get("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID") or None
        dev_mode = not bool(key_vault_key_id)
        result = create_signed_decision_pack(
            output_dir=output_dir,
            vulnerability=vulnerability,
            evidence_items=_list_payload(payload.get("evidence_items")),
            model_name=str(payload.get("model_name") or "vuln_patch_governance"),
            patch_availability=_dict_or_none(payload.get("patch_availability")),
            patch_feasibility=_dict_or_none(payload.get("patch_feasibility")),
            controls=_dict_or_none(payload.get("controls")),
            risk_acceptance=_dict_or_none(payload.get("risk_acceptance")),
            approval_events=_list_payload(payload.get("approval_events")),
            requested_posture=_optional_str(payload.get("requested_posture")),
            key_vault_key_id=key_vault_key_id,
            dev_mode=dev_mode,
        )
        sigmeta_path = Path(result["pack_dir"]) / "signed_export.sigmeta.json"
        sigmeta = json.loads(sigmeta_path.read_text(encoding="utf-8"))

        return {
            "pack_id": result["pack_id"],
            "created_at": result["decision_context"]["created_at"],
            "runtime_component": "patchforge-runtime",
            "decision_context": result["decision_context"],
            "verification": result["verification"],
            "signing_provider": sigmeta.get("signing_provider") or sigmeta.get("algorithm"),
            "artefacts": _read_pack_artefacts(Path(result["pack_dir"])),
            "boundary": {
                "no_scanner": True,
                "no_exploit_generation": True,
                "no_patch_deployment": True,
                "no_production_mutation": True,
                "no_autonomous_approval": True,
            },
        }

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _dict_or_none(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def _list_payload(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _optional_str(value: object) -> str | None:
    return str(value) if value else None


def _read_pack_artefacts(pack_dir: Path) -> dict[str, object]:
    artefacts: dict[str, object] = {}
    for path in sorted(pack_dir.iterdir()):
        if path.suffix == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if path.name == "signed_export.sigmeta.json":
                payload["dev_key_hint"] = None
            artefacts[path.name] = payload
        elif path.name == "signed_export.sig":
            artefacts[path.name] = path.read_text(encoding="utf-8")
    return artefacts


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), PatchForgeRuntimeHandler)
    print(f"PatchForge runtime health server listening on {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

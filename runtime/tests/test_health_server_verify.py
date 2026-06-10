import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from runtime.health_server import PatchForgeRuntimeHandler


@pytest.fixture()
def runtime_server(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHFORGE_PACK_OUTPUT_DIR", str(tmp_path / "packs"))
    monkeypatch.delenv("PATCHFORGE_KEYVAULT_SIGNING_KEY_ID", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), PatchForgeRuntimeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def post_json(port: int, path: str, payload) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload),
            headers={"content-type": "application/json"},
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def sample_vulnerability() -> dict:
    return {
        "tenant_id": "tenant-a",
        "vulnerability_id": "REAL-RECORD-1",
        "canonical_id": "REAL-RECORD-1",
        "severity": "critical",
        "known_exploited": True,
        "internet_exposed": True,
        "patch_status": "patch_available",
    }


def test_verify_endpoint_round_trip(runtime_server):
    status, pack = post_json(
        runtime_server,
        "/api/runtime/decision-packs",
        {"vulnerability": sample_vulnerability()},
    )
    assert status == 201
    assert pack["verification"]["verified"] is True

    status, verification = post_json(runtime_server, "/api/runtime/decision-packs/verify", {"pack": pack})
    assert status == 200
    assert verification == {
        "verified": True,
        "algorithm": "dev_hmac_sha256",
        "artefact_hash_check": True,
        "manifest_hash_check": True,
        "signature_check": True,
        "failed_artefacts": [],
    }


def test_verify_endpoint_detects_tampered_artefact(runtime_server):
    status, pack = post_json(
        runtime_server,
        "/api/runtime/decision-packs",
        {"vulnerability": sample_vulnerability()},
    )
    assert status == 201

    pack["artefacts"]["patch_decision_context.json"]["final_approval_issued"] = True
    status, verification = post_json(runtime_server, "/api/runtime/decision-packs/verify", {"pack": pack})
    assert status == 200
    assert verification["verified"] is False
    assert verification["artefact_hash_check"] is False
    assert "patch_decision_context.json" in verification["failed_artefacts"]


def test_verify_endpoint_rejects_malformed_bodies(runtime_server):
    status, body = post_json(runtime_server, "/api/runtime/decision-packs/verify", {})
    assert status == 400
    assert body["error"] == "malformed_pack_payload"

    status, body = post_json(runtime_server, "/api/runtime/decision-packs/verify", {"pack": "not-an-object"})
    assert status == 400

    status, body = post_json(runtime_server, "/api/runtime/decision-packs/verify", {"pack": {"artefacts": {}}})
    assert status == 400

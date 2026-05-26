from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), PatchForgeRuntimeHandler)
    print(f"PatchForge runtime health server listening on {port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()


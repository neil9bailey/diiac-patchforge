export async function handlePlatformRoutes({ req, res, url, storage, authConfig, sendJson }) {
  if (req.method === "GET" && url.pathname === "/health") {
    sendJson(res, 200, {
      status: "ok",
      product: "DIIaC PatchForge",
      boundary: "governance-only"
    });
    return true;
  }

  if (req.method === "GET" && url.pathname === "/readiness") {
    sendJson(res, 200, {
      status: "ready",
      storage: storage.storageMode || "local-json",
      auth_required: Boolean(authConfig.required),
      tenant_required: true
    });
    return true;
  }

  return false;
}

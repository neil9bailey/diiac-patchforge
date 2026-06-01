const DEFAULT_TENANT_ID = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da";
const DEFAULT_API_CLIENT_ID = "ec30b0eb-cfc4-48cc-a5f2-2a1345d96736";
const DEFAULT_AUDIENCE = "api://ec30b0eb-cfc4-48cc-a5f2-2a1345d96736";
const ADMIN_ROLE = "PatchForge.Admin";

const ROUTE_ROLES = [
  { method: "GET", pattern: /^\/api\/patchforge\/admin\/config$/, roles: ["PatchForge.Admin", "PatchForge.Auditor"] },
  { method: "PUT", pattern: /^\/api\/patchforge\/admin\/config$/, roles: ["PatchForge.Admin"] },
  { method: "GET", pattern: /^\/api\/patchforge\/admin\/health$/, roles: ["PatchForge.Admin", "PatchForge.Auditor"] },
  { method: "GET", pattern: /^\/api\/patchforge\/admin\/purge$/, roles: ["PatchForge.Admin", "PatchForge.Auditor"] },
  { method: "POST", pattern: /^\/api\/patchforge\/admin\/purge$/, roles: ["PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/vulnerabilities\/ingest$/, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/vulnerabilities\/[^/]+\/review$/, roles: ["PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/assets\/ingest$/, roles: ["PatchForge.TriageAnalyst", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/services\/ingest$/, roles: ["PatchForge.TriageAnalyst", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/agent-findings\/ingest$/, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/source-feeds\/refresh$/, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/bayesian\//, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/vendors/, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/patchforge\/decision-packs\/generate$/, roles: ["PatchForge.SecurityLead", "PatchForge.CABApprover", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\/sra\//, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "GET", pattern: /^\/api\//, roles: ["PatchForge.Reader", "PatchForge.Auditor", "PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] },
  { method: "POST", pattern: /^\/api\//, roles: ["PatchForge.TriageAnalyst", "PatchForge.SecurityLead", "PatchForge.Admin"] }
];

export function createAuthConfigFromEnv() {
  const tenantId = process.env.PATCHFORGE_ENTRA_TENANT_ID || DEFAULT_TENANT_ID;
  const audience = process.env.PATCHFORGE_ENTRA_AUDIENCE || DEFAULT_AUDIENCE;
  const production = isProductionEnvironment();
  const required = parseBoolean(process.env.PATCHFORGE_AUTH_REQUIRED, false);
  if (production && !required) {
    throw new Error("PatchForge production startup blocked: PATCHFORGE_AUTH_REQUIRED=true is mandatory when APP_ENV/PATCHFORGE_ENV/NODE_ENV is production.");
  }
  const audiences = (process.env.PATCHFORGE_ENTRA_AUDIENCES || `${audience},${DEFAULT_API_CLIENT_ID}`)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const issuer = process.env.PATCHFORGE_ENTRA_ISSUER || `https://login.microsoftonline.com/${tenantId}/v2.0`;
  return {
    required,
    production,
    tenantId,
    audience,
    audiences,
    issuer,
    jwksUri: process.env.PATCHFORGE_ENTRA_JWKS_URI || `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`,
    defaultTenant: process.env.PATCHFORGE_DEFAULT_TENANT || "diiac.io",
    tenantMappings: parseTenantMappings(process.env.PATCHFORGE_TENANT_MAPPINGS, tenantId),
    allowTenantOverride: parseBoolean(process.env.PATCHFORGE_ALLOW_TENANT_OVERRIDE, false),
    adminDiagnosticTenantOverride: parseBoolean(process.env.PATCHFORGE_ADMIN_DIAGNOSTIC_TENANT_OVERRIDE, false)
  };
}

export async function authorizeRequest(req, url, authConfig = {}) {
  const method = req.method || "GET";
  const requiredRoles = rolesForRoute(method, url.pathname);
  if (!requiredRoles.length) {
    return { ok: true, principal: null, requiredRoles };
  }

  if (!authConfig.required) {
    return { ok: true, principal: { auth_disabled: true }, requiredRoles };
  }

  const token = bearerToken(req.headers.authorization);
  if (!token) {
    return {
      ok: false,
      statusCode: 401,
      error: "missing_bearer_token",
      message: "A Microsoft Entra access token is required.",
      requiredRoles
    };
  }

  try {
    const principal = authConfig.verifier
      ? await authConfig.verifier(token)
      : await verifyEntraJwt(token, authConfig);
    const roles = normalizeRoles(principal.roles);
    if (!roles.some((role) => requiredRoles.includes(role) || role === ADMIN_ROLE)) {
      return {
        ok: false,
        statusCode: 403,
        error: "insufficient_patchforge_role",
        message: "The token is valid but does not contain a required PatchForge app role.",
        requiredRoles,
        roles
      };
    }
    return { ok: true, principal: { ...principal, roles }, requiredRoles };
  } catch (error) {
    return {
      ok: false,
      statusCode: 401,
      error: "invalid_bearer_token",
      message: error.message,
      requiredRoles
    };
  }
}

export function rolesForRoute(method, pathname) {
  const match = ROUTE_ROLES.find((route) => route.method === method && route.pattern.test(pathname));
  return match ? match.roles : [];
}

function bearerToken(authorizationHeader) {
  if (!authorizationHeader) {
    return null;
  }
  const match = authorizationHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

async function verifyEntraJwt(token, authConfig) {
  const { createRemoteJWKSet, jwtVerify } = await import("jose");
  const jwks = createRemoteJWKSet(new URL(authConfig.jwksUri));
  const { payload } = await jwtVerify(token, jwks, {
    issuer: authConfig.issuer,
    audience: authConfig.audiences || authConfig.audience,
    clockTolerance: "2 minutes"
  });
  if (authConfig.tenantId && payload.tid !== authConfig.tenantId) {
    throw new Error("Token tenant does not match the PatchForge tenant.");
  }
  return {
    oid: payload.oid || payload.sub,
    upn: payload.preferred_username || payload.upn || null,
    tid: payload.tid,
    aud: payload.aud,
    roles: payload.roles || [],
    scopes: typeof payload.scp === "string" ? payload.scp.split(" ") : []
  };
}

function normalizeRoles(roles) {
  if (!roles) {
    return [];
  }
  if (Array.isArray(roles)) {
    return roles.flatMap((role) => String(role).split(",")).map((role) => role.trim()).filter(Boolean);
  }
  return String(roles).split(",").map((role) => role.trim()).filter(Boolean);
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

export function isProductionEnvironment() {
  return ["production", "prod"].includes(String(process.env.APP_ENV || "").toLowerCase())
    || ["production", "prod"].includes(String(process.env.PATCHFORGE_ENV || "").toLowerCase())
    || ["production", "prod"].includes(String(process.env.PATCHFORGE_ENVIRONMENT || "").toLowerCase())
    || String(process.env.NODE_ENV || "").toLowerCase() === "production";
}

function parseTenantMappings(raw, tenantId) {
  if (!raw) {
    return { [tenantId]: "diiac.io" };
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : { [tenantId]: "diiac.io" };
  } catch {
    return { [tenantId]: "diiac.io" };
  }
}

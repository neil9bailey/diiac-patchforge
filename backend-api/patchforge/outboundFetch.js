import dns from "node:dns/promises";
import https from "node:https";
import net from "node:net";

const DEFAULT_ALLOWED_HOSTS = Object.freeze([
  "api.first.org",
  "developer.cisco.com",
  "forums.ivanti.com",
  "msrc.microsoft.com",
  "sec.cloudapps.cisco.com",
  "security.paloaltonetworks.com",
  "services.nvd.nist.gov",
  "support.apple.com",
  "support.broadcom.com",
  "support.citrix.com",
  "supportportal.juniper.net",
  "www.cisa.gov",
  "www.fortiguard.com",
  "www.ncsc.gov.uk"
]);

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_REDIRECT_HEADERS = new Set(["authorization", "cookie", "apikey", "proxy-authorization"]);

export function outboundSourceAllowlist(extra = []) {
  const configured = String(process.env.PATCHFORGE_OUTBOUND_SOURCE_ALLOWLIST || "")
    .split(",")
    .map(normalizeHostname)
    .filter(Boolean);
  return new Set([...DEFAULT_ALLOWED_HOSTS, ...configured, ...(Array.isArray(extra) ? extra : [extra])].map(normalizeHostname).filter(Boolean));
}

export function isDisallowedOutboundAddress(address) {
  const value = String(address || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  const family = net.isIP(value);
  if (family === 4) {
    const octets = value.split(".").map(Number);
    const [a, b] = octets;
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0 && octets[2] === 0)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && octets[2] === 2)
      || (a === 192 && b === 88 && octets[2] === 99)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && octets[2] === 100)
      || (a === 203 && b === 0 && octets[2] === 113)
      || a >= 224;
  }
  if (family === 6) {
    if (value === "::" || value === "::1") return true;
    const mapped = value.match(/^(?:0*:)*ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) return isDisallowedOutboundAddress(mapped[1]);
    return value.startsWith("fc")
      || value.startsWith("fd")
      || /^fe[89ab]/.test(value)
      || value.startsWith("ff")
      || value.startsWith("100:")
      || /^2001:0{0,3}[0-1]?[0-9a-f]:/i.test(value)
      || value.startsWith("2001:db8:")
      || value.startsWith("2002:")
      || value.startsWith("3fff:");
  }
  return true;
}

export async function assertApprovedOutboundUrl(input, options = {}) {
  let url;
  try {
    url = new URL(String(input));
  } catch {
    throw outboundError("outbound_url_invalid", "Outbound source URL is invalid.");
  }
  if (url.protocol !== "https:") {
    throw outboundError("outbound_https_required", "Outbound source URLs must use HTTPS.");
  }
  if (url.username || url.password) {
    throw outboundError("outbound_userinfo_forbidden", "Outbound source URLs cannot contain credentials.");
  }
  const hostname = normalizeHostname(url.hostname);
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname === "metadata.google.internal") {
    throw outboundError("outbound_hostname_forbidden", "Local and metadata hostnames are not valid outbound sources.");
  }
  if (net.isIP(hostname)) {
    throw outboundError("outbound_ip_literal_forbidden", "Outbound source URLs must use an approved DNS hostname, not an IP literal.");
  }
  const allowlist = options.allowlist instanceof Set
    ? new Set([...options.allowlist].map(normalizeHostname))
    : outboundSourceAllowlist(options.allowHosts || []);
  if (!allowlist.has(hostname)) {
    throw outboundError("outbound_hostname_not_allowed", `Outbound source hostname is not allowlisted: ${hostname}.`);
  }
  const resolveHostname = options.resolveHostname || defaultResolveHostname;
  let answers;
  try {
    const dnsTimeoutMs = boundedNumber(options.dnsTimeoutMs ?? process.env.PATCHFORGE_OUTBOUND_DNS_TIMEOUT_MS, 5000, 100, 15000);
    answers = await withTimeout(resolveHostname(hostname), dnsTimeoutMs, "outbound_dns_timeout", `Outbound source DNS resolution exceeded ${dnsTimeoutMs} ms for ${hostname}.`);
  } catch (error) {
    if (error?.code === "outbound_dns_timeout") throw error;
    throw outboundError("outbound_dns_resolution_failed", `Outbound source DNS resolution failed for ${hostname}.`, { cause: error });
  }
  const addresses = normalizeDnsAnswers(answers);
  if (!addresses.length) {
    throw outboundError("outbound_dns_no_addresses", `Outbound source DNS returned no addresses for ${hostname}.`);
  }
  if (addresses.some(({ address }) => isDisallowedOutboundAddress(address))) {
    throw outboundError("outbound_dns_address_forbidden", `Outbound source DNS for ${hostname} resolved to a private, local, metadata, or reserved address.`);
  }
  return { url, hostname, addresses };
}

export async function guardedFetchBuffer(input, options = {}) {
  const maxRedirects = boundedNumber(options.maxRedirects ?? process.env.PATCHFORGE_OUTBOUND_MAX_REDIRECTS, 3, 0, 5);
  const maxBytes = boundedNumber(options.maxBytes ?? process.env.PATCHFORGE_OUTBOUND_MAX_BYTES, 8 * 1024 * 1024, 1024, 32 * 1024 * 1024);
  const timeoutMs = boundedNumber(options.timeoutMs ?? process.env.PATCHFORGE_OUTBOUND_TIMEOUT_MS, 15000, 100, 60000);
  let current = String(input);
  let headers = normalizeHeaders(options.headers || {});

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const approved = await assertApprovedOutboundUrl(current, options);
    const response = options.fetchImpl && options.fetchImpl !== globalThis.fetch
      ? await fetchWithInjectedClient(approved.url, { ...options, headers, maxBytes, timeoutMs })
      : await fetchWithPinnedHttps(approved, { headers, maxBytes, timeoutMs });
    if (!REDIRECT_STATUSES.has(response.status)) {
      if (response.status < 200 || response.status >= 300) {
        throw outboundError("outbound_http_error", `Outbound source request failed with HTTP ${response.status}.`, { status: response.status });
      }
      return response;
    }
    if (redirects === maxRedirects) {
      throw outboundError("outbound_redirect_limit", "Outbound source exceeded the redirect limit.");
    }
    const location = headerValue(response.headers, "location");
    if (!location) {
      throw outboundError("outbound_redirect_location_missing", "Outbound source redirect did not include a Location header.");
    }
    const next = new URL(location, approved.url);
    headers = redirectHeaders(headers, approved.url, next);
    current = next.toString();
  }
  throw outboundError("outbound_redirect_limit", "Outbound source exceeded the redirect limit.");
}

export async function guardedFetchJson(url, options = {}) {
  const response = await guardedFetchBuffer(url, options);
  try {
    return JSON.parse(response.buffer.toString("utf8"));
  } catch {
    throw outboundError("outbound_invalid_json", "Outbound source returned invalid JSON.");
  }
}

export async function guardedFetchText(url, options = {}) {
  return (await guardedFetchBuffer(url, options)).buffer.toString("utf8");
}

async function defaultResolveHostname(hostname) {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

function normalizeDnsAnswers(answers) {
  const values = Array.isArray(answers) ? answers : answers ? [answers] : [];
  return [...new Map(values.map((answer) => {
    const address = typeof answer === "string" ? answer : answer?.address;
    const family = typeof answer === "string" ? net.isIP(answer) : Number(answer?.family || net.isIP(address));
    return [String(address || ""), { address: String(address || ""), family }];
  }).filter(([address, answer]) => address && (answer.family === 4 || answer.family === 6))).values()];
}

function fetchWithPinnedHttps(approved, { headers, maxBytes, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const selected = approved.addresses.find((answer) => answer.family === 4) || approved.addresses[0];
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      callback(value);
    };
    const request = https.request(approved.url, {
      method: "GET",
      headers,
      servername: approved.hostname,
      lookup(_hostname, lookupOptions, callback) {
        if (lookupOptions?.all) {
          callback(null, [selected]);
          return;
        }
        callback(null, selected.address, selected.family);
      }
    }, (response) => {
      const contentLength = Number(response.headers["content-length"] || 0);
      if (contentLength > maxBytes) {
        response.destroy();
        return finish(reject, outboundError("outbound_response_too_large", `Outbound source response exceeds ${maxBytes} bytes.`));
      }
      const chunks = [];
      let total = 0;
      response.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          response.destroy(outboundError("outbound_response_too_large", `Outbound source response exceeds ${maxBytes} bytes.`));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => finish(resolve, {
        url: approved.url.toString(),
        status: response.statusCode || 0,
        headers: response.headers,
        buffer: Buffer.concat(chunks)
      }));
      response.on("error", (error) => finish(reject, error));
    });
    const timeoutError = outboundError("outbound_timeout", `Outbound source request exceeded ${timeoutMs} ms.`);
    const totalTimer = setTimeout(() => request.destroy(timeoutError), timeoutMs);
    request.setTimeout(timeoutMs, () => request.destroy(timeoutError));
    request.on("error", (error) => finish(reject, error));
    request.end();
  });
}

async function fetchWithInjectedClient(url, { fetchImpl, headers, maxBytes, timeoutMs }) {
  const controller = new AbortController();
  const timeoutError = outboundError("outbound_timeout", `Outbound source request exceeded ${timeoutMs} ms.`);
  let timer;
  try {
    return await Promise.race([
      (async () => {
        const response = await fetchImpl(url.toString(), { method: "GET", headers, redirect: "manual", signal: controller.signal });
        const length = Number(response.headers?.get?.("content-length") || 0);
        if (length > maxBytes) {
          throw outboundError("outbound_response_too_large", `Outbound source response exceeds ${maxBytes} bytes.`);
        }
        if (typeof response.arrayBuffer !== "function") {
          throw outboundError("outbound_response_invalid", "Outbound source response does not provide a bounded byte stream.");
        }
        const buffer = Buffer.from(await response.arrayBuffer());
        if (buffer.length > maxBytes) {
          throw outboundError("outbound_response_too_large", `Outbound source response exceeds ${maxBytes} bytes.`);
        }
        return { url: url.toString(), status: response.status, headers: response.headers, buffer };
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(timeoutError);
        }, timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function normalizeHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [String(key).toLowerCase(), String(value)]));
}

function redirectHeaders(headers, from, to) {
  if (from.origin === to.origin) return headers;
  return Object.fromEntries(Object.entries(headers).filter(([key]) => !SENSITIVE_REDIRECT_HEADERS.has(key.toLowerCase())));
}

function headerValue(headers, name) {
  if (headers?.get) return headers.get(name);
  const value = headers?.[name] ?? headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
}

function boundedNumber(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, Math.trunc(parsed))) : fallback;
}

function withTimeout(promise, timeoutMs, code, message) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(outboundError(code, message)), timeoutMs);
    })
  ]).finally(() => clearTimeout(timer));
}

function outboundError(code, message, extra = {}) {
  return Object.assign(new Error(message), { code, publicError: code, publicMessage: message, ...extra });
}

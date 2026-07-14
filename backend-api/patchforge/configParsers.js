import { createHash, randomUUID } from "node:crypto";

const SECRET_PATTERNS = [
  /\b(set\s+(?:password|passwd|secret|pre[-_ ]?shared[-_ ]?key|psk|community|token|api[-_ ]?key|client[-_ ]?secret))\s+("[^"\r\n]+"|'[^'\r\n]+'|\S+)/gi,
  /\b(password|passwd|pwd|secret|pre[-_ ]?shared[-_ ]?key|psk|community|token|api[-_ ]?key|client[-_ ]?secret)\s*[:=]\s*("[^"\r\n]+"|'[^'\r\n]+'|\S+)/gi,
  /\b(authorization)\s*:\s*(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi,
  /\b(snmp-server\s+community)\s+\S+/gi,
  /\b(radius-server\s+key|tacacs-server\s+key|ldap-bind-password)\s+\S+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b[A-Za-z][A-Za-z0-9+.-]+:\/\/[^:\s/@]+:[^@\s]+@[^ \r\n]+/g,
  /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\b(?:xox[baprs]-|gh[pousr]_|github_pat_)[A-Za-z0-9_=-]{16,}\b/g
];

const PARSER_HINTS = [
  ["cisco", /\b(cisco|ios xe|asa|nx-os|interface GigabitEthernet|show running-config)\b/i],
  ["fortinet", /\b(fortigate|fortios|config system|set vdom|config vpn ssl)\b/i],
  ["palo_alto", /\b(pan-os|palo alto|set deviceconfig|globalprotect|security-policy)\b/i],
  ["juniper", /\b(junos|juniper|set system host-name|interfaces ge-|security zones)\b/i],
  ["windows", /\b(windows|hostname\s*:\s*|OS Name|Hotfix|Get-ComputerInfo|KB\d{6,})\b/i],
  ["linux", /\b(linux|ubuntu|debian|rhel|centos|kernel|uname -a|dpkg -l|rpm -qa)\b/i],
  ["vmware", /\b(vmware|esxi|vcenter|build-\d+|esxcli)\b/i]
];

export function redactConfigInput(input = "") {
  const raw = String(input || "");
  let redacted = raw;
  let count = 0;
  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, (match, key) => {
      count += 1;
      if (key && typeof key === "string" && match.toLowerCase().includes(String(key).toLowerCase())) {
        return `${key}: [REDACTED_SECRET]`;
      }
      return "[REDACTED_SECRET]";
    });
  }
  return {
    raw_upload_hash: sha256(raw),
    redacted_config: redacted,
    redaction_status: count > 0 ? "redacted" : "no_secrets_detected",
    redacted_secret_count: count,
    raw_secret_values_persisted: false
  };
}

export function parseConfigEvidence({ tenantId, customerId = null, assetId = null, input = "", sourceType = "paste", parser = "auto" }) {
  const redaction = redactConfigInput(input);
  const parserFamily = parser === "auto" ? detectParser(redaction.redacted_config) : parser;
  const facts = parsedFacts(redaction.redacted_config, parserFamily);
  const confidence = parserConfidence(parserFamily, facts);
  return {
    tenant_id: tenantId,
    id: `cfg-${Date.now()}-${randomUUID().slice(0, 8)}`,
    customer_id: customerId,
    asset_id: assetId || facts.hostname || null,
    source_type: sourceType,
    parser_family: parserFamily,
    redacted_config: redaction.redacted_config,
    raw_upload_hash: redaction.raw_upload_hash,
    redaction_status: redaction.redaction_status,
    parsed_facts: facts,
    parser_confidence: confidence,
    evidence_refs: [{
      evidence_type: "redacted_config",
      source_type: sourceType,
      raw_upload_hash: redaction.raw_upload_hash,
      parser_family: parserFamily
    }],
    created_at: new Date().toISOString(),
    raw_secret_values_persisted: false
  };
}

export function importAssetsFromCsv({ tenantId, customerId = null, estateId = null, csv = "", source = "csv_import" }) {
  const rows = parseCsv(csv);
  return rows.map((row, index) => {
    const vendor = first(row.vendor, row.manufacturer, row.publisher, "unknown");
    const product = first(row.product, row.software, row.application, row.model, "unknown");
    return {
      tenant_id: tenantId,
      id: first(row.id, row.asset_id, row.hostname, `asset-${Date.now()}-${index}`),
      customer_id: customerId || first(row.customer_id, row.customer),
      estate_id: estateId || first(row.estate_id, row.estate),
      site: first(row.site, row.location),
      hostname: first(row.hostname, row.host, row.name),
      asset_type: first(row.asset_type, row.type, "server_or_device"),
      vendor,
      product,
      version: first(row.version, row.software_version, row.firmware_version),
      firmware_version: first(row.firmware_version, row.firmware),
      software_packages: list(first(row.software_packages, row.packages)),
      cpe: first(row.cpe, row.cpe23uri),
      internet_exposed: truthy(first(row.internet_exposed, row.public, row.external)),
      criticality: first(row.criticality, row.priority, "unknown"),
      source,
      source_confidence: row.source_confidence ? Number(row.source_confidence) : 0.75,
      parser_confidence: 0.8,
      tags: list(row.tags),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
  });
}

function parsedFacts(text, parserFamily) {
  return {
    hostname: extractHostname(text, parserFamily),
    vendor: vendorFor(parserFamily),
    product: productFor(text, parserFamily),
    version: extractVersion(text),
    firmware_version: extractVersion(text),
    software_packages: extractPackages(text, parserFamily),
    interfaces: extractInterfaces(text),
    enabled_features: extractEnabledFeatures(text),
    disabled_features: extractDisabledFeatures(text),
    cpe_candidates: cpeCandidates(parserFamily, text),
    internet_exposure_hints: exposureHints(text)
  };
}

function detectParser(text) {
  const match = PARSER_HINTS.find(([, pattern]) => pattern.test(text));
  return match ? match[0] : "generic_key_value";
}

function extractHostname(text, parserFamily) {
  const patterns = [
    /\bhostname\s+([A-Za-z0-9_.-]+)/i,
    /\bhost-name\s+([A-Za-z0-9_.-]+)/i,
    /\bcomputername\s*[:=]\s*([A-Za-z0-9_.-]+)/i,
    /\bname\s*[:=]\s*([A-Za-z0-9_.-]+)/i
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1];
  }
  return parserFamily === "generic_key_value" ? null : `${parserFamily}-asset`;
}

function extractVersion(text) {
  const patterns = [
    /\b(?:version|firmware|FortiOS|PAN-OS|Junos|ESXi|kernel)\s+v?([0-9]+(?:\.[0-9A-Za-z-]+){1,5})/i,
    /\bv?([0-9]+\.[0-9]+(?:\.[0-9A-Za-z-]+){0,4})\b/
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[1];
  }
  return null;
}

function extractInterfaces(text) {
  return Array.from(new Set((text.match(/\b(?:interface|port|ethernet|ge-|GigabitEthernet|vmnic)[A-Za-z0-9/_.-]*/gi) || []).slice(0, 20)));
}

function extractEnabledFeatures(text) {
  const features = [];
  if (/\bssl[- ]?vpn\b/i.test(text) && !/\bssl[- ]?vpn\b.{0,40}\b(disable|disabled|off)\b/i.test(text)) features.push("ssl_vpn");
  if (/\bipsec\b/i.test(text)) features.push("ipsec_vpn");
  if (/\bglobalprotect\b/i.test(text)) features.push("globalprotect");
  if (/\bweb\s*(management|ui)|https admin|management interface\b/i.test(text)) features.push("web_management");
  return Array.from(new Set(features));
}

function extractDisabledFeatures(text) {
  const features = [];
  if (/\bssl[- ]?vpn\b.{0,60}\b(disable|disabled|off)\b/i.test(text)) features.push("ssl_vpn");
  if (/\bglobalprotect\b.{0,60}\b(disable|disabled|off)\b/i.test(text)) features.push("globalprotect");
  return Array.from(new Set(features));
}

function extractPackages(text, parserFamily) {
  if (parserFamily === "windows") {
    return Array.from(new Set(text.match(/\bKB\d{6,}\b/gi) || []));
  }
  if (parserFamily === "linux") {
    return Array.from(new Set(text.match(/\b(?:openssl|openssh|nginx|apache2?|kernel|glibc)[A-Za-z0-9:_.+-]*/gi) || []));
  }
  if (parserFamily === "vmware") {
    return Array.from(new Set(text.match(/\b(?:ESXi|vCenter|VMware Tools)[A-Za-z0-9 ._-]*/gi) || []));
  }
  return [];
}

function cpeCandidates(parserFamily, text) {
  const product = productFor(text, parserFamily);
  const vendor = vendorFor(parserFamily);
  if (!vendor || !product) return [];
  return [`cpe:2.3:*:${slug(vendor)}:${slug(product)}:*:*:*:*:*:*:*:*`];
}

function exposureHints(text) {
  return {
    internet_exposed: /\b(public ip|internet[- ]facing|external|wan)\b/i.test(text),
    management_plane_exposed: /\bmanagement\b.{0,40}\b(public|internet|wan|external)\b/i.test(text)
  };
}

function vendorFor(parserFamily) {
  return {
    cisco: "Cisco",
    fortinet: "Fortinet",
    palo_alto: "Palo Alto Networks",
    juniper: "Juniper",
    windows: "Microsoft",
    linux: "Linux",
    vmware: "VMware"
  }[parserFamily] || null;
}

function productFor(text, parserFamily) {
  if (/fortigate/i.test(text)) return "FortiGate";
  if (/fortios/i.test(text)) return "FortiOS";
  if (/pan-os|panos/i.test(text)) return "PAN-OS";
  if (/junos/i.test(text)) return "Junos OS";
  if (/asa/i.test(text)) return "Cisco ASA";
  if (/windows/i.test(text)) return "Windows";
  if (/linux|ubuntu|debian|rhel|centos/i.test(text)) return "Linux";
  if (/esxi/i.test(text)) return "ESXi";
  return {
    cisco: "Cisco Network Device",
    fortinet: "FortiGate",
    palo_alto: "PAN-OS",
    juniper: "Junos OS",
    windows: "Windows",
    linux: "Linux",
    vmware: "VMware Platform"
  }[parserFamily] || null;
}

function parserConfidence(parserFamily, facts) {
  const score = [
    parserFamily !== "generic_key_value" ? 0.35 : 0.15,
    facts.hostname ? 0.15 : 0,
    facts.vendor ? 0.15 : 0,
    facts.product ? 0.15 : 0,
    facts.version ? 0.15 : 0,
    facts.enabled_features.length || facts.disabled_features.length || facts.software_packages.length ? 0.05 : 0
  ].reduce((sum, value) => sum + value, 0);
  return Math.round(Math.min(score, 0.95) * 100) / 100;
}

function parseCsv(csv) {
  const lines = String(csv || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length < 2) return [];
  const headers = splitCsvLine(lines[0]).map((header) => slug(header).replace(/-/g, "_"));
  return lines.slice(1).map((line) => Object.fromEntries(splitCsvLine(line).map((value, index) => [headers[index] || `field_${index}`, value])));
}

function splitCsvLine(line) {
  const values = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === "\"") {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      values.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current.trim());
  return values.map((value) => value.replace(/^"|"$/g, ""));
}

function list(value) {
  if (Array.isArray(value)) return value.flatMap((item) => list(item));
  if (value === undefined || value === null || value === "") return [];
  return String(value).split(/[;,]/).map((item) => item.trim()).filter(Boolean);
}

function first(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return null;
}

function truthy(value) {
  return ["true", "1", "yes", "y", "public", "external"].includes(String(value || "").toLowerCase());
}

function slug(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function sha256(value) {
  return createHash("sha256").update(String(value || "")).digest("hex");
}

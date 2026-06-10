// Shared version comparison and CPE 2.3 utilities for the PatchForge matching
// engine (PF-AZ12 contract section 9). Used by both the global catalogue
// matching path (intelligence.js) and the VendorLens config-applicability path
// (configApplicability.js). Governance boundary: these helpers only inform
// advisory matching confidence; they never approve, scan, or deploy anything.

export const MATCH_BASIS = Object.freeze({
  CPE_VERSION_RANGE: "cpe_version_range",
  VERSION_RANGE: "version_range",
  IDENTIFIER: "identifier",
  STRING_FALLBACK: "string_fallback"
});

export function versionSatisfiesAny(version, constraints) {
  return constraints.some((constraint) => versionSatisfies(version, constraint));
}

export function versionSatisfies(version, constraint) {
  const raw = String(constraint || "").trim();
  if (!raw || raw === "*") {
    return true;
  }
  const compact = raw.replace(/\s+/g, "");
  const comparator = compact.match(/^(<=|>=|<|>)(.+)$/);
  if (comparator) {
    const direction = comparator[1];
    const compare = versionCompare(version, comparator[2]);
    if (direction === "<") return compare < 0;
    if (direction === "<=") return compare <= 0;
    if (direction === ">") return compare > 0;
    if (direction === ">=") return compare >= 0;
  }
  const range = compact.match(/^(.+)-(.+)$/);
  if (range && hasVersionNumbers(range[1]) && hasVersionNumbers(range[2])) {
    return versionCompare(version, range[1]) >= 0 && versionCompare(version, range[2]) <= 0;
  }
  if (/x$/i.test(compact)) {
    const prefix = compact.replace(/\.?x$/i, "");
    return normalizedVersion(version).startsWith(`${prefix}.`) || normalizedVersion(version) === prefix;
  }
  return versionCompare(version, compact) === 0;
}

export function versionCompare(left, right) {
  const leftParts = versionParts(left);
  const rightParts = versionParts(right);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const lval = leftParts[index] || 0;
    const rval = rightParts[index] || 0;
    if (lval > rval) return 1;
    if (lval < rval) return -1;
  }
  return 0;
}

export function versionParts(value) {
  return normalizedVersion(value)
    .split(".")
    .filter((part) => part !== "")
    .map((part) => Number.parseInt(part, 10))
    .filter((part) => Number.isFinite(part));
}

export function normalizedVersion(value) {
  const match = String(value || "").toLowerCase().match(/\d+(?:\.\d+)*/);
  return match ? match[0] : "";
}

export function hasVersionNumbers(value) {
  return /\d/.test(String(value || ""));
}

// ---------------------------------------------------------------------------
// CPE 2.3 formatted-string parsing
// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
// "*" = ANY, "-" = NA.
// ---------------------------------------------------------------------------

const CPE_ATTRIBUTES = [
  "part",
  "vendor",
  "product",
  "version",
  "update",
  "edition",
  "language",
  "sw_edition",
  "target_sw",
  "target_hw",
  "other"
];

export function parseCpe(value) {
  const raw = String(value || "").trim();
  if (!/^cpe:2\.3:/i.test(raw)) {
    return null;
  }
  const components = splitCpeComponents(raw.slice("cpe:2.3:".length));
  const parsed = { cpe23: raw };
  for (let index = 0; index < CPE_ATTRIBUTES.length; index += 1) {
    parsed[CPE_ATTRIBUTES[index]] = unescapeCpeComponent(components[index] ?? "*");
  }
  if (!parsed.vendor || parsed.vendor === "-") {
    return null;
  }
  return parsed;
}

function splitCpeComponents(value) {
  const components = [];
  let current = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\\" && index + 1 < value.length) {
      current += character + value[index + 1];
      index += 1;
      continue;
    }
    if (character === ":") {
      components.push(current);
      current = "";
      continue;
    }
    current += character;
  }
  components.push(current);
  return components;
}

function unescapeCpeComponent(value) {
  return String(value || "").replace(/\\(.)/g, "$1").toLowerCase();
}

export function cpeComponentMatches(left, right) {
  const a = String(left ?? "*").toLowerCase();
  const b = String(right ?? "*").toLowerCase();
  if (a === "*" || b === "*" || a === "-" || b === "-") {
    return true;
  }
  return canonicalToken(a) === canonicalToken(b);
}

function canonicalToken(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

// Extract CPE entries from a vulnerability/advisory record. Supported shapes:
// - record.cpe / record.cpes / record.cpe_uris (string or array of strings/objects)
// - NVD 2.0 style: record.configurations[].nodes[].cpeMatch[] with `criteria`
//   plus optional versionStartIncluding / versionStartExcluding /
//   versionEndIncluding / versionEndExcluding range hints.
// Returns entries: { cpe, version_start_including, version_start_excluding,
//                    version_end_including, version_end_excluding }
export function extractCpes(record = {}) {
  const entries = [];
  for (const candidate of flatten([record.cpe, record.cpes, record.cpe_uris, record.cpe_matches])) {
    const entry = cpeEntryFrom(candidate);
    if (entry) {
      entries.push(entry);
    }
  }
  const configurations = flatten([record.configurations, record.raw_record?.configurations]);
  for (const configuration of configurations) {
    for (const node of flatten([configuration?.nodes])) {
      for (const match of flatten([node?.cpeMatch, node?.cpe_match])) {
        const entry = cpeEntryFrom(match);
        if (entry) {
          entries.push(entry);
        }
      }
    }
  }
  return entries;
}

function cpeEntryFrom(candidate) {
  if (!candidate) {
    return null;
  }
  if (typeof candidate === "string") {
    const parsed = parseCpe(candidate);
    return parsed ? { cpe: parsed } : null;
  }
  if (typeof candidate === "object") {
    const parsed = parseCpe(candidate.criteria || candidate.cpe23Uri || candidate.cpe || candidate.cpe_uri || candidate.uri);
    if (!parsed) {
      return null;
    }
    return {
      cpe: parsed,
      vulnerable: candidate.vulnerable !== false,
      version_start_including: candidate.versionStartIncluding || candidate.version_start_including || null,
      version_start_excluding: candidate.versionStartExcluding || candidate.version_start_excluding || null,
      version_end_including: candidate.versionEndIncluding || candidate.version_end_including || null,
      version_end_excluding: candidate.versionEndExcluding || candidate.version_end_excluding || null
    };
  }
  return null;
}

// True when a concrete version satisfies a CPE entry (the embedded version
// component plus any NVD-style range hints).
export function cpeEntryVersionMatches(entry, version) {
  const concrete = normalizedVersion(version);
  if (!concrete) {
    // Unknown version: only the vendor/product comparison can be asserted.
    return true;
  }
  if (entry.version_start_including && versionCompare(concrete, entry.version_start_including) < 0) return false;
  if (entry.version_start_excluding && versionCompare(concrete, entry.version_start_excluding) <= 0) return false;
  if (entry.version_end_including && versionCompare(concrete, entry.version_end_including) > 0) return false;
  if (entry.version_end_excluding && versionCompare(concrete, entry.version_end_excluding) >= 0) return false;
  const cpeVersion = entry.cpe?.version ?? "*";
  if (cpeVersion === "*" || cpeVersion === "-") {
    return true;
  }
  return versionCompare(concrete, cpeVersion) === 0;
}

// Two CPE entry lists overlap when any pair matches on vendor + product (with
// wildcard awareness) and their version components/ranges are compatible.
export function cpeEntriesOverlap(leftEntries = [], rightEntries = []) {
  for (const left of leftEntries) {
    for (const right of rightEntries) {
      if (!cpeComponentMatches(left.cpe.vendor, right.cpe.vendor)) continue;
      if (!cpeComponentMatches(left.cpe.product, right.cpe.product)) continue;
      const leftVersion = left.cpe.version;
      const rightVersion = right.cpe.version;
      const leftConcrete = leftVersion !== "*" && leftVersion !== "-" ? leftVersion : null;
      const rightConcrete = rightVersion !== "*" && rightVersion !== "-" ? rightVersion : null;
      if (leftConcrete && !cpeEntryVersionMatches(right, leftConcrete)) continue;
      if (rightConcrete && !cpeEntryVersionMatches(left, rightConcrete)) continue;
      return true;
    }
  }
  return false;
}

// Match a CPE entry list against loose vendor/product/version fields from a
// PatchForge record (vendor_id, product_family, firmware_version, ...).
export function cpeEntriesMatchVendorProduct(entries = [], { vendor = null, product = null, version = null } = {}) {
  const vendorToken = canonicalToken(vendor);
  const productToken = canonicalToken(product);
  if (!vendorToken && !productToken) {
    return false;
  }
  return entries.some((entry) => {
    const cpeVendor = canonicalToken(entry.cpe.vendor);
    const cpeProduct = canonicalToken(entry.cpe.product);
    const vendorOk = !vendorToken || cpeVendor === "*" || tokensRelate(cpeVendor, vendorToken);
    const productOk = !productToken || cpeProduct === "*" || tokensRelate(cpeProduct, productToken);
    if (!vendorOk || !productOk) {
      return false;
    }
    return cpeEntryVersionMatches(entry, version);
  });
}

function tokensRelate(a, b) {
  if (!a || !b) {
    return false;
  }
  return a === b || a.includes(b) || b.includes(a);
}

function flatten(values) {
  const output = [];
  for (const value of values) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      output.push(...value);
    } else {
      output.push(value);
    }
  }
  return output;
}

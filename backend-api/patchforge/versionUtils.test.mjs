import assert from "node:assert/strict";
import test from "node:test";
import {
  MATCH_BASIS,
  cpeComponentMatches,
  cpeEntriesMatchVendorProduct,
  cpeEntriesOverlap,
  cpeEntryVersionMatches,
  extractCpes,
  normalizedVersion,
  parseCpe,
  versionCompare,
  versionSatisfies,
  versionSatisfiesAny
} from "./versionUtils.js";
import { buildFindingIntelligence } from "./intelligence.js";
import { assessConfigApplicability } from "./configApplicability.js";

test("versionCompare orders dotted versions numerically", () => {
  assert.equal(versionCompare("7.2.7", "7.2.8"), -1);
  assert.equal(versionCompare("7.2.8", "7.2.8"), 0);
  assert.equal(versionCompare("7.10.1", "7.9.9"), 1);
  assert.equal(versionCompare("7.2", "7.2.0"), 0);
  assert.equal(versionCompare("v7.2.7", "7.2.7"), 0);
});

test("versionSatisfies handles comparators, ranges, wildcards, and exact matches", () => {
  assert.equal(versionSatisfies("7.2.7", "< 7.2.8"), true);
  assert.equal(versionSatisfies("7.2.8", "< 7.2.8"), false);
  assert.equal(versionSatisfies("7.2.8", ">= 7.2.8"), true);
  assert.equal(versionSatisfies("10.2.3", "10.2.0-10.2.6"), true);
  assert.equal(versionSatisfies("10.2.7", "10.2.0-10.2.6"), false);
  assert.equal(versionSatisfies("9.18.2", "9.18.x"), true);
  assert.equal(versionSatisfies("9.19.1", "9.18.x"), false);
  assert.equal(versionSatisfies("1.2.3", "*"), true);
  assert.equal(versionSatisfies("1.2.3", "1.2.3"), true);
  assert.equal(versionSatisfiesAny("7.2.7", ["9.x", "< 7.2.8"]), true);
  assert.equal(versionSatisfiesAny("8.0.0", ["9.x", "< 7.2.8"]), false);
});

test("normalizedVersion extracts the numeric core", () => {
  assert.equal(normalizedVersion("FortiOS 7.2.7-build1234"), "7.2.7");
  assert.equal(normalizedVersion("no digits"), "");
});

test("parseCpe parses CPE 2.3 formatted strings including wildcards and escapes", () => {
  const cpe = parseCpe("cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*");
  assert.equal(cpe.part, "o");
  assert.equal(cpe.vendor, "fortinet");
  assert.equal(cpe.product, "fortios");
  assert.equal(cpe.version, "7.2.7");
  assert.equal(cpe.update, "*");

  const wildcard = parseCpe("cpe:2.3:a:cisco:asa_software:*:*:*:*:*:*:*:*");
  assert.equal(wildcard.version, "*");

  const escaped = parseCpe("cpe:2.3:a:vendor:product\\:name:1.0:-:*:*:*:*:*:*");
  assert.equal(escaped.product, "product:name");
  assert.equal(escaped.update, "-");

  assert.equal(parseCpe("not-a-cpe"), null);
  assert.equal(parseCpe(""), null);
});

test("cpeComponentMatches treats * and - as wildcards", () => {
  assert.equal(cpeComponentMatches("*", "fortinet"), true);
  assert.equal(cpeComponentMatches("fortinet", "-"), true);
  assert.equal(cpeComponentMatches("fortinet", "Fortinet"), true);
  assert.equal(cpeComponentMatches("fortinet", "cisco"), false);
});

test("extractCpes reads cpe, cpes, cpe_uris fields and NVD-style configurations", () => {
  const record = {
    cpe: "cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*",
    cpes: ["cpe:2.3:h:fortinet:fortigate-100f:-:*:*:*:*:*:*:*"],
    cpe_uris: ["cpe:2.3:a:cisco:asa_software:9.18:*:*:*:*:*:*:*"],
    configurations: [{
      nodes: [{
        cpeMatch: [{
          criteria: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
          versionStartIncluding: "10.2.0",
          versionEndExcluding: "10.2.7"
        }]
      }]
    }]
  };
  const entries = extractCpes(record);
  assert.equal(entries.length, 4);
  assert.equal(entries[0].cpe.vendor, "fortinet");
  assert.equal(entries[3].cpe.vendor, "paloaltonetworks");
  assert.equal(entries[3].version_start_including, "10.2.0");
  assert.equal(entries[3].version_end_excluding, "10.2.7");
  assert.deepEqual(extractCpes({}), []);
});

test("cpeEntryVersionMatches respects NVD version range hints", () => {
  const [entry] = extractCpes({
    configurations: [{
      nodes: [{
        cpeMatch: [{
          criteria: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
          versionStartIncluding: "10.2.0",
          versionEndExcluding: "10.2.7"
        }]
      }]
    }]
  });
  assert.equal(cpeEntryVersionMatches(entry, "10.2.5"), true);
  assert.equal(cpeEntryVersionMatches(entry, "10.2.7"), false);
  assert.equal(cpeEntryVersionMatches(entry, "10.1.9"), false);
});

test("cpeEntriesOverlap matches on vendor+product with version awareness", () => {
  const left = extractCpes({ cpe: "cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*" });
  const sameProduct = extractCpes({ cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" });
  const otherVersion = extractCpes({ cpe: "cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*" });
  const otherVendor = extractCpes({ cpe: "cpe:2.3:o:cisco:asa_software:7.2.7:*:*:*:*:*:*:*" });
  assert.equal(cpeEntriesOverlap(left, sameProduct), true);
  assert.equal(cpeEntriesOverlap(left, otherVersion), false);
  assert.equal(cpeEntriesOverlap(left, otherVendor), false);
});

test("cpeEntriesMatchVendorProduct matches loose vendor/product/version fields", () => {
  const entries = extractCpes({ cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" });
  assert.equal(cpeEntriesMatchVendorProduct(entries, { vendor: "fortinet", product: "FortiOS", version: "7.2.7" }), true);
  assert.equal(cpeEntriesMatchVendorProduct(entries, { vendor: "cisco", product: "ASA" }), false);
  assert.equal(cpeEntriesMatchVendorProduct(entries, {}), false);
});

test("matchAdvisories assigns match_basis per the PF-AZ12 ladder", () => {
  const vulnerability = {
    vulnerability_id: "CVE-2026-MATCH-001",
    canonical_id: "CVE-2026-MATCH-001",
    title: "FortiOS SSL-VPN issue",
    severity: "high",
    vendor_id: "fortinet",
    product_family: "FortiOS",
    affected_versions: ["7.2.7"],
    cpe: "cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*",
    sources: [],
    tags: []
  };
  const advisories = [
    { advisory_id: "ADV-ID", cve: "CVE-2026-MATCH-001", vendor_id: "fortinet" },
    { advisory_id: "ADV-CPE", cpes: ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"], vendor_id: "someone-else" },
    { advisory_id: "ADV-VER", vendor_id: "fortinet", product_family: "FortiOS", affected_versions: ["< 7.2.8"] },
    { advisory_id: "ADV-STR-CVE-2026-MATCH-001-suffix", vendor_id: "unrelated" },
    { advisory_id: "ADV-NONE", vendor_id: "cisco", product_family: "ASA", affected_versions: ["9.18.x"] }
  ];
  const intelligence = buildFindingIntelligence({ vulnerability, vendorAdvisories: advisories });
  const byId = Object.fromEntries(intelligence.source_context.advisory_matches.map((item) => [item.advisory_id, item.match_basis]));
  assert.equal(byId["ADV-ID"], MATCH_BASIS.IDENTIFIER);
  assert.equal(byId["ADV-CPE"], MATCH_BASIS.CPE_VERSION_RANGE);
  assert.equal(byId["ADV-VER"], MATCH_BASIS.VERSION_RANGE);
  assert.equal(byId["ADV-STR-CVE-2026-MATCH-001-suffix"], MATCH_BASIS.STRING_FALLBACK);
  assert.equal(byId["ADV-NONE"], undefined);
  assert.equal(intelligence.source_context.vendor_advisory_count, 4);
});

test("inferVendorProduct prefers CPE vendor/product when present", () => {
  const intelligence = buildFindingIntelligence({
    vulnerability: {
      vulnerability_id: "CVE-2026-MATCH-002",
      title: "Some unrelated title words",
      severity: "high",
      cpe_uris: ["cpe:2.3:o:fortinet:fortios:7.2.7:*:*:*:*:*:*:*"],
      sources: [],
      tags: []
    },
    vendorAdvisories: []
  });
  assert.equal(intelligence.vendor, "Fortinet");
  assert.equal(intelligence.product, "Fortios");
});

test("assessConfigApplicability exposes match_basis and keeps governance boundary", () => {
  const cpeAssessment = assessConfigApplicability({
    advisory: {
      advisory_id: "ADV-CPE-1",
      cve: "CVE-2026-CFG-001",
      cpes: ["cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"],
      affected_versions: ["< 7.2.8"]
    },
    asset: { asset_id: "fw-1", vendor_id: "fortinet", product_family: "FortiOS", firmware_version: "7.2.7" }
  });
  assert.equal(cpeAssessment.match_basis, MATCH_BASIS.CPE_VERSION_RANGE);
  assert.equal(cpeAssessment.final_approval_issued, false);

  const versionAssessment = assessConfigApplicability({
    advisory: { advisory_id: "ADV-VER-1", cve: "CVE-2026-CFG-002", affected_versions: ["< 7.2.8"] },
    asset: { asset_id: "fw-1", vendor_id: "fortinet", product_family: "FortiOS", firmware_version: "7.2.7" }
  });
  assert.equal(versionAssessment.match_basis, MATCH_BASIS.VERSION_RANGE);

  const identifierAssessment = assessConfigApplicability({
    advisory: { advisory_id: "ADV-ONLY-1", cve: "CVE-2026-CFG-003" },
    asset: { asset_id: "fw-1", vendor_id: "fortinet", product_family: "FortiOS" }
  });
  assert.equal(identifierAssessment.match_basis, MATCH_BASIS.IDENTIFIER);

  const fallbackAssessment = assessConfigApplicability({
    advisory: { title: "Unidentified advisory" },
    asset: { asset_id: "fw-1", vendor_id: "fortinet" }
  });
  assert.equal(fallbackAssessment.match_basis, MATCH_BASIS.STRING_FALLBACK);
});

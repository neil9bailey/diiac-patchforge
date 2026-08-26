import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { normalizeSourceRecord, syncSourceAdapter } from "./sourceAdapters.js";
import { PatchForgeJsonStorage } from "./storage.js";

const TENANT = "tenant-source-adapter";

const ADAPTER = {
  adapter_id: "vendor-advisory",
  name: "Vendor Advisory",
  provider: "Example Vendor",
  source_url: "https://example.invalid/advisories",
  source_class: "vendor_advisory"
};

test("source adapters preserve absent risk scores without inventing threat signals", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-source-adapter-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    const result = await syncSourceAdapter({
      storage,
      tenantId: TENANT,
      body: {
        adapter_id: "vendor-advisory",
        fetched_at: "2026-08-24T12:00:00.000Z",
        records: [{
          cve_id: "CVE-2026-9999",
          advisory_id: "VENDOR-2026-9999",
          title: "Advisory with no CVSS or EPSS data",
          severity: "unknown",
          vendor: "Example Vendor",
          product: "Example Product",
          source_url: "https://example.invalid/advisories/9999",
          last_modified: "2026-08-24T10:00:00.000Z"
        }]
      }
    });

    const [normalized] = result.normalized_records;
    assert.equal(normalized.cvss_score, null);
    assert.equal(normalized.epss_probability, null);
    assert.equal(normalized.epss_percentile, null);
    assert.deepEqual(await storage.list("threat_signals", TENANT), []);
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("source adapters reject malformed and non-finite risk scores fail-closed", () => {
  for (const value of [true, false, { score: 7 }, Number.NaN, Infinity, -Infinity]) {
    const record = normalizeSourceRecord(ADAPTER, { cvss_score: value, epss_probability: value });
    assert.equal(record.cvss_score, null, `expected ${String(value)} cvss to stay null`);
    assert.equal(record.epss_probability, null, `expected ${String(value)} epss to stay null`);
  }
  // Valid finite numbers and numeric strings are retained.
  const valid = normalizeSourceRecord(ADAPTER, { cvss_score: "7.5", epss_probability: 0.42 });
  assert.equal(valid.cvss_score, 7.5);
  assert.equal(valid.epss_probability, 0.42);
});

test("source adapters never turn false-like strings into known-exploited signals", () => {
  const falseLike = ["false", "0", "no", "off", ""];
  for (const value of [...falseLike, 0]) {
    const record = normalizeSourceRecord(ADAPTER, {
      kev: value,
      known_exploited: value,
      active_exploitation: value
    });
    assert.equal(record.kev, false, `kev must be false for ${JSON.stringify(value)}`);
    assert.equal(
      record.active_exploitation,
      false,
      `active_exploitation must be false for ${JSON.stringify(value)}`
    );
  }
  // Affirmative values remain true; absent values default to false.
  const affirmative = normalizeSourceRecord(ADAPTER, { kev: true });
  assert.equal(affirmative.kev, true);
  assert.equal(affirmative.active_exploitation, true);
  const absent = normalizeSourceRecord(ADAPTER, {});
  assert.equal(absent.kev, false);
  assert.equal(absent.active_exploitation, false);
});

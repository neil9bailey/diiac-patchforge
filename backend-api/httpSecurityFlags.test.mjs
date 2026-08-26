import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { once } from "node:events";
import { createServer } from "./server.js";
import { createPatchForgeStorage } from "./patchforge/storage.js";

const FALSE_LIKE_FLAGS = ["false", "False", "FALSE", "0", "no", "off", "", 0, false, [], {}, Number.NaN];

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

async function post(base, route, body) {
  const res = await fetch(`${base}${route}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    // non-JSON error bodies are fine for these probes
  }
  return { status: res.status, body: json };
}

async function get(base, route) {
  const res = await fetch(`${base}${route}`);
  return { status: res.status, body: await res.json() };
}

test("HTTP ingestion routes reject false-like security flags end-to-end", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-http-flags-"));
  const server = createServer({
    storage: createPatchForgeStorage({ storageRoot }),
    auth: { required: false }
  });
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  try {
    // F2a: agent findings ingest
    for (const value of FALSE_LIKE_FLAGS) {
      const r = await post(base, "/api/patchforge/agent-findings/ingest", {
        finding_id: `AF-${String(value).replace(/\W/g, "") || "blank"}`,
        title: "probe",
        known_exploited: value,
        internet_exposed: value,
        ot_relevant: value
      });
      assert.equal(r.status, 202, `agent-findings ingest should accept ${JSON.stringify(value)}`);
      assert.equal(r.body.vulnerability.known_exploited, false);
      assert.equal(r.body.vulnerability.internet_exposed, false);
    }

    // F2b: vendor advisory ingest must not raise exploitation counts
    await post(base, "/api/patchforge/vendors/acme/advisories/ingest", {
      advisory_id: "ACME-1",
      title: "probe",
      known_exploited: "false",
      patch_available: "no"
    });
    const landscape = await get(base, "/api/patchforge/threat-landscape/summary");
    assert.equal(landscape.body.metrics.active_exploitation_count, 0);

    // F2c: vendorlens advisory ingest
    const vlAdvisory = await post(base, "/api/patchforge/vendorlens/advisories/ingest", {
      vendor_id: "cisco",
      advisory_id: "VL-1",
      cve: "CVE-2026-PROBE1",
      known_exploited: "false"
    });
    assert.equal(vlAdvisory.body.advisory.known_exploited, false);

    // F1: vendorlens asset upsert
    const vlAsset = await post(base, "/api/patchforge/vendorlens/assets", {
      asset_id: "net-probe-1",
      vendor_id: "cisco",
      internet_facing: "false"
    });
    assert.equal(vlAsset.status, 201);
    assert.equal(vlAsset.body.asset.internet_facing, false);

    // Raw passthrough vulnerabilities/ingest
    for (const value of ["false", "no", 0]) {
      const r = await post(base, "/api/patchforge/vulnerabilities/ingest", {
        vulnerability_id: `VULN-PASSTHRU-${String(value)}`,
        title: "passthrough probe",
        kev: value,
        known_exploited: value
      });
      assert.equal(r.status, 201);
      assert.equal(r.body.vulnerability.kev, false);
      assert.equal(r.body.vulnerability.known_exploited, false);
    }

    // F4: Bayesian assess must not inflate from a false-like string (unconditional).
    const omitted = await post(base, "/api/patchforge/bayesian/assess", {
      vulnerability_id: "VULN-BAYES-PROBE"
    });
    const withFalse = await post(base, "/api/patchforge/bayesian/assess", {
      vulnerability_id: "VULN-BAYES-PROBE",
      known_exploited: "false"
    });
    const posteriorOf = (r) =>
      r.body?.bayesian?.exploit_probability_posterior ??
      r.body?.assessment?.exploit_probability_posterior;
    const pOmitted = posteriorOf(omitted);
    const pFalse = posteriorOf(withFalse);
    assert.ok(pOmitted !== undefined, "bayesian omitted response must carry a posterior");
    assert.ok(pFalse !== undefined, "bayesian with-false response must carry a posterior");
    assert.equal(
      pOmitted,
      pFalse,
      `"false" must not change exploit probability (${pOmitted} vs ${pFalse})`
    );
    // Positive control: an affirmative true value MUST inflate the posterior.
    const withTrue = await post(base, "/api/patchforge/bayesian/assess", {
      vulnerability_id: "VULN-BAYES-PROBE",
      known_exploited: true
    });
    assert.ok(
      posteriorOf(withTrue) > pOmitted,
      `legitimate known_exploited=true must raise the posterior (${posteriorOf(withTrue)} vs ${pOmitted})`
    );

    // F5: customer-estate extract and match must not flip false-like exposure to true.
    for (const value of ["false", "no", 0, []]) {
      const extracted = await post(base, "/api/patchforge/customer-estate/assets/extract", {
        description: "Cisco ASA at edge site",
        internet_facing: value
      });
      assert.equal(
        extracted.body.extracted_asset.internet_facing,
        false,
        `extract must keep ${JSON.stringify(value)} non-exposed`
      );
      const matched = await post(base, "/api/patchforge/customer-estate/match", {
        description: "Cisco ASA at edge site",
        internet_facing: value
      });
      if (matched.body.asset) {
        assert.equal(matched.body.asset.internet_facing, false);
      }
    }
    // Positive control: affirmative value stays true through extract.
    const extractedTrue = await post(base, "/api/patchforge/customer-estate/assets/extract", {
      description: "Cisco ASA at edge site",
      internet_facing: "yes"
    });
    assert.equal(extractedTrue.body.extracted_asset.internet_facing, true);

    // F6: patch-compare must not upgrade to remediates from a false-like evidence flag.
    // The route wraps the summary in a `comparison` envelope and derives
    // target_version_status itself; supplying a target_version with no advisory
    // fixed-list marks it "recorded as fixed pending review".
    const remediationOf = (r) => r.body?.comparison?.proposed_version_remediates;
    const compareBody = { target_version: "7.2.8" };
    const compareNoEvidence = await post(base, "/api/patchforge/customer-estate/patch-compare", {
      ...compareBody,
      reviewed_evidence: undefined
    });
    assert.notEqual(remediationOf(compareNoEvidence), "remediates");
    const compareFalseEvidence = await post(base, "/api/patchforge/customer-estate/patch-compare", {
      ...compareBody,
      reviewed_evidence: "false"
    });
    assert.notEqual(
      remediationOf(compareFalseEvidence),
      "remediates",
      "reviewed_evidence=\"false\" must not manufacture a remediation verdict"
    );
    // Positive control: legitimate reviewed evidence DOES yield the remediation verdict.
    const compareTrueEvidence = await post(base, "/api/patchforge/customer-estate/patch-compare", {
      ...compareBody,
      reviewed_evidence: true
    });
    assert.equal(remediationOf(compareTrueEvidence), "remediates");
  } finally {
    server.close();
    await rm(storageRoot, { recursive: true, force: true });
  }
});

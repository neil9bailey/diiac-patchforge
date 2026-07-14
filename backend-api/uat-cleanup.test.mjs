import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { rolesForRoute } from "./auth.js";
import { createServer } from "./server.js";
import { PatchForgeJsonStorage, PatchForgePostgresStorage } from "./patchforge/storage.js";

const TENANT_ID = "diiac.io";
const TOKEN_TENANT_ID = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da";
const TARGET_ID = "UAT-PF-CLEANUP-001";
const PREFIX_COLLISION_ID = `${TARGET_ID}-OTHER`;

test("UAT cleanup route is Admin-only", () => {
  assert.deepEqual(
    rolesForRoute("POST", "/api/patchforge/admin/uat-cleanup"),
    ["PatchForge.Admin"]
  );
});

test("local UAT cleanup deletes exact linked records and preserves audit history", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-uat-cleanup-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  try {
    await seedUatRecords(storage);

    await assert.rejects(
      storage.cleanupUatRecords(TENANT_ID, { identifier: "CVE-2099-NOT-UAT" }),
      (error) => error.statusCode === 400 && error.publicError === "invalid_uat_identifier"
    );
    await assert.rejects(
      storage.cleanupUatRecords(TENANT_ID, { identifier: TARGET_ID, all: false }),
      (error) => error.statusCode === 400 && error.publicError === "collection_wide_selection_forbidden"
    );

    const preview = await storage.cleanupUatRecords(TENANT_ID, {
      identifier: TARGET_ID,
      dry_run: true
    });
    assert.equal(preview.dry_run, true);
    assert.equal(preview.selection_mode, "exact_identifier_value");
    assert.equal(preview.total_records, 3);
    assert.deepEqual(preview.collections, ["vulnerabilities", "sources", "decision_packs"]);
    assert.equal(preview.boundary.collection_wide_selection_permitted, false);
    assert.equal(preview.boundary.audit_events_preserved, true);
    assert.match(preview.preview_token, /^[0-9a-f-]{36}$/i);
    assert.match(preview.preview_digest, /^[a-f0-9]{64}$/);

    await assert.rejects(
      storage.cleanupUatRecords(TENANT_ID, {
        identifier: TARGET_ID,
        dry_run: false,
        confirm: TARGET_ID
      }),
      (error) => error.statusCode === 400 && error.publicError === "uat_cleanup_preview_required"
    );
    await assert.rejects(
      storage.cleanupUatRecords("other-tenant", {
        identifier: TARGET_ID,
        dry_run: false,
        confirm: TARGET_ID,
        preview_token: preview.preview_token
      }),
      (error) => error.statusCode === 409 && error.publicError === "uat_cleanup_preview_invalid"
    );

    const blocked = await storage.cleanupUatRecords(TENANT_ID, {
      identifier: TARGET_ID,
      dry_run: false,
      confirm: "UAT-PF-WRONG"
    });
    assert.equal(blocked.blocked, true);
    assert.equal(blocked.error, "exact_identifier_confirmation_required");
    assert.equal(blocked.storage_mutation_executed, false);
    assert.equal((await storage.list("vulnerabilities", TENANT_ID)).length, 2);

    await storage.append("sources", {
      tenant_id: TENANT_ID,
      source_record_id: "source-after-preview",
      vulnerability_id: TARGET_ID
    });
    await assert.rejects(
      storage.cleanupUatRecords(TENANT_ID, {
        identifier: TARGET_ID,
        dry_run: false,
        confirm: TARGET_ID,
        preview_token: preview.preview_token
      }),
      (error) => error.statusCode === 409 && error.publicError === "uat_cleanup_preview_drift"
    );
    assert.equal((await storage.list("sources", TENANT_ID)).length, 3);

    const currentPreview = await storage.cleanupUatRecords(TENANT_ID, {
      identifier: TARGET_ID,
      dry_run: true
    });
    assert.equal(currentPreview.total_records, 4);

    const completed = await storage.cleanupUatRecords(TENANT_ID, {
      identifier: TARGET_ID,
      dry_run: false,
      confirm: TARGET_ID,
      preview_token: currentPreview.preview_token,
      lineage: {
        actor_oid: "admin-oid",
        actor_upn: "admin@diiac.io",
        actor_roles: ["PatchForge.Admin"]
      }
    });
    assert.equal(completed.total_removed, 4);
    assert.match(completed.audit_id, /^audit-/);
    assert.equal(completed.storage_mutation_executed, true);

    const vulnerabilities = await storage.list("vulnerabilities", TENANT_ID);
    assert.deepEqual(vulnerabilities.map((record) => record.vulnerability_id), [PREFIX_COLLISION_ID]);
    assert.equal((await storage.list("sources", TENANT_ID)).length, 1);
    assert.equal((await storage.list("decision_packs", TENANT_ID)).length, 0);

    const audits = await storage.list("audit_events", TENANT_ID);
    assert.equal(audits.length, 2);
    assert.ok(audits.some((event) => event.event_type === "uat_fixture_created"));
    const cleanupAudit = audits.find((event) => event.audit_id === completed.audit_id);
    assert.equal(cleanupAudit.event_type, "patchforge_uat_cleanup_completed");
    assert.equal(cleanupAudit.details.identifier, TARGET_ID);
    assert.equal(cleanupAudit.details.preview_digest, currentPreview.preview_digest);
    assert.equal(cleanupAudit.details.actor_oid, "admin-oid");
    assert.deepEqual(cleanupAudit.details.actor_roles, ["PatchForge.Admin"]);
    await assert.rejects(
      storage.cleanupUatRecords(TENANT_ID, {
        identifier: TARGET_ID,
        dry_run: false,
        confirm: TARGET_ID,
        preview_token: currentPreview.preview_token
      }),
      (error) => error.statusCode === 409 && error.publicError === "uat_cleanup_preview_consumed"
    );
  } finally {
    await rm(storageRoot, { recursive: true, force: true });
  }
});

test("PostgreSQL UAT cleanup uses record-ID deletes and commits its audit atomically", async () => {
  const database = createFakePostgresDatabase([
    postgresRow("vulnerabilities", TARGET_ID, {
      tenant_id: TENANT_ID,
      vulnerability_id: TARGET_ID,
      title: "Target UAT record"
    }),
    postgresRow("vulnerabilities", PREFIX_COLLISION_ID, {
      tenant_id: TENANT_ID,
      vulnerability_id: PREFIX_COLLISION_ID,
      title: "Must survive"
    }),
    postgresRow("sources", "source-target", {
      tenant_id: TENANT_ID,
      source_record_id: "source-target",
      vulnerability_id: TARGET_ID
    }),
    postgresRow("audit_events", "audit-existing", {
      tenant_id: TENANT_ID,
      audit_id: "audit-existing",
      event_type: "uat_fixture_created",
      details: { identifier: TARGET_ID }
    })
  ]);
  const storage = new PatchForgePostgresStorage({ pool: database.pool });
  storage.ready = true;

  const preview = await storage.cleanupUatRecords(TENANT_ID, {
    identifier: TARGET_ID,
    dry_run: true
  });
  assert.equal(preview.total_records, 2);
  assert.equal(database.rows.length, 5);

  const completed = await storage.cleanupUatRecords(TENANT_ID, {
    identifier: TARGET_ID,
    dry_run: false,
    confirm: TARGET_ID,
    preview_token: preview.preview_token,
    lineage: { actor_oid: "postgres-admin", actor_roles: ["PatchForge.Admin"] }
  });
  assert.equal(completed.total_removed, 2);
  assert.equal(database.commits, 1);
  assert.equal(database.rollbacks, 0);
  assert.equal(database.releases, 1);
  assert.ok(database.deleteCalls.length > 0);
  for (const call of database.deleteCalls) {
    assert.match(call.sql, /record_id = any\(\$3::text\[\]\)/);
    assert.ok(call.params[2].length > 0, "delete IDs must never be empty");
  }

  assert.ok(database.rows.some((row) => row.record_id === PREFIX_COLLISION_ID));
  assert.ok(database.rows.some((row) => row.record_id === "audit-existing"));
  const auditRow = database.rows.find((row) => row.record_id === completed.audit_id);
  assert.equal(auditRow.collection, "audit_events");
  assert.equal(auditRow.record.event_type, "patchforge_uat_cleanup_completed");
  assert.equal(auditRow.record.details.actor_oid, "postgres-admin");
  assert.equal(auditRow.record.details.preview_digest, preview.preview_digest);
  const previewRow = database.rows.find((row) => row.collection === "uat_cleanup_previews");
  assert.equal(previewRow.record.status, "consumed");
});

test("UAT cleanup API rejects broad selectors and requires exact typed confirmation", async () => {
  const storageRoot = await mkdtemp(path.join(os.tmpdir(), "patchforge-uat-api-"));
  const storage = new PatchForgeJsonStorage(storageRoot);
  await seedUatRecords(storage);
  const server = createServer({
    storage,
    auth: {
      required: true,
      defaultTenant: TENANT_ID,
      tenantMappings: { [TOKEN_TENANT_ID]: TENANT_ID },
      verifier: async (token) => ({
        tid: TOKEN_TENANT_ID,
        oid: `${token}-oid`,
        upn: `${token}@diiac.io`,
        roles: token === "admin" ? ["PatchForge.Admin"] : ["PatchForge.TriageAnalyst"]
      })
    }
  });
  const baseUrl = await listen(server);
  try {
    const forbidden = await apiRequest(baseUrl, { identifier: TARGET_ID }, "triage");
    assert.equal(forbidden.response.status, 403);

    const broad = await apiRequest(baseUrl, { identifier: TARGET_ID, all: true }, "admin");
    assert.equal(broad.response.status, 400);
    assert.equal(broad.body.error, "collection_wide_selection_forbidden");

    const invalid = await apiRequest(baseUrl, { identifier: "PF-NOT-UAT" }, "admin");
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.body.error, "invalid_uat_identifier");

    const preview = await apiRequest(baseUrl, { identifier: TARGET_ID }, "admin");
    assert.equal(preview.response.status, 200);
    assert.equal(preview.body.cleanup.total_records, 3);
    assert.equal(preview.body.cleanup.required_confirmation, TARGET_ID);
    assert.match(preview.body.cleanup.preview_token, /^[0-9a-f-]{36}$/i);

    const direct = await apiRequest(baseUrl, {
      identifier: TARGET_ID,
      dry_run: false,
      confirm: TARGET_ID
    }, "admin");
    assert.equal(direct.response.status, 400);
    assert.equal(direct.body.error, "uat_cleanup_preview_required");

    const blocked = await apiRequest(baseUrl, {
      identifier: TARGET_ID,
      dry_run: false,
      confirm: "UAT-PF-WRONG"
    }, "admin");
    assert.equal(blocked.response.status, 400);
    assert.equal(blocked.body.error, "exact_identifier_confirmation_required");

    const completed = await apiRequest(baseUrl, {
      identifier: TARGET_ID,
      dry_run: false,
      confirm: TARGET_ID,
      preview_token: preview.body.cleanup.preview_token
    }, "admin");
    assert.equal(completed.response.status, 202);
    assert.equal(completed.body.cleanup.total_removed, 3);
    assert.match(completed.body.cleanup.audit_id, /^audit-/);

    const cleanupAudit = (await storage.list("audit_events", TENANT_ID))
      .find((event) => event.audit_id === completed.body.cleanup.audit_id);
    assert.equal(cleanupAudit.details.actor_oid, "admin-oid");
    assert.deepEqual(cleanupAudit.details.actor_roles, ["PatchForge.Admin"]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(storageRoot, { recursive: true, force: true });
  }
});

async function seedUatRecords(storage) {
  await storage.append("vulnerabilities", {
    tenant_id: TENANT_ID,
    vulnerability_id: TARGET_ID,
    title: "Target UAT record"
  });
  await storage.append("vulnerabilities", {
    tenant_id: TENANT_ID,
    vulnerability_id: PREFIX_COLLISION_ID,
    title: "Must survive"
  });
  await storage.append("sources", {
    tenant_id: TENANT_ID,
    source_record_id: "source-target",
    vulnerability_id: TARGET_ID
  });
  await storage.append("sources", {
    tenant_id: TENANT_ID,
    source_record_id: "source-prefix-collision",
    vulnerability_id: PREFIX_COLLISION_ID
  });
  await storage.append("decision_packs", {
    tenant_id: TENANT_ID,
    decision_pack_id: "decision-pack-target",
    selected_scope: { vulnerability_ids: [TARGET_ID] }
  });
  await storage.audit(TENANT_ID, "uat_fixture_created", { identifier: TARGET_ID });
}

function postgresRow(collection, recordId, record) {
  return { tenant_id: TENANT_ID, collection, record_id: recordId, record };
}

function createFakePostgresDatabase(initialRows) {
  const database = {
    rows: [...initialRows],
    deleteCalls: [],
    commits: 0,
    rollbacks: 0,
    releases: 0
  };
  const client = {
    async query(sql, params = []) {
      const normalized = String(sql).replace(/\s+/g, " ").trim().toLowerCase();
      if (normalized === "begin") {
        return { rows: [], rowCount: 0 };
      }
      if (normalized === "commit") {
        database.commits += 1;
        return { rows: [], rowCount: 0 };
      }
      if (normalized === "rollback") {
        database.rollbacks += 1;
        return { rows: [], rowCount: 0 };
      }
      if (normalized === "lock table patchforge_records in share row exclusive mode") {
        return { rows: [], rowCount: 0 };
      }
      if (normalized.startsWith("select collection, record_id, record from patchforge_records") && params.length === 2) {
        const [tenantId, collections] = params;
        return {
          rows: database.rows.filter((row) => row.tenant_id === tenantId && collections.includes(row.collection))
        };
      }
      if (normalized.startsWith("select record from patchforge_records") && normalized.includes("uat_cleanup_previews") && normalized.includes("for update")) {
        const [tenantId, tokenHash] = params;
        const row = database.rows.find((item) => (
          item.tenant_id === tenantId
            && item.collection === "uat_cleanup_previews"
            && item.record.preview_token_sha256 === tokenHash
        ));
        return { rows: row ? [{ record: row.record }] : [] };
      }
      if (normalized.includes("for update")) {
        const [tenantId, collection, recordIds] = params;
        return {
          rows: database.rows.filter((row) => (
            row.tenant_id === tenantId
              && row.collection === collection
              && recordIds.includes(row.record_id)
          ))
        };
      }
      if (normalized.startsWith("delete from patchforge_records")) {
        database.deleteCalls.push({ sql: normalized, params });
        const [tenantId, collection, recordIds] = params;
        const deleted = database.rows.filter((row) => (
          row.tenant_id === tenantId
            && row.collection === collection
            && recordIds.includes(row.record_id)
        ));
        database.rows = database.rows.filter((row) => !deleted.includes(row));
        return { rows: deleted.map((row) => ({ record_id: row.record_id })), rowCount: deleted.length };
      }
      if (normalized.startsWith("update patchforge_records") && normalized.includes("uat_cleanup_previews")) {
        const [serializedPatch, tenantId, previewId] = params;
        const row = database.rows.find((item) => (
          item.tenant_id === tenantId
            && item.collection === "uat_cleanup_previews"
            && item.record_id === previewId
        ));
        if (row) {
          row.record = { ...row.record, ...JSON.parse(serializedPatch) };
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }
      if (normalized.startsWith("insert into patchforge_records") && normalized.includes("'audit_events'")) {
        const [tenantId, auditId, serializedRecord] = params;
        database.rows.push({
          tenant_id: tenantId,
          collection: "audit_events",
          record_id: auditId,
          record: JSON.parse(serializedRecord)
        });
        return { rows: [], rowCount: 1 };
      }
      if (normalized.startsWith("insert into patchforge_records") && normalized.includes("on conflict")) {
        const [tenantId, collection, recordId, serializedRecord] = params;
        const record = JSON.parse(serializedRecord);
        const existing = database.rows.find((row) => (
          row.tenant_id === tenantId && row.collection === collection && row.record_id === recordId
        ));
        if (existing) {
          existing.record = record;
        } else {
          database.rows.push({ tenant_id: tenantId, collection, record_id: recordId, record });
        }
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`Unexpected fake PostgreSQL query: ${normalized}`);
    },
    release() {
      database.releases += 1;
    }
  };
  database.pool = {
    query: (...args) => client.query(...args),
    connect: async () => client
  };
  return database;
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function apiRequest(baseUrl, body, token) {
  const response = await fetch(`${baseUrl}/api/patchforge/admin/uat-cleanup`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });
  return { response, body: await response.json() };
}

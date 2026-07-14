import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyStoredExportArtifact, verifiedArtifact } from "./exportArtifacts.js";
import { PatchForgeJsonStorage } from "./storage.js";

test("stored export verification binds exact bytes to the signed descriptor and manifest", () => {
  const bytes = Buffer.from("%PDF-1.7\nfixed report bytes\n");
  const descriptor = {
    name: "report.pdf",
    media_type: "application/pdf",
    sha256: sha256(bytes),
    size_bytes: bytes.length
  };
  const manifest = {
    manifest_id: "PF-EXPORT-test",
    pack_id: "PF-TEST-1",
    artefact_count: 1,
    artefacts: [descriptor],
    final_approval_issued: false,
    source_pack_immutable: true
  };
  manifest.governance_manifest_sha256 = "a".repeat(64);
  const manifestHash = sha256(canonicalJson(manifest));
  const signedPayload = { manifest_id: manifest.manifest_id, manifest_sha256: manifestHash, pack_id: manifest.pack_id, governance_manifest_sha256: manifest.governance_manifest_sha256 };
  const signatureMetadata = { algorithm: "dev_hmac_sha256", signed_payload: signedPayload };
  const signature = createHmac("sha256", "patchforge-dev-test-key").update(canonicalJson(signedPayload)).digest("hex");
  const record = {
    artifact_id: "PF-ARTIFACT-test",
    artifact_kind: "report:test:pdf",
    pack_id: "PF-TEST-1",
    source_governance_manifest_sha256: manifest.governance_manifest_sha256,
    file_name: descriptor.name,
    content_type: descriptor.media_type,
    sha256: descriptor.sha256,
    size_bytes: descriptor.size_bytes,
    content_base64: bytes.toString("base64"),
    signed_manifest: manifest,
    signed_manifest_sha256: manifestHash,
    signature,
    signature_sha256: sha256(signature),
    signature_metadata: signatureMetadata,
    signature_metadata_sha256: sha256(canonicalJson(signatureMetadata)),
    runtime_verification: { verified: true },
    immutable: true,
    source_pack_immutable: true
  };

  assert.equal(verifyStoredExportArtifact(record).verified, true);
  assert.equal(verifyStoredExportArtifact(record).signature_verified_on_download, true);
  const tampered = { ...record, content_base64: Buffer.from("tampered").toString("base64") };
  const verification = verifyStoredExportArtifact(tampered);
  assert.equal(verification.verified, false);
  assert.ok(verification.failures.includes("artifact_sha256_mismatch"));
  assert.throws(() => verifiedArtifact(tampered), { code: "export_artifact_integrity_failed" });
  const signatureTampered = { ...record, signature: "changed" };
  assert.ok(verifyStoredExportArtifact(signatureTampered).failures.includes("signature_integrity_mismatch"));
});

test("immutable artifact insertion is first-writer-wins under concurrent local requests", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "patchforge-immutable-export-"));
  const storage = new PatchForgeJsonStorage(root);
  try {
    await storage.ensureReady();
    const base = { tenant_id: "tenant-a", artifact_id: "artifact-1", immutable: true };
    const [left, right] = await Promise.all([
      storage.appendImmutable("export_artifacts", { ...base, sha256: "a".repeat(64) }),
      storage.appendImmutable("export_artifacts", { ...base, sha256: "b".repeat(64) })
    ]);
    assert.equal([left.created, right.created].filter(Boolean).length, 1);
    assert.equal(left.record.sha256, right.record.sha256);
    assert.equal((await storage.list("export_artifacts", "tenant-a")).length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, sortValue(nested)]));
  }
  return value;
}

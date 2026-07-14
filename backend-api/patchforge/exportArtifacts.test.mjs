import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, sign as signPayload } from "node:crypto";
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

test("stored ES256 export verification accepts only standards or exact historical Azure enum labels", () => {
  const bytes = Buffer.from("signed report bytes");
  const descriptor = {
    name: "report.docx",
    media_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    sha256: sha256(bytes),
    size_bytes: bytes.length
  };
  const manifest = {
    manifest_id: "PF-EXPORT-es256",
    pack_id: "PF-ES256-1",
    artefact_count: 1,
    artefacts: [descriptor],
    final_approval_issued: false,
    source_pack_immutable: true,
    governance_manifest_sha256: "b".repeat(64)
  };
  const manifestHash = sha256(canonicalJson(manifest));
  const signedPayload = {
    manifest_id: manifest.manifest_id,
    manifest_sha256: manifestHash,
    pack_id: manifest.pack_id,
    governance_manifest_sha256: manifest.governance_manifest_sha256
  };
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const standardsJwk = publicKey.export({ format: "jwk" });
  const signature = signPayload(
    "sha256",
    Buffer.from(canonicalJson(signedPayload), "utf8"),
    { key: privateKey, dsaEncoding: "ieee-p1363" }
  ).toString("base64url");

  function recordWithJwk(publicJwk, signatureValue = signature) {
    const signatureMetadata = {
      algorithm: "ES256",
      signature_encoding: "base64url_raw_ecdsa",
      signed_payload: signedPayload,
      public_jwk: publicJwk
    };
    return {
      artifact_id: "PF-ARTIFACT-es256",
      artifact_kind: "report:test:docx",
      pack_id: manifest.pack_id,
      source_governance_manifest_sha256: manifest.governance_manifest_sha256,
      file_name: descriptor.name,
      content_type: descriptor.media_type,
      sha256: descriptor.sha256,
      size_bytes: descriptor.size_bytes,
      content_base64: bytes.toString("base64"),
      signed_manifest: manifest,
      signed_manifest_sha256: manifestHash,
      signature: signatureValue,
      signature_sha256: sha256(signatureValue),
      signature_metadata: signatureMetadata,
      signature_metadata_sha256: sha256(canonicalJson(signatureMetadata)),
      runtime_verification: { verified: true },
      immutable: true,
      source_pack_immutable: true
    };
  }

  assert.equal(verifyStoredExportArtifact(recordWithJwk(standardsJwk)).verified, true);
  for (const legacyKeyType of ["KeyType.ec", "KeyType.ec_hsm"]) {
    const legacyJwk = { ...standardsJwk, kty: legacyKeyType, crv: "KeyCurveName.p_256" };
    assert.equal(verifyStoredExportArtifact(recordWithJwk(legacyJwk)).verified, true);
  }

  for (const invalidJwk of [
    { ...standardsJwk, kty: "KeyType.rsa" },
    { ...standardsJwk, crv: "KeyCurveName.p_384" },
    { ...standardsJwk, x: Buffer.alloc(31).toString("base64url") },
    { ...standardsJwk, x: `${standardsJwk.x}!!` },
    { ...standardsJwk, y: `${standardsJwk.y}=` }
  ]) {
    assert.ok(verifyStoredExportArtifact(recordWithJwk(invalidJwk)).failures.includes("signature_cryptographic_verification_failed"));
  }
  const { publicKey: wrongPublicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  assert.ok(verifyStoredExportArtifact(recordWithJwk(wrongPublicKey.export({ format: "jwk" }))).failures.includes("signature_cryptographic_verification_failed"));
  const wrongSignature = Buffer.alloc(64).toString("base64url");
  assert.ok(verifyStoredExportArtifact(recordWithJwk(standardsJwk, wrongSignature)).failures.includes("signature_cryptographic_verification_failed"));
  const shortSignature = Buffer.alloc(63).toString("base64url");
  assert.ok(verifyStoredExportArtifact(recordWithJwk(standardsJwk, shortSignature)).failures.includes("signature_cryptographic_verification_failed"));
  assert.ok(verifyStoredExportArtifact(recordWithJwk(standardsJwk, `${signature}!!`)).failures.includes("signature_cryptographic_verification_failed"));
  assert.ok(verifyStoredExportArtifact(recordWithJwk(standardsJwk, `${signature}=`)).failures.includes("signature_cryptographic_verification_failed"));
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

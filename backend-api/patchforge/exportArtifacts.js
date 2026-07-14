import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as verifyCryptoSignature } from "node:crypto";
import JSZip from "jszip";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export async function findStoredExportArtifact(storage, tenantId, packId, artifactKind) {
  const records = await storage.list("export_artifacts", tenantId);
  return records.find((record) => record.pack_id === packId && record.artifact_kind === artifactKind) || null;
}

export async function materializeSignedExportArtifact({
  storage,
  runtimeClient,
  tenantId,
  pack,
  artifactKind,
  fileName,
  contentType,
  buffer
}) {
  const packId = pack.pack_id || pack.decision_pack_id;
  const existing = await findStoredExportArtifact(storage, tenantId, packId, artifactKind);
  if (existing) {
    return verifiedArtifact(existing);
  }
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const descriptor = artifactDescriptor(fileName, contentType, bytes);
  const governanceHash = governanceManifestHash(pack);
  const runtimeBundle = await runtimeClient.createExportManifest({
    tenant_id: tenantId,
    pack_id: packId,
    governance_manifest_sha256: governanceHash,
    final_approval_issued: Boolean(pack.final_approval_issued),
    created_at: pack.created_at || new Date().toISOString(),
    artefacts: [descriptor]
  });
  assertRuntimeBundle(runtimeBundle, packId, governanceHash, Boolean(pack.final_approval_issued), [descriptor]);
  const artifactId = `PF-ARTIFACT-${sha256(`${tenantId}\0${packId}\0${artifactKind}`).slice(0, 24)}`;
  const record = {
    tenant_id: tenantId,
    artifact_id: artifactId,
    artifact_kind: artifactKind,
    pack_id: packId,
    source_governance_manifest_sha256: governanceHash,
    file_name: fileName,
    content_type: contentType,
    sha256: descriptor.sha256,
    size_bytes: descriptor.size_bytes,
    content_base64: bytes.toString("base64"),
    signed_manifest: runtimeBundle.manifest,
    signed_manifest_sha256: runtimeBundle.manifest_sha256,
    signature: runtimeBundle.signature,
    signature_sha256: sha256(String(runtimeBundle.signature)),
    signature_metadata: runtimeBundle.signature_metadata,
    signature_metadata_sha256: sha256(canonicalJson(runtimeBundle.signature_metadata)),
    runtime_verification: runtimeBundle.verification,
    source_pack_immutable: true,
    immutable: true,
    final_approval_issued: Boolean(pack.final_approval_issued),
    created_at: new Date().toISOString()
  };
  const persisted = typeof storage.appendImmutable === "function"
    ? await storage.appendImmutable("export_artifacts", record)
    : { record: await storage.append("export_artifacts", record), created: true };
  if (persisted.created) {
    await storage.audit(tenantId, "signed_export_artifact_materialized", {
      artifact_id: artifactId,
      artifact_kind: artifactKind,
      pack_id: packId,
      sha256: descriptor.sha256,
      size_bytes: descriptor.size_bytes,
      manifest_id: runtimeBundle.manifest.manifest_id,
      final_approval_issued: Boolean(pack.final_approval_issued)
    });
  }
  return verifiedArtifact(persisted.record);
}

export function verifyStoredExportArtifact(record) {
  const failures = [];
  let buffer = Buffer.alloc(0);
  try {
    buffer = Buffer.from(String(record?.content_base64 || ""), "base64");
  } catch {
    failures.push("content_base64_invalid");
  }
  const actualSha256 = sha256(buffer);
  if (actualSha256 !== record?.sha256) failures.push("artifact_sha256_mismatch");
  if (buffer.length !== record?.size_bytes) failures.push("artifact_size_mismatch");
  const manifest = record?.signed_manifest;
  const descriptors = Array.isArray(manifest?.artefacts) ? manifest.artefacts : [];
  const descriptor = descriptors.find((item) => item.name === record?.file_name);
  if (!descriptor
    || descriptor.sha256 !== record?.sha256
    || descriptor.size_bytes !== record?.size_bytes
    || descriptor.media_type !== record?.content_type) {
    failures.push("signed_descriptor_mismatch");
  }
  const actualManifestHash = manifest && typeof manifest === "object" ? sha256(canonicalJson(manifest)) : null;
  if (actualManifestHash !== record?.signed_manifest_sha256) failures.push("signed_manifest_hash_mismatch");
  const signedPayload = record?.signature_metadata?.signed_payload;
  if (signedPayload?.manifest_sha256 !== actualManifestHash
    || signedPayload?.manifest_id !== manifest?.manifest_id
    || signedPayload?.pack_id !== record?.pack_id
    || signedPayload?.governance_manifest_sha256 !== manifest?.governance_manifest_sha256
    || manifest?.governance_manifest_sha256 !== record?.source_governance_manifest_sha256) {
    failures.push("signature_payload_mismatch");
  }
  if (!record?.signature || sha256(String(record.signature)) !== record?.signature_sha256) failures.push("signature_integrity_mismatch");
  if (!record?.signature_metadata || sha256(canonicalJson(record.signature_metadata)) !== record?.signature_metadata_sha256) failures.push("signature_metadata_integrity_mismatch");
  const cryptographicVerification = verifyProductionSignature(record);
  if (cryptographicVerification === false) failures.push("signature_cryptographic_verification_failed");
  if (record?.runtime_verification?.verified !== true) failures.push("runtime_signature_not_verified");
  if (record?.immutable !== true || record?.source_pack_immutable !== true) failures.push("immutability_marker_missing");
  return {
    verified: failures.length === 0,
    failures,
    actual_sha256: actualSha256,
    actual_size_bytes: buffer.length,
    manifest_id: manifest?.manifest_id || null,
    byte_integrity_verified: actualSha256 === record?.sha256 && buffer.length === record?.size_bytes,
    signed_manifest_binding_verified: !failures.includes("signed_descriptor_mismatch")
      && !failures.includes("signed_manifest_hash_mismatch")
      && !failures.includes("signature_payload_mismatch"),
    runtime_signature_verified_at_issuance: record?.runtime_verification?.verified === true,
    signature_verified_on_download: cryptographicVerification === true,
    signature_integrity_verified: !failures.includes("signature_integrity_mismatch")
      && !failures.includes("signature_metadata_integrity_mismatch")
  };
}

export function verifiedArtifact(record) {
  const verification = verifyStoredExportArtifact(record);
  if (!verification.verified) {
    throw artifactError("export_artifact_integrity_failed", `Stored export artifact failed closed: ${verification.failures.join(", ")}.`, 409);
  }
  return { record, buffer: Buffer.from(record.content_base64, "base64"), verification };
}

export function publicExportArtifact(record) {
  const verification = verifyStoredExportArtifact(record);
  return {
    artifact_id: record.artifact_id,
    artifact_kind: record.artifact_kind,
    pack_id: record.pack_id,
    file_name: record.file_name,
    content_type: record.content_type,
    sha256: record.sha256,
    size_bytes: record.size_bytes,
    manifest_id: record.signed_manifest?.manifest_id || null,
    manifest_sha256: record.signed_manifest_sha256,
    signature_metadata: record.signature_metadata,
    verification,
    source_pack_immutable: true,
    final_approval_issued: Boolean(record.final_approval_issued),
    created_at: record.created_at
  };
}

export function signedArtifactHeaders(record) {
  return {
    digest: `sha-256=${Buffer.from(record.sha256, "hex").toString("base64")}`,
    "x-patchforge-artifact-id": record.artifact_id,
    "x-patchforge-artifact-sha256": record.sha256,
    "x-patchforge-export-manifest-id": record.signed_manifest.manifest_id,
    "x-patchforge-export-verified": "true",
    "x-patchforge-source-pack-immutable": "true"
  };
}

export async function buildSignedDecisionPackZip({ runtimeClient, tenantId, pack }) {
  const packId = pack.pack_id || pack.decision_pack_id;
  const zip = new JSZip();
  const date = safeZipDate(pack.created_at);
  const descriptors = [];
  for (const [name, value] of Object.entries(pack.artefacts || {}).sort(([left], [right]) => left.localeCompare(right))) {
    assertSafeFileName(name);
    const contentType = name.endsWith(".json") ? "application/json" : name.endsWith(".sig") ? "text/plain" : null;
    if (!contentType) continue;
    const bytes = Buffer.from(contentType === "application/json" ? `${prettyJson(value)}\n` : String(value), "utf8");
    zip.file(name, bytes, { date, createFolders: false });
    descriptors.push(artifactDescriptor(name, contentType, bytes));
  }
  if (!descriptors.length) {
    throw artifactError("decision_pack_artefacts_missing", "The signed decision pack contains no exportable artefacts.", 409);
  }
  const contentBundle = await runtimeClient.createExportManifest({
    tenant_id: tenantId,
    pack_id: packId,
    governance_manifest_sha256: governanceManifestHash(pack),
    final_approval_issued: Boolean(pack.final_approval_issued),
    created_at: pack.created_at || new Date().toISOString(),
    artefacts: descriptors
  });
  assertRuntimeBundle(contentBundle, packId, governanceManifestHash(pack), Boolean(pack.final_approval_issued), descriptors);
  zip.file("export_content_manifest.json", `${prettyJson(contentBundle.manifest)}\n`, { date });
  zip.file("export_content_manifest.sig", String(contentBundle.signature), { date });
  zip.file("export_content_manifest.sigmeta.json", `${prettyJson(contentBundle.signature_metadata)}\n`, { date });
  zip.file("export_content_verification.json", `${prettyJson(contentBundle.verification)}\n`, { date });
  const buffer = await zip.generateAsync({
    type: "nodebuffer",
    compression: "DEFLATE",
    compressionOptions: { level: 9 },
    platform: "DOS",
    streamFiles: false
  });
  return {
    buffer,
    contentType: "application/zip",
    fileName: `${safeFileStem(packId)}-signed-decision-pack.zip`,
    innerManifestId: contentBundle.manifest.manifest_id
  };
}

function artifactDescriptor(name, mediaType, buffer) {
  assertSafeFileName(name);
  return { name, media_type: mediaType.toLowerCase(), sha256: sha256(buffer), size_bytes: buffer.length };
}

function assertRuntimeBundle(bundle, packId, governanceHash, finalApprovalIssued, expectedDescriptors) {
  if (!bundle?.verification?.verified || !bundle?.signature || !bundle?.manifest || !bundle?.signature_metadata) {
    throw artifactError("export_manifest_signing_failed", "Runtime did not return a verified signed export manifest.", 502);
  }
  if (bundle.manifest.pack_id !== packId
    || bundle.manifest.governance_manifest_sha256 !== governanceHash
    || bundle.signature_metadata.signed_payload?.governance_manifest_sha256 !== governanceHash
    || bundle.manifest.final_approval_issued !== finalApprovalIssued) {
    throw artifactError("export_manifest_scope_mismatch", "Runtime export manifest did not bind to the requested pack.", 502);
  }
  const expected = canonicalJson([...expectedDescriptors].sort((left, right) => left.name.localeCompare(right.name)));
  if (canonicalJson(bundle.manifest.artefacts) !== expected) {
    throw artifactError("export_manifest_descriptor_mismatch", "Runtime export manifest did not bind the exact artifact descriptors.", 502);
  }
  const manifestHash = sha256(canonicalJson(bundle.manifest));
  if (bundle.manifest_sha256 !== manifestHash || bundle.signature_metadata.signed_payload?.manifest_sha256 !== manifestHash) {
    throw artifactError("export_manifest_hash_mismatch", "Runtime export manifest hash binding is invalid.", 502);
  }
}

function governanceManifestHash(pack) {
  const recorded = String(pack?.artefacts?.["verification_manifest.json"]?.governance_manifest_sha256 || "").toLowerCase();
  return SHA256_PATTERN.test(recorded)
    ? recorded
    : sha256(canonicalJson(pack?.artefacts?.["governance_manifest.json"] || { pack_id: pack?.pack_id || pack?.decision_pack_id }));
}

function assertSafeFileName(name) {
  if (!name || name.length > 180 || name === "." || name === ".." || name.includes("/") || name.includes("\\") || name.includes("\0")) {
    throw artifactError("unsafe_export_file_name", `Unsafe export file name: ${name || "missing"}.`, 400);
  }
}

function safeFileStem(value) {
  return String(value || "patchforge-pack").replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "patchforge-pack";
}

function safeZipDate(value) {
  const date = new Date(value || "2020-01-01T00:00:00Z");
  return Number.isFinite(date.valueOf()) && date.getUTCFullYear() >= 1980 ? date : new Date("2020-01-01T00:00:00Z");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function verifyProductionSignature(record) {
  const metadata = record?.signature_metadata;
  if (metadata?.algorithm === "dev_hmac_sha256") {
    const expected = createHmac("sha256", process.env.PATCHFORGE_DEV_SIGNING_KEY || "patchforge-dev-test-key")
      .update(canonicalJson(metadata.signed_payload))
      .digest("hex");
    const actual = String(record.signature || "");
    return expected.length === actual.length && timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
  }
  if (metadata?.algorithm !== "ES256") return null;
  try {
    const key = createPublicKey({ key: metadata.public_jwk, format: "jwk" });
    const signature = Buffer.from(String(record.signature), "base64url");
    return verifyCryptoSignature(
      "sha256",
      Buffer.from(canonicalJson(metadata.signed_payload), "utf8"),
      { key, dsaEncoding: "ieee-p1363" },
      signature
    );
  } catch {
    return false;
  }
}

function canonicalJson(value) {
  return JSON.stringify(sortValue(value));
}

function prettyJson(value) {
  return JSON.stringify(sortValue(value), null, 2);
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, sortValue(nested)]));
  }
  return value;
}

function artifactError(code, message, statusCode) {
  return Object.assign(new Error(message), { code, statusCode, publicError: code, publicMessage: message });
}

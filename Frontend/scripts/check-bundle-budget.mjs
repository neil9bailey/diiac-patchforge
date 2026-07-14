import { readFile, readdir, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = path.join(frontendRoot, "dist");
const manifestPath = path.join(distRoot, ".vite", "manifest.json");
const entryBudgetBytes = 500_000;
const deferredChunkBudgetBytes = 100_000;
const vendorChunkBudgetBytes = 400_000;
const totalJavaScriptBudgetBytes = 650_000;

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const entry = Object.values(manifest).find((record) => record?.isEntry && typeof record.file === "string");
if (!entry) {
  throw new Error(`Bundle budget check could not find an entry asset in ${manifestPath}.`);
}

const assetsDirectory = path.join(distRoot, "assets");
const javascriptAssets = (await readdir(assetsDirectory))
  .filter((fileName) => fileName.endsWith(".js"));
const chunks = await Promise.all(javascriptAssets.map(async (fileName) => ({
  fileName,
  bytes: (await stat(path.join(assetsDirectory, fileName))).size
})));
chunks.sort((left, right) => right.bytes - left.bytes);

console.log("PatchForge JavaScript bundle sizes:");
for (const chunk of chunks) {
  const marker = `assets/${chunk.fileName}` === entry.file ? " entry" : " deferred";
  console.log(`- ${chunk.fileName}: ${(chunk.bytes / 1000).toFixed(2)} kB (${marker.trim()})`);
}

const entryBytes = (await stat(path.join(distRoot, entry.file))).size;
if (entryBytes > entryBudgetBytes) {
  throw new Error(`Entry bundle ${(entryBytes / 1000).toFixed(2)} kB exceeds the ${(entryBudgetBytes / 1000).toFixed(2)} kB budget.`);
}

const oversizedDeferredChunks = chunks.filter(({ fileName, bytes }) => {
  if (`assets/${fileName}` === entry.file) {
    return false;
  }
  const budget = fileName.startsWith("auth-vendor-") ? vendorChunkBudgetBytes : deferredChunkBudgetBytes;
  return bytes > budget;
});
if (oversizedDeferredChunks.length) {
  throw new Error(`Deferred bundle budget exceeded: ${oversizedDeferredChunks.map(({ fileName, bytes }) => `${fileName} ${(bytes / 1000).toFixed(2)} kB`).join(", ")}. Limits: ${(deferredChunkBudgetBytes / 1000).toFixed(2)} kB per feature chunk and ${(vendorChunkBudgetBytes / 1000).toFixed(2)} kB for the authentication vendor chunk.`);
}

const totalJavaScriptBytes = chunks.reduce((total, chunk) => total + chunk.bytes, 0);
if (totalJavaScriptBytes > totalJavaScriptBudgetBytes) {
  throw new Error(`Total JavaScript ${(totalJavaScriptBytes / 1000).toFixed(2)} kB exceeds the ${(totalJavaScriptBudgetBytes / 1000).toFixed(2)} kB budget.`);
}

console.log(`Entry bundle ${(entryBytes / 1000).toFixed(2)} kB is within the ${(entryBudgetBytes / 1000).toFixed(2)} kB budget.`);
console.log(`Feature chunks are within ${(deferredChunkBudgetBytes / 1000).toFixed(2)} kB and the authentication vendor chunk is within ${(vendorChunkBudgetBytes / 1000).toFixed(2)} kB; total JavaScript ${(totalJavaScriptBytes / 1000).toFixed(2)} kB is within ${(totalJavaScriptBudgetBytes / 1000).toFixed(2)} kB.`);

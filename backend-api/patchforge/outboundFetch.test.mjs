import assert from "node:assert/strict";
import test from "node:test";
import {
  assertApprovedOutboundUrl,
  guardedFetchBuffer,
  guardedFetchJson,
  isDisallowedOutboundAddress
} from "./outboundFetch.js";

const PUBLIC_DNS = async () => [{ address: "93.184.216.34", family: 4 }];

test("outbound policy accepts an allowlisted HTTPS hostname with only public DNS answers", async () => {
  const approved = await assertApprovedOutboundUrl("https://www.cisa.gov/feed.json", { resolveHostname: PUBLIC_DNS });
  assert.equal(approved.hostname, "www.cisa.gov");
  assert.deepEqual(approved.addresses, [{ address: "93.184.216.34", family: 4 }]);
});

test("outbound policy rejects unsafe URL forms, metadata names, and private address answers", async () => {
  await assert.rejects(() => assertApprovedOutboundUrl("http://www.cisa.gov/feed.json", { resolveHostname: PUBLIC_DNS }), { code: "outbound_https_required" });
  await assert.rejects(() => assertApprovedOutboundUrl("https://user:pass@www.cisa.gov/feed.json", { resolveHostname: PUBLIC_DNS }), { code: "outbound_userinfo_forbidden" });
  await assert.rejects(() => assertApprovedOutboundUrl("https://metadata.google.internal/computeMetadata/v1/", { resolveHostname: PUBLIC_DNS }), { code: "outbound_hostname_forbidden" });
  await assert.rejects(() => assertApprovedOutboundUrl("https://127.0.0.1/source", { resolveHostname: PUBLIC_DNS, allowHosts: ["127.0.0.1"] }), { code: "outbound_ip_literal_forbidden" });
  await assert.rejects(() => assertApprovedOutboundUrl("https://www.cisa.gov/feed.json", {
    resolveHostname: async () => [
      { address: "93.184.216.34", family: 4 },
      { address: "169.254.169.254", family: 4 }
    ]
  }), { code: "outbound_dns_address_forbidden" });
});

test("address policy blocks private, link-local, metadata, documentation, and mapped IPv6 ranges", () => {
  for (const address of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.0.1", "192.0.2.4", "198.51.100.2", "203.0.113.7", "::1", "fd00::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
    assert.equal(isDisallowedOutboundAddress(address), true, address);
  }
  assert.equal(isDisallowedOutboundAddress("93.184.216.34"), false);
  assert.equal(isDisallowedOutboundAddress("2606:4700:4700::1111"), false);
});

test("every redirect target is independently allowlisted and DNS checked", async () => {
  const fetchImpl = async () => new Response(null, {
    status: 302,
    headers: { location: "https://127.0.0.1/metadata" }
  });
  await assert.rejects(() => guardedFetchBuffer("https://www.cisa.gov/feed.json", {
    fetchImpl,
    resolveHostname: PUBLIC_DNS
  }), { code: "outbound_ip_literal_forbidden" });

  await assert.rejects(() => guardedFetchBuffer("https://www.cisa.gov/feed.json", {
    fetchImpl: async () => new Response(null, { status: 302, headers: { location: "https://example.org/unapproved" } }),
    resolveHostname: PUBLIC_DNS
  }), { code: "outbound_hostname_not_allowed" });
});

test("guarded fetch enforces maximum response bytes and timeout for injected clients", async () => {
  await assert.rejects(() => guardedFetchBuffer("https://www.cisa.gov/feed.json", {
    fetchImpl: async () => new Response("x".repeat(2048), { status: 200 }),
    resolveHostname: PUBLIC_DNS,
    maxBytes: 1024
  }), { code: "outbound_response_too_large" });

  await assert.rejects(() => guardedFetchBuffer("https://www.cisa.gov/feed.json", {
    fetchImpl: async () => new Promise(() => {}),
    resolveHostname: PUBLIC_DNS,
    timeoutMs: 100
  }), { code: "outbound_timeout" });

  await assert.rejects(() => guardedFetchBuffer("https://www.cisa.gov/feed.json", {
    fetchImpl: async () => ({
      status: 200,
      headers: { get: () => null },
      async arrayBuffer() { return new Promise(() => {}); }
    }),
    resolveHostname: PUBLIC_DNS,
    timeoutMs: 100
  }), { code: "outbound_timeout" });

  await assert.rejects(() => assertApprovedOutboundUrl("https://www.cisa.gov/feed.json", {
    resolveHostname: async () => new Promise(() => {}),
    dnsTimeoutMs: 100
  }), { code: "outbound_dns_timeout" });
});

test("guarded JSON fetch returns parsed data from an approved bounded response", async () => {
  const payload = await guardedFetchJson("https://api.first.org/data/v1/epss", {
    fetchImpl: async (_url, request) => {
      assert.equal(request.redirect, "manual");
      return new Response(JSON.stringify({ data: [{ cve: "CVE-2026-0001" }] }), { status: 200 });
    },
    resolveHostname: PUBLIC_DNS
  });
  assert.equal(payload.data[0].cve, "CVE-2026-0001");
});

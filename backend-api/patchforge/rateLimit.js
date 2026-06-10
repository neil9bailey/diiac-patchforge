// PF-AZ12 contract section 8: in-memory token bucket per tenant.
// Default 120 requests/minute; override with PATCHFORGE_RATE_LIMIT_PER_MINUTE;
// disable with PATCHFORGE_RATE_LIMIT_DISABLED=true.

export function createRateLimiter(options = {}) {
  const disabled = options.disabled !== undefined
    ? Boolean(options.disabled)
    : String(process.env.PATCHFORGE_RATE_LIMIT_DISABLED || "").toLowerCase() === "true";
  const perMinute = clampLimit(options.perMinute || process.env.PATCHFORGE_RATE_LIMIT_PER_MINUTE || 120);
  const buckets = new Map();

  return {
    disabled,
    perMinute,
    // Returns { allowed, retryAfterSeconds }.
    take(tenantId, now = Date.now()) {
      if (disabled) {
        return { allowed: true, retryAfterSeconds: 0 };
      }
      const key = tenantId || "unknown-tenant";
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { tokens: perMinute, updatedAt: now };
        buckets.set(key, bucket);
      }
      const elapsedMs = Math.max(0, now - bucket.updatedAt);
      bucket.tokens = Math.min(perMinute, bucket.tokens + (elapsedMs / 60000) * perMinute);
      bucket.updatedAt = now;
      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return { allowed: true, retryAfterSeconds: 0 };
      }
      const retryAfterSeconds = Math.max(1, Math.ceil(((1 - bucket.tokens) / perMinute) * 60));
      return { allowed: false, retryAfterSeconds };
    }
  };
}

function clampLimit(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return 120;
  }
  return Math.min(Math.floor(parsed), 100000);
}

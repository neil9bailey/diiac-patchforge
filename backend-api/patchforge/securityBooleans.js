/**
 * Shared semantic boolean parsing for source-supplied security flags.
 *
 * Single source of truth for the fail-closed rule introduced in EPIC-01: a
 * false-like value ("false", "0", "no", "off", 0, false, blank, arrays,
 * objects, NaN) must never be coerced to `true` by JavaScript truthiness.
 * Only affirmative true-like values may set a security-positive flag.
 */

const TRUE_LIKE = new Set(["1", "true", "yes", "on"]);
const FALSE_LIKE = new Set(["0", "false", "no", "off"]);

/**
 * Parse an untrusted value into a strict boolean.
 *
 * @param {unknown} value the raw input (any type)
 * @param {boolean} [fallback] returned for absent/blank/ambiguous values; default false
 * @returns {boolean}
 */
export function parseSecurityBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return fallback;
    if (value === 1) return true;
    if (value === 0) return false;
    return fallback;
  }
  // Arrays and objects are never affirmative, even when their string form
  // would parse as true-like — fail closed on structured values.
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (TRUE_LIKE.has(normalized)) return true;
  if (FALSE_LIKE.has(normalized)) return false;
  return fallback;
}

/**
 * OR-combine several candidate values with semantic parsing: the first
 * affirmative value wins; otherwise every value must be non-affirmative.
 * Used where callers previously wrote `Boolean(a || b)` and a false-like
 * string for either operand silently became true.
 *
 * @param {...unknown} values candidate values in priority order
 * @returns {boolean}
 */
export function parseSecurityBooleanAny(...values) {
  for (const value of values) {
    if (parseSecurityBoolean(value, false) === true) return true;
  }
  return false;
}

// Minimal input validation helpers for PatchForge POST endpoints.
// Throws errors shaped like server.js public errors (statusCode/publicError)
// so handlers can let them propagate to the shared error responder.

const DEFAULT_MAX_STRING_LENGTH = 4000;

export function validationError(message, field = null) {
  const error = new Error(message);
  error.statusCode = 400;
  error.publicError = "validation_failed";
  error.publicMessage = field ? `${field}: ${message}` : message;
  return error;
}

// rules: { field: { required, type: "string"|"number"|"boolean"|"array"|"object",
//                   enum: [...], maxLength, items: "string", pattern } }
export function validateBody(body, rules = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw validationError("Request body must be a JSON object.");
  }
  for (const [field, rule] of Object.entries(rules)) {
    const value = body[field];
    const missing = value === undefined || value === null || (typeof value === "string" && value.trim() === "");
    if (missing) {
      if (rule.required) {
        throw validationError(`A value is required.`, field);
      }
      continue;
    }
    if (rule.type === "string") {
      if (typeof value !== "string") {
        throw validationError("Must be a string.", field);
      }
      const maxLength = rule.maxLength || DEFAULT_MAX_STRING_LENGTH;
      if (value.length > maxLength) {
        throw validationError(`Must be at most ${maxLength} characters.`, field);
      }
      if (rule.pattern && !rule.pattern.test(value)) {
        throw validationError("Has an invalid format.", field);
      }
    } else if (rule.type === "number") {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw validationError("Must be a finite number.", field);
      }
    } else if (rule.type === "boolean") {
      if (typeof value !== "boolean") {
        throw validationError("Must be a boolean.", field);
      }
    } else if (rule.type === "array") {
      if (!Array.isArray(value)) {
        throw validationError("Must be an array.", field);
      }
      if (rule.items === "string" && !value.every((item) => typeof item === "string" && item.length <= DEFAULT_MAX_STRING_LENGTH)) {
        throw validationError("Must be an array of strings.", field);
      }
    } else if (rule.type === "object") {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw validationError("Must be an object.", field);
      }
    }
    if (rule.enum && !rule.enum.includes(value)) {
      throw validationError(`Must be one of: ${rule.enum.join(", ")}.`, field);
    }
  }
  return body;
}

export function validIsoDate(value, field) {
  const parsed = Date.parse(String(value || ""));
  if (!Number.isFinite(parsed)) {
    throw validationError("Must be an ISO-8601 date-time.", field);
  }
  return new Date(parsed).toISOString();
}

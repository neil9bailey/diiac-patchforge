// Structured one-line JSON logging for PatchForge server and scheduler.
// No new dependencies; mirrors the console transport while keeping fields
// machine-parseable: { ts, level, msg, tenant, route, ... }.

export function logEvent(level, msg, fields = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...fields
  };
  const line = JSON.stringify(entry);
  if (level === "error") {
    console.error(line);
  } else {
    console.log(line);
  }
  return entry;
}

export const logger = {
  info: (msg, fields) => logEvent("info", msg, fields),
  warn: (msg, fields) => logEvent("warn", msg, fields),
  error: (msg, fields) => logEvent("error", msg, fields)
};

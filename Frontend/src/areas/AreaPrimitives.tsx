import { useEffect, useState } from "react";
import { Database } from "lucide-react";
import type { DecisionPackRecord } from "../api";

export function StatusLine({ label, value, tone, detail }: { label: string; value: string; tone: string; detail?: string }) {
  return (
    <div className="status-line">
      <span>{label}</span>
      <strong className={tone}>{value}</strong>
      {detail && <small>{detail}</small>}
    </div>
  );
}

export type PaginationState<T> = {
  items: T[];
  page: number;
  pageCount: number;
  total: number;
  pageSize: number;
  start: number;
  end: number;
  setPage: (page: number) => void;
};

export function usePagination<T>(items: T[], pageSize = 8, key = "page"): PaginationState<T> {
  const [pageByKey, setPageByKey] = useState<Record<string, number>>({});
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const requestedPage = pageByKey[key] || 1;
  const page = Math.min(Math.max(1, requestedPage), pageCount);
  useEffect(() => {
    if (requestedPage !== page) {
      setPageByKey((current) => ({ ...current, [key]: page }));
    }
  }, [key, page, requestedPage]);
  const start = (page - 1) * pageSize;
  const end = Math.min(start + pageSize, items.length);
  return {
    items: items.slice(start, end),
    page,
    pageCount,
    total: items.length,
    pageSize,
    start,
    end,
    setPage: (nextPage) => setPageByKey((current) => ({ ...current, [key]: Math.min(Math.max(1, nextPage), pageCount) }))
  };
}

export function PaginationControls<T>({ page, pageCount, total, start, end, setPage, label }: PaginationState<T> & { label: string }) {
  if (total <= 0) {
    return null;
  }
  const pages = pageNumbers(page, pageCount);
  return (
    <nav className="pagination" aria-label={`${label} pagination`}>
      <span>{start + 1}-{end} of {total} {label}</span>
      <div>
        <button type="button" className="icon-button page-button" onClick={() => setPage(page - 1)} disabled={page <= 1} aria-label={`Previous ${label} page`}>Back</button>
        {pages.map((item, index) => item === "gap"
          ? <span className="page-gap" key={`${label}-${item}-${index}`}>...</span>
          : <button type="button" className={item === page ? "icon-button page-button active" : "icon-button page-button"} key={`${label}-${item}`} onClick={() => setPage(item)} aria-label={`${label} page ${item}`}>{item}</button>)}
        <button type="button" className="icon-button page-button" onClick={() => setPage(page + 1)} disabled={page >= pageCount} aria-label={`Next ${label} page`}>Next</button>
      </div>
    </nav>
  );
}

function pageNumbers(current: number, total: number): Array<number | "gap"> {
  if (total <= 7) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }
  const values = new Set([1, total, current - 1, current, current + 1]);
  const sorted = Array.from(values).filter((value) => value >= 1 && value <= total).sort((a, b) => a - b);
  return sorted.flatMap((value, index) => index > 0 && value - sorted[index - 1] > 1 ? ["gap" as const, value] : [value]);
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty-state">
      <Database size={22} aria-hidden />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

export function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (match) => match.toUpperCase());
}

export function candidateValue(candidate: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = candidate[key];
    if (value !== undefined && value !== null && value !== "") {
      return String(value);
    }
  }
  return "";
}

export function candidateList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).filter(Boolean);
  }
  if (value === undefined || value === null || value === "") {
    return [];
  }
  return [String(value)];
}

export function newestDecisionPacks(decisionPacks: DecisionPackRecord[]): DecisionPackRecord[] {
  return [...decisionPacks].sort((a, b) => {
    const byCreatedAt = decisionPackTime(b) - decisionPackTime(a);
    return byCreatedAt || String(b.pack_id || b.decision_pack_id || "").localeCompare(String(a.pack_id || a.decision_pack_id || ""));
  });
}

function decisionPackTime(pack: DecisionPackRecord): number {
  const parsed = Date.parse(pack.created_at || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

export function recordMatchesContext(
  record: { asset_id?: string | null; advisory_id?: string | null; cve?: string | null } | null,
  assetId: string,
  advisoryId: string
): boolean {
  if (!record) {
    return false;
  }
  const recordAdvisoryIds = [record.advisory_id, record.cve]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());
  return (!assetId || record.asset_id === assetId)
    && (!advisoryId || recordAdvisoryIds.includes(advisoryId.toLowerCase()));
}

export function healthTone(status = ""): string {
  if (["ready", "verified", "advisory", "governed"].includes(status.toLowerCase())) {
    return "trust";
  }
  if (["planned", "pending", "placeholder", "unknown", "stale", "degraded", "failed"].includes(status.toLowerCase())) {
    return "amber";
  }
  return "steel";
}

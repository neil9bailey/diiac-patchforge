import { BadgeCheck, CheckCircle2, KeyRound, LockKeyhole } from "lucide-react";
import type { PatchForgeAuthSession } from "../auth";
import type { AdminHealth, DecisionPackRecord, PatchForgeMetrics, SourceFeedState } from "../api";
import { StatusLine, healthTone, humanize } from "./AreaPrimitives";

export default function UtilityRail({
  session,
  metrics,
  decisionPacks,
  sourceFeedState,
  adminHealth
}: {
  session: PatchForgeAuthSession;
  metrics: PatchForgeMetrics;
  decisionPacks: DecisionPackRecord[];
  sourceFeedState: SourceFeedState;
  adminHealth: AdminHealth | null;
}) {
  const signing = adminHealth?.checks?.find((check) => check.name === "Signing trust");
  const signingStatus = signing?.status || "unknown";
  return (
    <>
      <section className="rail-section">
        <h3>Session</h3>
        <p className="rail-note"><BadgeCheck size={15} aria-hidden /> {session.accountName || "Signed in"}</p>
        <p className="rail-note"><LockKeyhole size={15} aria-hidden /> App roles enforced by API</p>
        <p className="rail-note"><KeyRound size={15} aria-hidden /> {session.roles.length ? session.roles.join(", ") : "No PatchForge role in token"}</p>
      </section>
      <section className="rail-section">
        <h3>Queue</h3>
        <StatusLine label="Records" value={String(metrics.vulnerability_count)} tone="steel" />
        <StatusLine label="Pending review" value={String(metrics.pending_review)} tone="amber" />
      </section>
      <section className="rail-section">
        <h3>Source Feeds</h3>
        <StatusLine label="Feeds" value={String(sourceFeedState.feeds.length)} tone="steel" />
        <StatusLine label="Runs" value={String(sourceFeedState.recent_runs.length)} tone="teal" />
      </section>
      <section className="rail-section">
        <h3>Signing Trust</h3>
        <StatusLine label="Verifier" value={decisionPacks.some((pack) => pack.verification?.verified) ? "Verified pack present" : "No verified pack"} tone={decisionPacks.some((pack) => pack.verification?.verified) ? "trust" : "amber"} />
        <StatusLine label="Trust" value={humanize(signingStatus)} tone={healthTone(signingStatus)} detail={signing?.mode || "Admin health status unavailable or restricted"} />
      </section>
      <section className="rail-section">
        <h3>Recent Packs</h3>
        {decisionPacks.slice(0, 3).map((pack) => (
          <p className="rail-note" key={pack.pack_id}><CheckCircle2 size={15} aria-hidden /> {pack.pack_id}</p>
        ))}
        {!decisionPacks.length && <p className="muted-copy">No packs yet.</p>}
      </section>
    </>
  );
}

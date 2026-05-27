const BOUNDARY = {
  advisory_only: true,
  source_bound: true,
  human_approval_required: true,
  no_scanner: true,
  no_exploit_code: true,
  no_procedural_exploit_steps: true,
  no_patch_deployment: true,
  no_production_mutation: true,
  no_autonomous_risk_acceptance: true,
  no_autonomous_cab_approval: true
};

const EXPOSURE_HINTS = {
  internet: "Internet-facing exposure increases urgency because a vulnerable service can be reached without internal network access.",
  customer: "Customer-facing service impact means remediation decisions should consider availability, customer communications, and service-owner approval.",
  ot: "OT relevance means patch feasibility must consider safety, vendor support, maintenance windows, rollback constraints, and operational continuity.",
  unmapped: "Affected asset and service scope is not fully mapped. PatchForge can recommend a posture, but closure should wait for reviewed scope evidence."
};

const HUMAN_APPROVAL_NOTICE = "Human approval remains required. PatchForge does not approve CAB decisions, risk acceptance, patch deployment, or closure autonomously.";
const UNCONFIRMED_SCOPE_TEXT = "PatchForge has public-source vulnerability intelligence, but customer asset and service exposure are not yet confirmed.";
const URGENT_SCOPE_POSTURE = "Urgent scope confirmation required - final remediation decision blocked pending evidence.";

export async function buildIntelligenceForTenant({ storage, tenantId, vulnerabilityId, bayesianSnapshot = null }) {
  const vulnerability = await storage.getVulnerability(tenantId, vulnerabilityId);
  if (!vulnerability) {
    return null;
  }

  const [vendorAdvisories, threatSignals, assets, services, decisionPacks, sourceFeedRuns, reviews] = await Promise.all([
    storage.list("vendor_advisories", tenantId),
    storage.list("threat_signals", tenantId),
    storage.list("assets", tenantId),
    storage.list("services", tenantId),
    storage.list("decision_packs", tenantId),
    storage.list("source_feed_runs", tenantId),
    storage.list("reviews", tenantId)
  ]);

  return buildFindingIntelligence({
    vulnerability,
    vendorAdvisories,
    threatSignals,
    assets,
    services,
    decisionPacks,
    sourceFeedRuns,
    reviews,
    bayesianSnapshot
  });
}

export function buildFindingIntelligence({
  vulnerability,
  vendorAdvisories = [],
  threatSignals = [],
  assets = [],
  services = [],
  decisionPacks = [],
  sourceFeedRuns = [],
  reviews = [],
  bayesianSnapshot = null
}) {
  const matchingAdvisories = matchAdvisories(vulnerability, vendorAdvisories);
  const matchingSignals = matchThreatSignals(vulnerability, threatSignals);
  const affectedServices = matchServices(vulnerability, services);
  const affectedAssets = matchAssets(vulnerability, assets);
  const latestPack = decisionPacks
    .filter((pack) => pack.vulnerability_id === vulnerability.vulnerability_id)
    .sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")))[0] || null;
  const vendorProfile = inferVendorProduct(vulnerability, matchingAdvisories);
  const epss = latestEpss(matchingSignals);
  const evidence = evidenceSummary(vulnerability, matchingAdvisories, matchingSignals, reviews);
  const exposure = exposureSummary(vulnerability, affectedServices, affectedAssets);
  const posture = recommendPosture({ vulnerability, affectedServices, affectedAssets, advisories: matchingAdvisories, epss, bayesianSnapshot });
  const customerPosture = customerFacingPosture(vulnerability, matchingAdvisories, posture, exposure);
  const recommendation = {
    ...posture,
    customer_posture: customerPosture.label,
    customer_posture_detail: customerPosture.detail,
    display_posture: customerPosture.display_posture,
    approval_notice: HUMAN_APPROVAL_NOTICE
  };
  const generatedAt = new Date().toISOString();

  return {
    intelligence_id: `intel-${vulnerability.vulnerability_id}-${generatedAt.replace(/[-:.TZ]/g, "").slice(0, 14)}`,
    generated_at: generatedAt,
    vulnerability_id: vulnerability.vulnerability_id,
    title: vulnerability.title || vulnerability.canonical_id || vulnerability.vulnerability_id,
    severity: vulnerability.severity || "unknown",
    vendor: vendorProfile.vendor,
    product: vendorProfile.product,
    component: vendorProfile.component,
    summary: {
      plain_english: plainEnglishSummary(vulnerability, vendorProfile, matchingAdvisories),
      why_now: whyNow(vulnerability, matchingAdvisories, epss),
      what_it_affects: whatItAffects(vulnerability, exposure),
      operational_risk: operationalRisk(vulnerability, exposure, recommendation),
      decision_required: decisionRequired(recommendation, evidence),
      executive_readout: executiveReadout(vulnerability, recommendation, evidence, exposure)
    },
    exploitability: {
      known_exploited: Boolean(vulnerability.known_exploited || matchingAdvisories.some((item) => item.known_exploited)),
      epss_score: epss?.epss_score ?? null,
      epss_percentile: epss?.percentile ?? null,
      ransomware_use: ransomwareUse(matchingAdvisories),
      active_exploitation_signal: Boolean(vulnerability.known_exploited || matchingAdvisories.some((item) => item.known_exploited)),
      safe_description: exploitabilityNarrative(vulnerability, matchingAdvisories, epss),
      kev_epss_interpretation: kevEpssInterpretation(vulnerability, matchingAdvisories, epss),
      prohibited_detail: "Exploit code, exploit payloads, and procedural exploitation steps are intentionally not provided."
    },
    exposure,
    recommendation,
    decision_options: decisionOptions(vulnerability, exposure, evidence, recommendation),
    evidence,
    automation: {
      completed: completedAnalysis(vulnerability, matchingAdvisories, matchingSignals, bayesianSnapshot, sourceFeedRuns),
      remaining_human_decisions: remainingHumanDecisions(evidence, posture, latestPack),
      available_actions: availableActions(vulnerability, latestPack)
    },
    latest_signed_pack: latestPack ? {
      pack_id: latestPack.pack_id,
      decision_posture: latestPack.decision_posture || "not recorded",
      readiness_state: latestPack.readiness?.readiness_state || "pending",
      verified: Boolean(latestPack.verification?.verified),
      final_approval_issued: Boolean(latestPack.final_approval_issued || latestPack.readiness?.final_approval_issued)
    } : null,
    source_context: {
      source_count: (vulnerability.sources || []).length,
      reviewed_source_count: (vulnerability.usable_evidence_sources || []).length,
      vendor_advisory_count: matchingAdvisories.length,
      threat_signal_count: matchingSignals.length,
      latest_source_feed_run_at: sourceFeedRuns.sort((a, b) => String(b.completed_at || "").localeCompare(String(a.completed_at || "")))[0]?.completed_at || null
    },
    boundary: BOUNDARY
  };
}

function matchAdvisories(vulnerability, advisories) {
  const ids = new Set([
    vulnerability.vulnerability_id,
    vulnerability.canonical_id,
    ...(vulnerability.tags || [])
  ].filter(Boolean).map((value) => String(value).toLowerCase()));
  return advisories.filter((item) => {
    const candidates = [
      item.cve,
      item.vulnerability_id,
      item.advisory_id,
      item.title,
      item.vendor_id,
      item.product_id
    ].filter(Boolean).map((value) => String(value).toLowerCase());
    return candidates.some((candidate) => ids.has(candidate) || candidate.includes(String(vulnerability.vulnerability_id).toLowerCase()));
  });
}

function matchThreatSignals(vulnerability, signals) {
  const id = String(vulnerability.canonical_id || vulnerability.vulnerability_id).toUpperCase();
  return signals.filter((item) => String(item.cve || item.vulnerability_id || "").toUpperCase() === id);
}

function matchServices(vulnerability, services) {
  const affected = new Set(vulnerability.affected_service_ids || []);
  return services.filter((service) => affected.has(service.service_id) || (service.vulnerability_ids || []).includes(vulnerability.vulnerability_id));
}

function matchAssets(vulnerability, assets) {
  const affected = new Set(vulnerability.affected_asset_ids || []);
  return assets.filter((asset) => affected.has(asset.asset_id) || (asset.vulnerability_ids || []).includes(vulnerability.vulnerability_id));
}

function inferVendorProduct(vulnerability, advisories) {
  const advisory = advisories[0] || {};
  const tags = vulnerability.tags || [];
  const title = vulnerability.title || "";
  const vendorTag = tags.find((tag) => !["live_source_feed", "cisa_kev"].includes(tag));
  const titleParts = title.split(/\s+/).filter(Boolean);
  return {
    vendor: humanize(advisory.vendor_id || vendorTag || titleParts[0] || "Unknown vendor"),
    product: humanize(advisory.product_id || tags[tags.indexOf(vendorTag) + 1] || titleParts.slice(1, 3).join(" ") || "Unknown product"),
    component: advisory.component || "Not recorded"
  };
}

function latestEpss(signals) {
  return signals
    .filter((item) => item.epss_score !== null && item.epss_score !== undefined)
    .sort((a, b) => String(b.signal_date || b.created_at || "").localeCompare(String(a.signal_date || a.created_at || "")))[0] || null;
}

function recommendPosture({ vulnerability, affectedServices, affectedAssets, advisories, epss, bayesianSnapshot }) {
  const knownExploited = Boolean(vulnerability.known_exploited || advisories.some((item) => item.known_exploited));
  const internetExposed = Boolean(vulnerability.internet_exposed || affectedAssets.some((asset) => String(asset.exposure || "").toLowerCase().includes("internet")));
  const patchAvailable = ["patch_available", "patch_feasible"].includes(String(vulnerability.patch_status || "").toLowerCase())
    || advisories.some((item) => item.patch_available);
  const otRelevant = Boolean(vulnerability.ot_relevant || affectedAssets.some((asset) => String(asset.asset_class || "").toLowerCase().includes("ot")));
  const customerFacing = Boolean(affectedServices.some((service) => service.customer_facing));
  const hasReviewedScope = Boolean(affectedServices.length || affectedAssets.length);
  const epssHigh = Number(epss?.epss_score || 0) >= 0.6 || Number(epss?.percentile || 0) >= 0.9;
  const bayesianPosture = bayesianSnapshot?.recommended_governance_posture || null;

  let posture = bayesianPosture || "defer_pending_evidence";
  const rationale = [];
  const doNow = [];
  const doNext = [];

  if (knownExploited && !hasReviewedScope) {
    posture = "defer_pending_evidence";
    rationale.push("A known-exploited public-source signal is present, but reviewed customer asset and service exposure are not confirmed.");
    doNow.push("Confirm customer exposure and patch applicability before selecting emergency change, patch, mitigation, or risk acceptance.");
  } else if (knownExploited && patchAvailable && (internetExposed || customerFacing)) {
    posture = "emergency_change_required";
    rationale.push("Known exploitation, patch availability, and exposed or customer-facing service context indicate emergency change governance.");
    doNow.push("Open CAB/security-lead emergency review and confirm rollback evidence before approval.");
  } else if ((knownExploited || epssHigh) && patchAvailable) {
    posture = "patch_required";
    rationale.push("Exploitability signals and patch availability make deferral risk difficult to justify without compensating controls.");
    doNow.push("Prepare patch-change evidence and service-owner review.");
  } else if (otRelevant) {
    posture = "mitigate_temporarily";
    rationale.push("OT relevance means immediate patching may be unsafe or infeasible without vendor and maintenance-window evidence.");
    doNow.push("Confirm vendor support, safety impact, compensating controls, and maintenance window.");
  } else {
    rationale.push("Evidence is not yet sufficient for closure or acceptance. PatchForge recommends completing source and exposure review first.");
    doNow.push("Review source evidence, map assets/services, and rerun compile.");
  }

  if (!patchAvailable) {
    doNext.push("Confirm vendor patch availability or record mitigation-only posture.");
  }
  if (!vulnerability.affected_asset_ids?.length) {
    doNext.push("Attach affected asset scope evidence.");
  }
  if (!vulnerability.affected_service_ids?.length) {
    doNext.push("Attach business service impact evidence.");
  }
  if (otRelevant) {
    doNext.push("Attach OT safety, vendor-support, maintenance-window, and rollback evidence.");
  }

  return {
    posture,
    next_best_action: doNow[0] || "Complete source review and service mapping.",
    confidence: confidenceLevel({ knownExploited, internetExposed, patchAvailable, hasScope: Boolean(vulnerability.affected_asset_ids?.length || vulnerability.affected_service_ids?.length), epssHigh }),
    rationale,
    do_now: doNow,
    do_next: doNext,
    due_date: vulnerability.sla_due_at || advisories.find((item) => item.due_date)?.due_date || null,
    advisory_only: true,
    final_approval_issued: false
  };
}

function customerFacingPosture(vulnerability, advisories, posture, exposure) {
  const knownExploited = Boolean(vulnerability.known_exploited || advisories.some((item) => item.known_exploited));
  if (knownExploited && exposure.unmapped_scope) {
    return {
      display_posture: "urgent_scope_confirmation_required",
      label: URGENT_SCOPE_POSTURE,
      detail: `${UNCONFIRMED_SCOPE_TEXT} Known-exploited status increases urgency, but it does not prove tenant exposure or patch applicability.`
    };
  }
  return {
    display_posture: posture.posture,
    label: humanize(posture.posture),
    detail: posture.rationale?.join(" ") || "PatchForge has prepared the current governed posture for accountable human review."
  };
}

function evidenceSummary(vulnerability, advisories, signals, reviews) {
  const sources = vulnerability.sources || [];
  const accepted = sources.filter((source) => source.evidence_state === "accepted_positive_evidence");
  const rejected = sources.filter((source) => source.review_state === "rejected" || source.evidence_state === "rejected");
  const pending = sources.filter((source) => !accepted.includes(source) && !rejected.includes(source));
  const gaps = [];
  if (!accepted.some((source) => ["vendor_advisory", "cve_record"].includes(source.source_class))) {
    gaps.push("Reviewed vulnerability identity evidence");
  }
  if (!vulnerability.affected_asset_ids?.length) {
    gaps.push("Affected asset scope");
  }
  if (!vulnerability.affected_service_ids?.length) {
    gaps.push("Business service impact");
  }
  if (!["patch_available", "patch_feasible", "no_patch_available", "mitigation_only"].includes(String(vulnerability.patch_status || ""))) {
    gaps.push("Patch availability and feasibility");
  }
  if (!reviews.length) {
    gaps.push("Human source review event");
  }
  return {
    accepted_positive_evidence_count: accepted.length,
    pending_review_count: pending.length + advisories.filter((item) => item.review_state === "pending_review").length + signals.filter((item) => item.review_state === "pending_review").length,
    rejected_source_count: rejected.length,
    gaps,
    gap_details: gaps.map(gapDetail),
    usable_sources: accepted.map((source) => source.source_record_id),
    pending_sources: pending.map((source) => source.source_record_id),
    warning: "Source and agent outputs remain source-bound until reviewed. Rejected evidence cannot support positive gates."
  };
}

function gapDetail(gap) {
  const normalized = String(gap || "").toLowerCase();
  if (normalized.includes("vulnerability identity")) {
    return {
      gap,
      plain_english_gap: "The finding identity has not yet been accepted by a named reviewer.",
      why_it_matters: "CAB and customer assurance need confidence that the CVE, affected product, affected versions, and source provenance are correct before remediation decisions are presented as evidence-led.",
      required_evidence: "Reviewed CISA/CVE/vendor advisory record confirming CVE, product, affected versions, and source provenance.",
      evidence_examples: ["CISA KEV record", "NVD/CVE record", "vendor advisory", "source review event"],
      suggested_owner_role: "Security lead or vulnerability manager",
      next_decision_gate: "Source identity review"
    };
  }
  if (normalized.includes("asset")) {
    return {
      gap,
      plain_english_gap: "Customer asset exposure is not confirmed.",
      why_it_matters: "Without asset scope, the organisation cannot tell whether the public-source finding affects the customer estate or what operational risk a change would introduce.",
      required_evidence: "CMDB, hosting control panel inventory, scanner output, asset owner confirmation.",
      evidence_examples: ["CMDB asset record", "hosting control panel inventory", "scanner output", "asset owner confirmation"],
      suggested_owner_role: "Asset owner or infrastructure lead",
      next_decision_gate: "Asset exposure confirmation"
    };
  }
  if (normalized.includes("service")) {
    return {
      gap,
      plain_english_gap: "Business service and customer impact are not confirmed.",
      why_it_matters: "Severity alone does not tell the CAB which service, customer journey, SLA, or owner is affected.",
      required_evidence: "Service map, customer-facing flag, SLA/OLA impact, service owner.",
      evidence_examples: ["service catalogue map", "customer-facing flag", "SLA/OLA record", "service owner confirmation"],
      suggested_owner_role: "Service owner",
      next_decision_gate: "Business impact review"
    };
  }
  if (normalized.includes("patch")) {
    return {
      gap,
      plain_english_gap: "Patch availability and feasibility are not yet reviewed.",
      why_it_matters: "The decision cannot responsibly select patch, mitigation, deferral, or customer assurance until affected versions, testing, rollback, and applicability are understood.",
      required_evidence: "Vendor patch note, affected version mapping, test evidence, rollback plan.",
      evidence_examples: ["vendor patch note", "affected version mapping", "test evidence", "rollback plan"],
      suggested_owner_role: "Change owner or platform engineer",
      next_decision_gate: "Patch feasibility review"
    };
  }
  if (normalized.includes("human")) {
    return {
      gap,
      plain_english_gap: "No named human source review event is recorded.",
      why_it_matters: "Source-bound intelligence cannot become accepted positive evidence without a reviewer accepting or rejecting the source record.",
      required_evidence: "Named reviewer decision accepting or rejecting source records.",
      evidence_examples: ["source review event", "reviewer name or role", "accepted/rejected/superseded outcome", "review notes"],
      suggested_owner_role: "Security lead or CAB reviewer",
      next_decision_gate: "Human evidence review"
    };
  }
  return {
    gap,
    plain_english_gap: humanize(gap),
    why_it_matters: "The decision gate remains open until reviewed evidence is attached and accepted.",
    required_evidence: "Reviewed evidence appropriate to this blocker.",
    evidence_examples: ["accepted evidence record", "review note", "owner confirmation"],
    suggested_owner_role: "Accountable evidence owner",
    next_decision_gate: "Evidence review"
  };
}

function exposureSummary(vulnerability, affectedServices, affectedAssets) {
  const internetExposed = Boolean(vulnerability.internet_exposed || affectedAssets.some((asset) => String(asset.exposure || "").toLowerCase().includes("internet")));
  const customerFacing = Boolean(affectedServices.some((service) => service.customer_facing));
  const otRelevant = Boolean(vulnerability.ot_relevant || affectedAssets.some((asset) => String(asset.asset_class || "").toLowerCase().includes("ot")));
  const mapped = affectedServices.length || affectedAssets.length;
  return {
    affected_service_count: affectedServices.length,
    affected_asset_count: affectedAssets.length,
    affected_services: affectedServices.map((service) => ({
      service_id: service.service_id,
      service_name: service.service_name || service.service_id,
      owner: service.owner || "Not recorded",
      customer_facing: Boolean(service.customer_facing),
      service_tier: service.service_tier || "unknown"
    })),
    affected_assets: affectedAssets.map((asset) => ({
      asset_id: asset.asset_id,
      asset_name: asset.asset_name || asset.asset_id,
      asset_class: asset.asset_class || "unknown",
      criticality: asset.criticality || "unknown",
      exposure: asset.exposure || "unknown"
    })),
    internet_exposed: internetExposed,
    customer_facing: customerFacing,
    ot_relevant: otRelevant,
    unmapped_scope: !mapped,
    interpretation: [
      internetExposed ? EXPOSURE_HINTS.internet : null,
      customerFacing ? EXPOSURE_HINTS.customer : null,
      otRelevant ? EXPOSURE_HINTS.ot : null,
      !mapped ? EXPOSURE_HINTS.unmapped : null
    ].filter(Boolean)
  };
}

function plainEnglishSummary(vulnerability, vendorProfile, advisories) {
  const advisory = advisories[0] || {};
  const base = vulnerability.description || advisory.short_description || advisory.description;
  if (base) {
    return `${base} PatchForge treats this as a governance decision until source evidence, affected scope, and human approval are complete.`;
  }
  return `${vulnerability.vulnerability_id} is recorded as a ${humanize(vulnerability.severity || "unknown")} vulnerability affecting ${vendorProfile.vendor} ${vendorProfile.product}. PatchForge has normalised the finding into a governed remediation decision, not a deployment action.`;
}

function whyNow(vulnerability, advisories, epss) {
  const reasons = [];
  if (vulnerability.known_exploited || advisories.some((item) => item.known_exploited)) {
    reasons.push("It is flagged as known exploited in source-bound intelligence.");
  }
  if (Number(epss?.epss_score || 0) > 0) {
    reasons.push(`FIRST EPSS source-bound signal is ${formatProbability(epss.epss_score)} with percentile ${formatProbability(epss.percentile)}.`);
  }
  if (vulnerability.sla_due_at) {
    reasons.push(`The recorded remediation due date is ${vulnerability.sla_due_at}.`);
  }
  if (vulnerability.internet_exposed) {
    reasons.push("The finding is marked internet exposed.");
  }
  return reasons.length ? reasons.join(" ") : "Urgency depends on completing reviewed source, exposure, and service-impact evidence.";
}

function whatItAffects(vulnerability, exposure) {
  if (exposure.unmapped_scope) {
    return `${UNCONFIRMED_SCOPE_TEXT} This gap matters because severity alone does not tell the CAB what could break, who owns it, or whether customer-facing operations are affected.`;
  }
  const services = exposure.affected_services.map((service) => service.service_name).join(", ") || "no named services";
  const assets = exposure.affected_assets.map((asset) => asset.asset_name).join(", ") || "no named assets";
  return `Mapped service impact: ${services}. Mapped asset scope: ${assets}.`;
}

function operationalRisk(vulnerability, exposure, posture) {
  const risks = [];
  if (posture.posture === "emergency_change_required") {
    risks.push("Delay could leave an exposed known-exploited condition unresolved.");
  }
  if (exposure.unmapped_scope) {
    risks.push("Unmapped scope could cause under-remediation or unnecessary disruption.");
  }
  if (exposure.ot_relevant) {
    risks.push("OT change risk may include safety, vendor-support, and maintenance-window constraints.");
  }
  if (!["patch_available", "patch_feasible"].includes(String(vulnerability.patch_status || ""))) {
    risks.push("Patch availability is not yet confirmed, so mitigation and monitoring may be needed while evidence is completed.");
  }
  return risks.join(" ") || "Operational risk is mainly evidence confidence and accountable approval before closure.";
}

function decisionRequired(posture, evidence) {
  if (posture.display_posture === "urgent_scope_confirmation_required") {
    return `${URGENT_SCOPE_POSTURE} ${HUMAN_APPROVAL_NOTICE}`;
  }
  const action = humanize(posture.posture);
  if (evidence.gaps.length) {
    return `${action} is recommended as an advisory posture, but ${evidence.gaps.length} evidence gaps remain before final approval or closure.`;
  }
  return `${action} is ready for accountable human review. PatchForge will not issue final approval automatically.`;
}

function executiveReadout(vulnerability, posture, evidence, exposure) {
  if (posture.display_posture === "urgent_scope_confirmation_required" || exposure.unmapped_scope) {
    return `${vulnerability.vulnerability_id}: ${URGENT_SCOPE_POSTURE} ${UNCONFIRMED_SCOPE_TEXT} ${evidence.gaps.length} evidence gap(s) remain, and final approval has not been issued.`;
  }
  const impact = exposure.customer_facing ? "customer-facing service exposure" : exposure.ot_relevant ? "OT operational exposure" : "enterprise service exposure";
  return `${vulnerability.vulnerability_id} should be handled as ${humanize(posture.posture)} because PatchForge sees ${impact}, ${evidence.gaps.length} open evidence gap(s), and a final approval gate that still requires an accountable human decision.`;
}

function exploitabilityNarrative(vulnerability, advisories, epss) {
  const lines = [];
  if (vulnerability.known_exploited || advisories.some((item) => item.known_exploited)) {
    lines.push("Source-bound intelligence indicates this vulnerability is known to be exploited in the wild.");
  } else {
    lines.push("PatchForge has not recorded a reviewed known-exploited signal for this finding.");
  }
  if (epss) {
    lines.push(`EPSS gives a source-bound probability signal of ${formatProbability(epss.epss_score)} and percentile ${formatProbability(epss.percentile)}. This informs prioritisation but does not prove exploitability in the tenant estate.`);
  }
  lines.push(kevEpssInterpretation(vulnerability, advisories, epss));
  lines.push("The safe governance question is whether exposure, service impact, patch feasibility, and compensating controls justify patch, mitigation, deferral, or risk acceptance.");
  return lines.join(" ");
}

function kevEpssInterpretation(vulnerability, advisories, epss) {
  const knownExploited = Boolean(vulnerability.known_exploited || advisories.some((item) => item.known_exploited));
  const lowEpss = epss && (Number(epss.epss_score || 0) <= 0.05 || Number(epss.percentile || 0) <= 0.1);
  const base = "CISA KEV indicates the vulnerability appears in a known exploited vulnerability source feed. EPSS provides a probability-style signal and may be lower. PatchForge treats these as prioritisation signals, not proof of tenant exposure. Customer exposure must be confirmed through asset and service evidence.";
  if (knownExploited && lowEpss) {
    return `${base} Known exploited signal is present, but EPSS is low. This does not remove the need for scope confirmation.`;
  }
  if (knownExploited) {
    return base;
  }
  return "EPSS and KEV signals are prioritisation inputs. They do not prove tenant exposure and cannot close hard gates without reviewed asset, service, and source evidence.";
}

function ransomwareUse(advisories) {
  const value = advisories.find((item) => item.known_ransomware_campaign_use)?.known_ransomware_campaign_use;
  return value || "Unknown";
}

function decisionOptions(vulnerability, exposure, evidence, recommendation) {
  const hasScope = !exposure.unmapped_scope;
  const patchReviewed = ["patch_available", "patch_feasible"].includes(String(vulnerability.patch_status || "").toLowerCase());
  const hasControls = false;
  const hasRiskAcceptanceEvidence = false;
  return [
    {
      posture: "urgent_scope_confirmation_required",
      current_status: recommendation.display_posture === "urgent_scope_confirmation_required" ? "recommended now" : "available",
      reason: hasScope ? "Reviewed exposure mapping exists; keep scope current before final approval." : "Known-exploited public intelligence exists, but customer asset and service exposure are not confirmed.",
      required_evidence: ["Reviewed asset scope", "Reviewed service impact", "Source identity review"],
      required_approval: "Security lead or service owner confirms the affected scope.",
      when_to_choose: "Use now when a known-exploited public-source record needs customer estate scope confirmed before a final remediation decision.",
      benefits: "Turns an ambiguous queue item into a concrete evidence task without implying patch approval.",
      risks: "Remediation assurance cannot be issued until customer exposure and patch applicability are reviewed.",
      evidence_needed: ["Affected asset scope", "Business service impact", "Human source review event"],
      approval_needed: false,
      recommended: recommendation.display_posture === "urgent_scope_confirmation_required"
    },
    {
      posture: "emergency_change_required",
      current_status: hasScope && patchReviewed ? "available" : "blocked",
      reason: hasScope && patchReviewed ? "Reviewed scope and patch applicability can support emergency change review." : "Emergency Change Required is blocked pending asset/service exposure and patch applicability.",
      required_evidence: ["Reviewed affected scope", "Patch applicability", "Rollback plan", "Customer/service impact", "Human approval"],
      required_approval: "CAB/security lead emergency approval.",
      when_to_choose: "Use when known exploitation and exposed/customer-facing impact make normal change cadence too slow.",
      benefits: "Fast accountable response with rollback and post-change validation gates preserved.",
      risks: "Higher change risk if test, rollback, or service-impact evidence is incomplete.",
      evidence_needed: ["Vulnerability identity", "Affected scope", "Patch availability", "Rollback plan", "Human approval"],
      approval_needed: true,
      recommended: recommendation.posture === "emergency_change_required"
    },
    {
      posture: "patch_required",
      current_status: patchReviewed && hasScope ? "available" : "blocked",
      reason: patchReviewed && hasScope ? "Patch and reviewed scope evidence can support a scheduled change decision." : "Patch Required is blocked pending patch availability, feasibility, and reviewed exposure scope.",
      required_evidence: ["Vendor patch note", "Affected version mapping", "Test evidence", "Rollback plan", "Service owner review"],
      required_approval: "Change owner, service owner, and CAB/security approval.",
      when_to_choose: "Use when patch is available and deferral risk is high but emergency criteria are not fully met.",
      benefits: "Clear remediation direction while allowing scheduled change control.",
      risks: "Delay remains accountable and should be tracked against SLA.",
      evidence_needed: ["Patch feasibility", "Test evidence", "Service owner review"],
      approval_needed: true,
      recommended: recommendation.posture === "patch_required"
    },
    {
      posture: "mitigate_temporarily",
      current_status: hasControls ? "available" : "blocked",
      reason: "Mitigate Temporarily is available only if compensating-control evidence is attached and reviewed.",
      required_evidence: ["Compensating control plan", "Control owner", "Monitoring evidence", "Expiry or reassessment date"],
      required_approval: "Security lead and service owner approve temporary mitigation.",
      when_to_choose: "Use when patching is not immediately feasible, especially for OT, unsupported, or change-sensitive assets.",
      benefits: "Controls exposure while preserving evidence for later patch or acceptance.",
      risks: "Controls can degrade or be bypassed; expiry and reassessment are required.",
      evidence_needed: ["Compensating controls", "Owner", "Expiry", "Residual risk"],
      approval_needed: true,
      recommended: recommendation.posture === "mitigate_temporarily"
    },
    {
      posture: "risk_accept_temporarily",
      current_status: hasRiskAcceptanceEvidence ? "available" : "blocked",
      reason: "Risk Accept Temporarily is blocked until risk owner, rationale, expiry, compensating controls, and accountable approval exist.",
      required_evidence: ["Risk owner", "Rationale", "Expiry", "Compensating controls", "Residual risk statement"],
      required_approval: "Named accountable risk owner approval.",
      when_to_choose: "Use only when an accountable risk owner accepts residual risk with rationale and expiry.",
      benefits: "Makes deferral explicit, time-bounded, and auditable.",
      risks: "Cannot be used to quietly park an exposed known-exploited condition.",
      evidence_needed: ["Risk owner", "Rationale", "Expiry", "Compensating controls"],
      approval_needed: true,
      recommended: recommendation.posture === "risk_accept_temporarily"
    },
    {
      posture: "defer_pending_evidence",
      current_status: evidence.gaps.length ? "not recommended" : "not applicable",
      reason: evidence.gaps.length ? "Plain deferral is too passive for a known-exploited finding; use urgent scope confirmation as the active evidence posture." : "Evidence blockers are not currently listed.",
      required_evidence: evidence.gaps,
      required_approval: "Evidence owner confirms blocker resolution before approval is requested.",
      when_to_choose: "Use when source, scope, or feasibility evidence is incomplete.",
      benefits: "Avoids false certainty and drives evidence completion.",
      risks: "Deferral can become unmanaged if no owner or SLA is set.",
      evidence_needed: evidence.gaps,
      approval_needed: false,
      recommended: recommendation.posture === "defer_pending_evidence"
    }
  ];
}

function completedAnalysis(vulnerability, advisories, signals, bayesianSnapshot, sourceFeedRuns) {
  const completed = ["Normalised finding identity", "Bound source provenance", "Applied governance boundary"];
  if (advisories.length) {
    completed.push("Correlated vendor/KEV advisory context");
  }
  if (signals.length) {
    completed.push("Attached exploit-probability signal");
  }
  if (bayesianSnapshot) {
    completed.push("Generated Bayesian advisory snapshot");
  }
  if (sourceFeedRuns.length) {
    completed.push("Recorded live source-feed refresh history");
  }
  if (vulnerability.affected_asset_ids?.length || vulnerability.affected_service_ids?.length) {
    completed.push("Mapped affected asset/service references");
  }
  return completed;
}

function remainingHumanDecisions(evidence, posture, latestPack) {
  const items = [];
  if (evidence.gaps.length) {
    items.push(`Review or attach missing evidence: ${evidence.gaps.join(", ")}.`);
  }
  if (!latestPack) {
    items.push("Generate a signed decision pack after analysis review.");
  }
  if (posture.posture === "risk_accept_temporarily") {
    items.push("Record risk owner, rationale, expiry, and compensating controls.");
  }
  items.push("Issue or withhold CAB/security/service-owner approval. PatchForge will not approve automatically.");
  return items;
}

function availableActions(vulnerability, latestPack) {
  return [
    "Open Finding Detail",
    "Review exploitability intelligence",
    "Run or refresh Bayesian advisory",
    latestPack ? "Download board/CAB DOCX or PDF report" : "Generate signed decision pack",
    "Record reviewed evidence or status outcome"
  ];
}

function confidenceLevel({ knownExploited, internetExposed, patchAvailable, hasScope, epssHigh }) {
  const score = [knownExploited, internetExposed, patchAvailable, hasScope, epssHigh].filter(Boolean).length;
  if (score >= 4) {
    return "high";
  }
  if (score >= 2) {
    return "medium";
  }
  return "low";
}

function humanize(value) {
  return safeText(value)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function safeText(value) {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }
  return String(value);
}

function formatProbability(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "not recorded";
  }
  return `${Math.round(numeric * 100)}%`;
}

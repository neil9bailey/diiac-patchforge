import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  Packer,
  PageOrientation,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  VerticalAlign,
  WidthType
} from "docx";
import PDFDocument from "pdfkit";

export const REPORT_CATALOG = [
  {
    report_type: "executive_vulnerability_remediation_one_pager",
    title: "Executive Vulnerability Remediation One-Pager",
    audience: "Executive and board brief",
    formats: ["docx", "pdf"]
  },
  {
    report_type: "cab_patch_decision_report",
    title: "CAB Patch Decision Report",
    audience: "Change Advisory Board",
    formats: ["docx", "pdf"]
  },
  {
    report_type: "board_vulnerability_remediation_summary",
    title: "Board Vulnerability Remediation Summary",
    audience: "Board and senior leadership",
    formats: ["docx", "pdf"]
  },
  {
    report_type: "customer_patch_governance_pack",
    title: "Customer Patch Governance Pack",
    audience: "Customer assurance",
    formats: ["docx", "pdf"]
  },
  {
    report_type: "risk_acceptance_report",
    title: "Risk Acceptance Report",
    audience: "Risk owner and audit",
    formats: ["docx", "pdf"]
  },
  {
    report_type: "ot_patch_deferral_report",
    title: "OT Patch Deferral Report",
    audience: "OT operations and safety review",
    formats: ["docx", "pdf"]
  }
];

const BOUNDARY_TEXT = "PatchForge is a governance product. It does not scan environments, generate exploit code, provide procedural exploit steps, deploy patches, mutate production systems, approve CAB decisions, or accept risk autonomously.";
const REPORT_TYPE_MAP = new Map(REPORT_CATALOG.map((item) => [item.report_type, item]));
const COLORS = {
  ink: "17212B",
  muted: "5E6B76",
  line: "C9D2DC",
  navy: "1D3C5A",
  teal: "0F766E",
  amber: "B7791F",
  red: "A33A3A",
  fill: "EEF3F7",
  softBlue: "E6EEF7",
  softAmber: "FFF6E4",
  white: "FFFFFF"
};

export async function generateDecisionPackReport({ reportType, format, pack, vulnerability = null, intelligence = null, sourceFeedRuns = [] }) {
  const normalizedFormat = String(format || "").toLowerCase();
  if (!["docx", "pdf"].includes(normalizedFormat)) {
    throw new Error("Unsupported report format. Use docx or pdf.");
  }
  const context = buildReportContext({ reportType, pack, vulnerability, intelligence, sourceFeedRuns });
  if (normalizedFormat === "docx") {
    return {
      buffer: await buildDocxReport(context),
      contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      fileName: fileNameFor(context, "docx")
    };
  }
  return {
    buffer: await buildPdfReport(context),
    contentType: "application/pdf",
    fileName: fileNameFor(context, "pdf")
  };
}

export function buildReportContext({ reportType, pack, vulnerability = null, intelligence = null, sourceFeedRuns = [] }) {
  const catalogItem = REPORT_TYPE_MAP.get(reportType);
  if (!catalogItem) {
    const error = new Error(`Unknown PatchForge report type: ${reportType}`);
    error.code = "unknown_report_type";
    throw error;
  }
  const artefacts = pack?.artefacts || {};
  const vulnerabilitySnapshot = artefacts["vulnerability_intelligence_snapshot.json"] || vulnerability || {};
  const decisionContext = artefacts["patch_decision_context.json"] || {};
  const readiness = pack?.readiness || decisionContext.readiness || {};
  const bayesian = artefacts["bayesian_patch_risk_snapshot.json"] || null;
  const findingIntelligence = intelligence || artefacts["finding_intelligence_snapshot.json"] || null;
  const vendor = artefacts["vendor_intelligence_snapshot.json"] || null;
  const threat = artefacts["threat_landscape_snapshot.json"] || null;
  const sraTrace = artefacts["sra_trace.json"] || null;
  const governanceManifest = artefacts["governance_manifest.json"] || {};
  const verificationManifest = artefacts["verification_manifest.json"] || {};
  const sigmeta = artefacts["signed_export.sigmeta.json"] || {};
  const humanReview = artefacts["human_review_state.json"] || {};
  const riskAcceptance = artefacts["patch_risk_acceptance_state.json"] || {};
  const controls = artefacts["compensating_controls_plan.json"] || {};
  const patchFeasibility = artefacts["patch_feasibility_assessment.json"] || {};
  const generatedAt = new Date().toISOString();

  return {
    reportType,
    title: catalogItem.title,
    audience: catalogItem.audience,
    generatedAt,
    packId: pack.pack_id || pack.decision_pack_id,
    vulnerabilityId: pack.vulnerability_id || vulnerabilitySnapshot.vulnerability_id || decisionContext.vulnerability_id,
    vulnerabilityTitle: vulnerabilitySnapshot.title || vulnerabilitySnapshot.vulnerabilityName || pack.vulnerability_id || "Vulnerability record",
    severity: vulnerabilitySnapshot.severity || "unknown",
    knownExploited: Boolean(vulnerabilitySnapshot.known_exploited),
    internetExposed: Boolean(vulnerabilitySnapshot.internet_exposed),
    otRelevant: Boolean(vulnerabilitySnapshot.ot_relevant),
    patchStatus: vulnerabilitySnapshot.patch_status || "unknown",
    decisionPosture: pack.decision_posture || decisionContext.decision_posture || "defer_pending_evidence",
    readinessState: readiness.readiness_state || "pending",
    readinessScore: readiness.readiness_score ?? null,
    blockers: pack.blockers || readiness.blockers || decisionContext.blockers || [],
    finalApprovalIssued: Boolean(pack.final_approval_issued || decisionContext.final_approval_issued || humanReview.final_approval_issued),
    sourcePackImmutable: pack.source_pack_immutable !== false && governanceManifest.source_pack_immutable !== false,
    verified: Boolean(pack.verification?.verified),
    signingProvider: pack.signing_provider || sigmeta.signing_provider || sigmeta.algorithm || "not recorded",
    signatureAlgorithm: sigmeta.algorithm || "not recorded",
    governanceManifestHash: verificationManifest.governance_manifest_sha256 || "not recorded",
    evidenceRefs: decisionContext.evidence_refs || vulnerabilitySnapshot.source_record_ids || [],
    sources: normalizedSources(vulnerabilitySnapshot),
    intelligence: findingIntelligence,
    executiveReadout: findingIntelligence?.summary?.executive_readout || null,
    plainEnglish: findingIntelligence?.summary?.plain_english || null,
    whyNow: findingIntelligence?.summary?.why_now || null,
    whatItAffects: findingIntelligence?.summary?.what_it_affects || null,
    operationalRisk: findingIntelligence?.summary?.operational_risk || null,
    decisionRequired: findingIntelligence?.summary?.decision_required || null,
    exploitability: findingIntelligence?.exploitability || null,
    exposure: findingIntelligence?.exposure || null,
    recommendation: findingIntelligence?.recommendation || null,
    decisionOptions: findingIntelligence?.decision_options || [],
    automation: findingIntelligence?.automation || null,
    bayesian,
    vendor,
    threat,
    sraTrace,
    controls,
    riskAcceptance,
    patchFeasibility,
    sourceFeedRuns: sourceFeedRuns.slice(0, 6),
    artefactNames: Object.keys(artefacts).sort(),
    boundaryText: BOUNDARY_TEXT
  };
}

function normalizedSources(vulnerabilitySnapshot) {
  const sources = vulnerabilitySnapshot.sources || vulnerabilitySnapshot.usable_evidence_sources || [];
  if (!Array.isArray(sources)) {
    return [];
  }
  return sources.map((source) => ({
    ref: source.source_record_id || source.id || "source",
    className: source.source_class || "source_bound",
    name: source.source_name || "Source-bound record",
    review: source.review_state || "pending_review",
    evidence: source.evidence_state || "referenced",
    url: source.source_url || null
  }));
}

async function buildDocxReport(context) {
  const doc = new Document({
    creator: "DIIaC PatchForge",
    title: context.title,
    description: `${context.title} for ${context.vulnerabilityId}`,
    styles: {
      default: {
        document: {
          run: { font: "Calibri", size: 22, color: COLORS.ink },
          paragraph: { spacing: { after: 120 }, alignment: AlignmentType.LEFT }
        }
      },
      paragraphStyles: [
        {
          id: "Heading1",
          name: "Heading 1",
          basedOn: "Normal",
          next: "Normal",
          quickFormat: true,
          run: { size: 32, bold: true, color: "2E74B5", font: "Calibri" },
          paragraph: { spacing: { before: 320, after: 160 } }
        },
        {
          id: "Heading2",
          name: "Heading 2",
          basedOn: "Normal",
          next: "Normal",
          quickFormat: true,
          run: { size: 26, bold: true, color: "2E74B5", font: "Calibri" },
          paragraph: { spacing: { before: 240, after: 120 } }
        }
      ]
    },
    sections: [{
      properties: {
        page: {
          size: { orientation: PageOrientation.PORTRAIT },
          margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 }
        }
      },
      children: [
        titleBlock(context),
        leadCallout(context),
        heading("Executive Decision Summary", HeadingLevel.HEADING_1),
        para(context.executiveReadout || `${context.vulnerabilityId} is currently governed as ${humanize(context.decisionPosture)}. Final approval has not been issued unless explicitly recorded in the signed pack.`),
        decisionSummaryTable(context),
        heading("What This Vulnerability Means", HeadingLevel.HEADING_1),
        para(context.plainEnglish || `${context.vulnerabilityTitle} is recorded in PatchForge as a source-bound vulnerability decision. The business question is not only whether the issue exists, but what the organisation should do next with reviewed evidence.`),
        heading("Why It Matters Now", HeadingLevel.HEADING_2),
        para(context.whyNow || "PatchForge has not recorded enough reviewed urgency evidence to make a stronger statement. Complete source review, exposure mapping, and patch feasibility evidence before final approval."),
        heading("Affected Products, Services, and Assets", HeadingLevel.HEADING_1),
        para(context.whatItAffects || "Affected assets and services were not fully mapped in the pack. This gap matters because severity alone does not show customer impact, operational risk, ownership, or change feasibility."),
        scopeTable(context),
        heading("Exploitability Intelligence", HeadingLevel.HEADING_1),
        warningBox(context.exploitability?.prohibited_detail || "Exploit code, exploit payloads, and procedural exploitation steps are intentionally not provided."),
        para(context.exploitability?.safe_description || "PatchForge records exploitability signals for governance prioritisation only. They do not prove tenant compromise, and they do not close evidence gates without human review."),
        keyValueTable(exploitabilityRows(context)),
        heading("Recommended Governance Posture", HeadingLevel.HEADING_1),
        para(recommendationNarrative(context)),
        actionPlanTable(context),
        heading("Decision Options Matrix", HeadingLevel.HEADING_1),
        decisionOptionsTable(context),
        heading("Evidence Confidence and Gaps", HeadingLevel.HEADING_1, { pageBreakBefore: true }),
        para("The report separates source-pack evidence from current-state overlays. Source records, scanner findings, SRA/MCP/agent findings, CISA KEV records, EPSS signals, and vendor advisories remain source-bound until reviewed."),
        evidenceGapTable(context),
        heading("Decision Snapshot", HeadingLevel.HEADING_1),
        keyValueTable([
          ["Vulnerability", context.vulnerabilityId],
          ["Title", context.vulnerabilityTitle],
          ["Severity", humanize(context.severity)],
          ["Decision posture", humanize(context.decisionPosture)],
          ["Readiness", `${humanize(context.readinessState)}${context.readinessScore === null ? "" : ` (${context.readinessScore})`}`],
          ["Final approval", context.finalApprovalIssued ? "Issued" : "Not issued"],
          ["Source pack", context.sourcePackImmutable ? "Immutable and preserved" : "Not confirmed"]
        ]),
        heading("Evidence, Trust, and Signing", HeadingLevel.HEADING_1),
        keyValueTable([
          ["Signed pack", context.packId],
          ["Verification", context.verified ? "Verified" : "Pending or not recorded"],
          ["Signing provider", humanize(context.signingProvider)],
          ["Signature algorithm", context.signatureAlgorithm],
          ["Governance manifest SHA-256", context.governanceManifestHash],
          ["Evidence references", context.evidenceRefs.length ? String(context.evidenceRefs.length) : "None recorded"]
        ]),
        heading("Source Intelligence", HeadingLevel.HEADING_1),
        sourceTable(context.sources),
        heading("Bayesian Advisory", HeadingLevel.HEADING_1),
        keyValueTable(bayesianRows(context)),
        heading("Vendor and Threat Landscape", HeadingLevel.HEADING_1),
        keyValueTable(threatRows(context)),
        heading("Blockers and Required Human Actions", HeadingLevel.HEADING_1),
        blockersTable(context),
        heading("Autonomous Analysis Completed", HeadingLevel.HEADING_1),
        ...bulletList(context.automation?.completed || ["Source-bound finding normalised", "Governance boundary applied"]),
        heading("Human Decisions Still Required", HeadingLevel.HEADING_1),
        ...bulletList(context.automation?.remaining_human_decisions || ["Review evidence and issue or withhold accountable approval."]),
        heading("Source-Pack and Current-State Separation", HeadingLevel.HEADING_1),
        para("The signed source pack preserves the compiled evidence state at generation time. Current-state overlays, post-pack evidence events, human approvals, and later reviews must be recorded as separate accountable events."),
        heading("Decision Boundary", HeadingLevel.HEADING_1),
        warningBox(context.boundaryText),
        heading("Appendix: Signed Artefacts", HeadingLevel.HEADING_1),
        artefactTable(context.artefactNames)
      ]
    }]
  });
  return Packer.toBuffer(doc);
}

function titleBlock(context) {
  return new Paragraph({
    spacing: { before: 0, after: 80 },
    children: [
      new TextRun({ text: "DIIaC PatchForge", bold: true, size: 22, color: COLORS.teal }),
      new TextRun({ text: " | Signed Patch Governance", size: 22, color: COLORS.muted })
    ]
  });
}

function leadCallout(context) {
  const lines = [
    new TextRun({ text: context.title, bold: true, size: 32, color: COLORS.navy, break: 1 }),
    new TextRun({ text: `${context.audience} | ${context.vulnerabilityId} | Pack ${context.packId}`, size: 20, color: COLORS.muted, break: 1 }),
    new TextRun({ text: `Generated ${formatDate(context.generatedAt)}. Decision posture: ${humanize(context.decisionPosture)}. Readiness: ${humanize(context.readinessState)}.`, size: 20, color: COLORS.ink, break: 1 })
  ];
  return new Paragraph({
    shading: { type: ShadingType.CLEAR, fill: COLORS.softBlue },
    border: { left: { color: COLORS.teal, size: 16, style: BorderStyle.SINGLE } },
    spacing: { before: 80, after: 200 },
    indent: { left: 160 },
    children: lines
  });
}

function heading(text, level, options = {}) {
  return new Paragraph({ text, heading: level, keepNext: true, pageBreakBefore: Boolean(options.pageBreakBefore) });
}

function para(text) {
  return new Paragraph({ text: safeText(text), spacing: { after: 120 } });
}

function warningBox(text) {
  return new Paragraph({
    shading: { type: ShadingType.CLEAR, fill: COLORS.softAmber },
    border: { left: { color: COLORS.amber, size: 16, style: BorderStyle.SINGLE } },
    indent: { left: 160 },
    spacing: { before: 80, after: 180 },
    children: [new TextRun({ text: safeText(text), bold: true, color: COLORS.ink })]
  });
}

function bulletList(items) {
  const values = Array.isArray(items) && items.length ? items : ["Not recorded"];
  return values.slice(0, 10).map((item) => new Paragraph({
    bullet: { level: 0 },
    spacing: { after: 80 },
    children: [new TextRun({ text: safeText(item), size: 20, color: COLORS.ink })]
  }));
}

function decisionSummaryTable(context) {
  return keyValueTable([
    ["Recommended posture", humanize(context.recommendation?.posture || context.decisionPosture)],
    ["Next best action", context.recommendation?.next_best_action || "Review evidence and compile the signed decision pack."],
    ["Confidence", humanize(context.recommendation?.confidence || "not recorded")],
    ["Human approval", context.finalApprovalIssued ? "Recorded in signed pack" : "Still required"],
    ["Decision boundary", "Analysis is autonomous; approval, risk acceptance, and closure are human-controlled"]
  ]);
}

function scopeTable(context) {
  const services = context.exposure?.affected_services || [];
  const assets = context.exposure?.affected_assets || [];
  const rows = [["Scope", "Record", "Operational meaning"]];
  for (const service of services.slice(0, 6)) {
    rows.push([
      "Service",
      service.service_name || service.service_id,
      `${service.customer_facing ? "Customer-facing" : humanize(service.service_tier || "tier unknown")} | Owner: ${service.owner || "not recorded"}`
    ]);
  }
  for (const asset of assets.slice(0, 6)) {
    rows.push([
      "Asset",
      asset.asset_name || asset.asset_id,
      `${humanize(asset.asset_class || "class unknown")} | ${humanize(asset.criticality || "criticality unknown")} | ${humanize(asset.exposure || "exposure unknown")}`
    ]);
  }
  if (rows.length === 1) {
    rows.push(["Unmapped", "No reviewed asset/service scope", "This is a decision blocker because the organisation cannot safely judge impact or completion."]);
  }
  return gridTable(rows, [1500, 3060, 4800]);
}

function exploitabilityRows(context) {
  const exploitability = context.exploitability || {};
  return [
    ["Known exploited signal", exploitability.known_exploited ? "Yes, source-bound pending review unless accepted" : "Not recorded as reviewed"],
    ["EPSS score", formatProbability(exploitability.epss_score)],
    ["EPSS percentile", formatProbability(exploitability.epss_percentile)],
    ["Ransomware campaign use", exploitability.ransomware_use || "Unknown"],
    ["Can close gates alone", "No"]
  ];
}

function recommendationNarrative(context) {
  const recommendation = context.recommendation || {};
  const rationale = Array.isArray(recommendation.rationale) && recommendation.rationale.length
    ? recommendation.rationale.join(" ")
    : "PatchForge recommends completing evidence review before final approval.";
  return `${humanize(recommendation.posture || context.decisionPosture)} is the current advisory posture. ${rationale} This remains a governed decision: PatchForge can prepare the evidence and report, but a human approver must issue the decision outcome.`;
}

function actionPlanTable(context) {
  const recommendation = context.recommendation || {};
  const rows = [["Timing", "Action", "Owner / gate"]];
  const doNow = Array.isArray(recommendation.do_now) && recommendation.do_now.length ? recommendation.do_now : [recommendation.next_best_action || "Review source evidence and compile decision pack."];
  const doNext = Array.isArray(recommendation.do_next) ? recommendation.do_next : [];
  for (const action of doNow.slice(0, 4)) {
    rows.push(["Now", action, "Security lead / CAB reviewer"]);
  }
  for (const action of doNext.slice(0, 5)) {
    rows.push(["Next", action, "Service owner / evidence owner"]);
  }
  if (recommendation.due_date) {
    rows.push(["Deadline", `Recorded due date: ${recommendation.due_date}`, "Accountable owner"]);
  }
  return gridTable(rows, [1300, 5360, 2700]);
}

function decisionOptionsTable(context) {
  const options = context.decisionOptions.length ? context.decisionOptions : [{
    posture: context.decisionPosture,
    when_to_choose: "Use when evidence supports the posture and an accountable human reviewer approves it.",
    benefits: "Preserves traceability.",
    risks: "Evidence gaps remain if source review and scope are incomplete.",
    evidence_needed: context.blockers || [],
    approval_needed: true,
    recommended: true
  }];
  const rows = [["Option", "When it fits", "Decision impact"]];
  for (const option of options.slice(0, 6)) {
    rows.push([
      `${option.recommended ? "Recommended: " : ""}${humanize(option.posture)}`,
      option.when_to_choose,
      `Benefit: ${option.benefits} Required evidence: ${(option.evidence_needed || []).join(", ") || "reviewed evidence"}. Approval: ${option.approval_needed ? "required" : "not required at this stage"}.`
    ]);
  }
  return gridTable(rows, [2200, 3400, 3760]);
}

function evidenceGapTable(context) {
  const evidence = context.intelligence?.evidence || {};
  const gaps = evidence.gaps?.length ? evidence.gaps : context.blockers;
  const rows = [["Evidence / gate", "State", "Decision implication"]];
  if (gaps?.length) {
    for (const gap of gaps.slice(0, 8)) {
      rows.push([humanize(gap), "Open", actionForBlocker(gap)]);
    }
  } else {
    rows.push(["Evidence blockers", "No open blocker list supplied", "Human approval and final outcome still require accountable review."]);
  }
  rows.push(["Pending source review", String(evidence.pending_review_count ?? "Not recorded"), "Pending sources cannot be treated as accepted truth."]);
  rows.push(["Accepted positive evidence", String(evidence.accepted_positive_evidence_count ?? "Not recorded"), "Only accepted positive evidence can support hard gates."]);
  rows.push(["Rejected sources", String(evidence.rejected_source_count ?? "Not recorded"), "Rejected sources cannot support the decision."]);
  return gridTable(rows, [2600, 1900, 4860]);
}

function footerNote(context) {
  return new Paragraph({
    spacing: { before: 240 },
    children: [
      new TextRun({ text: "Report integrity note: ", bold: true, color: COLORS.navy }),
      new TextRun({ text: `This report was generated from signed pack ${context.packId}. Source truth still depends on reviewed source evidence and accountable human approval.` })
    ]
  });
}

function keyValueTable(rows) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    margins: tableMargins(),
    rows: rows.map(([label, value], index) => new TableRow({
      tableHeader: false,
      children: [
        cell(label, { width: 2800, bold: true, fill: index % 2 ? COLORS.white : COLORS.fill }),
        cell(value, { width: 6560, fill: index % 2 ? COLORS.white : COLORS.fill })
      ]
    }))
  });
}

function sourceTable(sources) {
  const rows = [["Source ref", "Class", "Review", "Evidence"]];
  for (const source of sources.slice(0, 8)) {
    rows.push([source.ref, humanize(source.className), humanize(source.review), humanize(source.evidence)]);
  }
  if (rows.length === 1) {
    rows.push(["No source records", "Not recorded", "Pending", "Referenced"]);
  }
  return gridTable(rows, [3180, 2240, 1880, 2060]);
}

function blockersTable(context) {
  const blockers = context.blockers.length ? context.blockers : ["No blocker list was supplied with the pack."];
  const rows = [["Blocker / Action", "Owner", "Required outcome"]];
  for (const blocker of blockers) {
    rows.push([humanize(blocker), "Accountable service/security owner", actionForBlocker(blocker)]);
  }
  rows.push(["Human approval", "CAB / security lead", context.finalApprovalIssued ? "Approval event already recorded" : "Explicit approval remains required"]);
  return gridTable(rows, [3180, 2620, 3560]);
}

function artefactTable(artefactNames) {
  const rows = [["Artefact", "Status"]];
  for (const name of artefactNames.slice(0, 16)) {
    rows.push([name, "Preserved in signed pack export"]);
  }
  if (rows.length === 1) {
    rows.push(["No artefacts listed", "Not recorded"]);
  }
  return gridTable(rows, [5800, 3560]);
}

function gridTable(rows, widths) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    margins: tableMargins(),
    rows: rows.map((row, rowIndex) => new TableRow({
      tableHeader: rowIndex === 0,
      children: row.map((value, cellIndex) => cell(value, {
        width: widths[cellIndex],
        bold: rowIndex === 0,
        fill: rowIndex === 0 ? COLORS.navy : (rowIndex % 2 ? COLORS.white : COLORS.fill),
        color: rowIndex === 0 ? COLORS.white : COLORS.ink,
        align: cellIndex === 0 ? AlignmentType.LEFT : AlignmentType.CENTER
      }))
    }))
  });
}

function cell(value, options = {}) {
  return new TableCell({
    width: { size: options.width || 4680, type: WidthType.DXA },
    verticalAlign: VerticalAlign.CENTER,
    shading: { type: ShadingType.CLEAR, fill: options.fill || COLORS.white },
    margins: { top: 100, bottom: 100, left: 120, right: 120 },
    children: [
      new Paragraph({
        alignment: options.align || AlignmentType.LEFT,
        spacing: { before: 0, after: 0 },
        children: [new TextRun({ text: safeText(value), bold: Boolean(options.bold), color: options.color || COLORS.ink, size: 19 })]
      })
    ]
  });
}

function tableMargins() {
  return { top: 80, bottom: 80, left: 120, right: 120 };
}

function bayesianRows(context) {
  const snapshot = context.bayesian || {};
  return [
    ["Availability", snapshot.available === false ? "Not generated" : "Generated"],
    ["Advisory boundary", "Advisory only; cannot close gates or approve risk"],
    ["Recommended posture", humanize(snapshot.recommended_governance_posture || context.decisionPosture)],
    ["Exploit probability posterior", formatProbability(snapshot.exploit_probability_posterior)],
    ["Business impact posterior", formatProbability(snapshot.business_impact_posterior)],
    ["Patch feasibility posterior", formatProbability(snapshot.patch_feasibility_posterior)],
    ["Change risk posterior", formatProbability(snapshot.change_risk_posterior)],
    ["Deferral risk posterior", formatProbability(snapshot.deferral_risk_posterior)]
  ];
}

function threatRows(context) {
  const metrics = context.threat?.metrics || {};
  const vendor = context.vendor || {};
  return [
    ["Vendor intelligence", vendor.available === false ? "Not generated" : "Source-bound"],
    ["Threat landscape", context.threat?.available === false ? "Not generated" : "Source-bound"],
    ["Active exploitation signals", metrics.active_exploitation_count ?? "Not recorded"],
    ["Critical open advisories", metrics.critical_open_advisory_count ?? "Not recorded"],
    ["Patch maturity", humanize(metrics.patch_maturity || context.patchStatus)],
    ["Source review", "Pending review unless explicitly accepted"]
  ];
}

async function buildPdfReport(context) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "LETTER", margin: 54, info: { Title: context.title, Author: "DIIaC PatchForge" } });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("error", reject);
    doc.on("end", () => resolve(Buffer.concat(chunks)));

    pdfTitle(doc, context);
    pdfSection(doc, "Executive Decision Summary");
    pdfParagraph(doc, context.executiveReadout || `${context.vulnerabilityId} is currently governed as ${humanize(context.decisionPosture)}. Final approval remains human-controlled.`);
    pdfKeyValues(doc, [
      ["Recommended posture", humanize(context.recommendation?.posture || context.decisionPosture)],
      ["Next best action", context.recommendation?.next_best_action || "Review evidence and compile the signed decision pack."],
      ["Confidence", humanize(context.recommendation?.confidence || "not recorded")],
      ["Human approval", context.finalApprovalIssued ? "Recorded" : "Still required"]
    ]);
    pdfSection(doc, "What This Vulnerability Means");
    pdfParagraph(doc, context.plainEnglish || `${context.vulnerabilityTitle} is a source-bound vulnerability decision. PatchForge translates it into governed options, evidence gaps, and accountable human actions.`);
    pdfSection(doc, "Why It Matters Now");
    pdfParagraph(doc, context.whyNow || "Urgency depends on reviewed source, exposure, and service-impact evidence.");
    pdfSection(doc, "Affected Scope");
    pdfParagraph(doc, context.whatItAffects || "Affected asset and service scope is not fully mapped in the signed pack.");
    pdfSection(doc, "Exploitability Intelligence");
    pdfCallout(doc, context.exploitability?.prohibited_detail || "Exploit code, exploit payloads, and procedural exploitation steps are intentionally not provided.");
    pdfParagraph(doc, context.exploitability?.safe_description || "Exploitability signals inform prioritisation only and do not close evidence gates.");
    pdfKeyValues(doc, exploitabilityRows(context));
    pdfSection(doc, "Recommended Action Plan");
    pdfParagraph(doc, recommendationNarrative(context));
    for (const action of [...(context.recommendation?.do_now || []), ...(context.recommendation?.do_next || [])].slice(0, 7)) {
      pdfBullet(doc, action);
    }
    pdfSection(doc, "Decision Snapshot");
    pdfKeyValues(doc, [
      ["Vulnerability", context.vulnerabilityId],
      ["Title", context.vulnerabilityTitle],
      ["Severity", humanize(context.severity)],
      ["Posture", humanize(context.decisionPosture)],
      ["Readiness", humanize(context.readinessState)],
      ["Final approval", context.finalApprovalIssued ? "Issued" : "Not issued"]
    ]);
    pdfSection(doc, "Decision Options");
    for (const option of (context.decisionOptions.length ? context.decisionOptions : []).slice(0, 5)) {
      pdfBullet(doc, `${option.recommended ? "Recommended: " : ""}${humanize(option.posture)} - ${option.when_to_choose}`);
    }
    pdfSection(doc, "Evidence, Trust, and Signing");
    pdfKeyValues(doc, [
      ["Signed pack", context.packId],
      ["Verification", context.verified ? "Verified" : "Pending or not recorded"],
      ["Signing provider", humanize(context.signingProvider)],
      ["Manifest hash", context.governanceManifestHash],
      ["Source pack", context.sourcePackImmutable ? "Immutable and preserved" : "Not confirmed"]
    ]);
    pdfSection(doc, "Bayesian Advisory");
    pdfKeyValues(doc, bayesianRows(context));
    pdfSection(doc, "Vendor and Threat Landscape");
    pdfKeyValues(doc, threatRows(context));
    pdfSection(doc, "Blockers and Next Actions");
    for (const blocker of (context.blockers.length ? context.blockers : ["Human review required"])) {
      pdfBullet(doc, `${humanize(blocker)}: ${actionForBlocker(blocker)}`);
    }
    pdfSection(doc, "Decision Boundary");
    pdfCallout(doc, context.boundaryText);
    pdfSection(doc, "Signed Artefacts");
    for (const artefact of context.artefactNames.slice(0, 14)) {
      pdfBullet(doc, artefact);
    }
    doc.end();
  });
}

function pdfTitle(doc, context) {
  doc.fillColor(`#${COLORS.teal}`).font("Helvetica-Bold").fontSize(10).text("DIIaC PatchForge | Signed Patch Governance");
  doc.moveDown(0.7);
  doc.fillColor(`#${COLORS.navy}`).fontSize(22).text(context.title, { lineGap: 3 });
  doc.moveDown(0.4);
  doc.fillColor(`#${COLORS.muted}`).font("Helvetica").fontSize(9).text(`${context.audience} | ${context.vulnerabilityId} | Pack ${context.packId}`);
  doc.moveDown(0.8);
  pdfCallout(doc, `Generated ${formatDate(context.generatedAt)}. Decision posture: ${humanize(context.decisionPosture)}. Readiness: ${humanize(context.readinessState)}.`);
}

function pdfSection(doc, title) {
  ensurePdfRoom(doc, 64);
  doc.moveDown(0.8);
  doc.fillColor(`#${COLORS.navy}`).font("Helvetica-Bold").fontSize(13).text(title);
  doc.moveTo(doc.page.margins.left, doc.y + 4).lineTo(doc.page.width - doc.page.margins.right, doc.y + 4).strokeColor(`#${COLORS.line}`).lineWidth(0.6).stroke();
  doc.moveDown(0.8);
}

function pdfKeyValues(doc, rows) {
  for (const [label, value] of rows) {
    ensurePdfRoom(doc, 30);
    const y = doc.y;
    doc.fillColor(`#${COLORS.navy}`).font("Helvetica-Bold").fontSize(9).text(safeText(label), doc.page.margins.left, y, { width: 160 });
    doc.fillColor(`#${COLORS.ink}`).font("Helvetica").fontSize(9).text(safeText(value), doc.page.margins.left + 175, y, { width: 320 });
    doc.moveDown(0.55);
  }
}

function pdfParagraph(doc, text) {
  ensurePdfRoom(doc, 44);
  doc.fillColor(`#${COLORS.ink}`).font("Helvetica").fontSize(9.5).text(safeText(text), {
    width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
    lineGap: 2
  });
  doc.moveDown(0.7);
}

function pdfBullet(doc, text) {
  ensurePdfRoom(doc, 30);
  const y = doc.y;
  doc.fillColor(`#${COLORS.teal}`).font("Helvetica-Bold").fontSize(9).text("•", doc.page.margins.left, y, { width: 12 });
  doc.fillColor(`#${COLORS.ink}`).font("Helvetica").fontSize(9).text(safeText(text), doc.page.margins.left + 16, y, { width: 500 });
  doc.moveDown(0.45);
}

function pdfCallout(doc, text) {
  ensurePdfRoom(doc, 60);
  const x = doc.page.margins.left;
  const y = doc.y;
  const width = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const height = Math.max(46, doc.heightOfString(safeText(text), { width: width - 24 }) + 18);
  doc.roundedRect(x, y, width, height, 4).fillAndStroke(`#${COLORS.softBlue}`, `#${COLORS.line}`);
  doc.fillColor(`#${COLORS.ink}`).font("Helvetica").fontSize(9).text(safeText(text), x + 12, y + 10, { width: width - 24 });
  doc.y = y + height + 8;
}

function ensurePdfRoom(doc, height) {
  if (doc.y + height > doc.page.height - doc.page.margins.bottom) {
    doc.addPage();
  }
}

function actionForBlocker(blocker) {
  const normalized = String(blocker || "").toLowerCase();
  if (normalized.includes("human")) {
    return "Record accountable approval event after evidence review.";
  }
  if (normalized.includes("rollback")) {
    return "Attach reviewed rollback evidence before close or emergency approval.";
  }
  if (normalized.includes("test")) {
    return "Attach reviewed test evidence or record explicit deferral rationale.";
  }
  if (normalized.includes("risk")) {
    return "Record owner, rationale, expiry, and compensating controls.";
  }
  if (normalized.includes("post")) {
    return "Attach post-patch validation evidence before closure.";
  }
  return "Assign owner, attach reviewed evidence, and rerun deterministic compile.";
}

function fileNameFor(context, extension) {
  return `${context.packId}-${context.reportType}.${extension}`.replace(/[^a-zA-Z0-9_.-]+/g, "-");
}

function safeText(value) {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }
  return String(value);
}

function humanize(value) {
  return safeText(value)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatProbability(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "Not generated";
  }
  return `${Math.round(numeric * 100)}%`;
}

function formatDate(value) {
  try {
    return new Date(value).toLocaleString("en-GB", { timeZone: "UTC", hour12: false });
  } catch {
    return safeText(value);
  }
}

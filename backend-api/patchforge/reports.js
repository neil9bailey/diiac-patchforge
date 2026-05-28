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
import JSZip from "jszip";
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
    report_type: "ciso_patch_version_comparison_report",
    title: "CISO Patch Version Comparison Report",
    audience: "CISO and security leadership",
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
const HUMAN_APPROVAL_NOTICE = "Human approval remains required. PatchForge does not approve CAB decisions, risk acceptance, patch deployment, or closure autonomously.";
const UNCONFIRMED_SCOPE_TEXT = "PatchForge has public-source vulnerability intelligence, but customer asset and service exposure are not yet confirmed.";
const NO_CUSTOMER_ASSURANCE_TEXT = "No customer remediation assurance can be issued yet because affected customer service scope and patch applicability evidence are not reviewed.";
const REPORT_TEMPLATE_VERSION = "patchforge-report-template.v2026-05-27.2";
const REPORT_CONTEXT_VERSION = "patchforge-report-context.v2";
const DEFAULT_PRODUCT_BASELINE = process.env.PATCHFORGE_PRODUCT_BASELINE || "PF-AZ9-VENDORLENS";
const DEFAULT_RENDERER_COMMIT = process.env.PATCHFORGE_RENDERER_COMMIT || process.env.PATCHFORGE_COMMIT_SHA || process.env.GIT_COMMIT || "local";
const DEFAULT_IMAGE_TAG = process.env.PATCHFORGE_IMAGE_TAG || process.env.CONTAINER_IMAGE_TAG || "local";
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
  const networkVendor = artefacts["network_vendor_profile_snapshot.json"] || null;
  const customerNetworkAsset = artefacts["customer_network_asset_snapshot.json"] || null;
  const vendorSecurityAdvisory = artefacts["vendor_security_advisory_snapshot.json"] || null;
  const configApplicability = artefacts["config_applicability_assessment.json"] || null;
  const vendorLensPatchComparison = artefacts["vendorlens_patch_comparison.json"] || null;
  const sraConfigChat = artefacts["sra_config_chat_session.json"] || null;
  const vendorLensDecisionContext = artefacts["vendorlens_decision_context.json"] || null;
  const sraTrace = artefacts["sra_trace.json"] || null;
  const governanceManifest = artefacts["governance_manifest.json"] || {};
  const verificationManifest = artefacts["verification_manifest.json"] || {};
  const sigmeta = artefacts["signed_export.sigmeta.json"] || {};
  const humanReview = artefacts["human_review_state.json"] || {};
  const riskAcceptance = artefacts["patch_risk_acceptance_state.json"] || {};
  const controls = artefacts["compensating_controls_plan.json"] || {};
  const patchFeasibility = artefacts["patch_feasibility_assessment.json"] || {};
  const generatedAt = new Date().toISOString();
  const packId = pack.pack_id || pack.decision_pack_id;

  return {
    reportType,
    title: catalogItem.title,
    audience: catalogItem.audience,
    generatedAt,
    reportTemplateVersion: pack.report_template_version || governanceManifest.report_template_version || REPORT_TEMPLATE_VERSION,
    rendererCommit: pack.renderer_commit || governanceManifest.renderer_commit || DEFAULT_RENDERER_COMMIT,
    imageTag: pack.image_tag || governanceManifest.image_tag || DEFAULT_IMAGE_TAG,
    generatedFromPackId: pack.generated_from_pack_id || governanceManifest.generated_from_pack_id || packId,
    productBaseline: pack.product_baseline || governanceManifest.product_baseline || DEFAULT_PRODUCT_BASELINE,
    reportContextVersion: pack.report_context_version || governanceManifest.report_context_version || REPORT_CONTEXT_VERSION,
    packId,
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
    evidenceGapDetails: findingIntelligence?.evidence?.gap_details || [],
    automation: findingIntelligence?.automation || null,
    bayesian,
    vendor,
    threat,
    networkVendor,
    customerNetworkAsset,
    vendorSecurityAdvisory,
    configApplicability,
    vendorLensPatchComparison,
    sraConfigChat,
    vendorLensDecisionContext,
    sraTrace,
    controls,
    riskAcceptance,
    patchFeasibility,
    sourceFeedRuns: sourceFeedRuns.slice(0, 6),
    artefactNames: Object.keys(artefacts).sort(),
    boundaryText: BOUNDARY_TEXT,
    humanApprovalNotice: HUMAN_APPROVAL_NOTICE
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
        heading("Report Version Stamp", HeadingLevel.HEADING_1),
        ...keyValueBlocks(reportVersionRows(context)),
        heading("Executive Decision Summary", HeadingLevel.HEADING_1),
        para(context.executiveReadout || `${context.vulnerabilityId} is currently governed as ${displayPosture(context)}. Final approval has not been issued unless explicitly recorded in the signed pack.`),
        para(finalApprovalSentence(context)),
        decisionSummaryTable(context),
        ...customerSpecificSections(context),
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
        para(context.exploitability?.kev_epss_interpretation || "KEV and EPSS are prioritisation signals only. They do not prove tenant exposure and cannot close hard gates without reviewed customer asset and service evidence."),
        ...keyValueBlocks(exploitabilityRows(context)),
        heading("Recommended Governance Posture", HeadingLevel.HEADING_1),
        para(recommendationNarrative(context)),
        actionPlanTable(context),
        heading("Decision Options Matrix", HeadingLevel.HEADING_1),
        ...decisionOptionsBlocks(context),
        heading("Evidence Confidence and Gaps", HeadingLevel.HEADING_1, { pageBreakBefore: true }),
        para("The report separates source-pack evidence from current-state overlays. Source records, scanner findings, SRA/MCP/agent findings, CISA KEV records, EPSS signals, and vendor advisories remain source-bound until reviewed."),
        ...evidenceGapBlocks(context),
        heading("Decision Snapshot", HeadingLevel.HEADING_1),
        ...keyValueBlocks([
          ["Vulnerability", context.vulnerabilityId],
          ["Title", context.vulnerabilityTitle],
          ["Severity", humanize(context.severity)],
          ["Decision posture", humanize(context.decisionPosture)],
          ["Readiness", `${humanize(context.readinessState)}${context.readinessScore === null ? "" : ` (${context.readinessScore})`}`],
          ["Final approval", context.finalApprovalIssued ? "Issued" : "Not issued"],
          ["Source pack", context.sourcePackImmutable ? "Immutable and preserved" : "Not confirmed"]
        ]),
        heading("Evidence, Trust, and Signing", HeadingLevel.HEADING_1),
        ...keyValueBlocks([
          ["Signed pack", context.packId],
          ["Verification", context.verified ? "Verified" : "Pending or not recorded"],
          ["Signing provider", humanize(context.signingProvider)],
          ["Signature algorithm", context.signatureAlgorithm],
          ["Governance manifest SHA-256", context.governanceManifestHash],
          ["Evidence references", context.evidenceRefs.length ? String(context.evidenceRefs.length) : "None recorded"]
        ]),
        heading("Source Intelligence", HeadingLevel.HEADING_1),
        ...sourceBlocks(context.sources),
        heading("Bayesian Advisory", HeadingLevel.HEADING_1),
        ...keyValueBlocks(bayesianRows(context)),
        heading("Vendor and Threat Landscape", HeadingLevel.HEADING_1),
        ...keyValueBlocks(threatRows(context)),
        ...vendorLensDocxSections(context),
        ...patchComparisonDocxSections(context),
        heading("Blockers and Required Human Actions", HeadingLevel.HEADING_1),
        ...blockerBlocks(context),
        heading("Automated Governance Analysis Completed", HeadingLevel.HEADING_1),
        warningBox(context.humanApprovalNotice),
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
  return normalizeDocxForWord(await Packer.toBuffer(doc));
}

async function normalizeDocxForWord(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  const output = new JSZip();
  const omittedRelationshipParts = new Set([
    "word/_rels/footnotes.xml.rels",
    "word/_rels/endnotes.xml.rels",
    "word/_rels/comments.xml.rels",
    "word/_rels/fontTable.xml.rels"
  ]);
  const names = Object.keys(zip.files).sort();
  for (const name of names) {
    const entry = zip.files[name];
    if (!entry || entry.dir || omittedRelationshipParts.has(name)) {
      continue;
    }
    output.file(name, await entry.async("uint8array"), { createFolders: false });
  }
  return output.generateAsync({ type: "nodebuffer", compression: "STORE" });
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
  const approvalLine = finalApprovalSentence(context);
  const lines = [
    new TextRun({ text: context.title, bold: true, size: 32, color: COLORS.navy, break: 1 }),
    new TextRun({ text: `${context.audience} | ${context.vulnerabilityId} | Pack ${context.packId}`, size: 20, color: COLORS.muted, break: 1 }),
    new TextRun({ text: `Generated ${formatDate(context.generatedAt)}. Governed posture: ${displayPosture(context)}. Readiness: ${humanize(context.readinessState)}. ${approvalLine}`, size: 20, color: COLORS.ink, break: 1 })
  ];
  return new Paragraph({
    shading: { type: ShadingType.CLEAR, fill: COLORS.softBlue },
    border: { left: { color: COLORS.teal, size: 16, style: BorderStyle.SINGLE } },
    spacing: { before: 80, after: 200 },
    indent: { left: 160 },
    children: lines
  });
}

function finalApprovalSentence(context) {
  return context.finalApprovalIssued
    ? "Final approval issued by recorded human approval event."
    : "Final approval not issued.";
}

function heading(text, level, options = {}) {
  return new Paragraph({ text, heading: level, pageBreakBefore: Boolean(options.pageBreakBefore) });
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
    ["Recommended posture", displayPosture(context)],
    ["Next best action", context.recommendation?.next_best_action || "Review evidence and compile the signed decision pack."],
    ["Confidence", humanize(context.recommendation?.confidence || "not recorded")],
    ["Human approval", context.finalApprovalIssued ? "Recorded in signed pack" : "Still required"],
    ["Decision boundary", "Automated evidence preparation is complete where stated; approval, risk acceptance, patch deployment, and closure remain human-controlled"]
  ]);
}

function reportVersionRows(context) {
  return [
    ["report_template_version", context.reportTemplateVersion],
    ["renderer_commit", context.rendererCommit],
    ["image_tag", context.imageTag],
    ["generated_from_pack_id", context.generatedFromPackId],
    ["generated_at", context.generatedAt],
    ["product_baseline", context.productBaseline],
    ["report_context_version", context.reportContextVersion]
  ];
}

function customerSpecificSections(context) {
  if (context.reportType !== "customer_patch_governance_pack") {
    return [];
  }
  const customerScopeConfirmed = Boolean(context.exposure && !context.exposure.unmapped_scope && context.exposure.affected_service_count > 0);
  const patchApplicabilityReviewed = ["patch_available", "patch_feasible", "mitigation_only", "no_patch_available"].includes(String(context.patchStatus || "").toLowerCase());
  const assurancePosition = customerScopeConfirmed && patchApplicabilityReviewed
    ? "Customer remediation assurance can be prepared only for the reviewed services and evidence references listed in this pack."
    : NO_CUSTOMER_ASSURANCE_TEXT;
  const impactStatus = customerScopeConfirmed
    ? "Reviewed customer-facing service scope is present. Confirm the listed service owner, SLA/OLA impact, and communication owner before issuing customer-facing assurance."
    : `${UNCONFIRMED_SCOPE_TEXT} Customer impact must be treated as unconfirmed.`;

  return [
    heading("Customer Assurance Position", HeadingLevel.HEADING_1),
    warningBox(assurancePosition),
    heading("Customer Impact Status", HeadingLevel.HEADING_2),
    para(impactStatus),
    heading("Customer Evidence Required", HeadingLevel.HEADING_2),
    ...evidenceGapBlocks(context),
    heading("Customer Communication Position", HeadingLevel.HEADING_2),
    para(customerScopeConfirmed ? "Customer communication can describe reviewed source-bound risk, affected services, current blockers, and the accountable decision timeline." : "Customer communication should be limited to source-bound public-intelligence awareness and the active scope-confirmation work. Do not state that the customer estate is affected or remediated until reviewed exposure and patch applicability evidence exists."),
    heading("What Can Be Shared With Customer", HeadingLevel.HEADING_2),
    ...bulletList([
      "PatchForge has recorded a source-bound vulnerability governance case.",
      "Known-exploited and EPSS-style signals are prioritisation inputs, not proof of tenant exposure.",
      "Human review, customer scope confirmation, and patch applicability evidence are required before assurance is issued."
    ]),
    heading("What Cannot Yet Be Claimed", HeadingLevel.HEADING_2),
    ...bulletList([
      "Do not claim customer exposure is confirmed unless reviewed asset and service evidence is attached.",
      "Do not claim patch applicability, successful remediation, closure, certification, or risk acceptance unless the signed pack and current-state events record those facts.",
      "Do not imply PatchForge deployed a patch or approved the decision autonomously."
    ])
  ];
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
    current_status: "blocked",
    reason: "Decision evidence has not been fully supplied in the pack.",
    required_evidence: context.blockers || [],
    required_approval: "Accountable human approval.",
    approval_needed: true,
    recommended: true
  }];
  const rows = [["Option", "Current status", "Reason", "Required evidence / approval"]];
  for (const option of options.slice(0, 6)) {
    rows.push([
      `${option.recommended ? "Recommended: " : ""}${humanize(option.posture)}`,
      humanize(option.current_status || (option.recommended ? "recommended" : "available")),
      option.reason || option.when_to_choose,
      `Evidence: ${(option.required_evidence || option.evidence_needed || []).join(", ") || "reviewed evidence"}. Approval: ${option.required_approval || (option.approval_needed ? "required" : "not required at this stage")}.`
    ]);
  }
  return gridTable(rows, [2050, 1700, 3100, 2510]);
}

function decisionOptionsBlocks(context) {
  const options = context.decisionOptions.length ? context.decisionOptions : [{
    posture: context.decisionPosture,
    current_status: "blocked",
    reason: "Decision evidence has not been fully supplied in the pack.",
    required_evidence: context.blockers || [],
    required_approval: "Accountable human approval.",
    recommended: true
  }];
  return options.slice(0, 6).flatMap((option) => detailBlock(`${option.recommended ? "Recommended: " : ""}${humanize(option.posture)}`, [
    ["Current status", humanize(option.current_status || (option.recommended ? "recommended" : "available"))],
    ["Reason", option.reason || option.when_to_choose || "Use when reviewed evidence supports this posture."],
    ["Required evidence", (option.required_evidence || option.evidence_needed || []).join(", ") || "Reviewed evidence required"],
    ["Required approval", option.required_approval || (option.approval_needed ? "Required" : "Not required at this stage")]
  ]));
}

function evidenceGapTable(context) {
  const evidence = context.intelligence?.evidence || {};
  const gaps = evidence.gaps?.length ? evidence.gaps : context.blockers;
  const details = context.evidenceGapDetails?.length ? context.evidenceGapDetails : (gaps || []).map(gapDetailForReport);
  const rows = [["Gap", "Why it matters", "Required evidence", "Owner / next gate"]];
  if (details?.length) {
    for (const detail of details.slice(0, 8)) {
      rows.push([
        humanize(detail.gap || detail.plain_english_gap),
        detail.why_it_matters || actionForBlocker(detail.gap),
        `${detail.required_evidence || "Reviewed evidence required"} Examples: ${(detail.evidence_examples || []).join(", ") || "accepted source record"}.`,
        `${detail.suggested_owner_role || "Evidence owner"} | ${detail.next_decision_gate || "Evidence review"}`
      ]);
    }
  } else {
    rows.push(["Evidence blockers", "No open blocker list supplied", "Human approval and final outcome still require accountable review.", "CAB / security lead"]);
  }
  rows.push(["Pending source review", "Pending sources cannot be treated as accepted truth.", String(evidence.pending_review_count ?? "Not recorded"), "Security lead / source review"]);
  rows.push(["Accepted positive evidence", "Only accepted positive evidence can support hard gates.", String(evidence.accepted_positive_evidence_count ?? "Not recorded"), "Evidence reviewer"]);
  rows.push(["Rejected sources", "Rejected sources cannot support the decision.", String(evidence.rejected_source_count ?? "Not recorded"), "Evidence reviewer"]);
  return gridTable(rows, [2100, 3100, 2600, 1560]);
}

function evidenceGapBlocks(context) {
  const evidence = context.intelligence?.evidence || {};
  const gaps = evidence.gaps?.length ? evidence.gaps : context.blockers;
  const details = context.evidenceGapDetails?.length ? context.evidenceGapDetails : (gaps || []).map(gapDetailForReport);
  const blocks = [];
  if (details?.length) {
    for (const detail of details.slice(0, 8)) {
      blocks.push(...detailBlock(humanize(detail.gap || detail.plain_english_gap), [
        ["Plain English gap", detail.plain_english_gap || humanize(detail.gap || "Evidence gap")],
        ["Why it matters", detail.why_it_matters || actionForBlocker(detail.gap)],
        ["Required evidence", detail.required_evidence || "Reviewed evidence required"],
        ["Evidence examples", (detail.evidence_examples || []).join(", ") || "Accepted source record"],
        ["Suggested owner", detail.suggested_owner_role || "Evidence owner"],
        ["Next decision gate", detail.next_decision_gate || "Evidence review"]
      ]));
    }
  } else {
    blocks.push(...detailBlock("Evidence blockers", [
      ["State", "No open blocker list supplied"],
      ["Decision implication", "Human approval and final outcome still require accountable review"]
    ]));
  }
  blocks.push(...detailBlock("Source Review Counts", [
    ["Pending source review", String(evidence.pending_review_count ?? "Not recorded")],
    ["Accepted positive evidence", String(evidence.accepted_positive_evidence_count ?? "Not recorded")],
    ["Rejected sources", String(evidence.rejected_source_count ?? "Not recorded")]
  ]));
  return blocks;
}

function blockerBlocks(context) {
  const blockers = context.evidenceGapDetails?.length ? context.evidenceGapDetails : (context.blockers.length ? context.blockers : ["Human review required"]);
  const blocks = blockers.flatMap((blocker) => {
    const detail = typeof blocker === "string" ? gapDetailForReport(blocker) : blocker;
    return detailBlock(humanize(detail.gap || blocker), [
      ["Owner", detail.suggested_owner_role || "Accountable service/security owner"],
      ["Required outcome", detail.required_evidence || actionForBlocker(detail.gap || blocker)],
      ["Next gate", detail.next_decision_gate || "Evidence review"]
    ]);
  });
  blocks.push(...detailBlock("Human approval", [
    ["Owner", "CAB / security lead"],
    ["Required outcome", context.finalApprovalIssued ? "Approval event already recorded" : "Explicit approval remains required"]
  ]));
  return blocks;
}

function detailBlock(title, rows) {
  const children = [
    new Paragraph({
      spacing: { before: 120, after: 60 },
      children: [new TextRun({ text: safeText(title), bold: true, color: COLORS.navy, size: 22 })]
    })
  ];
  for (const [label, value] of rows) {
    children.push(new Paragraph({
      spacing: { after: 70 },
      indent: { left: 220 },
      children: [
        new TextRun({ text: `${safeText(label)}: `, bold: true, color: COLORS.navy, size: 20 }),
        new TextRun({ text: safeText(value), color: COLORS.ink, size: 20 })
      ]
    }));
  }
  return children;
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

function keyValueBlocks(rows) {
  return rows.map(([label, value]) => new Paragraph({
    spacing: { after: 70 },
    indent: { left: 180 },
    children: [
      new TextRun({ text: `${safeText(label)}: `, bold: true, color: COLORS.navy, size: 20 }),
      new TextRun({ text: safeText(value), color: COLORS.ink, size: 20 })
    ]
  }));
}

function sourceBlocks(sources) {
  const values = sources?.length ? sources.slice(0, 8) : [{
    ref: "No source records",
    className: "not recorded",
    review: "pending",
    evidence: "referenced"
  }];
  return values.flatMap((source) => detailBlock(source.ref, [
    ["Class", humanize(source.className)],
    ["Review", humanize(source.review)],
    ["Evidence", humanize(source.evidence)],
    ["Source URL", source.url || "Not recorded"]
  ]));
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
  const blockers = context.evidenceGapDetails?.length ? context.evidenceGapDetails : (context.blockers.length ? context.blockers : ["No blocker list was supplied with the pack."]);
  const rows = [["Blocker / Action", "Owner", "Required outcome"]];
  for (const blocker of blockers) {
    const detail = typeof blocker === "string" ? gapDetailForReport(blocker) : blocker;
    rows.push([
      humanize(detail.gap || blocker),
      detail.suggested_owner_role || "Accountable service/security owner",
      `${detail.required_evidence || actionForBlocker(detail.gap || blocker)} Next gate: ${detail.next_decision_gate || "Evidence review"}.`
    ]);
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
  const vendorMissing = vendor.available === false || (!context.vendor && !vendor.source_bound);
  return [
    ["Vendor intelligence", vendorMissing ? "Reviewed vendor advisory evidence has not yet been attached." : "Source-bound; pending review unless explicitly accepted"],
    ["Vendor applicability", vendorMissing ? "Patch maturity, affected versions, workaround guidance, and remediation applicability remain unverified." : "Review vendor affected-version and workaround evidence before relying on it."],
    ["Threat landscape", context.threat?.available === false ? "Threat metrics not generated" : "Threat metrics shown below are source-bound public-intelligence signals and do not close hard gates."],
    ["Active exploitation signals", metrics.active_exploitation_count ?? "Not recorded"],
    ["Critical open advisories", metrics.critical_open_advisory_count ?? "Not recorded"],
    ["Patch maturity", humanize(metrics.patch_maturity || context.patchStatus)],
    ["Source review", "Pending review unless explicitly accepted"]
  ];
}

function vendorLensDocxSections(context) {
  const assessment = context.configApplicability || {};
  const asset = context.customerNetworkAsset || {};
  const advisory = context.vendorSecurityAdvisory || {};
  const chat = context.sraConfigChat || {};
  const decision = context.vendorLensDecisionContext || {};
  const hasVendorLens = Boolean(
    context.networkVendor
    || context.customerNetworkAsset
    || context.vendorSecurityAdvisory
    || context.configApplicability
    || context.sraConfigChat
    || context.vendorLensDecisionContext
  );
  const availability = hasVendorLens
    ? "VendorLens context is attached to this signed pack as source-bound advisory intelligence."
    : "VendorLens network vendor applicability context was not attached to this signed pack.";
  return [
    heading("Network Vendor Applicability", HeadingLevel.HEADING_1),
    para(availability),
    ...keyValueBlocks([
      ["Vendor", context.networkVendor?.vendor_name || advisory.vendor_name || assessment.vendor_id || "Not attached"],
      ["Advisory / CVE", advisory.cve || assessment.cve || advisory.advisory_id || "Not attached"],
      ["Applicability posture", humanize(assessment.applicability_posture || decision.applicability_posture || "not assessed")],
      ["Urgency posture", humanize(assessment.urgency_posture || decision.urgency_posture || "not assessed")],
      ["Human review", assessment.human_review_required === false ? "Not recorded" : "Required"],
      ["Final approval", assessment.final_approval_issued ? "Issued" : "Not issued"]
    ]),
    heading("Customer Configuration Context", HeadingLevel.HEADING_2),
    ...keyValueBlocks([
      ["Asset", asset.asset_id || "Not attached"],
      ["Product family", asset.product_family || advisory.product_family || "Not recorded"],
      ["Model", asset.model || "Not recorded"],
      ["Firmware / version", asset.firmware_version || "Not recorded"],
      ["Enabled features", listText(asset.enabled_features)],
      ["Disabled features", listText(asset.disabled_features)],
      ["Configuration evidence", listText(asset.config_evidence_refs)],
      ["Review state", humanize(asset.review_state || "pending_review")]
    ]),
    heading("Affected Feature Assessment", HeadingLevel.HEADING_2),
    ...keyValueBlocks([
      ["Affected feature", humanize(assessment.affected_feature || listText(advisory.affected_features))],
      ["Affected version status", humanize(assessment.affected_version_status || "not assessed")],
      ["Affected feature status", humanize(assessment.affected_feature_status || "not assessed")],
      ["Feature enabled status", humanize(assessment.feature_enabled_status || "not assessed")]
    ]),
    heading("Exposure Assessment", HeadingLevel.HEADING_2),
    ...keyValueBlocks([
      ["Internet-facing", asset.internet_facing ? "Yes, source-bound pending review unless accepted" : "Not recorded or not reviewed"],
      ["Management exposure", humanize(asset.management_exposure || "unknown")],
      ["Exposure status", humanize(assessment.exposure_status || "not assessed")]
    ]),
    heading("Evidence Required to Prove Not Applicable", HeadingLevel.HEADING_2),
    ...vendorLensGapBlocks(assessment),
    heading("Urgent Patch / Mitigation / Scope Confirmation Recommendation", HeadingLevel.HEADING_2),
    para(decision.recommended_next_action || assessment.decision_not_allowed_yet || "PatchForge cannot issue a final remediation, risk acceptance, closure, or not-applicable decision without reviewed evidence and named human approval."),
    heading("SRA/AIP Chat Summary", HeadingLevel.HEADING_2),
    ...keyValueBlocks([
      ["Session", chat.session_id || "Not attached"],
      ["Short answer", chat.latest_response?.short_answer || "No VendorLens chat summary attached."],
      ["Governed posture", humanize(chat.latest_response?.current_governed_posture || assessment.urgency_posture || "not assessed")],
      ["Decision not allowed yet", chat.latest_response?.decision_not_allowed_yet || assessment.decision_not_allowed_yet || "Human review remains required."]
    ])
  ];
}

function vendorLensGapBlocks(assessment = {}) {
  const gaps = Array.isArray(assessment.evidence_gaps) && assessment.evidence_gaps.length ? assessment.evidence_gaps : [{
    gap_id: "vendorlens_context",
    plain_english_gap: "VendorLens evidence was not attached to this pack.",
    why_it_matters: "The report cannot prove network vendor applicability without customer asset, version, feature, and source-advisory evidence.",
    required_evidence: "Reviewed vendor advisory, customer network asset inventory, firmware/version evidence, feature configuration evidence, and exposure evidence.",
    suggested_owner_role: "Network engineering lead",
    next_decision_gate: "Configuration applicability review"
  }];
  return gaps.slice(0, 8).flatMap((gap) => detailBlock(humanize(gap.gap_id || gap.plain_english_gap), [
    ["Plain English gap", gap.plain_english_gap || "Evidence gap"],
    ["Why it matters", gap.why_it_matters || "PatchForge cannot support the decision without reviewed evidence."],
    ["Required evidence", gap.required_evidence || "Reviewed evidence required"],
    ["Suggested owner", gap.suggested_owner_role || "Network engineering lead"],
    ["Next decision gate", gap.next_decision_gate || "Configuration applicability review"]
  ]));
}

function patchComparisonDocxSections(context) {
  const comparison = context.vendorLensPatchComparison || {};
  const hasComparison = Boolean(context.vendorLensPatchComparison && context.vendorLensPatchComparison.available !== false);
  return [
    heading("Patch Version Comparison for CISO Review", HeadingLevel.HEADING_1),
    para(hasComparison
      ? "This section compares the recorded device firmware or patch level with the source-bound remediating version. It is prepared for CISO/CAB review and does not deploy or approve a patch."
      : "Patch version comparison was not attached to this signed pack."),
    ...keyValueBlocks([
      ["Vendor", comparison.vendor_name || comparison.vendor_id || "Not attached"],
      ["Asset", comparison.asset_id || "Not attached"],
      ["Advisory / CVE", comparison.cve || comparison.advisory_id || "Not attached"],
      ["Current version", comparison.current_version || "Not recorded"],
      ["Target / fixed version", comparison.target_version || listText(comparison.fixed_versions)],
      ["Current version status", humanize(comparison.current_version_status || "not assessed")],
      ["Target version status", humanize(comparison.target_version_status || "not assessed")],
      ["Final approval", comparison.final_approval_issued ? "Issued" : "Not issued"]
    ]),
    heading("Security Delta", HeadingLevel.HEADING_2),
    para(comparison.security_delta || "Reviewed release-note evidence is required before PatchForge can state the exact security changes introduced by the target version."),
    heading("Operational Delta and Evidence Required", HeadingLevel.HEADING_2),
    ...bulletList([
      ...(Array.isArray(comparison.operational_delta) ? comparison.operational_delta : []),
      ...(Array.isArray(comparison.evidence_required) ? comparison.evidence_required.map((item) => `Evidence required: ${item}`) : [])
    ].slice(0, 12)),
    heading("CISO Summary", HeadingLevel.HEADING_2),
    para(comparison.ciso_summary || "No CISO version-comparison summary is available because the comparison artefact was not attached.")
  ];
}

async function buildPdfReport(context) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "LETTER", margin: 54, compress: false, info: { Title: context.title, Author: "DIIaC PatchForge" } });
    const chunks = [];
    doc.on("data", (chunk) => chunks.push(chunk));
    doc.on("error", reject);
    doc.on("end", () => resolve(Buffer.concat(chunks)));

    pdfTitle(doc, context);
    pdfSection(doc, "Report Version Stamp");
    pdfKeyValues(doc, reportVersionRows(context));
    pdfSection(doc, "Executive Decision Summary");
    pdfParagraph(doc, context.executiveReadout || `${context.vulnerabilityId} is currently governed as ${humanize(context.decisionPosture)}. Final approval remains human-controlled.`);
    pdfParagraph(doc, finalApprovalSentence(context));
    pdfKeyValues(doc, [
      ["Recommended posture", displayPosture(context)],
      ["Next best action", context.recommendation?.next_best_action || "Review evidence and compile the signed decision pack."],
      ["Confidence", humanize(context.recommendation?.confidence || "not recorded")],
      ["Human approval", context.finalApprovalIssued ? "Recorded" : "Still required"]
    ]);
    pdfCustomerSections(doc, context);
    pdfSection(doc, "What This Vulnerability Means");
    pdfParagraph(doc, context.plainEnglish || `${context.vulnerabilityTitle} is a source-bound vulnerability decision. PatchForge translates it into governed options, evidence gaps, and accountable human actions.`);
    pdfSection(doc, "Why It Matters Now");
    pdfParagraph(doc, context.whyNow || "Urgency depends on reviewed source, exposure, and service-impact evidence.");
    pdfSection(doc, "Affected Scope");
    pdfParagraph(doc, context.whatItAffects || "Affected asset and service scope is not fully mapped in the signed pack.");
    pdfSection(doc, "Exploitability Intelligence");
    pdfCallout(doc, context.exploitability?.prohibited_detail || "Exploit code, exploit payloads, and procedural exploitation steps are intentionally not provided.");
    pdfParagraph(doc, context.exploitability?.safe_description || "Exploitability signals inform prioritisation only and do not close evidence gates.");
    pdfParagraph(doc, context.exploitability?.kev_epss_interpretation || "KEV and EPSS are prioritisation signals only. They do not prove tenant exposure and cannot close hard gates without reviewed customer asset and service evidence.");
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
      pdfBullet(doc, `${option.recommended ? "Recommended: " : ""}${humanize(option.posture)} - Status: ${humanize(option.current_status || "available")}. Reason: ${option.reason || option.when_to_choose}. Required evidence: ${(option.required_evidence || option.evidence_needed || []).join(", ") || "reviewed evidence"}. Approval: ${option.required_approval || (option.approval_needed ? "required" : "not required at this stage")}.`);
    }
    pdfSection(doc, "Evidence Confidence and Gaps");
    for (const detail of (context.evidenceGapDetails?.length ? context.evidenceGapDetails : context.blockers.map(gapDetailForReport)).slice(0, 8)) {
      pdfBullet(doc, `${humanize(detail.gap)} - Why it matters: ${detail.why_it_matters} Required evidence: ${detail.required_evidence} Owner/gate: ${detail.suggested_owner_role}; ${detail.next_decision_gate}.`);
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
    pdfVendorLensSections(doc, context);
    pdfPatchComparisonSections(doc, context);
    pdfSection(doc, "Blockers and Next Actions");
    for (const blocker of (context.evidenceGapDetails?.length ? context.evidenceGapDetails : (context.blockers.length ? context.blockers : ["Human review required"]))) {
      const detail = typeof blocker === "string" ? gapDetailForReport(blocker) : blocker;
      pdfBullet(doc, `${humanize(detail.gap || blocker)}: ${detail.required_evidence || actionForBlocker(detail.gap || blocker)}`);
    }
    pdfSection(doc, "Automated Governance Analysis Completed");
    pdfCallout(doc, context.humanApprovalNotice);
    for (const item of (context.automation?.completed || ["Source-bound finding normalised", "Governance boundary applied"]).slice(0, 8)) {
      pdfBullet(doc, item);
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
  pdfCallout(doc, `Generated ${formatDate(context.generatedAt)}. Governed posture: ${displayPosture(context)}. Readiness: ${humanize(context.readinessState)}.`);
}

function pdfCustomerSections(doc, context) {
  if (context.reportType !== "customer_patch_governance_pack") {
    return;
  }
  const customerScopeConfirmed = Boolean(context.exposure && !context.exposure.unmapped_scope && context.exposure.affected_service_count > 0);
  const patchApplicabilityReviewed = ["patch_available", "patch_feasible", "mitigation_only", "no_patch_available"].includes(String(context.patchStatus || "").toLowerCase());
  pdfSection(doc, "Customer Assurance Position");
  pdfCallout(doc, customerScopeConfirmed && patchApplicabilityReviewed
    ? "Customer remediation assurance can be prepared only for the reviewed services and evidence references listed in this pack."
    : NO_CUSTOMER_ASSURANCE_TEXT);
  pdfSection(doc, "Customer Impact Status");
  pdfParagraph(doc, customerScopeConfirmed ? "Reviewed customer-facing service scope is present. Confirm the listed service owner, SLA/OLA impact, and communication owner before issuing customer-facing assurance." : `${UNCONFIRMED_SCOPE_TEXT} Customer impact must be treated as unconfirmed.`);
  pdfSection(doc, "Customer Evidence Required");
  for (const detail of (context.evidenceGapDetails?.length ? context.evidenceGapDetails : context.blockers.map(gapDetailForReport)).slice(0, 6)) {
    pdfBullet(doc, `${humanize(detail.gap)} - Required evidence: ${detail.required_evidence}. Owner: ${detail.suggested_owner_role}.`);
  }
  pdfSection(doc, "Customer Communication Position");
  pdfParagraph(doc, customerScopeConfirmed ? "Customer communication can describe reviewed source-bound risk, affected services, current blockers, and the accountable decision timeline." : "Customer communication should be limited to source-bound public-intelligence awareness and the active scope-confirmation work. Do not state that the customer estate is affected or remediated until reviewed exposure and patch applicability evidence exists.");
  pdfSection(doc, "What Can Be Shared With Customer");
  pdfBullet(doc, "PatchForge has recorded a source-bound vulnerability governance case.");
  pdfBullet(doc, "Known-exploited and EPSS-style signals are prioritisation inputs, not proof of tenant exposure.");
  pdfSection(doc, "What Cannot Yet Be Claimed");
  pdfBullet(doc, "Do not claim customer exposure, patch applicability, successful remediation, closure, certification, or risk acceptance unless reviewed evidence records those facts.");
  pdfBullet(doc, "Do not imply PatchForge deployed a patch or approved the decision autonomously.");
}

function pdfVendorLensSections(doc, context) {
  const assessment = context.configApplicability || {};
  const asset = context.customerNetworkAsset || {};
  const advisory = context.vendorSecurityAdvisory || {};
  const chat = context.sraConfigChat || {};
  pdfSection(doc, "Network Vendor Applicability");
  pdfParagraph(doc, context.configApplicability
    ? "VendorLens context is attached as source-bound advisory intelligence. It does not verify customer configuration or approve a decision by itself."
    : "VendorLens network vendor applicability context was not attached to this signed pack.");
  pdfKeyValues(doc, [
    ["Vendor", context.networkVendor?.vendor_name || advisory.vendor_name || assessment.vendor_id || "Not attached"],
    ["Advisory / CVE", advisory.cve || assessment.cve || advisory.advisory_id || "Not attached"],
    ["Applicability posture", humanize(assessment.applicability_posture || "not assessed")],
    ["Urgency posture", humanize(assessment.urgency_posture || "not assessed")],
    ["Final approval", assessment.final_approval_issued ? "Issued" : "Not issued"]
  ]);
  pdfSection(doc, "Customer Configuration Context");
  pdfKeyValues(doc, [
    ["Asset", asset.asset_id || "Not attached"],
    ["Product family", asset.product_family || advisory.product_family || "Not recorded"],
    ["Model", asset.model || "Not recorded"],
    ["Firmware / version", asset.firmware_version || "Not recorded"],
    ["Enabled features", listText(asset.enabled_features)],
    ["Disabled features", listText(asset.disabled_features)]
  ]);
  pdfSection(doc, "Affected Feature Assessment");
  pdfKeyValues(doc, [
    ["Affected feature", humanize(assessment.affected_feature || listText(advisory.affected_features))],
    ["Affected version status", humanize(assessment.affected_version_status || "not assessed")],
    ["Feature enabled status", humanize(assessment.feature_enabled_status || "not assessed")],
    ["Exposure status", humanize(assessment.exposure_status || "not assessed")]
  ]);
  pdfSection(doc, "Evidence Required to Prove Not Applicable");
  const gaps = Array.isArray(assessment.evidence_gaps) && assessment.evidence_gaps.length ? assessment.evidence_gaps : [{
    plain_english_gap: "VendorLens evidence was not attached to this pack.",
    required_evidence: "Reviewed vendor advisory, customer network asset inventory, firmware/version evidence, feature configuration evidence, and exposure evidence.",
    suggested_owner_role: "Network engineering lead"
  }];
  for (const gap of gaps.slice(0, 6)) {
    pdfBullet(doc, `${gap.plain_english_gap || gap.gap_id}: ${gap.required_evidence || "Reviewed evidence required"} Owner: ${gap.suggested_owner_role || "Network engineering lead"}.`);
  }
  pdfSection(doc, "Urgent Patch / Mitigation / Scope Confirmation Recommendation");
  pdfParagraph(doc, context.vendorLensDecisionContext?.recommended_next_action || assessment.decision_not_allowed_yet || "Final decision requires reviewed evidence and named human approval.");
  pdfSection(doc, "SRA/AIP Chat Summary");
  pdfKeyValues(doc, [
    ["Session", chat.session_id || "Not attached"],
    ["Short answer", chat.latest_response?.short_answer || "No VendorLens chat summary attached."],
    ["Governed posture", humanize(chat.latest_response?.current_governed_posture || assessment.urgency_posture || "not assessed")],
    ["Decision not allowed yet", chat.latest_response?.decision_not_allowed_yet || assessment.decision_not_allowed_yet || "Human review remains required."]
  ]);
}

function pdfPatchComparisonSections(doc, context) {
  const comparison = context.vendorLensPatchComparison || {};
  pdfSection(doc, "Patch Version Comparison for CISO Review");
  pdfParagraph(doc, context.vendorLensPatchComparison
    ? "This comparison shows the recorded running version against the target or fixed version for CISO/CAB review. It does not deploy or approve a patch."
    : "Patch version comparison was not attached to this signed pack.");
  pdfKeyValues(doc, [
    ["Vendor", comparison.vendor_name || comparison.vendor_id || "Not attached"],
    ["Asset", comparison.asset_id || "Not attached"],
    ["Advisory / CVE", comparison.cve || comparison.advisory_id || "Not attached"],
    ["Current version", comparison.current_version || "Not recorded"],
    ["Target / fixed version", comparison.target_version || listText(comparison.fixed_versions)],
    ["Current version status", humanize(comparison.current_version_status || "not assessed")],
    ["Target version status", humanize(comparison.target_version_status || "not assessed")],
    ["Final approval", comparison.final_approval_issued ? "Issued" : "Not issued"]
  ]);
  pdfSection(doc, "Security Delta");
  pdfParagraph(doc, comparison.security_delta || "Reviewed release-note evidence is required before PatchForge can state the exact security changes introduced by the target version.");
  pdfSection(doc, "Operational Delta and Evidence Required");
  for (const item of [
    ...(Array.isArray(comparison.operational_delta) ? comparison.operational_delta : []),
    ...(Array.isArray(comparison.evidence_required) ? comparison.evidence_required.map((value) => `Evidence required: ${value}`) : [])
  ].slice(0, 10)) {
    pdfBullet(doc, item);
  }
  pdfSection(doc, "CISO Summary");
  pdfParagraph(doc, comparison.ciso_summary || "No CISO version-comparison summary is available because the comparison artefact was not attached.");
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
  doc.fillColor(`#${COLORS.teal}`).font("Helvetica-Bold").fontSize(9).text("-", doc.page.margins.left, y, { width: 12 });
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

function displayPosture(context) {
  return safeText(context.recommendation?.customer_posture || humanize(context.recommendation?.posture || context.decisionPosture));
}

function gapDetailForReport(gap) {
  const normalized = String(gap || "").toLowerCase();
  if (normalized.includes("vulnerability") || normalized.includes("identity")) {
    return {
      gap,
      why_it_matters: "CAB and customer assurance need confidence that the CVE, product, affected versions, and source provenance are correct.",
      required_evidence: "Reviewed CISA/CVE/vendor advisory record confirming CVE, product, affected versions, and source provenance.",
      evidence_examples: ["CISA KEV record", "NVD/CVE record", "vendor advisory", "source review event"],
      suggested_owner_role: "Security lead or vulnerability manager",
      next_decision_gate: "Source identity review"
    };
  }
  if (normalized.includes("asset")) {
    return {
      gap,
      why_it_matters: "Without asset scope, the organisation cannot tell whether the public-source finding affects the customer estate.",
      required_evidence: "CMDB, hosting control panel inventory, scanner output, asset owner confirmation.",
      evidence_examples: ["CMDB asset record", "hosting control panel inventory", "scanner output", "asset owner confirmation"],
      suggested_owner_role: "Asset owner or infrastructure lead",
      next_decision_gate: "Asset exposure confirmation"
    };
  }
  if (normalized.includes("service")) {
    return {
      gap,
      why_it_matters: "Severity alone does not identify the affected customer journey, SLA/OLA, service owner, or communication need.",
      required_evidence: "Service map, customer-facing flag, SLA/OLA impact, service owner.",
      evidence_examples: ["service catalogue map", "customer-facing flag", "SLA/OLA record", "service owner confirmation"],
      suggested_owner_role: "Service owner",
      next_decision_gate: "Business impact review"
    };
  }
  if (normalized.includes("patch")) {
    return {
      gap,
      why_it_matters: "Patch, mitigation, deferral, or customer assurance cannot be selected confidently until affected versions, testing, rollback, and applicability are known.",
      required_evidence: "Vendor patch note, affected version mapping, test evidence, rollback plan.",
      evidence_examples: ["vendor patch note", "affected version mapping", "test evidence", "rollback plan"],
      suggested_owner_role: "Change owner or platform engineer",
      next_decision_gate: "Patch feasibility review"
    };
  }
  if (normalized.includes("human")) {
    return {
      gap,
      why_it_matters: "Source-bound intelligence cannot become accepted positive evidence without a named reviewer decision.",
      required_evidence: "Named reviewer decision accepting or rejecting source records.",
      evidence_examples: ["source review event", "reviewer name or role", "review outcome", "review notes"],
      suggested_owner_role: "Security lead or CAB reviewer",
      next_decision_gate: "Human evidence review"
    };
  }
  return {
    gap,
    why_it_matters: "The decision gate remains open until reviewed evidence is attached and accepted.",
    required_evidence: actionForBlocker(gap),
    evidence_examples: ["accepted evidence record", "review note", "owner confirmation"],
    suggested_owner_role: "Accountable evidence owner",
    next_decision_gate: "Evidence review"
  };
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
  return "Attach reviewed evidence specific to this blocker and record the accountable owner before requesting approval.";
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

function listText(value) {
  if (Array.isArray(value)) {
    return value.length ? value.join(", ") : "Not recorded";
  }
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

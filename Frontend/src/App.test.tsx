import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import { FindingEvidenceQueue, FindingIntelligence, PatchForgeApi, PatchForgeMetrics } from "./api";
import { PatchForgeAuthSession } from "./auth";

const metrics: PatchForgeMetrics = {
  tenant_id: "diiac.io",
  vulnerability_count: 1,
  critical_exposure: 1,
  known_exploited: 1,
  patch_overdue: 0,
  pending_review: 1,
  accepted_positive_evidence_sources: 0,
  rejected_sources: 0,
  signed_packs: 1
};

const auth: PatchForgeAuthSession = {
  status: "authenticated",
  accountName: "n.bailey@diiac.io",
  roles: ["PatchForge.Admin"],
  signIn: vi.fn(async () => undefined),
  signOut: vi.fn(async () => undefined),
  getAccessToken: vi.fn(async () => "test-token")
};

const finding = {
  intelligence_id: "intel-CVE-2026-REAL-001",
  generated_at: "2026-05-30T08:00:00Z",
  vulnerability_id: "CVE-2026-REAL-001",
  title: "FortiOS SSL-VPN source-bound advisory",
  severity: "critical",
  vendor: "Fortinet",
  product: "FortiGate",
  summary: {
    plain_english: "PatchForge treats this as governed advisory work.",
    why_now: "Known exploited signal is present.",
    what_it_affects: "Customer estate scope is pending review.",
    operational_risk: "Customer-facing impact is not confirmed.",
    decision_required: "Human approval remains required.",
    executive_readout: "Urgent scope confirmation is required."
  },
  exploitability: {
    known_exploited: true,
    epss_score: 0.91,
    epss_percentile: 0.98,
    ransomware_use: "Unknown",
    safe_description: "Source-bound intelligence only.",
    prohibited_detail: "Procedural exploitation steps are intentionally not provided."
  },
  exposure: {
    affected_service_count: 0,
    affected_asset_count: 1,
    internet_exposed: false,
    customer_facing: false,
    ot_relevant: false,
    unmapped_scope: false,
    interpretation: ["Customer estate match requires review."],
    affected_services: [],
    affected_assets: []
  },
  recommendation: {
    posture: "urgent_scope_confirmation_required",
    next_best_action: "Attach reviewed customer, feature, version, and patch evidence.",
    confidence: "medium",
    rationale: ["Evidence gaps remain."],
    do_now: ["Review customer scope."],
    do_next: ["Request human approval."],
    advisory_only: true,
    final_approval_issued: false,
    customer_posture: "Urgent scope confirmation required",
    display_posture: "urgent_scope_confirmation_required"
  },
  decision_options: [],
  evidence: {
    accepted_positive_evidence_count: 0,
    pending_review_count: 1,
    rejected_source_count: 0,
    gaps: ["Reviewed feature state"],
    warning: "Source and customer evidence remain pending review."
  },
  automation: {
    completed: [],
    remaining_human_decisions: ["Issue or withhold final approval."],
    available_actions: ["Generate signed pack"]
  },
  latest_signed_pack: null,
  boundary: {
    advisory_only: true,
    no_exploit_code: true,
    no_patch_deployment: true
  }
} as FindingIntelligence;

const securityActionCenterState = {
  tenant_id: "diiac.io",
  generated_at: "2026-05-30T08:00:00Z",
  catalogue_rows: [{
    id: "FG-PFAZ10-SSLVPN",
    record_type: "vendor_advisory",
    vulnerability_id: "CVE-2026-REAL-001",
    cve_id: "CVE-2026-REAL-001",
    advisory_id: "FG-PFAZ10-SSLVPN",
    title: "FortiOS SSL-VPN source-bound advisory",
    vendor_id: "fortinet",
    vendor_name: "Fortinet",
    product_family: "FortiGate",
    affected_feature: "SSL-VPN",
    severity: "critical",
    cvss_score: 9.8,
    epss_score: 0.91,
    epss_percentile: 0.98,
    kev: true,
    patch_available: true,
    known_exploited: true,
    source_state: "source_bound",
    review_state: "pending_review",
    customer_match_count: 1,
    urgency_posture: "urgent_scope_confirmation_required",
    applicability_posture: "requires_review",
    final_approval_issued: false,
    last_refreshed: "2026-05-30T08:00:00Z"
  }],
  groups: [{
    vendor_id: "fortinet",
    vendor_name: "Fortinet",
    count: 1,
    customer_match_count: 1,
    known_exploited_count: 1,
    highest_urgency: "urgent_scope_confirmation_required",
    product_families: [{
      product_family: "FortiGate",
      count: 1,
      customer_match_count: 1,
      items: []
    }]
  }],
  vendors: [{ vendor_id: "fortinet", vendor_name: "Fortinet" }],
  filters: {
    vendors: [{ value: "Fortinet", count: 1 }],
    severities: [{ value: "critical", count: 1 }]
  },
  source_feed_status: [],
  summary: {
    total_records: 1,
    critical_records: 1,
    known_exploited_records: 1,
    kev_records: 1,
    patch_available_records: 1,
    customer_match_records: 1,
    final_approval_issued: 0
  },
  boundary: { advisory_only: true, final_approval_issued: false }
};

const asset = {
  asset_id: "net-asset-1",
  tenant_id: "diiac.io",
  customer: "DIIaC",
  site: "London",
  vendor_id: "fortinet",
  vendor_name: "Fortinet",
  product_family: "FortiGate",
  model: "100F",
  firmware_version: "7.2.7",
  internet_facing: false,
  management_exposure: "internal",
  enabled_features: ["ipsec_vpn"],
  disabled_features: ["ssl_vpn"],
  config_evidence_refs: [],
  review_state: "pending_review",
  evidence_state: "user_stated_unreviewed"
};

const advisory = {
  advisory_id: "FG-PFAZ10-SSLVPN",
  vendor_id: "fortinet",
  vendor_name: "Fortinet",
  cve: "CVE-2026-REAL-001",
  title: "FortiOS SSL-VPN source-bound advisory",
  severity: "critical",
  product_family: "FortiGate",
  affected_versions: ["< 7.2.8"],
  fixed_versions: ["7.2.8"],
  affected_features: ["ssl_vpn"],
  known_exploited: true,
  patch_available: true,
  review_state: "pending_review",
  evidence_state: "referenced"
};

const match = {
  assessment_id: "cfg-app-1",
  advisory_id: "FG-PFAZ10-SSLVPN",
  asset_id: "net-asset-1",
  cve: "CVE-2026-REAL-001",
  vendor_id: "fortinet",
  product_family: "FortiGate",
  model: "100F",
  firmware_version: "7.2.7",
  affected_feature: "ssl_vpn",
  affected_version_status: "affected",
  feature_enabled_status: "disabled_unreviewed",
  exposure_status: "internal_management",
  applicability_posture: "requires_review",
  urgency_posture: "urgent_scope_confirmation_required",
  evidence_required: ["Reviewed vendor advisory", "Reviewed feature configuration"],
  evidence_gaps: [],
  human_review_required: true,
  final_approval_issued: false
};

const comparison = {
  comparison_id: "vl-compare-1",
  vendor_id: "fortinet",
  vendor_name: "Fortinet",
  asset_id: "net-asset-1",
  advisory_id: "FG-PFAZ10-SSLVPN",
  cve: "CVE-2026-REAL-001",
  product_family: "FortiGate",
  model: "100F",
  current_version: "7.2.7",
  target_version: "7.2.8",
  proposed_version: "7.2.8",
  fixed_versions: ["7.2.8"],
  affected_versions: ["< 7.2.8"],
  affected_features: ["ssl_vpn"],
  current_version_status: "current_version_potentially_affected",
  target_version_status: "target_version_recorded_as_fixed_pending_review",
  current_version_affected: "affected",
  proposed_version_remediates: "unknown",
  evidence_needed: ["Reviewed vendor advisory and release notes"],
  recommended_posture: "review_fixed_version_evidence",
  required_human_review: true,
  security_delta: "The proposed version is recorded as fixed pending review.",
  operational_delta: ["Confirm rollback support."],
  evidence_required: ["Reviewed vendor advisory and release notes"],
  ciso_summary: "Final approval has not been issued.",
  human_review_required: true,
  advisory_only: true,
  final_approval_issued: false
};

const discoveryOverview = {
  tenant_id: "diiac.io",
  generated_at: "2026-06-11T19:30:00Z",
  categories: ["network_device", "security_appliance", "physical_server", "virtual_server", "hypervisor"],
  collectors: [{
    collector_id: "collector-customer-estate-mvp",
    name: "Customer estate collector MVP",
    platform: "windows",
    site: "Primary site",
    enabled_categories: ["network_device", "security_appliance"],
    connection_mode: "outbound_only",
    status: "registered",
    last_seen_at: null,
    advisory_only: true,
    review_required: true,
    no_vulnerability_scanning: true,
    no_patch_deployment: true,
    final_approval_issued: false
  }],
  policies: [{
    policy_id: "policy-customer-estate-mvp",
    collector_id: "collector-customer-estate-mvp",
    name: "Read-only customer estate snapshot",
    enabled: true,
    categories: ["network_device", "security_appliance"],
    discovery_methods: ["manual_snapshot"],
    schedule: "manual",
    credential_reference: "customer-vault:patchforge/read-only-discovery",
    read_only: true,
    outbound_only: true,
    advisory_only: true,
    review_required: true,
    final_approval_issued: false
  }],
  recent_runs: [{
    run_id: "run-customer-estate-mvp",
    collector_id: "collector-customer-estate-mvp",
    policy_id: "policy-customer-estate-mvp",
    status: "completed",
    completed_at: "2026-06-11T19:31:00Z",
    received_asset_count: 1,
    imported_asset_count: 1,
    rejected_asset_count: 0,
    categories: ["security_appliance"],
    discovery_method: "manual_snapshot",
    final_approval_issued: false
  }],
  metrics: {
    collector_count: 1,
    enabled_policy_count: 1,
    collector_imported_asset_count: 1,
    pending_review_asset_count: 1,
    last_import_at: "2026-06-11T19:31:00Z"
  },
  boundary: {
    advisory_only: true,
    outbound_collector_only: true,
    no_vulnerability_scanning: true,
    no_patch_deployment: true,
    final_approval_issued: false
  }
};

const findingEvidenceQueue: FindingEvidenceQueue = {
  tenant_id: "diiac.io",
  vulnerability_id: "CVE-2026-REAL-001",
  supported_evidence_classes: ["affected_asset_scope", "human_review_signoff"],
  evidence: [{
    tenant_id: "diiac.io",
    evidence_id: "evidence-pending-1",
    vulnerability_id: "CVE-2026-REAL-001",
    evidence_class: "affected_asset_scope",
    summary: "Customer asset scope confirmed",
    source_refs: ["CHG-1001"],
    content_hash: "sha256:pending-content",
    finding_revision_hash: "sha256:finding-revision",
    latest_event_hash: "sha256:submitted-event",
    event_count: 1,
    replay_verified: true,
    expired: false,
    expiry_evaluated_at: "2026-07-14T10:00:00Z",
    review_state: "pending_review",
    evidence_state: "pending_review",
    final_approval_issued: false
  }, {
    tenant_id: "diiac.io",
    evidence_id: "evidence-expired-1",
    vulnerability_id: "CVE-2026-REAL-001",
    evidence_class: "affected_asset_scope",
    summary: "Expired customer configuration snapshot",
    content_hash: "sha256:expired-content",
    finding_revision_hash: "sha256:finding-revision",
    latest_event_hash: "sha256:rejected-event",
    event_count: 2,
    replay_verified: true,
    expires_at: "2026-07-01T10:00:00Z",
    expired: true,
    expiry_evaluated_at: "2026-07-14T10:00:00Z",
    review_state: "rejected",
    evidence_state: "rejected",
    final_approval_issued: false
  }],
  evidence_events: [],
  audit_replay: [],
  boundary: { final_approval_issued: false }
};

function createApi(overrides: Partial<PatchForgeApi> = {}): PatchForgeApi {
  const base: PatchForgeApi = {
    metrics: vi.fn(async () => metrics),
    securityActionCenter: vi.fn(async () => securityActionCenterState),
    searchSecurityActionCenter: vi.fn(async () => securityActionCenterState),
    securityActionCenterVendors: vi.fn(async () => [{ vendor_id: "fortinet", vendor_name: "Fortinet" }]),
    cveDetail: vi.fn(async () => ({ cve: securityActionCenterState.catalogue_rows[0] })),
    customerEstate: vi.fn(async () => ({
      assets: [asset],
      services: [],
      exposure_matches: [match],
      patch_comparisons: []
    })),
    extractCustomerAsset: vi.fn(async () => ({
      ...asset,
      extraction_confidence: 1,
      extracted_from: "FortiGate 100F running FortiOS 7.2.7. SSL-VPN disabled. IPsec enabled. Management internal only.",
      final_approval_issued: false,
      human_review_required: true
    })),
    upsertCustomerEstateAsset: vi.fn(async (_tenantId, payload) => ({ ...asset, ...payload, asset_id: String(payload.asset_id || asset.asset_id) })),
    matchCustomerEstate: vi.fn(async () => ({
      asset,
      matches: [match],
      match_count: 1,
      highest_urgency: "urgent_scope_confirmation_required",
      final_approval_issued: false,
      human_review_required: true
    })),
    compareCustomerEstatePatch: vi.fn(async () => comparison),
    askPatchForge: vi.fn(async () => ({
      response: {
        short_answer: "PatchForge cannot confirm not-applicable status until reviewed evidence is attached.",
        current_governed_posture: "urgent_scope_confirmation_required",
        why: "Customer feature, source, version, and patch evidence are not fully reviewed.",
        what_we_know: ["Vendor/product: Fortinet FortiGate 100F", "Version: 7.2.7"],
        what_we_do_not_know: ["Reviewed feature configuration is missing."],
        evidence_needed: ["Reviewed vendor advisory", "Reviewed feature configuration", "Human approval event"],
        recommended_next_action: "Confirm customer exposure, affected feature state, firmware/version, and vendor advisory source review.",
        decision_not_allowed_yet: "PatchForge cannot issue final approval, risk acceptance, closure, or not-applicable status without reviewed evidence and named human approval.",
        human_approval_required: true,
        final_approval_issued: false,
        advisory_only: true
      },
      asset,
      matched_assessment: match,
      candidate_matches: [match],
      final_approval_issued: false
    })),
    openAiAgentStatus: vi.fn(async () => ({
      enabled: false,
      configured: false,
      provider: "openai",
      model: "gpt-4o-mini",
      timeout_ms: 15000,
      max_output_tokens: 1000,
      verifier_required: true,
      advisory_only: true,
      final_approval_issued: false,
      can_close_hard_gates: false,
      can_approve: false,
      can_patch: false,
      can_accept_risk: false
    })),
    askOpenAiAgent: vi.fn(async () => ({
      snapshot_id: "agent-test",
      agent_name: "Ask PatchForge Agent",
      status: "disabled" as const,
      verifier_status: "not_run" as const,
      output: null,
      fallback: {
        message: "PatchForge could not use this agent response because it failed governance verification.",
        final_approval_issued: false
      },
      verification_failures: [],
      final_approval_issued: false,
      can_close_hard_gates: false
    })),
    reportsPacks: vi.fn(async () => ({
      reports: [{
        report_type: "customer_patch_governance_pack",
        title: "Customer Patch Governance Pack",
        audience: "Customer and account team",
        formats: ["docx", "pdf"]
      }, {
        report_type: "board_vulnerability_remediation_summary",
        title: "Board Vulnerability Summary",
        audience: "Board and senior leadership",
        formats: ["docx", "pdf"]
      }, {
        report_type: "cab_patch_decision_report",
        title: "CAB Patch Decision Report",
        audience: "Change Advisory Board",
        formats: ["docx", "pdf"]
      }, {
        report_type: "technical_evidence_appendix",
        title: "Technical Evidence Appendix",
        audience: "Security engineering and audit",
        formats: ["docx", "pdf"]
      }],
      decision_packs: [{
        decision_pack_id: "PF-TEST-0001",
        pack_id: "PF-TEST-0001",
        vulnerability_id: "CVE-2026-REAL-001",
        decision_posture: "urgent_scope_confirmation_required",
        readiness: { readiness_state: "blocked", final_approval_issued: false },
        verification: { verified: true },
        final_approval_issued: false,
        product_baseline: "PF-AZ11-CUSTOMER-DEMO-MATURITY",
        report_renderer_commit: "test-commit",
        report_renderer_image_tag: "pfaz11-test"
      }],
      export_options: ["Customer Patch Governance Pack", "Board Vulnerability Summary", "CAB Patch Decision Report", "Technical Evidence Appendix", "Signed Decision Pack ZIP", "Verification"],
      pre_export_state: {
        pack_id: "PF-TEST-0001",
        baseline: "PF-AZ11-CUSTOMER-DEMO-MATURITY",
        renderer_commit: "test-commit",
        image_tag: "pfaz11-test",
        evidence_state: "evidence_review_required",
        vendorlens_context_included: true,
        customer_context_included: true,
        verification_state: "verified",
        final_approval_issued: false,
        report_quality_reviews: [{
          review_id: "report-review-customer",
          report_type: "customer_patch_governance_pack",
          pack_id: "PF-TEST-0001",
          status: "PASS" as const,
          checks: [{ name: "known_explained", status: "pass" as const }],
          final_approval_issued: false
        }, {
          review_id: "report-review-board",
          report_type: "board_vulnerability_remediation_summary",
          pack_id: "PF-TEST-0001",
          status: "PASS" as const,
          checks: [{ name: "audience_specific", status: "pass" as const }],
          final_approval_issued: false
        }, {
          review_id: "report-review-cab",
          report_type: "cab_patch_decision_report",
          pack_id: "PF-TEST-0001",
          status: "PASS" as const,
          checks: [{ name: "required_evidence", status: "pass" as const }],
          final_approval_issued: false
        }, {
          review_id: "report-review-technical",
          report_type: "technical_evidence_appendix",
          pack_id: "PF-TEST-0001",
          status: "PASS" as const,
          checks: [{ name: "metadata_present", status: "pass" as const }],
          final_approval_issued: false
        }]
      }
    })),
    generateReportsPack: vi.fn(async () => ({
      decision_pack_id: "PF-TEST-0002",
      pack_id: "PF-TEST-0002",
      vulnerability_id: "CVE-2026-REAL-001",
      final_approval_issued: false,
      verification: { verified: true }
    })),
    listVulnerabilities: vi.fn(async () => [{
      tenant_id: "diiac.io",
      vulnerability_id: "CVE-2026-REAL-001",
      severity: "critical",
      patch_status: "patch_available",
      known_exploited: true,
      vendor_id: "fortinet",
      vendor_name: "Fortinet",
      product_family: "FortiGate"
    }]),
    ingestVulnerability: vi.fn(async (_tenantId, payload) => ({ tenant_id: "diiac.io", vulnerability_id: String(payload.vulnerability_id) })),
    listAssets: vi.fn(async () => []),
    listServices: vi.fn(async () => []),
    listDecisionPacks: vi.fn(async () => [{
      decision_pack_id: "PF-TEST-0001",
      pack_id: "PF-TEST-0001",
      vulnerability_id: "CVE-2026-REAL-001",
      final_approval_issued: false,
      verification: { verified: true },
      product_baseline: "PF-AZ11-CUSTOMER-DEMO-MATURITY",
      report_renderer_commit: "test-commit",
      report_renderer_image_tag: "pfaz11-test"
    }]),
    generateDecisionPack: vi.fn(async () => ({
      decision_pack_id: "PF-TEST-0001",
      pack_id: "PF-TEST-0001",
      vulnerability_id: "CVE-2026-REAL-001",
      verification: { verified: true },
      final_approval_issued: false
    })),
    exportDecisionPack: vi.fn(async () => ({ pack_id: "PF-TEST-0001", source_pack_immutable: true })),
    reportCatalog: vi.fn(async () => [{
      report_type: "customer_patch_governance_pack",
      title: "Customer Patch Governance Pack",
      audience: "Customer and account team",
      formats: ["docx", "pdf"]
    }, {
      report_type: "board_vulnerability_remediation_summary",
      title: "Board Vulnerability Summary",
      audience: "Board and senior leadership",
      formats: ["docx", "pdf"]
    }, {
      report_type: "cab_patch_decision_report",
      title: "CAB Patch Decision Report",
      audience: "Change Advisory Board",
      formats: ["docx", "pdf"]
    }, {
      report_type: "technical_evidence_appendix",
      title: "Technical Evidence Appendix",
      audience: "Security engineering and audit",
      formats: ["docx", "pdf"]
    }]),
    downloadDecisionPackReport: vi.fn(async () => new Blob(["report"], { type: "application/pdf" })),
    assessBayesianRisk: vi.fn(async () => ({
      advisory_only: true,
      can_close_hard_gates_alone: false,
      exploit_probability_posterior: 0.8,
      business_impact_posterior: 0.4,
      patch_feasibility_posterior: 0.5,
      change_risk_posterior: 0.3,
      deferral_risk_posterior: 0.7,
      recommended_governance_posture: "urgent_scope_confirmation_required"
    })),
    bayesianPriors: vi.fn(async () => ({ live_prior_update_enabled: false })),
    threatLandscapeSummary: vi.fn(async () => ({
      tenant_id: "diiac.io",
      source_bound: true,
      review_required: true,
      vendor_count: 1,
      metrics: {
        active_exploitation_count: 1,
        critical_open_advisory_count: 1,
        patch_available_rate: 1,
        known_exploited_rate: 1,
        customer_estate_exposure: 1,
        internet_exposed_asset_count: 0,
        ot_relevance: 0,
        patch_maturity: "pending_review",
        vendor_response_timeliness: "source_bound_pending_review",
        superseded_advisory_count: 0,
        false_positive_history: 0,
        open_customer_decision_count: 1
      },
      top_exposed_vendors: []
    })),
    listVendors: vi.fn(async () => [{ vendor_id: "fortinet", vendor_name: "Fortinet", category: "networking", review_state: "reference_catalogue" }]),
    sourceFeeds: vi.fn(async () => ({ feeds: [], recent_runs: [] })),
    refreshSourceFeed: vi.fn(async () => ({
      run_id: "run-cisa-kev-test",
      feed_id: "cisa-kev",
      feed_name: "CISA KEV",
      status: "completed",
      records_seen: 1,
      records_ingested: 1,
      records_enriched: 0,
      message: "Refreshed.",
      completed_at: "2026-05-30T08:00:00Z",
      can_close_hard_gates_alone: false
    })),
    vendorLensDashboard: vi.fn(async () => ({
      vendors_tracked: 1,
      active_advisories: 1,
      known_exploited_vendor_cves: 1,
      customer_estate_matches: 1,
      config_unknown_count: 1,
      emergency_attention_required: 0,
      recent_assessments: [match]
    })),
    listNetworkVendors: vi.fn(async () => [{
      vendor_id: "fortinet",
      vendor_name: "Fortinet",
      vendor_category: "infrastructure_networking",
      advisory_source_type: "public_vendor_advisory",
      advisory_source_url: "https://www.fortiguard.com/psirt",
      product_families: ["FortiGate"],
      source_review_state: "reference_catalogue",
      enabled: true
    }]),
    listCustomerNetworkAssets: vi.fn(async () => [asset]),
    upsertCustomerNetworkAsset: vi.fn(async (_tenantId, payload) => ({ ...asset, ...payload, asset_id: String(payload.asset_id || asset.asset_id) })),
    assetDiscoveryOverview: vi.fn(async () => discoveryOverview),
    registerAssetCollector: vi.fn(async (_tenantId, payload) => ({
      ...discoveryOverview.collectors[0],
      ...payload,
      collector_id: String(payload.collector_id || discoveryOverview.collectors[0].collector_id)
    })),
    upsertAssetDiscoveryPolicy: vi.fn(async (_tenantId, payload) => ({
      ...discoveryOverview.policies[0],
      ...payload,
      policy_id: String(payload.policy_id || discoveryOverview.policies[0].policy_id)
    })),
    importDiscoveredAssets: vi.fn(async () => ({
      run: discoveryOverview.recent_runs[0],
      imported_assets: [{ ...asset, asset_id: "disc-srx4100-edge-1", discovery_source: "patchforge_collector", review_state: "pending_review" }],
      rejected_assets: [],
      boundary: discoveryOverview.boundary
    })),
    listVendorSecurityAdvisories: vi.fn(async () => [advisory]),
    ingestVendorSecurityAdvisory: vi.fn(async (_tenantId, payload) => ({ ...advisory, advisory_id: String(payload.advisory_id || advisory.advisory_id) })),
    refreshVendorLensSource: vi.fn(async () => ({
      run_id: "run-vendorlens-test",
      feed_id: "nvd-cve-2-catalogue",
      feed_name: "NVD CVE 2.0 VendorLens Catalogue",
      status: "completed",
      records_seen: 1,
      records_ingested: 1,
      records_enriched: 0,
      message: "Refreshed.",
      completed_at: "2026-05-30T08:00:00Z",
      can_close_hard_gates_alone: false
    })),
    assessConfigApplicability: vi.fn(async () => match),
    compareVendorLensPatch: vi.fn(async () => comparison),
    startVendorLensChat: vi.fn(async () => ({
      session: {
        session_id: "vl-chat-1",
        advisory_id: advisory.advisory_id,
        asset_id: asset.asset_id,
        assessment_id: match.assessment_id,
        latest_response: {
          short_answer: "Human review remains required.",
          current_governed_posture: "urgent_scope_confirmation_required",
          why: "Evidence is incomplete.",
          evidence_used: [],
          evidence_missing: [],
          configuration_assumptions: [],
          recommended_next_action: "Attach evidence.",
          decision_not_allowed_yet: "Final decision requires reviewed evidence.",
          human_review_required: true,
          final_approval_issued: false
        }
      },
      response: {
        short_answer: "Human review remains required.",
        current_governed_posture: "urgent_scope_confirmation_required",
        why: "Evidence is incomplete.",
        evidence_used: [],
        evidence_missing: [],
        configuration_assumptions: [],
        recommended_next_action: "Attach evidence.",
        decision_not_allowed_yet: "Final decision requires reviewed evidence.",
        human_review_required: true,
        final_approval_issued: false
      }
    })),
    sendVendorLensChatMessage: vi.fn(async () => ({
      session: { session_id: "vl-chat-1" },
      response: {
        short_answer: "Human review remains required.",
        current_governed_posture: "urgent_scope_confirmation_required",
        why: "Evidence is incomplete.",
        evidence_used: [],
        evidence_missing: [],
        configuration_assumptions: [],
        recommended_next_action: "Attach evidence.",
        decision_not_allowed_yet: "Final decision requires reviewed evidence.",
        human_review_required: true,
        final_approval_issued: false
      }
    })),
    actionCenter: vi.fn(async () => [finding]),
    findingIntelligence: vi.fn(async () => finding),
    analyseFinding: vi.fn(async () => ({ intelligence: finding })),
    findingEvidence: vi.fn(async () => findingEvidenceQueue),
    submitFindingEvidence: vi.fn(async (_tenantId, vulnerabilityId, payload) => ({
      ...findingEvidenceQueue.evidence[0],
      evidence_id: "evidence-submitted-2",
      vulnerability_id: vulnerabilityId,
      evidence_class: String(payload.evidence_class || "affected_asset_scope"),
      summary: String(payload.summary || "Submitted evidence")
    })),
    reviewFindingEvidence: vi.fn(async (_tenantId, _vulnerabilityId, _evidenceId, payload) => ({
      ...findingEvidenceQueue.evidence[0],
      review_state: payload.decision === "accept" ? "reviewed" : "rejected",
      evidence_state: payload.decision === "accept" ? "accepted_positive_evidence" : "rejected"
    })),
    reopenFindingEvidence: vi.fn(async () => ({
      ...findingEvidenceQueue.evidence[1],
      review_state: "reopened",
      evidence_state: "pending_review"
    })),
    sraResearch: vi.fn(async () => ({ sra: { advisory_only: true, can_close_evidence_gates_alone: false } })),
    adminHealth: vi.fn(async () => ({
      tenant_id: "diiac.io",
      live_azure_mutation_enabled: false,
      checks: [
        { name: "MCP agent intake", status: "governed", mode: "agent-led-human-approved" },
        { name: "Public source feeds", status: "ready", mode: "cisa-kev / first-epss" },
        { name: "Signing trust", status: "ready", mode: "key-vault" }
      ]
    })),
    adminPurge: vi.fn(async () => ({
      dry_run: true,
      scopes: ["reports"],
      collections: ["decision_packs"],
      counts: { decision_packs: 1 },
      total_records: 1,
      required_confirmation: "FACTORY_RESET_PATCHFORGE"
    })),
    adminConfig: vi.fn(async () => ({
      general: { environment: "Production", governance_tier: "Enterprise Strict" }
    })),
    saveAdminConfig: vi.fn(async (_tenantId, payload) => payload)
  };
  return { ...base, ...overrides };
}

describe("PatchForge simplified customer experience", () => {
  it("renders the six PatchForge top-level areas and the patch catalogue", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    await waitFor(() => expect(api.securityActionCenter).toHaveBeenCalled());

    expect(screen.getByRole("region", { name: "Patch & CVE Catalogue" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Patch & CVE Catalogue" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Vendor Catalogue" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Customer Estate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask PatchForge" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reports" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Admin" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Security Action Center" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Vendors & Exploits Register" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Patch / Hotfix Compare" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "VendorLens" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "What needs attention today?" })).toBeInTheDocument();
    expect(screen.getAllByText("Fortinet").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("CVE-2026-REAL-001").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("heading", { name: "Priority action queue" })).toBeInTheDocument();
    expect(screen.getByText("Urgent Scope Confirmation Required")).toBeInTheDocument();
    expect(screen.getByText("Recommended next step")).toBeInTheDocument();
    expect(screen.getByText("PatchForge prepares the evidence. An accountable human approves the decision.")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /CVE-2026-REAL-001 Fortinet/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("cell", { name: "CVE-2026-REAL-001" })).toHaveAttribute("data-label", "CVE");
    expect(screen.getByRole("button", { name: "Ask PatchForge about selected record" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Needs review" }));
    expect(screen.getByRole("button", { name: "Needs review" })).toHaveAttribute("aria-pressed", "true");
  }, 15000);

  it("routes the global command search into the governed catalogue", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    await screen.findByRole("heading", { name: "What needs attention today?" });
    fireEvent.click(screen.getByRole("button", { name: "Reports" }));
    const commandSearch = screen.getByLabelText("Search PatchForge");
    fireEvent.change(commandSearch, { target: { value: "CVE-2026-REAL-001" } });
    fireEvent.submit(commandSearch.closest("form")!);

    await waitFor(() => expect(api.searchSecurityActionCenter).toHaveBeenCalledWith("diiac.io", expect.objectContaining({ q: "CVE-2026-REAL-001" })));
    expect(screen.getByRole("heading", { name: "What needs attention today?" })).toBeInTheDocument();
  });

  it("prepares a catalogue pack without inheriting an unrelated asset", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Prepare decision pack" }));

    await waitFor(() => expect(api.generateReportsPack).toHaveBeenCalledWith("diiac.io", expect.objectContaining({
      vulnerability_id: "CVE-2026-REAL-001",
      advisory_id: "FG-PFAZ10-SSLVPN",
      asset_id: undefined
    })));
  }, 15000);

  it("never treats unreviewed or rejected evidence as verified", async () => {
    const guardedCatalogue = {
      ...securityActionCenterState,
      catalogue_rows: [{
        ...securityActionCenterState.catalogue_rows[0],
        review_state: "reviewed",
        evidence_state: "rejected"
      }]
    };
    const api = createApi({
      securityActionCenter: vi.fn(async () => guardedCatalogue),
      actionCenter: vi.fn(async () => [])
    });
    render(<App auth={auth} api={api} />);

    expect(await screen.findByRole("cell", { name: "Needs review" })).toBeInTheDocument();
    expect(screen.queryByText("Verified evidence")).not.toBeInTheDocument();
    expect(screen.getByText(/Confidence not recorded/)).toBeInTheDocument();
  }, 15000);

  it("searches the security action center with customer and patch filters", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    await screen.findByRole("region", { name: "Patch & CVE Catalogue" });
    fireEvent.change(screen.getByLabelText("Search"), { target: { value: "SSL-VPN FortiGate 7.2.7" } });
    fireEvent.change(screen.getByLabelText("Customer match"), { target: { value: "true" } });
    fireEvent.change(screen.getByLabelText("Patch available"), { target: { value: "true" } });
    fireEvent.click(screen.getByRole("button", { name: "Search" }));

    await waitFor(() => expect(api.searchSecurityActionCenter).toHaveBeenCalledWith("diiac.io", expect.objectContaining({
      q: "SSL-VPN FortiGate 7.2.7",
      customer_match: "true",
      patch_available: "true"
    })));
  });

  it("registers a real collector path and downloads config without sample imports", async () => {
    const api = createApi();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Customer Estate" }));
    expect(await screen.findByRole("heading", { name: "Collector Intake" }, { timeout: 20000 })).toBeInTheDocument();
    expect(screen.getByText("Outbound-only | review required")).toBeInTheDocument();
    expect(screen.getByText(/network device/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Register Collector" }));
    await waitFor(() => expect(api.registerAssetCollector).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Create Policy" }));
    await waitFor(() => expect(api.upsertAssetDiscoveryPolicy).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Import Sample Snapshot" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Download Collector Config" }));
    expect(api.importDiscoveredAssets).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent(/Collector config downloaded/i);
  });

  it("extracts a device, confirms the customer asset, matches CVEs, and runs Patch Compare", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Customer Estate" }));
    expect(await screen.findByRole("heading", { name: "Describe a Device" })).toBeInTheDocument();
    expect(screen.getByText("Devices & Assets")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Extract Fields" }));
    await waitFor(() => expect(api.extractCustomerAsset).toHaveBeenCalled());
    expect(await screen.findByDisplayValue("100F")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Confirm Asset" }));
    await waitFor(() => expect(api.upsertCustomerEstateAsset).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Run CVE Match" }));
    await waitFor(() => expect(api.matchCustomerEstate).toHaveBeenCalledWith("diiac.io", expect.objectContaining({
      asset_id: "net-asset-1"
    })));
    expect(await screen.findByText("Exposure Matches")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Advisory / CVE"), { target: { value: "FG-PFAZ10-SSLVPN" } });
    fireEvent.click(screen.getByRole("button", { name: "Run Patch Compare" }));
    await waitFor(() => expect(api.compareCustomerEstatePatch).toHaveBeenCalled());
    expect(screen.getAllByText("False").length).toBeGreaterThanOrEqual(1);
  });

  it("answers advisory-only questions with governed posture and human approval required", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Ask PatchForge" }));
    expect(await screen.findByText(/No CVE\/advisory is selected/i, {}, { timeout: 10000 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Run Plan" })).toBeInTheDocument();
    expect(screen.getByText("Find the right CVE or patch")).toBeInTheDocument();
    expect(screen.getByText("Create the decision pack")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);

    await waitFor(() => expect(api.askPatchForge).toHaveBeenCalledWith("diiac.io", expect.not.objectContaining({
      advisory_id: expect.anything()
    })));
    expect(await screen.findByText("Short Answer")).toBeInTheDocument();
    expect(screen.getByText("Current Governed Posture")).toBeInTheDocument();
    expect(screen.getByText("Candidate CVEs / Patches / Catalogue Scopes")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-REAL-001")).toBeInTheDocument();
    expect(screen.getByText("Decision Not Allowed Yet")).toBeInTheDocument();
    expect(screen.getByText(/cannot issue final approval/i)).toBeInTheDocument();
    expect(screen.getByText("Human Approval Required")).toBeInTheDocument();
    expect(screen.getByText("Optional AI-Assisted Answer")).toBeInTheDocument();
    expect(screen.getByText("Deterministic answer active")).toBeInTheDocument();
    expect(screen.getAllByText("Runtime disabled").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "Use advisory FG-PFAZ10-SSLVPN" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);
    await waitFor(() => expect(api.askPatchForge).toHaveBeenLastCalledWith("diiac.io", expect.objectContaining({
      advisory_id: "FG-PFAZ10-SSLVPN"
    })));
    fireEvent.click(screen.getByRole("button", { name: /Generate Signed Pack/ }));
    await waitFor(() => expect(api.generateReportsPack).toHaveBeenCalled());
  });

  it("keeps deterministic Ask PatchForge visible when optional AI fails", async () => {
    const api = createApi({
      openAiAgentStatus: vi.fn(async () => ({
        enabled: true,
        configured: true,
        provider: "openai",
        model: "gpt-4o-mini",
        timeout_ms: 15000,
        max_output_tokens: 1000,
        verifier_required: true,
        advisory_only: true,
        final_approval_issued: false,
        can_close_hard_gates: false,
        can_approve: false,
        can_patch: false,
        can_accept_risk: false
      })),
      askOpenAiAgent: vi.fn()
        .mockResolvedValueOnce({
          snapshot_id: "agent-verified",
          agent_name: "Ask PatchForge Agent",
          status: "verified" as const,
          verifier_status: "passed" as const,
          output: {
            recommended_next_action: "Attach reviewed customer evidence.",
            decision_not_allowed_yet: "Human approval remains required.",
            final_approval_issued: false
          },
          fallback: null,
          verification_failures: [],
          final_approval_issued: false,
          can_close_hard_gates: false
        })
        .mockRejectedValueOnce(new Error("agent unavailable"))
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Ask PatchForge" }));
    await screen.findByRole("heading", { name: "Run Plan" });
    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);

    await waitFor(() => expect(api.askOpenAiAgent).toHaveBeenCalledTimes(1));
    expect(await screen.findByText("Deterministic + verified AI")).toBeInTheDocument();
    expect(screen.getByText("Verifier Status")).toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);

    await waitFor(() => expect(api.askOpenAiAgent).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Deterministic answer active")).toBeInTheDocument();
    expect(screen.queryByText("Verifier Status")).not.toBeInTheDocument();
    expect(screen.getByText(/answered deterministically/i)).toBeInTheDocument();
  });

  it("keeps the selected Vendor Catalogue context through assessment and pack generation", async () => {
    const secondAsset = { ...asset, asset_id: "net-asset-2", model: "200F", firmware_version: "7.4.1" };
    const secondAdvisory = { ...advisory, advisory_id: "FG-SECOND-002", cve: "CVE-2026-SECOND-002", title: "Second advisory" };
    const secondAssessment = { ...match, assessment_id: "cfg-app-2", asset_id: secondAsset.asset_id, advisory_id: secondAdvisory.advisory_id };
    const api = createApi({
      listCustomerNetworkAssets: vi.fn(async () => [asset, secondAsset]),
      listVendorSecurityAdvisories: vi.fn(async () => [advisory, secondAdvisory]),
      assessConfigApplicability: vi.fn(async () => secondAssessment)
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Vendor Catalogue" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Patch Compare" }, { timeout: 10000 }));
    fireEvent.click(screen.getByRole("button", { name: /fortinet 200F/i }));
    fireEvent.click(screen.getByRole("button", { name: /CVE-2026-SECOND-002/i }));
    fireEvent.click(screen.getByRole("button", { name: "Assess" }));

    await waitFor(() => expect(api.assessConfigApplicability).toHaveBeenCalledWith("diiac.io", {
      asset_id: "net-asset-2",
      advisory_id: "FG-SECOND-002"
    }));

    fireEvent.click(screen.getByRole("button", { name: "Reports" }));
    fireEvent.click(await screen.findByRole("button", { name: "Generate Signed Pack" }, { timeout: 10000 }));
    await waitFor(() => expect(api.generateReportsPack).toHaveBeenCalled());
    const payload = vi.mocked(api.generateReportsPack).mock.calls.at(-1)?.[1] || {};
    expect(payload).toEqual(expect.objectContaining({
      asset_id: "net-asset-2",
      advisory_id: "FG-SECOND-002",
      config_applicability_assessment: expect.objectContaining({ assessment_id: "cfg-app-2" })
    }));
    expect(payload).not.toHaveProperty("product_baseline");
    expect(payload).not.toHaveProperty("report_template_version");
    expect(payload).not.toHaveProperty("report_context_version");
  }, 30000);

  it("does not send a stale Vendor Catalogue assessment after the selected context changes", async () => {
    const secondAsset = { ...asset, asset_id: "net-asset-2", model: "200F", firmware_version: "7.4.1" };
    const secondAdvisory = { ...advisory, advisory_id: "FG-SECOND-002", cve: "CVE-2026-SECOND-002", title: "Second advisory" };
    const api = createApi({
      listCustomerNetworkAssets: vi.fn(async () => [asset, secondAsset]),
      listVendorSecurityAdvisories: vi.fn(async () => [advisory, secondAdvisory])
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Vendor Catalogue" }));
    fireEvent.click(await screen.findByRole("tab", { name: "Patch Compare" }, { timeout: 10000 }));
    fireEvent.click(screen.getByRole("button", { name: /fortinet 200F/i }));
    fireEvent.click(screen.getByRole("button", { name: /CVE-2026-SECOND-002/i }));
    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);
    fireEvent.click(screen.getAllByRole("button", { name: "Ask PatchForge" }).at(-1)!);

    await waitFor(() => expect(api.startVendorLensChat).toHaveBeenCalledWith("diiac.io", expect.objectContaining({
      asset_id: "net-asset-2",
      advisory_id: "FG-SECOND-002",
      assessment: undefined
    })));
  }, 30000);

  it("consolidates report generation, metadata, downloads, and signed pack export", async () => {
    const api = createApi();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Reports" }));
    expect(screen.getByRole("region", { name: "Reports" })).toBeInTheDocument();
    expect(await screen.findByText("Pre-Export Check")).toBeInTheDocument();
    expect(screen.getAllByText("PF-AZ11-CUSTOMER-DEMO-MATURITY").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("pfaz11-test")).toBeInTheDocument();
    expect(screen.getByText("Final approval false")).toBeInTheDocument();
    expect(screen.getByText("Report Content QA")).toBeInTheDocument();
    expect(screen.getByText("4/4 PASS")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Generate Signed Pack" }));
    await waitFor(() => expect(api.generateReportsPack).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: "Download Board Vulnerability Summary DOCX from PF-TEST-0001" }));
    await waitFor(() => expect(api.downloadDecisionPackReport).toHaveBeenCalledWith("diiac.io", "PF-TEST-0001", "board_vulnerability_remediation_summary", "docx"));
  });

  it("keeps an explicitly selected historical verified pack stable across refresh", async () => {
    const historicalPack = {
      decision_pack_id: "PF-HISTORY-0001",
      pack_id: "PF-HISTORY-0001",
      vulnerability_id: "CVE-2026-REAL-001",
      final_approval_issued: false,
      verification: { verified: true },
      product_baseline: "PF-HISTORICAL",
      created_at: "2026-06-01T08:00:00Z"
    };
    const currentPack = {
      decision_pack_id: "PF-TEST-0001",
      pack_id: "PF-TEST-0001",
      vulnerability_id: "CVE-2026-REAL-001",
      final_approval_issued: false,
      verification: { verified: true },
      product_baseline: "PF-AZ11-CUSTOMER-DEMO-MATURITY",
      created_at: "2026-07-14T08:00:00Z"
    };
    const api = createApi({
      listDecisionPacks: vi.fn(async () => [historicalPack, currentPack])
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Reports" }));
    const selector = await screen.findByRole("combobox", { name: "Verified decision pack" });
    await waitFor(() => expect(selector).toHaveValue("PF-TEST-0001"));
    fireEvent.change(selector, { target: { value: "PF-HISTORY-0001" } });
    expect(selector).toHaveValue("PF-HISTORY-0001");
    expect(screen.getByRole("button", { name: "Download Board Vulnerability Summary DOCX from PF-HISTORY-0001" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Generate Signed Pack" }));
    await waitFor(() => expect(api.generateReportsPack).toHaveBeenCalled());
    await waitFor(() => expect(selector).toHaveValue("PF-HISTORY-0001"));
  }, 15000);

  it("blocks signed report downloads when the newest pack is not verified", async () => {
    const api = createApi({
      listDecisionPacks: vi.fn(async () => [{
        decision_pack_id: "PF-UNVERIFIED-1",
        pack_id: "PF-UNVERIFIED-1",
        vulnerability_id: "CVE-2026-REAL-001",
        final_approval_issued: false,
        verification: { verified: false }
      }])
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Reports" }));
    expect(await screen.findByText("Report downloads remain blocked until a decision pack passes signature verification.")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Verified decision pack" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Download Board Vulnerability Summary DOCX from selected pack" })).toBeDisabled();
  }, 15000);

  it("supports finding evidence submission, reject conflict handling, expiry, and reopen", async () => {
    const conflict = Object.assign(new Error("evidence_revision_conflict"), { status: 409 });
    const api = createApi({
      reviewFindingEvidence: vi.fn(async () => { throw conflict; })
    });
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Open review queue" }));
    expect(await screen.findByRole("heading", { name: "Submit, review, reject, and reopen immutable evidence" }, { timeout: 10000 })).toBeInTheDocument();
    expect(screen.getByText(/This immutable record is expired/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Concise evidence summary"), { target: { value: "New customer scope evidence" } });
    fireEvent.click(screen.getByRole("button", { name: "Submit immutable evidence" }));
    await waitFor(() => expect(api.submitFindingEvidence).toHaveBeenCalledWith("diiac.io", "CVE-2026-REAL-001", expect.objectContaining({
      evidence_class: "affected_asset_scope",
      summary: "New customer scope evidence"
    })));

    const pendingCard = screen.getByRole("heading", { name: "Customer asset scope confirmed" }).closest("article");
    expect(pendingCard).not.toBeNull();
    fireEvent.change(within(pendingCard!).getByLabelText("Reviewer rationale"), { target: { value: "Source hash does not match the current finding." } });
    expect(within(pendingCard!).getByRole("button", { name: "Accept" })).toBeEnabled();
    fireEvent.click(within(pendingCard!).getByRole("button", { name: "Reject" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Evidence conflict");
    expect(api.reviewFindingEvidence).toHaveBeenCalledWith("diiac.io", "CVE-2026-REAL-001", "evidence-pending-1", expect.objectContaining({
      decision: "reject",
      expected_content_hash: "sha256:pending-content",
      expected_event_hash: "sha256:submitted-event"
    }));

    const expiredCard = screen.getByRole("heading", { name: "Expired customer configuration snapshot" }).closest("article");
    expect(expiredCard).not.toBeNull();
    fireEvent.change(within(expiredCard!).getByLabelText("Reviewer rationale"), { target: { value: "Reopen for a refreshed evidence submission." } });
    fireEvent.click(within(expiredCard!).getByRole("button", { name: "Reopen review" }));
    await waitFor(() => expect(api.reopenFindingEvidence).toHaveBeenCalledWith("diiac.io", "CVE-2026-REAL-001", "evidence-expired-1", expect.objectContaining({
      expected_content_hash: "sha256:expired-content",
      expected_event_hash: "sha256:rejected-event"
    })));
  }, 30000);

  it("allows a CAB approver to generate packs without enabling triage actions", async () => {
    const api = createApi();
    const cabAuth = { ...auth, roles: ["PatchForge.CABApprover"] };
    render(<App auth={cabAuth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Reports" }));
    expect(await screen.findByRole("button", { name: "Generate Signed Pack" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Patch & CVE Catalogue" }));
    expect(await screen.findByRole("button", { name: "Refresh KEV intelligence" })).toBeDisabled();
  }, 15000);

  it("refreshes source feeds from the simplified action center", async () => {
    const api = createApi();
    render(<App auth={auth} api={api} />);

    fireEvent.click(await screen.findByRole("button", { name: "Refresh KEV intelligence" }));
    await waitFor(() => expect(api.refreshSourceFeed).toHaveBeenCalledWith("diiac.io", expect.objectContaining({ feed_id: "cisa-kev", limit: 5 })));
    expect(screen.getByRole("heading", { name: "What needs attention today?" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Patch & CVE Catalogue" })).toHaveClass("active");
  });

  it("keeps assurance visible and disables write actions without privileged roles", async () => {
    render(<App auth={{ ...auth, roles: ["PatchForge.Reader"] }} api={createApi()} />);

    expect(screen.getByRole("button", { name: "Admin" })).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Refresh KEV intelligence" })).toBeDisabled();
  });

  it("renders admin controls and avoids prohibited wording", async () => {
    const { container } = render(<App auth={auth} api={createApi()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Admin" }));
    expect((await screen.findAllByRole("heading", { name: "System & Data Health" }, { timeout: 10000 })).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Entra ID / RBAC")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Entra ID \/ RBAC/i })).not.toBeInTheDocument();
    expect(screen.getByText("OpenAI Assistance")).toBeInTheDocument();
    expect(screen.getByText("DIIaC IT Service / Enterprise Build")).toBeInTheDocument();
    expect(screen.getByText("Patch Deployment")).toBeInTheDocument();
    expect(screen.getAllByText("Blocked").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole("heading", { name: "Typed confirmation required before destructive data cleanup" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Execute Confirmed Purge" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "admin sections page 2" }));
    expect(screen.getByText("Signing & Trust")).toBeInTheDocument();
    expect(container.textContent?.toLowerCase()).not.toContain("autonomous patching");
    expect(container.textContent?.toLowerCase()).not.toContain("exploit generation");
  });

  it("shows the Entra sign-in gate when unauthenticated", () => {
    const { container } = render(<App auth={{ ...auth, status: "unauthenticated", accountName: null }} api={createApi()} />);
    expect(screen.getByRole("heading", { name: "PatchForge Intelligence by DIIaC\u2122" })).toBeInTheDocument();
    expect(screen.getByText("DIIaC\u2122")).toBeInTheDocument();
    expect(container.textContent).not.toContain("\\u2122");
    expect(screen.queryByRole("heading", { name: /PatchForge Intelligence by DIIaC.*PatchForge/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in with Microsoft" })).toBeInTheDocument();
  });

  it("lets signed-in users collapse and restore the primary navigation", async () => {
    const { container } = render(<App auth={auth} api={createApi()} />);
    const toggle = await screen.findByRole("button", { name: "Toggle navigation" });
    const shell = container.querySelector("main.app-shell");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(shell).not.toHaveClass("nav-collapsed");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(shell).toHaveClass("nav-collapsed");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(shell).not.toHaveClass("nav-collapsed");
  });

  it("provides keyboard-complete Vendor Catalogue tabs", async () => {
    render(<App auth={auth} api={createApi()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Vendor Catalogue" }));
    const firstTab = await screen.findByRole("tab", { name: "Network Vendors" }, { timeout: 10000 });
    const secondTab = screen.getByRole("tab", { name: "Product Families" });
    expect(firstTab).toHaveAttribute("aria-selected", "true");
    expect(secondTab).toHaveAttribute("tabindex", "-1");

    firstTab.focus();
    fireEvent.keyDown(firstTab, { key: "ArrowRight" });

    expect(secondTab).toHaveFocus();
    expect(secondTab).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tabpanel")).toHaveAttribute("aria-labelledby", secondTab.id);
  });

  it("closes the mobile drawer with Escape and restores toggle focus", async () => {
    vi.stubGlobal("matchMedia", vi.fn((query: string) => ({
      matches: query === "(max-width: 820px)",
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(() => false)
    })));
    try {
      render(<App auth={auth} api={createApi()} />);
      const toggle = await screen.findByRole("button", { name: "Toggle navigation" });
      expect(toggle).toHaveAttribute("aria-expanded", "false");

      toggle.focus();
      fireEvent.click(toggle);
      expect(await screen.findByRole("button", { name: "Close navigation" })).toHaveFocus();

      fireEvent.keyDown(document, { key: "Escape" });
      expect(toggle).toHaveAttribute("aria-expanded", "false");
      await waitFor(() => expect(toggle).toHaveFocus());
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("retains successful panels and retries one unavailable data surface", async () => {
    const metricsRequest = vi.fn()
      .mockRejectedValueOnce(new Error("insufficient_patchforge_role"))
      .mockResolvedValue(metrics);
    render(<App auth={auth} api={createApi({ metrics: metricsRequest })} />);

    const warning = await screen.findByLabelText("Partially unavailable data sources");
    expect(warning).toHaveTextContent("Dashboard metrics: insufficient_patchforge_role");
    expect(await screen.findByRole("heading", { name: "What needs attention today?" })).toBeInTheDocument();
    fireEvent.click(within(warning).getByRole("button", { name: "Retry Dashboard metrics" }));

    await waitFor(() => expect(metricsRequest).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByLabelText("Partially unavailable data sources")).not.toBeInTheDocument());
  });
});

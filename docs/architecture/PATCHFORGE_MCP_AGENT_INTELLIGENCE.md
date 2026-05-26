# PatchForge MCP Agent Intelligence

## Purpose

PatchForge is designed for agent-led, human-approved patch governance.

MCP agents, SRA tools, Mythos, scanner connectors, advisory feeds, and other AGI-agent sources should do as much of the research, correlation, contradiction checking, source mapping, and draft decision-context work as possible. The human role should be concentrated on accountable review, approval, rejection, risk ownership, and final decision signoff.

## Operating Model

```text
leading-class finding -> source-bound intake -> evidence binding -> exposure mapping -> deterministic compile -> human review -> signed decision pack
```

The protected agent-finding intake path is:

```text
POST /api/patchforge/agent-findings/ingest
```

Accepted source classes:

- `mcp_agent_finding`
- `mythos_finding`
- `agi_agent_finding`
- `sra_trace`

Required source identity:

- `finding_id`, `vulnerability_id`, or `advisory_id`

Default governance state:

- source-bound
- advisory only
- pending review
- cannot close hard gates alone
- cannot issue final approval
- cannot risk accept
- cannot deploy patches

## Human Review Boundary

Agents may:

- identify and correlate findings
- enrich vulnerability context
- map affected assets and services from provided context
- flag known exploitation and exposure signals
- identify contradictions between sources
- suggest compensating controls for review
- draft patch feasibility and decision context
- prepare evidence candidates for deterministic compile

Agents must not:

- generate exploit instructions
- issue patch deployment actions
- mutate production systems
- approve CAB decisions
- accept risk
- close hard evidence gates by themselves
- claim source truth without review

## Evidence Model

Agent findings are included in `contracts/evidence_models.json` as advisory source defaults.

The following source classes are disallowed from closing hard gates alone:

- `scanner_output`
- `sra_trace`
- `mcp_agent_finding`
- `mythos_finding`
- `agi_agent_finding`

This means leading-class AI findings can drive priority and attention, but the signed pack remains grounded in reviewed evidence, deterministic policy, and accountable approval.

## LLM Key Handling

PatchForge should use existing approved LLM integration keys from managed configuration or Key Vault. New keys should not be introduced into source code, docs, frontend config, environment evidence, or repository files.

## Customer Demo Posture

The customer demo must use real operator-approved or customer-provided records only. No demo seed data, synthetic vulnerability records, or fabricated findings should be shipped in the product repository.

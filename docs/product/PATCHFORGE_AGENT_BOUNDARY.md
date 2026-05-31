# PatchForge Agent Boundary

PatchForge agents prepare advisory guidance only. They do not scan environments, generate exploit code, provide procedural exploit steps, deploy patches, mutate production, approve CAB decisions, accept risk, close evidence gates, or issue final approval.

Every agent response must state:

- `advisory_only=true`
- `can_close_hard_gates=false`
- `can_approve=false`
- `can_patch=false`
- `can_accept_risk=false`
- `final_approval_issued=false`
- `human_review_required=true`

The deterministic verifier blocks unsafe claims, including exploit instructions, patch deployment instructions, autonomous approval, risk acceptance, hard-gate closure, "safe" or "not vulnerable" claims without reviewed evidence, and customer assurance without reviewed exposure/applicability evidence.

OpenAI-native agents are optional and disabled by default. The deterministic PatchForge workflow remains the authority for customer-demo behaviour.

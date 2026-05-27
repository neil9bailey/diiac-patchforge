# PF-AZ7 Operational Demo Evidence

This evidence folder records PF-AZ7 local validation, report visual QA, Azure rollout, and live UI validation.

PF-AZ7 scope:

- Professional DOCX/PDF board and governance report outputs.
- Protected report export API.
- Live UI Reports page and Decision Pack DOCX/PDF export actions.
- Scheduler-backed live CISA KEV and FIRST EPSS refresh.
- Customer-demo workflow using live public-source intelligence, signed packs, and human-review boundaries.

No scanner execution, exploit generation, procedural exploit guidance, patch deployment, production mutation from the UI, autonomous CAB approval, or autonomous risk acceptance is introduced.

## Local Evidence

- `doc-qa/`: DOCX/PDF board-pack sample, Word-rendered PDF, page PNGs, and visual QA summary.

## Azure Evidence

- `build-push/`: ACR build/push log and tag verification for `pfaz7-20260527-71643ce`.
- `deploy-plan/`: Bicep what-if evidence. Full template apply was not used because it included broader drift/noise than required for the image rollout.
- `deploy-apply/`: targeted Container Apps update evidence, active revisions, scheduler state, and scheduler logs.
- `live-ui/`: live HTTP/API smoke, signed-in browser validation, screenshots, authenticated API summary, fresh pack verification, scheduler/source-feed evidence, Key Vault signing smoke, PostgreSQL smoke, and live DOCX/PDF report visual QA.

Fresh live signed pack: `PF-20260527-54588be9`.

Validated source record: `CVE-2026-48172`.

Final approval remained false. Human review, evidence resolution, and accountable approval remain required.

# PatchForge Collector And Automation Operations Runbook

## Boundary

The collector, scheduler, and worker automate source-bound evidence intake only. They do not scan for vulnerabilities, execute exploits, deploy patches, mutate customer production systems, approve CAB decisions, accept risk, or close evidence gates.

## Windows Collector Lifecycle

1. Build with `scripts/build_patchforge_collector_windows_exe.ps1`.
2. For customer distribution, provide `-SigningCertificateThumbprint` and `-RequireSigning` so Authenticode signing and timestamp verification fail closed.
3. Verify the EXE against `collector-package-manifest.json` with `scripts/verify_patchforge_collector_windows_package.ps1`.
4. Configure and install with `scripts/setup_patchforge_collector_windows.ps1`.
5. Upgrade by rerunning setup with `-Upgrade`; the prior executable and scheduled-task XML are retained until replacement registration succeeds.
6. Revoke locally with `scripts/revoke_patchforge_collector_windows.ps1`; this disables the task and creates a non-secret marker that blocks execution before collection or network access.
7. Disable the corresponding Entra service principal/app-role assignment separately. The local script does not mutate Entra or Azure.
8. Uninstall with `scripts/uninstall_patchforge_collector_windows.ps1`; config is preserved unless `-RemoveConfiguration` is explicit.

Unsigned packages are permitted only with the explicit `-AllowUnsignedDevelopmentPackage` switch. They are not customer deliverables.

Customer package build and verification:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_patchforge_collector_windows_exe.ps1 `
  -SigningCertificateThumbprint "<approved-patchforge-code-signing-thumbprint>" `
  -RequireSigning

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_patchforge_collector_windows_package.ps1 `
  -CollectorExePath .\artifacts\collector\windows\package\patchforge-collector.exe
```

Stop when the source worktree is dirty, the source commit is not the approved commit, the manifest hash differs, Authenticode is not valid, the signer is not the approved PatchForge signer, or timestamp verification fails. Do not reuse a code-signing certificate issued for another product merely because it is installed locally.

## Least-Privilege Authentication

No token, client secret, password, certificate private key, or source-system credential is written to JSON or passed as an installer argument.

Supported paths are:

- `PATCHFORGE_COLLECTOR_TOKEN` injected into the process environment by an approved OS/secret-management mechanism;
- Azure CLI managed identity for an Azure VM or Azure Arc-enabled host, optionally using a client ID from `PATCHFORGE_COLLECTOR_MANAGED_IDENTITY_CLIENT_ID`;
- a scheduled user's existing Azure CLI identity for attended/current-user operation.

Unattended `SYSTEM` or service-account installation is rejected unless managed identity is enabled or the operator explicitly confirms that an OS-injected credential environment exists. Scheduled tasks use limited run level and ignore overlapping starts.

Example unattended managed-identity setup:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_patchforge_collector_windows.ps1 `
  -CollectorExePath .\artifacts\collector\windows\package\patchforge-collector.exe `
  -AzureCliManagedIdentity `
  -RunAs System `
  -RunNow
```

For a gMSA, use `-RunAs ServiceAccount -ServiceAccount "CONTOSO\svc-patchforge$"` only after the account, local rights, network access, and PatchForge app-role assignment have been approved.

## Heartbeat And Revocation

Every push run writes a non-secret heartbeat file and upserts lifecycle state through the collector registration API. Operators can review:

- collector/package version and package SHA-256;
- heartbeat/run identifier and timestamp;
- lifecycle state and last asset/warning counts;
- authentication mode, never token material;
- calculated `ready`, `degraded`, `stale`, `pending`, or `revoked` state.

The default stale threshold is eight hours and can be changed with `PATCHFORGE_COLLECTOR_STALE_AFTER_MS`.

## Offline Spool And Replay

The Windows configuration generator enables a bounded spool at `%ProgramData%\PatchForge\Collector\spool`. Each submission is persisted atomically before API delivery and replayed oldest-first. Policy, import, and completion-heartbeat acknowledgements are checkpointed independently, so an interrupted replay resumes from the first unacknowledged step. The API run identifier remains stable across replay.

- `queued_offline` means local discovery succeeded, but Core has not acknowledged the import.
- `pending_spool_entries` in the heartbeat is the operator-visible queue depth.
- retryable network, timeout, rate-limit, and server failures remain in the queue;
- authentication, authorization, revocation, and validation failures remain blocked for operator correction;
- after `lifecycle.maxReplayAttempts` retryable failures, the entry moves to `spool\quarantine` and is never silently deleted.

Spool entries contain customer asset evidence, not credentials. Restrict filesystem access, include the directory in customer backup/retention policy, and never clear it merely to restore a green health state. After connectivity recovery, start the scheduled task once and confirm FIFO replay, zero pending entries, a completed server-side run with the same `run_id`, and a current heartbeat.

## Scheduler And Worker Resilience

Scheduler work is represented by deterministic `automation_work_items`:

- the same tenant/cycle/feed/CVE produces the same idempotency key;
- feed/CVE checkpoints retain the latest completed cursor;
- a tenant scheduler lease prevents concurrent cycles;
- each item has its own lease;
- retry uses bounded exponential backoff and a finite attempt limit;
- every failure is recorded without secret material;
- exhausted work enters the dead-letter ledger;
- reconciliation recovers expired leases, performs bounded replay, then quarantines repeatedly failing work;
- only `cisa-kev` and `first-epss` source-bound refresh work is accepted.

The worker runtime executes pending/retry work and reconciliation. Configure:

- `PATCHFORGE_WORKER_ENABLED=true`
- `PATCHFORGE_WORKER_INTERVAL_MS` (minimum 15000)
- `PATCHFORGE_WORKER_BATCH_SIZE`
- `PATCHFORGE_WORKER_LEASE_TTL_MS`
- `PATCHFORGE_WORKER_MAX_REPLAYS`
- `PATCHFORGE_WORKER_BACKLOG_SLO_MS`
- `PATCHFORGE_WORKER_CHECKPOINT_SLO_MS`
- `PATCHFORGE_WORKER_RUN_ON_START`

The server process must call `startWorker()` when `PATCHFORGE_COMPONENT=ingest-export-worker`.

## Health And Intervention

Admin health derives worker status from configured runtime state plus pending, dead-letter, quarantined, backlog-age, and checkpoint-age evidence. A quarantined item or breached SLO is degraded and requires human investigation. Do not delete failure/dead-letter evidence merely to make health green.

| Alert | Meaning | Operator action |
| --- | --- | --- |
| `open_dead_letters` | Work exhausted its normal attempt path | Inspect the recorded failure and upstream dependency before bounded replay |
| `quarantined_work` | Poison or repeatedly failing work was isolated | Investigate and correct the cause; do not requeue or delete blindly |
| `backlog_slo_breached` | The oldest pending work exceeds the configured backlog threshold | Confirm worker lease ownership, upstream availability, and queue progress |
| `checkpoint_missing` | Work exists but no completed checkpoint is recorded | Review scheduler/worker run evidence before claiming refresh success |
| `checkpoint_slo_breached` | The newest checkpoint is older than the configured threshold | Verify scheduler execution, source availability, persistence, and alert handling |

Safe recovery is:

1. inspect the failure class/message and upstream source availability;
2. correct configuration or dependency state;
3. allow one bounded reconciliation replay;
4. confirm checkpoint advance and source-bound pending-review records;
5. retain failure, reconciliation, and audit evidence.

No retry or reconciliation event constitutes evidence acceptance, approval, risk acceptance, or permission to deploy a patch.

## Customer Acceptance Checklist

Do not describe the collector as customer-ready until a representative clean Windows machine proves:

- the approved Authenticode signature and timestamp validate;
- package manifest, source commit, and EXE SHA-256 match;
- install succeeds using the approved least-privilege identity;
- no token or private credential is present in the package, config, heartbeat, logs, or spool;
- scheduled execution ignores overlaps and records a current heartbeat;
- a normal import is duplicate-safe and arrives as source-bound pending-review evidence;
- an offline run enters `queued_offline`, preserves FIFO order, and replays with the same run ID after recovery;
- retry exhaustion moves evidence to quarantine without silent deletion;
- upgrade preserves the previous executable/task until replacement succeeds;
- local revoke blocks execution before collection/network access and Entra access is separately revoked;
- uninstall preserves configuration unless removal is explicitly requested;
- no scanner, exploit, patch-deployment, production-mutation, approval, or risk-acceptance behavior occurs.

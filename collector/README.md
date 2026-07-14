# PatchForge Collector

The PatchForge Collector is a day-1 Windows asset evidence collector. It runs outbound to PatchForge Core and imports categorized asset facts into the governed discovery API.

It is not a vulnerability scanner, exploit tool, patch deployment agent, or approval mechanism. Imported assets are source-bound and pending review.

## Windows EXE Package

Build the customer-side EXE:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_patchforge_collector_windows_exe.ps1
```

The build writes:

```text
artifacts\collector\windows\patchforge-collector.exe
```

The build writes `collector-package-manifest.json` with the source commit, tracked-worktree state, EXE SHA-256, and Authenticode signer metadata. A signed customer build fails before packaging when tracked source is dirty. Customer distribution should use a certificate in the Windows certificate store:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_patchforge_collector_windows_exe.ps1 `
  -SigningCertificateThumbprint "<code-signing-certificate-thumbprint>" `
  -RequireSigning
```

Verify every package before install or upgrade:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_patchforge_collector_windows_package.ps1 `
  -CollectorExePath .\artifacts\collector\windows\package\patchforge-collector.exe
```

Unsigned packages require the explicit `-AllowUnsignedDevelopmentPackage` switch and are for local development only. Tokens and customer secrets are never embedded in the EXE, manifest, ZIP, or JSON config.

## Simple Windows Setup

Generate config and install the scheduled task:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_patchforge_collector_windows.ps1 `
  -CollectorExePath .\artifacts\collector\windows\patchforge-collector.exe `
  -Site "Primary site" `
  -RunNow
```

Defaults point to the live PatchForge Azure API:

```text
https://api.patchforge.diiac.io
```

The config is written to:

```text
%ProgramData%\PatchForge\Collector\patchforge-collector.config.json
```

The collector authenticates in this order and caches one token for the run:

1. `PATCHFORGE_COLLECTOR_TOKEN` environment variable, if set.
2. Azure CLI managed identity, when `auth.azureCliManagedIdentity=true` (recommended for unattended Azure VM/Azure Arc hosts).
3. Azure CLI token acquisition from the scheduled user's existing identity.

For the Azure CLI path, sign in as the scheduled-task user:

```powershell
az login --tenant 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da
```

For unattended operation, install as limited `SYSTEM` or a least-privilege gMSA/service identity and use managed identity or an OS-injected credential environment. The installer refuses unattended configuration that depends on an interactive Azure CLI session. It never accepts a raw secret parameter or writes a secret to config.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_patchforge_collector_windows.ps1 `
  -CollectorExePath .\artifacts\collector\windows\package\patchforge-collector.exe `
  -AzureCliManagedIdentity `
  -RunAs System `
  -RunNow
```

For an approved gMSA, use `-RunAs ServiceAccount -ServiceAccount "CONTOSO\svc-patchforge$"`.

## Development Run

```bash
export PATCHFORGE_COLLECTOR_TOKEN="<access token>"
node ./collector/patchforge-collector.mjs --config=./collector/patchforge-collector.config.json
```

Use `--dry-run` to collect and print the asset snapshot without sending it to PatchForge.

## Configuration

Use `scripts\new_patchforge_collector_windows_config.ps1` or start from `patchforge-collector.config.example.json`.

Required:

- `apiBaseUrl`: PatchForge UI/API origin, for example `https://patchforge.diiac.io`.
- `tenantId`: PatchForge tenant id.
- `collector.collector_id`: stable collector id for this customer site.
- `policy.policy_id`: stable policy id for this collector.
- `auth.bearerTokenEnv`: environment variable that holds the bearer token.
- `auth.azureCliScope`: PatchForge API scope used when the collector obtains a token with Azure CLI.
- `auth.azureTenantId`: Entra tenant used for Azure CLI token acquisition.

Secrets are not allowed in the config file. Use environment references such as `Bearer env:NMS_READONLY_TOKEN` for source API headers and `PATCHFORGE_COLLECTOR_TOKEN` for PatchForge API auth.

`lifecycle.spoolDirectory` enables the bounded durable offline queue (the Windows generator defaults it to `%ProgramData%\PatchForge\Collector\spool`). A collected submission is written atomically before delivery, replayed oldest-first, and removed only after policy, import, and final heartbeat are acknowledged. Repeatedly unavailable submissions are retained for bounded retry and then moved to `spool\quarantine`; authentication, authorization, revocation, and other non-retryable API failures remain blocked for operator action rather than being discarded. Spool files contain inventory evidence but no bearer token or raw credential, so protect the directory as customer-sensitive operational data.

## Lifecycle And Heartbeat

Each push run writes a non-secret local heartbeat and upserts the same lifecycle state through the existing collector registration API. Heartbeats include collector/package version, package digest, run ID, status, counts, and authentication mode but never token material. The backend exposes `ready`, `degraded`, `stale`, `pending`, or `revoked` lifecycle state.

The local heartbeat also reports `pending_spool_entries`. A `queued_offline` state means collection succeeded locally but API acknowledgement has not occurred; it must not be reported as an imported or reviewed asset run. Restore connectivity or authentication, rerun the scheduled task, and confirm the queue reaches zero. Inspect (do not delete) `spool\quarantine` when bounded replay is exhausted.

Upgrade in place after verifying a new package:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_patchforge_collector_windows.ps1 `
  -CollectorExePath .\patchforge-collector.exe `
  -Upgrade `
  -RunNow
```

The installer preserves the previous executable and task definition until registration succeeds, then removes the local backup.

Locally revoke and disable scheduled execution:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\revoke_patchforge_collector_windows.ps1 `
  -Reason "Customer offboarding"
```

The revocation marker blocks the collector before collection or network access. An Entra administrator must separately disable the service principal or app-role assignment; the local script does not mutate Entra or Azure.

Uninstall while preserving config by default:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\uninstall_patchforge_collector_windows.ps1 -Revoke
```

Reactivation requires the explicit `-Reactivate` setup switch after accountable access approval.

## Day-1 Windows Adapters

- `local_host`: collects the machine running the collector.
- `hyperv`: collects local Hyper-V VM inventory on Windows where Hyper-V PowerShell is available.
- `azure_cli`: collects Azure resources through `az resource list` using the existing Azure CLI identity.
- `http_json`: pulls assets from a CMDB, NMS, ITSM, or inventory API that returns JSON.

The collector does not enumerate subnets or run exploit/vulnerability checks. Network devices should come from an existing read-only NMS/CMDB/API source on day 1.

## Output Boundary

Every pushed run keeps these guarantees:

- `advisory_only=true`
- `review_required=true`
- `final_approval_issued=false`
- no vulnerability scanning
- no exploit execution
- no patch deployment
- no production mutation

## Windows Helper Scripts

- Build EXE: `scripts/build_patchforge_collector_windows_exe.ps1`
- Generate config: `scripts/new_patchforge_collector_windows_config.ps1`
- Install scheduled task: `scripts/install_patchforge_collector_windows.ps1`
- One-step setup: `scripts/setup_patchforge_collector_windows.ps1`
- Verify package: `scripts/verify_patchforge_collector_windows_package.ps1`
- Revoke locally: `scripts/revoke_patchforge_collector_windows.ps1`
- Uninstall: `scripts/uninstall_patchforge_collector_windows.ps1`

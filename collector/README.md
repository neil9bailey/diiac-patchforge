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

The EXE must not be distributed with embedded tokens or customer secrets. Sign the EXE with Authenticode before customer distribution when a code-signing certificate is available.

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

The collector authenticates in this order:

1. `PATCHFORGE_COLLECTOR_TOKEN` environment variable, if set.
2. Azure CLI token acquisition using the configured PatchForge API scope.

For the Azure CLI path, sign in as the scheduled-task user:

```powershell
az login --tenant 67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da
```

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

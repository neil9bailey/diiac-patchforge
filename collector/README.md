# PatchForge Collector

The PatchForge Collector is a day-1 Windows/Linux asset evidence collector. It runs outbound to PatchForge Core and imports categorized asset facts into the governed discovery API.

It is not a vulnerability scanner, exploit tool, patch deployment agent, or approval mechanism. Imported assets are source-bound and pending review.

## Run

```powershell
$env:PATCHFORGE_COLLECTOR_TOKEN = "<access token>"
node .\collector\patchforge-collector.mjs --config=.\collector\patchforge-collector.config.json
```

```bash
export PATCHFORGE_COLLECTOR_TOKEN="<access token>"
node ./collector/patchforge-collector.mjs --config=./collector/patchforge-collector.config.json
```

Use `--dry-run` to collect and print the asset snapshot without sending it to PatchForge.

## Configuration

Start from `patchforge-collector.config.example.json`.

Required:

- `apiBaseUrl`: PatchForge UI/API origin, for example `https://patchforge.diiac.io`.
- `tenantId`: PatchForge tenant id.
- `collector.collector_id`: stable collector id for this customer site.
- `policy.policy_id`: stable policy id for this collector.
- `auth.bearerTokenEnv`: environment variable that holds the bearer token.

Secrets are not allowed in the config file. Use environment references such as `Bearer env:NMS_READONLY_TOKEN` for source API headers and `PATCHFORGE_COLLECTOR_TOKEN` for PatchForge API auth.

## Day-1 Adapters

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

## Install Helpers

- Windows scheduled task helper: `scripts/install_patchforge_collector_windows.ps1`
- Linux systemd helper: `scripts/install_patchforge_collector_linux.sh`

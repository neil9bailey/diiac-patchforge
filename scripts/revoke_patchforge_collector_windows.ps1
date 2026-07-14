param(
  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$RevocationFile = "$env:ProgramData\PatchForge\Collector\collector.revoked.json",
  [string]$TaskName = "PatchForgeCollector",
  [string]$Reason = "Collector access revoked by an accountable operator",
  [switch]$RemoveMachineCredentialEnvironment
)

$ErrorActionPreference = "Stop"

$collectorId = $null
if (Test-Path -LiteralPath $ConfigPath) {
  $config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
  $collectorId = [string]$config.collector.collector_id
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $task) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName $TaskName | Out-Null
}

$directory = Split-Path -Parent $RevocationFile
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$record = [ordered]@{
  revoked = $true
  collector_id = $collectorId
  revoked_at = [DateTime]::UtcNow.ToString("o")
  revoked_by = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  reason = $Reason
  local_execution_blocked = $true
  remote_identity_revocation_required = $true
  no_patch_deployment = $true
  no_production_mutation = $true
}
[System.IO.File]::WriteAllText(
  $RevocationFile,
  (($record | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
  [System.Text.UTF8Encoding]::new($false)
)

if ($RemoveMachineCredentialEnvironment) {
  [Environment]::SetEnvironmentVariable("PATCHFORGE_COLLECTOR_TOKEN", $null, "Machine")
}

Write-Host "PatchForge collector is locally revoked and scheduled execution is disabled."
Write-Host "Revocation marker: $RevocationFile"
Write-Warning "An Entra administrator must separately disable or delete the collector service principal/app-role assignment when one exists."

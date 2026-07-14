param(
  [string]$InstallDirectory = "$env:ProgramFiles\PatchForge Collector",
  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$HeartbeatFile = "$env:ProgramData\PatchForge\Collector\collector-heartbeat.json",
  [string]$RevocationFile = "$env:ProgramData\PatchForge\Collector\collector.revoked.json",
  [string]$TaskName = "PatchForgeCollector",
  [switch]$Revoke,
  [switch]$RemoveConfiguration,
  [switch]$RemoveHeartbeat
)

$ErrorActionPreference = "Stop"

$resolvedInstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
$installLeaf = Split-Path -Leaf $resolvedInstallDirectory
if ([string]::IsNullOrWhiteSpace($installLeaf) -or $installLeaf -notmatch "(?i)patchforge") {
  throw "Refusing recursive removal outside an explicitly named PatchForge install directory: $resolvedInstallDirectory"
}

if ($Revoke) {
  & (Join-Path $PSScriptRoot "revoke_patchforge_collector_windows.ps1") `
    -ConfigPath $ConfigPath `
    -RevocationFile $RevocationFile `
    -TaskName $TaskName `
    -Reason "Collector uninstalled and locally revoked"
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $task) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if (Test-Path -LiteralPath $resolvedInstallDirectory) {
  Remove-Item -LiteralPath $resolvedInstallDirectory -Recurse -Force
}
if ($RemoveConfiguration -and (Test-Path -LiteralPath $ConfigPath)) {
  Remove-Item -LiteralPath $ConfigPath -Force
}
if ($RemoveHeartbeat -and (Test-Path -LiteralPath $HeartbeatFile)) {
  Remove-Item -LiteralPath $HeartbeatFile -Force
}

Write-Host "PatchForge collector scheduled task and binaries were removed."
Write-Host "Configuration preserved: $(-not [bool]$RemoveConfiguration)"
Write-Host "Local revocation preserved: $(Test-Path -LiteralPath $RevocationFile)"

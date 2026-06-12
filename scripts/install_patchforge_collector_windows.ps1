param(
  [Parameter(Mandatory = $true)]
  [string]$RepoPath,

  [Parameter(Mandatory = $true)]
  [string]$ConfigPath,

  [string]$TaskName = "PatchForgeCollector",
  [string]$NodePath = "node",
  [string]$TokenEnvironmentVariable = "PATCHFORGE_COLLECTOR_TOKEN",
  [int]$IntervalMinutes = 240
)

$ErrorActionPreference = "Stop"

$collectorPath = Join-Path $RepoPath "collector\patchforge-collector.mjs"
if (-not (Test-Path -LiteralPath $collectorPath)) {
  throw "Collector not found: $collectorPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Collector config not found: $ConfigPath"
}

$action = New-ScheduledTaskAction `
  -Execute $NodePath `
  -Argument "`"$collectorPath`" --config=`"$ConfigPath`"" `
  -WorkingDirectory $RepoPath

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
  -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings `
  -Description "PatchForge outbound asset discovery collector. Token must be provided through $TokenEnvironmentVariable." `
  -Force | Out-Null

Write-Output "Installed scheduled task $TaskName. Set $TokenEnvironmentVariable in the task runtime environment before live use."

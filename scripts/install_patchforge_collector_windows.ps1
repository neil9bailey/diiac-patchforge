param(
  [string]$CollectorExePath = "",
  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$InstallDirectory = "$env:ProgramFiles\PatchForge Collector",
  [string]$TaskName = "PatchForgeCollector",
  [int]$IntervalMinutes = 240,
  [ValidateSet("CurrentUser", "System")]
  [string]$RunAs = "CurrentUser",
  [switch]$RunNow,

  [string]$RepoPath = "",
  [string]$NodePath = "node"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Collector config not found: $ConfigPath. Run scripts\new_patchforge_collector_windows_config.ps1 first."
}

$isExeInstall = -not [string]::IsNullOrWhiteSpace($CollectorExePath)
if ($isExeInstall) {
  if (-not (Test-Path -LiteralPath $CollectorExePath)) {
    throw "Collector EXE not found: $CollectorExePath"
  }
  New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
  $installedExe = Join-Path $InstallDirectory "patchforge-collector.exe"
  Copy-Item -LiteralPath $CollectorExePath -Destination $installedExe -Force
  $execute = $installedExe
  $arguments = "--config=`"$ConfigPath`""
  $workingDirectory = $InstallDirectory
} else {
  if ([string]::IsNullOrWhiteSpace($RepoPath)) {
    throw "Provide -CollectorExePath for the Windows EXE install path, or -RepoPath for the development Node path."
  }
  $collectorPath = Join-Path $RepoPath "collector\patchforge-collector.mjs"
  if (-not (Test-Path -LiteralPath $collectorPath)) {
    throw "Collector source not found: $collectorPath"
  }
  $execute = $NodePath
  $arguments = "`"$collectorPath`" --config=`"$ConfigPath`""
  $workingDirectory = $RepoPath
}

$action = New-ScheduledTaskAction `
  -Execute $execute `
  -Argument $arguments `
  -WorkingDirectory $workingDirectory

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
  -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

if ($RunAs -eq "System") {
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
  Write-Warning "Installing as SYSTEM. Ensure PATCHFORGE_COLLECTOR_TOKEN or Azure CLI auth is available to the SYSTEM account."
} else {
  $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
}

$settings = New-ScheduledTaskSettingsSet `
  -Compatibility Win8 `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable

Register-ScheduledTask `
  -TaskName $TaskName `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings `
  -Description "PatchForge outbound asset evidence collector. No scanning, exploit, patch deployment, production mutation, or autonomous approval." `
  -Force | Out-Null

if ($RunNow) {
  Start-ScheduledTask -TaskName $TaskName
}

Write-Host "Installed scheduled task $TaskName."
Write-Host "Executable: $execute"
Write-Host "Config: $ConfigPath"
Write-Host "Run mode: $RunAs"

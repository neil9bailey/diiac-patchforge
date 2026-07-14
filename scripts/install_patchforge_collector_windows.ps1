param(
  [string]$CollectorExePath = "",
  [string]$ConfigPath = "$env:ProgramData\PatchForge\Collector\patchforge-collector.config.json",
  [string]$InstallDirectory = "$env:ProgramFiles\PatchForge Collector",
  [string]$ManifestPath = "",
  [string]$RevocationFile = "$env:ProgramData\PatchForge\Collector\collector.revoked.json",
  [string]$TaskName = "PatchForgeCollector",
  [int]$IntervalMinutes = 240,
  [ValidateSet("CurrentUser", "System", "ServiceAccount")]
  [string]$RunAs = "CurrentUser",
  [string]$ServiceAccount = "",
  [switch]$EnvironmentCredentialAvailable,
  [switch]$AllowUnsignedDevelopmentPackage,
  [switch]$Upgrade,
  [switch]$Reactivate,
  [switch]$RunNow,

  [string]$RepoPath = "",
  [string]$NodePath = "node"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Collector config not found: $ConfigPath. Run scripts\new_patchforge_collector_windows_config.ps1 first."
}

if ((Test-Path -LiteralPath $RevocationFile) -and -not $Reactivate) {
  throw "Collector is locally revoked: $RevocationFile. Use -Reactivate only after accountable access approval."
}
if ($Reactivate -and (Test-Path -LiteralPath $RevocationFile)) {
  Remove-Item -LiteralPath $RevocationFile -Force
}

$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
if ($RunAs -in @("System", "ServiceAccount")) {
  $managedIdentityEnabled = [bool]$config.auth.azureCliManagedIdentity
  if (-not $managedIdentityEnabled -and -not $EnvironmentCredentialAvailable) {
    throw "Unattended $RunAs mode requires Azure managed identity or -EnvironmentCredentialAvailable for an OS-injected credential. Secrets must not be stored in config files."
  }
}
if ($RunAs -eq "ServiceAccount" -and [string]::IsNullOrWhiteSpace($ServiceAccount)) {
  throw "-ServiceAccount is required when -RunAs ServiceAccount is selected. Use a least-privilege gMSA or service identity."
}

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$existingTaskXml = if ($null -ne $existingTask) { Export-ScheduledTask -TaskName $TaskName } else { $null }
$existingTaskWasRunning = $null -ne $existingTask -and [string]$existingTask.State -eq "Running"
if ($null -ne $existingTask -and -not $Upgrade) {
  throw "Scheduled task $TaskName already exists. Use -Upgrade for an intentional in-place upgrade."
}
$isExeInstall = -not [string]::IsNullOrWhiteSpace($CollectorExePath)
if ($isExeInstall) {
  if (-not (Test-Path -LiteralPath $CollectorExePath)) {
    throw "Collector EXE not found: $CollectorExePath"
  }
  if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path (Split-Path -Parent $CollectorExePath) "collector-package-manifest.json"
  }
  $verifyScript = Join-Path $PSScriptRoot "verify_patchforge_collector_windows_package.ps1"
  & $verifyScript `
    -CollectorExePath $CollectorExePath `
    -ManifestPath $ManifestPath `
    -AllowUnsignedDevelopmentPackage:$AllowUnsignedDevelopmentPackage | Out-Null

  if ($null -ne $existingTask -and $Upgrade) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  }

  New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
  $installedExe = Join-Path $InstallDirectory "patchforge-collector.exe"
  if ((Test-Path -LiteralPath $installedExe) -and -not $Upgrade) {
    throw "Collector binary already exists at $installedExe. Use -Upgrade for an intentional replacement."
  }
  $backupExe = "$installedExe.previous"
  $stagedExe = "$installedExe.staged"
  Copy-Item -LiteralPath $CollectorExePath -Destination $stagedExe -Force
  try {
    if (Test-Path -LiteralPath $installedExe) {
      Copy-Item -LiteralPath $installedExe -Destination $backupExe -Force
      Remove-Item -LiteralPath $installedExe -Force
    }
    Move-Item -LiteralPath $stagedExe -Destination $installedExe
    Copy-Item -LiteralPath $ManifestPath -Destination (Join-Path $InstallDirectory "collector-package-manifest.json") -Force
  } catch {
    if (Test-Path -LiteralPath $backupExe) {
      Copy-Item -LiteralPath $backupExe -Destination $installedExe -Force
    }
    if ($existingTaskWasRunning) {
      Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    throw
  }
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
  if ($null -ne $existingTask -and $Upgrade) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  }
}

if ($null -ne $existingTask) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action = New-ScheduledTaskAction `
  -Execute $execute `
  -Argument $arguments `
  -WorkingDirectory $workingDirectory

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
  -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

if ($RunAs -eq "System") {
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Limited
  Write-Host "Installing as SYSTEM with limited run level and secretless managed identity or OS-injected credential configuration."
} elseif ($RunAs -eq "ServiceAccount") {
  $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
} else {
  $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
  $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
}

$settings = New-ScheduledTaskSettingsSet `
  -Compatibility Win8 `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 60)

try {
  Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "PatchForge outbound asset evidence collector. No scanning, exploit, patch deployment, production mutation, or autonomous approval." `
    -Force | Out-Null
} catch {
  if ($isExeInstall -and (Test-Path -LiteralPath $backupExe)) {
    Copy-Item -LiteralPath $backupExe -Destination $installedExe -Force
  }
  if (-not [string]::IsNullOrWhiteSpace($existingTaskXml)) {
    Register-ScheduledTask -TaskName $TaskName -Xml $existingTaskXml -Force | Out-Null
    if ($existingTaskWasRunning) {
      Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
  }
  throw
}

if ($isExeInstall -and (Test-Path -LiteralPath $backupExe)) {
  Remove-Item -LiteralPath $backupExe -Force
}

if ($RunNow) {
  Start-ScheduledTask -TaskName $TaskName
}

Write-Host "Installed scheduled task $TaskName."
Write-Host "Executable: $execute"
Write-Host "Config: $ConfigPath"
Write-Host "Run mode: $RunAs"
Write-Host "Lifecycle operation: $(if ($Upgrade) { 'upgrade' } else { 'install' })"

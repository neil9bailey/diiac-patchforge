[CmdletBinding()]
param(
    [int]$ApiPort = 8080,
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$logDir = Join-Path $repoRoot "artifacts/tmp"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

function Start-PatchForgeProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory
    )

    $out = Join-Path $logDir "$Name.out.log"
    $err = Join-Path $logDir "$Name.err.log"
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden `
        -RedirectStandardOutput $out `
        -RedirectStandardError $err `
        -PassThru

    [PSCustomObject]@{
        Name = $Name
        Id = $process.Id
        Output = $out
        Error = $err
    }
}

$api = Start-PatchForgeProcess `
    -Name "patchforge-api" `
    -FilePath "node.exe" `
    -ArgumentList @("backend-api/server.js") `
    -WorkingDirectory $repoRoot

$frontend = Start-PatchForgeProcess `
    -Name "patchforge-frontend" `
    -FilePath "npm.cmd" `
    -ArgumentList @("--prefix", "Frontend", "run", "dev", "--", "--host", "127.0.0.1", "--port", "$FrontendPort") `
    -WorkingDirectory $repoRoot

Start-Sleep -Seconds 3

Write-Host "PatchForge local dev started"
Write-Host "API: http://127.0.0.1:$ApiPort"
Write-Host "Frontend: http://127.0.0.1:$FrontendPort"
Write-Host "Processes:"
$api
$frontend


[CmdletBinding()]
param(
    [string]$TenantId = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    [string]$ApiDisplayName = "DIIaC PatchForge API",
    [string]$UiDisplayName = "DIIaC PatchForge UI",
    [string]$LiveUiRedirectUri = "https://ca-patchforge-ui-prod.lemonpebble-11b2e331.uksouth.azurecontainerapps.io/auth/callback",
    [string]$CustomUiRedirectUri = "https://patchforge.diiac.io/auth/callback",
    [string]$LocalUiRedirectUri = "http://localhost:5173/auth/callback",
    [string]$AdminGroupId = "8a75c082-61b1-433a-9f2b-1ad6fc60540a",
    [string]$StandardGroupId = "8d989893-378e-45e0-ac67-3d1a3acee7c4",
    [string]$OutputPath = "docs/release/evidence/2026-05-26-patchforge-gates/entra-apps.json",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$resolvedOutputPath = Join-Path $repoRoot $OutputPath
$outputDir = Split-Path -Parent $resolvedOutputPath
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

function Invoke-AzRestJson {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)]$Body
    )

    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("patchforge-graph-" + [guid]::NewGuid().ToString() + ".json")
    try {
        $Body | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $tempPath -Encoding UTF8
        az rest --method $Method --url $Url --headers "Content-Type=application/json" --body "@$tempPath" --output none
    }
    finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-AppByDisplayName {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    $apps = az ad app list --display-name $DisplayName --query "[].{appId:appId,id:id,displayName:displayName}" --output json | ConvertFrom-Json
    if ($apps -is [array] -and $apps.Count -gt 0) {
        return $apps[0]
    }
    if ($null -ne $apps -and $apps.appId) {
        return $apps
    }
    return $null
}

function Ensure-App {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    $app = Get-AppByDisplayName -DisplayName $DisplayName
    if ($null -ne $app) {
        return $app
    }

    if (-not $Execute) {
        return [pscustomobject]@{
            appId = "<created-on-execute>"
            id = "<created-on-execute>"
            displayName = $DisplayName
        }
    }

    az ad app create --display-name $DisplayName --sign-in-audience AzureADMyOrg --output json | ConvertFrom-Json
}

function Ensure-ServicePrincipal {
    param([Parameter(Mandatory = $true)][string]$AppId)

    if (-not $Execute) {
        return [pscustomobject]@{
            id = "<created-on-execute>"
            appId = $AppId
        }
    }

    $sp = az ad sp list --filter "appId eq '$AppId'" --query "[0].{id:id,appId:appId,displayName:displayName}" --output json | ConvertFrom-Json
    if ($null -ne $sp -and $sp.id) {
        return $sp
    }

    az ad sp create --id $AppId --output json | ConvertFrom-Json
}

$account = az account show --query "{tenantId:tenantId,subscriptionId:id,user:user.name}" --output json | ConvertFrom-Json
if ($account.tenantId -ne $TenantId) {
    throw "Current Azure tenant '$($account.tenantId)' does not match requested tenant '$TenantId'."
}

$patchForgeRoles = @(
    @{ id = "10632fba-8231-4b78-a31d-df652da97f55"; value = "PatchForge.Reader"; displayName = "PatchForge Reader"; description = "Read PatchForge queues, evidence, packs, and reports." },
    @{ id = "430704a8-870e-40c7-b4de-4283c62607d1"; value = "PatchForge.TriageAnalyst"; displayName = "PatchForge Triage Analyst"; description = "Triage vulnerabilities and request advisory research." },
    @{ id = "eb0c14a2-5fc3-4bd7-8636-3eb7adb52c76"; value = "PatchForge.SecurityLead"; displayName = "PatchForge Security Lead"; description = "Review exploitability, threat context, and security posture decisions." },
    @{ id = "2649a57c-6fba-43ae-8186-b47f97cd9524"; value = "PatchForge.ServiceOwner"; displayName = "PatchForge Service Owner"; description = "Review business service impact and change feasibility." },
    @{ id = "682d9b0e-1c5d-46d9-88ed-a279c58c603c"; value = "PatchForge.CABApprover"; displayName = "PatchForge CAB Approver"; description = "Record CAB approval events for governed patch decisions." },
    @{ id = "06687056-bb28-4cac-b68d-ab3dde96e097"; value = "PatchForge.RiskOwner"; displayName = "PatchForge Risk Owner"; description = "Own temporary risk acceptances and expiry reviews." },
    @{ id = "99a124f9-128f-43ae-b54a-f50aa7578259"; value = "PatchForge.Admin"; displayName = "PatchForge Admin"; description = "Administer PatchForge tenant settings, policy, integrations, and trust configuration." },
    @{ id = "613541e3-6973-42d8-a26d-e3492612cd13"; value = "PatchForge.Auditor"; displayName = "PatchForge Auditor"; description = "Review signed decision packs, audit events, and evidence registers." }
)

$appRoles = @($patchForgeRoles | ForEach-Object {
    @{
        allowedMemberTypes = @("User")
        description = $_["description"]
        displayName = $_["displayName"]
        id = $_["id"]
        isEnabled = $true
        value = $_["value"]
    }
})

$accessScopeId = "3bec314e-34ab-4e19-b209-dfdb3e057e24"

$apiApp = Ensure-App -DisplayName $ApiDisplayName
$uiApp = Ensure-App -DisplayName $UiDisplayName

if ($Execute) {
    $apiPatch = @{
        identifierUris = @("api://$($apiApp.appId)")
        appRoles = $appRoles
        api = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes = @(
                @{
                    adminConsentDescription = "Allow PatchForge UI to call the PatchForge API as the signed-in user."
                    adminConsentDisplayName = "Access PatchForge API"
                    id = $accessScopeId
                    isEnabled = $true
                    type = "User"
                    userConsentDescription = "Allow PatchForge UI to call the PatchForge API as you."
                    userConsentDisplayName = "Access PatchForge API"
                    value = "PatchForge.Access"
                }
            )
        }
    }
    Invoke-AzRestJson -Method PATCH -Url "https://graph.microsoft.com/v1.0/applications/$($apiApp.id)" -Body $apiPatch

    $uiPatch = @{
        appRoles = $appRoles
        spa = @{
            redirectUris = @($LiveUiRedirectUri, $CustomUiRedirectUri, $LocalUiRedirectUri)
        }
        requiredResourceAccess = @(
            @{
                resourceAppId = $apiApp.appId
                resourceAccess = @(
                    @{
                        id = $accessScopeId
                        type = "Scope"
                    }
                )
            }
        )
    }
    Invoke-AzRestJson -Method PATCH -Url "https://graph.microsoft.com/v1.0/applications/$($uiApp.id)" -Body $uiPatch
}

$apiSp = Ensure-ServicePrincipal -AppId $apiApp.appId
$uiSp = Ensure-ServicePrincipal -AppId $uiApp.appId

$assignmentResults = @()
if ($Execute) {
    foreach ($targetSp in @($apiSp, $uiSp)) {
        $spPatch = @{ appRoleAssignmentRequired = $true }
        Invoke-AzRestJson -Method PATCH -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$($targetSp.id)" -Body $spPatch

        $assignments = @(
            @{ groupId = $AdminGroupId; roleValue = "PatchForge.Admin" },
            @{ groupId = $StandardGroupId; roleValue = "PatchForge.Reader" }
        )

        foreach ($assignment in $assignments) {
            $role = $patchForgeRoles | Where-Object { $_["value"] -eq $assignment.roleValue } | Select-Object -First 1
            $existing = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$($targetSp.id)/appRoleAssignedTo" --output json | ConvertFrom-Json
            $alreadyAssigned = $false
            if ($existing.value) {
                $alreadyAssigned = @($existing.value | Where-Object { $_.principalId -eq $assignment.groupId -and $_.appRoleId -eq $role["id"] }).Count -gt 0
            }

            if (-not $alreadyAssigned) {
                $body = @{
                    principalId = $assignment.groupId
                    resourceId = $targetSp.id
                    appRoleId = $role["id"]
                }
                Invoke-AzRestJson -Method POST -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$($targetSp.id)/appRoleAssignedTo" -Body $body
                $status = "created"
            }
            else {
                $status = "already_present"
            }

            $assignmentResults += [pscustomobject]@{
                servicePrincipalId = $targetSp.id
                groupId = $assignment.groupId
                role = $assignment.roleValue
                status = $status
            }
        }
    }

    try {
        az ad app permission admin-consent --id $uiApp.appId --output none
        $adminConsentStatus = "granted_or_already_present"
    }
    catch {
        $adminConsentStatus = "not_granted_by_script: $($_.Exception.Message)"
    }
}
else {
    $adminConsentStatus = "dry_run"
}

$result = [pscustomobject]@{
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    tenant_id = $TenantId
    api_app = [pscustomobject]@{
        display_name = $ApiDisplayName
        app_id = $apiApp.appId
        object_id = $apiApp.id
        service_principal_id = $apiSp.id
        identifier_uri = "api://$($apiApp.appId)"
        access_scope = "PatchForge.Access"
        access_scope_id = $accessScopeId
    }
    ui_app = [pscustomobject]@{
        display_name = $UiDisplayName
        app_id = $uiApp.appId
        object_id = $uiApp.id
        service_principal_id = $uiSp.id
        redirect_uris = @($LiveUiRedirectUri, $CustomUiRedirectUri, $LocalUiRedirectUri)
    }
    app_roles = @($patchForgeRoles | ForEach-Object {
        [pscustomobject]@{
            value = $_["value"]
            display_name = $_["displayName"]
            id = $_["id"]
        }
    })
    assignments = $assignmentResults
    admin_consent = $adminConsentStatus
    executed = [bool]$Execute
}

$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $resolvedOutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 20

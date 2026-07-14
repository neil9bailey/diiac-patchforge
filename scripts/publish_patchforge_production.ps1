[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [string]$ImageTag,

    [Parameter(Mandatory = $true)]
    [string]$ProductBaseline,

    [Parameter(Mandatory = $true)]
    [string]$ReportContextVersion,

    [string]$ApprovalRunId = "",
    [string]$ApprovalRepository = "neil9bailey/diiac-patchforge",
    [string]$ApprovedRef = "refs/heads/main",
    [string]$SubscriptionId = "9ae9da49-de67-443b-af55-ce9db33ed8f4",
    [string]$TenantId = "67f8be6c-07da-4a7c-bb0a-d6bcb38cd6da",
    [string]$RegistryName = "acrdiiacpatchforgeprod",
    [string]$ResourceGroup = "rg-diiac-patchforge-prod",
    [string]$KeyVaultName = "kv-diiac-patchforge-prod",
    [string]$SigningKeyName = "pf-pack-signing-prod",
    [string]$RepositoryRoot = "",
    [string]$EvidenceRoot = "",
    [ValidateRange(60, 3600)]
    [int]$ReadinessTimeoutSeconds = 900,
    [ValidateRange(2, 60)]
    [int]$PollIntervalSeconds = 10,
    [switch]$Execute,
    [switch]$ApproveTargetedImageOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$apps = @(
    [pscustomobject]@{ App = "ca-patchforge-runtime-prod"; Repository = "diiac/patchforge-runtime" },
    [pscustomobject]@{ App = "ca-patchforge-sra-prod"; Repository = "diiac/patchforge-sra-agent" },
    [pscustomobject]@{ App = "ca-patchforge-worker-prod"; Repository = "diiac/patchforge-ingest-worker" },
    [pscustomobject]@{ App = "ca-patchforge-scheduler-prod"; Repository = "diiac/patchforge-scheduler" },
    [pscustomobject]@{ App = "ca-patchforge-bridge-prod"; Repository = "diiac/patchforge-bridge" },
    [pscustomobject]@{ App = "ca-patchforge-ui-prod"; Repository = "diiac/patchforge-frontend" }
)

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
}

function Test-PathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $candidatePath = Get-NormalizedPath -Path $Candidate
    $parentPath = Get-NormalizedPath -Path $Parent
    if ($candidatePath.Equals($parentPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $parentPath + [System.IO.Path]::DirectorySeparatorChar
    return $candidatePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        & $Command @Arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
        $stdout = [System.IO.File]::ReadAllText($stdoutPath)
        $stderr = [System.IO.File]::ReadAllText($stderrPath)
        if (($exitCode -ne 0) -and (-not $AllowFailure)) {
            $detail = $stderr.Trim()
            if ([string]::IsNullOrWhiteSpace($detail)) {
                $detail = $stdout.Trim()
            }
            if ($detail.Length -gt 1200) {
                $detail = $detail.Substring(0, 1200) + "..."
            }
            throw "$Command failed with exit code $exitCode. $detail"
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            StdOut = $stdout
            StdErr = $stderr
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-NativeStreaming {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

function Invoke-AzJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $result = Invoke-NativeCapture -Command "az" -Arguments ($Arguments + @("--only-show-errors", "--output", "json"))
    if ([string]::IsNullOrWhiteSpace($result.StdOut)) {
        return $null
    }
    try {
        return $result.StdOut | ConvertFrom-Json
    }
    catch {
        throw "Azure CLI returned invalid JSON for 'az $($Arguments -join ' ')'."
    }
}

function Invoke-AzText {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $result = Invoke-NativeCapture -Command "az" -Arguments ($Arguments + @("--only-show-errors", "--output", "tsv"))
    return $result.StdOut.Trim()
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-Sha256Record {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash($bytes)
    }
    finally {
        $sha.Dispose()
    }
    $hex = ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
    return [pscustomobject]@{
        Hex = $hex
        Base64 = [Convert]::ToBase64String($digest)
        Bytes = $bytes.LongLength
    }
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-KeyVaultSignatureValue {
    param([Parameter(Mandatory = $true)]$SignResult)

    if ($SignResult -is [string] -and -not [string]::IsNullOrWhiteSpace($SignResult)) {
        return $SignResult
    }
    foreach ($propertyName in @("signature", "result", "value")) {
        $candidate = Get-ObjectPropertyValue -Object $SignResult -Name $propertyName
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            return [string]$candidate
        }
    }
    return $null
}

function Test-KeyVaultVerificationResult {
    param([Parameter(Mandatory = $true)]$VerifyResult)

    if ($VerifyResult -is [bool]) {
        return $VerifyResult
    }
    foreach ($propertyName in @("isValid", "value", "result")) {
        $candidate = Get-ObjectPropertyValue -Object $VerifyResult -Name $propertyName
        if ($null -ne $candidate) {
            return $candidate -eq $true
        }
    }
    return $false
}

function Assert-ReleaseInputs {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    if ($Commit -cnotmatch "^[a-f0-9]{40}$") {
        throw "Commit must be a full lowercase 40-character Git SHA-1."
    }
    if (($ImageTag.Length -gt 128) -or ($ImageTag -cnotmatch "^[a-z0-9][a-z0-9._-]{7,127}$")) {
        throw "ImageTag must be an immutable lowercase Docker tag between 8 and 128 characters."
    }
    if (($ImageTag -match "latest") -or ($ImageTag -match "bootstrap")) {
        throw "ImageTag must not contain 'latest' or 'bootstrap'."
    }
    if (-not $ImageTag.Contains($Commit.Substring(0, 7))) {
        throw "ImageTag must contain the first seven characters of Commit ($($Commit.Substring(0, 7)))."
    }
    if (($ProductBaseline.Length -gt 128) -or ($ProductBaseline -cnotmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) {
        throw "ProductBaseline contains unsupported characters or is too long."
    }
    if (($ReportContextVersion.Length -gt 128) -or ($ReportContextVersion -cnotmatch "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) {
        throw "ReportContextVersion contains unsupported characters or is too long."
    }

    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $git) {
        throw "Git is required."
    }
    $head = (Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "rev-parse", "HEAD")).StdOut.Trim().ToLowerInvariant()
    if ($head -ne $Commit) {
        throw "Commit '$Commit' does not match repository HEAD '$head'."
    }
    $trackedStatus = (Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "status", "--porcelain", "--untracked-files=no")).StdOut.Trim()
    if (-not [string]::IsNullOrWhiteSpace($trackedStatus)) {
        Write-Host $trackedStatus
        throw "Tracked worktree changes are present. Commit, restore, or intentionally exclude them before release."
    }
    $branch = (Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "symbolic-ref", "--quiet", "--short", "HEAD")).StdOut.Trim()
    if ([string]::IsNullOrWhiteSpace($branch)) {
        throw "Detached HEAD releases are not allowed."
    }
    return $branch
}

function Assert-RemoteHead {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )
    $upstreamResult = Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}") -AllowFailure
    if ($upstreamResult.ExitCode -ne 0) {
        throw "The current branch has no upstream. Push it and configure an upstream before release."
    }
    $upstream = $upstreamResult.StdOut.Trim()
    $separator = $upstream.IndexOf("/")
    if ($separator -lt 1) {
        throw "Unable to parse upstream '$upstream'."
    }
    $remote = $upstream.Substring(0, $separator)
    $remoteBranch = $upstream.Substring($separator + 1)
    $localUpstream = (Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "rev-parse", $upstream)).StdOut.Trim().ToLowerInvariant()
    if ($localUpstream -ne $ExpectedCommit) {
        throw "Local upstream '$upstream' is at '$localUpstream', not the release commit '$ExpectedCommit'."
    }
    $remoteResult = Invoke-NativeCapture -Command "git" -Arguments @("-C", $RepoRoot, "ls-remote", "--heads", $remote, "refs/heads/$remoteBranch")
    $remoteLine = ($remoteResult.StdOut -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($remoteLine)) {
        throw "Remote branch '$upstream' was not found."
    }
    $remoteCommit = ($remoteLine -split "\s+")[0].ToLowerInvariant()
    if ($remoteCommit -ne $ExpectedCommit) {
        throw "Remote branch '$upstream' is at '$remoteCommit', not the release commit '$ExpectedCommit'."
    }
    return $upstream
}

function Assert-AzureContext {
    $account = Invoke-AzJson -Arguments @("account", "show", "--query", "{id:id,tenantId:tenantId,name:name}")
    if (($account.id -ne $SubscriptionId) -or ($account.tenantId -ne $TenantId)) {
        throw "Azure CLI context mismatch. Expected tenant '$TenantId' and subscription '$SubscriptionId'; no automatic context switch was performed."
    }
    return $account
}

function Assert-NewAcrTag {
    foreach ($app in $apps) {
        $existing = Invoke-AzText -Arguments @(
            "acr", "repository", "show-tags",
            "--name", $RegistryName,
            "--repository", $app.Repository,
            "--query", "[?@=='$ImageTag'] | [0]"
        )
        if (-not [string]::IsNullOrWhiteSpace($existing)) {
            throw "Refusing to reuse ACR tag '$ImageTag' in '$($app.Repository)'."
        }
    }
}

function Assert-GitHubReleaseAuthorization {
    param([Parameter(Mandatory = $true)][string]$ReleaseDirectory)

    if ($ApprovalRunId -cnotmatch "^[0-9]+$") {
        throw "-ApprovalRunId is required with -Execute and must be a GitHub Actions run ID."
    }
    if ($ApprovalRepository -cnotmatch "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$") {
        throw "ApprovalRepository must be an owner/repository pair."
    }
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if ($null -eq $gh) {
        throw "GitHub CLI is required to verify production release authorization."
    }

    $environmentJson = (Invoke-NativeCapture -Command "gh" -Arguments @(
        "api", "repos/$ApprovalRepository/environments/production"
    )).StdOut | ConvertFrom-Json
    $reviewRule = @($environmentJson.protection_rules | Where-Object { $_.type -eq "required_reviewers" }) | Select-Object -First 1
    $configuredReviewers = if ($null -eq $reviewRule) { @() } else { @($reviewRule.reviewers) }
    if (($environmentJson.name -ne "production") -or ($configuredReviewers.Count -lt 1)) {
        throw "The GitHub production environment must exist and require at least one explicit reviewer before a release can be authorized."
    }

    $runJson = (Invoke-NativeCapture -Command "gh" -Arguments @(
        "run", "view", $ApprovalRunId,
        "--repo", $ApprovalRepository,
        "--json", "databaseId,headSha,conclusion,event,workflowName,url"
    )).StdOut | ConvertFrom-Json
    if (($runJson.conclusion -ne "success") -or ($runJson.event -ne "workflow_dispatch") -or ($runJson.workflowName -ne "PatchForge production release approval")) {
        throw "GitHub approval run '$ApprovalRunId' is not a successful workflow_dispatch of the production release approval workflow."
    }

    $approvalDirectory = Join-Path $ReleaseDirectory "release-approval"
    New-Item -ItemType Directory -Path $approvalDirectory -Force | Out-Null
    Invoke-NativeStreaming -Command "gh" -Arguments @(
        "run", "download", $ApprovalRunId,
        "--repo", $ApprovalRepository,
        "--name", "patchforge-production-release-$ImageTag",
        "--dir", $approvalDirectory
    )

    $authorizationFiles = @(Get-ChildItem -LiteralPath $approvalDirectory -Recurse -File -Filter "release-authorization.json")
    $checksumFiles = @(Get-ChildItem -LiteralPath $approvalDirectory -Recurse -File -Filter "SHA256SUMS")
    if (($authorizationFiles.Count -ne 1) -or ($checksumFiles.Count -ne 1)) {
        throw "The approval artifact must contain exactly one release-authorization.json and one SHA256SUMS file."
    }
    $authorizationPath = $authorizationFiles[0].FullName
    $checksumLine = ([System.IO.File]::ReadAllText($checksumFiles[0].FullName) -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
    if ($checksumLine -notmatch "^(?<digest>[a-f0-9]{64})\s+\*?.*release-authorization\.json$") {
        throw "Approval artifact SHA256SUMS is malformed."
    }
    $authorizationHash = Get-Sha256Record -Path $authorizationPath
    if ($authorizationHash.Hex -ne $Matches.digest) {
        throw "Approval artifact checksum mismatch."
    }

    $attestationResult = Invoke-NativeCapture -Command "gh" -Arguments @(
        "attestation", "verify", $authorizationPath,
        "--repo", $ApprovalRepository,
        "--signer-workflow", "$ApprovalRepository/.github/workflows/production-release-approval.yml",
        "--source-ref", $ApprovedRef,
        "--source-digest", [string]$runJson.headSha,
        "--format", "json"
    )
    if ([string]::IsNullOrWhiteSpace($attestationResult.StdOut)) {
        throw "GitHub attestation verification succeeded but returned no verification evidence."
    }
    try {
        $verifiedAttestations = $attestationResult.StdOut | ConvertFrom-Json
    }
    catch {
        throw "GitHub attestation verification returned invalid JSON evidence."
    }
    if (@($verifiedAttestations).Count -lt 1) {
        throw "GitHub attestation verification returned no verified attestations."
    }
    Write-Utf8NoBom -Path (Join-Path $approvalDirectory "attestation-verification.json") -Content $attestationResult.StdOut

    $authorization = [System.IO.File]::ReadAllText($authorizationPath) | ConvertFrom-Json
    $expected = [ordered]@{
        schema = "patchforge-production-release-authorization-v1"
        repository = $ApprovalRepository
        source_commit = $Commit
        image_tag = $ImageTag
        product_baseline = $ProductBaseline
        report_context_version = $ReportContextVersion
        approved_ref = $ApprovedRef
        run_id = $ApprovalRunId
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $actual = Get-ObjectPropertyValue -Object $authorization -Name $entry.Key
        if ([string]$actual -cne [string]$entry.Value) {
            throw "Approval field '$($entry.Key)' does not match the requested production release."
        }
    }
    if ((Get-ObjectPropertyValue -Object $authorization -Name "explicit_environment_approval") -ne $true) {
        throw "Approval artifact does not record explicit production-environment approval."
    }
    if ([string]::IsNullOrWhiteSpace([string](Get-ObjectPropertyValue -Object $authorization -Name "approved_by"))) {
        throw "Approval artifact does not identify the approver."
    }
    if ([string]$runJson.databaseId -ne $ApprovalRunId) {
        throw "Downloaded approval run ID does not match -ApprovalRunId."
    }

    return [pscustomobject]@{
        RunId = $ApprovalRunId
        RunUrl = $runJson.url
        ApprovedBy = $authorization.approved_by
        ApprovedRef = $authorization.approved_ref
        CreatedAt = $authorization.created_at
        AuthorizationSha256 = $authorizationHash.Hex
        AttestationVerified = $true
        ProductionEnvironmentReviewerCount = $configuredReviewers.Count
    }
}

function Get-AppSnapshot {
    param([Parameter(Mandatory = $true)]$AppDefinition)

    $stateQuery = "{name:name,provisioningState:properties.provisioningState,runningStatus:properties.runningStatus,activeRevisionsMode:properties.configuration.activeRevisionsMode,latestRevisionName:properties.latestRevisionName,latestReadyRevisionName:properties.latestReadyRevisionName,image:properties.template.containers[0].image,traffic:properties.configuration.ingress.traffic[].{revisionName:revisionName,weight:weight,latestRevision:latestRevision}}"
    $revisionQuery = "[].{name:name,active:properties.active,healthState:properties.healthState,provisioningState:properties.provisioningState,runningState:properties.runningState,trafficWeight:properties.trafficWeight,image:properties.template.containers[0].image}"
    $configQuery = "{environmentId:properties.environmentId,workloadProfileName:properties.workloadProfileName,identity:{type:identity.type,userAssignedIdentities:identity.userAssignedIdentities},ingress:{external:properties.configuration.ingress.external,targetPort:properties.configuration.ingress.targetPort,transport:properties.configuration.ingress.transport,allowInsecure:properties.configuration.ingress.allowInsecure,clientCertificateMode:properties.configuration.ingress.clientCertificateMode,customDomains:properties.configuration.ingress.customDomains[].{name:name,bindingType:bindingType}},dapr:{enabled:properties.configuration.dapr.enabled,appId:properties.configuration.dapr.appId,appPort:properties.configuration.dapr.appPort,appProtocol:properties.configuration.dapr.appProtocol},registries:properties.configuration.registries[].{server:server,identity:identity},secretNames:properties.configuration.secrets[].name,containers:properties.template.containers[].{name:name,cpu:resources.cpu,memory:resources.memory,env:env[].{name:name,secretRef:secretRef}},scale:{minReplicas:properties.template.scale.minReplicas,maxReplicas:properties.template.scale.maxReplicas}}"

    $state = Invoke-AzJson -Arguments @("containerapp", "show", "--resource-group", $ResourceGroup, "--name", $AppDefinition.App, "--query", $stateQuery)
    $revisions = Invoke-AzJson -Arguments @("containerapp", "revision", "list", "--resource-group", $ResourceGroup, "--name", $AppDefinition.App, "--all", "--query", $revisionQuery)
    $configuration = Invoke-AzJson -Arguments @("containerapp", "show", "--resource-group", $ResourceGroup, "--name", $AppDefinition.App, "--query", $configQuery)

    return [pscustomobject]@{
        state = $state
        revisions = @($revisions)
        configurationGuard = $configuration
    }
}

function Assert-AppReady {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExpectedImage,
        [Parameter(Mandatory = $true)][string]$AppName
    )

    $state = $Snapshot.state
    $problems = New-Object System.Collections.Generic.List[string]
    if ($state.provisioningState -ne "Succeeded") { $problems.Add("provisioningState=$($state.provisioningState)") }
    if ($state.runningStatus -ne "Running") { $problems.Add("runningStatus=$($state.runningStatus)") }
    if ($state.activeRevisionsMode -ne "Single") { $problems.Add("activeRevisionsMode=$($state.activeRevisionsMode)") }
    if ($state.image -cne $ExpectedImage) { $problems.Add("configured image mismatch") }
    if ([string]::IsNullOrWhiteSpace([string]$state.latestRevisionName)) { $problems.Add("latest revision is missing") }
    if ($state.latestRevisionName -ne $state.latestReadyRevisionName) { $problems.Add("latest revision is not latest-ready") }

    $active = @($Snapshot.revisions | Where-Object { $_.active -eq $true })
    if ($active.Count -ne 1) {
        $problems.Add("active revision count=$($active.Count)")
    }
    else {
        $revision = $active[0]
        if ($revision.name -ne $state.latestReadyRevisionName) { $problems.Add("active revision is not latest-ready") }
        if ($revision.image -cne $ExpectedImage) { $problems.Add("active revision image mismatch") }
        if ($revision.healthState -ne "Healthy") { $problems.Add("healthState=$($revision.healthState)") }
        if ($revision.provisioningState -ne "Provisioned") { $problems.Add("revision provisioningState=$($revision.provisioningState)") }
        if (@("Running", "ScaledToZero") -notcontains $revision.runningState) { $problems.Add("runningState=$($revision.runningState)") }
    }

    $traffic = @($state.traffic)
    if ($traffic.Count -ne 1) {
        $problems.Add("traffic target count=$($traffic.Count)")
    }
    else {
        $target = $traffic[0]
        if ([int]$target.weight -ne 100) { $problems.Add("traffic weight=$($target.weight)") }
        $targetsLatest = (($target.latestRevision -eq $true) -or ($target.revisionName -eq $state.latestReadyRevisionName))
        if (-not $targetsLatest) { $problems.Add("traffic does not target latest-ready") }
    }

    if ($problems.Count -gt 0) {
        throw "$AppName failed readiness: $($problems -join '; ')."
    }
}

function Wait-AppReady {
    param(
        [Parameter(Mandatory = $true)]$AppDefinition,
        [Parameter(Mandatory = $true)][string]$ExpectedImage,
        [Parameter(Mandatory = $true)]$ExpectedConfiguration
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($ReadinessTimeoutSeconds)
    $lastError = "no readback completed"
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $snapshot = Get-AppSnapshot -AppDefinition $AppDefinition
            Assert-AppReady -Snapshot $snapshot -ExpectedImage $ExpectedImage -AppName $AppDefinition.App
            $beforeGuard = $ExpectedConfiguration | ConvertTo-Json -Depth 20 -Compress
            $afterGuard = $snapshot.configurationGuard | ConvertTo-Json -Depth 20 -Compress
            if ($beforeGuard -cne $afterGuard) {
                throw "$($AppDefinition.App) non-image configuration guard changed."
            }
            return $snapshot
        }
        catch {
            $lastError = $_.Exception.Message
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }
    throw "$($AppDefinition.App) did not become ready within $ReadinessTimeoutSeconds seconds. Last result: $lastError"
}

function Backup-CurrentImages {
    param(
        [Parameter(Mandatory = $true)]$BeforeSnapshots,
        [Parameter(Mandatory = $true)][string]$BackupDirectory
    )

    New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    $records = @()
    $loginServer = "$RegistryName.azurecr.io"
    foreach ($app in $apps) {
        $image = $BeforeSnapshots[$app.App].state.image
        $expectedPrefix = "$loginServer/$($app.Repository)"
        if (-not $image.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Current image '$image' for '$($app.App)' is outside expected repository '$expectedPrefix'."
        }
        Write-Host "Backing up current image for $($app.App): $image"
        Invoke-NativeStreaming -Command "docker" -Arguments @("pull", $image)
        $repoDigestsResult = Invoke-NativeCapture -Command "docker" -Arguments @("image", "inspect", $image, "--format", "{{json .RepoDigests}}")
        $repoDigests = @()
        if (-not [string]::IsNullOrWhiteSpace($repoDigestsResult.StdOut)) {
            $repoDigests = @($repoDigestsResult.StdOut.Trim() | ConvertFrom-Json)
        }
        if ($repoDigests.Count -lt 1) {
            throw "No repository digest was available for rollback image '$image'."
        }
        $archivePath = Join-Path $BackupDirectory "$($app.App).docker-image.tar"
        Invoke-NativeStreaming -Command "docker" -Arguments @("save", "--output", $archivePath, $image)
        $archiveHash = Get-Sha256Record -Path $archivePath
        $records += [pscustomobject][ordered]@{
            app = $app.App
            repository = $app.Repository
            image = $image
            repo_digests = $repoDigests
            archive = [System.IO.Path]::GetFileName($archivePath)
            archive_sha256 = $archiveHash.Hex
            archive_bytes = $archiveHash.Bytes
        }
    }
    return $records
}

function Get-PushedImageRecords {
    $records = @()
    $loginServer = "$RegistryName.azurecr.io"
    foreach ($app in $apps) {
        $digest = Invoke-AzText -Arguments @(
            "acr", "repository", "show",
            "--name", $RegistryName,
            "--image", "$($app.Repository):$ImageTag",
            "--query", "digest"
        )
        if ($digest -cnotmatch "^sha256:[a-f0-9]{64}$") {
            throw "ACR did not return a valid digest for '$($app.Repository):$ImageTag'."
        }
        $fullImage = "$loginServer/$($app.Repository):$ImageTag"
        $inspect = Invoke-NativeCapture -Command "docker" -Arguments @("image", "inspect", $fullImage, "--format", "{{json .RepoDigests}}")
        $repoDigests = @($inspect.StdOut.Trim() | ConvertFrom-Json)
        if (@($repoDigests | Where-Object { $_ -eq "$loginServer/$($app.Repository)@$digest" }).Count -ne 1) {
            throw "Local Docker/ACR digest readback mismatch for '$fullImage'."
        }
        $records += [pscustomobject][ordered]@{
            app = $app.App
            repository = $app.Repository
            image = $fullImage
            digest = $digest
        }
    }
    return $records
}

function Get-ProductionSigningKey {
    $key = Invoke-AzJson -Arguments @(
        "keyvault", "key", "show",
        "--vault-name", $KeyVaultName,
        "--name", $SigningKeyName,
        "--query", "{id:key.kid,kty:key.kty,crv:key.crv,keyOps:key.keyOps,enabled:attributes.enabled}"
    )
    if (($key.enabled -ne $true) -or ($key.kty -ne "EC") -or ($key.crv -ne "P-256")) {
        throw "Production signing key is not an enabled P-256 EC key."
    }
    if ((@($key.keyOps) -notcontains "sign") -or (@($key.keyOps) -notcontains "verify")) {
        throw "Production signing key does not permit both sign and verify."
    }
    return $key
}

function Assert-KeyVaultSigningPreflight {
    try {
        $key = Get-ProductionSigningKey
        $challenge = "patchforge-release-signing-preflight|$Commit|$ImageTag|$ProductBaseline|$ReportContextVersion"
        $challengeBytes = [System.Text.Encoding]::UTF8.GetBytes($challenge)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($challengeBytes)
        }
        finally {
            $sha.Dispose()
        }
        $digestBase64 = [Convert]::ToBase64String($digest)
        $signResult = Invoke-AzJson -Arguments @(
            "keyvault", "key", "sign",
            "--id", $key.id,
            "--algorithm", "ES256",
            "--digest", $digestBase64
        )
        $signature = Get-KeyVaultSignatureValue -SignResult $signResult
        if ([string]::IsNullOrWhiteSpace([string]$signature)) {
            throw "Key Vault did not return a preflight signature."
        }
        $verifyResult = Invoke-AzJson -Arguments @(
            "keyvault", "key", "verify",
            "--id", $key.id,
            "--algorithm", "ES256",
            "--digest", $digestBase64,
            "--signature", [string]$signature
        )
        $verified = Test-KeyVaultVerificationResult -VerifyResult $verifyResult
        if (-not $verified) {
            throw "Key Vault rejected the preflight signature verification."
        }
        return [pscustomobject][ordered]@{
            key_id = $key.id
            algorithm = "ES256"
            verified = $true
            checked_at_utc = [DateTime]::UtcNow.ToString("o")
        }
    }
    catch {
        throw "Key Vault signing preflight failed before image build or Azure app mutation. The release identity requires Key Vault Crypto User (role 12338af0-0e69-4776-bea7-57ae8d297424) at the '$SigningKeyName' key scope, preferably time-bound and revoked after release evidence is complete. Original error: $($_.Exception.Message)"
    }
}

function New-SignedImageManifest {
    param(
        [Parameter(Mandatory = $true)]$ImageRecords,
        [Parameter(Mandatory = $true)][string]$ReleaseDirectory
    )

    $sortedImages = @($ImageRecords | Sort-Object -Property repository)
    $manifest = [ordered]@{
        schema = "patchforge-six-image-provenance-v1"
        product = "DIIaC PatchForge"
        product_baseline = $ProductBaseline
        report_context_version = $ReportContextVersion
        source_commit = $Commit
        image_tag = $ImageTag
        registry = "$RegistryName.azurecr.io"
        images = $sortedImages
    }
    $manifestPath = Join-Path $ReleaseDirectory "six-image-digest-manifest.json"
    $manifestJson = ($manifest | ConvertTo-Json -Depth 12 -Compress) + "`n"
    Write-Utf8NoBom -Path $manifestPath -Content $manifestJson
    $hash = Get-Sha256Record -Path $manifestPath

    $key = Get-ProductionSigningKey

    $signResult = Invoke-AzJson -Arguments @(
        "keyvault", "key", "sign",
        "--id", $key.id,
        "--algorithm", "ES256",
        "--digest", $hash.Base64
    )
    $signature = Get-KeyVaultSignatureValue -SignResult $signResult
    if ([string]::IsNullOrWhiteSpace([string]$signature)) {
        throw "Key Vault did not return a signature."
    }

    $readbackHash = Get-Sha256Record -Path $manifestPath
    if ($readbackHash.Hex -ne $hash.Hex) {
        throw "Canonical digest manifest changed before signature verification."
    }
    $verifyResult = Invoke-AzJson -Arguments @(
        "keyvault", "key", "verify",
        "--id", $key.id,
        "--algorithm", "ES256",
        "--digest", $readbackHash.Base64,
        "--signature", [string]$signature
    )
    $verified = Test-KeyVaultVerificationResult -VerifyResult $verifyResult
    if (-not $verified) {
        throw "Key Vault ES256 signature verification failed."
    }

    $signatureRecord = [ordered]@{
        schema = "patchforge-six-image-provenance-signature-v1"
        manifest_file = [System.IO.Path]::GetFileName($manifestPath)
        manifest_sha256 = $hash.Hex
        digest_base64 = $hash.Base64
        algorithm = "ES256"
        key_id = $key.id
        signature_base64 = [string]$signature
        verified = $true
        signed_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    $signaturePath = Join-Path $ReleaseDirectory "six-image-digest-manifest.signature.json"
    Write-Utf8NoBom -Path $signaturePath -Content (($signatureRecord | ConvertTo-Json -Depth 8) + "`n")

    return [pscustomobject]@{
        ManifestPath = $manifestPath
        SignaturePath = $signaturePath
        ManifestSha256 = $hash.Hex
        KeyId = $key.id
        Verified = $true
    }
}

function Invoke-PublicSmoke {
    $checks = @(
        [pscustomobject]@{ Name = "ui"; Url = "https://patchforge.diiac.io/"; ExpectedStatus = 200; Readiness = $false },
        [pscustomobject]@{ Name = "api-health"; Url = "https://api.patchforge.diiac.io/health"; ExpectedStatus = 200; Readiness = $false },
        [pscustomobject]@{ Name = "api-readiness"; Url = "https://api.patchforge.diiac.io/readiness"; ExpectedStatus = 200; Readiness = $true },
        [pscustomobject]@{ Name = "protected-route"; Url = "https://api.patchforge.diiac.io/api/patchforge/security-action-center"; ExpectedStatus = 401; Readiness = $false }
    )
    $results = @()
    foreach ($check in $checks) {
        $status = 0
        $body = ""
        try {
            $response = Invoke-WebRequest -Uri $check.Url -Method Get -UseBasicParsing -TimeoutSec 30 -MaximumRedirection 5
            $status = [int]$response.StatusCode
            $body = [string]$response.Content
        }
        catch {
            $errorResponse = $_.Exception.Response
            if ($null -ne $errorResponse) {
                $status = [int]$errorResponse.StatusCode
            }
        }
        if ($status -ne $check.ExpectedStatus) {
            throw "Public smoke '$($check.Name)' returned HTTP $status; expected $($check.ExpectedStatus)."
        }
        $readinessSummary = $null
        if ($check.Readiness) {
            try {
                $readiness = $body | ConvertFrom-Json
            }
            catch {
                throw "Readiness response was not valid JSON."
            }
            if (($readiness.status -ne "ready") -or ($readiness.storage -ne "postgresql") -or ($readiness.auth_required -ne $true) -or ($readiness.tenant_required -ne $true)) {
                throw "Readiness did not report ready PostgreSQL storage with auth and tenant enforcement."
            }
            $readinessSummary = [ordered]@{
                status = $readiness.status
                storage = $readiness.storage
                auth_required = $readiness.auth_required
                tenant_required = $readiness.tenant_required
            }
        }
        $results += [pscustomobject][ordered]@{
            name = $check.Name
            url = $check.Url
            expected_status = $check.ExpectedStatus
            actual_status = $status
            readiness = $readinessSummary
            checked_at_utc = [DateTime]::UtcNow.ToString("o")
        }
    }
    return $results
}

function Write-ReleaseRecord {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$Path
    )
    Write-Utf8NoBom -Path $Path -Content (($Record | ConvertTo-Json -Depth 30) + "`n")
}

$resolvedRepositoryRoot = if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}
else {
    (Resolve-Path $RepositoryRoot).Path
}
$resolvedRepositoryRoot = Get-NormalizedPath -Path $resolvedRepositoryRoot

$validateScript = Join-Path $resolvedRepositoryRoot "scripts/validate_iac.ps1"
$buildScript = Join-Path $resolvedRepositoryRoot "scripts/build_push_images.ps1"
foreach ($requiredScript in @($validateScript, $buildScript)) {
    if (-not (Test-Path -LiteralPath $requiredScript -PathType Leaf)) {
        throw "Required release helper is missing: $requiredScript"
    }
}

$branch = Assert-ReleaseInputs -RepoRoot $resolvedRepositoryRoot
$artifactBase = if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    Join-Path (Split-Path $resolvedRepositoryRoot -Parent) "patchforge-release-artifacts"
}
else {
    $EvidenceRoot
}
$artifactBase = Get-NormalizedPath -Path $artifactBase
if (Test-PathInside -Candidate $artifactBase -Parent $resolvedRepositoryRoot) {
    throw "EvidenceRoot must be outside the Git repository so rollback images and signatures cannot be committed accidentally."
}

$loginServer = "$RegistryName.azurecr.io"
Write-Host "PatchForge guarded production release"
Write-Host "Mode: $(if ($Execute) { 'EXECUTE' } else { 'DRY RUN' })"
Write-Host "Repository: $resolvedRepositoryRoot"
Write-Host "Branch/commit: $branch / $Commit"
Write-Host "Image tag: $ImageTag"
Write-Host "Baseline/context: $ProductBaseline / $ReportContextVersion"
Write-Host "Target: tenant $TenantId, subscription $SubscriptionId, resource group $ResourceGroup"
Write-Host "External evidence root: $artifactBase"
Write-Host ""
Write-Host "Ordered six-app plan:"
foreach ($app in $apps) {
    Write-Host "- $($app.App) <- $loginServer/$($app.Repository):$ImageTag"
}

if (-not $Execute) {
    Write-Host ""
    Write-Host "DRY RUN ONLY: no files, images, registry tags, Key Vault signatures, or Azure resources were changed."
    Write-Host "Execute additionally requires:"
    Write-Host "- clean tracked worktree and exact live upstream commit"
    Write-Host "- -ApprovalRunId for a successful environment-approved, GitHub-attested authorization matching commit/tag/baseline/context"
    Write-Host "- -ApproveTargetedImageOnly (the script never applies Bicep or changes custom domains/configuration)"
    Write-Host "- exact tenant/subscription context; Docker Desktop; new tag absent from all six ACR repositories"
    Write-Host "- external per-app rollback image archives before build/push"
    Write-Host "- six pushed digest readbacks and an ES256 Key Vault-signed canonical provenance manifest"
    Write-Host "- sequential readiness/configuration checks, public smoke, and automatic reverse-order rollback on failure"
    exit 0
}

if (-not $ApproveTargetedImageOnly) {
    throw "-ApproveTargetedImageOnly is required with -Execute. This authorizes only six explicit 'az containerapp update --image' operations."
}
if ([string]::IsNullOrWhiteSpace($ApprovalRunId)) {
    throw "-ApprovalRunId is required with -Execute."
}

foreach ($command in @("az", "docker", "gh")) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is required for -Execute."
    }
}
$upstream = Assert-RemoteHead -RepoRoot $resolvedRepositoryRoot -ExpectedCommit $Commit
$azureAccount = Assert-AzureContext
Invoke-NativeStreaming -Command "docker" -Arguments @("version")
Invoke-NativeStreaming -Command "docker" -Arguments @("info")
Assert-NewAcrTag

$releaseStamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$safeTag = $ImageTag -replace "[^A-Za-z0-9._-]", "-"
$releaseDirectory = Join-Path $artifactBase "$releaseStamp-$safeTag"
New-Item -ItemType Directory -Path $releaseDirectory -Force | Out-Null
$recordPath = Join-Path $releaseDirectory "release-execution.json"
$record = [ordered]@{
    schema = "patchforge-guarded-production-release-v1"
    status = "preflight"
    started_at_utc = [DateTime]::UtcNow.ToString("o")
    repository = $ApprovalRepository
    branch = $branch
    upstream = $upstream
    commit = $Commit
    image_tag = $ImageTag
    product_baseline = $ProductBaseline
    report_context_version = $ReportContextVersion
    tenant_id = $TenantId
    subscription_id = $SubscriptionId
    subscription_name = $azureAccount.name
    registry = $loginServer
    resource_group = $ResourceGroup
    approval = $null
    rollback_backups = @()
    images = @()
    apps_before = [ordered]@{}
    apps_after = [ordered]@{}
    provenance = $null
    signing_preflight = $null
    public_smoke = @()
    rollback = @()
    errors = @()
}
Write-ReleaseRecord -Record $record -Path $recordPath

$attemptedApps = New-Object System.Collections.Generic.List[object]
$beforeSnapshots = @{}
try {
    $record.approval = Assert-GitHubReleaseAuthorization -ReleaseDirectory $releaseDirectory
    $record.status = "approval_verified"
    Write-ReleaseRecord -Record $record -Path $recordPath

    $powershellExecutable = (Get-Process -Id $PID).Path
    Invoke-NativeStreaming -Command $powershellExecutable -Arguments @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $validateScript)

    $record.signing_preflight = Assert-KeyVaultSigningPreflight
    $record.status = "signing_access_verified"
    Write-ReleaseRecord -Record $record -Path $recordPath

    foreach ($app in $apps) {
        $snapshot = Get-AppSnapshot -AppDefinition $app
        Assert-AppReady -Snapshot $snapshot -ExpectedImage $snapshot.state.image -AppName $app.App
        $beforeSnapshots[$app.App] = $snapshot
        $record.apps_before[$app.App] = $snapshot
    }
    $record.status = "current_state_verified"
    Write-ReleaseRecord -Record $record -Path $recordPath

    $backupDirectory = Join-Path $releaseDirectory "rollback-images"
    $record.rollback_backups = @(Backup-CurrentImages -BeforeSnapshots $beforeSnapshots -BackupDirectory $backupDirectory)
    $record.status = "rollback_images_backed_up"
    Write-ReleaseRecord -Record $record -Path $recordPath

    Invoke-NativeStreaming -Command $powershellExecutable -Arguments @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $buildScript,
        "-RegistryName", $RegistryName,
        "-ImageTag", $ImageTag,
        "-Execute"
    )
    $record.images = @(Get-PushedImageRecords)
    $record.status = "images_pushed_and_verified"
    Write-ReleaseRecord -Record $record -Path $recordPath

    $provenance = New-SignedImageManifest -ImageRecords $record.images -ReleaseDirectory $releaseDirectory
    $record.provenance = [ordered]@{
        manifest_file = [System.IO.Path]::GetFileName($provenance.ManifestPath)
        signature_file = [System.IO.Path]::GetFileName($provenance.SignaturePath)
        manifest_sha256 = $provenance.ManifestSha256
        key_id = $provenance.KeyId
        verified = $provenance.Verified
    }
    $record.status = "provenance_signed_and_verified"
    Write-ReleaseRecord -Record $record -Path $recordPath

    foreach ($app in $apps) {
        $targetImage = "$loginServer/$($app.Repository):$ImageTag"
        $attemptedApps.Add($app)
        Write-Host "Updating $($app.App) to $targetImage"
        Invoke-NativeStreaming -Command "az" -Arguments @(
            "containerapp", "update",
            "--resource-group", $ResourceGroup,
            "--name", $app.App,
            "--image", $targetImage,
            "--only-show-errors",
            "--output", "none"
        )
        $after = Wait-AppReady -AppDefinition $app -ExpectedImage $targetImage -ExpectedConfiguration $beforeSnapshots[$app.App].configurationGuard
        $record.apps_after[$app.App] = $after
        Write-ReleaseRecord -Record $record -Path $recordPath
    }

    $record.public_smoke = @(Invoke-PublicSmoke)
    $record.status = "succeeded"
    $record.completed_at_utc = [DateTime]::UtcNow.ToString("o")
    Write-ReleaseRecord -Record $record -Path $recordPath
    Write-Host "PatchForge production release succeeded. Evidence: $releaseDirectory"
}
catch {
    $failure = $_.Exception.Message
    $record.errors += $failure
    $containerAppUpdateAttempted = $attemptedApps.Count -gt 0
    $record.status = if ($containerAppUpdateAttempted) { "failed_rollback_pending" } else { "failed_before_containerapp_update" }
    Write-ReleaseRecord -Record $record -Path $recordPath
    if ($containerAppUpdateAttempted) {
        Write-Warning "Release failed: $failure. Automatic reverse-order rollback is starting."
    }
    else {
        Write-Warning "Release failed before any Container App update: $failure. No application rollback is required."
    }

    $rollbackErrors = New-Object System.Collections.Generic.List[string]
    for ($index = $attemptedApps.Count - 1; $index -ge 0; $index--) {
        $app = $attemptedApps[$index]
        $previousImage = $beforeSnapshots[$app.App].state.image
        $rollbackEntry = [ordered]@{
            app = $app.App
            image = $previousImage
            status = "pending"
        }
        try {
            Write-Host "Rolling back $($app.App) to $previousImage"
            Invoke-NativeStreaming -Command "az" -Arguments @(
                "containerapp", "update",
                "--resource-group", $ResourceGroup,
                "--name", $app.App,
                "--image", $previousImage,
                "--only-show-errors",
                "--output", "none"
            )
            $rollbackSnapshot = Wait-AppReady -AppDefinition $app -ExpectedImage $previousImage -ExpectedConfiguration $beforeSnapshots[$app.App].configurationGuard
            $rollbackEntry.status = "succeeded"
            $rollbackEntry.revision = $rollbackSnapshot.state.latestReadyRevisionName
        }
        catch {
            $rollbackEntry.status = "failed"
            $rollbackEntry.error = $_.Exception.Message
            $rollbackErrors.Add("$($app.App): $($_.Exception.Message)")
        }
        $record.rollback += [pscustomobject]$rollbackEntry
        Write-ReleaseRecord -Record $record -Path $recordPath
    }

    try {
        $record.public_smoke = @(Invoke-PublicSmoke)
    }
    catch {
        $rollbackErrors.Add("post-rollback public smoke: $($_.Exception.Message)")
    }
    if (-not $containerAppUpdateAttempted) {
        $record.status = "failed_before_containerapp_update"
    }
    elseif ($rollbackErrors.Count -eq 0) {
        $record.status = "failed_rolled_back"
    }
    else {
        $record.status = "failed_rollback_incomplete"
        $record.errors += @($rollbackErrors)
    }
    $record.completed_at_utc = [DateTime]::UtcNow.ToString("o")
    Write-ReleaseRecord -Record $record -Path $recordPath
    throw "Production release failed. Rollback status: $($record.status). Evidence: $releaseDirectory"
}

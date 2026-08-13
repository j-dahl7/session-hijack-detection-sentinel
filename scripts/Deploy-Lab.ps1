#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Infostealer Session Hijacking Detection Lab.

.DESCRIPTION
    Deploys detection resources to an existing Microsoft Sentinel workspace:
    1. Verifies Entra ID diagnostic settings (SigninLogs, NonInteractiveUserSignInLogs)
    2. Sentinel analytics rules (5 scheduled rules for session hijacking detection)
    3. Sentinel workbook (Session Hijack Threat Dashboard)
    4. Points to the optional session-hijacking telemetry helper

.PARAMETER ResourceGroup
    Resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Sentinel enabled.

.PARAMETER SkipDiagnostics
    Skip verifying Entra ID diagnostic settings.

.PARAMETER SkipSentinel
    Skip deploying analytics rules and workbook.

.PARAMETER Destroy
    Tear down all lab resources (analytics rules and workbook).

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"

.EXAMPLE
    ./Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [Parameter()]
    [switch]$SkipDiagnostics,

    [Parameter()]
    [switch]$SkipSentinel,

    [Parameter()]
    [switch]$Destroy
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir
$LabOwnerMarker = 'nine-lives-zero-trust:session-hijack-detection-sentinel'
$LabRuleNames = @(
    "LAB - Token Replay from New Device or IP",
    "LAB - Impossible Travel on Token Refresh",
    "LAB - Anomalous Non-Interactive Sign-in Surge",
    "LAB - Browser or OS Mismatch in Same Session",
    "LAB - CAE Revocation Followed by New Location Auth"
)
$LabWorkbookTitle = 'Session Hijack Threat Dashboard'

function Get-LabResourceGuid {
    param([Parameter(Mandatory)][string]$ResourceKey)

    $hash = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes("$workspaceId|$LabOwnerMarker|$ResourceKey")
    )
    return [guid]::new([byte[]]$hash[0..15]).ToString()
}

Write-Host "`n=== Infostealer Session Hijacking Detection Lab ===" -ForegroundColor Cyan
Write-Host "Resource Group: $ResourceGroup"
Write-Host "Workspace:      $WorkspaceName"
Write-Host ""

# --- [0/7] Pre-flight ---
Write-Host "[0/7] Verifying prerequisites..." -ForegroundColor Yellow
$workspace = az monitor log-analytics workspace show `
    --resource-group $ResourceGroup `
    --workspace-name $WorkspaceName 2>$null | ConvertFrom-Json

if (-not $workspace) {
    Write-Error "Workspace '$WorkspaceName' not found in resource group '$ResourceGroup'"
}

$workspaceId = $workspace.id
$customerId = $workspace.customerId
$subscriptionId = ($workspaceId -split '/')[2]
Write-Host "  Workspace ID: $customerId" -ForegroundColor DarkGray

$sentinel = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/onboardingStates?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json

if (-not $sentinel.value) {
    Write-Error "Microsoft Sentinel is not enabled on workspace '$WorkspaceName'"
}
Write-Host "  Sentinel: Enabled" -ForegroundColor Green

# --- Destroy mode ---
if ($Destroy) {
    Write-Host "`nDestroying lab resources..." -ForegroundColor Red

    $existingRulesResponse = az rest --method GET `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
        2>$null | ConvertFrom-Json

    foreach ($labRuleName in $LabRuleNames) {
        $expectedRuleId = Get-LabResourceGuid -ResourceKey "rule:$labRuleName"
        $existingRule = @($existingRulesResponse.value) |
            Where-Object { $_.name -eq $expectedRuleId } |
            Select-Object -First 1
        if ($existingRule) {
            $ownedRule = $existingRule.properties.displayName -eq $labRuleName -and
                $existingRule.properties.description -like "*$LabOwnerMarker*"
            if (-not $ownedRule) {
                throw "Refusing to delete analytics rule '$expectedRuleId': ownership marker or display name does not match this lab."
            }
            if ($PSCmdlet.ShouldProcess($labRuleName, 'Delete owned Sentinel analytics rule')) {
                Write-Host "  Deleting rule: $labRuleName"
                az rest --method DELETE `
                    --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/${expectedRuleId}?api-version=2024-03-01" `
                    2>$null | Out-Null
                Write-Host "    Deleted" -ForegroundColor Green
            }
        }
    }

    $existingWorkbooks = az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
    $expectedWorkbookId = Get-LabResourceGuid -ResourceKey 'workbook'
    $labWorkbook = $existingWorkbooks | Where-Object { $_.name -eq $expectedWorkbookId } | Select-Object -First 1
    if ($labWorkbook) {
        $ownedWorkbook = $labWorkbook.tags.'hidden-title' -eq $LabWorkbookTitle -and
            $labWorkbook.tags.'nlzt-owner' -eq $LabOwnerMarker
        if (-not $ownedWorkbook) {
            throw "Refusing to delete workbook '$expectedWorkbookId': ownership tags do not match this lab."
        }
        if ($PSCmdlet.ShouldProcess($LabWorkbookTitle, 'Delete owned Sentinel workbook')) {
            Write-Host "  Deleting workbook: $LabWorkbookTitle"
            az rest --method DELETE `
                --url "$($labWorkbook.id)?api-version=2022-04-01" `
                2>$null | Out-Null
            Write-Host "    Deleted" -ForegroundColor Green
        }
    }

    if ($WhatIfPreference) {
        Write-Host "`nCleanup preview complete; no resources were deleted." -ForegroundColor Yellow
    }
    else {
        Write-Host "`nLab resources destroyed." -ForegroundColor Green
    }
    return
}

# --- [1/7] Verify diagnostic settings ---
if (-not $SkipDiagnostics) {
    Write-Host "`n[1/7] Verifying Entra ID diagnostic settings..." -ForegroundColor Yellow

    $diagSettings = az rest --method GET `
        --url "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview" `
        2>$null | ConvertFrom-Json

    $requiredCategories = @("SignInLogs", "NonInteractiveUserSignInLogs")
    $missingCategories = @()

    foreach ($cat in $requiredCategories) {
        $found = $false
        foreach ($setting in @($diagSettings.value)) {
            $enabledLogs = @($setting.properties.logs | Where-Object { $_.enabled -eq $true })
            if ($enabledLogs.category -contains $cat) {
                $targetWs = $setting.properties.workspaceId
                if ($targetWs -and $targetWs -like "*$WorkspaceName*") {
                    $found = $true
                    break
                }
            }
        }
        if ($found) {
            Write-Host "  $cat : Enabled -> $WorkspaceName" -ForegroundColor Green
        } else {
            $missingCategories += $cat
            Write-Host "  $cat : NOT FOUND" -ForegroundColor Red
        }
    }

    if ($missingCategories.Count -gt 0) {
        Write-Host ""
        Write-Host "  WARNING: Missing diagnostic categories: $($missingCategories -join ', ')" -ForegroundColor Yellow
        Write-Host "  Enable them in Entra admin center > Monitoring > Diagnostic settings." -ForegroundColor Yellow
        Write-Host "  Continuing deployment — rules will deploy but may not fire until logs are flowing." -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "`n[1/7] Skipping diagnostic settings check (-SkipDiagnostics)" -ForegroundColor DarkGray
}

# --- [2/7] Data verification ---
Write-Host "`n[2/7] Verifying sign-in data in workspace..." -ForegroundColor Yellow

$signinCheck = az monitor log-analytics query `
    --workspace $customerId `
    --analytics-query "SigninLogs | take 1 | project TimeGenerated" `
    2>$null | ConvertFrom-Json

if ($signinCheck.Count -gt 0 -and $signinCheck[0].TimeGenerated) {
    Write-Host "  SigninLogs: Data present" -ForegroundColor Green
} else {
    Write-Host "  SigninLogs: No data found (may take 15-30 min after enabling diagnostics)" -ForegroundColor Yellow
}

$nonInteractiveCheck = az monitor log-analytics query `
    --workspace $customerId `
    --analytics-query "AADNonInteractiveUserSignInLogs | take 1 | project TimeGenerated" `
    2>$null | ConvertFrom-Json

if ($nonInteractiveCheck.Count -gt 0 -and $nonInteractiveCheck[0].TimeGenerated) {
    Write-Host "  AADNonInteractiveUserSignInLogs: Data present" -ForegroundColor Green
} else {
    Write-Host "  AADNonInteractiveUserSignInLogs: No data found" -ForegroundColor Yellow
}

if ($SkipSentinel) {
    Write-Host "`nSkipping Sentinel deployment (-SkipSentinel)" -ForegroundColor DarkGray
    return
}

# --- [3/7] Deploy Analytics Rules ---
Write-Host "`n[3/7] Deploying Sentinel analytics rules..." -ForegroundColor Yellow

$rules = @(
    @{
        displayName = "LAB - Token Replay from New Device or IP"
        description = "Detects non-interactive sign-ins from a device+IP combination never seen for the user in the past 14 days. Infostealers replay stolen cookies from unknown infrastructure."
        severity    = "High"
        query       = @"
let LookbackPeriod = 14d;
let DetectionWindow = 1d;
let MinUnfamiliarEvents = 1;
let KnownUserFootprint = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where ResultType == "0"
    | extend DeviceId = tostring(parse_json(DeviceDetail).deviceId)
    | summarize by UserPrincipalName, IPAddress, DeviceId
    | extend Known = true;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(DetectionWindow)
| where ResultType == "0"
| where isnotempty(UserPrincipalName)
| extend DeviceId = tostring(parse_json(DeviceDetail).deviceId)
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| join kind=leftouter (KnownUserFootprint)
    on UserPrincipalName, IPAddress, DeviceId
| extend IsUnfamiliar = isnull(Known)
| summarize UnfamiliarEvents = countif(IsUnfamiliar), NewIPCount = dcountif(IPAddress, IsUnfamiliar), IPs = make_set_if(IPAddress, IsUnfamiliar, 10), Apps = make_set_if(AppDisplayName, IsUnfamiliar, 10), OS_Set = make_set_if(OS, IsUnfamiliar, 5), Browser_Set = make_set_if(Browser, IsUnfamiliar, 5), EventCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where UnfamiliarEvents >= MinUnfamiliarEvents
| project TimeGenerated, UserPrincipalName, UnfamiliarEvents, NewIPCount, IPs, Apps, OS_Set, Browser_Set, EventCount
"@
        # LookbackPeriod is 14d, so the rule must be able to see 14 days. Under the
        # default P1D the KnownUserFootprint subquery resolves to an empty set, the
        # leftouter join leaves Known null on every row, and IsUnfamiliar becomes
        # true for every sign-in - the rule alerts on all normal traffic.
        queryPeriod    = "P14D"
        tactics        = @("CredentialAccess", "LateralMovement")
        techniques     = @("T1539", "T1550")
        subTechniques  = @("T1550.001")
    },
    @{
        displayName = "LAB - Impossible Travel on Token Refresh"
        description = "Detects consecutive non-interactive sign-ins exceeding 500 km/h. Legitimate flights, VPN egress, and GeoIP error require analyst context and tenant tuning."
        severity    = "High"
        query       = @"
let SpeedThresholdKmH = 500;
let MinDistanceKm = 100;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| extend LocDetails = parse_json(tostring(LocationDetails))
| extend Lat = toreal(LocDetails.geoCoordinates.latitude)
| extend Lon = toreal(LocDetails.geoCoordinates.longitude)
| extend City = tostring(LocDetails.city)
| extend Country = tostring(LocDetails.countryOrRegion)
| where isnotnull(Lat) and isnotnull(Lon)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevLat = prev(Lat, 1), PrevLon = prev(Lon, 1), PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1), PrevCity = prev(City, 1), PrevCountry = prev(Country, 1)
| where UserPrincipalName == PrevUser
| extend TimeDeltaHours = datetime_diff('second', TimeGenerated, PrevTime) / 3600.0
| where TimeDeltaHours > 0
| extend DistanceKm = geo_distance_2points(Lon, Lat, PrevLon, PrevLat) / 1000.0
| extend SpeedKmH = DistanceKm / TimeDeltaHours
| where SpeedKmH > SpeedThresholdKmH and DistanceKm > MinDistanceKm
| project TimeGenerated, UserPrincipalName, FromCity = PrevCity, FromCountry = PrevCountry, ToCity = City, ToCountry = Country, DistanceKm = round(DistanceKm, 0), TimeDeltaMinutes = round(TimeDeltaHours * 60, 1), SpeedKmH = round(SpeedKmH, 0), AppDisplayName, IPAddress
"@
        tactics        = @("CredentialAccess", "InitialAccess")
        techniques     = @("T1539")
        subTechniques  = @()
    },
    @{
        displayName = "LAB - Anomalous Non-Interactive Sign-in Surge"
        description = "Detects a 3x spike in non-interactive sign-in volume vs 7-day baseline. Infostealers replaying cookies across M365 services create burst token renewal patterns."
        severity    = "Medium"
        query       = @"
let BaselinePeriod = 7d;
let DetectionWindow = 1h;
let SpikeMultiplier = 3;
let MinAbsoluteThreshold = 20;
let Baseline = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (ago(BaselinePeriod) .. ago(DetectionWindow))
    | where ResultType == "0"
    | summarize BaselineHourlyAvg = count() / (24.0 * 7) by UserPrincipalName;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(DetectionWindow)
| where ResultType == "0"
| summarize CurrentCount = count(), DistinctApps = dcount(AppDisplayName), Apps = make_set(AppDisplayName, 15), DistinctIPs = dcount(IPAddress), IPs = make_set(IPAddress, 10) by UserPrincipalName
| join kind=inner (Baseline) on UserPrincipalName
| where CurrentCount > BaselineHourlyAvg * SpikeMultiplier and CurrentCount > MinAbsoluteThreshold
| extend SpikeRatio = round(CurrentCount / BaselineHourlyAvg, 1)
| project TimeGenerated = now(), UserPrincipalName, CurrentCount, BaselineHourlyAvg = round(BaselineHourlyAvg, 1), SpikeRatio, DistinctApps, Apps, DistinctIPs, IPs
"@
        queryPeriod    = "P7D"
        tactics        = @("CredentialAccess", "LateralMovement")
        techniques     = @("T1539", "T1550")
        subTechniques  = @("T1550.001")
    },
    @{
        displayName = "LAB - Browser or OS Mismatch in Same Session"
        description = "Detects 3+ distinct browser/OS fingerprints for the same recorded Entra session in a fixed 4-hour bucket. Rows without SessionId are excluded."
        severity    = "Medium"
        query       = @"
let FingerprintThreshold = 3;
let TimeWindowHours = 4h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| where isnotempty(UserPrincipalName) and isnotempty(SessionId)
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| where isnotempty(OS) and isnotempty(Browser)
| extend Fingerprint = strcat(OS, "|", Browser)
| summarize DistinctFingerprints = dcount(Fingerprint), Fingerprints = make_set(Fingerprint, 10), DistinctIPs = dcount(IPAddress), IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10), EventCount = count() by UserPrincipalName, SessionId, bin(TimeGenerated, TimeWindowHours)
| where DistinctFingerprints >= FingerprintThreshold
| project TimeGenerated, UserPrincipalName, SessionId, DistinctFingerprints, Fingerprints, DistinctIPs, IPs, Apps, EventCount
"@
        tactics        = @("DefenseEvasion", "CredentialAccess")
        techniques     = @("T1539", "T1550")
        subTechniques  = @("T1550.001")
    },
    @{
        displayName = "LAB - CAE Revocation Followed by New Location Auth"
        description = "Detects when CAE terminates a session but the user re-authenticates from a different IP within 30 minutes. Indicates an active adversary fighting defensive token revocation."
        severity    = "High"
        query       = @"
let CAEWindow = 30m;
let RevocationCodes = dynamic(["530032", "530034", "50173", "70043", "50133"]);
let CAEEvents = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType != "0"
    | where ResultType in (RevocationCodes)
    | where tostring(AuthenticationDetails) has "caePolicyId"
        or tostring(ConditionalAccessPolicies) has "continuousAccessEvaluation"
    | project CAETime = TimeGenerated, UserPrincipalName, CAE_IP = IPAddress, CAE_Location = Location, ResultType;
let NewAuth = union SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "0"
    | project AuthTime = TimeGenerated, UserPrincipalName, Auth_IP = IPAddress, Auth_Location = Location, AppDisplayName;
CAEEvents
| join kind=inner (NewAuth) on UserPrincipalName
| where AuthTime between (CAETime .. (CAETime + CAEWindow))
| where CAE_IP != Auth_IP
| project CAETime, AuthTime, UserPrincipalName, CAE_IP, CAE_Location, Auth_IP, Auth_Location, AppDisplayName, TimeDelta = AuthTime - CAETime
"@
        tactics        = @("CredentialAccess", "Persistence", "LateralMovement")
        techniques     = @("T1539", "T1550")
        subTechniques  = @("T1550.001")
    }
)

$existingRulesResponse = az rest --method GET `
    --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" `
    2>$null | ConvertFrom-Json
foreach ($rule in $rules) {
    Write-Host "  Deploying: $($rule.displayName)"

    $ruleId = Get-LabResourceGuid -ResourceKey "rule:$($rule.displayName)"
    $existingById = @($existingRulesResponse.value) | Where-Object { $_.name -eq $ruleId } | Select-Object -First 1
    $foreignSameName = @($existingRulesResponse.value) | Where-Object {
        $_.properties.displayName -eq $rule.displayName -and $_.name -ne $ruleId
    } | Select-Object -First 1
    if ($foreignSameName) {
        throw "A non-lab analytics rule already uses '$($rule.displayName)' (ID $($foreignSameName.name)); refusing to overwrite or shadow it."
    }
    if ($existingById -and $existingById.properties.description -notlike "*$LabOwnerMarker*") {
        throw "Analytics rule ID '$ruleId' exists without this lab's ownership marker; refusing to overwrite it."
    }

    $ruleBody = @{
        kind       = "Scheduled"
        properties = @{
            displayName           = $rule.displayName
            description           = "$($rule.description) [Owner: $LabOwnerMarker]"
            severity              = $rule.severity
            query                 = $rule.query
            queryFrequency        = "PT1H"
            queryPeriod           = if ($rule.queryPeriod) { $rule.queryPeriod } else { "P1D" }
            triggerOperator       = "GreaterThan"
            triggerThreshold      = 0
            suppressionDuration   = "PT5H"
            suppressionEnabled    = $false
            tactics               = $rule.tactics
            techniques            = $rule.techniques
            subTechniques         = $rule.subTechniques
            enabled               = $true
            incidentConfiguration = @{
                createIncident        = $true
                groupingConfiguration = @{
                    enabled               = $true
                    reopenClosedIncident  = $false
                    lookbackDuration      = "PT5H"
                    matchingMethod        = "AllEntities"
                }
            }
        }
    } | ConvertTo-Json -Depth 10

    $ruleAction = if ($existingById) { "Updated" } else { "Created" }
    if ($PSCmdlet.ShouldProcess($rule.displayName, "$ruleAction Sentinel analytics rule")) {
        $bodyFile = New-TemporaryFile
        try {
            [System.IO.File]::WriteAllText($bodyFile.FullName, $ruleBody, [System.Text.Encoding]::UTF8)
            $result = az rest --method PUT `
                --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2024-03-01" `
                --body "@$($bodyFile.FullName)" `
                --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

            if (-not $result.name) {
                throw "Sentinel did not return an analytics rule resource"
            }
            Write-Host "    ${ruleAction}: $($result.name)" -ForegroundColor Green
        }
        finally {
            Remove-Item $bodyFile.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- [4/7] Hunting queries ---
Write-Host "`n[4/7] Hunting queries available at:" -ForegroundColor Yellow
Write-Host "  $LabRoot/detection/hunting-queries.kql" -ForegroundColor DarkGray

# --- [5/7] Deploy Workbook ---
Write-Host "`n[5/7] Deploying Sentinel workbook..." -ForegroundColor Yellow

$workbookContentPath = "$LabRoot/workbook/session-hijack-workbook.json"
$workbookDefinition = Get-Content -Path $workbookContentPath -Raw | ConvertFrom-Json
$workbookDefinition.fallbackResourceIds = @($workspaceId)
$workbookContent = $workbookDefinition | ConvertTo-Json -Depth 100 -Compress

$workbookDisplayName = $LabWorkbookTitle
$workbookId = Get-LabResourceGuid -ResourceKey 'workbook'
$allWorkbooks = @(
    az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
)
$existingWorkbook = $allWorkbooks | Where-Object { $_.name -eq $workbookId } | Select-Object -First 1
$foreignSameTitleWorkbook = $allWorkbooks | Where-Object {
    $_.tags.'hidden-title' -eq $workbookDisplayName -and $_.name -ne $workbookId
} | Select-Object -First 1
if ($foreignSameTitleWorkbook) {
    throw "A non-lab workbook already uses '$workbookDisplayName' (ID $($foreignSameTitleWorkbook.name)); refusing to overwrite or shadow it."
}
if ($existingWorkbook -and $existingWorkbook.tags.'nlzt-owner' -ne $LabOwnerMarker) {
    throw "Workbook ID '$workbookId' exists without this lab's ownership tag; refusing to overwrite it."
}
$workbookAction = if ($existingWorkbook) { "Updated" } else { "Created" }
$workbookBody = @{
    location   = $workspace.location
    kind       = "shared"
    tags       = @{
        'hidden-title' = $workbookDisplayName
        'nlzt-owner'   = $LabOwnerMarker
    }
    properties = @{
        displayName    = $workbookDisplayName
        serializedData = $workbookContent
        category       = "sentinel"
        sourceId       = $workspaceId
    }
} | ConvertTo-Json -Depth 10

if ($PSCmdlet.ShouldProcess($workbookDisplayName, "$workbookAction Sentinel workbook")) {
    $bodyFile = New-TemporaryFile
    try {
        [System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.Encoding]::UTF8)
        $wbResult = az rest --method PUT `
            --url "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01" `
            --body "@$($bodyFile.FullName)" `
            --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

        if (-not $wbResult.name) {
            throw "Azure did not return a workbook resource"
        }
        Write-Host "  Workbook $($workbookAction.ToLower()): $($wbResult.properties.displayName)" -ForegroundColor Green
    }
    finally {
        Remove-Item $bodyFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

# --- [6/7] Simulation ---
Write-Host "`n[6/7] Session hijacking simulation..." -ForegroundColor Yellow
Write-Host "  Run Test-SessionHijack.ps1 to generate detectable telemetry:" -ForegroundColor DarkGray
Write-Host "  $ScriptDir/Test-SessionHijack.ps1" -ForegroundColor DarkGray

# --- [7/7] Summary ---
$completionLabel = if ($WhatIfPreference) { 'Deployment preview complete; no changes applied.' } else { 'Deployment complete!' }
Write-Host "`n[7/7] $completionLabel" -ForegroundColor Green
Write-Host ""
Write-Host "=== $(if ($WhatIfPreference) { 'Planned Resources' } else { 'Deployed Resources' }) ===" -ForegroundColor Cyan
Write-Host "  Analytics Rules: 5 scheduled rules"
Write-Host "    - LAB - Token Replay from New Device or IP (High)"
Write-Host "    - LAB - Impossible Travel on Token Refresh (High)"
Write-Host "    - LAB - Anomalous Non-Interactive Sign-in Surge (Medium)"
Write-Host "    - LAB - Browser or OS Mismatch in Same Session (Medium)"
Write-Host "    - LAB - CAE Revocation Followed by New Location Auth (High)"
Write-Host "  Workbook:        Session Hijack Threat Dashboard"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open Microsoft Sentinel > Analytics to review the 5 new rules"
Write-Host "  2. Open Workbooks > 'Session Hijack Threat Dashboard'"
Write-Host "  3. Run hunting queries in detection/hunting-queries.kql"
Write-Host "  4. Run Test-SessionHijack.ps1 to generate test telemetry"
Write-Host "  5. Wait ~1 hour for analytics rules to evaluate"
Write-Host ""

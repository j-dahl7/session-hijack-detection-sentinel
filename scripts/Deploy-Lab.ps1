#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Infostealer Session Hijacking Detection Lab.

.DESCRIPTION
    Deploys detection resources to an existing Microsoft Sentinel workspace:
    1. Verifies Entra ID diagnostic settings (SigninLogs, NonInteractiveUserSignInLogs)
    2. Sentinel analytics rules (5 scheduled rules for session hijacking detection)
    3. Sentinel workbook (Session Hijack Threat Dashboard)
    4. Runs the session hijacking simulation

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
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LabRoot = Split-Path -Parent $ScriptDir

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

    $labRuleNames = @(
        "LAB - Token Replay from New Device or IP",
        "LAB - Impossible Travel on Token Refresh",
        "LAB - Anomalous Non-Interactive Sign-in Surge",
        "LAB - Browser or OS Mismatch in Same Session",
        "LAB - CAE Revocation Followed by New Location Auth"
    )

    foreach ($existingRule in @($existingRulesResponse.value)) {
        if ($existingRule.properties.displayName -in $labRuleNames) {
            Write-Host "  Deleting rule: $($existingRule.properties.displayName)"
            az rest --method DELETE `
                --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/$($existingRule.name)?api-version=2024-03-01" `
                2>$null | Out-Null
            Write-Host "    Deleted" -ForegroundColor Green
        }
    }

    $existingWorkbooks = az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
    $labWorkbook = $existingWorkbooks | Where-Object {
        $_.tags.'hidden-title' -eq "Session Hijack Threat Dashboard"
    } | Select-Object -First 1
    if ($labWorkbook) {
        Write-Host "  Deleting workbook: Session Hijack Threat Dashboard"
        az rest --method DELETE `
            --url "$($labWorkbook.id)?api-version=2022-04-01" `
            2>$null | Out-Null
        Write-Host "    Deleted" -ForegroundColor Green
    }

    Write-Host "`nLab resources destroyed." -ForegroundColor Green
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
let KnownUserFootprint = AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (ago(LookbackPeriod) .. ago(DetectionWindow))
    | where ResultType == "0"
    | summarize by UserPrincipalName, IPAddress, DeviceDetail_string = tostring(DeviceDetail);
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(DetectionWindow)
| where ResultType == "0"
| extend DeviceDetail_string = tostring(DeviceDetail)
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| join kind=leftanti (KnownUserFootprint)
    on UserPrincipalName, IPAddress, DeviceDetail_string
| where isnotempty(UserPrincipalName)
| summarize NewIPCount = dcount(IPAddress), IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10), OS_Set = make_set(OS, 5), Browser_Set = make_set(Browser, 5), EventCount = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where NewIPCount >= 1
| project TimeGenerated, UserPrincipalName, NewIPCount, IPs, Apps, OS_Set, Browser_Set, EventCount
"@
        tactics        = @("CredentialAccess", "LateralMovement")
        techniques     = @("T1539", "T1550")
        subTechniques  = @("T1550.001")
    },
    @{
        displayName = "LAB - Impossible Travel on Token Refresh"
        description = "Detects consecutive non-interactive sign-ins where geographic distance exceeds physical possibility (>500 km/h). Infostealers operate from different regions than the victim."
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
| where isnotempty(Lat) and isnotempty(Lon)
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
        description = "Detects 3+ distinct browser/OS fingerprints for the same user in a 4-hour window. Infostealers replaying tokens often have different DeviceDetail than the victim's original user agent."
        severity    = "Medium"
        query       = @"
let FingerprintThreshold = 3;
let TimeWindowHours = 4h;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| extend OS = tostring(parse_json(DeviceDetail).operatingSystem)
| extend Browser = tostring(parse_json(DeviceDetail).browser)
| where isnotempty(OS) and isnotempty(Browser)
| extend Fingerprint = strcat(OS, "|", Browser)
| summarize DistinctFingerprints = dcount(Fingerprint), Fingerprints = make_set(Fingerprint, 10), DistinctIPs = dcount(IPAddress), IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10), EventCount = count() by UserPrincipalName, bin(TimeGenerated, TimeWindowHours)
| where DistinctFingerprints >= FingerprintThreshold
| project TimeGenerated, UserPrincipalName, DistinctFingerprints, Fingerprints, DistinctIPs, IPs, Apps, EventCount
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
let CAEEvents = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType != "0"
    | where ResultType in ("50074", "530032", "530034", "50173", "70043", "50133", "50140", "50199")
        or tostring(AuthenticationDetails) has "caePolicyId"
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
$existingRuleIdsByName = @{}
foreach ($existingRule in @($existingRulesResponse.value)) {
    $existingDisplayName = $existingRule.properties.displayName
    if ($existingDisplayName) {
        $existingRuleIdsByName[$existingDisplayName] = $existingRule.name
    }
}

foreach ($rule in $rules) {
    Write-Host "  Deploying: $($rule.displayName)"

    $ruleBody = @{
        kind       = "Scheduled"
        properties = @{
            displayName           = $rule.displayName
            description           = $rule.description
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

    $bodyFile = New-TemporaryFile
    [System.IO.File]::WriteAllText($bodyFile.FullName, $ruleBody, [System.Text.Encoding]::UTF8)

    $ruleId = if ($existingRuleIdsByName[$rule.displayName]) {
        $existingRuleIdsByName[$rule.displayName]
    } else {
        [guid]::NewGuid().ToString()
    }
    $ruleAction = if ($existingRuleIdsByName[$rule.displayName]) { "Updated" } else { "Created" }
    $result = az rest --method PUT `
        --url "$workspaceId/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2024-03-01" `
        --body "@$($bodyFile.FullName)" `
        --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

    Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue

    if ($result.name) {
        Write-Host "    ${ruleAction}: $($result.name)" -ForegroundColor Green
    } else {
        Write-Host "    Warning: Rule may not have deployed correctly" -ForegroundColor Red
    }
}

# --- [4/7] Hunting queries ---
Write-Host "`n[4/7] Hunting queries available at:" -ForegroundColor Yellow
Write-Host "  $LabRoot/detection/hunting-queries.kql" -ForegroundColor DarkGray

# --- [5/7] Deploy Workbook ---
Write-Host "`n[5/7] Deploying Sentinel workbook..." -ForegroundColor Yellow

$workbookContentPath = "$LabRoot/workbook/session-hijack-workbook.json"
$workbookContent = Get-Content -Path $workbookContentPath -Raw

$workbookDisplayName = "Session Hijack Threat Dashboard"
$existingWorkbook = @(
    az resource list `
        --resource-group $ResourceGroup `
        --resource-type Microsoft.Insights/workbooks `
        2>$null | ConvertFrom-Json
) | Where-Object {
    $_.tags.'hidden-title' -eq $workbookDisplayName
} | Select-Object -First 1
$workbookId = if ($existingWorkbook) { $existingWorkbook.name } else { [guid]::NewGuid().ToString() }
$workbookAction = if ($existingWorkbook) { "Updated" } else { "Created" }
$workbookBody = @{
    location   = $workspace.location
    kind       = "shared"
    tags       = @{
        'hidden-title' = $workbookDisplayName
    }
    properties = @{
        displayName    = $workbookDisplayName
        serializedData = $workbookContent
        category       = "sentinel"
        sourceId       = $workspaceId
    }
} | ConvertTo-Json -Depth 10

$bodyFile = New-TemporaryFile
[System.IO.File]::WriteAllText($bodyFile.FullName, $workbookBody, [System.Text.Encoding]::UTF8)

$wbResult = az rest --method PUT `
    --url "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2022-04-01" `
    --body "@$($bodyFile.FullName)" `
    --headers 'Content-Type=application/json' 2>$null | ConvertFrom-Json

Remove-Item $bodyFile.FullName -ErrorAction SilentlyContinue

if ($wbResult.name) {
    Write-Host "  Workbook $($workbookAction.ToLower()): $($wbResult.properties.displayName)" -ForegroundColor Green
} else {
    Write-Host "  Warning: Workbook may not have deployed correctly" -ForegroundColor Red
}

# --- [6/7] Simulation ---
Write-Host "`n[6/7] Session hijacking simulation..." -ForegroundColor Yellow
Write-Host "  Run Test-SessionHijack.ps1 to generate detectable telemetry:" -ForegroundColor DarkGray
Write-Host "  $ScriptDir/Test-SessionHijack.ps1" -ForegroundColor DarkGray

# --- [7/7] Summary ---
Write-Host "`n[7/7] Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Deployed Resources ===" -ForegroundColor Cyan
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

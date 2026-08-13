#Requires -Version 7.0
<#
.SYNOPSIS
    Simulates infostealer session hijacking telemetry for detection rule validation.

.DESCRIPTION
    Performs benign Microsoft Graph calls with varied request headers and a
    controlled request burst. This validates authentication and creates safe
    seed activity, but downstream Graph requests do not map one-to-one to Entra
    sign-in events and are not guaranteed to trigger the lab rules.

    IMPORTANT: This script does NOT perform actual session hijacking. It generates
    benign Graph API traffic for authentication checks and safe seed activity.

.PARAMETER TenantId
    Azure AD tenant ID.

.PARAMETER BurstCount
    Number of rapid Graph API calls for the connectivity burst (default: 30).

.PARAMETER SkipBurst
    Skip the non-interactive sign-in surge simulation.

.EXAMPLE
    ./Test-SessionHijack.ps1 -TenantId "<tenant-id>"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [int]$BurstCount = 30,

    [Parameter()]
    [switch]$SkipBurst
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== Session Hijacking Simulation ===" -ForegroundColor Cyan
Write-Host "Generates benign Graph API traffic for connectivity and seed activity."
Write-Host "This does NOT perform actual session hijacking.`n"
Write-Host "Graph resource calls do not guarantee one Entra sign-in row per request." -ForegroundColor Yellow
Write-Host "Validate detections against actual token issuance/refresh telemetry.`n" -ForegroundColor Yellow

# --- Scenario 1: Multi-User-Agent Graph API Calls ---
Write-Host "[1/5] Scenario: Varied Graph Request Headers" -ForegroundColor Yellow
Write-Host "  Calling Graph API /me with different User-Agent headers..."
Write-Host "  This validates request handling. These headers are not guaranteed"
Write-Host "  to become Entra DeviceDetail fingerprints or trigger Rule 4.`n"

if ($TenantId) {
    $token = az account get-access-token --resource https://graph.microsoft.com --tenant $TenantId --query accessToken -o tsv 2>$null
} else {
    $token = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
}
if (-not $token) {
    Write-Error "Failed to get Graph API token. Run 'az login' first (add -TenantId if targeting a specific tenant)."
}

$userAgents = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/124.0.2478.67",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/21A5248v"
)

# Keep the simulation on low-privilege endpoints so it works with the default
# delegated Graph token that Azure CLI commonly receives (`User.Read`).
$graphEndpoints = @(
    "https://graph.microsoft.com/v1.0/me",
    "https://graph.microsoft.com/v1.0/me?`$select=id",
    "https://graph.microsoft.com/v1.0/me?`$select=displayName",
    "https://graph.microsoft.com/v1.0/me?`$select=userPrincipalName",
    "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName"
)

$headers = @{ Authorization = "Bearer $token" }
$successCount = 0

foreach ($ua in $userAgents) {
    $endpoint = $graphEndpoints[$successCount % $graphEndpoints.Count]
    try {
        $response = Invoke-RestMethod -Uri $endpoint `
            -Headers ($headers + @{ 'User-Agent' = $ua }) `
            -Method GET -ErrorAction Stop
        $successCount++
        $shortUA = $ua.Substring(0, [Math]::Min(60, $ua.Length))
        Write-Host "  [$successCount/$($userAgents.Count)] $shortUA..." -ForegroundColor Green
    } catch {
        Write-Host "  Warning: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Start-Sleep -Milliseconds 500
}
Write-Host "  Generated $successCount calls with $($userAgents.Count) distinct User-Agents`n"

# --- Scenario 2: Burst Non-Interactive Calls ---
if (-not $SkipBurst) {
    Write-Host "[2/5] Scenario: Graph Request Burst" -ForegroundColor Yellow
    Write-Host "  Sending $BurstCount rapid Graph API calls to validate the request path."
    Write-Host "  Cached-token requests may not create new Entra refresh events, so this"
    Write-Host "  does not deterministically trigger Rule 3.`n"

    $burstSuccess = 0
    for ($i = 1; $i -le $BurstCount; $i++) {
        $endpoint = $graphEndpoints[($i - 1) % $graphEndpoints.Count]
        try {
            Invoke-RestMethod -Uri $endpoint -Headers $headers -Method GET -ErrorAction Stop | Out-Null
            $burstSuccess++
            if ($i % 10 -eq 0) {
                Write-Host "  Progress: $i/$BurstCount" -ForegroundColor DarkGray
            }
        } catch {
            # Graph API rate limiting — expected at high volume
            if ($i % 10 -eq 0) {
                Write-Host "  Progress: $i/$BurstCount (some throttled)" -ForegroundColor Yellow
            }
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Host "  Generated $burstSuccess/$BurstCount burst calls`n"
} else {
    Write-Host "[2/5] Skipping burst simulation (-SkipBurst)`n" -ForegroundColor DarkGray
}

# --- Scenario 3: New IP Token Use ---
Write-Host "[3/5] Scenario: Token Use from Current IP" -ForegroundColor Yellow
Write-Host "  Actual token issuance or refresh may record your current source IP."
Write-Host "  A genuinely new IP can then contribute evidence for Rule 1.`n"

try {
    $myIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -ErrorAction Stop).ip
    Write-Host "  Current public IP: $myIP" -ForegroundColor DarkGray
} catch {
    Write-Host "  Could not determine public IP" -ForegroundColor Yellow
}

$meInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me?`$select=displayName,userPrincipalName" `
    -Headers $headers -ErrorAction SilentlyContinue
if ($meInfo) {
    Write-Host "  Signed in as: $($meInfo.userPrincipalName)" -ForegroundColor DarkGray
}
Write-Host ""

# --- Scenario 4: Impossible Travel (Manual) ---
Write-Host "[4/5] Scenario: Impossible Travel (Manual Steps Required)" -ForegroundColor Yellow
Write-Host "  This scenario cannot be automated from a single machine."
Write-Host "  To trigger Rule 2 (Impossible Travel on Token Refresh):`n"
Write-Host "  Option A: VPN-based" -ForegroundColor White
Write-Host "    1. Run this script from your current location"
Write-Host "    2. Connect to a VPN in a different country"
Write-Host "    3. Run: az account get-access-token --resource https://graph.microsoft.com"
Write-Host "    4. Make a Graph API call from the VPN IP`n"
Write-Host "  Option B: Azure Cloud Shell" -ForegroundColor White
Write-Host "    1. Run this script locally"
Write-Host "    2. Open Azure Cloud Shell (portal.azure.com)"
Write-Host "    3. Run: az rest --method GET --url https://graph.microsoft.com/v1.0/me"
Write-Host "    4. Cloud Shell runs from Azure datacenter IP -> different geo`n"

# --- Scenario 5: Revoked Grant Followed by New-IP Authentication (Manual) ---
Write-Host "[5/5] Scenario: Revoked Grant Followed by New-IP Authentication (Manual)" -ForegroundColor Yellow
Write-Host "  This helper intentionally does not revoke a user's sessions. To validate Rule 5:`n"
Write-Host "    1. Use a dedicated, low-privilege lab user and two approved egress paths."
Write-Host "    2. At IP A, sign in to an app that uses refresh tokens; confirm the raw"
Write-Host "       sign-in row and record its immutable UserId."
Write-Host "    3. As an authorized administrator, revoke that lab user's sign-in sessions."
Write-Host "       This invalidates the user's refresh tokens across applications."
Write-Host "    4. Let the existing client at IP A attempt a token refresh. Confirm a raw"
Write-Host "       SigninLogs or AADNonInteractiveUserSignInLogs row with ResultType 50173."
Write-Host "    5. Only after that failure, reauthenticate the same lab user at IP B within"
Write-Host "       30 minutes. Confirm ResultType 0, the same nonempty UserId, and a"
Write-Host "       different IPAddress, then run Rule 5 manually over the matching window.`n"
Write-Host "  A password change or refresh-token expiry can also produce 50173. A rule"
Write-Host "  match is therefore a triage lead, not proof of theft or CAE enforcement.`n" -ForegroundColor Yellow

# --- Summary ---
Write-Host "=== Simulation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Validation timing:" -ForegroundColor Yellow
Write-Host "  Sign-in ingestion, hourly rule evaluation, and incident creation are"
Write-Host "  asynchronous. Confirm raw rows first; do not assume a fixed arrival time."
Write-Host ""
Write-Host "Detection expectations (dependent on actual sign-in telemetry):" -ForegroundColor Yellow
Write-Host "  Rule 1 (Token Replay):     If current IP is new for your account"
Write-Host "  Rule 3 (Surge):            Requires real token-refresh volume above baseline"
Write-Host "  Rule 4 (Fingerprint):      Requires real DeviceDetail fingerprint diversity"
Write-Host "  Rule 2 (Impossible Travel): Only with manual VPN/Cloud Shell step"
Write-Host "  Rule 5 (Revoked Grant):    Requires 50173 then same-UserId success from another IP"
Write-Host ""

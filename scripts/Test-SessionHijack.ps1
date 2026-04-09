#Requires -Version 7.0
<#
.SYNOPSIS
    Simulates infostealer session hijacking telemetry for detection rule validation.

.DESCRIPTION
    Generates sign-in events that trigger the Session Hijacking Detection Lab rules.
    Uses Graph API calls with varied parameters to create detectable patterns in
    SigninLogs and AADNonInteractiveUserSignInLogs.

    IMPORTANT: This script does NOT perform actual session hijacking. It generates
    benign Graph API traffic that produces patterns matching the detection rules.

.PARAMETER TenantId
    Azure AD tenant ID.

.PARAMETER BurstCount
    Number of rapid Graph API calls for the surge simulation (default: 30).

.PARAMETER SkipBurst
    Skip the non-interactive sign-in surge simulation.

.EXAMPLE
    ./Test-SessionHijack.ps1 -TenantId "e24be7b2-dbc8-47ef-8071-593408b48c9e"
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
Write-Host "Generates benign Graph API traffic to trigger detection rules."
Write-Host "This does NOT perform actual session hijacking.`n"

# --- Scenario 1: Multi-User-Agent Graph API Calls ---
Write-Host "[1/4] Scenario: Browser/OS Fingerprint Mismatch" -ForegroundColor Yellow
Write-Host "  Calling Graph API /me with different User-Agent headers..."
Write-Host "  This generates AADNonInteractiveUserSignInLogs entries with"
Write-Host "  distinct browser/OS fingerprints -> triggers Rule 4.`n"

$token = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
if (-not $token) {
    Write-Error "Failed to get Graph API token. Run 'az login' first."
}

$userAgents = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/124.0.2478.67",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/21A5248v"
)

$graphEndpoints = @(
    "https://graph.microsoft.com/v1.0/me",
    "https://graph.microsoft.com/v1.0/me/messages?`$top=1",
    "https://graph.microsoft.com/v1.0/me/drive/root",
    "https://graph.microsoft.com/v1.0/me/calendar/events?`$top=1",
    "https://graph.microsoft.com/v1.0/me/memberOf?`$top=1"
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
    Write-Host "[2/4] Scenario: Non-Interactive Sign-in Surge" -ForegroundColor Yellow
    Write-Host "  Sending $BurstCount rapid Graph API calls to create a volume spike"
    Write-Host "  -> triggers Rule 3 (anomalous surge vs baseline).`n"

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
    Write-Host "[2/4] Skipping burst simulation (-SkipBurst)`n" -ForegroundColor DarkGray
}

# --- Scenario 3: New IP Token Use ---
Write-Host "[3/4] Scenario: Token Use from Current IP" -ForegroundColor Yellow
Write-Host "  Your current IP will be logged in AADNonInteractiveUserSignInLogs."
Write-Host "  If this IP differs from your usual sign-in IP -> triggers Rule 1.`n"

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
Write-Host "[4/4] Scenario: Impossible Travel (Manual Steps Required)" -ForegroundColor Yellow
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

# --- Summary ---
Write-Host "=== Simulation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Expected detection timeline:" -ForegroundColor Yellow
Write-Host "  - Sign-in logs appear:    15-30 minutes"
Write-Host "  - Analytics rules evaluate: ~1 hour (PT1H frequency)"
Write-Host "  - Incidents created:       ~1.5 hours after simulation"
Write-Host ""
Write-Host "Rules expected to trigger:" -ForegroundColor Yellow
Write-Host "  Rule 1 (Token Replay):     If current IP is new for your account"
Write-Host "  Rule 3 (Surge):            If burst exceeded 3x your hourly baseline"
Write-Host "  Rule 4 (Fingerprint):      From multi-User-Agent calls"
Write-Host "  Rule 2 (Impossible Travel): Only with manual VPN/Cloud Shell step"
Write-Host "  Rule 5 (CAE Revocation):    Requires actual CAE event (rare in labs)"
Write-Host ""

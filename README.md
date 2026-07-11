# Session Hijack Detection for Microsoft Sentinel

Detect infostealer session hijacking with 5 Sentinel analytics rules, 5 hunting queries, and a threat dashboard workbook.

**Blog post:** [Detecting Infostealer Session Hijacking with Microsoft Sentinel](https://nineliveszerotrust.com/blog/session-hijack-detection-sentinel/)

## Verification status

**Source-verified with historical live evidence — last verified 2026-07-10.** PowerShell parsed, workbook JSON loaded, the five checked-in KQL rules matched the five deployment-script definitions, and tracked links and cleanup selectors were reviewed. No tenant changes, Graph calls, VPN tests, session revocations, or Sentinel queries were performed during this verification.

The repository records prior live incidents for all five rules, but the helper script is not a deterministic incident generator: repeated Microsoft Graph resource requests made with one cached access token do not create one new Entra sign-in event per request, and request `User-Agent` headers are not guaranteed to become `DeviceDetail` fingerprints in Entra logs. Use the script as a safe connectivity and seed-activity helper, then validate against actual token issuance, refresh, VPN, and CAE telemetry. This repository does not currently include a standalone license file; confirm reuse terms before redistribution.

## What Gets Deployed

| Resource | Type | MITRE |
|---|---|---|
| LAB - Token Replay from New Device or IP | Analytics Rule (High) | T1539, T1550.001 |
| LAB - Impossible Travel on Token Refresh | Analytics Rule (High) | T1539 |
| LAB - Anomalous Non-Interactive Sign-in Surge | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - Browser or OS Mismatch in Same Session | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - CAE Revocation Followed by New Location Auth | Analytics Rule (High) | T1539, T1550.001 |
| Session Hijack Threat Dashboard | Workbook | - |

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled
- Entra ID P2 (for Identity Protection risk scoring)
- SigninLogs and NonInteractiveUserSignInLogs routed to Sentinel via Entra diagnostic settings
- Azure CLI + PowerShell 7+
- Microsoft Sentinel Contributor (or equivalent analytics-rule/workbook permissions) on the target workspace and permission to read Log Analytics data

## Quick Start

```powershell
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
./scripts/Test-SessionHijack.ps1

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
```

## Historical Results and Expected Limitations

All 5 rules were previously validated with real incidents in a live Sentinel workspace. Those observations are historical evidence, not a guarantee that one execution of `Test-SessionHijack.ps1` will reproduce them.

- **Rule 1 (Token Replay)** fires first. Any simulation run from a new IP or device triggers it within the first evaluation cycle.
- **Rule 3 (Surge)** and **Rule 4 (Browser Mismatch)** require actual non-interactive token activity in `AADNonInteractiveUserSignInLogs`. The helper's Graph request burst validates the low-privilege request path but cannot guarantee new token-refresh rows or distinct Entra device fingerprints.
- **Rule 2 (Impossible Travel)** requires sign-ins from two different geographic locations. The most reliable method:
  1. Run the simulation from your normal network
  2. Connect to a VPN in a different city or country
  3. From Windows PowerShell (not WSL — WSL may bypass the VPN), run: `az rest --method GET --url "https://graph.microsoft.com/v1.0/me"`
  4. Wait for the rule to evaluate (up to 1 hour, or temporarily set queryFrequency to PT5M)
  - In testing, a US-to-Canada VPN hop triggered the rule at over 7,500 km/h
  - Azure Cloud Shell is another option but its IP may resolve to the same region depending on your tenant
- **Rule 5 (CAE Revocation)** requires a session revocation followed by re-authentication from a different IP:
  1. Revoke sessions: `az rest --method POST --url "https://graph.microsoft.com/v1.0/users/{user-id}/revokeSignInSessions"`
  2. Re-authenticate with `az login`
  3. Switch to a VPN in a different location and run a Graph API call
  - The revocation produces CAE error codes (50133, 50140, 50199) and the re-auth from a new IP completes the correlation
  - Note: after revoking sessions, your existing az CLI token will be invalidated by CAE — you must re-login before making further calls

## Cost and safety

The repository deploys rules and one workbook into an existing Sentinel workspace; it creates no VM or cluster. Costs come from Entra diagnostic-log ingestion, Log Analytics retention/querying, and the Microsoft licenses required for the source data. Confirm current licensing and ingestion pricing for your tenant. The test helper uses only the signed-in user's low-privilege Microsoft Graph `/me` endpoint, but VPN changes and session revocation affect real sign-in state—use a disposable, non-admin lab account.

## Troubleshooting

- **WSL and VPN:** WSL terminals may bypass your Windows VPN. Run az rest from Windows PowerShell or Azure Cloud Shell where the VPN is active.
- **MFA blocks container-based auth:** Tenants with MFA enforced cannot use password-based az login from Azure Container Instances. Use VPN + interactive login instead.
- **Sign-in log ingestion delay:** AADNonInteractiveUserSignInLogs entries can take 15-30 minutes to appear after the auth event.
- **Rule evaluation frequency:** Analytics rules evaluate hourly (PT1H). Wait up to 1 hour after generating telemetry for incidents to appear.
- **Risk Level Distribution panel empty:** Expected in low-risk sandboxes until Identity Protection emits medium or high risk signals.
- **Graph API 403 errors:** The simulation uses User.Read-scoped /me endpoints. Run az login fresh if you see 403s.
- **LocationDetails parsing:** Some workspaces store LocationDetails as a string. The KQL uses parse_json(tostring(LocationDetails)) to handle both formats.
- **Burst produced no extra sign-in rows:** This can be expected. Entra records token issuance/refresh activity, not every downstream Graph resource request, and it aggregates similar non-interactive events.
- **Browser mismatch did not fire:** A custom HTTP `User-Agent` on a Graph request is not guaranteed to populate Entra `DeviceDetail`. Validate the rule with real sign-ins or token refreshes from controlled client/device combinations.

## Cleanup scope

`Deploy-Lab.ps1 -Destroy` removes only the five lab analytics rules and the workbook whose hidden title is `Session Hijack Threat Dashboard`. It does not alter Entra diagnostic settings, delete sign-in data, disable Sentinel, revoke user sessions, or change licensing.

## License

MIT

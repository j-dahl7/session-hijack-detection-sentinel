# Session Hijack Detection for Microsoft Sentinel

Detect infostealer session hijacking with 5 Sentinel analytics rules, 5 hunting queries, and a threat dashboard workbook.

**Blog post:** [Detecting Infostealer Session Hijacking with Microsoft Sentinel](https://nineliveszerotrust.com/blog/session-hijack-detection-sentinel/)

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

## Quick Start

```powershell
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
./scripts/Test-SessionHijack.ps1

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
```

## Expected Results

All 5 rules have been validated with real incidents in a live Sentinel workspace.

- **Rule 1 (Token Replay)** fires first. Any simulation run from a new IP or device triggers it within the first evaluation cycle.
- **Rule 3 (Surge)** and **Rule 4 (Browser Mismatch)** fire after the simulation generates enough burst and multi-user-agent traffic. Running Test-SessionHijack.ps1 with -BurstCount 40 reliably triggers both.
- **Rule 2 (Impossible Travel)** requires sign-ins from two different geographic locations. Connect to a VPN in a different city or country and run az rest --method GET --url "https://graph.microsoft.com/v1.0/me". In testing, Springfield to Toronto at 7,526 km/h triggered the rule immediately.
- **Rule 5 (CAE Revocation)** requires a session revocation followed by re-authentication from a different IP. Revoke sessions with az rest --method POST --url "https://graph.microsoft.com/v1.0/users/{user-id}/revokeSignInSessions", then sign in from a VPN or different network.

## Troubleshooting

- **WSL and VPN:** WSL terminals may bypass your Windows VPN. Run az rest from Windows PowerShell or Azure Cloud Shell where the VPN is active.
- **MFA blocks container-based auth:** Tenants with MFA enforced cannot use password-based az login from Azure Container Instances. Use VPN + interactive login instead.
- **Sign-in log ingestion delay:** AADNonInteractiveUserSignInLogs entries can take 15-30 minutes to appear after the auth event.
- **Rule evaluation frequency:** Analytics rules evaluate hourly (PT1H). Wait up to 1 hour after generating telemetry for incidents to appear.
- **Risk Level Distribution panel empty:** Expected in low-risk sandboxes until Identity Protection emits medium or high risk signals.
- **Graph API 403 errors:** The simulation uses User.Read-scoped /me endpoints. Run az login fresh if you see 403s.
- **LocationDetails parsing:** Some workspaces store LocationDetails as a string. The KQL uses parse_json(tostring(LocationDetails)) to handle both formats.

## License

MIT

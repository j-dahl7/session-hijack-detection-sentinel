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
| Session Hijack Threat Dashboard | Workbook | — |

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled
- Entra ID P2 (for Identity Protection risk scoring)
- `SigninLogs` and `NonInteractiveUserSignInLogs` routed to Sentinel via Entra diagnostic settings
- Azure CLI + PowerShell 7+

## Quick Start

```powershell
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

# Deploy
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"

# Simulate
./scripts/Test-SessionHijack.ps1

# Cleanup
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
```

## Expected Results

- `LAB - Token Replay from New Device or IP` is usually the first rule to generate incidents in a small sandbox.
- `LAB - Anomalous Non-Interactive Sign-in Surge` and `LAB - Browser or OS Mismatch in Same Session` often return live query matches from the same simulation run.
- `LAB - Impossible Travel on Token Refresh` needs an extra sign-in from a different geography, such as Azure Cloud Shell or a VPN in another country.
- `LAB - CAE Revocation Followed by New Location Auth` needs a real CAE revocation event, so it is valid but less common in test tenants.

## Troubleshooting

- The lab is portable across tenants, but it is not environment-agnostic. You still need Sentinel enabled, both Entra sign-in log categories routed to the workspace, Azure CLI authenticated, and PowerShell 7+.
- The simulation now sticks to low-privilege Graph `User.Read` calls so it works with the default Azure CLI delegated token in most tenants.
- If you still see sparse telemetry, wait 15-30 minutes for ingestion and 1 hour for scheduled analytics evaluation.
- If the workbook's **Risk Level Distribution** panel is empty, that is expected until Entra ID emits medium or high risk signals.

## License

MIT

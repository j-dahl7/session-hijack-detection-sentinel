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

## License

MIT

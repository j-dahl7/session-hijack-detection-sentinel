# Session Hijack Detection for Microsoft Sentinel

Detect infostealer session hijacking with 5 Sentinel analytics rules, 5 hunting queries, and a threat dashboard workbook.

**Blog post:** [Detecting Infostealer Session Hijacking with Microsoft Sentinel](https://nineliveszerotrust.com/blog/session-hijack-detection-sentinel/)

## Validation Boundary

The August 13, 2026 source-audited revision passed offline PowerShell parsing, mocked
ownership/cleanup checks, and KQL/static contract review. It was not freshly
deployed, queried, or exercised against a live Entra/Sentinel tenant. Historical
incidents may demonstrate earlier revisions, but they do not prove that the
current helper will create the token issuance, refresh, device, geography, risk,
or revoked-grant rows required by every rule.

## What Gets Deployed

| Resource | Type | MITRE |
|---|---|---|
| LAB - Token Replay from New Device or IP | Analytics Rule (High) | Unfamiliar user/IP/device-ID tuple; a new combination does not prove either value is globally new. T1539, T1550.001 |
| LAB - Impossible Travel on Token Refresh | Analytics Rule (High) | 500 km/h triage threshold; legitimate flights, VPN egress, and GeoIP error require context and tenant tuning. T1539 |
| LAB - Anomalous Non-Interactive Sign-in Surge | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - Browser or OS Mismatch in Same Session | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - Revoked Grant Followed by New-IP Authentication | Analytics Rule (High) | Entra error 50173 followed by a same-UserId success from a different IP; triage lead, not proof of theft or CAE enforcement. T1539, T1550.001 |
| Session Hijack Threat Dashboard | Workbook | - |

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled
- Entra ID P2 (for Identity Protection risk scoring)
- SigninLogs and NonInteractiveUserSignInLogs routed to Sentinel via Entra diagnostic settings
- Azure CLI + PowerShell 7+
- Permission to read Entra diagnostic settings and workspace logs and to create
  Sentinel rules/workbooks in the named existing workspace

The deployer checks each Azure CLI exit code explicitly. Failed reads and
deletes remain fatal on supported PowerShell versions even when the optional
native-error preference is unavailable or disabled.

The workspace is shared infrastructure. This lab does not create or delete it.
Existing ingestion, retention, Entra licensing, and Sentinel charges apply.

## Quick Start

```powershell
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"
./scripts/Test-SessionHijack.ps1 -TenantId "<tenant-id>" -BurstCount 30

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy -WhatIf
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
```

For deployment preview, append `-WhatIf` to the first deploy command. It still
performs read-only discovery, diagnostic-setting checks, and workspace queries,
but guarded rule/workbook writes are skipped. `-Destroy -WhatIf` lists and
validates deterministic IDs and ownership markers without deleting them.
Neither preview validates live rule output.

Deployment parameters are `-ResourceGroup`, `-WorkspaceName`,
`-SkipDiagnostics`, `-SkipSentinel`, `-Destroy`, and PowerShell's common
`-WhatIf` switch. The helper accepts `-TenantId`, `-BurstCount` (default 30),
and `-SkipBurst`.

## Validation Expectations

`Test-SessionHijack.ps1` is a benign connectivity and seed-activity helper. It
does not hijack a session, replay a stolen token, force token refreshes, control
Entra's sign-in aggregation, or deterministically generate incidents. Cached
Graph calls do not map one-to-one to sign-in-log rows, and changing an HTTP
`User-Agent` does not guarantee a different Entra `DeviceDetail` fingerprint.
`-BurstCount` controls Graph request count only; no value reliably triggers a
rule.

| Rule | Live telemetry actually required |
|---|---|
| Token Replay | Successful activity for the same user from a genuinely new IP or device relative to the query baseline |
| Impossible Travel | Successful sign-ins/token refreshes from geographically separated public IPs with usable locations and timestamps; a VPN or Cloud Shell may still resolve nearby or be normalized |
| Non-Interactive Surge | Enough qualifying rows in `AADNonInteractiveUserSignInLogs` above the rule threshold/baseline, not merely repeated cached-token API calls |
| Browser/OS Mismatch | The same recorded session with genuinely different browser/OS fingerprints in `DeviceDetail` |
| Revoked Grant | Error 50173 in either interactive or non-interactive logs, followed within 30 minutes by a successful authentication in either table for the same nonempty immutable `UserId` from a different `IPAddress`; the helper does not perform this lifecycle |

Validate in layers: confirm raw rows and their session/correlation fields,
execute each KQL query manually over the right time window, then wait for the
scheduled rule and incident pipeline. Treat rule silence as a data/condition
question, not proof that the deployment or attack simulation succeeded.

### Rule 5 manual validation

Use a dedicated low-privilege lab identity because revoking sign-in sessions
invalidates that user's refresh tokens across applications:

1. At egress IP A, sign in to an application that uses refresh tokens. Confirm
   the raw row and record its nonempty `UserId`.
2. As an authorized administrator, revoke the lab user's sign-in sessions.
3. Let the existing client at IP A attempt a token refresh. Confirm a
   `SigninLogs` or `AADNonInteractiveUserSignInLogs` row whose `ResultType` is
   `50173`.
4. Only after that failure, reauthenticate the same user from approved egress
   IP B within 30 minutes. Confirm a success (`ResultType == "0"`) with the same
   `UserId` and a different `IPAddress`.
5. Run Rule 5 manually over the matching time range before waiting for its
   hourly schedule.

Microsoft documents 50173 as an expired grant that was revoked; causes include
password changes, refresh-token expiry, and administrator revocation. It does
not by itself prove Continuous Access Evaluation or malicious activity. Both
interactive and non-interactive sign-in tabs can contain relevant requests, so
the rule searches both tables on each side of the correlation. Review
[Microsoft's 50173 guidance](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/error-code-aadsts50173-grant-expired-revoked),
[the sign-in table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs),
and [CAE reporting boundaries](https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-continuous-access-evaluation-troubleshoot).

The helper sends benign calls to Microsoft Graph and queries `api.ipify.org` to
display the current public IP. Run it only with a dedicated low-privilege lab
identity and review that external call for your environment.

## Troubleshooting

- **WSL and VPN:** WSL terminals may bypass your Windows VPN. Run az rest from Windows PowerShell or Azure Cloud Shell where the VPN is active.
- **Sign-in log ingestion delay:** `AADNonInteractiveUserSignInLogs` can be
  delayed or aggregated; do not assume a fixed arrival window.
- **Rule evaluation frequency:** the bundled analytics rules are configured
  hourly (`PT1H`). Ingestion, scheduling, and incident creation can add further
  delay.
- **Risk Level Distribution panel empty:** Expected in low-risk sandboxes until Identity Protection emits medium or high risk signals.
- **Graph API 403 errors:** The simulation uses User.Read-scoped /me endpoints. Run az login fresh if you see 403s.
- **LocationDetails parsing:** Some workspaces store LocationDetails as a string. The KQL uses parse_json(tostring(LocationDetails)) to handle both formats.

## Cleanup Scope

Destroy mode removes only the five deterministically identified, ownership-
marked analytics rules and the ownership-tagged workbook from the named
existing workspace. It does not delete the resource group, workspace,
diagnostic settings, sign-in data, incidents, or shared licensing/configuration.
Always run `-Destroy -WhatIf` first and verify the subscription, resource group,
workspace, IDs, and ownership markers shown.

## License

MIT

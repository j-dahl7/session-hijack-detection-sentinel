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

The November 13, 2026 revision changes the deployment default: all five rules
are now created disabled, and `-EnableRules` is the explicit switch that enables
them. Validation of that revision is offline checks only, run on November 13,
2026: PowerShell parsing and the mocked deployment and cleanup tests, including
a contract test that fails if a default deployment ever sends an enabled rule.
The five rule queries are unchanged. The disabled default and `-EnableRules`
have not been deployed to, or exercised against, a live Sentinel workspace.

## What Gets Deployed

| Resource | Type | MITRE |
|---|---|---|
| LAB - Token Replay from New Device or IP | Analytics Rule (High) | Unfamiliar user/IP/device-ID tuple; a new combination does not prove either value is globally new. T1539, T1550.001 |
| LAB - Impossible Travel on Token Refresh | Analytics Rule (High) | 500 km/h triage threshold; legitimate flights, VPN egress, and GeoIP error require context and tenant tuning. T1539 |
| LAB - Anomalous Non-Interactive Sign-in Surge | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - Browser or OS Mismatch in Same Session | Analytics Rule (Medium) | T1539, T1550.001 |
| LAB - Revoked Grant Followed by New-IP Authentication | Analytics Rule (High) | Entra error 50173 followed by a same-UserId success from a different IP; triage lead, not proof of theft or CAE enforcement. T1539, T1550.001 |
| Session Hijack Threat Dashboard | Workbook | - |

All five rules are created disabled; the next section explains how to enable
them.

## Rule State: Disabled by Default

Rules deploy disabled unless `-EnableRules` is explicitly supplied. Microsoft
documents that a rule created with the Disabled status is created but does not
run, and that an Enabled rule runs immediately upon creation
([Create scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/create-analytics-rules)).
A disabled rule therefore creates no alerts or incidents. Each rule keeps its
incident-creation setting, which applies as soon as the rule is enabled.

1. Deploy without the switch and review the five rules in Microsoft Sentinel >
   Analytics > Active rules.
2. Run each query manually against your own sign-in data and tune thresholds
   and exclusions (see [Validation Expectations](#validation-expectations)).
3. Enable deliberately: rerun the same command with `-EnableRules`, or enable
   individual rules from the Active rules list.

The switch is declarative: every deployment writes the state it was asked for.
A later run without `-EnableRules` returns all five lab rules to disabled,
including rules you enabled in the portal, and warns about each enabled rule
before it does. `-WhatIf` prints the same warnings and the planned state
without writing. After each write the deployer compares the state in Sentinel's
response with the requested one and stops if they differ. The summary reports
that confirmed state and the command that enables the rules later.
`-EnableRules` cannot be combined with `-Destroy` or `-SkipSentinel`.

Revisions through commit `6992806` created every rule enabled. Rules deployed
from those revisions stay enabled until you rerun this revision without
`-EnableRules`, disable them in the portal, or remove them with `-Destroy`.

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled
- Entra ID P2 (for Identity Protection risk scoring)
- SigninLogs and NonInteractiveUserSignInLogs routed to Sentinel via Entra diagnostic settings
- Azure CLI + PowerShell 7.4+
- The explicitly installed `log-analytics` CLI extension (`az extension add --name log-analytics`)
- Permission to read Entra diagnostic settings and workspace logs and to create
  Sentinel rules/workbooks in the named existing workspace

The deployer checks each Azure CLI exit code explicitly. Failed reads and
deletes remain fatal even when automatic native-error handling is disabled.
Azure CLI stderr remains visible for troubleshooting; avoid sharing raw command
logs without reviewing them. The diagnostics check uses the active Azure cloud's
ARM origin and compares the full workspace resource ID, not a name substring.

All rule and workbook ownership conflicts are checked before the first write.
This reduces known partial-deployment failures; it is not an atomic transaction
against concurrent changes by another operator.

The workspace is shared infrastructure. This lab does not create or delete it.
Existing ingestion, retention, Entra licensing, and Sentinel charges apply.

## Quick Start

```powershell
git clone https://github.com/j-dahl7/session-hijack-detection-sentinel.git
cd session-hijack-detection-sentinel

# Creates the workbook and the five rules, disabled (safe default)
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab"

# After reviewing and tuning the queries, enable the rules explicitly
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -EnableRules
./scripts/Test-SessionHijack.ps1 -TenantId "<tenant-id>" -BurstCount 30

./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy -WhatIf
./scripts/Deploy-Lab.ps1 -ResourceGroup "rg-sentinel-lab" -WorkspaceName "law-sentinel-lab" -Destroy
```

For deployment preview, append `-WhatIf` to either deploy command. It still
performs read-only discovery, diagnostic-setting checks, and workspace queries,
but guarded rule/workbook writes are skipped, and the summary shows the planned
rule state. `-Destroy -WhatIf` lists and validates deterministic IDs and
ownership markers without deleting them. Neither preview validates live rule
output.

Cleanup also recognizes the deterministic ID and ownership marker of the prior
`LAB - CAE Revocation Followed by New Location Auth` rule. An upgrade stops if
that legacy rule remains, so preview cleanup before redeploying the current rule.
Resources with a matching title but an unknown ID or missing marker are never
adopted or deleted automatically; inspect those older deployments manually.

Deployment parameters are `-ResourceGroup`, `-WorkspaceName`,
`-SkipDiagnostics`, `-SkipSentinel`, `-EnableRules` (alias
`-EnableSentinelRules`), `-Destroy`, and PowerShell's common `-WhatIf` switch.
`Get-Help ./scripts/Deploy-Lab.ps1 -Parameter EnableRules` shows the switch and
its disabled default. The helper accepts `-TenantId`, `-BurstCount` (default
30), and `-SkipBurst`.

## Validation Expectations

The September 25 source revision adds offline tests of exact diagnostic targets,
preflight failure ordering, legacy cleanup, emitted entity mappings, and optional
Graph failures. CI also parses and binds all five actual deployed KQL queries
with checksum-pinned Microsoft Kusto Language tooling. These are source and
mocked-transport checks, not a new Sentinel deployment or live detection result.

Scheduled rules retain their historical correlation windows and gate output on
source evidence ingested in the last hour (falling back to event time only when
ingestion time is unavailable). Rule 1 considers newly arrived *unfamiliar*
evidence; Rule 5 considers either side of the correlation, including a late
revocation record. This avoids repeating unchanged day-old matches on every
hourly run. New evidence can still update an existing group; this is not an
exactly-once guarantee, and outages or irregular scheduling need independent
replay and tenant validation. The 14-day and 7-day baselines remain intact.

All rules retain nonempty immutable `UserId` in their output and map it to the
Account `AadUserId`; alerts use `AlertPerResult` to avoid combining unrelated
users into one alert. Rules 2 and 5 also map their scalar result IP. Aggregate IP
arrays remain investigation context. The stable API carries parent MITRE
techniques; sub-technique detail remains in this documentation instead of an
unsupported `subTechniques` property. See [entity identifiers](https://learn.microsoft.com/azure/sentinel/entities-reference)
and the [scheduled-rule API](https://learn.microsoft.com/rest/api/securityinsights/alert-rules/create-or-update?view=rest-securityinsights-2024-03-01).

The travel rule preserves subsecond elapsed time and separately labels distant
events with equal timestamps as `Simultaneous`; speed is null for those rows.
GeoIP and timestamp quality still need analyst review. The off-hours hunt ends
at 06:00 UTC exclusively, matching its documented 22:00–06:00 window.

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
execute each KQL query manually over the right time window, then enable the
rules with `-EnableRules` and wait for the scheduled rule and incident pipeline.
Treat rule silence as a rule-state or data/condition question, not proof that
the deployment or attack simulation succeeded.

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
   hourly schedule, which runs only while the rule is enabled.

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

- **No alerts or incidents:** rules are disabled by default, and a disabled rule
  never runs. Check each rule's status in Microsoft Sentinel > Analytics, verify
  the raw sign-in rows and the manual query, then enable with `-EnableRules`.
- **WSL and VPN:** WSL terminals may bypass your Windows VPN. Run az rest from Windows PowerShell or Azure Cloud Shell where the VPN is active.
- **Sign-in log ingestion delay:** `AADNonInteractiveUserSignInLogs` can be
  delayed or aggregated; do not assume a fixed arrival window.
- **Rule evaluation frequency:** once enabled, the bundled analytics rules run
  hourly (`PT1H`). Ingestion, scheduling, and incident creation can add further
  delay.
- **Risk Level Distribution panel empty:** Expected in low-risk sandboxes until Identity Protection emits medium or high risk signals.
- **Graph API 403 errors:** The simulation uses User.Read-scoped /me endpoints. Run az login fresh if you see 403s.
- **LocationDetails parsing:** Some workspaces store LocationDetails as a string. The KQL uses parse_json(tostring(LocationDetails)) to handle both formats.

## Cleanup Scope

Destroy mode removes only the five deterministically identified, ownership-
marked analytics rules, enabled or disabled, and the ownership-tagged workbook
from the named existing workspace. It does not delete the resource group,
workspace, diagnostic settings, sign-in data, incidents, or shared
licensing/configuration.
Always run `-Destroy -WhatIf` first and verify the subscription, resource group,
workspace, IDs, and ownership markers shown.

## License

MIT

"""Rules deploy disabled unless -EnableRules is supplied; mocked Azure responses only."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = ROOT / "scripts" / "Deploy-Lab.ps1"
RULE_NAMES = [
    "LAB - Token Replay from New Device or IP",
    "LAB - Impossible Travel on Token Refresh",
    "LAB - Anomalous Non-Interactive Sign-in Surge",
    "LAB - Browser or OS Mismatch in Same Session",
    "LAB - Revoked Grant Followed by New-IP Authentication",
]
DISABLE_NOTICE = "Currently enabled; deploying without -EnableRules sets it to disabled."
DISABLED_SUMMARY = ("Rule state: DISABLED (safe default; disabled rules do not run, raise alerts, "
                    "or create incidents)")
ENABLED_SUMMARY = ("Rule state: ENABLED by -EnableRules (hourly runs; each result requests an alert, "
                   "with incident creation on)")

# Runs the real deployer. Every az call is answered locally and each PUT body is
# captured exactly as it was written for the request; nothing reaches Azure.
HARNESS = r"""
$ErrorActionPreference = 'Stop'
$global:WorkspaceId = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law'
$owner = 'nine-lives-zero-trust:session-hijack-detection-sentinel'
$global:Calls = [System.Collections.Generic.List[string]]::new()
$global:Puts = [System.Collections.Generic.List[object]]::new()
$global:TempFiles = [System.Collections.Generic.List[string]]::new()
$global:Inventory = @()
if ($env:RULE_STATE_EXISTING -in @('enabled', 'disabled')) {
    $global:Inventory = @(foreach ($name in ($env:RULE_STATE_NAMES -split '\|')) {
        $hash = [System.Security.Cryptography.SHA256]::HashData(
            [System.Text.Encoding]::UTF8.GetBytes("$($global:WorkspaceId)|$owner|rule:$name")
        )
        @{
            name = [guid]::new([byte[]]$hash[0..15]).ToString()
            properties = @{
                displayName = $name
                description = "Owned [Owner: $owner]"
                enabled = $env:RULE_STATE_EXISTING -eq 'enabled'
            }
        }
    })
}

function global:az {
    $request = $args -join ' '
    $global:Calls.Add($request)
    if ($request -match '^monitor log-analytics workspace show') {
        return (@{ id = $global:WorkspaceId; customerId = '11111111-1111-1111-1111-111111111111'; location = 'eastus' } | ConvertTo-Json -Compress)
    }
    if ($request -match 'onboardingStates') { return '{"value":[{"name":"default"}]}' }
    if ($request -match '^cloud show') { return 'https://management.azure.com/' }
    if ($request -match '^extension list') { return '[{"name":"log-analytics"}]' }
    if ($request -match '^monitor log-analytics query') { return '[]' }
    if ($request -match '--method GET' -and $request -match 'alertRules') {
        return (@{ value = @($global:Inventory) } | ConvertTo-Json -Depth 8 -Compress)
    }
    if ($request -match '^resource list') { return '[]' }
    if ($request -match '--method PUT') {
        $url = [string]$args[[array]::IndexOf($args, '--url') + 1]
        $bodyArgument = [string]$args[[array]::IndexOf($args, '--body') + 1]
        if (-not $bodyArgument.StartsWith('@')) { throw 'Expected a local JSON body file' }
        $raw = Get-Content -LiteralPath $bodyArgument.Substring(1) -Raw
        $global:Puts.Add(@{ url = $url; raw = $raw })
        $body = $raw | ConvertFrom-Json
        if ($url -match '/alertRules/([^/?]+)\?api-version=2024-03-01$') {
            $properties = @{ displayName = $body.properties.displayName }
            switch ($env:RULE_STATE_ECHO) {
                'opposite' { $properties.enabled = -not $body.properties.enabled }
                'missing' { }
                default { $properties.enabled = $body.properties.enabled }
            }
            return (@{ name = $Matches[1]; properties = $properties } | ConvertTo-Json -Depth 5 -Compress)
        }
        if ($url -match '/workbooks/([^/?]+)\?api-version=2022-04-01$') {
            return (@{ name = $Matches[1]; properties = @{ displayName = $body.properties.displayName } } | ConvertTo-Json -Depth 5 -Compress)
        }
        throw "Unexpected mocked PUT target: $url"
    }
    throw "Unexpected mocked az call: $request"
}

function global:New-TemporaryFile {
    if ($env:RULE_STATE_SWITCHES -split ',' -contains 'WhatIf') { throw 'Preview attempted to create a temporary request file' }
    $file = Microsoft.PowerShell.Utility\New-TemporaryFile
    $global:TempFiles.Add($file.FullName)
    return $file
}

$parameters = @{ ResourceGroup = 'lab-rg'; WorkspaceName = 'lab-law'; SkipDiagnostics = $true }
foreach ($name in ($env:RULE_STATE_SWITCHES -split ',' | Where-Object { $_ })) { $parameters[$name] = $true }

# Collect host output line by line so a failed run still shows what it printed.
$lines = [System.Collections.Generic.List[string]]::new()
$failure = $null
try {
    & $env:RULE_STATE_DEPLOY_SCRIPT @parameters 6>&1 | ForEach-Object { $lines.Add([string]$_) }
}
catch { $failure = $_.Exception.Message }
'RESULT:' + (@{
    error = $failure
    output = $lines -join "`n"
    calls = @($global:Calls.ToArray())
    puts = @($global:Puts.ToArray())
    inventoryIds = @($global:Inventory | ForEach-Object { $_.name })
    tempFilesLeft = @($global:TempFiles | Where-Object { Test-Path -LiteralPath $_ }).Count
} | ConvertTo-Json -Depth 6 -Compress)
"""


class RuleEnablementContractTests(unittest.TestCase):
    def test_deployer_source_keeps_the_disabled_default(self):
        script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("[switch]$EnableRules", script)
        self.assertIn("[Alias('EnableSentinelRules')]", script)
        self.assertIn("$RulesEnabled = [bool]$EnableRules", script)
        self.assertIn("enabled               = $RulesEnabled", script)
        # A switch initializer, a second assignment, or a literal true would
        # make "enabled" the state an operator gets without asking for it.
        self.assertIsNone(re.search(r"\[switch\]\s*\$EnableRules\s*=", script))
        self.assertEqual(len(re.findall(r"\$RulesEnabled\s*=(?!=)", script)), 1)
        # The one literal true that remains is incident grouping, not the rule state.
        self.assertEqual(len(re.findall(r"(?im)^\s*enabled\s*=\s*\$true\b", script)), 1)
        self.assertRegex(script, r"groupingConfiguration = @\{\s*enabled\s*=\s*\$true\b")
        self.assertIn(".PARAMETER EnableRules", script)
        self.assertRegex(
            script, r"Without this switch the\s+rules are created or updated disabled"
        )
        self.assertIn("cannot be combined with -Destroy or -SkipSentinel", script)

    def test_documentation_states_the_disabled_default_and_the_opt_in(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        helper = (ROOT / "scripts" / "Test-SessionHijack.ps1").read_text(encoding="utf-8")

        self.assertIn("-EnableRules", readme)
        self.assertIn("-EnableSentinelRules", readme)
        self.assertIn("created disabled", readme)
        self.assertIn('-WorkspaceName "law-sentinel-lab" -EnableRules', readme)
        self.assertIn("Deploy-Lab.ps1 -EnableRules", helper)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class RuleEnablementTests(unittest.TestCase):
    def run_deploy(self, *switches, existing="none", echo="request"):
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", HARNESS],
            env={**os.environ, "RULE_STATE_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT),
                 "RULE_STATE_SWITCHES": ",".join(switches), "RULE_STATE_EXISTING": existing,
                 "RULE_STATE_ECHO": echo, "RULE_STATE_NAMES": "|".join(RULE_NAMES)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        result_lines = [line[7:] for line in completed.stdout.splitlines() if line.startswith("RESULT:")]
        self.assertEqual(len(result_lines), 1, completed.stdout + completed.stderr)
        result = json.loads(result_lines[0])
        # Column alignment is presentation; compare the words.
        result["output"] = " ".join(result["output"].split())
        return result

    def rule_requests(self, result):
        return [(put["url"], json.loads(put["raw"])) for put in result["puts"] if "/alertRules/" in put["url"]]

    def assert_rule_bodies(self, result, enabled):
        requests = self.rule_requests(result)
        self.assertEqual([body["properties"]["displayName"] for _, body in requests], RULE_NAMES)
        for _, body in requests:
            properties = body["properties"]
            with self.subTest(rule=properties["displayName"]):
                self.assertEqual(body["kind"], "Scheduled")
                # A JSON boolean, never a string, an absent key, or a serialized switch.
                self.assertIs(properties.get("enabled"), enabled)
                # Incident settings stay ready for the moment an operator opts in.
                self.assertIs(properties["incidentConfiguration"]["createIncident"], True)
                self.assertIs(properties["incidentConfiguration"]["groupingConfiguration"]["enabled"], True)
                self.assertEqual(properties["eventGroupingSettings"], {"aggregationKind": "AlertPerResult"})
        self.assertEqual(result["tempFilesLeft"], 0, result)
        return requests

    def test_default_deployment_creates_every_rule_disabled(self):
        result = self.run_deploy()
        self.assertIsNone(result["error"], result)
        self.assert_rule_bodies(result, False)
        self.assertEqual(len(result["puts"]), 6, result)  # five rules and the workbook
        output = result["output"]
        self.assertIn("Rule state: DISABLED (safe default; add -EnableRules to enable)", output)
        self.assertEqual(output.count("(disabled)"), 5, output)
        self.assertIn("Deployment complete!", output)
        self.assertIn(DISABLED_SUMMARY, output)
        # The summary says how to enable later, for this workspace.
        self.assertIn(
            "./scripts/Deploy-Lab.ps1 -ResourceGroup 'lab-rg' -WorkspaceName 'lab-law' -EnableRules",
            output,
        )
        self.assertIn("A later run without -EnableRules disables the rules again.", output)
        self.assertNotIn("ENABLED", output)
        self.assertNotIn(DISABLE_NOTICE, output)

    def test_enable_rules_and_its_family_alias_enable_every_rule(self):
        for switch in ("EnableRules", "EnableSentinelRules"):
            with self.subTest(switch=switch):
                result = self.run_deploy(switch)
                self.assertIsNone(result["error"], result)
                self.assert_rule_bodies(result, True)
                output = result["output"]
                self.assertIn("Rule state: ENABLED by -EnableRules", output)
                self.assertEqual(output.count("(enabled)"), 5, output)
                self.assertIn(ENABLED_SUMMARY, output)
                self.assertIn("To disable them, rerun without -EnableRules", output)
                self.assertNotIn("DISABLED", output)

    def test_rerun_without_the_switch_disables_enabled_rules_and_says_so(self):
        result = self.run_deploy(existing="enabled")
        self.assertIsNone(result["error"], result)
        requests = self.assert_rule_bodies(result, False)
        # The same five owned rules are updated in place, not recreated beside them.
        updated_ids = [url.split("/alertRules/")[1].split("?")[0] for url, _ in requests]
        self.assertEqual(updated_ids, result["inventoryIds"])
        self.assertEqual(result["output"].count(DISABLE_NOTICE), 5, result["output"])
        self.assertEqual(result["output"].count("Updated: "), 5, result["output"])

        for existing, switches in (("disabled", ()), ("enabled", ("EnableRules",))):
            with self.subTest(existing=existing, switches=switches):
                quiet = self.run_deploy(*switches, existing=existing)
                self.assertIsNone(quiet["error"], quiet)
                self.assert_rule_bodies(quiet, bool(switches))
                self.assertNotIn(DISABLE_NOTICE, quiet["output"])

    def test_preview_reports_the_planned_rule_state_without_writes(self):
        for switches, summary, notices in ((("WhatIf",), DISABLED_SUMMARY, 5),
                                           (("WhatIf", "EnableRules"), ENABLED_SUMMARY, 0)):
            with self.subTest(switches=switches):
                result = self.run_deploy(*switches, existing="enabled")
                self.assertIsNone(result["error"], result)
                self.assertEqual(result["puts"], [])
                self.assertFalse(any(f"--method {method}" in call for call in result["calls"]
                                     for method in ("PUT", "PATCH", "POST", "DELETE")), result)
                output = result["output"]
                self.assertIn("Deployment preview complete; no changes applied.", output)
                self.assertIn("=== Planned Resources ===", output)
                self.assertIn(summary, output)
                self.assertEqual(output.count(DISABLE_NOTICE), notices, output)

    def test_unconfirmed_rule_state_stops_the_deployment(self):
        for switches, echo in (((), "opposite"), (("EnableRules",), "opposite"), ((), "missing")):
            with self.subTest(switches=switches, echo=echo):
                result = self.run_deploy(*switches, echo=echo)
                expected = "enabled" if switches else "disabled"
                self.assertIn(
                    f"did not confirm analytics rule '{RULE_NAMES[0]}' as {expected}",
                    result["error"] or "",
                )
                self.assertEqual(len(result["puts"]), 1, result)
                self.assertEqual(result["tempFilesLeft"], 0, result)
                self.assertIn(f"Deploying: {RULE_NAMES[0]}", result["output"])
                self.assertNotIn("Created: ", result["output"])
                self.assertNotIn("Deployment complete!", result["output"])
                self.assertNotIn("Deployed Resources", result["output"])

    def test_enable_rules_is_rejected_where_no_rule_is_written_before_any_azure_call(self):
        for other in ("Destroy", "SkipSentinel"):
            with self.subTest(other=other):
                result = self.run_deploy("EnableRules", other, existing="enabled")
                self.assertIn("cannot be combined with -Destroy or -SkipSentinel", result["error"] or "")
                self.assertEqual(result["calls"], [])

    def test_get_help_exposes_the_switch_and_its_default(self):
        command = "(Get-Help $env:RULE_STATE_DEPLOY_SCRIPT -Parameter EnableRules).description | Out-String -Width 4096"
        completed = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            env={**os.environ, "RULE_STATE_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("Without this switch the rules are created or updated disabled",
                      " ".join(completed.stdout.split()))


if __name__ == "__main__":
    unittest.main()

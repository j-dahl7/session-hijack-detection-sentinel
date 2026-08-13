import shutil
import subprocess
import os
import textwrap
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = LAB_ROOT / "scripts" / "Deploy-Lab.ps1"
TEST_SCRIPT = LAB_ROOT / "scripts" / "Test-SessionHijack.ps1"


class SessionHijackScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deploy_source = DEPLOY_SCRIPT.read_text(encoding="utf-8-sig")
        cls.test_source = TEST_SCRIPT.read_text(encoding="utf-8-sig")

    def test_workbook_is_bound_to_the_deployed_workspace(self):
        self.assertIn("$workbookDefinition.fallbackResourceIds = @($workspaceId)", self.deploy_source)
        self.assertIn("ConvertTo-Json -Depth 100 -Compress", self.deploy_source)

    def test_helper_uses_placeholder_tenant_and_truthful_detection_claims(self):
        self.assertNotIn("e24be7b2-dbc8-47ef-8071-593408b48c9e", self.test_source)
        self.assertIn('-TenantId "<tenant-id>"', self.test_source)
        self.assertIn("cached-token requests may not create new entra refresh events", self.test_source.lower())
        self.assertIn("not guaranteed", self.test_source)
        self.assertNotIn("distinct browser/OS fingerprints -> triggers Rule 4", self.test_source)

    def test_deployment_uses_deterministic_ids_and_proves_ownership(self):
        self.assertIn("function Get-LabResourceGuid", self.deploy_source)
        self.assertIn("nine-lives-zero-trust:session-hijack-detection-sentinel", self.deploy_source)
        self.assertIn("Refusing to delete analytics rule", self.deploy_source)
        self.assertIn("Refusing to delete workbook", self.deploy_source)
        self.assertIn("A non-lab analytics rule already uses", self.deploy_source)
        self.assertIn("A non-lab workbook already uses", self.deploy_source)
        self.assertNotIn("$existingRuleIdsByName", self.deploy_source)

    def test_browser_os_rule_is_correlated_to_one_recorded_session(self):
        self.assertIn(
            "where isnotempty(UserPrincipalName) and isnotempty(SessionId)",
            self.deploy_source,
        )
        self.assertIn(
            "by UserPrincipalName, SessionId, bin(TimeGenerated, TimeWindowHours)",
            self.deploy_source,
        )
        self.assertIn(
            "project TimeGenerated, UserPrincipalName, SessionId, DistinctFingerprints",
            self.deploy_source,
        )

    def test_rule_descriptions_preserve_tuple_and_travel_boundaries(self):
        readme = (LAB_ROOT / "README.md").read_text(encoding="utf-8")
        queries = (LAB_ROOT / "detection" / "analytics-rules.kql").read_text(
            encoding="utf-8"
        )

        self.assertIn("new combination does not prove either value is globally new", readme)
        self.assertIn("Legitimate flights, VPN egress, and GeoIP error", self.deploy_source)
        self.assertIn("legitimate air travel, VPN egress changes, or GeoIP error", queries)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
    def test_deploy_and_destroy_whatif_perform_no_mutations_or_temp_writes(self):
        harness = textwrap.dedent(
            r"""
            $ErrorActionPreference = 'Stop'
            $script:Mutations = @()
            function global:az {
                $request = $args -join ' '
                if ($request -match '(--method PUT|--method DELETE|deployment .* create)') {
                    $script:Mutations += $request
                    throw "Mutation attempted during WhatIf: $request"
                }
                if ($request -match 'monitor log-analytics workspace show') {
                    '{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law","customerId":"11111111-1111-1111-1111-111111111111","location":"eastus"}'
                }
                elseif ($request -match 'onboardingStates') { '{"value":[{"name":"default"}]}' }
                elseif ($request -match 'alertRules') {
                    '{"value":[]}'
                }
                elseif ($request -match 'resource list') {
                    '[]'
                }
                elseif ($request -match 'monitor log-analytics query') { '[]' }
                else { throw "Unexpected mocked az call: $request" }
            }
            function global:New-TemporaryFile {
                throw 'WhatIf attempted to create a temporary file'
            }

            $deploy = & $env:SESSION_DEPLOY_SCRIPT -ResourceGroup lab-rg -WorkspaceName lab-law -SkipDiagnostics -WhatIf 6>&1 | Out-String
            if ($deploy -notmatch 'Deployment preview complete; no changes applied') {
                throw "Deployment preview summary missing: $deploy"
            }
            $destroy = & $env:SESSION_DEPLOY_SCRIPT -ResourceGroup lab-rg -WorkspaceName lab-law -Destroy -WhatIf 6>&1 | Out-String
            if ($destroy -notmatch 'Cleanup preview complete; no resources were deleted') {
                throw "Cleanup preview summary missing: $destroy"
            }
            if ($script:Mutations.Count -ne 0) {
                throw "WhatIf mutations: $($script:Mutations -join '; ')"
            }
            'OK'
            """
        )
        result = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-Command", harness],
            env={**os.environ, "SESSION_DEPLOY_SCRIPT": str(DEPLOY_SCRIPT)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertIn("OK", result.stdout)


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is not available")
class SessionHijackPowerShellSyntaxTests(unittest.TestCase):
    def test_scripts_parse_without_errors(self):
        for script_path in (DEPLOY_SCRIPT, TEST_SCRIPT):
            with self.subTest(script=script_path.name):
                command = (
                    "$tokens=$null; $errors=$null; "
                    "[System.Management.Automation.Language.Parser]::ParseFile("
                    "$env:SESSION_SCRIPT,[ref]$tokens,[ref]$errors) | Out-Null; "
                    "if ($errors.Count) { throw ($errors | ForEach-Object Message | Out-String) }"
                )
                completed = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
                    env={**dict(__import__("os").environ), "SESSION_SCRIPT": str(script_path)},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)


if __name__ == "__main__":
    unittest.main()

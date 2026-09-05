"""Native subprocess failures must not become successful Azure operations."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is required')
class NativeExitTests(unittest.TestCase):
    def run_harness(self, source):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'harness.ps1'
            script.write_text(source, encoding='utf-8')
            result = subprocess.run(['pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                    env={**os.environ, 'LAB_ROOT': str(ROOT), 'NATIVE_PYTHON': sys.executable,
                                         'NATIVE_TEST_DIR': directory},
                                    capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
            self.assertIn('OK', result.stdout)

    def test_native_failure_is_fatal_without_leaking_failed_output(self):
        self.run_harness(r'''
            $ErrorActionPreference='Stop'
            . (Join-Path $env:LAB_ROOT 'scripts/Invoke-AzChecked.ps1')
            function global:az {
                & $env:NATIVE_PYTHON -c 'import sys; print("failed-output-sentinel"); sys.exit(int(sys.argv[1]))' $env:MOCK_EXIT
            }
            foreach($preference in @($false,$true)) {
                $PSNativeCommandUseErrorActionPreference=$preference
                $env:MOCK_EXIT='0'
                if ((Invoke-AzChecked rest --method GET) -ne 'failed-output-sentinel') { throw 'Successful output lost' }
                $env:MOCK_EXIT='7'
                $result=$null; $failure=''
                try { $result=Invoke-AzChecked rest --method DELETE --token 'argument-sentinel' } catch { $failure=$_.Exception.Message }
                if ($failure -notmatch 'exit code 7' -or $result) { throw 'Failed native output escaped' }
                if ($failure -match 'failed-output-sentinel|argument-sentinel') { throw 'Failure exposed command data' }
                if ($PSNativeCommandUseErrorActionPreference -ne $preference) { throw 'Preference leaked across calls' }
            }
            'OK'
        ''')

    def test_cleanup_native_delete_failure_never_reports_success(self):
        self.run_harness(r'''
            $ErrorActionPreference='Stop'
            $global:workspaceId='/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law'
            $global:isOAuth=Test-Path -LiteralPath (Join-Path $env:LAB_ROOT 'hardening/Set-OAuthHardening.ps1')
            $global:owner=if($global:isOAuth){'nine-lives-zero-trust:oauth-redirect-abuse-sentinel'}else{'nine-lives-zero-trust:session-hijack-detection-sentinel'}
            $global:ruleName=if($global:isOAuth){'LAB - OAuth Consent After Risky Sign-in'}else{'LAB - Token Replay from New Device or IP'}
            $hash=[System.Security.Cryptography.SHA256]::Create()
            try { $bytes=$hash.ComputeHash([Text.Encoding]::UTF8.GetBytes("$($global:workspaceId)|$($global:owner)|rule:$($global:ruleName)")) } finally { $hash.Dispose() }
            $global:ruleId=[guid]::new([byte[]]$bytes[0..15]).ToString()
            $global:deletes=0
            function global:az {
                $request=$args -join ' '
                if ($request -match '^monitor log-analytics workspace show') { return (@{id=$global:workspaceId;customerId='customer-1';location='eastus'} | ConvertTo-Json -Compress) }
                if ($request -match 'onboardingStates') { return '{"value":[{"name":"default"}]}' }
                if ($request -match '^cloud show') { return 'https://management.azure.com/' }
                if ($request -match '^resource list') { return '[]' }
                if ($request -match '--method GET' -and $request -match 'alertRules') {
                    return (@{value=@(@{name=$global:ruleId;properties=@{displayName=$global:ruleName;description="[Owner: $($global:owner)]"}})} | ConvertTo-Json -Depth 5 -Compress)
                }
                if ($request -match '--method DELETE') {
                    $global:deletes++
                    & $env:NATIVE_PYTHON -c 'import sys; sys.exit(7)'
                    return
                }
                throw 'Unexpected command in offline cleanup harness'
            }
            $output='';$failure=''
            try { $output=& (Join-Path $env:LAB_ROOT 'scripts/Deploy-Lab.ps1') -ResourceGroup lab-rg -WorkspaceName lab-law -Destroy 6>&1 | Out-String } catch { $failure=$_.Exception.Message }
            if ($failure -notmatch 'exit code 7' -or $global:deletes -ne 1) { throw "Native deletion failure was not fatal: $failure" }
            if ($output -match 'resources destroyed|Deleted:') { throw 'Failed cleanup claimed success' }
            'OK'
        ''')


if __name__ == '__main__':
    unittest.main()

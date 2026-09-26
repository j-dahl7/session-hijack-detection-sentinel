"""Run the actual PowerShell orchestration with no Azure/Graph transport."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
$ErrorActionPreference = 'Stop'
$global:Calls = [Collections.Generic.List[string]]::new()
$global:Bodies = [Collections.Generic.List[object]]::new()
$testWorkspace = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/lab-rg/providers/Microsoft.OperationalInsights/workspaces/lab-law'
function global:az {
    $request = $args -join ' '
    $global:Calls.Add($request)
    if ($request -match '^cloud show') { return 'https://management.usgovcloudapi.net/' }
    if ($request -match '^extension list') {
        if ($env:REPAIR_CASE -eq 'missing_extension') { return '[]' }
        return '[{"name":"log-analytics"}]'
    }
    if ($request -match '^monitor log-analytics workspace show') {
        return (@{ id=$testWorkspace;customerId='customer';location='usgovvirginia' } | ConvertTo-Json)
    }
    if ($request -match 'onboardingStates') { return '{"value":[{"name":"default"}]}' }
    if ($request -match 'diagnosticSettings') {
        $target = if ($env:REPAIR_CASE -eq 'wrong_workspace') { $testWorkspace.Replace('/workspaces/lab-law','/workspaces/lab-law-other') } else { $testWorkspace.ToUpperInvariant() + '/' }
        return (@{value=@(@{properties=@{workspaceId=$target;logs=@(@{category='SignInLogs';enabled=$true},@{category='NonInteractiveUserSignInLogs';enabled=$true})}})} | ConvertTo-Json -Depth 10)
    }
    if ($request -match '^monitor log-analytics query') { return '[]' }
    if ($request -match '--method GET' -and $request -match 'alertRules') {
        if ($env:REPAIR_CASE -eq 'legacy_owned') {
            $name = 'LAB - CAE Revocation Followed by New Location Auth'
            $owner = 'nine-lives-zero-trust:session-hijack-detection-sentinel'
            $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("$testWorkspace|$owner|rule:$name"))
            $id = [guid]::new([byte[]]$hash[0..15]).ToString()
            return (@{value=@(@{name=$id;properties=@{displayName=$name;description="[Owner: $owner]"}})} | ConvertTo-Json -Depth 10)
        }
        return '{"value":[]}'
    }
    if ($request -match '^resource list') {
        if ($env:REPAIR_CASE -eq 'workbook_conflict') {
            return '[{"name":"foreign-workbook","tags":{"hidden-title":"Session Hijack Threat Dashboard"}}]'
        }
        return '[]'
    }
    if ($request -match '--method DELETE') { return }
    if ($request -match '--method PUT') {
        $file = $args[[Array]::IndexOf($args,'--body')+1].Substring(1)
        $body = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json -Depth 100
        $global:Bodies.Add($body)
        $url = $args[[Array]::IndexOf($args,'--url')+1]
        $name = ($url -split '\?')[0].Split('/')[-1]
        return (@{name=$name;properties=$body.properties} | ConvertTo-Json -Depth 100)
    }
    throw "Unexpected offline command: $request"
}
$failure=$null; $output=''
try {
    if ($env:REPAIR_CASE -eq 'legacy_owned') {
        $output=& (Join-Path $env:LAB_ROOT 'scripts/Deploy-Lab.ps1') -ResourceGroup lab-rg -WorkspaceName lab-law -Destroy 3>&1 6>&1 | Out-String
    } else {
        $output=& (Join-Path $env:LAB_ROOT 'scripts/Deploy-Lab.ps1') -ResourceGroup lab-rg -WorkspaceName lab-law 3>&1 6>&1 | Out-String
    }
} catch { $failure=$_.Exception.Message }
'RESULT:' + (@{error=$failure;output=$output;calls=@($global:Calls.ToArray());bodies=@($global:Bodies.ToArray())} | ConvertTo-Json -Depth 100 -Compress)
'''


@unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 is required')
class ReviewRepairTests(unittest.TestCase):
    def run_case(self, case):
        result = subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',HARNESS],
            env={**os.environ,'LAB_ROOT':str(ROOT),'REPAIR_CASE':case},
            capture_output=True,text=True,timeout=40,check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith('RESULT:')))

    def test_workbook_conflict_stops_before_any_rule_write(self):
        result=self.run_case('workbook_conflict')
        self.assertIn('non-lab workbook', result['error'])
        self.assertEqual(result['bodies'], [])
        self.assertFalse(any('--method PUT' in call or '--method DELETE' in call for call in result['calls']))

    def test_diagnostic_target_uses_exact_resource_id_and_active_cloud(self):
        for case, expected in [('wrong_workspace', 'NOT FOUND'), ('matching_workspace','Enabled ->')]:
            with self.subTest(case=case):
                result=self.run_case(case)
                self.assertIsNone(result['error'],result)
                self.assertIn(expected,result['output'])
                calls=[x for x in result['calls'] if 'diagnosticSettings' in x]
                self.assertEqual(len(calls),1)
                self.assertIn('https://management.usgovcloudapi.net/providers/',calls[0])

    def test_deployed_payloads_map_each_result_to_a_stable_account(self):
        result=self.run_case('matching_workspace')
        self.assertIsNone(result['error'],result)
        rules=[body['properties'] for body in result['bodies'] if body['kind']=='Scheduled']
        self.assertEqual(len(rules),5)
        for rule in rules:
            self.assertEqual(rule['eventGroupingSettings']['aggregationKind'],'AlertPerResult')
            self.assertEqual(rule['entityMappings'][0]['fieldMappings'],[{'identifier':'AadUserId','columnName':'UserId'}])
            self.assertNotIn('subTechniques',rule)
            self.assertIn('UserId',rule['query'].split('| project')[-1])
        self.assertEqual(rules[0]['queryPeriod'],'P14D')
        self.assertEqual(rules[2]['queryPeriod'],'P7D')

    def test_known_owned_legacy_rule_is_included_in_cleanup(self):
        result=self.run_case('legacy_owned')
        self.assertIsNone(result['error'],result)
        self.assertEqual(sum('--method DELETE' in x for x in result['calls']),1)

    def test_missing_query_extension_fails_before_writes(self):
        result=self.run_case('missing_extension')
        self.assertIn('az extension add --name log-analytics',result['error'])
        self.assertEqual(result['bodies'],[])

    def test_optional_identity_failure_does_not_abort_summary(self):
        script=r'''
        $ErrorActionPreference='Stop'
        function global:az { 'offline-test-token' }
        function global:Start-Sleep {}
        function global:Invoke-RestMethod {
            param($Uri,$Headers,$Method,$ErrorAction)
            if ($Uri -match '\$select=') { throw 'Simulated terminating throttle' }
            if ($Uri -match 'ipify') { return @{ip='192.0.2.1'} }
            return @{displayName='Offline Test';userPrincipalName='test@example.invalid'}
        }
        & (Join-Path $env:LAB_ROOT 'scripts/Test-SessionHijack.ps1') -SkipBurst 3>&1 6>&1 | Out-String
        '''
        result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',script],
            env={**os.environ,'LAB_ROOT':str(ROOT)},capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Optional identity lookup failed',result.stdout)
        self.assertIn('Simulation Complete',result.stdout)
        self.assertNotIn('offline-test-token',result.stdout+result.stderr)

    def test_actual_query_variants_keep_exact_parity_and_source_arrival_gates(self):
        deploy=(ROOT/'scripts/Deploy-Lab.ps1').read_text(encoding='utf-8')
        actual=re.findall(r'query\s+= @"\n(.*?)\n"@',deploy,re.S)
        standalone=(ROOT/'detection/analytics-rules.kql').read_text(encoding='utf-8')
        chunks=re.split(r'// RULE \d+:',standalone)[1:]
        self.assertEqual(len(actual),5)
        for query,chunk in zip(actual,chunks):
            extracted=chunk[chunk.index('let '):].split('// ---')[0].strip()
            self.assertEqual(' '.join(query.split()),' '.join(extracted.split()))
            self.assertIn('ingestion_time()',query)
            self.assertRegex(query,r'(LatestEvidence|max_of\([^\n]+\)) > ago\(1h\)')
        self.assertIn('maxif(ArrivalTime, IsUnfamiliar)',actual[0])
        self.assertIn('max_of(RevocationArrival, AuthArrival)',actual[4])
        self.assertIn('(TimeGenerated - PrevTime) / 1h',actual[1])
        self.assertIn('Simultaneous or SpeedKmH',actual[1])


if __name__=='__main__': unittest.main()

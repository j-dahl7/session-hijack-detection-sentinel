[CmdletBinding()]
param([Parameter(Mandatory)][string]$KustoAssembly)
$ErrorActionPreference = 'Stop'
Add-Type -Path $KustoAssembly
$schema = '(TimeGenerated:datetime,UserId:string,UserPrincipalName:string,IPAddress:string,DeviceDetail:dynamic,LocationDetails:dynamic,ResultType:string,SessionId:string,AppDisplayName:string)'
$tables = foreach ($name in @('SigninLogs','AADNonInteractiveUserSignInLogs')) {
    [Kusto.Language.Symbols.TableSymbol]::new($name, $schema, 'Synthetic documented sign-in schema')
}
$database = [Kusto.Language.Symbols.DatabaseSymbol]::new('OfflineValidation', [Kusto.Language.Symbols.Symbol[]]$tables)
$kustoState = [Kusto.Language.GlobalState]::Default.WithDatabase($database)
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Deploy-Lab.ps1') -Raw
$queries = [regex]::Matches($source, '(?s)query\s+= @"\r?\n(.*?)\r?\n"@')
if ($queries.Count -ne 5) { throw 'Expected all five deployed queries; no partial validation allowed.' }
foreach ($query in $queries) {
    $code = [Kusto.Language.KustoCode]::ParseAndAnalyze($query.Groups[1].Value, $kustoState, [Kusto.Language.Utils.CancellationToken]::new())
    $diagnostics = @($code.GetDiagnostics())
    if ($diagnostics.Count) {
        $diagnostics | Select-Object Code, Severity, Message | Format-Table
        throw 'A deployed rule failed offline KQL semantic analysis.'
    }
    if ('UserId' -notin $code.ResultType.Columns.Name) { throw 'An account entity mapping references a missing result column.' }
}
Write-Host 'PASS: all five deployed rules parse and bind, including Account entity columns. No tenant query was run.'

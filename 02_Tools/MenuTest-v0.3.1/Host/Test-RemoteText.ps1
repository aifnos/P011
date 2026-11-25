param([string]$Fixture='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\MenuLab\host\RemoteText.ps1')
$cases=@(Test-P011RemoteText)
if ($Fixture) {
    $raw=[IO.File]::ReadAllText($Fixture,[Text.Encoding]::UTF8)
    $parsed=Read-P011ExitEnvelope -Text $raw
    if ($parsed.Text -cne '0' -or $parsed.Exit -ne 0) { throw 'Captured fixture did not reproduce root response.' }
    Write-Host 'CAPTURED_FIXTURE_OK: body=0, exit=0'
}
Write-Host ('HOST_PARSER_SELFTEST_OK: '+$cases.Count+' cases; no device I/O.')
$cases | ConvertTo-Json -Depth 5

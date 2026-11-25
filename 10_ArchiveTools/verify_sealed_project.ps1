$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $taskRoot 'archive-audit\retained-files.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $manifest.files -or @($manifest.files).Count -eq 0 -or $manifest.root -ne $taskRoot) { throw 'Empty or mismatched retained manifest.' }
$plan = Get-Content -LiteralPath (Join-Path $taskRoot 'archive-audit\archive-plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$retainedPaths = @($manifest.files | ForEach-Object { $_.path })
foreach ($job in $plan.jobs.PSObject.Properties) {
    foreach ($required in @($job.Value.output, ($job.Value.output + '.manifest.json'), ($job.Value.output + '.verified.json'))) {
        if ($required -notin $retainedPaths) { throw ('Required archive is absent from retained manifest: ' + $required) }
    }
}
$checked = 0
foreach ($entry in $manifest.files) {
    $path = [IO.Path]::GetFullPath((Join-Path $taskRoot $entry.path))
    if (-not $path.StartsWith($taskRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid retained member path.' }
    $file = Get-Item -LiteralPath $path -Force
    if ($file.Length -ne $entry.bytes) { throw ('Size mismatch: ' + $entry.path) }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) { throw ('SHA256 mismatch: ' + $entry.path) }
    $checked++
}
Write-Host ('PASS: ' + $checked + ' retained files match SHA256; no device access.')
exit 0

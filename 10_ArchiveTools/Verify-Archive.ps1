param([string]$Root = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
try {
    if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
    $Root = [IO.Path]::GetFullPath($Root)
    $prefix = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $manifest = Get-Content -LiteralPath (Join-Path $Root 'MANIFEST.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $failures = [Collections.Generic.List[string]]::new()
    $checked = 0
    foreach ($item in $manifest.files) {
        $rel = [string]$item.path
        if ([IO.Path]::IsPathRooted($rel) -or $rel.Contains(':') -or $rel -match '(^|[\/])\.\.([\/]|$)') {
            throw "Unsafe manifest path: $rel"
        }
        $full = [IO.Path]::GetFullPath((Join-Path $Root $rel))
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Path outside archive root.' }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            $failures.Add("MISSING: $rel")
        } elseif ((Get-Item -LiteralPath $full).Length -ne [int64]$item.bytes) {
            $failures.Add("SIZE: $rel")
        } elseif ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ine [string]$item.sha256) {
            $failures.Add("HASH: $rel")
        }
        $checked++
        if (($checked % 100) -eq 0) { Write-Host "Checked $checked / $($manifest.files.Count)" }
    }
    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { Write-Host $_ }
        throw "$($failures.Count) archive verification error(s)."
    }
    Write-Host "ARCHIVE_OK: $checked files; edition=$($manifest.edition). No device accessed."
    exit 0
} catch {
    Write-Host ('VERIFY_FAILED: ' + $_.Exception.Message)
    exit 1
}

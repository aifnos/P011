# Local-only candidate builder. Does NOT run adb, modify a device, or launch Z03.
# Uses a source-reviewed, version-specific resource block and fails on hash mismatch.
[CmdletBinding()]
param(
    [string]$PackageDir = 'D:\project\P011\MenuLab',
    [string]$OriginalPath = 'D:\project\P011\backups\Z03',
    [string]$WorkRoot = 'D:\project\P011'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
function Bytes-Hash {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
$manifestPath = Join-Path $PackageDir 'patch\manifest.json'
$m = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$src = (Resolve-Path -LiteralPath $OriginalPath).Path
[byte[]]$original = [IO.File]::ReadAllBytes($src)
if ($original.Length -ne $m.original_size -or (Bytes-Hash $original) -cne $m.original_sha256) {
    throw 'Original Z03 differs from the analysed firmware. Nothing was patched.'
}
[byte[]]$block = [IO.File]::ReadAllBytes((Join-Path $PackageDir 'patch\NaviPanel.resource-block.bin'))
if ($block.Length -ne $m.original_record_size -or (Bytes-Hash $block) -cne $m.block_sha256) {
    throw 'Resource block failed integrity validation.'
}
$qmlHash = (Get-FileHash -LiteralPath (Join-Path $PackageDir 'patch\NaviPanel.embedded.qml') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($qmlHash -cne $m.embedded_qml_sha256) { throw 'Embedded QML was modified without rebuilding its compressed resource block.' }
$offset = [int]$m.record_offset
if ($offset -lt 0 -or $offset + $block.Length -gt $original.Length) { throw 'Invalid patch range.' }
[byte[]]$candidate = $original.Clone()
[Array]::Copy($block, 0, $candidate, $offset, $block.Length)
if ((Bytes-Hash $candidate) -cne $m.candidate_sha256) { throw 'Candidate hash mismatch. Nothing was saved.' }
$out = Join-Path $WorkRoot ('MenuLab\build\candidate-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
if (Test-Path -LiteralPath $out) { throw 'Output directory already exists; refusing overwrite.' }
[void](New-Item -ItemType Directory -Path $out)
[IO.File]::WriteAllBytes((Join-Path $out 'Z03.menu-candidate'), $candidate)
Copy-Item -LiteralPath (Join-Path $PackageDir 'examples\device') -Destination (Join-Path $out 'device') -Recurse
Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $out 'manifest.json')
if ((Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash.ToLowerInvariant() -cne $m.original_sha256) { throw 'Input changed during build; preserve output for investigation.' }
Write-Host 'OFFLINE_BUILD_OK: only a local candidate copy was generated.'
Write-Host ('ORIGINAL_UNCHANGED: ' + $src)
Write-Host ('CANDIDATE: ' + (Join-Path $out 'Z03.menu-candidate'))
Write-Host ('SHA256: ' + $m.candidate_sha256)
Write-Host 'No ADB push, service stop, system overwrite, startup edit or device execution was performed.'
Write-Host 'The embedded-menu prototype still requires a separately planned, reversible device test.'

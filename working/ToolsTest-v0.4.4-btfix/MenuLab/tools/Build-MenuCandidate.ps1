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
$pinned = 'e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997'
if ($m.original_sha256 -cne $pinned -or $m.original_size -ne 4001256 -or $original.Length -ne 4001256 -or (Bytes-Hash $original) -cne $pinned) {
    throw 'Original Z03 differs from the analysed firmware. Nothing was patched.'
}
function Read-BigEndian32([byte[]]$Data, [int]$At) {
    return [long]$Data[$At]*16777216 + [long]$Data[$At+1]*65536 + [long]$Data[$At+2]*256 + [long]$Data[$At+3]
}
if ($m.qml_resource -cne '/NaviPanel.qml' -or $m.record_offset -ne 0x1c625c -or $m.original_record_size -ne 1584 -or $m.original_qml_sha256 -cne '68915d92ca6cc084779e106d65e1c62b2e7bb64d735c0676298795d7ce04f42b') { throw 'NaviPanel fixed slot mismatch.' }
$patches = @(@{Meta=$m; Offset=0x1c625c; Size=1584; Qml='patch\NaviPanel.embedded.qml'; Block='patch\NaviPanel.resource-block.bin'})
if ($m.PSObject.Properties.Name -contains 'bluetooth_patch') {
    $bt=$m.bluetooth_patch
    if ($null -eq $bt -or $bt.qml_resource -cne '/ZybQmlFiles/ZybSet/SetBtPage.qml' -or $bt.record_offset -ne 0x21e225 -or $bt.original_record_size -ne 3992 -or $bt.original_payload_size -ne 3988 -or $bt.embedded_qml_file -cne 'patch/SetBtPage.embedded.qml' -or $bt.resource_block_file -cne 'patch/SetBtPage.resource-block.bin' -or $bt.original_qml_sha256 -cne '8b37d58f19c686891942c387bf448e16bad13d1d2b560d54609b227747a59901') { throw 'Bluetooth fixed slot/path mismatch.' }
    $patches += @{Meta=$bt; Offset=0x21e225; Size=3992; Qml='patch\SetBtPage.embedded.qml'; Block='patch\SetBtPage.resource-block.bin'}
}
$expectedResources=@('/NaviPanel.qml');if($patches.Count -eq 2){$expectedResources+='/ZybQmlFiles/ZybSet/SetBtPage.qml'}
if (@($m.changed_resources).Count -ne $patches.Count -or $m.other_resources_unchanged -ne 400-$patches.Count) { throw 'Changed resource count mismatch.' }
foreach($resource in $expectedResources){if(@($m.changed_resources) -cnotcontains $resource){throw 'Unexpected changed resource list.'}}
[byte[]]$candidate = $original.Clone()
$previousEnd=0
foreach($patch in $patches) {
    $offset=[int]$patch.Offset; $size=[int]$patch.Size
    if ($offset -lt $previousEnd -or $offset+$size -gt $original.Length) { throw 'Patch ranges overlap or exceed original.' }
    if ((Read-BigEndian32 $original $offset) -ne $size-4) { throw 'Original resource record size mismatch.' }
    [byte[]]$block=[IO.File]::ReadAllBytes((Join-Path $PackageDir $patch.Block))
    [byte[]]$qml=[IO.File]::ReadAllBytes((Join-Path $PackageDir $patch.Qml))
    if ($block.Length -ne $size -or (Bytes-Hash $block) -cne $patch.Meta.block_sha256 -or (Bytes-Hash $qml) -cne $patch.Meta.embedded_qml_sha256) { throw 'Resource block/QML hash mismatch.' }
    if ($patch.Meta.embedded_qml_sha256 -ceq $patch.Meta.original_qml_sha256) { throw 'Required resource content was not changed.' }
    $payload=[int](Read-BigEndian32 $block 0)
    if ($payload -lt 10 -or $payload -gt $size-4 -or (Read-BigEndian32 $block 4) -ne $qml.Length -or $block[8] -ne 0x78 -or (([int]$block[8]*256+[int]$block[9])%31) -ne 0) { throw 'Invalid compressed resource framing.' }
    $compressed=New-Object IO.MemoryStream(,$block)
    $expanded=New-Object IO.MemoryStream
    $deflater=$null
    try {
        $compressed.Position=10
        $deflater=New-Object IO.Compression.DeflateStream($compressed,[IO.Compression.CompressionMode]::Decompress,$true)
        $deflater.CopyTo($expanded)
        if ((Bytes-Hash $expanded.ToArray()) -cne $patch.Meta.embedded_qml_sha256) { throw 'Resource block differs from embedded QML.' }
    } finally { if($null -ne $deflater){$deflater.Dispose()}; $compressed.Dispose(); $expanded.Dispose() }
    for($i=$payload+4;$i -lt $size;$i++){if($block[$i] -ne 0){throw 'Nonzero resource padding.'}}
    [Array]::Copy($block,0,$candidate,$offset,$size)
    $previousEnd=$offset+$size
}
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

param([string]$Root = '')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$destination = $null
$partial = ''
$fullHash = $null
try {
    if (-not $Root) { $Root = Split-Path -Parent $PSScriptRoot }
    $Root = [IO.Path]::GetFullPath($Root)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expected = 'e22201045d0bbbd11ffc947316ddeb4fc97fcfab51508d3ce29795be47e61c84'
    $parts = @(Get-Content -LiteralPath (Join-Path $Root '06_Firmware\metadata\system-parts.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
    if ($parts.Count -ne 8) { throw 'Eight part descriptions are required.' }
    for ($i=0; $i -lt 8; $i++) {
        $m=$parts[$i]
        if ($m.part -ne ($i+1) -or $m.total_parts -ne 8 -or [int64]$m.length_bytes -ne 134217728 -or
            [int64]$m.offset_bytes -ne ([int64]$i*134217728) -or $m.full_image_sha256 -ine $expected -or
            [int64]$m.full_image_bytes -ne 1073741824 -or
            $m.uncompressed_entry -cne ('system.img.part{0:D2}.bin' -f ($i+1))) {
            throw "Invalid metadata at part $($i+1)."
        }
        if ([IO.Path]::GetFileName([string]$m.archive_filename) -cne [string]$m.archive_filename) { throw 'Unsafe archive filename.' }
        $file=Join-Path (Join-Path $Root '06_Firmware\system-parts') ([string]$m.archive_filename)
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing firmware ZIP: $file. Tools edition excludes these files." }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $m.archive_sha256) { throw "Archive SHA mismatch: $file" }
    }
    $outdir=Join-Path $Root ('working\system-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
    if (Test-Path -LiteralPath $outdir) { throw 'Output directory exists; nothing will be overwritten.' }
    [void](New-Item -ItemType Directory -Path $outdir)
    $partial=Join-Path $outdir 'system.img.partial'
    $final=Join-Path $outdir 'system.img'
    $destination=[IO.File]::Open($partial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $fullHash=[Security.Cryptography.SHA256]::Create()
    $buffer=New-Object byte[] 1048576
    [int64]$total=0
    foreach ($m in $parts) {
        $file=Join-Path (Join-Path $Root '06_Firmware\system-parts') ([string]$m.archive_filename)
        $zip=$null; $input=$null; $partHash=[Security.Cryptography.SHA256]::Create()
        [int64]$readBytes=0
        try {
            $zip=[System.IO.Compression.ZipFile]::OpenRead($file)
            $entry=$zip.GetEntry([string]$m.uncompressed_entry)
            if ($null -eq $entry -or $entry.Length -ne [int64]$m.length_bytes) { throw 'Wrong ZIP entry/size.' }
            $input=$entry.Open()
            while (($n=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                $destination.Write($buffer,0,$n)
                [void]$partHash.TransformBlock($buffer,0,$n,$buffer,0)
                [void]$fullHash.TransformBlock($buffer,0,$n,$buffer,0)
                $readBytes+=$n
            }
            [void]$partHash.TransformFinalBlock([byte[]]@(),0,0)
            $hash=[BitConverter]::ToString($partHash.Hash).Replace('-','').ToLowerInvariant()
            if ($readBytes -ne [int64]$m.length_bytes -or $hash -ine $m.part_sha256) { throw "Slice check failed: $($m.part)" }
            $total+=$readBytes
            Write-Host "PART $($m.part)/8 OK: $readBytes bytes"
        } finally {
            if ($null -ne $input) { $input.Dispose() }
            if ($null -ne $zip) { $zip.Dispose() }
            $partHash.Dispose()
        }
    }
    [void]$fullHash.TransformFinalBlock([byte[]]@(),0,0)
    $actual=[BitConverter]::ToString($fullHash.Hash).Replace('-','').ToLowerInvariant()
    if ($total -ne 1073741824 -or $actual -ine $expected) { throw 'Full image length/SHA mismatch.' }
    $destination.Dispose();$destination=$null
    [IO.File]::Move($partial,$final)
    @{bytes=$total;sha256=$actual;scope='PC-only; no device write'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outdir 'rebuild-result.json') -Encoding UTF8
    Write-Host "FULL_IMAGE_OK: $actual"
    Write-Host "SAVED: $final"
    Write-Host 'This is an offline reconstruction, not a firmware flash.'
    exit 0
} catch {
    Write-Host ('STOP: ' + $_.Exception.Message)
    if ($partial -and (Test-Path -LiteralPath $partial)) { Write-Host "INCOMPLETE file retained: $partial" }
    exit 1
} finally {
    if ($null -ne $destination) { $destination.Dispose() }
    if ($null -ne $fullHash) { $fullHash.Dispose() }
}

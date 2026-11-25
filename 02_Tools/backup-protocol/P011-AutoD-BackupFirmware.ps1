# P011 selected firmware backup v1.0 -- Windows PowerShell 5.1 / PowerShell 7.
# Uses the same pinned upstream x86 spd_dump release already tested on this P011.
# Not a full-device recovery backup. No private NV/userdata partitions are requested.
# AutoD staging executes the device's built-in handlers; it is not passive.
# Only a fixed partition_list invocation, then fixed read_part commands, are supplied.
# No external FDL, write, erase, repartition, unlock, firstmode or reset commands.
# References:
# https://github.com/TomKing062/spreadtrum_flash/tree/2a202404a7512026d146b62624f089aceb408520
# https://github.com/sprd-linux/u-boot15/blob/fb48fd09a42695ff1082a04c636f7ead3fd8850f/common/loader/autodloader_mode.c
# Reviewed statically; this new orchestration has not been executed on Windows/P011.
[CmdletBinding()]
param(
    [switch]$CoreOnly,
    [switch]$PrepareOnly,
    [string]$ReleaseZip = '',
    [string]$OutputRoot = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$tag = 'stable_20250726_0012'
$commit = '2a202404a7512026d146b62624f089aceb408520'
$archiveHash = 'C701B6445DCB95CB3EAFBFCBAD212AE01AA7ABF585D145288C49A49B12577B9C'
$exeHashExpected = '0C8EE50CF6B5DEAD2499C48B4693F7A4E55F8215DD21C9372145D887436C369B'
# SHA-256 of the user's actual 32768-byte pgpt.bin. Its header and entry-array
# CRC32 values were independently verified (77C7C673 / 87EF1E97).
$gptHashExpected = '9DDE510DD5FD7B1A46237DD193EC36F17EADA679BD7CFA19DC39664506BCEE1E'
$url = 'https://github.com/TomKing062/spreadtrum_flash/releases/download/stable_20250726_0012/spd_dump_stable_20250726_0012.zip'
$arguments = '--wait 60 --verbose 0 --kickto 2 partition_list p011-partitions.xml'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
$userHome = [Environment]::GetFolderPath('UserProfile')
if (-not $OutputRoot) { $OutputRoot = Join-Path $userHome 'Downloads' }
$outDir = Join-Path $OutputRoot ('P011-Firmware-' + $stamp)
[void](New-Item -ItemType Directory -Path $outDir)
$outDir = (Resolve-Path -LiteralPath $outDir).Path
$utf8 = [Text.UTF8Encoding]::new($false)
$reportPath = Join-Path $outDir 'report.txt'
$report = [IO.StreamWriter]::new($reportPath, $false, $utf8)
$report.AutoFlush = $true
$process = $null
$streams = @()
$files = [System.Collections.Generic.List[object]]::new()
$result = 'NOT_STARTED'
$stopReason = ''

# Exact partition lengths from the validated P011 GPT. Name, size in MiB.
$plan = @(
    [PSCustomObject]@{ Name='uboot_log'; MiB=4 },
    [PSCustomObject]@{ Name='uboot'; MiB=1 },
    [PSCustomObject]@{ Name='vbmeta'; MiB=1 },
    [PSCustomObject]@{ Name='vbmeta_system'; MiB=1 },
    [PSCustomObject]@{ Name='vbmeta_vendor'; MiB=1 },
    [PSCustomObject]@{ Name='dtbo'; MiB=2 },
    [PSCustomObject]@{ Name='boot'; MiB=35 }
)
if (-not $CoreOnly) { $plan += [PSCustomObject]@{ Name='system'; MiB=1024 } }
$queue = @($plan | ForEach-Object {
    [long]$bytes = [long]$_.MiB * 1048576
    [PSCustomObject]@{
        Name=$_.Name; Bytes=$bytes; File=($_.Name + '.img');
        Command=('read_part {0} 0 0x{1:x} {0}.img' -f $_.Name,$bytes)
    }
})

function Log-Line {
    param([string]$Text)
    Write-Host $Text
    $report.WriteLine(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'),$Text))
}
function Get-PeMachine {
    param([string]$Path)
    $f=[IO.File]::OpenRead($Path); $r=[IO.BinaryReader]::new($f)
    try {
        if ($f.Length -lt 64 -or $r.ReadUInt16() -ne 0x5A4D) { return 0 }
        $f.Position=0x3C; $off=$r.ReadInt32()
        if ($off -lt 64 -or ([long]$off+6) -gt $f.Length) { return 0 }
        $f.Position=$off
        if ($r.ReadUInt32() -ne 0x4550) { return 0 }
        return [int]$r.ReadUInt16()
    } finally { $r.Dispose() }
}
function Stop-Tool {
    param([string]$Reason)
    if ($null -ne $process -and -not $process.HasExited) {
        Log-Line ('HOST_STOP: '+$Reason+'; stopping the PC process, NOT sending a device reset.')
        $process.Kill()
        [void]$process.WaitForExit(3000)
    }
}
function Confirm-CurrentGpt {
    $path=Join-Path $outDir 'pgpt.bin'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'No pgpt.bin; no image reads will be queued.' }
    if ((Get-Item -LiteralPath $path).Length -ne 32768) { throw 'Unexpected GPT capture length; no image reads queued.' }
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Log-Line ('CURRENT_GPT_SHA256: '+$hash)
    if ($hash -ne $gptHashExpected) { throw 'GPT differs from the reviewed P011 snapshot. Preserve this report for review; no image reads queued.' }
    Log-Line 'GPT_MATCHED: byte-identical to the independently reviewed 40-partition snapshot.'
}
function Submit-FixedRead {
    param($Item)
    $allowed=@($queue | Where-Object { $_.Command -ceq $Item.Command -and $_.Name -ceq $Item.Name -and $_.Bytes -eq $Item.Bytes })
    if ($allowed.Count -ne 1 -or $Item.Command -notmatch '^read_part (uboot_log|uboot|vbmeta|vbmeta_system|vbmeta_vendor|dtbo|boot|system) 0 0x[0-9a-f]+ [a-z_]+\.img$') {
        throw 'Read command rejected by the fixed allowlist.'
    }
    Log-Line ('READ_BEGIN: '+$Item.Name+'; expected_bytes='+$Item.Bytes)
    Log-Line ('COMMAND: '+$Item.Command)
    # Only one command at a time, after an FDL2 prompt. No arbitrary user input.
    $process.StandardInput.WriteLine($Item.Command)
    $process.StandardInput.Flush()
}
function Confirm-ReadLength {
    param($Item)
    $path=Join-Path $outDir $Item.File
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('No output file for '+$Item.Name) }
    $actual=(Get-Item -LiteralPath $path).Length
    if ($actual -ne $Item.Bytes) { throw ('Incomplete read: '+$Item.Name+'; expected='+$Item.Bytes+'; actual='+$actual+'. No further reads queued.') }
    [void]$files.Add([PSCustomObject]@{ Partition=$Item.Name; File=$Item.File; Bytes=$actual; SHA256='' })
    Log-Line ('READ_LENGTH_OK: '+$Item.Name+'; bytes='+$actual+'. Hashing will follow after the tool stops.')
}
function Write-SystemSliceZip {
    param([IO.FileStream]$InputStream,[string]$ZipPath,[long]$Offset,[long]$Count,[int]$PartNumber,[string]$FullHash)
    $zf=$null; $za=$null; $es=$null; $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $zf=[IO.File]::Open($ZipPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $za=[IO.Compression.ZipArchive]::new($zf,[IO.Compression.ZipArchiveMode]::Create,$true)
        $entryName=('system.img.part{0:D2}.bin' -f $PartNumber)
        $entry=$za.CreateEntry($entryName,[IO.Compression.CompressionLevel]::Optimal)
        $es=$entry.Open()
        $InputStream.Position=$Offset
        [byte[]]$buf=New-Object byte[] 1048576
        [long]$remaining=$Count
        while ($remaining -gt 0) {
            $take=[int][Math]::Min([long]$buf.Length,$remaining)
            $n=$InputStream.Read($buf,0,$take)
            if ($n -le 0) { throw 'Unexpected EOF while packaging the system image.' }
            $es.Write($buf,0,$n)
            [void]$sha.TransformBlock($buf,0,$n,$buf,0)
            $remaining-=$n
        }
        [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
        $pieceHash=[BitConverter]::ToString($sha.Hash).Replace('-','')
        $es.Dispose(); $es=$null
        $manifest=@{
            image='system.img'; part=$PartNumber; total_parts=8;
            uncompressed_entry=$entryName; offset_bytes=$Offset; length_bytes=$Count;
            part_sha256=$pieceHash; full_image_bytes=1073741824; full_image_sha256=$FullHash;
            note='Independent ZIP containing one contiguous raw-image slice. Reconstruct in part-number order.'
        } | ConvertTo-Json -Depth 4
        $me=$za.CreateEntry('slice-manifest.json')
        $ms=$me.Open(); $sw=[IO.StreamWriter]::new($ms,$utf8)
        try { $sw.Write($manifest) } finally { $sw.Dispose() }
    } finally {
        if ($null -ne $es) { $es.Dispose() }
        if ($null -ne $za) { $za.Dispose() }
        if ($null -ne $zf) { $zf.Dispose() }
        $sha.Dispose()
    }
}

try {
    Log-Line 'P011 selected firmware backup v1.0'
    Log-Line ('OUTPUT: '+$outDir)
    Log-Line 'Same pinned AutoD client; fixed image reads only. NOT a full-device recovery backup.'
    if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
    $arch=$env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch=$env:PROCESSOR_ARCHITEW6432 }
    if ($arch -notin @('AMD64','x86')) { throw 'Use Intel/AMD Windows with the existing SPRD driver.' }
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($outDir))
    $required=4GB
    if ($CoreOnly) { $required=512MB }
    if ($drive.AvailableFreeSpace -lt $required) { throw ('Insufficient PC disk space; require '+$required+' free bytes.') }
    Log-Line ('PLAN: '+(($queue | ForEach-Object { $_.Name+'='+[string]$_.Bytes }) -join '; '))

    $cache=Join-Path $userHome 'Downloads\P011-AutoD-Tools'
    [void](New-Item -ItemType Directory -Path $cache -Force)
    if ($ReleaseZip) { $archive=(Resolve-Path -LiteralPath $ReleaseZip).Path }
    else {
        $archive=Join-Path $cache ('spd_dump_'+$tag+'.zip')
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            Log-Line 'The verified release is not cached; downloading the fixed release.'
            $partial=$archive+'.partial'; $oldTls=[Net.ServicePointManager]::SecurityProtocol
            try {
                [Net.ServicePointManager]::SecurityProtocol=$oldTls -bor [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $url -OutFile $partial -UseBasicParsing -TimeoutSec 120
                if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $archiveHash) { throw 'Downloaded release hash mismatch.' }
                Move-Item -LiteralPath $partial -Destination $archive
            } finally {
                [Net.ServicePointManager]::SecurityProtocol=$oldTls
                if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            }
        }
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $archiveHash) { throw 'Release ZIP hash mismatch. Nothing will execute.' }
    $unpack=Join-Path $cache ('verified-backup-'+$stamp)
    Expand-Archive -LiteralPath $archive -DestinationPath $unpack
    $exes=@(Get-ChildItem -LiteralPath $unpack -Recurse -File -Filter '*.exe' |
        Where-Object { $_.Name -match '^spd_dump.*\.exe$' } |
        Where-Object { (Get-PeMachine $_.FullName) -eq 0x014C })
    if ($exes.Count -ne 1) { throw 'Expected exactly one x86 SPRD executable.' }
    $exe=$exes[0].FullName
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $exeHashExpected) { throw 'Executable differs from the exact version used in the successful table capture.' }
    Log-Line ('TOOL_VERIFIED: '+$exe)
    @{ release=$tag; source_commit=$commit; archive_sha256=$archiveHash; exe_sha256=$exeHashExpected;
       initial_arguments=$arguments; expected_gpt_sha256=$gptHashExpected; fixed_reads=$queue;
       note='AutoD staging plus selected reads. Target-side logging is outside host control.' } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outDir 'plan.json') -Encoding UTF8

    if ($PrepareOnly) {
        $result='PREPARED_ONLY'; Log-Line 'No tool was launched.'
    } else {
        Log-Line 'Power the P011 OFF, unplug USB, and close other serial/flashing programs.'
        Log-Line 'The next step performs AutoD staging, then selected reads. No external FDL or device-write commands.'
        if ((Read-Host 'Type BACKUP to start') -cne 'BACKUP') { throw 'Not confirmed; no device process started.' }
        $attached=@(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_1782*' })
        if ($attached.Count -gt 0) { throw 'Unplug Unisoc USB devices before starting.' }
        $running=@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^spd_dump' })
        if ($running.Count -gt 0) { throw 'Another spd_dump is running. Close it first.' }
        $psi=[Diagnostics.ProcessStartInfo]::new()
        $psi.FileName=$exe; $psi.Arguments=$arguments; $psi.WorkingDirectory=$outDir
        $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
        $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$psi
        if (-not $process.Start()) { throw 'Could not start the verified executable.' }
        foreach ($name in @('stdout','stderr')) {
            $reader=$process.StandardOutput
            if ($name -eq 'stderr') { $reader=$process.StandardError }
            $writer=[IO.StreamWriter]::new((Join-Path $outDir ('tool-'+$name+'.txt')),$false,$utf8)
            $writer.AutoFlush=$true; [char[]]$buffer=New-Object char[] 4096
            $streams+=@{ Name=$name; Reader=$reader; Writer=$writer; Buffer=$buffer;
                        Task=$reader.ReadAsync($buffer,0,$buffer.Length); Eof=$false; Tail='' }
        }
        Log-Line 'WAIT: Insert USB into the powered-OFF P011 now. Do not press a button.'
        Log-Line 'Reading system is much larger than reading GPT. Keep this PC awake and USB connected.'
        $timer=[Diagnostics.Stopwatch]::StartNew(); $phase='TABLE'; $index=0; $active=$null
        $stopping=$false; $stopAt=-1L; $characters=0L; $result='RUNNING'
        while ($true) {
            $prompt=''
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Task.IsCompleted) {
                    $n=$s.Task.Result
                    if ($n -eq 0) { $s.Eof=$true; continue }
                    $text=[string]::new($s.Buffer,0,$n)
                    $s.Writer.Write($text); Write-Host -NoNewline $text
                    $characters+=$n; $s.Tail+=$text
                    if ($s.Tail.Length -gt 16384) { $s.Tail=$s.Tail.Substring($s.Tail.Length-16384) }
                    if ($s.Tail -match '(?:^|[\r\n])(BROM|FDL1|FDL2)\s*>[ \t]*$') { $prompt=$Matches[1] }
                    $s.Task=$s.Reader.ReadAsync($s.Buffer,0,$s.Buffer.Length)
                }
            }
            if ($prompt -and -not $stopping) {
                foreach ($s in $streams) { $s.Tail='' }
                if ($prompt -ne 'FDL2') { throw ('Unexpected '+$prompt+' prompt; no further command sent.') }
                if ($phase -eq 'TABLE') {
                    Confirm-CurrentGpt
                    $phase='READ'
                } elseif ($phase -eq 'READ') {
                    Confirm-ReadLength $active
                    $index++
                }
                if ($index -lt $queue.Count) {
                    $active=$queue[$index]
                    Submit-FixedRead $active
                } else {
                    $result='ALL_SELECTED_READS_LENGTH_OK'
                    $stopReason='FIXED_READ_QUEUE_COMPLETED'; $stopping=$true; $stopAt=$timer.ElapsedMilliseconds
                }
            }
            if (-not $stopping -and ($timer.Elapsed.TotalSeconds -ge 5400 -or $characters -gt 16777216)) {
                $stopReason='HOST_WATCHDOG_OR_LOG_LIMIT'; $stopping=$true; $stopAt=$timer.ElapsedMilliseconds
                $result='INCOMPLETE'
            }
            if ($stopping -and -not $process.HasExited -and ($timer.ElapsedMilliseconds-$stopAt) -ge 250) { Stop-Tool $stopReason }
            if ($process.HasExited -and @($streams | Where-Object { -not $_.Eof }).Count -eq 0) { break }
            if ($stopping -and ($timer.ElapsedMilliseconds-$stopAt) -gt 6000) { break }
            Start-Sleep -Milliseconds 30
        }
        if ($process.HasExited) { Log-Line ('TOOL_EXIT_CODE: '+$process.ExitCode+'; a host stop after the last completed read is intentional.') }
        if ($result -eq 'RUNNING') { $result='INCOMPLETE_TOOL_EXIT' }
    }
} catch {
    $result='STOPPED: '+$result
    Log-Line ('ERROR: '+$_.Exception.Message)
    Log-Line 'Preserve partial data. Do not run write, erase, format, or unlock commands.'
} finally {
    if ($null -ne $process) {
        try { Stop-Tool 'FINAL_CLEANUP' } catch { Log-Line ('CLEANUP: '+$_.Exception.Message) }
        foreach ($s in $streams) { try { $s.Writer.Dispose() } catch { } }
        $process.Dispose()
    }
    # Hash only completed selected images after the writer process has stopped.
    foreach ($f in $files) {
        try {
            $f.SHA256=(Get-FileHash -LiteralPath (Join-Path $outDir $f.File) -Algorithm SHA256).Hash
            Log-Line ('SAVED: '+$f.File+'; bytes='+$f.Bytes+'; SHA256='+$f.SHA256)
        } catch { Log-Line ('HASH_ERROR: '+$f.File+'; '+$_.Exception.Message) }
    }
    @{ result=$result; stop_reason=$stopReason; completed=$files.ToArray();
       warning='Selected firmware only, NOT a complete restore set. No evidence of ADB/root/unlock from these reads.' } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outDir 'backup-manifest.json') -Encoding UTF8
    Log-Line ('RESULT: '+$result)
    Log-Line 'No external FDL, password attempt, device write/erase/repartition/unlock command was supplied.'
    Log-Line 'Unplug USB and use the normal power-on procedure. Keep original IMG files locally.'
    $report.Dispose()
}

# Packaging only: the device process is already stopped.
try {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # Snapshot the list before creating the hash manifest; do not hash the manifest into itself.
    $hostFiles=@(Get-ChildItem -LiteralPath $outDir -File)
    $hashRows=@($hostFiles | ForEach-Object {
        [PSCustomObject]@{ File=$_.Name; Bytes=$_.Length; SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
    $hashRows | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $outDir 'host-file-hashes.json') -Encoding UTF8
    $shareDir=Join-Path $outDir 'share'; [void](New-Item -ItemType Directory -Path $shareDir)
    $coreZip=Join-Path $shareDir ('P011-Core-'+$stamp+'.zip')
    $coreFiles=@(Get-ChildItem -LiteralPath $outDir -File | Where-Object { $_.Name -ne 'system.img' })
    Compress-Archive -LiteralPath $coreFiles.FullName -DestinationPath $coreZip -CompressionLevel Optimal
    Write-Host ('CORE_ZIP: '+$coreZip)
    $system=@($files | Where-Object { $_.Partition -eq 'system' -and $_.Bytes -eq 1073741824 -and $_.SHA256 })
    if ($system.Count -eq 1) {
        $inputFile=[IO.File]::OpenRead((Join-Path $outDir 'system.img'))
        try {
            for ($part=1; $part -le 8; $part++) {
                $zipPath=Join-Path $shareDir ('P011-System-{0:D2}-of-08-{1}.zip' -f $part,$stamp)
                Write-Host ('PACKAGING: system part '+$part+'/8')
                Write-SystemSliceZip -InputStream $inputFile -ZipPath $zipPath -Offset ([long]($part-1)*134217728) -Count 134217728 -PartNumber $part -FullHash $system[0].SHA256
                Write-Host ('SYSTEM_ZIP: '+$zipPath)
            }
        } finally { $inputFile.Dispose() }
    }
    Write-Host ('SHARE_FOLDER: '+$shareDir)
    Write-Host 'Upload the Core ZIP and all generated System ZIPs. Keep original IMG files on this PC.'
} catch { Write-Host ('PACKAGING_ERROR: '+$_.Exception.Message+'. Original captures remain in '+$outDir) }
Write-Host ('REPORT: '+$reportPath)

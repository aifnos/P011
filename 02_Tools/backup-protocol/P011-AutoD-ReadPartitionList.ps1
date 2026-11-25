# P011 AutoD partition-list launcher v1.0
# Windows PowerShell 5.1 / PowerShell 7, Intel/AMD Windows.
# Runs a pinned upstream spd_dump release; it does NOT implement another BSL client.
# Reference source/release, not P011 firmware:
# https://github.com/TomKing062/spreadtrum_flash/tree/2a202404a7512026d146b62624f089aceb408520
# https://github.com/TomKing062/spreadtrum_flash/releases/tag/stable_20250726_0012
# The release's x86 executable uses the existing SPRD driver; x64 uses libusb.
# Important: AutoD transition uses EXEC_DATA to enter the DEVICE'S built-in code.
# This is NOT passive, and NOT the previous handshake-only operation.
# No external FDL/PAC, password, unlock, write/erase/repartition command is supplied.
# Upstream is a general-purpose flasher; the fixed invocation below requests only a
# mode transition + AutoD initialization + partition metadata. Firmware may log events.
# Untested on P011 hardware by the author. Hash matching is not a safety guarantee.
[CmdletBinding()]
param(
    # Optional already-downloaded ORIGINAL release ZIP. Same SHA-256 is required.
    [string]$ReleaseZip = '',
    # Download/verify/extract/select executable, without launching it or opening USB.
    [switch]$PrepareOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$tag = 'stable_20250726_0012'
$sourceCommit = '2a202404a7512026d146b62624f089aceb408520'
$url = 'https://github.com/TomKing062/spreadtrum_flash/releases/download/stable_20250726_0012/spd_dump_stable_20250726_0012.zip'
$expectedHash = 'C701B6445DCB95CB3EAFBFCBAD212AE01AA7ABF585D145288C49A49B12577B9C'
# No free-form device commands accepted by this launcher.
$fixedArguments = '--wait 60 --verbose 2 --kickto 2 partition_list p011-partitions.xml'
$outDir = Join-Path $env:TEMP ('P011-AutoD-PartitionList-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
[void](New-Item -ItemType Directory -Path $outDir)
$reportPath = Join-Path $outDir 'report.txt'
$utf8 = [Text.UTF8Encoding]::new($false)
$report = [IO.StreamWriter]::new($reportPath, $false, $utf8)
$report.AutoFlush = $true
$process = $null
$streams = @()
$result = 'NOT_STARTED'
$stopReason = ''
$toolStarted = $false

function Log-Line {
    param([string]$Text)
    Write-Host $Text
    $report.WriteLine(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text))
}
function Get-PeMachine {
    param([string]$Path)
    $file = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($file)
    try {
        if ($file.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { return 0 }
        $file.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or ([int64]$offset + 6) -gt $file.Length) { return 0 }
        $file.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { return 0 }
        return [int]$reader.ReadUInt16()
    } finally { $reader.Dispose() }
}
function Stop-Tool {
    param([string]$Reason)
    Log-Line ('HOST_STOP: ' + $Reason + '. Ending the PC process only; no device reset/erase command.')
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill()
        [void]$process.WaitForExit(3000)
    }
}

try {
    Log-Line 'P011 AutoD partition-list launcher v1.0'
    Log-Line 'Fixed upstream release; use device-built-in AutoD stages, then request partition metadata.'
    Log-Line 'No external loader or firmware image is supplied. No unlock or write/erase command is queued.'
    Log-Line ('OUTPUT: ' + $outDir)
    if ($env:OS -ne 'Windows_NT') { throw 'Device operation requires Windows.' }
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }
    if ($arch -notin @('AMD64','x86')) { throw ('This launcher is intended for Intel/AMD Windows, not ' + $arch) }

    $cache = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\P011-AutoD-Tools'
    [void](New-Item -ItemType Directory -Path $cache -Force)
    if ($ReleaseZip) {
        $archivePath = (Resolve-Path -LiteralPath $ReleaseZip).Path
    } else {
        $archivePath = Join-Path $cache ('spd_dump_' + $tag + '.zip')
        if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
            Log-Line ('DOWNLOAD: ' + $url)
            $partial = $archivePath + '.partial'
            $oldTls = [Net.ServicePointManager]::SecurityProtocol
            try {
                [Net.ServicePointManager]::SecurityProtocol = $oldTls -bor [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $url -OutFile $partial -UseBasicParsing -TimeoutSec 120
                $h = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
                if ($h -cne $expectedHash) { throw ('Release archive hash mismatch: ' + $h) }
                Move-Item -LiteralPath $partial -Destination $archivePath
            } finally {
                [Net.ServicePointManager]::SecurityProtocol = $oldTls
                if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            }
        }
    }
    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    Log-Line ('ARCHIVE_SHA256: ' + $actualHash)
    if ($actualHash -cne $expectedHash) { throw 'Archive differs from the upstream release digest. Nothing will execute.' }

    # Fresh extraction per run avoids executing previously modified extracted files.
    $unpack = Join-Path $cache ('verified-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
    Expand-Archive -LiteralPath $archivePath -DestinationPath $unpack
    $candidates = @(
        Get-ChildItem -LiteralPath $unpack -Recurse -File -Filter '*.exe' |
            Where-Object { $_.Name -match '^spd_dump.*\.exe$' } |
            Where-Object { (Get-PeMachine -Path $_.FullName) -eq 0x014C }
    )
    if ($candidates.Count -ne 1) {
        $names = @($candidates | ForEach-Object { $_.FullName }) -join '; '
        throw ('Expected one x86 spd_dump executable; found ' + $candidates.Count + '. ' + $names)
    }
    $exe = $candidates[0].FullName
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    Log-Line ('TOOL: ' + $exe)
    Log-Line 'TOOL_ARCH: x86 (uses SPRD U2S driver, even when Windows is 64-bit)'
    Log-Line ('COMMAND: "' + $exe + '" ' + $fixedArguments)
    @{
        release=$tag; source_commit=$sourceCommit; release_url=$url;
        archive_sha256=$actualHash; executable=$exe; executable_sha256=$exeHash;
        arguments=$fixedArguments; working_directory=$outDir;
        note='Source-reviewed invocation. Hardware behavior and result are not pre-verified.'
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outDir 'tool-manifest.json') -Encoding UTF8

    if ($PrepareOnly) {
        $result = 'PREPARED_ONLY'
        Log-Line 'PREPARED_ONLY: no executable launched; no USB connection or command.'
    } else {
        Log-Line ''
        Log-Line 'This step can switch boot mode and execute the device-built-in AutoD stage handlers.'
        Log-Line 'It is NOT a passive probe. Do not connect another Unisoc device.'
        Log-Line 'First restore normal operation, power the P011 OFF, and unplug USB.'
        if ((Read-Host 'Type READTABLE to permit AutoD staging and partition-list reads') -cne 'READTABLE') {
            throw 'Not confirmed. No tool was launched.'
        }
        $attached = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\VID_1782*' })
        if ($attached.Count -gt 0) { throw 'An Unisoc USB device is already attached. Unplug it before starting a fresh run.' }
        $existing = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^spd_dump' })
        if ($existing.Count -gt 0) { throw 'Another spd_dump process is running. Close it manually before continuing.' }

        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $exe
        $psi.Arguments = $fixedArguments
        $psi.WorkingDirectory = $outDir
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = $true  # Kept open, but NEVER supplied additional commands.
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $psi
        if (-not $process.Start()) { throw 'Could not start spd_dump.' }
        $toolStarted = $true
        $result = 'TOOL_RUNNING'
        Log-Line 'WAIT: Insert USB into the powered-OFF P011 now. Do not press a button.'
        Log-Line 'The tool has 60 seconds to catch the device. Total host watchdog: 180 seconds.'

        foreach ($name in @('stdout','stderr')) {
            $reader = $process.StandardOutput
            if ($name -eq 'stderr') { $reader = $process.StandardError }
            $writer = [IO.StreamWriter]::new((Join-Path $outDir ('tool-' + $name + '.txt')), $false, $utf8)
            $writer.AutoFlush = $true
            [char[]]$buffer = New-Object char[] 4096
            $streams += @{
                Name=$name; Reader=$reader; Writer=$writer; Buffer=$buffer;
                Task=$reader.ReadAsync($buffer, 0, $buffer.Length); Eof=$false; Tail=''
            }
        }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $stopping = $false
        $stopAt = -1L
        $totalChars = 0L
        while ($true) {
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Task.IsCompleted) {
                    $n = $s.Task.Result
                    if ($n -eq 0) { $s.Eof = $true; continue }
                    $text = [string]::new($s.Buffer, 0, $n)
                    $s.Writer.Write($text)
                    Write-Host -NoNewline $text
                    $totalChars += $n
                    $s.Tail += $text
                    if ($s.Tail.Length -gt 8192) { $s.Tail = $s.Tail.Substring($s.Tail.Length - 8192) }
                    # Upstream prints this only when queued arguments are exhausted
                    # (or have failed back into interactive mode). Never send input.
                    if (-not $stopping -and $s.Tail -match '(?:^|[\r\n])(?:BROM|FDL1|FDL2)\s*>[ \t]*$') {
                        $stopReason = 'RETURNED_TO_INTERACTIVE_PROMPT'
                        $stopping = $true
                        $stopAt = $timer.ElapsedMilliseconds
                    }
                    $s.Task = $s.Reader.ReadAsync($s.Buffer, 0, $s.Buffer.Length)
                }
            }
            if (-not $stopping -and ($timer.Elapsed.TotalSeconds -ge 180 -or $totalChars -gt 8388608)) {
                $stopReason = 'HOST_TIME_OR_OUTPUT_LIMIT'
                $stopping = $true
                $stopAt = $timer.ElapsedMilliseconds
            }
            if ($stopping -and -not $process.HasExited -and ($timer.ElapsedMilliseconds - $stopAt) -ge 250) {
                Stop-Tool -Reason $stopReason
            }
            if ($process.HasExited -and @($streams | Where-Object { -not $_.Eof }).Count -eq 0) { break }
            if ($stopping -and ($timer.ElapsedMilliseconds - $stopAt) -gt 6000) { break }
            Start-Sleep -Milliseconds 30
        }
        foreach ($s in $streams) { $s.Writer.Flush() }
        if ($process.HasExited) { Log-Line ('TOOL_EXIT_CODE: ' + $process.ExitCode + ' (host termination may be intentional)') }
        Log-Line ('HOST_STOP_REASON: ' + $stopReason)

        $xmlPath = Join-Path $outDir 'p011-partitions.xml'
        $result = 'NO_CONFIRMED_PARTITION_LIST'
        if (Test-Path -LiteralPath $xmlPath -PathType Leaf) {
            if ((Get-Item -LiteralPath $xmlPath).Length -gt 1048576) { throw 'Unexpectedly large partition XML. Preserve output for inspection.' }
            $doc = [Xml.XmlDocument]::new()
            $doc.XmlResolver = $null
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $xmlReader = [Xml.XmlReader]::Create($xmlPath, $settings)
            try { $doc.Load($xmlReader) } finally { $xmlReader.Dispose() }
            $rows = @($doc.SelectNodes('/Partitions/Partition'))
            if ($rows.Count -gt 0) {
                $result = 'PARTITION_XML_RECEIVED_UNREVIEWED'
                Log-Line ('PARTITION_ROWS: ' + $rows.Count)
                foreach ($row in $rows) {
                    Log-Line ('PARTITION: id=' + $row.GetAttribute('id') + '; upstream_size_field=' + $row.GetAttribute('size'))
                }
                Log-Line 'Preserve pgpt.bin/sprdpart.bin for independent validation. XML alone does not verify GPT CRC or all partition contents.'
            }
        }
    }
} catch {
    $result = 'STOPPED: ' + $result
    Log-Line ('ERROR: ' + $_.Exception.Message)
    Log-Line 'Do not disable Windows security or driver-signature enforcement to force this to run.'
} finally {
    if ($null -ne $process) {
        try {
            if ($toolStarted -and -not $process.HasExited) { Stop-Tool -Reason 'LAUNCHER_FINALLY' }
        } catch { Log-Line ('HOST_CLEANUP_ERROR: ' + $_.Exception.Message) }
        foreach ($s in $streams) {
            try { $s.Writer.Dispose() } catch { }
        }
        $process.Dispose()
    }
    Log-Line ('RESULT: ' + $result)
    Log-Line 'No external FDL file or device-write command was supplied by this launcher.'
    Log-Line 'AutoD staging and upstream protocol setup may change runtime state; target-side internal logging is not controlled here.'
    Log-Line 'After capture, unplug USB and use the normal power-on procedure. Do not erase/format to leave a blank screen.'
    $report.Dispose()
    Write-Host ('REPORT: ' + $reportPath)
    try {
        Get-ChildItem -LiteralPath $outDir -File |
            Get-FileHash -Algorithm SHA256 |
            Select-Object @{Name='File';Expression={Split-Path $_.Path -Leaf}},Hash |
            Export-Csv -LiteralPath (Join-Path $outDir 'host-file-hashes.csv') -NoTypeInformation -Encoding UTF8
        Compress-Archive -LiteralPath $outDir -DestinationPath ($outDir + '.zip') -CompressionLevel Optimal
        Write-Host ('ZIP: ' + $outDir + '.zip')
    } catch { Write-Host ('ARCHIVE_ERROR: ' + $_.Exception.Message) }
}

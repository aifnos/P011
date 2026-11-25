# P011 boot-stage download selection probe v1.3
# Windows PowerShell 5.1 / PowerShell 7 on x64 Windows.
# WARNING: this is NOT passive observation. It requests download boot mode,
# which may reset the pen and leave its screen blank. Behavior on P011 is unverified.
# Only one FE/82 boot-selection request is allowed, only on an early 1782:4D00 port.
# Parse early responses BEFORE closing or waiting for USB re-enumeration.
# A clean CRC16-valid version OR pre-download VERIFY_ERROR permits one empty CONNECT.
# VERIFY_ERROR here authorizes only the CONNECT recovery documented by spd_dump.
# It is never treated as a version, an ACK, or a firmware-signature verdict.
# At most four 7E sync bytes and one FE/82 per run; never retransmit CONNECT.
# Reconnect only after loss of the current handle/target, and revalidate the version.
# No FDL upload, memory commands, eMMC/partition operations, eFuse, or password guesses.
# No runtime 1782:4064 endpoint is opened. No generic --kick/calibration fallback.
# Sources reviewed (implementations are reference evidence, NOT P011 firmware):
# https://github.com/TomKing062/spreadtrum_flash/blob/main/common.c (ChangeMode)
# https://github.com/sprd-linux/u-boot15/blob/sprdroid10_trunk/common/loader/calibration_detect.c
# https://github.com/sprd-linux/u-boot15/blob/sprdroid10_trunk/common/loader/calibration_detect.h
# https://github.com/iscle/sprdclient/blob/master/main.c
# v1.3: fixes v1.1's discarded early version / mandatory-removal state-machine bug.
# Regression vectors: captured AutoD (FD8B) and empty 008B VERIFY_ERROR (CBAB).
# https://github.com/sprd-linux/u-boot15/blob/fb48fd09a42695ff1082a04c636f7ead3fd8850f/common/dloader/packet.c
# https://github.com/TomKing062/spreadtrum_flash/blob/main/spd_dump.c
# v1.3 has NOT been tested on Windows hardware by the author.
# The AutoD banner is NOT proof of execution in immutable chip BootROM.
# Reference: https://github.com/sprd-linux/u-boot15/blob/fb48fd09a42695ff1082a04c636f7ead3fd8850f/common/loader/autodloader_mode.c
# Retains bounded port-open retries after fresh present-only enumeration.
# Open failures never resend the FE/82 mode request. Fresh SerialPort per attempt.
# Normal runtime PID_4064 ports are observed only, never opened by this script.
# -SelfTest validates packet framing only and is NOT a Windows/P011 device test.
# This revision has not been run on a P011 by its author.
# https://learn.microsoft.com/en-us/dotnet/api/system.io.ports.serialport.open
# https://learn.microsoft.com/en-us/dotnet/api/system.io.ports.serialport.close
param([switch]$SelfTest, [string]$ReplayFile)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Get-BromCrc16 {
    param([byte[]]$Bytes)
    [int]$crc = 0
    foreach ($b in $Bytes) {
        $crc = $crc -bxor ([int]$b -shl 8)
        for ($j = 0; $j -lt 8; $j++) {
            if (($crc -band 0x8000) -ne 0) {
                $crc = (($crc -shl 1) -bxor 0x1021) -band 0xFFFF
            } else {
                $crc = ($crc -shl 1) -band 0xFFFF
            }
        }
    }
    return $crc
}

function Get-FdlChecksum {
    param([byte[]]$Bytes)
    [uint32]$sum = 0
    $i = 0
    for (; $i + 1 -lt $Bytes.Length; $i += 2) {
        $sum += ([int]$Bytes[$i] -shl 8) -bor [int]$Bytes[$i + 1]
    }
    if ($i -lt $Bytes.Length) { $sum += [int]$Bytes[$i] }
    $sum = ($sum -shr 16) + ($sum -band 0xFFFF)
    $sum = ($sum -shr 16) + ($sum -band 0xFFFF)
    return ([int]$sum -bxor 0xFFFF) -band 0xFFFF
}

function ConvertTo-Hex {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return [BitConverter]::ToString($Bytes).Replace('-', ' ')
}

function Decode-BslStream {
    param([byte[]]$Bytes)
    $frames = [System.Collections.Generic.List[object]]::new()
    $body = [System.Collections.Generic.List[byte]]::new()
    $inside = $false
    $escaped = $false
    $junk = 0
    $invalid = 0
    $echoes = 0
    foreach ($b in $Bytes) {
        if ($b -eq 0x7E) {
            if ($inside -and $body.Count -gt 0) {
                [byte[]]$a = $body.ToArray()
                if (-not $escaped -and
                    (ConvertTo-Hex $a) -eq '00 00 00 00 08 00 FE 82') {
                    $echoes++  # Known boot-stage echo, never a BSL version/ACK.
                } elseif ($escaped -or $a.Length -lt 6) {
                    $invalid++
                } else {
                    $type = ([int]$a[0] -shl 8) -bor [int]$a[1]
                    $size = ([int]$a[2] -shl 8) -bor [int]$a[3]
                    if ($a.Length -ne ($size + 6)) {
                        $invalid++
                    } else {
                        [byte[]]$data = @()
                        if ($size -gt 0) {
                            $data = New-Object byte[] $size
                            [Array]::Copy($a, 4, $data, 0, $size)
                        }
                        [byte[]]$covered = $a[0..($a.Length - 3)]
                        $received = ([int]$a[$a.Length - 2] -shl 8) -bor [int]$a[$a.Length - 1]
                        [void]$frames.Add([PSCustomObject]@{
                            Type = $type; Size = $size; Payload = $data
                            ReceivedChecksum = $received
                            BromCrcOk = ($received -eq (Get-BromCrc16 $covered))
                            FdlChecksumOk = ($received -eq (Get-FdlChecksum $covered))
                        })
                    }
                }
            } elseif ($escaped) {
                $invalid++
            }
            $body.Clear()
            $inside = $true
            $escaped = $false
        } elseif (-not $inside) {
            $junk++
        } elseif ($escaped) {
            [void]$body.Add([byte]($b -bxor 0x20))
            $escaped = $false
        } elseif ($b -eq 0x7D) {
            $escaped = $true
        } else {
            [void]$body.Add($b)
        }
    }
    return [PSCustomObject]@{
        Frames = $frames.ToArray(); InvalidFrames = $invalid; Echoes = $echoes
        TrailingBytes = $body.Count; DanglingEscape = $escaped; LeadingJunk = $junk
    }
}


function Get-CleanVersion {
    param($Decoded)
    if ($Decoded.InvalidFrames -ne 0 -or $Decoded.TrailingBytes -ne 0 -or
        $Decoded.DanglingEscape -or $Decoded.LeadingJunk -ne 0) { return $null }
    # This revision accepts only the observed CRC16 flavor. Other flavors are
    # recorded but do not permit an automatic CONNECT.
    $bad=@($Decoded.Frames | Where-Object {
        -not $_.BromCrcOk -or $_.Type -ne 0x81 -or $_.Size -eq 0
    })
    $v=@($Decoded.Frames | Where-Object {
        $_.Type -eq 0x81 -and $_.Size -gt 0 -and $_.BromCrcOk
    })
    if ($bad.Count -ne 0 -or $v.Count -eq 0) { return $null }
    $names=@($v | ForEach-Object { ConvertTo-Hex $_.Payload } | Select-Object -Unique)
    if ($names.Count -ne 1) { return $null }
    return $v[0]
}

function Get-VersionRoute {
    param($Decoded, [bool]$HandleUsable)
    if ($null -ne (Get-CleanVersion $Decoded)) {
        if ($HandleUsable) { return 'CONNECT_SAME_HANDLE' }
        return 'REOPEN_AND_REVALIDATE'
    }
    return 'VERSION_NOT_CONFIRMED'
}


# Accept only the two documented pre-CONNECT response classes. Unknown errors,
# bad CRC, incomplete frames and ACK without a sent CONNECT are not evidence.
function Get-ConnectEvidence {
    param($Decoded)
    if ($Decoded.InvalidFrames -ne 0 -or $Decoded.TrailingBytes -ne 0 -or
        $Decoded.DanglingEscape -or $Decoded.LeadingJunk -ne 0 -or
        $Decoded.Frames.Count -eq 0) { return $null }
    $versions=[System.Collections.Generic.List[string]]::new()
    $errors=0
    foreach($frame in $Decoded.Frames) {
        if (-not $frame.BromCrcOk) { return $null }
        if ($frame.Type -eq 0x81 -and $frame.Size -gt 0) {
            [void]$versions.Add((ConvertTo-Hex $frame.Payload))
        } elseif ($frame.Type -eq 0x8B -and $frame.Size -eq 0) {
            $errors++
        } else { return $null }
    }
    $unique=@($versions.ToArray() | Select-Object -Unique)
    if ($unique.Count -gt 1) { return $null }
    if ($unique.Count -eq 1) {
        $v=@($Decoded.Frames | Where-Object { $_.Type -eq 0x81 })[0]
        return [PSCustomObject]@{
            Basis='VERSION_CRC16'
            Version=[Text.Encoding]::ASCII.GetString($v.Payload).TrimEnd([char]0)
            VerifyErrorCount=$errors
        }
    }
    if ($errors -gt 0) {
        return [PSCustomObject]@{
            Basis='VERIFY_ERROR_CRC16'; Version=''; VerifyErrorCount=$errors
        }
    }
    return $null
}

function Get-HandshakeRoute {
    param($Decoded,[bool]$HandleUsable)
    if ($null -eq (Get-ConnectEvidence $Decoded)) { return 'STOP_OR_WAIT' }
    if ($HandleUsable) { return 'CONNECT_SAME_HANDLE' }
    return 'REOPEN_AND_REVALIDATE'
}

function Test-ConnectRecovery {
    [byte[]]$err=0x7E,0,0x8B,0,0,0xCB,0xAB,0x7E
    [byte[]]$ver=0x7E,0,0x81,0,0x0C,0x53,0x50,0x52,0x44,0x34,0x3A,0x41,0x75,0x74,0x6F,0x44,0,0xFD,0x8B,0x7E
    [byte[]]$ack=0x7E,0,0x80,0,0,0x3B,0x5A,0x7E
    $d=Decode-BslStream $err
    $e=Get-ConnectEvidence $d
    if ($null -eq $e -or $e.Basis -ne 'VERIFY_ERROR_CRC16' -or $e.Version -ne '') {
        throw '008B regression: error must permit only CONNECT recovery, not a version claim.'
    }
    if ($null -ne (Get-CleanVersion $d)) { throw '008B incorrectly labeled as version.' }
    if ((Get-HandshakeRoute $d $true) -ne 'CONNECT_SAME_HANDLE') {
        throw '008B regression: live-handle CONNECT was not selected.'
    }
    if ((Get-HandshakeRoute $d $false) -ne 'REOPEN_AND_REVALIDATE') {
        throw '008B regression: lost handle must be revalidated.'
    }
    $e=Get-ConnectEvidence (Decode-BslStream $ver)
    if ($null -eq $e -or $e.Basis -ne 'VERSION_CRC16' -or $e.Version -cne 'SPRD4:AutoD') {
        throw 'AutoD regression failed.'
    }
    $e=Get-ConnectEvidence (Decode-BslStream ([byte[]]($ver+$err)))
    if ($null -eq $e -or $e.VerifyErrorCount -ne 1) { throw 'Version/error sequence regression failed.' }
    if ($null -ne (Get-ConnectEvidence (Decode-BslStream $ack))) { throw 'Unsolicited ACK accepted as handshake evidence.' }
    [byte[]]$bad=$err.Clone(); $bad[5]=$bad[5] -bxor 1
    if ($null -ne (Get-ConnectEvidence (Decode-BslStream $bad))) { throw 'Corrupt 008B CRC accepted.' }
    [byte[]]$bad=$err.Clone(); $bad[4]=1
    if ($null -ne (Get-ConnectEvidence (Decode-BslStream $bad))) { throw 'Invalid 008B length accepted.' }
    for($n=1;$n -lt $err.Length;$n++) {
        if ($null -ne (Get-ConnectEvidence (Decode-BslStream ([byte[]]$err[0..($n-1)])))) {
            throw 'Partial 008B accepted.'
        }
    }
    if ($null -ne (Get-ConnectEvidence (Decode-BslStream ([byte[]](0x55)+$err)))) {
        throw 'Leading junk accepted.'
    }
    # Build a valid CRC frame with an unapproved error type 0082.
    [byte[]]$unknown=0x7E,0,0x82,0,0,0,0,0x7E
    $crc=Get-BromCrc16 ([byte[]]@(0,0x82,0,0))
    $unknown[5]=[byte](($crc -shr 8) -band 0xFF); $unknown[6]=[byte]($crc -band 0xFF)
    if ($null -ne (Get-ConnectEvidence (Decode-BslStream $unknown))) { throw 'Unknown error incorrectly permitted CONNECT.' }
}

function Test-AutoDRegression {
    [byte[]]$actual=0x7E,0,0x81,0,0x0C,0x53,0x50,0x52,0x44,0x34,0x3A,0x41,0x75,0x74,0x6F,0x44,0,0xFD,0x8B,0x7E
    $d=Decode-BslStream $actual
    $v=Get-CleanVersion $d
    if ($null -eq $v -or $v.Size -ne 12 -or $v.ReceivedChecksum -ne 0xFD8B -or
        [Text.Encoding]::ASCII.GetString($v.Payload).TrimEnd([char]0) -cne 'SPRD4:AutoD') {
        throw 'Regression failed: the captured AutoD version must be accepted.'
    }
    if ((Get-VersionRoute $d $true) -ne 'CONNECT_SAME_HANDLE') {
        throw 'Regression failed: valid early version must not require USB removal.'
    }
    if ((Get-VersionRoute $d $false) -ne 'REOPEN_AND_REVALIDATE') {
        throw 'Regression failed: a dead handle must not authorize CONNECT.'
    }
    [byte[]]$echo=0x7E,0,0,0,0,8,0,0xFE,0x82,0x7E
    $mixed=Decode-BslStream ([byte[]]($echo+$actual))
    if ($mixed.Echoes -ne 1 -or $null -eq (Get-CleanVersion $mixed)) {
        throw 'Regression failed: exact echo plus a valid BSL frame.'
    }
    if ($null -ne (Get-CleanVersion (Decode-BslStream $echo))) {
        throw 'Regression failed: echo alone is not a version.'
    }
    [byte[]]$bad=$actual.Clone(); $bad[17]=$bad[17] -bxor 1
    if ($null -ne (Get-CleanVersion (Decode-BslStream $bad))) {
        throw 'Regression failed: corrupt CRC was accepted.'
    }
    [byte[]]$bad=$actual.Clone(); $bad[4]=13
    if ($null -ne (Get-CleanVersion (Decode-BslStream $bad))) {
        throw 'Regression failed: incorrect length was accepted.'
    }
    for ($n=1; $n -lt $actual.Length; $n++) {
        if ($null -ne (Get-CleanVersion (Decode-BslStream ([byte[]]$actual[0..($n-1)])))) {
            throw 'Regression failed: partial version accepted.'
        }
    }
    # Known CRC16 ACK from type 0080, length 0000.
    [byte[]]$ack=0x7E,0,0x80,0,0,0x3B,0x5A,0x7E
    $d=Decode-BslStream $ack
    if ($d.Frames.Count -ne 1 -or -not $d.Frames[0].BromCrcOk -or $d.Frames[0].Type -ne 0x80) {
        throw 'Regression failed: empty ACK vector.'
    }
}

function Test-BslCodec {
    if ((Get-BromCrc16 ([Text.Encoding]::ASCII.GetBytes('123456789'))) -ne 0x31C3) {
        throw 'CRC16 self-test failed.'
    }
    if ((Get-BromCrc16 ([byte[]]@(0,0,0,0))) -ne 0) { throw 'CONNECT CRC self-test failed.' }
    if ((Get-FdlChecksum ([byte[]]@(0,0,0,0))) -ne 0xFFFF) { throw 'FDL checksum self-test failed.' }
    # Known BSL connect frame, length=0, CRC16=0000.
    $p = Decode-BslStream ([byte[]]@(0x7E,0,0,0,0,0,0,0x7E))
    if ($p.Frames.Count -ne 1 -or -not $p.Frames[0].BromCrcOk -or $p.Frames[0].Type -ne 0) {
        throw 'BSL frame self-test failed.'
    }
    $p = Decode-BslStream ([byte[]]@(0x7E,0x7E,0,0,0,0,0,0,0x7E,0x7E))
    if ($p.Frames.Count -ne 1 -or $p.InvalidFrames -ne 0) { throw 'Flag handling self-test failed.' }
    $p = Decode-BslStream ([byte[]]@(0x7E,0,0,0,1,0,0,0x7E))
    if ($p.InvalidFrames -ne 1 -or $p.Frames.Count -ne 0) { throw 'Length rejection self-test failed.' }
    Write-Output 'SELFTEST PASS: CRC16, FDL checksum, empty frame, repeated flags, invalid length. No device I/O.'
}


[byte[]]$BootSelect = 0x7E,0,0,0,0,8,0,0xFE,0x82,0x7E
if ((ConvertTo-Hex $BootSelect) -ne '7E 00 00 00 00 08 00 FE 82 7E') {
    throw 'Boot-selection allowlist self-test failed.'
}
Test-BslCodec | Out-Null
Test-AutoDRegression
Test-ConnectRecovery
if ($SelfTest) {
    Write-Output 'SELFTEST PASS: captured AutoD and 008B; live/dead-handle routes; partial/bad CRC/unknown-error/unsolicited-ACK rejection. No device I/O.'
    return
}
if ($ReplayFile) {
    $raw=[IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ReplayFile).Path)
    $decoded=Decode-BslStream $raw
    $version=Get-CleanVersion $decoded
    Write-Output ('REPLAY BYTES: '+$raw.Length)
    Write-Output ('REPLAY HEX: '+(ConvertTo-Hex $raw))
    Write-Output ('DECISION assuming the live handle is still usable: '+(Get-HandshakeRoute $decoded $true))
    $evidence=Get-ConnectEvidence $decoded
    if ($null -ne $evidence) { Write-Output ('CONNECT_BASIS: '+$evidence.Basis) }
    if ($null -ne $version) {
        Write-Output ('VERSION: '+[Text.Encoding]::ASCII.GetString($version.Payload).TrimEnd([char]0))
        Write-Output ('CRC16: {0:X4}' -f $version.ReceivedChecksum)
    }
    Write-Output 'Offline only. No Windows enumeration, serial open or device data transmission.'
    return
}
if ($env:OS -ne 'Windows_NT') { throw 'Device operation requires Windows.' }

# Fast, present-only SetupAPI enumeration. Compiled before the insertion window.
if (-not ('P011BootPortsV13' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
public sealed class P011BootPortV13 {
    public string Id;
    public string Name;
    public string Port;
    public bool IsDownload;
    public uint Problem;
    public uint StatusFlags;
    public bool Started;
}
public static class P011BootPortsV13 {
    [StructLayout(LayoutKind.Sequential)]
    struct SP_DEVINFO_DATA {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr SetupDiGetClassDevsW(ref Guid g, string enumerator, IntPtr parent, uint flags);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiEnumDeviceInfo(IntPtr set, uint index, ref SP_DEVINFO_DATA info);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref SP_DEVINFO_DATA info,
        StringBuilder id, uint size, out uint needed);
    [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr set, ref SP_DEVINFO_DATA info,
        uint property, out uint regType, byte[] bytes, uint size, out uint needed);
    [DllImport("setupapi.dll", SetLastError=true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("cfgmgr32.dll")]
    static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);
    public static P011BootPortV13[] Find() {
        var items = new List<P011BootPortV13>();
        var g = new Guid("4d36e978-e325-11ce-bfc1-08002be10318");
        IntPtr set = SetupDiGetClassDevsW(ref g, null, IntPtr.Zero, 2); // DIGCF_PRESENT
        if (set == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try {
            for (uint i=0; ; i++) {
                var d = new SP_DEVINFO_DATA();
                d.cbSize = (uint)Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
                if (!SetupDiEnumDeviceInfo(set, i, ref d)) {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 259) break;
                    throw new System.ComponentModel.Win32Exception(err);
                }
                uint need;
                var id = new StringBuilder(1024);
                if (!SetupDiGetDeviceInstanceIdW(set, ref d, id, 1024, out need)) continue;
                string s = id.ToString();
                if (!Regex.IsMatch(s, @"^USB\\VID_1782&PID_(?:4D00|4064)(?:&|\\)", RegexOptions.IgnoreCase)) continue;
                var bytes = new byte[4096];
                uint reg;
                string name = "";
                if (SetupDiGetDeviceRegistryPropertyW(set, ref d, 12, out reg, bytes, (uint)bytes.Length, out need))
                    name = Encoding.Unicode.GetString(bytes, 0, (int)Math.Min(need,(uint)bytes.Length)).TrimEnd('\0');
                var m = Regex.Match(name, @"\((COM\d+)\)", RegexOptions.IgnoreCase);
                uint status, problem;
                if (CM_Get_DevNode_Status(out status, out problem, d.DevInst, 0) != 0) problem=0xFFFFFFFF;
                items.Add(new P011BootPortV13 { Id=s, Name=name, Port=m.Success ? m.Groups[1].Value : "",
                    IsDownload=Regex.IsMatch(s, @"^USB\\VID_1782&PID_4D00(?:&|\\)", RegexOptions.IgnoreCase), Problem=problem, StatusFlags=status, Started=(status & 0x8) != 0 });
            }
        } finally { SetupDiDestroyDeviceInfoList(set); }
        return items.ToArray();
    }
}
'@
}

$outDir = Join-Path $env:TEMP ('P011-BootSelect-v13-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmssfff'))
[void](New-Item -ItemType Directory -Path $outDir)
$log = [System.Collections.Generic.List[string]]::new()
$serial = $null
$state = @{ ModeAttempted=$false; ModeWriteReturned=$false; Echo=$false; SawRemoval=$false;
    SyncAttempted=0; SyncReturned=0; ConnectAttempted=$false; ConnectReturned=$false;
    Result='NOT_STARTED'; LastSnapshot=''; Phase='PREPARE'; ConnectBasis=''; Version='';
    OpenAttempts=0; OpenFailures=0; LastOpenWin32=$null }

function Log-Line {
    param([string]$Text)
    Write-Host $Text
    [void]$log.Add(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text))
}
function Current-Ports {
    $items = @([P011BootPortsV13]::Find())
    $parts = @($items | Sort-Object Id | ForEach-Object { '{0}: {1}; problem={2}; started={3}; flags=0x{4:X8}' -f (($_.Id -split '\\')[1]),$_.Name,$_.Problem,$_.Started,$_.StatusFlags })
    $signature = $parts -join ' | '
    if ($signature -ne $state.LastSnapshot) {
        $shown=$signature
        if (-not $shown) { $shown='(no present target COM interfaces)' }
        Log-Line "USB: $shown"
        $state.LastSnapshot=$signature
    }
    return $items
}
function Open-DownloadPortOnce {
    param($Device)
    # Caller has just enumerated present 1782:4D00 devices. No serial data is
    # transmitted by this function. Open configures serial parameters/control lines.
    $p = [IO.Ports.SerialPort]::new()
    try {
        $p.PortName=$Device.Port; $p.BaudRate=115200; $p.DataBits=8
        $p.Parity=[IO.Ports.Parity]::None; $p.StopBits=[IO.Ports.StopBits]::One
        $p.Handshake=[IO.Ports.Handshake]::None
        $p.DtrEnable=$true; $p.RtsEnable=$true; $p.DiscardNull=$false
        $p.ReadTimeout=200; $p.WriteTimeout=1000
        $p.Open()
        # Check that the driver accepts a status operation after Open. Do not
        # discard input here: an early version response must not be thrown away.
        $null=$p.BytesToRead
        return $p
    } catch {
        $savedError=$_
        try { $p.Dispose() } catch { }
        throw $savedError
    }
}
function Get-OpenErrorInfo {
    param([Exception]$Exception)
    $e=$Exception
    while ($null -ne $e.InnerException) { $e=$e.InnerException }
    # Do not label an arbitrary HRESULT's low word as a Win32 error.
    $facility=([int64]$e.HResult -shr 16) -band 0x1FFF
    $code=$null
    if ($e -is [ComponentModel.Win32Exception]) {
        $code=$e.NativeErrorCode
    } elseif ($facility -eq 7) {
        $code=([int64]$e.HResult -band 0xFFFF)
    }
    $retry=(($e -is [IO.IOException]) -or
        ($e -is [TimeoutException]) -or
        ($e -is [ComponentModel.Win32Exception] -and
         $null -ne $code -and $code -in @(2,3,6,21,31,55,121,433,995,1167)))
    # Access denied / sharing / invalid configuration needs investigation,
    # not repeated opens that obscure the original error.
    if ($e -is [UnauthorizedAccessException] -or
        ($null -ne $code -and $code -in @(5,32,87))) { $retry=$false }
    return [PSCustomObject]@{
        Retryable=$retry; Code=$code; HResult=$e.HResult;
        Type=$e.GetType().FullName; Message=$e.Message
    }
}
function Wait-DownloadPortOpen {
    param(
        [ValidateSet('BOOT','RECONNECT')][string]$Phase,
        [ValidateRange(1,60)][int]$TimeoutSeconds
    )
    $state.Phase=$Phase
    $timer=[Diagnostics.Stopwatch]::StartNew()
    $tries=0
    $normalSince=-1L
    $lastCandidate=''
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        # Re-enumerate every time; never reopen a stored pre-removal object.
        $all=@(Current-Ports)
        $dl=@($all | Where-Object { $_.IsDownload })
        if ($dl.Count -gt 1) {
            $state.Result='MULTIPLE_DOWNLOAD_PORTS'
            throw 'Multiple present 4D00 devices. Disconnect other Unisoc devices.'
        }
        if ($Phase -eq 'RECONNECT' -and $dl.Count -eq 0 -and -not $state.SawRemoval) {
            $state.SawRemoval=$true
            Log-Line 'USB_REMOVAL: no present 4D00 port remains.'
        }
        # The same COM number may be re-used. A fresh successful Open matters,
        # not whether the friendly name changed.
        $ready=@($dl | Where-Object { $_.Problem -eq 0 -and $_.Started -and $_.Port })
        if ($ready.Count -eq 1) {
            $device=$ready[0]
            $signature=$device.Id+'|'+$device.Port
            if ($signature -ne $lastCandidate) {
                Log-Line ('OPEN_CANDIDATE: phase={0}; port={1}; elapsed_ms={2}. Enumeration is not open success.' -f
                    $Phase,$device.Port,$timer.ElapsedMilliseconds)
                $lastCandidate=$signature
            }
            $tries++; $state.OpenAttempts++
            $opened=$null
            try {
                $opened=Open-DownloadPortOnce $device
                # If the port disappears/changes again, close this handle and wait.
                $after=@(Current-Ports | Where-Object {
                    $_.IsDownload -and $_.Problem -eq 0 -and $_.Started -and $_.Port
                })
                if ($after.Count -ne 1 -or $after[0].Id -ne $device.Id -or
                    $after[0].Port -ne $device.Port) {
                    throw [IO.IOException]::new('Target changed during port open; no payload sent.')
                }
            } catch {
                if ($null -ne $opened) { try { $opened.Dispose() } catch { }; $opened=$null }
                $state.OpenFailures++
                $detail=Get-OpenErrorInfo $_.Exception
                $state.LastOpenWin32=$detail.Code
                $codeText='not-a-Win32-HRESULT'
                if ($null -ne $detail.Code) { $codeText=[string]$detail.Code }
                Log-Line ('OPEN_RETRY: phase={0}; attempt={1}; port={2}; elapsed_ms={3}; retryable={4}; win32={5}; hresult={6}; {7}; {8}' -f
                    $Phase,$tries,$device.Port,$timer.ElapsedMilliseconds,$detail.Retryable,
                    $codeText,$detail.HResult,$detail.Type,$detail.Message)
                if (-not $detail.Retryable) {
                    $state.Result='PORT_OPEN_FATAL'
                    throw
                }
            }
            if ($null -ne $opened) {
                Log-Line ('OPEN_READY: phase={0}; port={1}; attempts={2}; elapsed_ms={3}' -f
                    $Phase,$device.Port,$tries,$timer.ElapsedMilliseconds)
                return [PSCustomObject]@{ Serial=$opened; Device=$device }
            }
            if ($tries -ge 60) {
                $state.Result='PORT_OPEN_RETRY_LIMIT'
                throw '60 open attempts reached. No repeated mode request or loader upload.'
            }
        }
        # A stable normal-runtime enumeration means this capture has fallen back
        # to the running OS. Never send BSL/boot-selection data to PID_4064.
        $normal=@($all | Where-Object { -not $_.IsDownload })
        if ($Phase -eq 'RECONNECT' -and
            $dl.Count -eq 0 -and $normal.Count -gt 0) {
            if ($normalSince -lt 0) { $normalSince=$timer.ElapsedMilliseconds }
            if (($timer.ElapsedMilliseconds-$normalSince) -ge 750) {
                $state.Result='RETURNED_TO_RUNTIME'
                throw 'Normal PID_4064 returned; stopping without opening runtime ports.'
            }
        } else { $normalSince=-1L }
        # Bounded readiness polling, not resending the mode-select command.
        Start-Sleep -Milliseconds 150
    }
    $state.Result='PORT_READY_TIMEOUT'
    throw ("{0}: no openable 4D00 captured within the {1}s polling window. Driver calls add their own latency." -f
        $Phase,$TimeoutSeconds)
}
function Log-Exception {
    param([Exception]$Exception)
    $e=$Exception
    while ($null -ne $e) {
        Log-Line ('EXCEPTION: {0}; HResult={1}; {2}' -f $e.GetType().FullName,$e.HResult,$e.Message)
        $e=$e.InnerException
    }
}
function Send-Only {
    param([string]$Kind, [byte[]]$Bytes)
    $hex=ConvertTo-Hex $Bytes
    if ($Kind -eq 'MODE' -and $hex -eq '7E 00 00 00 00 08 00 FE 82 7E' -and -not $state.ModeAttempted) {
        $state.ModeAttempted=$true
    } elseif ($Kind -eq 'SYNC' -and $hex -eq '7E' -and $state.Result -eq 'AWAITING_BSL_VERSION' -and $state.SyncAttempted -lt 4 -and -not $state.ConnectAttempted) {
        $state.SyncAttempted++
    } elseif ($Kind -eq 'CONNECT' -and $hex -eq '7E 00 00 00 00 00 00 7E' -and $state.Result -eq 'BSL_CONNECT_READY' -and $state.ConnectBasis -in @('VERSION_CRC16','VERIFY_ERROR_CRC16') -and -not $state.ConnectAttempted) {
        $state.ConnectAttempted=$true
    } else { throw 'Outbound packet rejected by fixed operation allowlist.' }
    $packetName=('{0}-{1:D2}-tx.bin' -f $Kind.ToLowerInvariant(),($state.SyncAttempted+1))
    [IO.File]::WriteAllBytes((Join-Path $outDir $packetName),$Bytes)
    Log-Line "TX_ATTEMPT $Kind : $hex"
    $serial.Write($Bytes,0,$Bytes.Length)
    if ($Kind -eq 'MODE') { $state.ModeWriteReturned=$true }
    elseif ($Kind -eq 'SYNC') { $state.SyncReturned++ }
    else { $state.ConnectReturned=$true }
    Log-Line "TX_API_RETURNED: $Kind (not proof of device acceptance)"
}
function Read-Available {
    param([System.Collections.Generic.List[byte]]$Destination)
    $available=$serial.BytesToRead
    if ($available -gt 0) {
        if ($Destination.Count -ge 16384) { throw 'Receive limit reached.' }
        $n=[Math]::Min([Math]::Min($available,4096),16384-$Destination.Count)
        $b=New-Object byte[] $n
        $n=$serial.Read($b,0,$b.Length)
        for($i=0;$i -lt $n;$i++){ [void]$Destination.Add($b[$i]) }
    }
}
function Save-Rx {
    param([string]$Stage,[byte[]]$Bytes)
    [IO.File]::WriteAllBytes((Join-Path $outDir "$Stage-rx.bin"),$Bytes)
    Log-Line "$Stage RX BYTES: $($Bytes.Length)"
    Log-Line ("$Stage RX HEX: " + (ConvertTo-Hex $Bytes))
}
function Receive-Bsl {
    param(
        [string]$Stage, [int]$Type, [switch]$Synchronize,
        [int]$TimeoutMs=4000, [byte[]]$Seed=@()
    )
    $rx=[System.Collections.Generic.List[byte]]::new()
    foreach($b in $Seed){ [void]$rx.Add($b) }
    $seedCount=$rx.Count
    $timer=[Diagnostics.Stopwatch]::StartNew()
    [long]$nextSync=0
    $errorSeen=$false
    try {
        while($timer.ElapsedMilliseconds -lt $TimeoutMs){
            # Preserve bytes already received, including a split frame.
            Read-Available $rx
            $d=Decode-BslStream ($rx.ToArray())
            if($d.InvalidFrames -gt 0 -or $d.LeadingJunk -gt 0){ break }
            if ($Type -eq 0x81) {
                if ($null -ne (Get-ConnectEvidence $d)) { break }
                # Do not keep waiting/synchronizing past a complete unapproved reply.
                if ($d.Frames.Count -gt 0 -and $d.TrailingBytes -eq 0 -and -not $d.DanglingEscape) { break }
            } else {
                $valid=@($d.Frames | Where-Object { $_.Type -eq $Type -and $_.BromCrcOk })
                if($valid.Count -gt 0 -and $d.TrailingBytes -eq 0){ break }
            }
            # Do not add sync bytes to a partial/unknown response.
            if($Synchronize -and $d.Frames.Count -eq 0 -and $d.TrailingBytes -eq 0 -and
                -not $d.DanglingEscape -and $state.SyncAttempted -lt 4 -and
                $timer.ElapsedMilliseconds -ge $nextSync){
                Send-Only 'SYNC' ([byte[]]@(0x7E))
                $nextSync=$timer.ElapsedMilliseconds+400
            }
            Start-Sleep -Milliseconds 20
        }
    } catch { $errorSeen=$true; Log-Exception $_.Exception }
    Save-Rx $Stage ($rx.ToArray())
    Log-Line ("{0} RX_NEW_BYTES: {1}; carried_from_previous_phase={2}" -f $Stage,($rx.Count-$seedCount),$seedCount)
    $d=Decode-BslStream ($rx.ToArray())
    if($d.Echoes -gt 0){ $state.Echo=$true; Log-Line 'BOOT_SELECT_ECHO: exact frame observed; not BSL proof.' }
    foreach($f in $d.Frames){
        Log-Line ('BSL FRAME: type=0x{0:X4}, payload={1}, checksum=0x{2:X4}, CRC16={3}, FDL_SUM={4}' -f
            $f.Type,$f.Size,$f.ReceivedChecksum,$f.BromCrcOk,$f.FdlChecksumOk)
        $text=[Text.Encoding]::ASCII.GetString($f.Payload).TrimEnd([char]0) -replace '[^\x20-\x7E]','.'
        Log-Line "PAYLOAD: $text"
    }
    Log-Line ('PARSE: invalid={0}; trailing={1}; escape={2}; junk={3}; echo={4}' -f
        $d.InvalidFrames,$d.TrailingBytes,$d.DanglingEscape,$d.LeadingJunk,$d.Echoes)
    return [PSCustomObject]@{ Decoded=$d; Raw=$rx.ToArray(); IoError=$errorSeen }
}

function Test-CurrentHandle {
    param($Device)
    if($null -eq $serial -or -not $serial.IsOpen){ return $false }
    $all=@(Current-Ports)
    $dl=@($all | Where-Object { $_.IsDownload })
    if($dl.Count -gt 1){ throw 'Multiple target download devices; stopped.' }
    if($dl.Count -eq 0){ $state.SawRemoval=$true; return $false }
    if($dl[0].Id -ne $Device.Id -or $dl[0].Port -ne $Device.Port){ return $false }
    try { $null=$serial.BytesToRead; return $true } catch { Log-Exception $_.Exception; return $false }
}

function Close-CurrentHandle {
    if($null -ne $serial){ try{$serial.Dispose()}catch{Log-Exception $_.Exception} }
}

try {
    Log-Line 'P011 boot-stage download selection probe v1.3'
    Log-Line 'FIX: valid 0081 VERSION or empty 008B VERIFY_ERROR -> one CONNECT on the same live handle.'
    Log-Line 'Mode selection may reboot the pen. No FDL, EXEC, memory or storage operations.'
    Log-Line "OUTPUT: $outDir"
    if ((Read-Host 'Type DOWNLOAD to permit the boot-mode request and one CONNECT') -cne 'DOWNLOAD') {
        throw 'Not confirmed; no device opened or command sent.'
    }
    $initial=@(Current-Ports | Where-Object { $_.IsDownload })
    if($initial.Count -gt 0){ throw '4D00 already present. Unplug, power off normally, then start a fresh run.' }
    Log-Line 'WAIT: With the pen OFF, insert USB now. Do not press any button. Waiting 60 seconds.'
    $state.Result='WAITING_FIRST_PORT'
    $connection=Wait-DownloadPortOpen -Phase BOOT -TimeoutSeconds 60
    $old=$connection.Device
    $serial=$connection.Serial
    $state.Result='BOOT_SELECT_PENDING'

    # Briefly inspect already-buffered data before issuing boot-stage syntax.
    # This is passive; it does not send a sync byte into a boot-selection parser.
    $hello=Receive-Bsl -Stage '00-passive' -Type 0x81 -TimeoutMs 100
    $evidence=Get-ConnectEvidence $hello.Decoded
    if ($hello.IoError) { throw 'Passive receive failed. No mode request sent.' }
    if ($null -eq $evidence) {
        if ($hello.Raw.Length -gt 0) {
            # Finish a possible partial reply, but never guess a mode for junk.
            $hello=Receive-Bsl -Stage '00-passive-tail' -Type 0x81 -TimeoutMs 500 -Seed $hello.Raw
            $evidence=Get-ConnectEvidence $hello.Decoded
            if ($hello.IoError -or $null -eq $evidence) {
                throw 'Unrecognized unsolicited data. No mode request or CONNECT sent.'
            }
        } else {
            Send-Only 'MODE' $BootSelect
            $hello=Receive-Bsl -Stage '01-boot-select' -Type 0x81 -TimeoutMs 1800
            $evidence=Get-ConnectEvidence $hello.Decoded
        }
    } else {
        Log-Line 'MODE_SKIPPED: already received validated BSL evidence on this handle.'
    }
    $sameHandle=(-not $hello.IoError) -and (Test-CurrentHandle $old)

    if($null -ne $evidence -and $sameHandle){
        Log-Line ('EARLY_BSL_EVIDENCE: '+$evidence.Basis)
        Log-Line 'ROUTE: CONNECT_SAME_HANDLE; neither another sync nor USB removal is required.'
    } else {
        if($sameHandle -and -not $hello.IoError){
            # Do not carry a complete unapproved error into an artificial sync wait.
            if ($hello.Decoded.InvalidFrames -gt 0 -or $hello.Decoded.LeadingJunk -gt 0 -or
                ($hello.Decoded.Frames.Count -gt 0 -and $hello.Decoded.TrailingBytes -eq 0)) {
                throw 'Complete but unapproved BSL response. No CONNECT sent.'
            }
            Log-Line 'ROUTE: WAIT_OR_SYNC_SAME_HANDLE; boot-selection will not be resent.'
            $state.Result='AWAITING_BSL_VERSION'
            $hello=Receive-Bsl -Stage '02-same-port-sync' -Type 0x81 -Synchronize -Seed $hello.Raw
            $evidence=Get-ConnectEvidence $hello.Decoded
            $sameHandle=(-not $hello.IoError) -and (Test-CurrentHandle $old)
        }
        if(-not $sameHandle){
            Close-CurrentHandle
            $serial=$null
            Log-Line 'ROUTE: REOPEN_AND_REVALIDATE; old-session data does not authorize CONNECT.'
            $state.Result='WAITING_REOPEN'
            $connection=Wait-DownloadPortOpen -Phase RECONNECT -TimeoutSeconds 30
            $serial=$connection.Serial
            $old=$connection.Device
            $state.Result='AWAITING_BSL_VERSION'
            $hello=Receive-Bsl -Stage '03-reopened-sync' -Type 0x81 -Synchronize
            $evidence=Get-ConnectEvidence $hello.Decoded
            $sameHandle=(-not $hello.IoError) -and (Test-CurrentHandle $old)
        }
    }
    if($null -eq $evidence -or -not $sameHandle){
        $state.Result='BSL_EVIDENCE_UNCONFIRMED'
        throw 'No allowed CRC16-valid BSL response on a live handle. No CONNECT sent.'
    }
    $state.Result='BSL_CONNECT_READY'
    $state.Phase='CONNECT_SAME_HANDLE'
    $state.ConnectBasis=$evidence.Basis
    $state.Version=$evidence.Version
    if ($evidence.Basis -eq 'VERIFY_ERROR_CRC16') {
        Log-Line 'BSL_VERIFY_ERROR_CONFIRMED: 0x008B; CRC16 valid; no firmware was uploaded.'
        Log-Line 'RECOVERY: one correctly framed empty CONNECT, as in spd_dump initial handshake.'
        Log-Line 'VERSION_UNKNOWN: this response contains no version or Secure Boot information.'
    } else {
        Log-Line ('BSL_REP_VER_CONFIRMED: '+$state.Version+'; CRC16 verified. Not immutable-BootROM proof.')
    }
    # The current protocol is CRC16 (confirmed by the response), so CONNECT is
    # 7E 0000 0000 0000 7E. Never resend after timeout or error in the ACK phase.
    Send-Only 'CONNECT' ([byte[]]@(0x7E,0,0,0,0,0,0,0x7E))
    $ack=Receive-Bsl -Stage '04-connect' -Type 0x80
    $d=$ack.Decoded
    $acks=@($d.Frames | Where-Object { $_.Type -eq 0x80 -and $_.Size -eq 0 -and $_.BromCrcOk })
    $other=@($d.Frames | Where-Object {
        -not $_.BromCrcOk -or ($_.Type -ne 0x80 -and $_.Type -ne 0x81)
    })
    if(-not $ack.IoError -and $d.InvalidFrames -eq 0 -and $d.TrailingBytes -eq 0 -and
        -not $d.DanglingEscape -and $d.LeadingJunk -eq 0 -and $acks.Count -gt 0 -and $other.Count -eq 0){
        $state.Result='BSL_HANDSHAKE_CONFIRMED'
        Log-Line 'BSL CONNECT: ACK verified. Stopping here: no EXEC or loader/staging sequence follows.'
        if (-not $state.Version) { Log-Line 'VERSION_UNKNOWN: a verified connection is not a version or storage-access result.' }
    } else {
        $state.Result='BSL_RESPONSE_CONFIRMED_CONNECT_UNCONFIRMED'
        Log-Line 'Pre-CONNECT response was valid, but CONNECT ACK was not verified. No resend or extra commands.'
    }
} catch {
    Log-Exception $_.Exception
    Log-Line ('STOP: '+$_.Exception.Message)
} finally {
    if($null -ne $serial){ try{$serial.Dispose()}catch{Log-Exception $_.Exception} }
    Log-Line ('RESULT: {0}; select_attempted={1}; select_API_returned={2}; echo={3}; USB_removal={4}; sync_attempts={5}; sync_API_returns={6}; CONNECT_attempted={7}' -f
        $state.Result,$state.ModeAttempted,$state.ModeWriteReturned,$state.Echo,$state.SawRemoval,$state.SyncAttempted,$state.SyncReturned,$state.ConnectAttempted)
    Log-Line ('OPEN_SUMMARY: attempts={0}; failures={1}; last_win32={2}; phase={3}' -f
        $state.OpenAttempts,$state.OpenFailures,$state.LastOpenWin32,$state.Phase)
    $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outDir 'state.json') -Encoding UTF8
    Log-Line 'No FDL uploads, EXEC_DATA, partition commands, memory commands, eFuse or password attempts. Mode change may have occurred.'
    Log-Line 'Unplug USB and use the normal power-on procedure. Do not run erase/format commands to exit a blank screen.'
    $report=Join-Path $outDir 'report.txt'
    $log | Set-Content -LiteralPath $report -Encoding UTF8
    Write-Host "REPORT: $report"
    try{
        Compress-Archive -LiteralPath $outDir -DestinationPath "$outDir.zip" -CompressionLevel Optimal
        Write-Host "ZIP: $outDir.zip"
    }catch{ Write-Host ('ZIP failed: '+$_.Exception.Message) }
}

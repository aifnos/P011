# P011 PlayLab 1.2
# Host workspace defaults to D:\project\P011. Device code stays in /tmp.
# This launcher never supplies flash/remount/startup/network-server commands.
# Python stdout, stderr and REMOTE status are captured independently on-device;
# this also works when old adbd does not propagate the remote shell exit code.
[CmdletBinding()]
param(
    [ValidateSet('Inventory','Demo','Calibrate','Stop','Capture','Screen')][string]$Mode='Inventory',
    [string]$WorkRoot='D:\project\P011',
    [string]$PackageDir='',
    [string]$AdbPath='',
    [ValidateRange(30,600)][int]$Seconds=120,
    [ValidateSet('auto','0','90','180','270')][string]$Rotate='auto',
    [ValidateSet('p011','full')][string]$Fit='p011',
    [ValidateRange(2,120)][int]$RecordEvery=10,
    [ValidateRange(1,12)][int]$Shots=1,
    [ValidateRange(2,60)][int]$Interval=5
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if (-not [IO.Path]::IsPathRooted($WorkRoot)) { throw 'WorkRoot must be an absolute host path.' }
[void](New-Item -ItemType Directory -Path $WorkRoot -Force)
$WorkRoot=(Resolve-Path -LiteralPath $WorkRoot).Path
if (-not $PackageDir) { $PackageDir=Join-Path $WorkRoot 'PlayLab' }
$PackageDir=(Resolve-Path -LiteralPath $PackageDir).Path
$runId=Get-Date -Format 'yyyyMMdd-HHmmssfff'
$out=Join-Path $WorkRoot ('logs\PlayLab-'+$Mode+'-'+$runId)
[void](New-Item -ItemType Directory -Path $out -Force)
$utf8=[Text.UTF8Encoding]::new($false)
$report=[IO.StreamWriter]::new((Join-Path $out 'report.txt'),$false,$utf8)
$report.AutoFlush=$true
$remote='/tmp/p011-playlab-v12'
$visualRemote=''
$visualLocal=Join-Path $out 'screenshots'
$serial=''
$counter=0
$result='NOT_STARTED'

function Log-Line {
    param([string]$Text)
    Write-Host $Text
    $report.WriteLine(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'),$Text))
}
function Quote-NativeArg {
    param([AllowEmptyString()][string]$Value)
    # Windows C-runtime command-line quoting; never invokes cmd.exe.
    $s=[regex]::Replace($Value,'(\\*)"','$1$1\"')
    $s=[regex]::Replace($s,'(\\+)$','$1$1')
    return ('"'+$s+'"')
}
function Invoke-AdbCapture {
    param([string[]]$Argv,[string]$Label,[int]$TimeoutSeconds=30)
    if ($Label -notmatch '^[A-Za-z0-9_-]+$') { throw 'Invalid host capture label.' }
    $psi=[Diagnostics.ProcessStartInfo]::new()
    $psi.FileName=$AdbPath
    $psi.Arguments=(@($Argv | ForEach-Object { Quote-NativeArg $_ }) -join ' ')
    $psi.WorkingDirectory=$WorkRoot
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=$true
    $psi.RedirectStandardError=$true
    $psi.RedirectStandardInput=$true
    $psi.StandardOutputEncoding=$utf8
    $psi.StandardErrorEncoding=$utf8
    $p=[Diagnostics.Process]::new()
    $p.StartInfo=$psi
    $stdout=''; $stderr=''; $rc=$null; $timedOut=$false
    try {
        if (-not $p.Start()) { throw 'Could not start adb.' }
        $p.StandardInput.Close()
        $readOut=$p.StandardOutput.ReadToEndAsync()
        $readErr=$p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds*1000)) {
            $timedOut=$true
            $p.Kill()
            if (-not $p.WaitForExit(5000)) { throw 'ADB host process did not exit after its deadline.' }
        }
        $stdout=$readOut.GetAwaiter().GetResult()
        $stderr=$readErr.GetAwaiter().GetResult()
        $rc=$p.ExitCode
    } finally {
        [IO.File]::WriteAllText((Join-Path $out ($Label+'.adb.stdout.txt')),$stdout,$utf8)
        [IO.File]::WriteAllText((Join-Path $out ($Label+'.adb.stderr.txt')),$stderr,$utf8)
        [IO.File]::WriteAllText((Join-Path $out ($Label+'.adb.status.txt')),
            ('exit='+$rc+'; timeout='+$timedOut),$utf8)
        $p.Dispose()
    }
    return [PSCustomObject]@{ Stdout=$stdout; Stderr=$stderr; ExitCode=$rc; TimedOut=$timedOut }
}
function Require-AdbSuccess {
    param($Capture,[string]$Label)
    if ($Capture.TimedOut -or $Capture.ExitCode -ne 0) {
        if ($Capture.Stderr) { Log-Line $Capture.Stderr.TrimEnd() }
        if ($Capture.Stdout) { Log-Line $Capture.Stdout.TrimEnd() }
        throw ('ADB operation failed: '+$Label+'; exit='+$Capture.ExitCode+'; timeout='+$Capture.TimedOut)
    }
}
function Invoke-RemoteCapture {
    param([string]$Label,[string]$Command,[int]$TimeoutSeconds=60)
    if ($Label -notmatch '^[a-z]+$') { throw 'Invalid remote capture label.' }
    $rundir=$remote+'/runs/'+$runId+'-'+$Label
    # Our paths contain only fixed safe characters. Every capture gets a new directory.
    $mk='test ! -L '+$remote+' && test ! -L '+$remote+'/runs && mkdir -p '+$remote+'/runs && mkdir '+$rundir+' && chmod 700 '+$rundir
    $c=Invoke-AdbCapture -Argv @('-s',$serial,'shell',$mk) -Label ($Label+'-mkdir')
    Require-AdbSuccess $c ($Label+' mkdir')
    # Do not merge stderr with the JSON output; record the *device* process status.
    $wrapped=$Command+' > '+$rundir+'/stdout.txt 2> '+$rundir+'/stderr.txt; p011_rc=$?; printf ''%s\n'' "$p011_rc" > '+$rundir+'/exitcode.txt; exit 0'
    Log-Line ('RUN: '+$Label+' (separate target stdout, stderr and exit code)')
    $c=Invoke-AdbCapture -Argv @('-s',$serial,'shell',$wrapped) -Label ($Label+'-run') -TimeoutSeconds $TimeoutSeconds
    $local=Join-Path $out $Label
    [void](New-Item -ItemType Directory -Path $local -Force)
    $pullsOK=$true
    foreach ($f in @('stdout.txt','stderr.txt','exitcode.txt')) {
        $x=Invoke-AdbCapture -Argv @('-s',$serial,'pull',($rundir+'/'+$f),(Join-Path $local $f)) -Label ($Label+'-pull-'+($f -replace '\.','_'))
        if ($x.TimedOut -or $x.ExitCode -ne 0) { $pullsOK=$false }
    }
    $errPath=Join-Path $local 'stderr.txt'
    $stdPath=Join-Path $local 'stdout.txt'
    $err=''; $std=''
    if (Test-Path -LiteralPath $errPath -PathType Leaf) { $err=[IO.File]::ReadAllText($errPath,$utf8) }
    if (Test-Path -LiteralPath $stdPath -PathType Leaf) { $std=[IO.File]::ReadAllText($stdPath,$utf8) }
    if ($err) { Log-Line ('TARGET_STDERR '+$Label+':'); Log-Line $err.TrimEnd() }
    if ($c.TimedOut -or $c.ExitCode -ne 0) { Require-AdbSuccess $c ($Label+' command') }
    if (-not $pullsOK) { throw ('Could not collect all remote output files for '+$Label+'. Existing files preserved in '+$local) }
    $exitText=[IO.File]::ReadAllText((Join-Path $local 'exitcode.txt'),$utf8).Trim()
    if ($exitText -notmatch '^[0-9]{1,3}$') { throw ('Invalid target exit record for '+$Label+': '+$exitText) }
    $remoteExit=[int]$exitText
    Log-Line ('REMOTE_EXIT: '+$Label+'='+$remoteExit)
    if ($remoteExit -ne 0) {
        if ($std) { Log-Line ('TARGET_STDOUT '+$Label+':'); Log-Line $std.TrimEnd() }
        throw ('Target '+$Label+' failed with exit '+$remoteExit+'. Original error preserved in '+$errPath+'; JSON parsing was NOT attempted.')
    }
    return [PSCustomObject]@{ Stdout=$std; Stderr=$err; RemoteExit=$remoteExit; Folder=$local }
}
function Read-CheckedReport {
    param($Capture,[string]$Schema,[string]$FileName)
    $raw=$Capture.Stdout.Trim()
    if (-not $raw.StartsWith('{')) {
        throw ('Expected JSON object, not target text. Inspect '+(Join-Path $Capture.Folder 'stdout.txt')+' and stderr.txt. Raw files preserved.')
    }
    try { $data=ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
    catch { throw ('Target report is not valid JSON. Original stdout/stderr were saved first. '+$_.Exception.Message) }
    $s=$data.PSObject.Properties['schema']
    if ($null -eq $s -or $s.Value -cne $Schema) { throw ('Unexpected report schema; expected '+$Schema) }
    [IO.File]::WriteAllText((Join-Path $out $FileName),$Capture.Stdout,$utf8)
    return $data
}

try {
    Log-Line 'P011 PlayLab 1.2: live window/renderer geometry + screenshot and touch records.'
    Log-Line ('WORK_ROOT: '+$WorkRoot)
    Log-Line ('PACKAGE: '+$PackageDir)
    Log-Line ('MODE: '+$Mode)
    if ($env:OS -ne 'Windows_NT') { throw 'The deployment launcher is for Windows.' }
    if (-not $AdbPath) {
        $a=Get-Command adb -ErrorAction SilentlyContinue
        if ($null -ne $a) { $AdbPath=$a.Source }
        else { $AdbPath=Join-Path $WorkRoot 'tools\platform-tools\adb.exe' }
    }
    if (-not (Test-Path -LiteralPath $AdbPath -PathType Leaf)) { throw 'adb.exe was not found; keep it on PATH or supply -AdbPath.' }
    $AdbPath=(Resolve-Path -LiteralPath $AdbPath).Path
    foreach ($f in @('p011_lab.py','p011_json.py','p011_preflight.py','p011_display.py','p011_screen.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $PackageDir $f) -PathType Leaf)) { throw ('Missing package file: '+$f+'. Extract the entire new ZIP, not only the launcher.') }
    }
    $c=Invoke-AdbCapture -Argv @('devices') -Label 'adb-devices'
    Require-AdbSuccess $c 'list devices'
    $online=@($c.Stdout -split '[\r\n]+' | ForEach-Object { if ($_ -match '^([^\s]+)\s+device\s*$') { $Matches[1] } })
    if ($online.Count -ne 1) { throw 'Connect exactly one authorized device with state=device.' }
    $serial=$online[0]
    $c=Invoke-AdbCapture -Argv @('-s',$serial,'shell','id -u') -Label 'device-uid'
    Require-AdbSuccess $c 'identity'
    if ($c.Stdout.Trim() -cne '0') { throw 'Expected the already-confirmed root ADB shell.' }
    $c=Invoke-AdbCapture -Argv @('-s',$serial,'shell','cat /etc/os-release') -Label 'device-os'
    Require-AdbSuccess $c 'OS identity'
    if ($c.Stdout -notmatch 'VERSION_ID="z031_v2\.1\.2-20221124_143128-user"') { throw 'Firmware did not match the inspected P011; no script was deployed.' }
    if ($Mode -eq 'Stop') {
        $cap=Invoke-RemoteCapture -Label 'stop' -Command ('/usr/bin/python3 -B -S '+$remote+'/p011_lab.py --stop') -TimeoutSeconds 20
        Log-Line $cap.Stdout.TrimEnd()
        $result='STOP_CHECK_COMPLETED'
    } elseif ($Mode -eq 'Capture') {
        # Ask the running app to capture its own renderer on the render thread.
        # Never create a fake new window and call it a screen capture.
        $cap=Invoke-RemoteCapture -Label 'capture' -Command ('/usr/bin/python3 -B -S '+$remote+'/p011_lab.py --request-shot --request-id '+$runId) -TimeoutSeconds 20
        $shot=Read-CheckedReport $cap 'p011.manualshot.v1.2' 'capture-result.json'
        if ($shot.capture_dir -notmatch '^/tmp/p011-playlab-v12/captures/[0-9-]+$') { throw 'Unexpected live app capture directory.' }
        $visualRemote=$shot.capture_dir
        Log-Line ('APP_CAPTURED: '+$shot.stem)
        $result='APP_CAPTURE_COMPLETED'
    } else {
        $c=Invoke-AdbCapture -Argv @('-s',$serial,'shell',('test ! -L '+$remote+' && mkdir -p '+$remote+' && chmod 700 '+$remote)) -Label 'deploy-mkdir'
        Require-AdbSuccess $c 'create dedicated temporary directory'
        Log-Line ('DEPLOY: '+$remote+' only; no system Python or startup files changed.')
        foreach ($f in @('p011_lab.py','p011_json.py','p011_preflight.py','p011_display.py','p011_screen.py')) {
            $c=Invoke-AdbCapture -Argv @('-s',$serial,'push',(Join-Path $PackageDir $f),($remote+'/'+$f)) -Label ('push-'+($f -replace '\.','_'))
            Require-AdbSuccess $c ('push '+$f)
        }
        if ($Mode -eq 'Screen') {
            $visualRemote=$remote+'/captures/'+$runId
            Log-Line 'SCREEN: read-only /dev/fb0 snapshot. May be stale/black on DRM; active scanout is NOT assumed.'
            Log-Line ('Shots='+$Shots+'; interval='+$Interval+' seconds. No output mode or driver settings are changed.')
            $cmd='/usr/bin/python3 -B -S '+$remote+'/p011_screen.py --output-dir '+$visualRemote+' --shots '+$Shots+' --interval '+$Interval
            $cap=Invoke-RemoteCapture -Label 'screen' -Command $cmd -TimeoutSeconds ($Shots*($Interval+12)+25)
            Log-Line $cap.Stdout.TrimEnd()
            $result='FRAMEBUFFER_READ_SCANOUT_UNVERIFIED'
        } else {
            $cap=Invoke-RemoteCapture -Label 'preflight' -Command ('/usr/bin/python3 -B -S '+$remote+'/p011_preflight.py') -TimeoutSeconds 45
            $pre=Read-CheckedReport $cap 'p011.preflight.v1.1' 'preflight.json'
            Log-Line ('PYTHON: '+($pre.python -split '[\r\n]')[0])
            foreach ($m in @($pre.modules)) {
                if (-not $m.ok) { Log-Line ('MODULE: '+$m.name+'; required='+$m.required+'; '+$m.exception+': '+$m.message) }
            }
            if (-not $pre.ok) { throw ('Required Python dependencies unavailable: '+(@($pre.missing_required) -join ', ')+'. See preflight.json; no GUI was started.') }
            Log-Line 'PREFLIGHT_OK: required imports passed. Standard json is NOT required.'
            $cap=Invoke-RemoteCapture -Label 'inventory' -Command ('/usr/bin/python3 -B -S '+$remote+'/p011_lab.py --inventory') -TimeoutSeconds 75
            $inv=Read-CheckedReport $cap 'p011.inventory.v1.1' 'inventory.json'
            Log-Line ('Kernel: '+$inv.kernel+' / '+$inv.machine)
            Log-Line ('SDL: '+($inv.sdl | ConvertTo-Json -Compress))
            Log-Line ('Wayland: '+($inv.graphics_environment | ConvertTo-Json -Compress))
            Log-Line ('Memory: '+$inv.memory)
            Log-Line 'INVENTORY_OK: report parsed. This does not prove that the graphical demo works.'
            $result='INVENTORY_OK'
            if ($Mode -in @('Demo','Calibrate')) {
                $p=$inv.sdl.PSObject.Properties['compiled_video_drivers']
                if ($null -eq $p -or @($p.Value) -notcontains 'wayland' -or $inv.wayland_selection -ne 'selected') {
                    throw 'Wayland/SDL prerequisites were not confirmed. Keep inventory.json; no demo started.'
                }
                $visualRemote=$remote+'/captures/'+$runId
                $page='home';if ($Mode -eq 'Calibrate') { $page='calibrate' }
                Log-Line ('DEMO: '+$Seconds+' seconds; record every '+$RecordEvery+' seconds plus page/touch/manual captures (bounded).')
                Log-Line 'SCREENSHOT_SOURCE: own renderer before Present + source canvas, not final Weston composition.'
                $cmd='/usr/bin/python3 -B -S '+$remote+'/p011_lab.py --demo --seconds '+$Seconds+' --rotate '+$Rotate+' --fit '+$Fit+' --record-dir '+$visualRemote+' --record-every '+$RecordEvery+' --start-page '+$page
                # Always collect images/geometry in finally, including after a nonzero demo exit.
                $cap=Invoke-RemoteCapture -Label 'demo' -Command $cmd -TimeoutSeconds ($Seconds+60)
                Log-Line $cap.Stdout.TrimEnd()
                $result='DEMO_PROCESS_COMPLETED'
            }
        }
    }
} catch {
    $result='STOPPED'
    $detail=$_.Exception.ToString()+"`r`n"+$_.ScriptStackTrace
    [IO.File]::WriteAllText((Join-Path $out 'launcher-error.txt'),$detail,$utf8)
    Log-Line ('STOP: '+$_.Exception.Message)
} finally {
    if ($visualRemote -and $serial) {
        try {
            $c=Invoke-AdbCapture -Argv @('-s',$serial,'pull',$visualRemote,$visualLocal) -Label 'visual-pull' -TimeoutSeconds 90
            Require-AdbSuccess $c 'collect screenshot records'
            Log-Line ('SCREENSHOTS: '+$visualLocal)
            if (Test-Path -LiteralPath (Join-Path $visualLocal 'index.html')) { Log-Line ('GALLERY: '+(Join-Path $visualLocal 'index.html')) }
            $images=@(Get-ChildItem -LiteralPath $visualLocal -Recurse -Filter '*.png' -File)
            Log-Line ('PNG_FILES: '+$images.Count)
        } catch { Log-Line ('SCREENSHOT_COLLECTION_ERROR: '+$_.Exception.Message) }
    }
    Log-Line ('RESULT: '+$result)
    Log-Line 'No flasher, remount, system package install, camera recording or network listener was requested.'
    # The adb transport capture contains the device serial. Redact it before sharing.
    if ($serial) {
        foreach ($file in @(Get-ChildItem -LiteralPath $out -Filter '*.adb.*.txt' -File)) {
            $text=[IO.File]::ReadAllText($file.FullName,$utf8)
            [IO.File]::WriteAllText($file.FullName,$text.Replace($serial,'<device-serial>'),$utf8)
        }
    }
    $report.Dispose()
    Write-Host ('RESULT_FOLDER: '+$out)
    try {
        Compress-Archive -LiteralPath $out -DestinationPath ($out+'.zip') -CompressionLevel Optimal
        Write-Host ('ZIP: '+$out+'.zip')
    } catch { Write-Host ('ZIP_ERROR: '+$_.Exception.Message) }
}

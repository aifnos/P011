# P011 MenuLab v0.4.3: local candidate build + device-side guarded, temporary trial.
# Windows PowerShell 5.1 / PowerShell 7. No flasher, remount, stock overwrite or
# startup configuration edit. Trial DOES stop/restart the original native app.
[CmdletBinding()]
param(
    [ValidateSet('OneClick','Check','Trial','Stop','Status','Collect')][string]$Mode = 'Check',
    [string]$WorkRoot = 'D:\project\P011',
    [string]$PackageDir = 'D:\project\P011\MenuLab',
    [ValidateRange(60,600)][int]$Seconds = 600,
    [string]$AdbPath = '',
    [string]$RunFolder = '',
    [string]$ClientPublicKeyPath = '',
    [string]$MediaDirectory = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$utf8 = [Text.UTF8Encoding]::new($false)
$sessionName = 'ToolsTest-' + $Mode + '-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
$outDir = $RunFolder
if (-not $outDir) { $outDir = Join-Path $WorkRoot ('logs\' + $sessionName) }
[void][IO.Directory]::CreateDirectory($outDir)
$report = [IO.StreamWriter]::new((Join-Path $outDir 'report.txt'), $false, $utf8)
$report.AutoFlush = $true
$result = 'NOT_STARTED'
$adb = $null
$serial = ''
$remote = ''
$lastFile = Join-Path $WorkRoot 'state\ToolsTest-last-session.json'
$hostState = @{ CallIndex = 0 }
$startAttempted = $false
$phase = 'HOST_SETUP'
$failurePhase = ''
$rootConfirmed = $false
$parserVerified = $false

function Log-Line {
    param([string]$Text)
    Write-Host $Text
    $report.WriteLine(('{0} {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text))
}
function Quote-Argument {
    param([string]$Value)
    # Windows CommandLineToArgvW-compatible quoting, including trailing slashes.
    $b = [Text.StringBuilder]::new()
    [void]$b.Append('"')
    $slashes = 0
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\') { $slashes++; continue }
        if ($c -eq '"') {
            [void]$b.Append(('\' * ($slashes * 2 + 1)))
            [void]$b.Append('"')
        } else {
            [void]$b.Append(('\' * $slashes))
            [void]$b.Append($c)
        }
        $slashes = 0
    }
    [void]$b.Append(('\' * ($slashes * 2)))
    [void]$b.Append('"')
    return $b.ToString()
}
function Adb-Call {
    param([string[]]$Argv, [string]$Tag, [int]$TimeoutSeconds = 25, [switch]$AllowFail)
    $hostState.CallIndex++
    $prefix = Join-Path $outDir ('{0:D3}-{1}' -f $hostState.CallIndex,$Tag)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $adb
    $info.Arguments = (($Argv | ForEach-Object { Quote-Argument $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = $utf8
    $info.StandardErrorEncoding = $utf8
    $p = [Diagnostics.Process]::new()
    $p.StartInfo = $info
    $o=''; $e=''; $code=-998; $timedOut=$false; $started=$false
    $ot=$null; $et=$null
    try {
        if (-not $p.Start()) { throw 'Could not start adb.' }
        $started=$true
        $ot = $p.StandardOutput.ReadToEndAsync()
        $et = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut=$true; $code=-124
            try { $p.Kill(); [void]$p.WaitForExit(3000) } catch { }
        } else { $code=$p.ExitCode }
        # Do not await a broken pipe forever. Preserve whatever completed.
        if ($ot.Wait(2000)) { $o=$ot.Result }
        if ($et.Wait(2000)) { $e=$et.Result }
        if ($timedOut) { $e += "`nADB host timeout at $Tag. Device guardian is independent." }
    } catch {
        $e += "`n" + $_.Exception.ToString()
        if ($code -eq 0) { $code=-998 }
    } finally {
        [IO.File]::WriteAllText($prefix + '-stdout.txt', $o, $utf8)
        [IO.File]::WriteAllText($prefix + '-stderr.txt', $e, $utf8)
        [IO.File]::WriteAllText($prefix + '-exit.txt', [string]$code, $utf8)
        if ($started) { try { if (-not $p.HasExited) { $p.Kill() } } catch { } }
        $p.Dispose()
    }
    if ($code -ne 0 -and -not $AllowFail) {
        throw ('adb failed at '+$Tag+' (exit '+$code+'): '+$e.Trim()+' '+$o.Trim())
    }
    return [PSCustomObject]@{Out=$o;Err=$e;Exit=$code}
}
function Target-Command {
    param([string]$Command,[string]$Tag,[int]$TimeoutSeconds=25,[switch]$AllowFail)
    # One per-call status token; supports old adbd without shell exit propagation.
    $marker = '__P011_REMOTE_EXIT_' + [Guid]::NewGuid().ToString('N') + '__='
    $wrapped = $Command + '; _p011_rc=$?; printf "\n' + $marker + '%s\n" "$_p011_rc"'
    $r = Adb-Call -Argv @('-s',$serial,'shell',$wrapped) -Tag $Tag -TimeoutSeconds $TimeoutSeconds -AllowFail:$AllowFail
    $prefix = Join-Path $outDir ('{0:D3}-{1}' -f $hostState.CallIndex,$Tag)
    $normalized = ConvertTo-P011CanonicalText -Text $r.Out
    [IO.File]::WriteAllText($prefix + '-stdout-normalized.txt',$normalized,$utf8)
    $status=[ordered]@{
        parser_version='0.3.1-eol-fixed'; tag=$Tag; host_exit=$r.Exit; marker=$marker;
        raw_characters=$r.Out.Length; normalized_characters=$normalized.Length;
        raw_cr_count=[regex]::Matches($r.Out,'\r').Count;
        raw_lf_count=[regex]::Matches($r.Out,'\n').Count;
        normalization_changed=($r.Out -cne $normalized);
        marker_verified=$false; remote_exit=$null; error=''
    }
    $parsed=$null
    try {
        # A marker never overrides a failed/timeout host adb process.
        if ($r.Exit -ne 0) { throw ('ADB_TRANSPORT_FAILED: host exit '+$r.Exit) }
        $parsed=Read-P011ExitEnvelope -Text $r.Out -Marker $marker
        $status.marker_verified=$true
        $status.remote_exit=$parsed.Exit
        if ($status.normalization_changed) { Log-Line ('TEXT_EOL_NORMALIZED: '+$Tag+'; raw output preserved.') }
        Log-Line ('REMOTE_EXIT: '+$Tag+'='+$parsed.Exit)
        if ($parsed.Exit -ne 0 -and -not $AllowFail) {
            throw ('Target failed at '+$Tag+' (exit '+$parsed.Exit+'): '+$parsed.Text+' '+$r.Err)
        }
        return [PSCustomObject]@{Text=$parsed.Text;Exit=$parsed.Exit}
    } catch {
        $status.error=$_.Exception.Message
        if ($AllowFail) {
            $failedCode=-999
            if ($r.Exit -ne 0) { $failedCode=$r.Exit }
            return [PSCustomObject]@{Text=$normalized;Exit=$failedCode}
        }
        throw ('Remote status check failed at '+$Tag+': '+$status.error+'. Original output preserved in '+$prefix+'-stdout.txt')
    } finally {
        [IO.File]::WriteAllText($prefix+'-remote-status.json',($status|ConvertTo-Json -Depth 4),$utf8)
    }
}
function Bytes-Hash {
    param([byte[]]$Bytes)
    $h=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
    finally { $h.Dispose() }
}
function Build-Candidate {
    param([string]$Original,[string]$Destination)
    $m=Get-Content -LiteralPath (Join-Path $PackageDir 'patch\manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    [byte[]]$orig=[IO.File]::ReadAllBytes($Original)
    $pinned='e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997'
    if ($m.original_sha256 -cne $pinned -or $m.original_size -ne 4001256 -or $orig.Length -ne 4001256 -or (Bytes-Hash $orig) -cne $pinned) { throw 'Original Z03 is not the pinned firmware.' }
    function Read-BigEndian32([byte[]]$Data, [int]$At) {
        return [long]$Data[$At]*16777216 + [long]$Data[$At+1]*65536 + [long]$Data[$At+2]*256 + [long]$Data[$At+3]
    }
    if ($m.qml_resource -cne '/NaviPanel.qml' -or $m.record_offset -ne 0x1c625c -or $m.original_record_size -ne 1584 -or $m.original_qml_sha256 -cne '68915d92ca6cc084779e106d65e1c62b2e7bb64d735c0676298795d7ce04f42b') { throw 'NaviPanel fixed slot mismatch.' }
    $patches=@(@{Meta=$m; Offset=0x1c625c; Size=1584; Qml='patch\NaviPanel.embedded.qml'; Block='patch\NaviPanel.resource-block.bin'})
    if ($m.PSObject.Properties.Name -contains 'bluetooth_patch') {
        $bt=$m.bluetooth_patch
        if ($null -eq $bt -or $bt.qml_resource -cne '/ZybQmlFiles/ZybSet/SetBtPage.qml' -or $bt.record_offset -ne 0x21e225 -or $bt.original_record_size -ne 3992 -or $bt.original_payload_size -ne 3988 -or $bt.embedded_qml_file -cne 'patch/SetBtPage.embedded.qml' -or $bt.resource_block_file -cne 'patch/SetBtPage.resource-block.bin' -or $bt.original_qml_sha256 -cne '8b37d58f19c686891942c387bf448e16bad13d1d2b560d54609b227747a59901') { throw 'Bluetooth fixed slot/path mismatch.' }
        $patches+=@{Meta=$bt; Offset=0x21e225; Size=3992; Qml='patch\SetBtPage.embedded.qml'; Block='patch\SetBtPage.resource-block.bin'}
    }
    $expectedResources=@('/NaviPanel.qml');if($patches.Count -eq 2){$expectedResources+='/ZybQmlFiles/ZybSet/SetBtPage.qml'}
    if (@($m.changed_resources).Count -ne $patches.Count -or $m.other_resources_unchanged -ne 400-$patches.Count) { throw 'Changed resource count mismatch.' }
    foreach($resource in $expectedResources){if(@($m.changed_resources) -cnotcontains $resource){throw 'Unexpected changed resource list.'}}
    [byte[]]$copy=$orig.Clone()
    $previousEnd=0
    foreach($patch in $patches) {
        $offset=[int]$patch.Offset; $size=[int]$patch.Size
        if ($offset -lt $previousEnd -or $offset+$size -gt $orig.Length) { throw 'Patch ranges overlap or exceed original.' }
        if ((Read-BigEndian32 $orig $offset) -ne $size-4) { throw 'Original resource record size mismatch.' }
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
        [Array]::Copy($block,0,$copy,$offset,$size)
        $previousEnd=$offset+$size
    }
    if ((Bytes-Hash $copy) -cne $m.candidate_sha256) { throw 'Candidate integrity mismatch.' }
    if (Test-Path -LiteralPath $Destination) { throw 'Candidate destination already exists; refusing overwrite.' }
    if ((Get-FileHash -LiteralPath $Original -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pinned) { throw 'Original changed during build.' }
    [IO.File]::WriteAllBytes($Destination,$copy)
    Log-Line ('BUILD_OK: candidate=' + $m.candidate_sha256 + '; original not modified.')
}
function Collect-Logs {
    if (-not $remote) { return }
    [void](Adb-Call -Argv @('-s',$serial,'pull',($remote+'/logs'),(Join-Path $outDir 'device')) -Tag 'collect-logs' -TimeoutSeconds 60 -AllowFail)
}

try {
    Log-Line 'P011 MenuLab v0.4.4: one-click trial with device-side rollback and evidence collection.'
    Log-Line ('WORK_ROOT: ' + $WorkRoot)
    Log-Line ('MODE: ' + $Mode)
    $parserPath=Join-Path $PackageDir 'host\RemoteText.ps1'
    . ([scriptblock]::Create((Get-Content -LiteralPath $parserPath -Raw -Encoding UTF8)))
    $parserTests=@(Test-P011RemoteText)
    [IO.File]::WriteAllText((Join-Path $outDir 'host-parser-selftest.json'),
        (@{scope='actual PowerShell host, offline parser only';cases=$parserTests;device_io=$false}|ConvertTo-Json -Depth 5),$utf8)
    $parserVerified=$true
    Log-Line ('HOST_PARSER_SELFTEST_OK: '+$parserTests.Count+' cases; no device I/O.')
    if ($env:OS -ne 'Windows_NT') { throw 'Use this host launcher on Windows.' }
    if ($AdbPath) { $adb=(Resolve-Path -LiteralPath $AdbPath).Path }
    else { $adb=(Get-Command adb -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    Log-Line ('ADB: '+$adb)
    $phase='ADB_DISCOVERY'
    $deviceWait=[Diagnostics.Stopwatch]::StartNew()
    do {
        $devices=Adb-Call -Argv @('devices') -Tag 'devices'
        $rows=@([regex]::Matches($devices.Out,'(?m)^([^\s]+)\s+(device|unauthorized|offline|recovery|sideload|bootloader|rescue)\b[^\r\n]*') )
        if ($rows.Count -gt 1) { throw 'Multiple ADB devices detected. Unplug all except this P011.' }
        $ids=@([regex]::Matches($devices.Out,'(?m)^([^\s]+)\s+device\s*\r?$') | ForEach-Object {$_.Groups[1].Value})
        if ($ids.Count -eq 1) { break }
        if ($Mode -ne 'OneClick' -or $deviceWait.Elapsed.TotalSeconds -ge 45) {
            throw 'No single online ADB device. Keep P011 ON and connect USB; inspect devices log.'
        }
        Log-Line '等待正常开机的 P011 USB ADB（最多 45 秒）；不进入下载模式。'
        Start-Sleep -Seconds 2
    } while ($true)
    $serial=$ids[0]
    $phase='ROOT_IDENTITY'
    $id=Target-Command -Command 'id -u' -Tag 'identity'
    if ($id.Text.Trim() -ne '0') { throw 'Current adb shell is not root.' }
    $rootConfirmed=$true
    Log-Line 'ROOT_IDENTITY_OK: id -u=0 and remote exit=0 verified.'

    if ($Mode -in @('Stop','Status','Collect')) {
        $phase='SESSION_'+$Mode.ToUpperInvariant()
        if (-not (Test-Path -LiteralPath $lastFile)) { throw 'No last-trial.json was saved. Nothing to stop.' }
        $last=Get-Content -LiteralPath $lastFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($last.serial -cne $serial) { throw 'Connected device differs from the saved trial. Nothing sent.' }
        $remote=$last.remote
        if ($remote -notmatch '^/tmp/p011-menutest-[0-9-]+$') { throw 'Invalid saved device session path.' }
        if ($Mode -eq 'Stop') {
            $r=Target-Command -Command ("python3 -B $remote/menu_trial.py stop") -Tag 'stop' -TimeoutSeconds 40
            Log-Line $r.Text
            $timer=[Diagnostics.Stopwatch]::StartNew()
            while ($timer.Elapsed.TotalSeconds -lt 35) {
                $r=Target-Command -Command ("python3 -B $remote/menu_trial.py status") -Tag 'stop-status'
                if ($r.Text -match 'FINISHED:') { break }
                Start-Sleep -Seconds 1
            }
            Log-Line $r.Text
        } elseif ($Mode -eq 'Status') {
            $r=Target-Command -Command ("python3 -B $remote/menu_trial.py status") -Tag 'status'
            Log-Line $r.Text
        }
        $sshCheck=Join-Path $WorkRoot 'state\ToolsSSH-last-check.json'
        if(Test-Path -LiteralPath $sshCheck) {
            try {
                $sshInfo=Get-Content -LiteralPath $sshCheck -Raw -Encoding UTF8|ConvertFrom-Json
                if($sshInfo.remote_session -ceq $remote){Copy-Item -LiteralPath $sshCheck -Destination (Join-Path $outDir 'ssh-client-collected.json') -Force}
            } catch {Log-Line 'SSH_CLIENT_COLLECT_WARNING: no matching client check'}
        }
        $result=$Mode.ToUpperInvariant() + '_DONE'
        if($Mode -eq 'Stop') {
            if($r.Text -match '(?m)^FINISHED: RESTORED\s*$'){$result='STOP_DONE_STOCK_RESTORED'}
            elseif($r.Text -match '(?m)^FINISHED: RECOVERY_NEEDS_ATTENTION\s*$'){$result='RECOVERY_NEEDS_ATTENTION'}
            else{$result='STOP_REQUESTED_RESTORE_NOT_CONFIRMED'}
        }
    } else {
        foreach($name in @('patch\manifest.json','patch\NaviPanel.resource-block.bin','runtime\menu_trial.py','runtime\menu_policy.py','runtime\p011_json.py')) {
            if (-not (Test-Path -LiteralPath (Join-Path $PackageDir $name) -PathType Leaf)) { throw ('Package missing: '+$name+'. Extract the complete one-click v0.4.4 ZIP.') }
        }
        $phase='BUILD_CANDIDATE'
        $stage=Join-Path $outDir 'staging'
        [void][IO.Directory]::CreateDirectory($stage)
        $pulled=Join-Path $outDir 'Z03.original'
        [void](Adb-Call -Argv @('-s',$serial,'pull','/usr/bin/Z03',$pulled) -Tag 'pull-original' -TimeoutSeconds 60)
        $origHash=(Get-FileHash -LiteralPath $pulled -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($origHash -cne 'e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997') { throw 'Device program differs from analysed original; no trial.' }
        $saved=Join-Path $WorkRoot 'backups\Z03'
        [void][IO.Directory]::CreateDirectory((Split-Path $saved))
        if (-not (Test-Path -LiteralPath $saved)) { Copy-Item -LiteralPath $pulled -Destination $saved }
        elseif ((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash.ToLowerInvariant() -cne $origHash) {
            throw 'Existing backups\Z03 is different; refusing to overwrite it.'
        }
        Build-Candidate -Original $pulled -Destination (Join-Path $stage 'Z03')
        foreach($n in @('menu_trial.py','menu_policy.py','p011_json.py','tools_metrics.py','tools_services.py','tools_bridge.py')) {
            Copy-Item -LiteralPath (Join-Path $PackageDir ('runtime\'+$n)) -Destination (Join-Path $stage $n)
        }
        Copy-Item -LiteralPath (Join-Path $PackageDir 'examples\device') -Destination (Join-Path $stage 'pages') -Recurse
        # RUNTIME_TOOLS_DEPLOY: explicit list independent of the original runtime list.
        foreach($toolModule in @('tools_metrics.py','tools_services.py','tools_bridge.py','tools_bluetooth.py')) {
            Copy-Item -LiteralPath (Join-Path $PackageDir ('runtime\'+$toolModule)) -Destination (Join-Path $stage $toolModule) -Force
        }


        if($ClientPublicKeyPath -and (Test-Path -LiteralPath $ClientPublicKeyPath -PathType Leaf)) {
            $pub=(Get-Content -LiteralPath $ClientPublicKeyPath -Raw).Trim()
            if($pub -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+=*(?: [^\r\n]*)?$'){throw 'Invalid client public key; no private key accepted.'}
            [IO.File]::WriteAllText((Join-Path $stage 'client.pub'),$pub+"`n",[Text.Encoding]::ASCII)
        }
        $mediaOut=Join-Path $stage 'media';[void][IO.Directory]::CreateDirectory($mediaOut)
        $mediaManifest=@();[int64]$mediaBytes=0
        if($MediaDirectory -and (Test-Path -LiteralPath $MediaDirectory -PathType Container)) {
            foreach($m in @(Get-ChildItem -LiteralPath $MediaDirectory -File | Sort-Object Name)) {
                if($m.Extension.ToLowerInvariant() -notin @('.mp3','.mp4','.wav','.flac','.ogg','.m4a','.aac','.opus','.mkv','.webm','.mov','.m4v','.avi')){continue}
                if(($m.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){continue}
                if($m.Length -gt 16777216 -or ($mediaBytes+$m.Length) -gt 33554432){Log-Line ('MEDIA_SKIPPED_SIZE: '+$m.Name+' (16 MiB/file, 32 MiB/session)');continue}
                Copy-Item -LiteralPath $m.FullName -Destination (Join-Path $mediaOut $m.Name)
                $mediaBytes+=$m.Length
                $mediaManifest+=@{name=$m.Name;bytes=$m.Length;sha256=(Get-FileHash -LiteralPath $m.FullName -Algorithm SHA256).Hash}
            }
        }
        [IO.File]::WriteAllText((Join-Path $outDir 'media-manifest.json'),(ConvertTo-Json -InputObject $mediaManifest -Depth 4),$utf8)
        Log-Line ('MEDIA_READY: '+$mediaManifest.Count+' files; '+$mediaBytes+' bytes. No autoplay.')

        $remote='/tmp/p011-menutest-' + (Get-Date -Format 'yyyyMMdd-HHmmssfff')
        $phase='DEPLOY_TEMP_FILES'
        Log-Line ('DEPLOY: ' + $remote + '; stock executable and startup files are NOT overwritten.')
        [void](Adb-Call -Argv @('-s',$serial,'push',$stage,$remote) -Tag 'push-trial' -TimeoutSeconds 60)
        [void](Target-Command -Command ("chmod 700 $remote $remote/pages $remote/Z03 && test -f $remote/menu_trial.py") -Tag 'prepare')
        $phase='DEVICE_PREFLIGHT'
        $check=Target-Command -Command ("python3 -B $remote/menu_trial.py inspect") -Tag 'preflight' -TimeoutSeconds 40
        Log-Line $check.Text
        $result='CHECK_OK'
        [IO.File]::WriteAllText((Join-Path $outDir 'session.json'),(@{serial=$serial;remote=$remote;host_result=$outDir;seconds=$Seconds} | ConvertTo-Json),$utf8)
        if ($Mode -in @('Trial','OneClick')) {
            Log-Line ('Trial: original GUI exits, candidate copy runs up to '+$Seconds+'s, then stock GUI is restarted.')
            Log-Line 'Return to the HOME page. Finish calls/recording/scanning; no upgrade, factory reset, reboot or power-off during trial.'
            Log-Line 'Native app still uses real services/data. This is not a data sandbox. Screens may briefly go black.'
            if ($Mode -eq 'OneClick') {
                Log-Line '检查通过。8 秒后临时切换原厂界面；按 Esc 取消。无需输入确认词。'
                for ($i=8; $i -ge 1; $i--) {
                    Write-Host ("  倒计时 {0} 秒..." -f $i)
                    $t=[Diagnostics.Stopwatch]::StartNew()
                    while ($t.ElapsedMilliseconds -lt 1000) {
                        $cancel=$false
                        try {
                            if ([Console]::KeyAvailable) { $cancel=([Console]::ReadKey($true).Key -eq [ConsoleKey]::Escape) }
                        } catch { }
                        if ($cancel) { throw 'USER_CANCELLED_BEFORE_SWITCH: original GUI was not stopped.' }
                        Start-Sleep -Milliseconds 50
                    }
                }
            } elseif ((Read-Host 'Type TESTMENU to allow the temporary GUI switch') -cne 'TESTMENU') {
                throw 'Not confirmed; original process left running.'
            }
            [void][IO.Directory]::CreateDirectory((Split-Path $lastFile))
            @{serial=$serial;remote=$remote;host_result=$outDir;seconds=$Seconds} | ConvertTo-Json | Set-Content -LiteralPath $lastFile -Encoding UTF8
            $phase='TRIAL_START'
            $startAttempted=$true
            $result='TRIAL_START_REQUESTED'
            $r=Target-Command -Command ("python3 -B $remote/menu_trial.py start $Seconds") -Tag 'start' -TimeoutSeconds 25
            Log-Line $r.Text
            $phase='TRIAL_MONITOR'
            $result='TRIAL_ACTIVE_AWAITING_RESTORE'
            $timer=[Diagnostics.Stopwatch]::StartNew()
            $prev='';$finished=$false; $guided=$false; $trialClock=$null
            while($timer.Elapsed.TotalSeconds -lt ($Seconds+150)) {
                try {
                    $r=Target-Command -Command ("python3 -B $remote/menu_trial.py status") -Tag 'poll' -TimeoutSeconds 8
                    if($r.Text -ne $prev) { Log-Line $r.Text; $prev=$r.Text }
                    if (-not $guided -and $r.Text -match 'CANDIDATE_RUNNING') {
                        $guided=$true; $trialClock=[Diagnostics.Stopwatch]::StartNew()
                        Log-Line '请在笔上操作：主菜单滑到最右 → 工具箱 → ADB / 电池 / 无线电 / 浏览器 / 影音 / SSH；点击需要测试的页面。'
                        Log-Line '工具箱页会尝试记录页面 PNG 和点击日志；时间到后自动恢复原厂界面。'
                    }
                    if ($guided -and $null -ne $trialClock) {
                        $left=[Math]::Max(0,$Seconds-[int]$trialClock.Elapsed.TotalSeconds)
                        Write-Progress -Activity 'P011 原厂菜单限时测试' -Status ("剩余约 {0} 秒；请在笔上点击测试，电脑自动记录" -f $left) -PercentComplete ([Math]::Min(100,100*($Seconds-$left)/$Seconds))
                    }
                    if($r.Text -match '(?m)^FINISHED: (RESTORED|RECOVERY_NEEDS_ATTENTION)\s*$') {
                        $finished=$true
                        $result='RECOVERY_NEEDS_ATTENTION'
                        if($r.Text -match '(?m)^FINISHED: RESTORED\s*$') { $result='TRIAL_FINISHED_STOCK_RESTORED' }
                        break
                    }
                } catch {
                    Log-Line ('ADB_STATUS_WARNING: '+$_.Exception.Message+' Guardian timeout remains device-side.')
                }
                Start-Sleep -Seconds 1
            }
            if(-not $finished) {
                $result='HOST_WAIT_ENDED_CHECK_DEVICE'
                Log-Line 'Host wait ended. Use -Mode Stop after reconnecting ADB. Do not overwrite files or repeat Trial blindly.'
            }
        }
    }
} catch {
    $failurePhase=$phase
    $result='STOPPED: '+$result
    Log-Line ('FAILURE_PHASE: '+$failurePhase)
    Log-Line ('ERROR: '+$_.Exception.Message)
    if($startAttempted) { Log-Line 'A device guardian may still be running. Use -Mode Stop; do not kill Z03/Weston by name.' }
} finally {
    # Do not label an interrupted/premature host monitor as CHECK_OK.
    if($Mode -in @('OneClick','Trial') -and $startAttempted -and $result -notin @('TRIAL_FINISHED_STOCK_RESTORED','RECOVERY_NEEDS_ATTENTION')) {
        Log-Line 'HOST_MONITOR_ENDED_WITHOUT_RESTORE: request bounded stop; no repeated trial.'
        $result='HOST_MONITOR_ENDED_RESTORE_NOT_CONFIRMED'
        try {
            $null=Target-Command -Command ("python3 -B $remote/menu_trial.py stop") -Tag 'finally-stop' -TimeoutSeconds 35
            $endWait=[Diagnostics.Stopwatch]::StartNew()
            while($endWait.Elapsed.TotalSeconds -lt 75) {
                $endStatus=Target-Command -Command ("python3 -B $remote/menu_trial.py status") -Tag 'finally-status' -TimeoutSeconds 15
                if($endStatus.Text -match '(?m)^FINISHED: RESTORED\s*$'){$result='TRIAL_FINISHED_STOCK_RESTORED';break}
                if($endStatus.Text -match '(?m)^FINISHED: RECOVERY_NEEDS_ATTENTION\s*$'){$result='RECOVERY_NEEDS_ATTENTION';break}
                Start-Sleep -Seconds 1
            }
        } catch {Log-Line ('BOUNDED_STOP_WARNING: '+$_.Exception.Message+'; device guardian remains the fallback.')}
    }
    if($remote) {
        try { Collect-Logs } catch { Log-Line ('COLLECT_WARNING: '+$_.Exception.Message) }
    }
    Log-Line ('RESULT: '+$result)
    Log-Line 'This validates process rollback only; report actual menu/page behavior separately.'
    Log-Line 'Native logs may contain device/account identifiers. Review before sharing.'
    $report.Dispose()
    Write-Progress -Activity 'P011 原厂菜单限时测试' -Completed
    $engineResult=[ordered]@{
        result=$result; mode=$Mode; seconds=$Seconds;
        folder=$outDir; remote_session=$remote;
        start_attempted=$startAttempted; failure_phase=$failurePhase;
        root_identity_confirmed=$rootConfirmed; host_parser_selftest_passed=$parserVerified;
        note='Process and file checks do not automatically verify visual or touch correctness.'
    }
    [IO.File]::WriteAllText((Join-Path $outDir 'engine-result.json'),($engineResult | ConvertTo-Json -Depth 5),$utf8)
    Write-Host ('RESULT_FOLDER: '+$outDir)
}
[PSCustomObject]$engineResult

# P011 wireless incident collector. No candidate launch or radio state changes.
[CmdletBinding()]
param(
    [ValidateSet('current','after-reboot')][string]$Tag = 'current',
    [string]$WorkRoot = 'D:\project\P011',
    [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$utf8 = [Text.UTF8Encoding]::new($false)
$package = $PSScriptRoot
. (Join-Path $package 'RemoteText.ps1')
$testRows = @(Test-P011RemoteText)

function Initialize-P011Compression {
    foreach($assembly in @('System.IO.Compression','System.IO.Compression.FileSystem','System.IO.Compression.ZipFile')) {
        try { Add-Type -AssemblyName $assembly -ErrorAction Stop } catch { }
    }
    if (-not ('System.IO.Compression.ZipFile' -as [type]) -or
        -not ('System.IO.Compression.CompressionLevel' -as [type])) {
        throw 'Cannot load .NET ZIP support. No ADB operation has been performed.'
    }
}
function Save-P011Zip {
    param([string]$Folder,[string]$ZipPath)
    Initialize-P011Compression
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $Folder,$ZipPath,[System.IO.Compression.CompressionLevel]::Optimal,$false)
    $z = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try { if ($z.Entries.Count -eq 0) {throw 'Generated ZIP is empty.'} }
    finally {$z.Dispose()}
}
Initialize-P011Compression
if($SelfTest) {
    $t = Join-Path ([IO.Path]::GetTempPath()) ('p011-radio-selftest-'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($t)
    try {
        [IO.File]::WriteAllText((Join-Path $t 'test.txt'),'host test',$utf8)
        Save-P011Zip $t ($t+'.zip')
        Write-Output ('HOST_SELFTEST_PASS: '+$testRows.Count+' remote-text cases plus .NET ZIP. No ADB.')
    } finally {
        Remove-Item -LiteralPath $t -Recurse -Force
        if(Test-Path -LiteralPath ($t+'.zip')) {Remove-Item -LiteralPath ($t+'.zip') -Force}
    }
    return
}
if($env:OS -ne 'Windows_NT'){throw 'This one-click launcher requires Windows.'}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmssfff'
$outDir = Join-Path $WorkRoot ('logs\RadioCheck-'+$Tag+'-'+$stamp)
$resultDir = Join-Path $WorkRoot 'results'
[void][IO.Directory]::CreateDirectory($outDir)
[void][IO.Directory]::CreateDirectory($resultDir)
$report = [IO.StreamWriter]::new((Join-Path $outDir 'report.txt'),$false,$utf8)
$report.AutoFlush=$true
$hostState=@{CallIndex=0}
$adb='';$serial='';$remote='';$result='NOT_STARTED';$deployed=$false
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

function Read-P011JsonFile {
    param([string]$Name)
    $p = Join-Path $outDir ('device\'+$Name)
    if(-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        $found = @(Get-ChildItem -LiteralPath (Join-Path $outDir 'device') -Filter $Name -File -Recurse -ErrorAction SilentlyContinue)
        if($found.Count -ne 1){return $null}
        $p=$found[0].FullName
    }
    try {return (Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json)}
    catch {return $null}
}
function Get-P011Property {
    param($Object,[string]$Name)
    if($null -eq $Object){return $null}
    $p=$Object.PSObject.Properties[$Name]
    if($null -eq $p){return $null}
    return $p.Value
}
try {
    Log-Line 'P011 Wi-Fi / Bluetooth 只读诊断 v1.0'
    Log-Line ('标签：'+$Tag+'；工作目录：'+$WorkRoot)
    Log-Line '不启动工具箱候选，不结束系统进程，不开关无线电，不刷写、不重启。'
    Log-Line '采集阶段请暂时不要操作设备。系统日志可能带有设备标识，分享前检查。'
    Log-Line ('HOST_PARSER_SELFTEST_OK: '+$testRows.Count)
    $manifest=Get-Content -LiteralPath (Join-Path $package 'runtime-hashes.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach($entry in $manifest){
        $p=Join-Path $package ('runtime\'+$entry.file)
        if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){
            throw ('Package runtime hash mismatch: '+$entry.file)
        }
    }
    $command=Get-Command adb.exe -ErrorAction SilentlyContinue
    if($null -ne $command){$adb=$command.Source}
    foreach($candidate in @('C:\Program Files\ADB\adb.exe',(Join-Path $WorkRoot 'tools\platform-tools\adb.exe'),(Join-Path $WorkRoot 'platform-tools\adb.exe'))) {
        if(-not $adb -and (Test-Path -LiteralPath $candidate -PathType Leaf)){$adb=$candidate}
    }
    if(-not $adb){throw '没有找到 adb.exe。请保留现有 ADB 安装，诊断包不下载新驱动。'}
    Log-Line ('ADB: '+$adb)
    $r=Adb-Call -Argv @('devices') -Tag 'devices'
    $lines=@((ConvertTo-P011CanonicalText $r.Out) -split "`n" | Where-Object {$_ -match '^\S+\s+(device|offline|unauthorized)(?:\s|$)'})
    if($lines.Count -ne 1 -or $lines[0] -notmatch '^(\S+)\s+device\s*$'){
        throw '需要且只允许一台已授权的 ADB 设备。不要启动下载模式或重新运行旧测试。'
    }
    $serial=$Matches[1]
    $r=Target-Command -Command 'id -u' -Tag 'root'
    if($r.Text.Trim() -ne '0'){throw '当前 ADB shell 不是 root，无法完整检查系统服务。'}
    $remote='/tmp/p011-radio-check-'+$stamp
    $null=Target-Command -Command ('umask 077; mkdir '+$remote) -Tag 'prepare'
    $deployed=$true
    foreach($name in @('radio_check.py','p011_json.py')){
        $null=Adb-Call -Argv @('-s',$serial,'push',(Join-Path $package ('runtime\'+$name)),($remote+'/'+$name)) -Tag ('push-'+$name)
    }
    Log-Line 'READING: 服务归属、进程、RFKill、网卡、蓝牙适配器、启动文件和崩溃线索。通常约 20～60 秒，单阶段有超时上限。'
    $r=Target-Command -Command ('python3 -B '+$remote+'/radio_check.py') -Tag 'collect' -TimeoutSeconds 125 -AllowFail
    Log-Line $r.Text
    $result='COLLECTOR_EXIT_'+$r.Exit
} catch {
    $result='CHECK_FAILED'
    Log-Line ('ERROR: '+$_.Exception.Message)
} finally {
    if($deployed){
        try {
            $null=Adb-Call -Argv @('-s',$serial,'pull',($remote+'/result'),(Join-Path $outDir 'device')) -Tag 'pull-result' -TimeoutSeconds 30
        } catch {Log-Line ('PULL_WARNING: '+$_.Exception.Message)}
    }
    try {
        $collector=Read-P011JsonFile 'collector.json'
        if($null -ne $collector){$result='READ_ONLY_'+[string](Get-P011Property $collector 'result')}
        $lines=[Collections.Generic.List[string]]::new()
        [void]$lines.Add('P011 Wi-Fi / 蓝牙只读诊断摘要')
        [void]$lines.Add('采集标签：'+$Tag+'；结果：'+$result)
        [void]$lines.Add('这是快照，不是无线连接成功验收，也没有执行修复。')
        foreach($name in @('bus_before.json','bus_after.json')) {
            $bus=Read-P011JsonFile $name
            if($null -eq $bus){continue}
            [void]$lines.Add('')
            [void]$lines.Add('['+$name+']')
            $services=Get-P011Property $bus 'services'
            foreach($service in @('net.connman','org.bluez','fi.w1.wpa_supplicant1','org.ofono')){
                $entry=Get-P011Property $services $service
                if($null -ne $entry) {
                    [void]$lines.Add($service+'：has_owner='+[string](Get-P011Property $entry 'has_owner')+' PID='+[string](Get-P011Property $entry 'pid')+' error='+[string](Get-P011Property $entry 'error'))
                }
            }
            $q=Get-P011Property $bus 'queries'
            foreach($a in @(Get-P011Property $q 'bluez.adapters')) {
                if($null -eq $a){continue}
                $p=Get-P011Property $a 'properties'
                [void]$lines.Add('蓝牙 '+[string](Get-P011Property $a 'path')+'：Powered='+[string](Get-P011Property $p 'Powered')+' Discovering='+[string](Get-P011Property $p 'Discovering')+' Discoverable='+[string](Get-P011Property $p 'Discoverable'))
            }
        }
        $f=Read-P011JsonFile 'files.json'
        foreach($b in @(Get-P011Property $f 'binaries')) {
            if($null -eq $b){continue}
            $matched=Get-P011Property $b 'matches_original_backup'
            if($null -ne $matched){[void]$lines.Add('原厂哈希匹配：'+[string](Get-P011Property $b 'path')+' = '+[string]$matched)}
        }
        [void]$lines.Add('')
        [void]$lines.Add('保留本包后，可按设备正常方式重启一次；不要恢复出厂。重启后仅复查原厂 Wi-Fi / 蓝牙，不再启动 v0.4.x 工具箱。')
        [void]$lines.Add('若问题仍在，可双击 AFTER-REBOOT.cmd 另存第二份诊断。请上传两份 ZIP，并注明是否另用刷机工具写过分区。')
        $summary=$lines -join "`r`n"
        [IO.File]::WriteAllText((Join-Path $outDir 'summary.txt'),$summary,$utf8)
        Log-Line $summary
    } catch {Log-Line ('SUMMARY_WARNING: '+$_.Exception.Message)}
    Log-Line ('RESULT: '+$result)
    Log-Line '没有请求修改无线配置或启停系统服务；临时诊断文件保留，不删除既有数据。'
    Log-Line ('RESULT_FOLDER: '+$outDir)
    $report.Dispose()
    try {
        $hashes=@(Get-ChildItem -LiteralPath $outDir -File -Recurse | ForEach-Object {
            [PSCustomObject]@{path=$_.FullName.Substring($outDir.Length+1).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
        })
        [IO.File]::WriteAllText((Join-Path $outDir 'manifest.json'),($hashes|ConvertTo-Json -Depth 4),$utf8)
        $zip=Join-Path $resultDir ('P011-RadioCheck-'+$Tag+'-'+$stamp+'.zip')
        Save-P011Zip $outDir $zip
        Write-Host ('ZIP: '+$zip)
        try{Start-Process explorer.exe -ArgumentList ('/select,"'+$zip+'"')}catch{}
    } catch {
        Write-Host ('ZIP_ERROR: '+$_.Exception.Message)
        Write-Host ('请保留并压缩原始日志目录：'+$outDir)
    }
}

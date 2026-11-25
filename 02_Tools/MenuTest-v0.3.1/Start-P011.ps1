# P011 MenuTest v0.3.1 one-click host entry. Local files only; no downloads.
[CmdletBinding()]
param([ValidateSet('Run','Stop','Collect')][string]$Action='Run')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$WorkRoot='D:\project\P011'
$SourceRoot=$PSScriptRoot
$runName='MenuTest-'+$Action+'-'+(Get-Date -Format 'yyyyMMdd-HHmmssfff')
$runFolder=Join-Path $WorkRoot ('logs\'+$runName)
$bootstrapError=''
$exitStatus=0
$engineObject=$null
$mutex=$null
$ownsMutex=$false
$utf8=[Text.UTF8Encoding]::new($false)
try { [Console]::OutputEncoding=$utf8 } catch { }

function Bootstrap-Log {
    param([string]$Text)
    Write-Host $Text
    [IO.File]::AppendAllText((Join-Path $runFolder 'bootstrap.log'),(Get-Date -Format 'HH:mm:ss.fff')+' '+$Text+"`r`n",$utf8)
}
function Verify-PackageFiles {
    param([string]$Root,$Manifest)
    $prefix=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    foreach($entry in $Manifest.files) {
        if ($entry.path -match '(^|[/\\])\.\.([/\\]|$)' -or [IO.Path]::IsPathRooted($entry.path)) { throw 'Invalid package manifest path.' }
        $f=[IO.Path]::GetFullPath((Join-Path $Root $entry.path))
        if (-not $f.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Package file escaped its root.' }
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw ('安装包不完整，缺少：'+$entry.path+'。请完整解压 ZIP。') }
        if ((Get-Item -LiteralPath $f).Length -ne $entry.bytes -or
            (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256) {
            throw ('安装包文件校验失败：'+$entry.path+'。未执行测试。')
        }
    }
}
function Find-Adb {
    $found=@()
    foreach($name in @('adb.exe','adb')) {
        $c=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if($null -ne $c){ $found+=$c.Source }
    }
    foreach($relative in @('platform-tools\adb.exe','tools\platform-tools\adb.exe','tools\adb\adb.exe')) { $found+=Join-Path $WorkRoot $relative }
    if($env:LOCALAPPDATA){$found+=Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'}
    if($env:USERPROFILE){$found+=Join-Path $env:USERPROFILE 'Downloads\platform-tools\adb.exe'}
    foreach($f in $found) { if($f -and (Test-Path -LiteralPath $f -PathType Leaf)) { return (Resolve-Path -LiteralPath $f).Path } }
    throw '没有找到 adb.exe。请将已有 platform-tools 文件夹放到 D:\project\P011\tools\platform-tools，或将 adb 加入 PATH。无需重装设备驱动。'
}

try {
    [void][IO.Directory]::CreateDirectory($runFolder)
    Bootstrap-Log '===================================================='
    Bootstrap-Log ' P011 原厂菜单一键测试 v0.3.1'
    Bootstrap-Log ' 自动检查 → 临时候选 → 180 秒体验 → 恢复 → 打包结果'
    Bootstrap-Log '===================================================='
    Bootstrap-Log ('工作目录：'+$WorkRoot)
    Bootstrap-Log ('操作：'+$Action)
    Bootstrap-Log '只连接这支 P011；正常开机，回到主页；关闭 PlayLab。'
    Bootstrap-Log '本测试会短暂退出并重启原厂界面，不永久安装菜单，也不覆盖原厂文件。'
    Bootstrap-Log '请先结束通话、录音和扫描；测试期间不要升级、恢复出厂或关闭 ADB。'
    Bootstrap-Log '日志及工具箱截图只保存到电脑，不自动上传。'
    if($env:OS -ne 'Windows_NT'){throw '双击入口要求 Windows。'}
    if($Action -eq 'Run') {
        $mutex=[Threading.Mutex]::new($false,'Local\P011_MenuTest_OneClick_Run')
        try { $ownsMutex=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex=$true }
        if(-not $ownsMutex){throw '已有一键测试窗口在运行。不要重复启动；需要提前结束请双击 STOP.cmd。'}
    }
    $manifestPath=Join-Path $SourceRoot 'package-manifest.json'
    if(-not (Test-Path -LiteralPath $manifestPath)){throw '请完整解压压缩包后运行 START.cmd，不要只复制一个文件。'}
    $manifest=Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if($manifest.version -cne '0.3.1' -or @($manifest.files).Count -lt 10){throw '安装包版本或清单无效。'}
    Verify-PackageFiles -Root $SourceRoot -Manifest $manifest
    $stamp=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.Substring(0,12).ToLowerInvariant()
    $installed=Join-Path $WorkRoot ('packages\MenuTest-v0.3.1-'+$stamp)
    if(-not (Test-Path -LiteralPath $installed)) {
        [void][IO.Directory]::CreateDirectory($installed)
        foreach($entry in $manifest.files) {
            $to=Join-Path $installed $entry.path
            [void][IO.Directory]::CreateDirectory((Split-Path $to))
            [IO.File]::Copy((Join-Path $SourceRoot $entry.path),$to,$false)
        }
        [IO.File]::Copy($manifestPath,(Join-Path $installed 'package-manifest.json'),$false)
    }
    Verify-PackageFiles -Root $installed -Manifest $manifest
    Bootstrap-Log ('运行副本：'+$installed+'（不覆盖已有 MenuLab/PlayLab）')
    $adb=Find-Adb
    Bootstrap-Log ('ADB：'+$adb)
    [IO.File]::WriteAllText((Join-Path $runFolder 'host.json'),(@{
        action=$Action; powershell=$PSVersionTable.PSVersion.ToString();
        work_root=$WorkRoot; package_version='0.3.1'; package_manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash;
        os_version=[Environment]::OSVersion.VersionString; adb_path=$adb
    } | ConvertTo-Json -Depth 4),$utf8)
    $mode='OneClick'
    if($Action -ne 'Run'){ $mode=$Action }
    $enginePath=Join-Path $installed 'MenuLab\P011-MenuTest.ps1'
    $engine=[scriptblock]::Create((Get-Content -LiteralPath $enginePath -Raw -Encoding UTF8))
    $returned=@(& $engine -Mode $mode -WorkRoot $WorkRoot -PackageDir (Join-Path $installed 'MenuLab') -Seconds 180 -AdbPath $adb -RunFolder $runFolder)
    if($returned.Count -gt 0){$engineObject=$returned[-1]}
    Bootstrap-Log '测试流程已结束，正在汇总实际日志和页面记录。'
} catch {
    $bootstrapError=$_.Exception.Message
    $exitStatus=1
    try {
        [void][IO.Directory]::CreateDirectory($runFolder)
        Bootstrap-Log ('停止：'+$bootstrapError)
        [IO.File]::WriteAllText((Join-Path $runFolder 'bootstrap-error.txt'),($_ | Out-String),$utf8)
    } catch { Write-Host ('不能写入工作目录：'+$runFolder+'；请保留此窗口错误。') }
} finally {
    try {
        # Result tools are part of this local bundle; no remote commands here.
        $resultTools=Join-Path $SourceRoot 'Host\ResultTools.ps1'
        $summaryBlock=[scriptblock]::Create((Get-Content -LiteralPath $resultTools -Raw -Encoding UTF8))
        . $summaryBlock
        $result=New-P011Result -RunFolder $runFolder -WorkRoot $WorkRoot -Action $Action -BootstrapError $bootstrapError
        Write-Host ''
        Write-Host '===================== 完成 ========================='
        Write-Host ('流程结果：'+$result.Summary.engine_result)
        Write-Host ('原厂进程恢复：'+$result.Summary.restoration)
        Write-Host ('可用截图：'+$result.Summary.screenshot_png_count)
        Write-Host '需要上传给我的文件：'
        Write-Host $result.Zip -ForegroundColor Cyan
        Write-Host ('查看报告：'+$result.ReportHtml)
        Write-Host '请先检查日志中的设备/账号信息；程序没有自动上传任何文件。'
        if($result.Summary.restoration -eq 'RECOVERY_NEEDS_ATTENTION') {
            $exitStatus=2
            Write-Host '恢复未确认：保持 ADB，双击 STOP.cmd。完全无响应时正常重启，不要格式化。' -ForegroundColor Yellow
        }
        if($result.Summary.engine_result -match 'STOPPED|ATTENTION|WAIT_ENDED'){ $exitStatus=1 }
        if($result.Summary.candidate_running_marker_seen -and $result.Summary.restoration -ne 'STOCK_PROCESS_RESTORED') {
            $exitStatus=2
            Write-Host '候选已运行，但未取得恢复确认。保持连接，优先运行 STOP.cmd 或 COLLECT.cmd，不要盲目再次 START。' -ForegroundColor Yellow
        }
        if($env:OS -eq 'Windows_NT') {
            try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"'+$result.Zip+'"') | Out-Null } catch { }
        }
    } catch {
        $exitStatus=1
        Write-Host ('结果打包异常：'+$_.Exception.Message)
        Write-Host ('原始日志仍保留在：'+$runFolder)
        try { [IO.File]::WriteAllText((Join-Path $runFolder 'packaging-error.txt'),($_ | Out-String),$utf8) } catch { }
    }
    if($ownsMutex -and $null -ne $mutex){try{$mutex.ReleaseMutex()}catch{}}
    if($null -ne $mutex){$mutex.Dispose()}
}
exit $exitStatus

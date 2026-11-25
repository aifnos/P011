# Local-only result packing. Does not call adb or modify a device.
Set-StrictMode -Version 2.0
function Read-P011Text {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        return [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8)
    }
    return ''
}
function New-P011Result {
    param([string]$RunFolder,[string]$WorkRoot,[string]$Action,[string]$BootstrapError='')
    $utf8=[Text.UTF8Encoding]::new($false)
    $enginePath=Join-Path $RunFolder 'engine-result.json'
    $engineResult='BOOTSTRAP_STOPPED'
    $engine=$null
    $explicitNoStart=$false
    $failurePhase=''
    $rootConfirmed=$null
    if (Test-Path -LiteralPath $enginePath) {
        try {
            $engine=Read-P011Text $enginePath | ConvertFrom-Json
            $engineResult=$engine.result
            if ($null -ne $engine.PSObject.Properties['start_attempted'] -and $engine.start_attempted -is [bool]) {
                $explicitNoStart=($engine.start_attempted -eq $false)
            }
            if ($null -ne $engine.PSObject.Properties['failure_phase']) { $failurePhase=$engine.failure_phase }
            if ($null -ne $engine.PSObject.Properties['root_identity_confirmed']) { $rootConfirmed=$engine.root_identity_confirmed }
        } catch { }

    }
    $deviceDir=Join-Path $RunFolder 'device'
    $deviceFiles=@()
    if (Test-Path -LiteralPath $deviceDir) { $deviceFiles=@(Get-ChildItem -LiteralPath $deviceDir -Recurse -File) }
    $trialFiles=@($deviceFiles | Where-Object {$_.Name -eq 'trial.log'})
    $candidateFiles=@($deviceFiles | Where-Object {$_.Name -eq 'candidate.log'})
    $trial=($trialFiles | ForEach-Object { Read-P011Text $_.FullName }) -join "`n"
    $candidate=($candidateFiles | ForEach-Object { Read-P011Text $_.FullName }) -join "`n"
    $report=Read-P011Text (Join-Path $RunFolder 'report.txt')
    $finishedFiles=@($deviceFiles | Where-Object {$_.Name -eq 'finished'})
    $finished=($finishedFiles | ForEach-Object { (Read-P011Text $_.FullName).Trim() }) -join ','
    $launched=($trial -match '\bCANDIDATE_RUNNING:')
    $checked=(($report+' '+$trial) -match '\bCHECK_OK:')
    $restore='UNCONFIRMED'
    if ($finished -ceq 'RESTORED' -and $trial -match '\bRESTORED_STOCK_PROCESS:') { $restore='STOCK_PROCESS_RESTORED' }
    elseif ($finished -match 'RECOVERY_NEEDS_ATTENTION') { $restore='RECOVERY_NEEDS_ATTENTION' }
    elseif ($explicitNoStart -and -not $launched -and $trial -notmatch 'RESTART_LOOP_PAUSED|ORIGINAL_TERM_SENT') { $restore='NOT_SWITCHED' }
    # Absence of device logs alone must not be interpreted as a successful restore.
    $phaseErrorLines=@($report -split '\r?\n' | Where-Object {$_ -match '\bERROR:|\bFAILURE_PHASE:'} | Select-Object -Last 8)
    $failureDetail=$phaseErrorLines -join "`n"

    $events=@([regex]::Matches($candidate,'P011_MENULAB_EVENT\|(\d+)\|([^\r\n]*)') | ForEach-Object {
        [PSCustomObject]@{device_epoch_ms=$_.Groups[1].Value;event=$_.Groups[2].Value.Trim()}
    })
    $eventText=($events | ForEach-Object {$_.event}) -join "`n"
    $modes=@([regex]::Matches($eventText,'(?m)^scan_mode:([01])\s*$') | ForEach-Object {$_.Groups[1].Value} | Select-Object -Unique)
    $pageRows=@(
        [PSCustomObject]@{name='工具箱';token='toolbox_ready';observed=[bool]($eventText -match '(?m)^toolbox_ready$')},
        [PSCustomObject]@{name='时钟';token='ClockPage.qml';observed=[bool]($eventText -match 'child_ready:ClockPage\.qml')},
        [PSCustomObject]@{name='计时器';token='TimerPage.qml';observed=[bool]($eventText -match 'child_ready:TimerPage\.qml')},
        [PSCustomObject]@{name='设备信息';token='DeviceInfoPage.qml';observed=[bool]($eventText -match 'child_ready:DeviceInfoPage\.qml')}
    )
    $inputRows=@('timer_start','timer_pause','timer_reset','back_child','back_home' | ForEach-Object {
        $token=$_
        [PSCustomObject]@{event=$token;count=@($events | Where-Object {$_.event -ceq $token}).Count}
    })
    $errorLines=@($candidate -split '\r?\n' | Where-Object {
        $_ -match 'ReferenceError:|TypeError:|SyntaxError:|Cannot assign|is not a type|P011 MenuLab child load failed|P011_MENULAB_CAPTURE_ERROR'
    } | Select-Object -First 60)
    $pngs=@($deviceFiles | Where-Object {$_.Extension -ieq '.png'})
    $summary=[ordered]@{
        schema='p011.menu.oneclick.v0.3.1'; action=$Action; generated_host=(Get-Date -Format o);
        engine_result=$engineResult; bootstrap_error=$BootstrapError; failure_phase=$failurePhase; failure_detail=$failureDetail;
        root_identity_confirmed=$rootConfirmed; start_not_requested=$explicitNoStart;
        preflight_marker_seen=$checked; candidate_running_marker_seen=$launched;
        restoration=$restore; finished_file=$finished;
        original_files_unchanged_confirmed=($restore -eq 'STOCK_PROCESS_RESTORED');
        page_load_events=$pageRows; scan_modes_observed=$modes; action_events=$inputRows;
        screenshot_png_count=$pngs.Count; capture_scope='Toolbox QML item only; not a physical display screenshot';
        qml_error_candidates=$errorLines;
        visual_and_touch_acceptance='USER_CONFIRMATION_REQUIRED';
        note='Unvisited pages are NOT_OBSERVED, not test failures. Process restore does not prove screen recovery. No report is uploaded automatically.'
    }
    [IO.File]::WriteAllText((Join-Path $RunFolder 'summary.json'),($summary | ConvertTo-Json -Depth 8),$utf8)
    if ($events.Count -gt 0) { $events | Export-Csv -LiteralPath (Join-Path $RunFolder 'page-events.csv') -NoTypeInformation -Encoding UTF8 }
    else { [IO.File]::WriteAllText((Join-Path $RunFolder 'page-events.csv'),"device_epoch_ms,event`n",$utf8) }
    $brief=@(
        'P011 菜单一键测试结果',
        ('流程结果：'+$engineResult),
        ('停止阶段：'+$failurePhase),
        ('root 身份校验：'+$rootConfirmed),
        ('原厂进程恢复：'+$restore),
        ('候选运行记录：'+$launched),
        ('工具箱截图数量：'+$pngs.Count),
        '',
        '页面加载记录（未观察到不等于功能失败）：'
    )
    if ($restore -eq 'NOT_SWITCHED') { $brief+= '本轮未请求启动候选，原厂界面没有因本轮测试而切换，无需恢复。' }
    if ($failureDetail) { $brief+=@('', '具体错误：', $failureDetail) }
    foreach($row in $pageRows){
        $label='未观察到'
        if (-not $launched) { $label='未测试（候选尚无启动记录）' }
        if($row.observed){$label='已观察到'}
        $brief+=($row.name+'：'+$label)
    }

    $brief+=@('', '请将本次 ZIP 上传到当前对话。没有自动上传。',
        '页面加载/点击事件不能替代对实际画面、触摸和恢复界面的人工确认。',
        '截图仅记录自定义工具箱页面，不是整机屏幕录像。',
        '原厂日志可能包含设备标识、账号和网络信息；分享前检查。')
    [IO.File]::WriteAllText((Join-Path $RunFolder '结果摘要.txt'),($brief -join "`r`n"),$utf8)
    $share=Join-Path $RunFolder 'share'
    [void][IO.Directory]::CreateDirectory($share)
    # Only root-level logs/metadata and controlled device logs; never staging/ELF/firmware/font files.
    $hostFiles=@(Get-ChildItem -LiteralPath $RunFolder -File | Where-Object {$_.Extension -in @('.txt','.json','.csv','.log')})
    foreach ($f in $hostFiles) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $share $f.Name) -Force }
    if ($deviceFiles.Count -gt 0) {
        $dest=Join-Path $share 'device'
        foreach ($f in $deviceFiles) {
            if (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $relative=$f.FullName.Substring($deviceDir.TrimEnd('\','/').Length).TrimStart('\','/')
            $ext=$f.Extension.ToLowerInvariant()
            if ($ext -notin @('.txt','.log','.json','.jsonl','.ident','.png','.exit','.request','.ready','.created','.attempted') -and $f.Name -notin @('finished')) { continue }
            if ($f.Length -gt 33554432) { continue }
            $d=Join-Path $dest $relative
            [void][IO.Directory]::CreateDirectory((Split-Path $d))
            Copy-Item -LiteralPath $f.FullName -Destination $d -Force
        }
    }
    $body=[Text.StringBuilder]::new()
    $encode={param($v) [Net.WebUtility]::HtmlEncode([string]$v)}
    [void]$body.Append('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>P011 菜单测试结果</title><style>body{font:16px/1.65 system-ui,sans-serif;background:#f3f6f8;color:#192835;max-width:1100px;margin:32px auto;padding:0 20px}section{background:white;padding:22px;border-radius:12px;margin:18px 0}table{border-collapse:collapse;width:100%}td,th{padding:9px;text-align:left;border-bottom:1px solid #e4e9ee}pre{white-space:pre-wrap;overflow-wrap:anywhere}img{max-width:100%;height:auto;border:1px solid #ccd6dd}figure{margin:20px 0}code{background:#eef2f5;padding:3px}h1{margin-bottom:4px}</style><h1>P011 原厂菜单测试结果</h1>')
    [void]$body.Append('<p>根据真实日志整理；“页面有加载记录”不等于显示、触摸和所有功能均验收通过。</p><section><h2>流程结果</h2><table>')
    foreach($row in @(@('主流程',$engineResult),@('停止阶段',$failurePhase),@('root 身份',$rootConfirmed),@('检查标记',$checked),@('候选运行标记',$launched),@('原厂恢复',$restore),@('截图数量',$pngs.Count),@('主菜单模式记录',($modes -join ', ')))) {
        [void]$body.Append('<tr><th>'+(& $encode $row[0])+'</th><td>'+(& $encode $row[1])+'</td></tr>')
    }
    [void]$body.Append('</table></section><section><h2>页面及点击记录</h2><table>')
    foreach($r in $pageRows) { $label='未观察到（可能未点击）'; if(-not $launched){$label='未测试（候选尚无启动记录）'}; if($r.observed){$label='已观察到加载事件'}; [void]$body.Append('<tr><th>'+(& $encode $r.name)+'</th><td>'+(& $encode $label)+'</td></tr>') }
    foreach($r in $inputRows) { [void]$body.Append('<tr><th>'+(& $encode $r.event)+'</th><td>'+(& $encode $r.count)+'</td></tr>') }
    [void]$body.Append('</table><p>点击记录见 <a href="page-events.csv">page-events.csv</a>；原始过程见 <a href="report.txt">report.txt</a>，机器可读结果见 <a href="summary.json">summary.json</a>。</p></section>')
    [void]$body.Append('<section><h2>错误线索</h2><pre>'+(& $encode ($BootstrapError+"`n"+$failureDetail+"`n"+($errorLines -join "`n")))+'</pre><p>没有匹配到错误文本，并不等于所有业务都通过。</p></section><section><h2>工具箱截图</h2><p>以下仅是工具箱 QML 元素的离屏渲染抓取，不包含原厂主页、其他窗口或最终物理面板效果。未打开工具箱、截图不受支持或保存失败时可能没有图片。</p>')
    $savedPngs=@(Get-ChildItem -LiteralPath $share -Recurse -File -Filter '*.png')
    foreach($f in $savedPngs) {
        $rel=$f.FullName.Substring($share.TrimEnd('\','/').Length).TrimStart('\','/').Replace('\','/')
        [void]$body.Append('<figure><img loading="lazy" src="'+(& $encode $rel)+'"><figcaption>'+(& $encode $f.Name)+'</figcaption></figure>')
    }
    [void]$body.Append('</section><section><h2>分享前</h2><p>原厂程序的日志可能包含设备标识、账号或网络信息。请先查看。这个工具不会自动上传日志。</p></section></html>')
    [IO.File]::WriteAllText((Join-Path $share 'index.html'),$body.ToString(),$utf8)
    $manifest=@(Get-ChildItem -LiteralPath $share -Recurse -File | ForEach-Object {
        [PSCustomObject]@{file=$_.FullName.Substring($share.Length).TrimStart('\','/').Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    [IO.File]::WriteAllText((Join-Path $share 'evidence-manifest.json'),(ConvertTo-Json -InputObject $manifest -Depth 5),$utf8)
    $results=Join-Path $WorkRoot 'results'
    [void][IO.Directory]::CreateDirectory($results)
    $zip=Join-Path $results ('P011-'+(Split-Path $RunFolder -Leaf)+'.zip')
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    [IO.Compression.ZipFile]::CreateFromDirectory($share,$zip,[IO.Compression.CompressionLevel]::Optimal,$false)
    [IO.File]::WriteAllText((Join-Path $WorkRoot 'LAST-RESULT.txt'),$zip+"`r`n",$utf8)
    return [PSCustomObject]@{Zip=$zip;Folder=$RunFolder;Summary=$summary;ReportHtml=(Join-Path $share 'index.html')}
}

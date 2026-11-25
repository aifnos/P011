function New-P011Result {
    param([string]$RunFolder,[string]$WorkRoot,[string]$Action='Run',[object]$EngineResult=$null,[string]$BootstrapError='',[string]$HostError='')
    $enc=[Text.UTF8Encoding]::new($false)
    function Txt([string]$p){if(Test-Path -LiteralPath $p -PathType Leaf){return [IO.File]::ReadAllText($p)};return ''}
    function Prop($o,[string]$name,$fallback){if($null -eq $o){return $fallback};$p=$o.PSObject.Properties[$name];if($null -eq $p){return $fallback};return $p.Value}
    function ConvertTo-P011HtmlText($v){return [Net.WebUtility]::HtmlEncode([string]$v)}
    [void][IO.Directory]::CreateDirectory($RunFolder)
    $er=$null
    try{$er=ConvertFrom-Json (Txt (Join-Path $RunFolder 'engine-result.json'))}catch{}
    $files=@(Get-ChildItem -LiteralPath $RunFolder -Recurse -File)
    $candidates=@($files|Where-Object{$_.Name -eq 'candidate.log'})
    $raw=($candidates|ForEach-Object{Txt $_.FullName})-join "`n"
    $clean=[regex]::Replace($raw,'\x1B\[[0-?]*[ -/]*[@-~]','')
    $events=@([regex]::Matches($clean,'P011_MENULAB_EVENT(?:[ \t]*\|[ \t]*|[ \t]+)([0-9]+)[ \t]*\|[ \t]*([^\r\n]+)')|ForEach-Object{
        [PSCustomObject]@{device_ms=[long]$_.Groups[1].Value;event=$_.Groups[2].Value.Trim()}
    })
    $names=@('AdbPage.qml','BatteryPage.qml','RadioPage.qml','BrowserPage.qml','MediaPage.qml','SshPage.qml')
    $labels=@('ADB 调试','电池信息','无线电','浏览器','影音播放','SSH 连接')
    $pages=@()
    for($i=0;$i -lt $names.Count;$i++){
        $token='child_ready:'+$names[$i];$count=@($events|Where-Object{$_.event -eq $token}).Count
        $pages+=@{page=$names[$i];name=$labels[$i];loads=$count;status=$(if($count){'观察到加载，功能需逐项核验'}else{'未观察到'})}
    }
    $actions=@($events|Group-Object event|ForEach-Object{[PSCustomObject]@{event=$_.Name;count=$_.Count}})
    $finished=@($files|Where-Object{$_.Name -eq 'finished'}|ForEach-Object{(Txt $_.FullName).Trim()})
    $recovery='未观察到完成标记'; $recoveryCode='NOT_CONFIRMED'
    $trialTexts=@($files|Where-Object{$_.Name -eq 'trial.log'}|ForEach-Object{Txt $_.FullName})
    $candidateSeen=[bool]($trialTexts -match 'CANDIDATE_RUNNING')
    $lifecycleSeen=[bool]($trialTexts -match 'GUARDIAN_ARMED|RESTART_LOOP_PAUSED|ORIGINAL_TERM_SENT|CANDIDATE_RUNNING|RESTORING_STOCK')
    $startField=$null
    if($null -ne $er){$startField=$er.PSObject.Properties['start_attempted']}
    $notStarted=($null -ne $startField -and $startField.Value -eq $false -and -not $lifecycleSeen)
    if($notStarted){
        $recovery='本轮未启动候选、未切换原厂界面；不需要恢复本轮界面'
        $recoveryCode='NOT_REQUIRED_NO_TRIAL'
        foreach($page in $pages){$page.status='未测试：候选未启动'}
    }
    $pathPreflight=$null
    $pathFiles=@($files|Where-Object{$_.Name -eq 'path-preflight.json'})
    if($pathFiles.Count){try{$pathPreflight=ConvertFrom-Json (Txt $pathFiles[-1].FullName)}catch{}}
    $keyStatus=$null
    try{$keyStatus=ConvertFrom-Json (Txt (Join-Path $RunFolder 'ssh-key-status.json'))}catch{}

    if($finished -contains 'RESTORED'){$recovery='原厂进程恢复记录存在，物理界面仍需观察';$recoveryCode='STOCK_PROCESS_RESTORED'}
    if($finished -contains 'RECOVERY_NEEDS_ATTENTION'){$recovery='恢复需要检查，请查看 trial.log 和 tools-recovery.json';$recoveryCode='RECOVERY_NEEDS_ATTENTION'}
    $png=@($files|Where-Object{$_.Extension -eq '.png' -and $_.FullName -match '[\\/]screenshots[\\/]'})
    $errors=@(($clean -split '\r?\n')|Where-Object{$_ -match 'ReferenceError|TypeError|SyntaxError|is not a type|not installed|P011_TOOLS_CALLBACK|P011_MENULAB_EVENT.*(?:error|failed)'}|Select-Object -First 60)
    $toolRecovery=$null
    $tr=@($files|Where-Object{$_.Name -eq 'tools-recovery.json'})
    if($tr.Count){try{$toolRecovery=ConvertFrom-Json (Txt $tr[-1].FullName)}catch{}}
    $summary=[ordered]@{schema='p011.tools.result.v0.4.4';host_time=(Get-Date -Format o);action=$Action;
        engine_result=(Prop $er 'result' '请查原始 report.txt');bootstrap_error=($BootstrapError+$HostError);
        recovery=$recovery;restoration=$recoveryCode;candidate_running_marker_seen=$candidateSeen;trial_not_started=$notStarted;path_preflight=$pathPreflight;ssh_key_status=$keyStatus;screenshot_png_count=$png.Count;tool_recovery=$toolRecovery;pages=$pages;actions=$actions;screenshots=$png.Count;
        note='页面加载、播放状态、SSH监听不等于硬件/音频/实际认证全部通过。未观察到不是失败。';
        privacy='不打包私钥/API token/USB原配置。日志可能含SSID、MAC、IP、设备或原厂业务信息。'}
    [IO.File]::WriteAllText((Join-Path $RunFolder 'summary.json'),($summary|ConvertTo-Json -Depth 12),$enc)
    [IO.File]::WriteAllText((Join-Path $RunFolder 'page-events.json'),(ConvertTo-Json -InputObject $events -Depth 4),$enc)
    $events|Export-Csv -LiteralPath (Join-Path $RunFolder 'page-events.csv') -NoTypeInformation -Encoding UTF8
    $text="P011 五类工具测试结果`r`n"+"运行结果："+$summary.engine_result+"`r`n"+"恢复："+$recovery+"`r`n"+"截图数："+$png.Count+"`r`n`r`n"
    foreach($page in $pages){$text+=$page.name+'：'+$page.status+'（'+$page.loads+" 次）`r`n"}
    $text+="`r`n"+$summary.note+"`r`n"+$summary.privacy
    [IO.File]::WriteAllText((Join-Path $RunFolder '结果摘要.txt'),$text,$enc)
    $html=[Text.StringBuilder]::new()
    [void]$html.Append('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>P011 工具箱测试结果</title><style>body{background:#101114;color:#e9ebef;font:16px/1.7 sans-serif;max-width:1140px;margin:30px auto;padding:18px}h1{color:#12cfa7}section{background:#27292e;border-radius:8px;padding:18px;margin:14px 0}table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #45474d;padding:9px}a{color:#12cfa7}.shots{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:16px}img{width:100%;background:#000}pre{white-space:pre-wrap;word-break:break-word;font-size:13px}</style><h1>P011 · 工具箱测试结果</h1>')
    [void]$html.Append('<section><b>'+ (ConvertTo-P011HtmlText $summary.engine_result)+'</b><p>'+(ConvertTo-P011HtmlText $recovery)+'</p><p>'+(ConvertTo-P011HtmlText $summary.note)+'</p></section><section><table><tr><th>页面</th><th>观察</th><th>加载次数</th></tr>')
    foreach($page in $pages){[void]$html.Append('<tr><td>'+(ConvertTo-P011HtmlText $page.name)+'</td><td>'+(ConvertTo-P011HtmlText $page.status)+'</td><td>'+ $page.loads+'</td></tr>')}
    [void]$html.Append('</table></section><section><h2>事件与操作</h2><table>')
    foreach($act in $actions){[void]$html.Append('<tr><td>'+(ConvertTo-P011HtmlText $act.event)+'</td><td>'+$act.count+'</td></tr>')}
    [void]$html.Append('</table></section><section><h2>应用截图</h2><p>不是物理全屏录像；浏览器联网后不自动抓取，手动截图除外。</p><div class="shots">')
    foreach($im in $png){$rel=$im.FullName.Substring($RunFolder.Length).TrimStart('\','/').Replace('\','/');$url=($rel.Split('/')|ForEach-Object{[Uri]::EscapeDataString($_)})-join '/';[void]$html.Append('<div><a href="'+(ConvertTo-P011HtmlText $url)+'"><img loading="lazy" src="'+(ConvertTo-P011HtmlText $url)+'"></a><small>'+(ConvertTo-P011HtmlText $im.Name)+'</small></div>')}
    [void]$html.Append('</div></section><section><h2>需检查的日志摘录</h2><pre>'+(ConvertTo-P011HtmlText ($errors -join "`n"))+'</pre></section><section>'+(ConvertTo-P011HtmlText $summary.privacy)+'</section></html>')
    [IO.File]::WriteAllText((Join-Path $RunFolder 'index.html'),$html.ToString(),$enc)
    # Curated evidence only. Never archive deployment payloads, keys, tokens or USB originals.
    $safe=@(Get-ChildItem -LiteralPath $RunFolder -Recurse -File|Where-Object{
        $rel=$_.FullName.Substring($RunFolder.Length)
        $rel -notmatch '[\\/](?:staging|private|keys|payload|backups|source-original)[\\/]' -and
        $_.Name -notmatch 'Session\.js|authorized_keys|host_ed25519|client\.pub|adb-original|^evidence-manifest\.json$' -and
        ($_.Extension.ToLowerInvariant() -in @('.txt','.log','.json','.jsonl','.csv','.html','.png') -or $_.Name -in @('finished','status.txt','toolbridge.identity','tools.ready'))
    })
    $hashes=@($safe|ForEach-Object{[PSCustomObject]@{path=$_.FullName.Substring($RunFolder.Length).TrimStart('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}})
    $hashFile=Join-Path $RunFolder 'evidence-manifest.json';[IO.File]::WriteAllText($hashFile,(ConvertTo-Json -InputObject $hashes -Depth 4),$enc)
    $safe+=Get-Item -LiteralPath $hashFile
    $resultDir=Join-Path $WorkRoot 'results';[void][IO.Directory]::CreateDirectory($resultDir)
    $zip=Join-Path $resultDir ('P011-'+(Split-Path $RunFolder -Leaf)+'.zip')
    if(Test-Path -LiteralPath $zip){$zip=Join-Path $resultDir ('P011-'+(Split-Path $RunFolder -Leaf)+'-'+(Get-Date -Format 'HHmmssfff')+'.zip')}
    # Explicitly load both assemblies. PowerShell 7 on some Windows installs does not
    # resolve the short namespace form of ZipArchiveMode even when ZipFile is available.
    foreach($assemblyName in @('System.IO.Compression','System.IO.Compression.FileSystem','System.IO.Compression.ZipFile')) {
        try { Add-Type -AssemblyName $assemblyName -ErrorAction Stop } catch { }
    }
    $z=[System.IO.Compression.ZipFile]::Open($zip,[System.IO.Compression.ZipArchiveMode]::Create)
    try{foreach($f in $safe){$rel=$f.FullName.Substring($RunFolder.Length).TrimStart('\','/').Replace('\','/');[void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($z,$f.FullName,$rel,[System.IO.Compression.CompressionLevel]::Optimal)}}finally{$z.Dispose()}
    return [PSCustomObject]@{Zip=$zip;ReportHtml=(Join-Path $RunFolder 'index.html');Summary=[PSCustomObject]$summary}
}


function New-P011RawResultZip {
    param([string]$RunFolder,[string]$WorkRoot)
    foreach($assemblyName in @('System.IO.Compression','System.IO.Compression.FileSystem','System.IO.Compression.ZipFile')) {
        try { Add-Type -AssemblyName $assemblyName -ErrorAction Stop } catch { }
    }
    $resultDir=Join-Path $WorkRoot 'results' 
    [void][IO.Directory]::CreateDirectory($resultDir)
    $zip=Join-Path $resultDir ('P011-RAW-'+(Split-Path $RunFolder -Leaf)+'-'+(Get-Date -Format 'HHmmssfff')+'.zip')
    $rawFiles=@(Get-ChildItem -LiteralPath $RunFolder -Recurse -File | Where-Object {
        $rel=$_.FullName.Substring($RunFolder.Length)
        $rel -notmatch '[\\/](?:staging|private|keys|payload|backups|source-original)[\\/]' -and
        $_.Name -notmatch 'Session\.js|authorized_keys|host_ed25519|client\.pub|adb-original|^evidence-manifest\.json$' -and
        ($_.Extension.ToLowerInvariant() -in @('.txt','.log','.json','.jsonl','.csv','.html','.png') -or $_.Name -eq 'finished')
    })
    $archive=[System.IO.Compression.ZipFile]::Open($zip,[System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach($file in $rawFiles) {
            $rel=$file.FullName.Substring($RunFolder.Length).TrimStart('\','/').Replace('\','/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,$rel,[System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally {$archive.Dispose()}
    return $zip
}

function Test-P011ResultTools {
    param([string]$WorkRoot)
    # Uses only a unique host fixture directory, never connected device data.
    $fixture=Join-Path $WorkRoot ('tests\result-selftest-'+[Guid]::NewGuid().ToString('N'))
    $run=Join-Path $fixture 'logs\fixture'
    [void][IO.Directory]::CreateDirectory((Join-Path $run 'device'))
    try {
        [IO.File]::WriteAllText((Join-Path $run 'engine-result.json'),'{"result":"STOP_DONE_STOCK_RESTORED","start_attempted":true}')
        [IO.File]::WriteAllText((Join-Path $run 'device\finished'),"RESTORED`n")
        [IO.File]::WriteAllText((Join-Path $run 'device\trial.log'),"CANDIDATE_RUNNING`nRESTORED_STOCK_PROCESS`n")
        $result=New-P011Result -RunFolder $run -WorkRoot $fixture -Action 'HostSelfTest'
        if(-not (Test-Path -LiteralPath $result.Zip) -or -not (Test-Path -LiteralPath $result.ReportHtml)) {throw 'Result paths were not returned correctly.'}
        if($result.Summary.restoration -cne 'STOCK_PROCESS_RESTORED') {throw 'Restore result was not parsed.'}
        if($result.Summary.screenshot_png_count -ne 0) {throw 'Empty fixture unexpectedly has screenshots.'}
        $raw=New-P011RawResultZip -RunFolder $run -WorkRoot $fixture
        if(-not (Test-Path -LiteralPath $raw)) {throw 'Raw fallback was not created.'}
        [IO.File]::WriteAllText((Join-Path $run 'device\finished'),"RECOVERY_NEEDS_ATTENTION`n")
        $failed=New-P011Result -RunFolder $run -WorkRoot $fixture -Action 'HostSelfTest'
        if($failed.Summary.restoration -cne 'RECOVERY_NEEDS_ATTENTION') {throw 'Failed restore was incorrectly classified.'}
        Remove-Item -LiteralPath (Join-Path $run 'device\finished') -Force
        [IO.File]::WriteAllText((Join-Path $run 'device\trial.log'),"PATH_CONFLICT: fixture`n")
        [IO.File]::WriteAllText((Join-Path $run 'engine-result.json'),'{"result":"STOPPED: NOT_STARTED","start_attempted":false}')
        $noTrial=New-P011Result -RunFolder $run -WorkRoot $fixture -Action 'HostSelfTest'
        if($noTrial.Summary.restoration -cne 'NOT_REQUIRED_NO_TRIAL'){throw 'Preflight failure incorrectly requires restoration.'}
        [IO.File]::WriteAllText((Join-Path $run 'engine-result.json'),'{"result":"UNKNOWN"}')
        $unknown=New-P011Result -RunFolder $run -WorkRoot $fixture -Action 'HostSelfTest'
        if($unknown.Summary.restoration -cne 'NOT_CONFIRMED'){throw 'Missing evidence was classified as no trial.'}
        return 'RESULT_HOST_SELFTEST_OK: HTML, ZIP, no-trial/unknown/recovery classification, raw fallback.'

    } finally {
        if(Test-Path -LiteralPath $fixture) {Remove-Item -LiteralPath $fixture -Recurse -Force}
    }
}

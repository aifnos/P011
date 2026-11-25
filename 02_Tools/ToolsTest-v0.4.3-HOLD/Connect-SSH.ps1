[CmdletBinding()]
param([ValidateSet('USB','WiFi')][string]$Mode='USB')
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root='D:\project\P011'
$forward='';$adb='';$serial='';$proc=$null
$utf8=[Text.UTF8Encoding]::new($false)
$result=[ordered]@{mode=$Mode;time=(Get-Date -Format o);connected=$false;exit=$null;error=''}
function Q([string]$s) {
    $b=[Text.StringBuilder]::new();[void]$b.Append('"');$n=0
    foreach($c in $s.ToCharArray()) {
        if($c -eq '\'){$n++;continue}
        if($c -eq '"'){[void]$b.Append(('\'*($n*2+1)));[void]$b.Append('"')}
        else{[void]$b.Append(('\'*$n));[void]$b.Append($c)};$n=0
    }
    [void]$b.Append(('\'*($n*2)));[void]$b.Append('"');$b.ToString()
}
function Run-Capture([string]$exe,[string[]]$argsList,[int]$seconds=20) {
    $si=[Diagnostics.ProcessStartInfo]::new();$si.FileName=$exe;$si.Arguments=($argsList|ForEach-Object{Q $_})-join ' '
    $si.UseShellExecute=$false;$si.CreateNoWindow=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
    $si.StandardOutputEncoding=$utf8;$si.StandardErrorEncoding=$utf8
    $p=[Diagnostics.Process]::new();$p.StartInfo=$si
    try {
        if(-not $p.Start()){throw '无法启动程序'}
        $a=$p.StandardOutput.ReadToEndAsync();$b=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit($seconds*1000)){try{$p.Kill()}catch{};throw '连接超时'}
        [PSCustomObject]@{Exit=$p.ExitCode;Out=$a.Result;Err=$b.Result}
    } finally {$p.Dispose()}
}
function Find-Exe([string]$name) {
    $cmd=Get-Command ($name+'.exe') -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
    if($null -ne $cmd){return $cmd.Source}
    foreach($p in @((Join-Path $root ('tools\platform-tools\'+$name+'.exe')),(Join-Path $root ('platform-tools\'+$name+'.exe')),(Join-Path $env:SystemRoot ('System32\OpenSSH\'+$name+'.exe')))) {
        if(Test-Path -LiteralPath $p){return $p}
    }
    throw ('没有找到 '+$name+'.exe')
}
try {
    $last=Get-Content -LiteralPath (Join-Path $root 'state\ToolsTest-last-session.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $remote=[string]$last.remote;$serial=[string]$last.serial
    if($remote -notmatch '^/tmp/p011-menutest-[0-9-]+$' -or $serial -notmatch '^[A-Za-z0-9._:-]+$'){throw '保存的会话标识无效'}
    $folder=[IO.Path]::GetFullPath([string]$last.host_result)
    if(-not $folder.StartsWith($root+'\logs\',[StringComparison]::OrdinalIgnoreCase)){throw '保存的结果路径无效'}
    $result.remote_session=$remote
    $adb=Find-Exe 'adb';$ssh=Find-Exe 'ssh'
    $r=Run-Capture $adb @('-s',$serial,'shell',('cat '+$remote+'/logs/ssh-connection.json'))
    if($r.Exit -ne 0){throw $r.Err}
    $info=($r.Out -replace '\r+\n',"`n" -replace '\r',"`n")|ConvertFrom-Json
    if(-not $info.running -or [int]$info.port -ne 2222){throw '请先在笔上 SSH 页面点击相应开启按钮'}
    if(($Mode -eq 'USB' -and $info.mode -ne 'usb') -or ($Mode -eq 'WiFi' -and $info.mode -ne 'wifi')){throw '电脑入口与笔上SSH监听模式不一致'}
    $public=([string]$info.public_host_key).Trim()
    if($public -notmatch '^ssh-ed25519 ([A-Za-z0-9+/]+=*)(?: [^\r\n]*)?$'){throw '主机公钥格式未通过核对'}
    $keyBody=$Matches[1]
    $key=Join-Path $root 'keys\p011-tools-client-ed25519'
    if(-not (Test-Path -LiteralPath $key)){throw '没有找到本测试专用的电脑私钥'}
    if($Mode -eq 'USB') {
        $r=Run-Capture $adb @('-s',$serial,'forward','tcp:0','tcp:2222')
        if($r.Exit -ne 0 -or $r.Out.Trim() -notmatch '^\d+$'){throw ('ADB 转发失败：'+$r.Err)}
        $port=[int]$r.Out.Trim();$forward='tcp:'+$port;$address='127.0.0.1'
    } else {
        $port=2222;$address=[string]$info.address
        $parsed=$null
        if(-not [Net.IPAddress]::TryParse($address,[ref]$parsed)){throw '局域网地址无效'}
        $bytes=$parsed.GetAddressBytes()
        if($bytes.Length -ne 4 -or -not ($bytes[0]-eq 10 -or ($bytes[0]-eq 172 -and $bytes[1]-ge 16 -and $bytes[1]-le 31) -or ($bytes[0]-eq 192 -and $bytes[1]-eq 168))){throw '仅允许Wi-Fi私网IPv4'}
    }
    $known=Join-Path $root ('keys\known-host-'+(Split-Path $remote -Leaf)+'-'+$Mode+'.txt')
    [IO.File]::WriteAllText($known,('['+$address+']:'+$port+' ssh-ed25519 '+$keyBody+"`n"),[Text.Encoding]::ASCII)
    Write-Host '通过现有 ADB 获取并固定主机公钥；正在做 SSH 身份和内核查询。'
    $argsList=@('-i',$key,'-p',[string]$port,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',('UserKnownHostsFile='+$known),'-o','ConnectTimeout=8',('root@'+$address),'id; uname -a')
    $r=Run-Capture $ssh $argsList 20
    $result.exit=$r.Exit;$result.stdout=$r.Out;$result.stderr=$r.Err
    $result.connected=($r.Exit -eq 0 -and $r.Out -match 'uid=0\(root\)')
    Write-Host $r.Out
    if($r.Err){Write-Host $r.Err}
    if($result.connected){Write-Host 'SSH_LOGIN_CONFIRMED：已通过密钥认证并执行 root 身份查询。'}
    else{throw 'SSH 登录尚未验证成功，检查服务日志；不要修改系统密码或关闭安全设置。'}
} catch {
    $result.error=$_.Exception.Message;Write-Host ('SSH_TEST_STOP: '+$result.error)
} finally {
    if($forward -and $adb){try{$null=Run-Capture $adb @('-s',$serial,'forward','--remove',$forward)}catch{}}
    $dest=Join-Path $root 'state\ToolsSSH-last-check.json';[void][IO.Directory]::CreateDirectory((Split-Path $dest))
    [IO.File]::WriteAllText($dest,($result|ConvertTo-Json -Depth 5),$utf8)
    if(Get-Variable folder -ErrorAction SilentlyContinue){try{[IO.File]::WriteAllText((Join-Path $folder ('ssh-client-'+(Get-Date -Format 'HHmmss')+'.json')),($result|ConvertTo-Json -Depth 5),$utf8)}catch{}}
    Write-Host '检查结果已保存。保持主测试等待结束，或双击 COLLECT.cmd 重新收集。'
}

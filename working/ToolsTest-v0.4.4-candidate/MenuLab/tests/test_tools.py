#!/usr/bin/env python3
"""Offline host tests with temporary fixtures, not P011/Windows validation."""
import sys,os,tempfile,pathlib,json,ast,socket,threading,time,re,hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
import tools_metrics as M,tools_services as S,tools_bridge as B
checks=[]
def check(name,condition):
    assert condition,name
    checks.append({'name':name,'passed':True})
for f in (ROOT/'runtime').glob('*.py'):
    ast.parse(f.read_text(),feature_version=(3,5));check('Python3.5 syntax '+f.name,True)
with tempfile.TemporaryDirectory(prefix='p011-tools-test-') as tmp:
    d=pathlib.Path(tmp);battery=d/'power/battery';battery.mkdir(parents=True)
    values={'type':'Battery','capacity':'85','voltage_now':'3900000','current_now':'-120000','temp':'287',
            'charge_full':'1800000','charge_full_design':'2000000','health':'Good'}
    for k,v in values.items():(battery/k).write_text(v)
    b=M.battery(str(d/'power'))
    check('battery voltage microV -> V',b['voltage']==3.9)
    check('current sign preserved',b['current']==-120)
    check('temperature tenths -> C',b['temperature']==28.7)
    check('battery-side calculated power',b['power']==-.468)
    check('missing cycle count is unavailable',not next(r for r in b['rows'] if r['key']=='循环次数')['available'])
    check('health is not converted to capacity percent',next(r for r in b['rows'] if r['key']=='驱动健康状态')['value']=='Good')
    check('missing battery does not invent capacity',M.battery(str(d/'missing'))['capacity'] is None)
    config=d/'usbenum.ini';initial=b'[property]\r\ndebug=1\r\nother=keep\r\n';config.write_bytes(initial)
    old=S.CONFIG;S.CONFIG=str(config)
    trial=d/'trial';trial.mkdir();(trial/'logs').mkdir();(trial/'pages').mkdir();(trial/'media').mkdir()
    srv=S.Services(str(trial),lambda s:None)
    srv.adb_set(0)
    check('ADB changes only debug field and preserves CRLF',config.read_bytes()==initial.replace(b'debug=1',b'debug=0'))
    check('ADB real daemon is never controlled by setting',not hasattr(srv,'restart_adbd'))
    S.restore_adb(str(trial));check('ADB rollback byte exact',config.read_bytes()==initial)
    srv.adb_set(0);config.write_bytes(initial+b'other_edit=yes\r\n')
    caught=False
    try:S.restore_adb(str(trial))
    except RuntimeError:caught=True
    check('external config edits are not overwritten',caught and b'other_edit' in config.read_bytes())
    config.write_bytes(initial)
    check('private Wi-Fi addresses accepted',all(M.private_ipv4(ip) for ip in ('192.168.1.2','172.16.1.2','10.1.1.2')))
    check('public/loopback/invalid addresses rejected',not any(M.private_ipv4(ip) for ip in ('8.8.8.8','127.0.0.1','172.32.1.1','192.168.1.999','::1')))
    (trial/'media/hello world.mp3').write_bytes(b'test');(trial/'media/escape.mp3').symlink_to('/etc/passwd')
    (trial/'media/run.sh').write_text('no')
    paths=[];cat=B.catalog(str(trial),paths);check('media whitelist + symlink containment',len(cat)==1 and cat[0]['url'].endswith('hello%20world.mp3') and cat[0]['id']==0 and paths==[str((trial/'media/hello world.mp3').resolve())])
    check('GStreamer duration parsed to milliseconds',B.duration_ms('Duration: 0:00:07.786000000')==7786)
    check('missing duration stays unavailable',B.duration_ms('no duration')==0)
    check('BlueZ address alias is not a device Name',M.bluez_name({'Alias':'AA-BB-CC-DD-EE-FF'}) is None)
    check('BlueZ explicit Name is retained',M.bluez_name({'Alias':'AA-BB-CC-DD-EE-FF','Name':'  Speaker  '})=='Speaker')
    bridge=B.Bridge(str(trial))
    bridge.service.state=lambda: {}
    bridge.audio_generation=1;bridge.audio_state=bridge.new_audio_state(1,'starting')
    bridge.audio=type('FixtureAudio',(),{'returncode':None,'poll':lambda self:self.returncode})()
    sample=bridge.snapshot()['audio_backend']
    check('starting process does not invent playback progress',sample['status']=='starting' and sample['process_alive'] and not sample['playing'] and all(sample[k]==0 for k in ('position_ms','duration_ms','position_sample_epoch_ms','position_sample_monotonic_ms','position_samples')) and sample['position_source']=='gst_play_query')
    check('gst-play query frame parsed in milliseconds',B.parse_gst_play_frame(b'0:00:00.4 / 0:00:07.7       ')=={'position_ms':400,'duration_ms':7700})
    check('gst-play timestamp fractions and hours parsed',B.parse_gst_play_frame('0:01:02.125 / 1:02:03.000000000')=={'position_ms':62125,'duration_ms':3723000})
    check('gst-play ANSI query frame parsed',B.parse_gst_play_frame('\x1b[2K0:00:00 / 0:00:08')=={'position_ms':0,'duration_ms':8000})
    check('preroll and malformed query are not playback samples',all(B.parse_gst_play_frame(frame) is None for frame in ('Prerolling...','Prerolled.','0:60:00.1 / 0:00:08.0','0:00:01.0 / unavailable')))
    bridge.audio_state.update({'status':'playing','position_ms':400,'duration_ms':7700,'position_sample_epoch_ms':123456789,'position_sample_monotonic_ms':1000,'position_samples':1})
    sample=bridge.audio_snapshot()
    check('audio API keeps actual sampled position and timestamp without wall-clock interpolation',sample['playing'] and sample['process_alive'] and sample['position_ms']==400 and sample['position_sample_monotonic_ms']==1000 and sample['position_sample_epoch_ms']==123456789 and sample['duration_ms']==7700)
    bridge.audio.returncode=0
    bridge.audio_state.update({'status':'ended','position_ms':8000,'duration_ms':8000,'exit_code':0})
    sample=bridge.audio_snapshot()
    check('normal terminal state preserves final media position',sample['status']=='ended' and not sample['process_alive'] and not sample['playing'] and sample['position_ms']==8000 and sample['duration_ms']==8000 and sample['exit_code']==0 and not sample['error'])
    bridge.audio_state=bridge.new_audio_state(1,'starting')
    sample=bridge.audio_snapshot()
    check('exited process cannot leave starting false-alive race',sample['status']=='error' and not sample['process_alive'] and not sample['playing'] and bool(sample['error']))
    bridge.stop_audio();sample=bridge.audio_snapshot()
    check('stop clears progress while retaining generation',sample['status']=='stopped' and sample['generation']==1 and not sample['process_alive'] and sample['position_ms']==0 and sample['position_sample_monotonic_ms']==0)
    def parse_raw(raw):
        a,c=socket.socketpair()
        try:a.sendall(raw);a.shutdown(socket.SHUT_WR);return bridge.parse(c)
        finally:a.close();c.close()
    header=('GET /api/state HTTP/1.1\r\nHost: '+bridge.host+'\r\nX-P011-Token: '+bridge.token+'\r\n\r\n').encode()
    check('authenticated loopback GET accepted',parse_raw(header)==('GET','/api/state',''))
    audio_header=header.replace(b'/api/state',b'/api/audio')
    check('light audio endpoint accepted with existing authentication',parse_raw(audio_header)==('GET','/api/audio',''))
    for name,raw in [
        ('missing token',header.replace(('X-P011-Token: '+bridge.token+'\r\n').encode(),b'')),
        ('web origin blocked',header.replace(b'\r\n\r\n',b'\r\nOrigin: https://example.com\r\n\r\n')),
        ('wrong Host blocked',header.replace(bridge.host.encode(),b'evil.example')),
        ('transfer encoding blocked',header.replace(b'\r\n\r\n',b'\r\nTransfer-Encoding: chunked\r\n\r\n')),
        ('arbitrary paths blocked',header.replace(b'/api/state',b'/etc/passwd')),
        ('duplicate headers blocked',header.replace(b'\r\n\r\n',('\r\nHost: '+bridge.host+'\r\n\r\n').encode()))]:
        rejected=False
        try:parse_raw(raw)
        except (ValueError,PermissionError):rejected=True
        check(name,rejected)
    for name,raw in [
        ('audio endpoint rejects missing token',audio_header.replace(('X-P011-Token: '+bridge.token+'\r\n').encode(),b'')),
        ('audio endpoint rejects wrong Host',audio_header.replace(bridge.host.encode(),b'evil.example'))]:
        rejected=False
        try:parse_raw(raw)
        except (ValueError,PermissionError):rejected=True
        check(name,rejected)
    try:bridge.action('exec rm -rf /');unsafe=False
    except ValueError:unsafe=True
    check('no arbitrary action/shell evaluator',unsafe)
    for action in ('media_play:-1:25','media_play:0:101','media_play:x:25'):
        rejected=False
        try:bridge.action(action)
        except (ValueError,RuntimeError):rejected=True
        check('invalid audio action rejected '+action,rejected)
    parsed=json.loads(bridge.response(200,{'ok':True,'data':{'中文':'值','absent':None}}).split(b'\r\n\r\n')[1])
    check('app-local JSON encoder response',parsed['data']['中文']=='值' and parsed['data']['absent'] is None)
    bridge.s.close();S.CONFIG=old
# Static behavior checks complement fixtures but do not certify the hardware.
svc=(ROOT/'runtime/tools_services.py').read_text()
metrics=(ROOT/'runtime/tools_metrics.py').read_text()
check('radio sampler never queries ConnMan','get_object(\'net.connman\'' not in metrics and "tool('connmanctl')" not in metrics)
check('SSH password and empty-password auth disabled','PasswordAuthentication no' in svc and 'PermitEmptyPasswords no' in svc)
check('SSH authorized keys not below /tmp',"self.sshdir='/run/p011-tools-ssh/'" in svc)
check('no account unlock / shadow edit','/etc/shadow' not in svc and "'passwd'" not in svc)
check('no remount/reboot/erase commands in feature bridge',not re.search(r"\[['\"](?:reboot|mount|flash|dd|killall)['\"]",svc))
result={'scope':'Linux host fixture/static tests, not hardware or Windows','cases':checks,'count':len(checks),'all_passed':True}
(ROOT/'tests/tools-tests.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
print('PASS',len(checks),'checks')

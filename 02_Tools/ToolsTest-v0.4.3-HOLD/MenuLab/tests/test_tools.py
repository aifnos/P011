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
    cat=B.catalog(str(trial));check('media whitelist + symlink containment',len(cat)==1 and cat[0]['url'].endswith('hello%20world.mp3'))
    bridge=B.Bridge(str(trial))
    def parse_raw(raw):
        a,c=socket.socketpair()
        try:a.sendall(raw);a.shutdown(socket.SHUT_WR);return bridge.parse(c)
        finally:a.close();c.close()
    header=('GET /api/state HTTP/1.1\r\nHost: '+bridge.host+'\r\nX-P011-Token: '+bridge.token+'\r\n\r\n').encode()
    check('authenticated loopback GET accepted',parse_raw(header)==('GET','/api/state',''))
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
    try:bridge.action('exec rm -rf /');unsafe=False
    except ValueError:unsafe=True
    check('no arbitrary action/shell evaluator',unsafe)
    parsed=json.loads(bridge.response(200,{'ok':True,'data':{'中文':'值','absent':None}}).split(b'\r\n\r\n')[1])
    check('app-local JSON encoder response',parsed['data']['中文']=='值' and parsed['data']['absent'] is None)
    bridge.s.close();S.CONFIG=old
# Static behavior checks complement fixtures but do not certify the hardware.
svc=(ROOT/'runtime/tools_services.py').read_text()
check('SSH password and empty-password auth disabled','PasswordAuthentication no' in svc and 'PermitEmptyPasswords no' in svc)
check('SSH authorized keys not below /tmp',"self.sshdir='/run/p011-tools-ssh/'" in svc)
check('no account unlock / shadow edit','/etc/shadow' not in svc and "'passwd'" not in svc)
check('no remount/reboot/erase commands in feature bridge',not re.search(r"\[['\"](?:reboot|mount|flash|dd|killall)['\"]",svc))
result={'scope':'Linux host fixture/static tests, not hardware or Windows','cases':checks,'count':len(checks),'all_passed':True}
(ROOT/'tests/tools-tests.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
print('PASS',len(checks),'checks')

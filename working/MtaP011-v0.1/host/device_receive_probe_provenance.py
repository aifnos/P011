"""Explicit new probe-method P011 diagnostic only; default is PC source check.

Uses the already fixed native helper in formal-receive-v1 without staging or
changing it. Only the four extracted new probe functions execute; no State,
Owner, UI, receiver, network mutation or RF admission is constructed.
"""
import ast
import base64
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import uuid
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
STATE = 'candidate/receive-probe-provenance-v1/runtime/mta_service.py'
STATE_PIN = (137508, 'f586bd2d98ca702bcb1d572fe92293ac40da44c94a3a85cd54c82b2b6125472c')
CODEC = 'runtime/p011_json.py'
CODEC_PIN = (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
RADIO = 'runtime/mta_receive_radio_baseline.py'
RADIO_PIN = (3971, '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c')
PROBE = 'host/device_probe.py'
PROBE_PIN = (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
INPUTS = (STATE, CODEC, RADIO, PROBE, 'host/device_receive_probe_provenance.py',
          'TEST_MTA_RECEIVE_PROBE_READONLY.cmd')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(name, pin):
    raw = (BASE / name).read_bytes()
    if (len(raw), digest(raw)) != pin:
        raise ValueError('fixed_source_changed')
    return raw


def extracted(raw):
    text = raw.decode('utf-8')
    tree = ast.parse(text, feature_version=(3, 5))
    names = {'_probe_closed', '_probe_result', '_probe_cleanup_call', 'capability'}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
             or isinstance(node, ast.Assign) and any(isinstance(value, ast.Name) and
                value.id == '_CAPABILITY_CREATOR' for value in node.targets)]
    if {node.name for node in nodes if isinstance(node, ast.FunctionDef)} != names or len(nodes) != 5:
        raise ValueError('probe_definitions')
    lines = text.splitlines()
    snippet = ('\n\n'.join('\n'.join(lines[node.lineno - 1:node.end_lineno]) for node in nodes) + '\n').encode('utf-8')
    ast.parse(snippet.decode('utf-8'), feature_version=(3, 5))
    return snippet


def encoded(name, raw):
    value = base64.b64encode(zlib.compress(raw)).decode('ascii')
    lines = [repr(value[index:index + 96]) + ',' for index in range(0, len(value), 96)]
    return name + ' = decode((\n' + '\n'.join(lines) + '\n), ' + repr((len(raw), digest(raw))) + ')\n'


REMOTE_HEAD = r'''
import base64,errno,hashlib,os,stat,subprocess,sys,threading,time,types,zlib
def decode(chunks,pin):
 raw=zlib.decompress(base64.b64decode(''.join(chunks)))
 if (len(raw),hashlib.sha256(raw).hexdigest())!=pin:raise ValueError('source_changed')
 return raw
'''

REMOTE_BODY = r'''
if (sys.platform!='linux' or sys.byteorder!='little' or os.uname()[4]!='armv7l' or
    os.geteuid()!=0 or tuple(sys.version_info[:2])!=(3,5) or
    os.O_NOFOLLOW!=0x8000 or os.O_CLOEXEC!=0x80000):raise ValueError('platform')
codec=types.ModuleType('private_receive_probe_json')
exec(compile(CODEC,'<fixed-p011-json>','exec'),codec.__dict__)
radio=types.ModuleType('private_receive_probe_radio')
exec(compile(RADIO,'<fixed-radio-normalizer>','exec'),radio.__dict__)
ns={'os':os,'subprocess':subprocess,'json':codec,'threading':threading,
    'types':types,'__name__':'private_receive_probe_functions'}
exec(compile(FUNCTIONS,'<extracted-original-probe-functions>','exec'),ns)
HELPER='/var/volatile/tmp/p011-mta-formal-receive-v1/native/mta-bluez-helper'
HELPER_PIN=(74920,'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181')
PINS={'/usr/bin/Z03':'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
 '/usr/bin/control_engine':'364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
 '/usr/bin/zyb_z03_launch.sh':'7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}
def meta(raw):
 return tuple(getattr(raw,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as source:
  for value in iter(lambda:source.read(65536),b''):h.update(value)
 return h.hexdigest()
def read(path,count=65536):
 with open(path,'rb') as source:return source.read(count)
def identity(pid):
 text=read('/proc/'+str(pid)+'/stat',4096).decode('ascii');end=text.rindex(')');fields=text[end+2:].split()
 return (int(pid),text[text.index('(')+1:end],int(fields[1]),fields[19],os.readlink('/proc/'+str(pid)+'/exe'))
def snapshot():
 rows=[]
 for pid in os.listdir('/proc'):
  if not pid.isdigit():continue
  try:
   item=identity(pid)
   if item[1] in ('Z03','control_engine','weston','connmand','bluetoothd','wpa_supplicant'):
    rows.append((item,identity(item[2]) if item[1] in ('Z03','control_engine') else None))
  except (OSError,ValueError):continue
 pending=None
 try:pending=meta(os.lstat('/var/volatile/tmp/p011-mta-p2p-device.pending'))
 except OSError as error:
  if error.errno!=errno.ENOENT:raise
 return {'stock':{path:sha(path) for path in PINS},'processes':sorted(rows),
  'boot':read('/proc/sys/kernel/random/boot_id',128),'pending':pending,
  'route':read('/proc/net/route',32768)}
def authenticate_helper():
 anchors=[]
 for path,mode in (('/',None),('/var',0o755),('/var/volatile',0o1777),
     ('/var/volatile/tmp',0o1777),('/var/volatile/tmp/p011-mta-formal-receive-v1',0o700),
     ('/var/volatile/tmp/p011-mta-formal-receive-v1/native',0o700)):
  m=meta(os.lstat(path))
  if (not stat.S_ISDIR(m[2]) or m[3:5]!=(0,0) or
      mode is None and m[2]&0o022 or mode is not None and stat.S_IMODE(m[2])!=mode):raise ValueError('anchor')
  anchors.append((path,m[:5]))
 named=meta(os.lstat(HELPER));fd=None;closed=False
 if (not stat.S_ISREG(named[2]) or stat.S_IMODE(named[2])!=0o500 or
     named[3:6]!=(0,0,1) or named[6]!=HELPER_PIN[0]):raise ValueError('helper_shape')
 try:
  fd=os.open(HELPER,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  held=meta(os.fstat(fd))
  if held!=named:raise ValueError('helper_identity')
  parts=[];count=0
  while count<=HELPER_PIN[0]:
   part=os.read(fd,min(65536,HELPER_PIN[0]+1-count));parts.append(part);count+=len(part)
   if not part:break
  raw=b''.join(parts)
  if ((len(raw),hashlib.sha256(raw).hexdigest())!=HELPER_PIN or
      meta(os.fstat(fd))!=held or meta(os.lstat(HELPER))!=held):raise ValueError('helper_bytes')
 finally:
  if fd is not None:
   os.close(fd)
   try:os.fstat(fd)
   except OSError as error:closed=error.errno==errno.EBADF
 if not closed:raise ValueError('auth_fd_close')
 return tuple(anchors),named,closed
before=snapshot()
if before['stock']!=PINS or any(len([r for r in before['processes'] if r[0][1]==name])!=1
   for name in ('Z03','control_engine','weston')):raise ValueError('stock_identity')
native_before=authenticate_helper()
actors=[];values=[];private=[]
for index in range(2):
 args=['--capabilities','hci0'];value=ns['capability'](HELPER,args,actors=actors)
 if len(actors)!=index+1:raise ValueError('actor_inventory')
 actor=actors[-1]
 known=(ns['_probe_closed'](actor) is True and ns['_probe_result'](actor,value,HELPER,args) is True)
 values.append(value)
 private.append({'raw_stdout':actor['out'],'raw_stderr':actor['err'],'returncode':actor['returncode'],
  'original_result':value,'actor_closed':actor['closed'],'result_owned':known,
  'cleanup_count':len(actor['cleanup_calls']),'cleanup_errors':len(actor['cleanup_failures'])})
 if not known:raise ValueError('new_probe_result_unknown')
 radio.normalize(value)
native_after=authenticate_helper();after=snapshot()
same=before==after and native_before==native_after
matches=radio.matches(values[0],values[1])
print('PRIVATE_PROBE_OBSERVATIONS='+repr({'before':before,'after':after,'native':native_before,'actors':private}))
print('RESULT='+repr({'passed':same and matches,'actual_extracted_functions':4,'actual_native_calls':2,
 'all_original_actors_closed':all(ns['_probe_closed'](row) for row in actors),
 'both_original_results_owned':all(row['result_owned'] for row in private),
 'auth_fd_closed':native_before[2] and native_after[2],
 'stock_and_pending_unchanged':same,'radio_observations_same':matches,
 'host_graph_executed':False,'state_constructed':False,'owner_constructed':False,
 'device_writes':False,'rf_tested':False,'admission':False,'phone_tested':False,
 'full_network_restore_verified':False,'pending_present':before['pending'] is not None}))
'''


def program():
    source = fixed(STATE, STATE_PIN)
    functions = extracted(source)
    text = REMOTE_HEAD + encoded('CODEC', fixed(CODEC, CODEC_PIN)) + encoded('RADIO', fixed(RADIO, RADIO_PIN)) + encoded('FUNCTIONS', functions) + REMOTE_BODY
    ast.parse(text, feature_version=(3, 5))
    if max(len(line.encode('utf-8')) for line in text.splitlines()) > 256:
        raise ValueError('envelope_line_limit')
    return text, functions


def main():
    check_device = sys.argv[1:] == ['--check-device']
    if sys.argv[1:] and not check_device:
        raise ValueError('Only explicit --check-device supported')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-probe-provenance-' + ('device-' if check_device else 'source-') + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-probe-functions-readonly-v1', passed=False,
        evidence_level='P011_EXTRACTED_FUNCTIONS_READONLY' if check_device else 'SOURCE_ONLY',
        device_tested=False, phone_tested=False, rf_tested=False, admission=False,
        full_graph=False, full_network_restore_verified=False, pending_removed=False,
        source_preserved=False, inputs=[], error=None)
    originals = {}
    try:
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            saved = out / 'private-inputs' / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(raw)
            report['inputs'].append(dict(path=name, bytes=len(raw), sha256=digest(raw)))
        fixed(PROBE, PROBE_PIN)
        text, functions = program()
        (out / 'private-program.py').write_bytes(text.encode('utf-8'))
        (out / 'private-extracted-functions.py').write_bytes(functions)
        report['program'] = dict(bytes=len(text.encode('utf-8')), sha256=digest(text.encode('utf-8')))
        report['functions'] = dict(bytes=len(functions), sha256=digest(functions))
        if check_device:
            spec = importlib.util.spec_from_file_location('fixed_probe_transport', str(BASE / PROBE))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # Never call its old main/run_probe.
            adb = module.Adb(out / 'private-raw')
            data = (text + "\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(60);exec(sys.stdin.buffer.read(' +
                str(len(data)) + '))" mta-new-probe-readonly; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            stdout = adb.run('new-probe-functions', ['shell', command], timeout=75, input_data=data)
            normalized = stdout.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            results = [line[7:] for line in normalized.splitlines() if line.startswith('RESULT=')]
            if len(results) != 1 or normalized.splitlines().count('MTA_REMOTE_OK') != 1 or normalized.splitlines().count('MTA_REMOTE_EXIT=0') != 1:
                raise ValueError('remote_markers')
            value = ast.literal_eval(results[0])
            if type(value) is not dict or value.get('passed') is not True:
                raise ValueError('actual_probe_failed')
            report.update(value)
            report['device_tested'] = True
            report['host_exit'] = report['remote_exit'] = 0
            report['stdout'] = dict(bytes=len(stdout), sha256=digest(stdout))
            stderr = (out / 'private-raw/01-new-probe-functions.stderr.raw').read_bytes()
            report['stderr'] = dict(bytes=len(stderr), sha256=digest(stderr))
            if stderr:
                raise ValueError('adb_stderr_nonempty')
        report['source_preserved'] = all((BASE / name).read_bytes() == value for name, value in originals.items())
        report['passed'] = report['source_preserved'] and (not check_device or report.get('both_original_results_owned') is True)
    except Exception as error:
        report['passed'] = False
        report['error'] = type(error).__name__
        (out / 'private-error.txt').write_text(str(error), encoding='utf-8')
    raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    (out / 'result.json').write_bytes(raw)
    note = b'New extracted probe functions only, not State/Owner/full graph. Device mode is metadata/source authentication and two read-only native capability calls, with no staging, UI, RF, network change, phone transfer or old pending handling. Private raw and input snapshots stay local.\n'
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or archive.read('result.json') != raw or archive.read('README.txt') != note:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result=str(out), device_tested=report['device_tested'],
        rf_tested=False, phone_tested=False), ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

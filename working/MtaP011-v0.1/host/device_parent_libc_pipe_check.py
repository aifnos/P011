"""One bounded P011 libc/PIPE check; no Parent, helper, RF or deployment.

The two complete frozen sources are loaded only into private in-memory modules.
Only their _LinuxIo platform validation and actual PIPE operations are exercised.
Raw outputs and source snapshots remain local; the ZIP has two public members.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SOURCE_PINS = {
    'host/device_probe.py': (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    'candidate/go-parent-libc-v1/runtime/mta_go_readonly_parent.py':
        (52873, '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
    'candidate/go-parent-libc-v1/runtime/mta_go_readonly_terminal_parent.py':
        (66973, '42ef91c27805d080f80706097834c6a73e4d5fe7b7683533a60fb33e59025a7a'),
}
PARENT_PATHS = (
    'candidate/go-parent-libc-v1/runtime/mta_go_readonly_parent.py',
    'candidate/go-parent-libc-v1/runtime/mta_go_readonly_terminal_parent.py',
)
STOCK_PINS = {
    '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b',
}
LANE_FIELDS = ('source_loaded', 'platform_validated', 'nonblock_validated',
               'empty_eagain', 'bytes_roundtrip', 'actual_eof', 'get_ebadf', 'set_ebadf')
BOOL_FIELDS = (
    'before_baseline_observed', 'after_baseline_observed', 'stock_hashes_match',
    'stock_processes_match', 'stock_hashes_unchanged', 'processes_unchanged',
    'boot_unchanged', 'pending_unchanged', 'routes_unchanged', 'netdev_unchanged',
    'baseline_unchanged', 'all_four_pipe_fds_closed', 'complete', 'resource_pending',
) + tuple(lane + '_' + field for lane in ('ordinary', 'terminal') for field in LANE_FIELDS)
COUNT_FIELDS = ('opened_fd_count', 'close_attempt_count', 'closed_fd_count')
REASONS = (
    'not_started', 'complete', 'deadline', 'invalid', 'source_pin', 'stock_baseline',
    'baseline_changed', 'pipe_metadata', 'pipe_flags', 'pipe_eagain', 'pipe_data',
    'pipe_eof', 'pipe_ebadf', 'pipe_close', 'parent_platform', 'parent_unvalidated',
    'parent_fcntl_input', 'parent_fcntl_return', 'parent_fcntl_errno', 'unexpected',
)
FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS + ('reason',))

TARGET_BODY = r'''
import base64,errno,hashlib,os,re,stat,sys,time,types,zlib
until=time.monotonic()+15.0
rows=[];modules=[];allocation_unknown=False;failure=None;before=None;after=None
result=dict((key,False) for key in BOOL_FIELDS)
result.update(dict((key,0) for key in COUNT_FIELDS));result['reason']='not_started'
def check():
 if time.monotonic()>=until:raise ValueError('deadline')
def read(path,limit):
 check()
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  value=os.read(fd,limit+1)
  if len(value)>limit:raise ValueError('invalid')
  return value
 finally:os.close(fd)
def metadata(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
         value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def fingerprint(path,limit):
 check();initial=os.lstat(path)
 if not stat.S_ISREG(initial.st_mode) or initial.st_uid!=0 or initial.st_nlink!=1:
  raise ValueError('invalid')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  if metadata(os.fstat(fd))!=metadata(initial):raise ValueError('invalid')
  digest=hashlib.sha256();count=0
  while True:
   check();block=os.read(fd,65536)
   if not block:break
   count+=len(block)
   if count>limit:raise ValueError('invalid')
   digest.update(block)
  if count!=initial.st_size or metadata(os.fstat(fd))!=metadata(initial):
   raise ValueError('invalid')
  if metadata(os.lstat(path))!=metadata(initial):raise ValueError('invalid')
  return (count,digest.hexdigest(),metadata(initial))
 finally:os.close(fd)
def pending():
 path='/var/volatile/tmp/p011-mta-p2p-device.pending'
 try:initial=os.lstat(path)
 except OSError as error:
  if type(error.errno) is int and error.errno==errno.ENOENT:return None
  raise
 if initial.st_mode&0o077:raise ValueError('invalid')
 return fingerprint(path,65536)
def process_identity(pid):
 raw=read('/proc/'+str(pid)+'/stat',4096);at=raw.rindex(b')')
 fields=raw[at+2:].split()
 if len(fields)<20 or not fields[1].isdigit() or not fields[19].isdigit():
  raise ValueError('invalid')
 return (pid,int(fields[1]),int(fields[19]),raw[raw.index(b'(')+1:at],
         os.readlink('/proc/'+str(pid)+'/exe'))
def processes():
 names=os.listdir('/proc')
 if len(names)>4096:raise ValueError('invalid')
 tracked=(b'Z03',b'control_engine',b'weston',b'connmand',b'bluetoothd',b'wpa_supplicant')
 output=[];races=0
 pids=sorted(int(name) for name in names if name.isdigit())
 if len(pids)>512:raise ValueError('invalid')
 for pid in pids:
  if pid==os.getpid():continue
  try:
   raw=read('/proc/'+str(pid)+'/stat',4096);at=raw.rindex(b')')
   if raw[raw.index(b'(')+1:at] not in tracked:continue
   row=process_identity(pid);parent=process_identity(row[1])
   if process_identity(pid)!=row or process_identity(row[1])!=parent:
    raise ValueError('invalid')
   output.append((row,parent))
  except OSError as error:
   if type(error.errno) is int and error.errno in (errno.ENOENT,errno.ESRCH):
    races+=1
    if races>32:raise ValueError('invalid')
   else:raise
 return tuple(output)
def stock_processes_match(observed):
 names=(b'Z03',b'control_engine',b'weston')
 return (all(len([entry for entry in observed if entry[0][3]==name])==1 for name in names)
  and all(entry[0][4]=='/usr/bin/'+entry[0][3].decode('ascii') for entry in observed
          if entry[0][3] in (b'Z03',b'control_engine')))
def netdev():
 names=sorted(os.listdir('/sys/class/net'))
 if len(names)>64:raise ValueError('invalid')
 output=[]
 for name in names:
  if type(name) is not str or not name or len(name)>15 or '/' in name:
   raise ValueError('invalid')
  raw=read('/sys/class/net/'+name+'/ifindex',32).strip()
  if not raw.isdigit() or not 0<int(raw)<=0x7fffffff:raise ValueError('invalid')
  output.append((name,int(raw)))
 return tuple(output)
def snapshot():
 check()
 hashes=tuple((path,fingerprint(path,134217728)) for path in sorted(STOCK_PINS))
 return dict(stock=hashes,boot=read('/proc/sys/kernel/random/boot_id',128),
             pending=pending(),routes=read('/proc/net/route',1048576),
             netdev=netdev(),processes=processes())
def stock_match(observed):
 return dict((path,row[1]) for path,row in observed['stock'])==STOCK_PINS
def pipe_meta(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
         value.st_nlink,value.st_rdev)
def closed_probe(io,fd):
 try:io.fstat(fd)
 except OSError as error:
  return type(error.errno) is int and error.errno==errno.EBADF
 return False
def close_row(row):
 if row['close_attempted']:return row['closed']
 row['close_attempted']=True
 try:
  io=row['io'];fd=row['fd']
  if row['identity'] is not None and pipe_meta(io.fstat(fd))!=row['identity']:
   raise ValueError('pipe_close')
  row['close_called']=True
  returned=io.close(fd)
  row['closed']=returned is None and closed_probe(io,fd)
  if not row['closed']:raise ValueError('pipe_close')
  return True
 except BaseException as error:
  row['close_error']=error
  raise
def typed_fcntl_ebadf(action):
 try:action()
 except OSError as error:
  return (type(error.errno) is int and error.errno==errno.EBADF and
          type(getattr(error,'fcntl_result',None)) is int and error.fcntl_result==-1 and
          type(getattr(error,'fcntl_errno',None)) is int and error.fcntl_errno==errno.EBADF)
 return False
def load_parent(lane,pin,encoded):
 check();raw=zlib.decompress(base64.b64decode(encoded.encode('ascii'),validate=True))
 if (len(raw),hashlib.sha256(raw).hexdigest())!=pin:raise ValueError('source_pin')
 module=types.ModuleType('p011_parent_libc_pipe_diagnostic_'+lane)
 module.__file__='<p011-parent-libc-pipe-'+lane+'>'
 modules.append(module)
 exec(compile(raw,module.__file__,'exec'),module.__dict__)
 result[lane+'_source_loaded']=True
 return module
def trial(lane,module):
 global allocation_unknown
 check();io=module._LinuxIo();io.validate();result[lane+'_platform_validated']=True
 pair=os.pipe()
 allocation_unknown=True
 known=[]
 for fd in pair:
  if type(fd) is int and 0<=fd<=0x7fffffff:
   row=dict(io=io,fd=fd,identity=None,close_attempted=False,close_called=False,
            closed=False,close_error=None)
   rows.append(row);known.append(row)
 if type(pair) is not tuple or len(pair)!=2 or len(known)!=2 or pair[0]==pair[1]:
  raise ValueError('pipe_metadata')
 allocation_unknown=False
 local_failure=None
 try:
  for row in known:
   check();value=io.fstat(row['fd']);row['identity']=pipe_meta(value)
   if not stat.S_ISFIFO(value.st_mode):raise ValueError('pipe_metadata')
  if known[0]['identity'][:2]!=known[1]['identity'][:2]:raise ValueError('pipe_metadata')
  rfd,wfd=pair;original=(io.flags(rfd),io.flags(wfd))
  if original[0]&os.O_ACCMODE!=os.O_RDONLY or original[1]&os.O_ACCMODE!=os.O_WRONLY:
   raise ValueError('pipe_flags')
  for fd,flags in zip(pair,original):
   check();returned=io.set_flags(fd,flags|os.O_NONBLOCK)
   if type(returned) is not int or returned!=0 or io.flags(fd)!=flags|os.O_NONBLOCK:
    raise ValueError('pipe_flags')
  result[lane+'_nonblock_validated']=True
  check()
  try:io.read(rfd,1)
  except OSError as error:
   result[lane+'_empty_eagain']=(type(error.errno) is int and
                              error.errno in (errno.EAGAIN,errno.EWOULDBLOCK))
  if not result[lane+'_empty_eagain']:raise ValueError('pipe_eagain')
  data=b'P011_LIBC_PIPE';check()
  written=io.write(wfd,data) if lane=='terminal' else os.write(wfd,data)
  if type(written) is not int or written!=len(data) or io.read(rfd,len(data))!=data:
   raise ValueError('pipe_data')
  result[lane+'_bytes_roundtrip']=True
  close_row(known[1]);check()
  result[lane+'_actual_eof']=io.read(rfd,1)==b''
  if not result[lane+'_actual_eof']:raise ValueError('pipe_eof')
  result[lane+'_get_ebadf']=typed_fcntl_ebadf(lambda:io.flags(wfd))
  result[lane+'_set_ebadf']=typed_fcntl_ebadf(lambda:io.set_flags(wfd,original[1]|os.O_NONBLOCK))
  if not result[lane+'_get_ebadf'] or not result[lane+'_set_ebadf']:
   raise ValueError('pipe_ebadf')
 except BaseException as error:
  local_failure=error
 finally:
  for row in reversed(known):
   if not row['close_attempted']:
    try:close_row(row)
    except BaseException as error:
     if local_failure is None:local_failure=error
 if local_failure is not None:raise local_failure
try:
 before=snapshot();result['before_baseline_observed']=True
 if not stock_match(before) or not stock_processes_match(before['processes']):
  raise ValueError('stock_baseline')
 for lane,pin,encoded in MODULE_ROWS:
  trial(lane,load_parent(lane,pin,encoded))
except BaseException as error:
 if failure is None:failure=error
finally:
 for row in reversed(rows):
  if not row['close_attempted']:
   try:close_row(row)
   except BaseException as error:
    if failure is None:failure=error
 try:
  after=snapshot();result['after_baseline_observed']=True
 except BaseException as error:
  if failure is None:failure=error
result['opened_fd_count']=len(rows)
result['close_attempt_count']=sum(row['close_called'] for row in rows)
result['closed_fd_count']=sum(row['closed'] for row in rows)
result['all_four_pipe_fds_closed']=len(rows)==4 and all(row['closed'] for row in rows)
result['resource_pending']=allocation_unknown or any(not row['closed'] for row in rows)
if before is not None and after is not None:
 result['stock_hashes_match']=stock_match(before) and stock_match(after)
 result['stock_processes_match']=stock_processes_match(before['processes']) and stock_processes_match(after['processes'])
 for field,key in (('stock_hashes_unchanged','stock'),('processes_unchanged','processes'),
                   ('boot_unchanged','boot'),('pending_unchanged','pending'),
                   ('routes_unchanged','routes'),('netdev_unchanged','netdev')):
  result[field]=before[key]==after[key]
 result['baseline_unchanged']=all(result[field] for field in (
  'stock_hashes_match','stock_processes_match','stock_hashes_unchanged','processes_unchanged',
  'boot_unchanged','pending_unchanged','routes_unchanged','netdev_unchanged'))
required=tuple(key for key in BOOL_FIELDS if key not in ('complete','resource_pending'))
result['complete']=failure is None and all(result[key] for key in required) and not result['resource_pending']
if failure is not None:
 reason=str(failure)
 result['reason']=reason if reason in REASONS else 'unexpected'
elif result['complete']:result['reason']='complete'
else:result['reason']='baseline_changed'
print('RESULT='+repr(result))
'''


def make_source(inputs):
    lines = ['STOCK_PINS=' + repr(STOCK_PINS), 'BOOL_FIELDS=' + repr(BOOL_FIELDS),
             'COUNT_FIELDS=' + repr(COUNT_FIELDS), 'REASONS=' + repr(REASONS), 'MODULE_ROWS=(']
    for lane, path in zip(('ordinary', 'terminal'), PARENT_PATHS):
        encoded = base64.b64encode(zlib.compress(inputs[path])).decode('ascii')
        lines.append('    (' + repr(lane) + ', ' + repr(SOURCE_PINS[path]) + ', (')
        lines.extend('        ' + repr(encoded[offset:offset + 1024])
                     for offset in range(0, len(encoded), 1024))
        lines.append('    )),')
    lines.append(')')
    program = '\n'.join(lines) + '\n' + TARGET_BODY + "\nprint('MTA_REMOTE_OK')\n"
    raw = program.encode('ascii')
    if len(raw) > 65536 or any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return program


def load_transport(raw):
    module = types.ModuleType('p011_parent_libc_pipe_host_transport')
    module.__file__ = str(BASE / 'host/device_probe.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if Path(module.ADB).resolve() != Path('C:/Program Files/ADB/adb.exe').resolve() or module.PINS != STOCK_PINS:
        raise ValueError('transport_identity')
    return module


def parse_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    results = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
    if len(remote) != 1 or int(remote[0]) != 0 or derived.splitlines().count('MTA_REMOTE_OK') != 1 or len(results) != 1:
        raise ValueError('remote_result_unknown')
    value = ast.literal_eval(results[0])
    if (type(value) is not dict or set(value) != FIELDS or
            any(type(value[key]) is not bool for key in BOOL_FIELDS) or
            any(type(value[key]) is not int or not 0 <= value[key] <= 4 for key in COUNT_FIELDS) or
            type(value['reason']) is not str or value['reason'] not in REASONS):
        raise ValueError('result_fields')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true', required=True)
    parser.parse_args()
    inputs = {}
    out = BASE / 'results' / ('parent-libc-pipe-device-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-parent-libc-pipe-component-v1', passed=False,
        device_invoked=False, remote_status_known=False, remote_exit=None, host_exit=None,
        stdout_bytes=None, stdout_sha256=None, stderr_bytes=None, stderr_sha256=None,
        component_result=None, source_preserved=False, host_error=None,
        platform_projected=False, parent_constructed=False, parent_collect_executed=False,
        candidate_subprocess_executed=False, rf_requested=False, device_file_writes_requested=False,
        pending_removed=False, full_network_restore_verified=False,
        send_available=False, receive_available=False, phone_tested=False, radio_health_verified=False)
    try:
        paths = tuple(SOURCE_PINS) + ('host/device_parent_libc_pipe_check.py', 'TEST_MTA_PARENT_LIBC_PIPE.cmd')
        for name in paths:
            raw = (BASE / name).read_bytes()
            inputs[name] = raw
            destination = out / 'private-inputs' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            if name in SOURCE_PINS and (len(raw), hashlib.sha256(raw).hexdigest()) != SOURCE_PINS[name]:
                raise ValueError('fixed_source_changed')
        program = make_source(inputs)
        data = program.encode('ascii')
        (out / 'private-target-source.py').write_bytes(data)
        # This is the sole HOST target-source syntax check; no Parent AST rerun.
        ast.parse(program, feature_version=(3, 5))
        report['target_source_sha256'] = hashlib.sha256(data).hexdigest()
        report['target_source_bytes'] = len(data)
        transport = load_transport(inputs['host/device_probe.py'])
        adb = transport.Adb(private)
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(20);'
            'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-parent-libc-pipe-check; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        report['device_invoked'] = True
        raw = adb.run('parent-libc-pipe', ['shell', command], timeout=30, input_data=data)
        value = parse_result(raw)
        report.update(remote_status_known=True, remote_exit=0, host_exit=0, component_result=value)
    except Exception as error:
        report['host_error'] = type(error).__name__
    finally:
        host_exit_path = private / '01-parent-libc-pipe.host-exit'
        if host_exit_path.exists():
            recorded = host_exit_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(recorded) if re.fullmatch(r'-?\d+', recorded) else 'TIMEOUT'
        stdout_path = private / '01-parent-libc-pipe.stdout.raw'
        stderr_path = private / '01-parent-libc-pipe.stderr.raw'
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream + '_bytes'] = len(original)
                report[stream + '_sha256'] = hashlib.sha256(original).hexdigest()
        remote_marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(remote) == 1:
                report['remote_exit'] = int(remote[0])
                report['remote_status_known'] = True
                remote_marker = remote[0]
        (private / '01-parent-libc-pipe.remote-exit').write_text(remote_marker + '\n', encoding='ascii')
        try:
            report['source_preserved'] = (len(inputs) == 5 and all(
                (BASE / name).read_bytes() == raw and (out / 'private-inputs' / name).read_bytes() == raw
                for name, raw in inputs.items()))
        except OSError:
            report['source_preserved'] = False
    value = report['component_result']
    report['passed'] = (report['host_error'] is None and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
        report['remote_status_known'] and report['remote_exit'] == 0 and report['source_preserved'] and
        type(value) is dict and value['complete'] is True and value['resource_pending'] is False and
        all(value[key] for key in BOOL_FIELDS if key not in ('resource_pending',)) and
        all(value[key] == 4 for key in COUNT_FIELDS))
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One P011 libc/PIPE component check only. Two complete pinned sources in isolated '
        b'in-memory non-main modules; real platform validation and two actual pipes/four original FDs. '
        b'NONBLOCK/EAGAIN/data/EOF/GET-SET EBADF and once-close observed facts only. '
        b'Before-after stock hashes, six tracked process identities/parents, boot, pending digest, '
        b'route bytes and interface names/ifindex; no traffic-counter equality or full network restoration claim. '
        b'No Parent construction/collect, candidate Popen, helper/RF, staging, device file writes, '
        b'pending removal or phone interoperability. The 20s target alarm precedes stdin read; '
        b'30s HOST timeout or missing remote markers never proves FD closure. '
        b'Raw stdout/stderr/remote-host exits and exact source snapshots remain local private.\n')
    (out / 'result.json').write_bytes(public)
    (out / 'README.txt').write_bytes(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

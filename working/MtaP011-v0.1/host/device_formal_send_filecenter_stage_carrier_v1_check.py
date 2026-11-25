"""Explicit legacy-ADB carrier stage; default checks fixed PC artifacts only.

No large bytes are sent to PTY stdin. Two fixed files are pushed to one fresh
EXCL project directory. The exact launcher binds regular stdin to the verified
wire FD. Carrier and partial stage assets are retained; no automatic cleanup,
Boot/Owner/helper/UI/RF start, CLIENT/pending handling or old SOURCE regeneration.
"""
import argparse
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
LOCAL_HELPER = ('host/device_formal_send_filecenter_stage_v1_check.py', 22495,
                '68cdbacc1f9a33e61fcdbe603b183909092f2a93c4f7dfcd82a92e2e98b4f145')
SELF = 'host/device_formal_send_filecenter_stage_carrier_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_STAGE_CARRIER_V1.cmd'
PROFILES = ('sender', 'observer', 'ordinary')
FILE_MODES = (0o600, 0o640, 0o644, 0o660, 0o664, 0o666)
ERROR_CODES = frozenset(('input_pin', 'source_result', 'source_budget', 'transport_pin',
    'stock_baseline', 'stock_changed', 'carrier_result', 'carrier_files', 'remote_result',
    'remote_status_unknown', 'stage_refused', 'host_transport', 'source_changed', 'unexpected'))

# Small fixed target source, transmitted as a bounded compressed shell command.
# No arbitrary source/path/command input is accepted by this HOST entry.
CARRIER_BODY = r'''
import errno,hashlib,os,signal,stat,sys,time
signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(20)
started=time.monotonic();whole_until=started+200.0
rows=[];edges=[];aliases=[];failure=None;created=False;original_root=None;timer_may_clear=True
files=[];files_stable=False;stdin_handle=None;stdin_expected=None;stdin_closed=False
result=None
def need(v):
 if not v:raise ValueError('carrier_invalid')
def meta(v):
 return (v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,
         v.st_size,v.st_mtime_ns,v.st_ctime_ns)
def hold(parent,name,flags):
 row=dict(fd=None,called=True,returned=False,unknown=True,closed=False,closing=False,meta=None)
 rows.append(row)
 try:
  fd=os.open(name,flags|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  row['fd']=fd;row['returned']=True;row['meta']=meta(os.fstat(fd))
  need(type(fd)is int and fd>2 and not any(x is not row and x['returned'] and
       not x['closed'] and x['fd']==fd for x in rows));row['unknown']=False
 except OSError:
  if not row['returned']:row['unknown']=False;row['closed']=True
  raise
 return row
def close(row):
 if row['closing']:return row['closed'] and not row['unknown']
 if not row['returned']:return row['closed'] and not row['unknown']
 if row['unknown']:return False
 row['closing']=True
 try:
  need(meta(os.fstat(row['fd']))[:5]==row['meta'][:5]);os.close(row['fd'])
  try:os.fstat(row['fd'])
  except OSError as e:need(e.errno==errno.EBADF);row['closed']=True
  else:row['unknown']=True
 except BaseException:row['unknown']=True
 return row['closed'] and not row['unknown']
def current():
 for p,m,t in aliases:need(meta(os.lstat(p))==m and os.readlink(p)==t)
 for parent,name,row in edges:
  need(meta(os.fstat(row['fd']))[:5]==row['meta'][:5])
  need(meta(os.stat(name,dir_fd=parent,follow_symlinks=False))[:5]==row['meta'][:5])
def directory(parent,name,mode):
 before=meta(os.stat(name,dir_fd=parent,follow_symlinks=False))
 need(before[2]==stat.S_IFDIR|mode and before[3:5]==(0,0))
 row=hold(parent,name,os.O_RDONLY|os.O_DIRECTORY)
 need(row['meta']==before);edges.append((parent,name,row));current();return row
def parents():
 for p,t in (('/tmp','/var/tmp'),('/var/tmp','/var/volatile/tmp')):
  m=meta(os.lstat(p));need(m[2]==stat.S_IFLNK|0o777 and m[3:6]==(0,0,1)
       and m[6]==len(t) and os.readlink(p)==t);aliases.append((p,m,t))
 row=directory(None,'/',0o755)
 for name,mode in (('var',0o755),('volatile',0o1777),('tmp',0o1777)):
  row=directory(row['fd'],name,mode)
 return row
def read_file(root,name,pin):
 current();before=meta(os.stat(name,dir_fd=root['fd'],follow_symlinks=False))
 need(stat.S_ISREG(before[2]) and stat.S_IMODE(before[2]) in FILE_MODES and
      before[3:7]==(0,0,1,pin[0]))
 row=hold(root['fd'],name,os.O_RDONLY|os.O_NONBLOCK)
 need(row['meta']==before);h=hashlib.sha256();count=0;parts=[]
 while True:
  b=os.read(row['fd'],65536)
  if not b:break
  count+=len(b);need(count<=pin[0]);h.update(b)
  if name=='bootstrap.py':parts.append(b)
 need(count==pin[0] and h.hexdigest()==pin[1] and meta(os.fstat(row['fd']))==before
      and meta(os.stat(name,dir_fd=root['fd'],follow_symlinks=False))==before)
 files.append((name,before));current();return row,b''.join(parts)
try:
 tmp=parents();current()
 if MODE=='create':
  try:os.stat(LEAF,dir_fd=tmp['fd'],follow_symlinks=False)
  except OSError as e:need(e.errno==errno.ENOENT)
  else:raise ValueError('carrier_exists')
  need(os.mkdir(LEAF,0o700,dir_fd=tmp['fd'])is None);created=True
  root=directory(tmp['fd'],LEAF,0o700);need(os.listdir(root['fd'])==[])
 else:
  root=directory(tmp['fd'],LEAF,0o700);need(root['meta'][:5]==EXPECTED_ROOT[:5])
  need(sorted(os.listdir(root['fd']))==['bootstrap.py','wire.raw'])
 original_root=root['meta'];current()
 if MODE!='create':
  source_row,source=read_file(root,'bootstrap.py',BOOTSTRAP_PIN)
  wire_row,unused=read_file(root,'wire.raw',WIRE_PIN)
  if EXPECTED_FILES is not None:need(tuple(files)==EXPECTED_FILES)
  need(close(source_row));need(close(wire_row)if MODE=='inspect'else True)
  if MODE=='launch':
   # No shell redirection race: original held NOFOLLOW wire FD becomes fd0.
   need(os.lseek(wire_row['fd'],0,os.SEEK_SET)==0)
   stdin_handle=sys.stdin;stdin_expected=wire_row['meta']
   dup_return=os.dup2(wire_row['fd'],0)
   need(dup_return is None and meta(os.fstat(0))==stdin_expected)
   signal.alarm(0)
   timer_may_clear=False
   namespace={'__name__':'formal_send_filecenter_carrier_fixed_entry'}
   try:exec(compile(source,'<fixed-formal-send-carrier-bootstrap>','exec'),namespace)
   except BaseException as e:failure=e
   # Do not erase an unknown bootstrap timer. Only a known-zero timer allows
   # the bounded post-readcheck under the SAME original 200s launcher period.
   need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0))
   remaining=whole_until-time.monotonic();need(0<remaining<=200.0)
   signal.setitimer(signal.ITIMER_REAL,remaining)
   timer_may_clear=True
   need(meta(os.fstat(0))==stdin_expected)
   check_source,unused=read_file(root,'bootstrap.py',BOOTSTRAP_PIN);need(close(check_source))
   check_wire,unused=read_file(root,'wire.raw',WIRE_PIN);need(close(check_wire))
   need(tuple(files[:2])==tuple(files[2:]) and meta(os.fstat(root['fd']))==original_root)
  current();need(os.lseek(root['fd'],0,os.SEEK_SET)==0)
  need(sorted(os.listdir(root['fd']))==['bootstrap.py','wire.raw']and
       meta(os.fstat(root['fd']))==original_root)
  for name,m in files:need(meta(os.stat(name,dir_fd=root['fd'],follow_symlinks=False))==m)
  files_stable=True
 result={'carrier_created':created,'root_metadata':original_root,
         'files':tuple(files[:2]),'files_stable':files_stable}
except BaseException as e:
 if failure is None:failure=e
finally:
 if stdin_handle is not None:
  try:
   need(meta(os.fstat(0))==stdin_expected);stdin_handle.close()
   need(meta(os.fstat(0))==stdin_expected);need(os.close(0)is None)
   try:os.fstat(0)
   except OSError as e:need(e.errno==errno.EBADF);stdin_closed=True
  except BaseException as e:
   if failure is None:failure=e
 for row in reversed(rows):close(row)
 closed=all(r['closed']and not r['unknown']for r in rows)and(
        stdin_handle is None or stdin_closed)
 if closed and result is not None and timer_may_clear:signal.setitimer(signal.ITIMER_REAL,0.0)
 if result is None:result={'carrier_created':created,'root_metadata':original_root,
                          'files':tuple(files[:2]),'files_stable':False}
 result['resources_closed']=closed;result['opened_fds']=sum(r['returned']for r in rows)
 result['closed_fds']=sum(r['returned']and r['closed']for r in rows)
 result['stdin_regular_verified']=stdin_expected is not None
 result['stdin_closed']=stdin_closed
 print('CARRIER_RESULT='+repr(result))
 if failure is not None:raise failure
 need(closed)
'''


def load_local_helper(inputs):
    path, size, sha = LOCAL_HELPER
    raw = (BASE / path).read_bytes()
    inputs[path] = raw
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('input_pin')
    module = types.ModuleType('formal_send_stage_carrier_local_private')
    module.__file__ = str(BASE / path)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def compressed_command(source):
    encoded = base64.b64encode(zlib.compress(source.encode('ascii'), 9)).decode('ascii')
    command = ('/usr/bin/python3.5 -I -B -c "import base64,zlib;exec(compile(zlib.decompress('
               'base64.b64decode(\'' + encoded + '\')),\'<fixed-stage-carrier>\',\'exec\'))"; r=$?; '
               'printf \'\\nMTA_CARRIER_REMOTE_EXIT=%s\\n\' "$r"')
    # This bounded shell argument is NOT PTY stdin or a source/wire payload.
    # Reserve room for actual nine-field metadata and generated nonce bytes.
    if len(command.encode('ascii')) > 4096:
        raise ValueError('source_budget')
    return command


def target_source(mode, leaf, row, root=None, files=None):
    if (mode not in ('create', 'launch', 'inspect') or
            re.fullmatch(r'p011-mta-stage-carrier-v1-[0-9a-f]{24}', leaf) is None):
        raise ValueError('unexpected')
    body = '\n'.join(line for line in CARRIER_BODY.splitlines() if not line.lstrip().startswith('#')) + '\n'
    return ('MODE=' + repr(mode) + '\nLEAF=' + repr(leaf) + '\nFILE_MODES=' + repr(FILE_MODES) +
            '\nBOOTSTRAP_PIN=' + repr(row[3:5]) + '\nWIRE_PIN=' + repr(row[5:7]) +
            '\nEXPECTED_ROOT=' + repr(root) + '\nEXPECTED_FILES=' + repr(files) + '\n' + body)


def carrier_result(raw, phase):
    text = raw.decode('ascii', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')
    selected = [line[len('CARRIER_RESULT='):] for line in text.splitlines() if line.startswith('CARRIER_RESULT=')]
    if len(selected) != 1 or len(selected[0]) > 8192:
        raise ValueError('carrier_result')
    value = __import__('ast').literal_eval(selected[0])
    fields = {'carrier_created', 'root_metadata', 'files', 'files_stable', 'resources_closed',
              'opened_fds', 'closed_fds', 'stdin_regular_verified', 'stdin_closed'}
    if (type(value) is not dict or set(value) != fields or
        any(type(value[key]) is not bool for key in ('carrier_created', 'files_stable',
            'resources_closed', 'stdin_regular_verified', 'stdin_closed')) or
        any(type(value[key]) is not int or not 0 <= value[key] <= 32 for key in ('opened_fds', 'closed_fds')) or
        type(value['root_metadata']) is not tuple or len(value['root_metadata']) != 9 or
        any(type(number) is not int for number in value['root_metadata']) or type(value['files']) is not tuple or
        len(value['files']) != (0 if phase == 'create' else 2)):
        raise ValueError('carrier_result')
    if phase != 'create':
        for item, name in zip(value['files'], ('bootstrap.py', 'wire.raw')):
            if (type(item) is not tuple or len(item) != 2 or item[0] != name or
                type(item[1]) is not tuple or len(item[1]) != 9 or any(type(n) is not int for n in item[1])):
                raise ValueError('carrier_result')
    return value


def run_target(helper, adb, private, label, source, timeout):
    command = compressed_command(source)
    helper.write_new(private / (label + '.source.private.py'), source.encode('ascii'))
    helper.write_new(private / (label + '.command.private'), command.encode('ascii'))
    stem = '%02d-%s' % (adb.index + 1, label)
    error = None
    try:
        adb.run(label, ['shell', command], timeout=timeout)
    except BaseException as caught:
        error = caught
    receipt, raw = helper.raw_receipt(private, stem, 'MTA_CARRIER_REMOTE_EXIT')
    return receipt, raw, error


def baseline(helper, adb, transport, private, phase, report):
    source = transport.source()
    # Prevent the pinned Adb.python large-stdin fallback on this legacy device.
    encoded = base64.b64encode(zlib.compress(source.encode('utf-8'))).decode('ascii')
    original_command = ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
                        encoded + '\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    helper.need(len(original_command) <= 3500, 'source_budget')
    label = 'stock-' + phase
    stem = '%02d-%s' % (adb.index + 1, label)
    try:
        value = transport.Adb.python(adb, label, source, timeout=45)
        helper.stock_identity(value, transport.PINS)
        helper.write_new(private / (label + '.private.json'),
                         (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report['wifi_connected_' + phase] = value['capabilities']['wifi_connected']
    finally:
        report['baseline_' + phase + '_receipt'], ignored = helper.raw_receipt(private, stem, 'MTA_REMOTE_EXIT')
    receipt = report['baseline_' + phase + '_receipt']
    helper.need(receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0, 'stock_baseline')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=PROFILES)
    args = parser.parse_args()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('formal-send-filecenter-stage-carrier-v1-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}
    helper = adb = transport = before = after = root = launch = None
    report = dict(kind='formal-send-filecenter-stage-carrier-v1', passed=False,
        mode='stage' if args.stage else 'local', profile=args.stage, local_inputs_verified=False,
        source_preserved=False, input_count=0, error_code=None, stock_identity_ok=None,
        stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        baseline_before_receipt=None, baseline_after_receipt=None, carrier_create_receipt=None,
        carrier_launch_receipt=None, carrier_after_receipt=None, push_receipts=[],
        carrier_created=False, carrier_created_files=0, carrier_files_verified=False,
        carrier_files_stable=False, carrier_resources_closed=False, carrier_file_modes=None,
        carrier_execution_unknown=False, stage_invoked=False, stage_execution_unknown=False,
        stage_result=None, bootstrap_result=None, legacy_pty_command_only=True,
        boot_owner_or_rf_requested=False, physical_stdin_eof_verified=False,
        retained_carrier=True, partial_inventory_policy='preserve-no-retry')
    try:
        helper = load_local_helper(inputs)
        payloads = helper.local_inputs(inputs)
        helper.read_input(inputs, SELF)
        helper.read_input(inputs, CMD)
        report['local_inputs_verified'] = True
        for path, raw in inputs.items():
            helper.write_new(out / 'private-inputs' / path, raw)
        if args.stage:
            row = next(row for row in helper.PROFILES if row[0] == args.stage)
            transport = helper.load_transport(inputs[helper.TRANSPORT[0]])
            adb = transport.Adb(private)
            before = baseline(helper, adb, transport, private, 'before', report)
            report['stock_identity_ok'] = helper.stock_identity(before, transport.PINS)
            helper.need(report['stock_identity_ok'], 'stock_baseline')
            leaf = 'p011-mta-stage-carrier-v1-' + secrets.token_hex(12)
            remote_root = '/var/volatile/tmp/' + leaf
            helper.write_new(private / 'carrier-root.private', remote_root.encode('ascii'))
            report['carrier_execution_unknown'] = True
            receipt, raw, error = run_target(helper, adb, private, 'carrier-create',
                                           target_source('create', leaf, row), 30)
            report['carrier_create_receipt'] = receipt
            root = carrier_result(raw, 'create')
            helper.write_new(private / 'carrier-create.private.json',
                             (json.dumps(root, sort_keys=True) + '\n').encode('ascii'))
            report['carrier_created'] = root['carrier_created']
            helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and root['carrier_created'] and
                root['resources_closed'] and root['opened_fds'] == root['closed_fds'], 'carrier_result')
            report['carrier_execution_unknown'] = False
            program, wire = payloads[args.stage]
            for name, data in (('bootstrap.py', program), ('wire.raw', wire)):
                local = private / 'carrier-inputs' / name
                helper.write_new(local, data)
                label = 'push-' + name.split('.')[0]
                stem = '%02d-%s' % (adb.index + 1, label)
                try:
                    adb.run(label, ['push', str(local), remote_root + '/' + name], timeout=45)
                finally:
                    push_receipt, ignored = helper.raw_receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
                    report['push_receipts'].append(push_receipt)
                # adb push may emit transfer progress on stderr. Its exact
                # bytes are retained; the target independently verifies SHA.
                helper.need(push_receipt['host_exit'] == 0 and local.read_bytes() == data, 'carrier_files')
            report['carrier_created_files'] = 2
            report['stage_invoked'] = report['stage_execution_unknown'] = True
            receipt, raw, error = run_target(helper, adb, private, 'carrier-launch',
                target_source('launch', leaf, row, root['root_metadata']), 210)
            report['carrier_launch_receipt'] = receipt
            launch = carrier_result(raw, 'launch')
            helper.write_new(private / 'carrier-launch.private.json',
                             (json.dumps(launch, sort_keys=True) + '\n').encode('ascii'))
            report['carrier_files_verified'] = True
            report['carrier_resources_closed'] = launch['resources_closed']
            report['carrier_files_stable'] = launch['files_stable']
            report['carrier_file_modes'] = [item[1][2] & 0o7777 for item in launch['files']]
            stage, bootstrap, ignored = helper.parse_results(raw, args.stage)
            report['stage_result'], report['bootstrap_result'] = stage, bootstrap
            if type(receipt['host_exit']) is int and receipt['remote_status_known']:
                report['stage_execution_unknown'] = False
            helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and
                launch['resources_closed'] and launch['files_stable'] and launch['stdin_regular_verified'] and
                launch['stdin_closed'] and helper.completed(stage, bootstrap, row), 'stage_refused')
    except BaseException as error:
        report['error_code'] = error.args[0] if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERROR_CODES) else (
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        if helper is not None and adb is not None:
            # Readonly check only. No re-launch, deletion or permission changes.
            if root is not None and report['carrier_created']:
                try:
                    receipt, raw, error = run_target(helper, adb, private, 'carrier-after',
                        target_source('inspect', leaf, row, root['root_metadata'],
                                      launch['files'] if launch is not None else None), 30)
                    report['carrier_after_receipt'] = receipt
                    value = carrier_result(raw, 'inspect')
                    helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                        receipt['remote_status_known'] and receipt['remote_exit'] == 0 and value['files_stable'] and
                        value['resources_closed'] and (launch is None or value['files'] == launch['files']), 'carrier_files')
                    if launch is not None:
                        report['carrier_files_stable'] = report['carrier_files_stable'] and value['files_stable']
                except BaseException:
                    report['carrier_files_stable'] = False
                    if report['error_code'] is None:
                        report['error_code'] = 'carrier_files'
            try:
                after = baseline(helper, adb, transport, private, 'after', report)
                report['stock_identity_ok'] = before is not None and helper.stock_identity(before, transport.PINS) and \
                    helper.stock_identity(after, transport.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                helper.need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None:
                    report['error_code'] = 'stock_baseline'
        inventory = {}
        preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                destination = out / 'private-inputs' / path
                if not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open('xb') as handle:
                        if handle.write(raw) != len(raw):
                            raise ValueError('source_changed')
                inventory[path] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                if (BASE / path).read_bytes() != raw or destination.read_bytes() != raw:
                    preserved = False
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        with (out / 'private-inputs.json').open('xb') as handle:
            handle.write((json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = report['local_inputs_verified'] and report['source_preserved'] and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Legacy-ADB explicit carrier-v1; default PC-only fixed SOURCE artifact checks.\n'
        b'An explicit stage creates one EXCL project carrier directory and pushes exactly two fixed files.\n'
        b'Carrier and partial assets are retained. No overwrite/delete/chmod/history repair or retry.\n'
        b'PTY carries bounded commands only; no large source/wire is read from PTY stdin.\n'
        b'Target source FD closes once with EBADF before exec; regular fd0 binds to the held verified wire FD.\n'
        b'Original bootstrap inner120/outer180, initial read20 and HOST210 bounds remain.\n'
        b'Actual stage/bootstrap output and limited stock before/after facts do not grant transfer/restoration.\n'
        b'Carrier adds two device files; this is assets-only, NOT zero device writes.\n'
        b'No Boot/Owner/native helper/UI/RF start, CLIENT/pending action or physical EOF claim.\n'
        b'Raw logs, carrier metadata and source snapshots remain private; ZIP has only result/README.\n')
    for name, raw in (('result.json', result), ('README.txt', readme)):
        with (out / name).open('xb') as handle:
            handle.write(raw)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != readme):
            raise ValueError('source_changed')
    print(json.dumps(dict(passed=report['passed'], mode=report['mode'], result_dir=str(out)), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Fixed real closed MTA UI session; PC-only unless --check-device is explicit.

The already-pinned closed checker is loaded only after identity/byte checks;
its read_fixed/manifest_rows/chunks assemble the same 68 service artifacts.
The copied-vendor UI bundle must already be staged/verified separately. No ELF
is repeated in this <=2 MiB stdin program, no old test/START script is executed.
Only new worker and assembled-envelope syntax checks occur in PC source mode.
Public ZIP has two scalar/fixed-text members; private raw/inputs remain local.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import types
import zipfile


BASE = Path(__file__).resolve().parents[1]
CHECKER = ('host/device_closed_service_check.py', 22984,
           '27710225a5591ee68146fb14c612b93675347f8caf5488464c441b56f975b9a8')
OLD_CMD = ('TEST_MTA_CLOSED_SERVICE.cmd', 262,
           'efb9e2c6bf28d28a7c48aacf2d485dfeccd7e35c04f3ec297362093b327d8980')
WORKER = ('candidate/formal-ui-native-v1/runtime/ui_session.py', 40610,
          '5ab355ea2d710af94854bff6360149638a15c54be11bf4431a36295e8d15368e')
VALIDATOR = ('candidate/formal-ui-native-v1/runtime/ui_assets.py', 10489,
             'e58de146a8274402af0535972b8179f1d7a973320f3437935a29212a962e6507')
SELF = 'host/device_formal_ui_session_v1_check.py'
INPUT_COUNT = 68
BOOL_FIELDS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
               'credentials_removed', 'candidate_exited', 'stock_restored',
               'guardian_exited', 'worker_fds_closed', 'radio_admission',
               'original_ui_exited', 'physical_ui_verified', 'resource_pending')
FIELDS = frozenset(BOOL_FIELDS + ('reason',))
REASONS = ('not_started', 'ui_finished', 'session_failed', 'read_budget', 'boot',
           'pid', 'process_stat', 'pid_changed', 'process_unknown',
           'process_exec_changed', 'boot_changed', 'self_signal',
           'candidate_identity', 'process_did_not_exit', 'process_budget',
           'foreign_candidate', 'process_race_budget', 'stock_file_identity',
           'hash_budget', 'hash_changed', 'pipe_frame', 'pipe_write',
           'pipe_budget', 'private_core_limit', 'inherited_fd_changed',
           'inherited_fd_close', 'guardian_fd_offset', 'guardian_inherited_fd',
           'guardian_stdio', 'inherited_fd_unknown', 'inherited_fd_duplicate',
           'duplicate_close_frame', 'restore_without_close_report',
           'duplicate_candidate_frame', 'candidate_frame', 'guardian_frame',
           'worker_not_stopped', 'candidate_inventory', 'candidate_remains',
           'launcher_missing', 'stock_pins_changed', 'control_changed',
           'guardian_after_write', 'fresh_worker', 'worker_threads', 'source_pin',
           'artifacts', 'assets_identity', 'stop_requested', 'raw_file',
           'raw_write', 'raw_close', 'pipe_fd', 'asset_directory_changed',
           'credentials_changed', 'credentials_remove', 'stock_pins',
           'private_assets_required', 'asset_binding', 'other_ui_trial',
           'stock_identity', 'stock_topology', 'stock_ui', 'stock_launcher',
           'wayland', 'fork_boundary', 'guardian_parent_fd_close',
           'guardian_not_armed', 'guardian_armed_frame', 'rf_gate_open',
           'credential_pair', 'credential_file', 'credential_write',
           'credential_identity', 'credential_close', 'guardian_missing',
           'launcher_not_stopped', 'candidate_start', 'ui_log_identity',
           'ui_writer_close', 'closed_service_changed', 'ui_log_budget',
           'qml_failed', 'qml_ready_timeout', 'guardian_eof_close',
           'guardian_result_frame')
HOST_ERROR_CODES = ('checker_ancestor', 'checker_link', 'checker_file',
                    'checker_identity', 'checker_changed', 'checker_pin',
                    'checker_base', 'fixed_path', 'fixed_ancestor', 'fixed_link',
                    'fixed_file', 'fixed_identity', 'fixed_changed', 'fixed_pin',
                    'input_shared_changed', 'input_count', 'manifest_schema',
                    'manifest_row', 'payload_budget', 'target_source_budget',
                    'transport_identity', 'remote_result_unknown', 'result_fields',
                    'zip_readback')
SUCCESS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
           'credentials_removed', 'candidate_exited', 'stock_restored',
           'guardian_exited', 'worker_fds_closed', 'original_ui_exited')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def load_checker():
    # Bootstrap only this one literal path, before executing its trusted helper.
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('checker_ancestor')
    path = BASE
    for part in CHECKER[0].split('/'):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('checker_link')
        if path != BASE / CHECKER[0] and not stat.S_ISDIR(value.st_mode):
            raise ValueError('checker_ancestor')
    before = _meta(value)
    if not stat.S_ISREG(value.st_mode) or value.st_size != CHECKER[1]:
        raise ValueError('checker_file')
    with path.open('rb') as handle:
        opened = _meta(os.fstat(handle.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not same:
            raise ValueError('checker_identity')
        raw = handle.read(CHECKER[1] + 1)
        if _meta(os.fstat(handle.fileno())) != opened:
            raise ValueError('checker_changed')
    if _meta(path.lstat()) != before:
        raise ValueError('checker_changed')
    if (len(raw), digest(raw)) != CHECKER[1:]:
        raise ValueError('checker_pin')
    checker = types.ModuleType('fixed_formal_ui_host_inputs')
    checker.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), checker.__dict__)
    if checker.BASE != BASE:
        raise ValueError('checker_base')
    return checker, raw


TARGET_END = r'''
import base64,hashlib,re,types,zlib
def fixed_error_details(errors):
 rows=[];seen=set()
 for error in errors:
  if len(rows)>=16:break
  if not isinstance(error,BaseException) or id(error) in seen:continue
  seen.add(id(error))
  if type(error) is session.UiSessionError:kind='UiSessionError'
  elif isinstance(error,OSError):kind='OSError'
  else:
   kind='Exception'
   for cls,name in ((ValueError,'ValueError'),(RuntimeError,'RuntimeError'),
                    (TypeError,'TypeError'),(AttributeError,'AttributeError'),
                    (KeyError,'KeyError'),(IndexError,'IndexError'),
                    (AssertionError,'AssertionError'),(ImportError,'ImportError'),
                    (SyntaxError,'SyntaxError')):
    if isinstance(error,cls):kind=name;break
  code=getattr(error,'code',None)
  code=code if type(code) is str and code in RESULT_REASONS else 'unclassified'
  number=error.errno if isinstance(error,OSError) else None
  number=number if type(number) is int and 1<=number<=4095 else None
  frames=[];tb=error.__traceback__;count=0
  while tb is not None and count<32:
   frame=tb.tb_frame;module=frame.f_globals.get('__name__');name=frame.f_code.co_name;line=tb.tb_lineno
   if (type(module) is str and module in ERROR_MODULES and type(name) is str and
       re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}',name) is not None and
       type(line) is int and 1<=line<=1000000):frames.append((module,name,line))
   tb=tb.tb_next;count+=1
  rows.append(dict(kind=kind,code=code,errno=number,trace=tuple(frames)))
 return tuple(rows)
def fixed_decode(encoded,size,sha):
 if type(size) is not int or not 0<size<=2097152:raise ValueError('payload_budget')
 compressed=base64.b64decode(encoded)
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,size+1)
 if (len(raw)!=size or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof or
     hashlib.sha256(raw).hexdigest()!=sha):raise ValueError('payload_pin')
 return raw
runner_raw=fixed_decode(RUNNER_ENCODED,RUNNER_PIN[0],RUNNER_PIN[1])
worker_raw=fixed_decode(WORKER_ENCODED,WORKER_PIN[0],WORKER_PIN[1])
validator_raw=fixed_decode(VALIDATOR_ENCODED,VALIDATOR_PIN[0],VALIDATOR_PIN[1])
artifacts=tuple((name,size,sha,fixed_decode(encoded,size,sha)) for name,size,sha,encoded in ARTIFACT_ROWS)
session=types.ModuleType('fixed_formal_ui_session')
session.__file__='<fixed-formal-ui-session-stdin>'
exec(worker_raw,session.__dict__)
try:
 component=session.run_fixed(runner_raw,artifacts,validator_raw)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 code=(error.code if type(error) is session.UiSessionError and error.code in RESULT_REASONS else 'ui_exception')
 print('UI_ERROR_CODE='+code)
 raise SystemExit(2)
if component['complete'] is not True:
 retained=session._RETAINED;errors=[]
 if type(retained) is dict:
  values=retained.get('failures')
  if type(values) is list:errors.extend(values[:16])
  original=retained.get('component')
  values=getattr(original,'failures',None)
  if type(values) is list:errors.extend(values[:16])
 detail=fixed_error_details(errors)
 if detail:print('ERROR_DETAIL='+repr(detail))
print('RESULT='+repr(component))
print('MTA_UI_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def make_source(checker, inputs, rows, private_rows):
    lines = ['RESULT_REASONS=' + repr(REASONS)]
    modules = tuple(sorted(set(checker.MODULE_NAMES + checker.PRIVATE_MODULE_NAMES +
                              ('fixed_formal_ui_session', 'fixed_formal_ui_runner',
                               'fixed_formal_ui_assets', 'closed_service_private_owner',
                               'threading', 'socket', 'subprocess', 'types'))))
    lines.append('ERROR_MODULES=' + repr(modules))
    for tag, pin in (('RUNNER', checker.RUNNER), ('WORKER', WORKER), ('VALIDATOR', VALIDATOR)):
        lines.append(tag + '_PIN=' + repr(pin[1:]))
        lines.extend((tag + '_ENCODED=(', checker.chunks(inputs[pin[0]]), ')'))
    lines.append('ARTIFACT_ROWS=(')
    for name, path, size, sha in rows + checker.HELPERS + private_rows + (checker.WPA,):
        lines.append('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(')
        lines.extend((checker.chunks(inputs[path]), '    )),'))
    lines.append(')')
    source = '\n'.join(lines) + '\n' + TARGET_END
    raw = source.encode('ascii')
    if len(raw) > 2 * 1024 * 1024 or any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return raw


def parse_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = derived.splitlines()
    remote = re.findall(r'^MTA_UI_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in lines if line.startswith('RESULT=')]
    if len(remote) != 1 or lines.count('MTA_UI_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('remote_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != FIELDS or
            any(type(value[key]) is not bool for key in BOOL_FIELDS) or value['reason'] not in REASONS):
        raise ValueError('result_fields')
    ready = lines.count('MTA_FORMAL_UI_READY')
    if (ready not in (0, 1) or ready == 1 and not (value['ui_ready'] and value['credentials_removed']) or
            value['complete'] and ready != 1):
        raise ValueError('result_fields')
    return int(remote[0]), value


def host_error_code(error):
    return (error.args[0] if type(error) is ValueError and len(error.args) == 1 and
            error.args[0] in HOST_ERROR_CODES else 'host_' + type(error).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'closed-ui' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('formal-ui-session-v1-' + mode + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    inputs, checker, component = {}, None, None
    report = dict(schema='p011-formal-ui-session-v1', mode=mode, passed=False,
                  source_check_complete=False, source_preserved=False, source_count=0,
                  host_error_code=None, device_invoked=False, host_exit=None, remote_exit=None,
                  remote_status_known=False, stdout_bytes=None, stdout_sha256=None,
                  stderr_bytes=None, stderr_sha256=None, result_received=False,
                  mta_scan_requested=False, mta_receive_requested=False, mta_send_requested=False,
                  pending_removed=False, phone_tested=False, physical_ui_verified=False,
                  full_network_restore_verified=False, whole_system_zero_rf_claimed=False,
                  vendor_binary_replaced=False, startup_changed=False, wake_or_timeout_changed=False,
                  ui_bundle_staging_requested=False, private_raw_public=False)
    for key in BOOL_FIELDS + ('reason',):
        report['component_' + key] = None
    label = 'formal-ui-session-v1'
    try:
        checker, checker_raw = load_checker()
        inputs[CHECKER[0]] = checker_raw
        fixed = (checker.MANIFEST, checker.PRIVATE_MANIFEST, checker.RUNNER,
                 checker.TRANSPORT, OLD_CMD, WORKER, VALIDATOR)
        for path, size, sha in fixed:
            inputs[path] = checker.read_fixed(path, (size, sha))
        rows = checker.manifest_rows(inputs[checker.MANIFEST[0]])
        private_rows = checker.manifest_rows(inputs[checker.PRIVATE_MANIFEST[0]], private=True)
        payload = rows + checker.HELPERS + private_rows + (checker.WPA,)
        if len(payload) != 68 or sum(row[2] for row in payload) > 4 * 1024 * 1024:
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            raw = checker.read_fixed(path, (size, sha))
            if path in inputs and inputs[path] != raw:
                raise ValueError('input_shared_changed')
            inputs[path] = raw
        inputs[SELF] = checker.read_fixed(SELF)
        if len(inputs) != INPUT_COUNT:
            raise ValueError('input_count')
        for path, raw in inputs.items():
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as handle:
                handle.write(raw)
        # New worker + new envelope only. No old module AST or test replay.
        ast.parse(inputs[WORKER[0]].decode('utf-8'), feature_version=(3, 5))
        data = make_source(checker, inputs, rows, private_rows)
        ast.parse(data.decode('ascii'), feature_version=(3, 5))
        with (out / 'private-target-source.py').open('xb') as handle:
            handle.write(data)
        report.update(source_check_complete=True, source_count=len(inputs),
                      target_source_bytes=len(data), target_source_sha256=digest(data),
                      payload_role_count=len(payload), worker_bytes=WORKER[1], worker_sha256=WORKER[2],
                      validator_bytes=VALIDATOR[1], validator_sha256=VALIDATOR[2])
        if args.check_device:
            transport = checker.load_transport(inputs[checker.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                       'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-formal-ui-session-v1; '
                       'r=$?; printf \'\\nMTA_UI_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=250, input_data=data)
            remote, component = parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, result_received=True)
            for key, value in component.items():
                report['component_' + key] = value
    except Exception as error:
        report['host_error_code'] = host_error_code(error)
    finally:
        report['source_count'] = len(inputs)
        prefix = private / ('01-' + label)
        host_path = Path(str(prefix) + '.host-exit')
        if host_path.exists():
            raw = host_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(raw) if re.fullmatch(r'-?\d+', raw) else 'TIMEOUT'
        stdout_path = Path(str(prefix) + '.stdout.raw')
        stderr_path = Path(str(prefix) + '.stderr.raw')
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream + '_bytes'] = len(original)
                report[stream + '_sha256'] = digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            found = re.findall(r'^MTA_UI_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'] = int(found[0])
                report['remote_status_known'] = True
                marker = found[0]
        with Path(str(prefix) + '.remote-exit').open('x', encoding='ascii') as handle:
            handle.write(marker + '\n')
        try:
            report['source_preserved'] = (checker is not None and len(inputs) == INPUT_COUNT and all(
                checker.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()))
        except (OSError, ValueError):
            report['source_preserved'] = False
    if not args.check_device:
        report['passed'] = (report['host_error_code'] is None and report['source_check_complete'] and
                            report['source_preserved'] and not report['device_invoked'])
    else:
        report['passed'] = (report['host_error_code'] is None and report['source_check_complete'] and
                            report['source_preserved'] and report['host_exit'] == 0 and
                            report['stderr_bytes'] == 0 and report['remote_status_known'] and
                            report['remote_exit'] == 0 and type(component) is dict and
                            all(component[key] is True for key in SUCCESS) and
                            component['resource_pending'] is False and component['radio_admission'] is False and
                            component['physical_ui_verified'] is False and component['reason'] == 'ui_finished')
    # Every public value is a scalar, never raw text/input inventories/credentials.
    if any(type(value) not in (type(None), bool, int, str) for value in report.values()):
        raise ValueError('result_fields')
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Fixed real closed MTA copied-vendor UI session only. Default SOURCE mode never accesses ADB. '
              b'Explicit --check-device starts only the existing fixed UI copy after original preflight/stage, '
              b'pre-Owner guardian arming and actual loopback endpoint/token initial-property handoff. '
              b'Runtime credentials are exclusive root0600 and withdrawn by original inode after QML READY. '
              b'No token, credential file, user content or private raw/inputs enter this two-member ZIP. '
              b'Normal PASS needs the original same-worker Owner.close, original FD close, copied candidate '
              b'exit and independent exact-parent/stock-three-pin/boot/peer restoration; the expected new '
              b'Z03 PID is not compared to the former PID as an unchanged snapshot. Guardian restoration '
              b'never proves Owner closure. Unknown live worker remains stopped/pending, not killed or cleared. '
              b'20s display/60s activity/original cleanup60/guardian recovery up to195s; remote alarm240 and '
              b'HOST timeout250. Timeout/missing result never signs closure and no target kill/cleanup is issued. '
              b'The copied vendor executable runs original initialization: MTA admission remains closed, '
              b'but that is NOT a whole-system zero-RF claim. No scan/receive/send/pending handling, phone '
              b'test, firmware/startup replacement, wake/brightness/auto-sleep modification or complete '
              b'network restoration. QML READY/requests are runtime evidence, not physical visibility '
              b'or layout acceptance. UI bundle staging was a separate step, not performed by this checker. '
              b'Original stdout/stderr, host/remote exits, input snapshots and private program stay local.\n')
    with (out / 'result.json').open('xb') as handle:
        handle.write(public)
    with (out / 'README.txt').open('xb') as handle:
        handle.write(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
                         result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

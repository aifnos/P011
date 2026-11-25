"""Default PC SOURCE; --device inspects current P011 TLS dependencies only.

No sockets, certificates, staging, radio, UI, user files or system changes.
Missing optional test libraries are observations, not runtime compatibility.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_tls_environment_v1_check.py'
CMDS = ('HOST_MTA_TLS_ENVIRONMENT_V1_CHECK.cmd', 'TEST_MTA_TLS_ENVIRONMENT_V1.cmd')
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/device_filecenter_audio_deadline_v1_check.py', 13753,
     '69f7c6d4b192f1ab7a7c75101a6583d31773141e007b7f33c5ba2e457763d71c'))
CORE_MODULES = ('base64', 'binascii', 'errno', 'hashlib', 'hmac', 'math',
    'os', 're', 'select', 'shutil', 'socket', 'ssl', 'stat', 'struct',
    'subprocess', 'tempfile', 'threading', 'time', 'urllib.parse', 'uuid',
    'zipfile', 'zlib')
TEST_MODULES = ('ast', 'builtins', 'pathlib', 'types', 'unittest',
                'unittest.mock', 'warnings')
SSL_ATTRIBUTES = ('SSLContext', 'PROTOCOL_TLSv1_2', 'CERT_NONE',
    'SSLWantReadError', 'SSLWantWriteError', 'SSLError', 'SSLSocket')
CONTEXT_ATTRIBUTES = ('wrap_socket', 'load_cert_chain', 'verify_mode',
                      'check_hostname')

REMOTE = r'''
import hashlib,os,stat,subprocess,sys
if os.geteuid()!=0 or os.uname()[4]!='armv7l':raise ValueError('target_profile')
if tuple(sys.version_info[:3])!=(3,5,5):raise ValueError('target_python')
rows=[];loaded={}
for name in CORE_MODULES+TEST_MODULES:
 try:
  loaded[name]=__import__(name,fromlist=['*'])
  rows.append((name,True,None))
 except ImportError as error:rows.append((name,False,type(error).__name__))
ssl_module=loaded.get('ssl');context=None
ssl_attrs=tuple((name,hasattr(ssl_module,name)) for name in SSL_ATTRIBUTES)
if ssl_module is not None and all(value for name,value in ssl_attrs):
 context=ssl_module.SSLContext(ssl_module.PROTOCOL_TLSv1_2)
context_attrs=tuple((name,hasattr(context,name)) for name in CONTEXT_ATTRIBUTES)
pathlib_module=loaded.get('pathlib')
path_attrs=tuple((name,hasattr(getattr(pathlib_module,'Path',None),name))
 for name in ('read_bytes','write_bytes','relative_to','is_symlink','mkdir'))
binary='/usr/bin/openssl';binary_exists=False;binary_sha=None
try:
 s=os.stat(binary);binary_exists=stat.S_ISREG(s.st_mode)
 if binary_exists:
  h=hashlib.sha256()
  with open(binary,'rb') as stream:
   for block in iter(lambda:stream.read(65536),b''):h.update(block)
  binary_sha=h.hexdigest()
except FileNotFoundError:pass
process=None;out=err=b'';code=None;timed_out=False
try:
 if binary_exists:
  process=subprocess.Popen([binary,'version'],stdin=subprocess.DEVNULL,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:out,err=process.communicate(timeout=3)
  except subprocess.TimeoutExpired:
   timed_out=True;process.kill();out,err=process.communicate(timeout=5)
  code=process.returncode
finally:
 if process is not None:
  process.stdout.close();process.stderr.close()
closed=process is None or (process.poll() is not None and
 process.stdout.closed and process.stderr.closed)
if not closed:raise ValueError('version_process_pending')
if len(out)>1024 or len(err)>1024:raise ValueError('version_output_limit')
result=dict(schema='p011-tls-environment-v1',python_version=tuple(sys.version_info[:3]),
 filesystem_encoding=sys.getfilesystemencoding(),default_encoding=sys.getdefaultencoding(),
 modules=tuple(rows),ssl_attributes=ssl_attrs,context_attributes=context_attrs,
 path_attributes=path_attrs,openssl_exists=binary_exists,openssl_sha256=binary_sha,
 openssl_exit=code,openssl_timed_out=timed_out,openssl_stdout=out,
 openssl_stderr=err,version_process_closed=closed,
 ssl_version=getattr(ssl_module,'OPENSSL_VERSION',None))
print('TLS_ENVIRONMENT='+repr(result))
'''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def definition(key, raw):
    value = types.ModuleType('_tls_environment_' + Path(key).stem)
    value.__file__ = str(BASE / key)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def validate(value):
    fields = {'schema', 'python_version', 'filesystem_encoding', 'default_encoding', 'modules', 'ssl_attributes',
        'context_attributes', 'path_attributes', 'openssl_exists', 'openssl_sha256',
        'openssl_exit', 'openssl_timed_out', 'openssl_stdout', 'openssl_stderr',
        'version_process_closed', 'ssl_version'}
    need(type(value) is dict and set(value) == fields and
         value['schema'] == 'p011-tls-environment-v1' and
         value['python_version'] == (3, 5, 5), 'observation_schema')
    need(all(type(value[name]) is str and 1 <= len(value[name]) <= 64
             for name in ('filesystem_encoding', 'default_encoding')), 'path_encodings')
    rows = value['modules']
    need(type(rows) is tuple and tuple(row[0] for row in rows) == CORE_MODULES + TEST_MODULES and
         all(type(row) is tuple and len(row) == 3 and type(row[1]) is bool and
             row[2] == (None if row[1] else 'ImportError') for row in rows), 'module_observations')
    for key, names in (('ssl_attributes', SSL_ATTRIBUTES),
                       ('context_attributes', CONTEXT_ATTRIBUTES),
                       ('path_attributes', ('read_bytes', 'write_bytes', 'relative_to', 'is_symlink', 'mkdir'))):
        need(type(value[key]) is tuple and tuple(row[0] for row in value[key]) == names and
             all(type(row) is tuple and len(row) == 2 and type(row[1]) is bool for row in value[key]), 'attribute_observations')
    need(value['version_process_closed'] is True and
         type(value['openssl_exists']) is bool and type(value['openssl_timed_out']) is bool and
         (value['openssl_exit'] is None or type(value['openssl_exit']) is int) and
         all(type(value[name]) is bytes and len(value[name]) <= 1024
             for name in ('openssl_stdout', 'openssl_stderr')), 'version_observations')
    pin = value['openssl_sha256']
    need(pin is None or (type(pin) is str and len(pin) == 64 and
         all(letter in '0123456789abcdef' for letter in pin)), 'openssl_digest')
    need(value['ssl_version'] is None or
         (type(value['ssl_version']) is str and len(value['ssl_version']) <= 128), 'ssl_version')
    return dict(schema=value['schema'], python_version=value['python_version'],
        filesystem_encoding=value['filesystem_encoding'], default_encoding=value['default_encoding'],
        modules=rows, ssl_attributes=value['ssl_attributes'],
        context_attributes=value['context_attributes'], path_attributes=value['path_attributes'],
        openssl_exists=value['openssl_exists'], openssl_sha256=pin,
        openssl_exit=value['openssl_exit'], openssl_timed_out=value['openssl_timed_out'],
        openssl_version=value['openssl_stdout'].decode('ascii', 'strict').strip(),
        openssl_stderr_bytes=len(value['openssl_stderr']),
        version_process_closed=True, ssl_version=value['ssl_version'],
        core_ready=all(available for name, available, error in rows[:len(CORE_MODULES)]) and
            all(available for name, available in value['ssl_attributes'] + value['context_attributes']) and
            value['openssl_exit'] == 0 and not value['openssl_timed_out'] and not value['openssl_stderr'])


def run(device):
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == PINS[0][1:], 'sealer_pin')
    seal = definition(PINS[0][0], raw)
    mode = 'device' if device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('tls-environment-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}; evidence = seal.InputEvidence(inputs)
    report = dict(schema='p011-tls-environment-v1-parent', mode=mode, passed=False,
        device_attempted=False, dependency_attempted=False, observation=None,
        source_preserved=False, stock_before_ok=False, stock_after_ok=False,
        limited_stock_unchanged=False, wifi_state_unchanged=False,
        device_writes=False, sockets_started=False, rf=False, ui=False,
        certificates_generated=False, transport_tested=False, phone=False,
        full_restore_verified=False, error=None, command_receipts={})
    adb = probe = helper = before = baseline_command = None; failure = None
    try:
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF,) + CMDS:
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        probe = definition(PINS[1][0], inputs[PINS[1][0]])
        helper = definition(PINS[2][0], inputs[PINS[2][0]])
        target = ('CORE_MODULES=' + repr(CORE_MODULES) + '\nTEST_MODULES=' + repr(TEST_MODULES) +
            '\nSSL_ATTRIBUTES=' + repr(SSL_ATTRIBUTES) + '\nCONTEXT_ATTRIBUTES=' + repr(CONTEXT_ATTRIBUTES) + '\n' + REMOTE).encode('ascii')
        ast.parse(target.decode('ascii'), feature_version=(3, 5))
        need(max(map(len, target.splitlines())) <= 512, 'terminal_line_limit')
        seal.fresh(out / 'private-raw/target.py', target)
        packed = base64.b64encode(zlib.compress(probe.source().encode('utf-8'))).decode('ascii')
        baseline_command = ('/usr/bin/python3.5 -I -B -c "import signal,base64,zlib;signal.alarm(60);'
            'exec(zlib.decompress(base64.b64decode(\'' + packed + '\')))"; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(25);'
            'exec(sys.stdin.buffer.read(' + str(len(target)) + '))" p011-tls-environment-v1; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        need(len(baseline_command) <= 3500, 'baseline_command_limit')
        seal.fresh(out / 'private-raw/commands.txt', (baseline_command + '\n' + command + '\n').encode('ascii'))
        report.update(input_count=len(inputs), target_bytes=len(target),
            target_sha256=hashlib.sha256(target).hexdigest(), target_alarm_seconds=25,
            target_host_timeout_seconds=35, alarm_before_stdin=True)
        if device:
            adb = probe.Adb(out / 'private-raw'); report['device_attempted'] = True
            before = helper.stock_probe(adb, probe, 'stock-before', baseline_command, report['command_receipts'])
            report['stock_before_ok'] = True; report['dependency_attempted'] = True
            value = helper.reply(adb, 'tls-dependencies', command, 'TLS_ENVIRONMENT=', 35,
                                 report['command_receipts'], target)
            report['observation'] = validate(value)
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            try:
                after = helper.stock_probe(adb, probe, 'stock-after', baseline_command, report['command_receipts'])
                report['stock_after_ok'] = True
                if before is not None:
                    report['limited_stock_unchanged'] = before['stock'] == after['stock']
                    report['wifi_state_unchanged'] = before['capabilities']['wifi_connected'] is after['capabilities']['wifi_connected']
                    need(report['limited_stock_unchanged'] and report['wifi_state_unchanged'], 'baseline_changed')
            except BaseException as error:
                seal.fresh(out / 'private-raw/after-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None: failure = error
        try:
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected, 'source_changed')
                need((out / 'private-inputs' / key).read_bytes() == expected, 'snapshot_changed')
            report['source_preserved'] = True
        except BaseException as error:
            seal.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        if failure is None: report['passed'] = True
        else: report['error'] = type(failure).__name__
    sealed = seal.seal_result(out, report, b'P011 readonly TLS dependency inventory, not a transport test.\nNo sockets, RF, UI, certificates, staging, user-file or system writes.\nOriginal stock/Wi-Fi comparison is limited; phone/full restoration remain unverified.\nRaw streams, remote exits, source and snapshots stay private.\n')
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        error=sealed['report']['error'], result_dir=str(out), result_zip=str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', action='store_true')
    sys_exit = run(parser.parse_args().device)
    raise SystemExit(sys_exit)

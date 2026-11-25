"""Fixed, once-only P011 STATUS API check. Default source check; no RF/repair.

The private manifest is ROOT-approved observed facts, not a production manifest.
Original sources and raw reports stay unchanged. Device modules run in memory.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import types
import zipfile

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
FACTS_DIR = ROOT / 'logs/MtaP011-WpaDaemonProfileReadOnly-20261001-114224-8bd44258'
FACTS_RAW_SHA = '4cb6d6d7af436b6168a1fa8746ae73c58024ce85faaac60d4a5e81a4d240ff4b'
FACTS_CHECKER_SHA = '942467601dbf22fb993d249f89c07d5d450b6a19ffe456018ec944d19ef861a2'
LEGACY_SHA = 'be59afc4ebda920db84075d509a1dec4e630a70590263eefa5754b9c13a2ad56'
STATUS_SHA = '4f0fa75132c8c81427f1d593fdc415b01657b061cd9d1dbcbcde789b52daf742'
PINS = (
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
    ('mta_client_proc', '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'),
    ('mta_client_caps', 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('mta_client_baseline', 'ce8fe17b60964cf9b421296eef033d1dde19f8a4118de12d7f3922133ee13f08'),
    ('mta_p2p_client_ctrl', '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'),
    ('mta_client_wpa_status', STATUS_SHA))
_ATTEMPTS = []

LOADER = '''import base64,builtins,hashlib,types
modules={};original=builtins.__import__
def pinned_import(name,globals=None,locals=None,fromlist=(),level=0):
 if name in dict(PINS):
  if level or name not in modules:raise ValueError('memory_order')
  return modules[name]
 if name.startswith('mta_') or name.startswith('p011_') or level:raise ValueError('memory_import')
 return original(name,globals,locals,fromlist,level)
for name,pin,encoded in ENCODED:
 raw=base64.b64decode(encoded.encode('ascii'),validate=True)
 if hashlib.sha256(raw).hexdigest()!=pin:raise ValueError('memory_pin')
 module=types.ModuleType(name);module.__file__='<pinned-client-status-readonly>'
 module.__dict__['__builtins__']=dict(vars(builtins),__import__=pinned_import)
 exec(raw,module.__dict__);modules[name]=module
'''
ENTRY = '''import time,traceback
wpa=modules['mta_client_wpa_status'];reader=wpa.AuthenticatedStatusReader(MANIFEST)
OWNERS=[reader];result=None;trace=None
try:result=reader.read_status(time.monotonic()+3)
except BaseException:trace=traceback.format_exc()
source=reader._source
def private(value):
 if value is None or type(value) in (str,bytes,int,float,bool):return value
 if type(value) in (list,tuple):return tuple(private(x) for x in value)
 if type(value) is dict:return {k:private(x) for k,x in value.items()}
 if hasattr(value,'__slots__'):return {k:private(getattr(value,k)) for k in value.__slots__ if not k.startswith('_')}
 raise ValueError('private_shape')
inventory=tuple(tuple({k:r[k] for k in ('fd','unknown','attempted','closed')} for r in f._tickets) for f in source._files)
actor_calls=tuple({'reader_retained':t['reader'] is not None,'observation':private(t['value']),'error_recorded':t['error'] is not None,'unknown':t['unknown']} for t in source._actor_calls)
failure=reader._failure
original_failure=None if failure is None else {'class':type(failure).__name__,'code':getattr(failure,'code',None),'errno':getattr(failure,'errno',None),'traceback':''.join(traceback.format_exception(type(failure),failure,failure.__traceback__))}
print('RESULT='+repr({'public':reader.status(),'private':{'result':private(result),'sources':private(reader._sources),'inventory':inventory,'actor_calls':actor_calls,'traceback':trace,'original_failure':original_failure}}))
'''


def _legacy():
    path = BASE / 'host/wpa_daemon_identity_readonly.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != LEGACY_SHA: raise ValueError('legacy_pin')
    module = types.ModuleType('fixed_status_transport'); module.__file__ = str(path)
    exec(raw, module.__dict__)
    return module


def source_check():
    legacy = _legacy()
    legacy._read(BASE / 'host/device_probe.py', legacy.ADB_PIN)
    facts_checker_path = BASE / 'host/wpa_daemon_profile_readonly.py'
    facts_checker_raw = legacy._read(facts_checker_path, FACTS_CHECKER_SHA)
    facts_checker = types.ModuleType('fixed_status_facts'); facts_checker.__file__ = str(facts_checker_path)
    exec(facts_checker_raw, facts_checker.__dict__)
    raw = (FACTS_DIR / 'private-raw/01-original-wpa-identity.stdout.raw').read_bytes()
    if hashlib.sha256(raw).hexdigest() != FACTS_RAW_SHA: raise ValueError('facts_pin')
    # Strip only the exact pinned source echo, then require the existing three
    # terminal lines. Empty separator lines are not extra protocol responses.
    facts_source = facts_checker.source_check()[1]
    facts = legacy._parse(raw, legacy._transport(facts_source)[2])
    pub = json.loads((FACTS_DIR / 'result.json').read_text(encoding='utf-8'))
    if pub['pass'] is not True or pub['resource_pending'] is not False or pub['checker_sha256'] != FACTS_CHECKER_SHA:
        raise ValueError('facts_incomplete')
    identity = facts['private']['identity_before']; endpoint = facts['private']['endpoint_before']
    if identity != facts['private']['identity_after'] or endpoint != facts['private']['endpoint_after']:
        raise ValueError('facts_changed')
    ids = identity['uid_gid']; manifest = {'daemon_exe': facts['private']['actors'][0]['actor']['exe'],
        'daemon_sha256': identity['image_sha'], 'endpoint': endpoint['path'],
        'real_uid': ids[0][0], 'real_gid': ids[1][0],
        'namespace_kind': identity['namespace_profile']['kind'],
        'config_sha256': identity['namespace_profile']['config_sha256']}
    chunks = []
    for name, pin in PINS:
        module_raw = legacy._read(BASE / 'runtime' / (name + '.py'), pin)
        ast.parse(module_raw.decode('utf-8'), feature_version=(3, 5))
        encoded = base64.b64encode(module_raw).decode('ascii')
        chunks.append('(%r,%r,\n%s),\n' % (name, pin, '\n'.join(repr(encoded[i:i+1000]) for i in range(0, len(encoded), 1000))))
    source = 'PINS=' + repr(PINS) + '\nENCODED=(\n' + ''.join(chunks) + ')\n' + LOADER + 'MANIFEST=' + repr(manifest) + '\n' + ENTRY
    tree = ast.parse(source, feature_version=(3, 5))
    if len(source.encode('utf-8')) > 524288 or max(map(len, source.splitlines())) > 2048 or any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        raise ValueError('source_budget')
    return legacy, source, {'source_check_pass': True, 'checker_sha256': hashlib.sha256(legacy._read(Path(__file__).absolute())).hexdigest(), 'source_sha256': dict(PINS)}


def run_readonly(expected):
    legacy, source, checks = source_check()
    if expected != checks['checker_sha256'] or _ATTEMPTS: raise ValueError('reviewed_pin_or_attempt')
    record = {'source': source}; _ATTEMPTS.append(record)
    out = ROOT / 'logs' / ('MtaP011-ClientWpaStatusReadOnly-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(4).hex())
    out.mkdir(parents=True, exist_ok=False)
    report = dict(checks, evidence='P011_ORIGINAL_WPA_STATUS_ONLY', **{'pass': False, 'device_command_attempted': False, 'device_reply_confirmed': False, 'rf_operations': False, 'network_mutations': False, 'old_pending_read_or_clear': False, 'restoration_verified': False, 'send_available': False, 'receive_available': False})
    try:
        helper = types.ModuleType('fixed_status_adb'); helper.__file__ = str(BASE / 'host/device_probe.py')
        exec(legacy._read(BASE / 'host/device_probe.py', legacy.ADB_PIN), helper.__dict__)
        adb = helper.Adb(out / 'private-raw'); record['adb'] = adb
        report['device_command_attempted'] = True
        value = legacy._remote(adb, source, record); report['device_reply_confirmed'] = True
        if type(value) is not dict or set(value) != {'public', 'private'}: raise ValueError('result_shape')
        public = value['public']
        bools = ('attempted', 'finished', 'read_success', 'source_authenticated', 'socket_closed', 'resource_pending', 'restoration_verified', 'mutation_admission', 'send_available', 'receive_available')
        counts = ('source_count', 'datagram_count', 'rights_count', 'rights_closed')
        if type(public) is not dict or set(public) != set(bools + counts + ('reason',)) or any(type(public[k]) is not bool for k in bools) or any(type(public[k]) is not int or not 0 <= public[k] <= 512 for k in counts) or public['reason'] not in ('read_closed', 'unavailable', 'invalid_manifest', 'invalid_budget', 'invalid_clock', 'deadline', 'already_attempted', 'unsupported_platform', 'source_unknown', 'source_invalid', 'source_changed', 'source_authentication', 'namespace_invalid', 'image_invalid', 'endpoint_invalid', 'file_budget', 'actor_unknown', 'socket_unknown', 'socket_identity', 'socket_option', 'timeout_readback', 'short_send', 'receive_unknown', 'receive_invalid', 'receive_truncated', 'receive_control', 'credential_mismatch', 'wrong_endpoint', 'invalid_status', 'rights_rejected', 'rights_unknown', 'close_unknown', 'io_error', 'interrupted'):
            raise ValueError('public_shape')
        if any(public[k] for k in ('restoration_verified', 'mutation_admission', 'send_available', 'receive_available')): raise ValueError('scope_shape')
        report.update(public)
        report['pass'] = all(public[k] for k in ('attempted', 'finished', 'read_success', 'source_authenticated', 'socket_closed')) and not public['resource_pending'] and public['source_count'] == 2 and public['datagram_count'] == 1 and public['rights_count'] == 0 and public['reason'] == 'read_closed'
    except Exception as error:
        record['first_error'] = error; report['error_class'] = type(error).__name__
    (out / 'result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text('Fixed original STATUS only; no ATTACH/SCAN/RF/network switch/reboot/pending operation.\nPrivate raw retains source/SSID/Actor/FD/error evidence; only public result is shareable.\nObserved ROOT manifest is for this diagnostic, not production RF or restore admission.\nSelector enumeration raw is not independently captured.\n', encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'), 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json', 'README.txt'): bundle.write(out / name, name)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-readonly', action='store_true'); parser.add_argument('--expected-checker-sha256')
    args = parser.parse_args(argv)
    if args.execute_readonly != (args.expected_checker_sha256 is not None): parser.error('Execute and reviewed SHA must be supplied together')
    try:
        report = run_readonly(args.expected_checker_sha256) if args.execute_readonly else source_check()[2]
        print(json.dumps(report, indent=2)); return 0 if report.get('pass', report.get('source_check_pass', False)) else 1
    except Exception:
        print(json.dumps({'pass': False, 'device_command_attempted': 'NOT_RECORDED', 'error_class': 'source_or_output'})); return 1


if __name__ == '__main__': sys.exit(main())

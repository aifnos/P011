"""PC-only v22 Store closure replacement; never imports target definitions."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = BASE / 'host/client_store_close_v22_source_manifest.json'
KIND = 'client-store-close-v22-source-only'
PREVIOUS_CHECK_SHA = 'b9db2d1c54ae882bd7575dfd5175ed7fdbf5ebb9c898156318ac7d269678e2f0'
PREVIOUS_PLAN_SHA = 'a8387d5e5036370ec8ae8bf7794f903680a5a124621b8815650dcd793fafd999'
OLD_STORE = {'module': 'mta_client_store',
    'path': 'candidate/client-durable-association-v18/runtime/mta_client_store.py',
    'sha256': '5ee1c184c3511bc3072e87409a88861713bfd249d79584df1d50fc1377964426', 'bytes': 52712}
NEW_PATH = 'candidate/client-store-close-v22/runtime/mta_client_store.py'


def _raw(relative, pin):
    value = (BASE / relative).read_bytes()
    if hashlib.sha256(value).hexdigest() != pin: raise ValueError('source_changed')
    return value


def verify():
    raw = _raw('host/client_dhcp_v21_source_check.py', PREVIOUS_CHECK_SHA)
    plan_raw = _raw('host/client_dhcp_v21_source_manifest.json', PREVIOUS_PLAN_SHA)
    pinned_extras = json.loads(plan_raw.decode('utf-8'))['sources']
    checker = types.ModuleType('private_v22_v21_pc_checker')
    checker.__file__ = str(BASE / 'host/client_dhcp_v21_source_check.py')
    exec(compile(raw, checker.__file__, 'exec'), checker.__dict__)
    rows = checker.verify()
    if len(rows) != 28 or rows[24:] != pinned_extras or sum(row == OLD_STORE for row in rows) != 1:
        raise ValueError('base_graph_changed')
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if (type(plan) is not dict or set(plan) != {'schema', 'previous_checker_sha256', 'previous_manifest_sha256', 'replacement'} or
            plan['schema'] != KIND or plan['previous_checker_sha256'] != PREVIOUS_CHECK_SHA or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA):
        raise ValueError('replacement_plan_invalid')
    row = plan['replacement']
    if (type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or
            row['module'] != OLD_STORE['module'] or row['path'] != NEW_PATH or
            type(row['bytes']) is not int or not 1 <= row['bytes'] <= 2097152 or
            type(row['sha256']) is not str or len(row['sha256']) != 64 or
            any(c not in '0123456789abcdef' for c in row['sha256'])):
        raise ValueError('replacement_source_invalid')
    raw = _raw(NEW_PATH, row['sha256'])
    if len(raw) != row['bytes']: raise ValueError('replacement_source_invalid')
    tree = ast.parse(raw.decode('utf-8'), filename=NEW_PATH, feature_version=(3, 5))
    if any(isinstance(n, ast.Assert) for n in ast.walk(tree)): raise ValueError('target_assert_forbidden')
    index = rows.index(OLD_STORE)
    available = {r['module'] for r in rows[:index]}
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import): names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level: raise ValueError('relative_target_import')
            names = [node.module or '']
        if any(name.startswith(('mta_', 'p011_')) and name not in available for name in names):
            raise ValueError('replacement_dependency_order')
    rows[index] = dict(row)
    return rows


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try: rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('SOURCE_ONLY_FAIL: pinned source/syntax/dependency mismatch; no device action')
        return 1
    public = {'schema': KIND, 'source_integrity_verified': True, 'python35_syntax_verified': True,
        'static_dependency_order_verified': True, 'source_count': len(rows), 'store_replacement_count': 1,
        'sources': rows, 'formal_executor_rewired': False, 'target_code_executed': False, 'tests_run': False,
        'device_accessed': False, 'rf_requested': False, 'restoration_verified': False,
        'dhcp_verified_on_device': False, 'ip_installed': False, 'endpoint_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / (KIND + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static Store closure candidate only. No target imports, tests, deployment, ADB, RF, restoration or phone acceptance.\n'
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded); bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps({'source_only_pass': True, 'source_count': len(rows), 'result_zip': str(archive),
        'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())

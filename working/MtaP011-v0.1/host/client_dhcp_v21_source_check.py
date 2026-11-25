"""PC-only isolated v21 extension graph; NEVER a deployment/test entrypoint.

The unchanged v19 F still declares 24 modules. The four extension modules
are parsed separately; loading this checker never imports target definitions.
"""
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
PLAN = BASE / 'host/client_dhcp_v21_source_manifest.json'
KIND = 'client-dhcp-v21-source-only'
BASE_CHECK_SHA = '1dc9fb303f206bd36314ab17243a88741157a7ba77faa88934bb8416931b4e17'
BASE_PLAN_SHA = '9c547fe0b30b899dc1b11beeb67d8815c4e98bd7db8da8c12a2d12cf775beec5'
ADDITIONS = (
    ('mta_dhcp', 'runtime/mta_dhcp.py'),
    ('mta_dhcp_client_core', 'runtime/mta_dhcp_client_core.py'),
    ('mta_dhcp_client', 'candidate/client-dhcp-v21/runtime/mta_dhcp_client.py'),
    ('mta_client_dora', 'candidate/client-dhcp-v21/runtime/mta_client_dora.py'))


def _raw(relative, pin):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('source_changed')
    return raw


def _base_rows():
    raw = _raw('host/client_durable_connect_v19_source_check.py', BASE_CHECK_SHA)
    plan_raw = _raw('host/client_durable_connect_v19_source_manifest.json', BASE_PLAN_SHA)
    pinned_sources = json.loads(plan_raw.decode('utf-8'))['sources']
    module = types.ModuleType('private_v21_v19_static_checker')
    module.__file__ = str(BASE / 'host/client_durable_connect_v19_source_check.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    rows = module.verify()
    if len(rows) != 24 or rows != pinned_sources:
        raise ValueError('base_graph_invalid')
    return rows


def verify():
    base = _base_rows()
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if (type(plan) is not dict or set(plan) != {'schema', 'base_checker_sha256', 'base_manifest_sha256', 'sources'} or
            plan['schema'] != KIND or plan['base_checker_sha256'] != BASE_CHECK_SHA or
            plan['base_manifest_sha256'] != BASE_PLAN_SHA or type(plan['sources']) is not list or
            len(plan['sources']) != len(ADDITIONS)):
        raise ValueError('extension_graph_invalid')
    rows = list(base)
    loaded = {row['module'] for row in base}
    for value, expected in zip(plan['sources'], ADDITIONS):
        if (type(value) is not dict or set(value) != {'module', 'path', 'sha256', 'bytes'} or
                (value['module'], value['path']) != expected or value['module'] in loaded or
                type(value['bytes']) is not int or not 1 <= value['bytes'] <= 2097152 or
                type(value['sha256']) is not str or len(value['sha256']) != 64 or
                any(char not in '0123456789abcdef' for char in value['sha256'])):
            raise ValueError('extension_source_invalid')
        raw = _raw(value['path'], value['sha256'])
        if len(raw) != value['bytes']:
            raise ValueError('extension_source_invalid')
        tree = ast.parse(raw.decode('utf-8'), filename=value['path'], feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_forbidden')
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    raise ValueError('relative_target_import')
                names = [node.module or '']
            for name in names:
                if name.startswith(('mta_', 'p011_')) and name not in loaded:
                    raise ValueError('extension_dependency_order')
        loaded.add(value['module'])
        rows.append(dict(value))
    return rows


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try:
        rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('SOURCE_ONLY_FAIL: pinned source/syntax/dependency mismatch; no device action')
        return 1
    public = {'schema': KIND, 'source_integrity_verified': True,
        'python35_syntax_verified': True, 'static_dependency_order_verified': True,
        'source_count': len(rows), 'base_executor_source_count': 24, 'extension_source_count': 4,
        'unchanged_base_executor_modules_match': True, 'formal_executor_extended': False,
        'sources': rows, 'target_code_executed': False, 'tests_run': False,
        'device_accessed': False, 'rf_requested': False, 'restoration_verified': False,
        'dhcp_verified_on_device': False, 'ip_installed': False, 'endpoint_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / (KIND + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static extension graph only. F remains 24 modules. No tests, target imports, ADB, RF or phone acceptance.\n'
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded)
        bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive), 'r') as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None:
            raise ValueError('archive_invalid')
        if bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps({'source_only_pass': True, 'source_count': len(rows),
        'result_zip': str(archive), 'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())

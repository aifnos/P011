"""PC-only v15 fixed sources; reuse frozen v14 static import-scope checker.

No target imports, tests, subprocesses, device actions or deployment approval.
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
PLAN = BASE / 'host/client_kernel_connect_v15_source_manifest.json'
SHARED_SHA = 'aea386b4f400488eb8795d2c9919f0456936646043129cae88f995b1f6d73470'
KIND = 'client-kernel-connect-v15-source-only'


def shared_checker():
    path = BASE / 'host/client_connect_v14_source_check.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHARED_SHA:
        raise ValueError('shared_checker_changed')
    module = types.ModuleType('private_v15_scope_checker')
    module.__file__ = str(path)
    # Execute exactly the hashed PC helper bytes, never a second read/pycache.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def expected(shared):
    rows = []
    new = ('mta_client_connection', 'mta_client_linux_provider', 'mta_client_executor')
    for name, relative in shared.EXPECTED:
        if name == 'mta_client_connection':
            rows.append(('mta_client_kernel_proof',
                'candidate/client-kernel-connect-v15/runtime/mta_client_kernel_proof.py'))
        if name in new:
            relative = 'candidate/client-kernel-connect-v15/runtime/' + name + '.py'
        rows.append((name, relative))
    if len(rows) != 24 or len(set(name for name, unused in rows)) != 24:
        raise ValueError('graph_invalid')
    return tuple(rows)


def verify():
    shared = shared_checker()
    graph = expected(shared)
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if (type(plan) is not dict or set(plan) != {'version', 'kind', 'sources'} or
            type(plan['version']) is not int or plan['version'] != 1 or
            plan['kind'] != KIND or type(plan['sources']) is not list or
            len(plan['sources']) != len(graph)):
        raise ValueError('manifest_invalid')
    loaded, names, result, executor = set(), {name for name, unused in graph}, [], None
    for row, (name, relative) in zip(plan['sources'], graph):
        if (type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or
                row['module'] != name or row['path'] != relative or
                type(row['sha256']) is not str or len(row['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in row['sha256']) or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152):
            raise ValueError('manifest_invalid')
        raw = (BASE / relative).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('source_mismatch')
        tree = ast.parse(raw.decode('utf-8'), filename=relative, feature_version=(3, 5))
        imports = shared._Imports()
        imports.visit(tree)
        for dependency, level, deferred in imports.rows:
            if level:
                raise ValueError('relative_import')
            if dependency.startswith(('mta_', 'p011_')) and (
                    dependency not in names or not deferred and dependency not in loaded):
                raise ValueError('dependency_order')
        loaded.add(name)
        result.append(row)
        if name == 'mta_client_executor':
            executor = [node.value for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
    if len(executor) != 1 or ast.literal_eval(executor[0]) != tuple(name for name, unused in graph):
        raise ValueError('executor_graph')
    return result


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try:
        rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError):
        print('SOURCE_ONLY_FAIL: fixed source, syntax or static graph mismatch; no device action')
        return 1
    public = {'schema': KIND, 'source_integrity_verified': True,
        'python35_syntax_verified': True, 'static_dependency_order_verified': True,
        'executor_modules_match': True, 'source_count': len(rows), 'sources': rows,
        'shared_scope_checker_sha256': SHARED_SHA,
        'target_code_executed': False, 'tests_run': False, 'device_accessed': False,
        'rf_requested': False, 'restoration_verified': False,
        'kernel_association_verified_on_device': False,
        'deferred_import_call_timing_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / ('client-kernel-connect-v15-source-only-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static source graph only. No target imports/tests, ADB, RF or phone acceptance.\n'
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
        'result_zip': str(archive), 'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()},
        ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())

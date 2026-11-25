"""PC-only named resource candidates. No target execution or device mode."""
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
PLAN = BASE / 'host/client_resource_v23_source_manifest.json'
KIND = 'client-resource-v23-source-only'
PREVIOUS_CHECK_SHA = 'd6f7f9f938e79d542237f0e99d8c26c44c6b3af69f2e00c18b03a0d6f50647de'
PREVIOUS_PLAN_SHA = '03a596f0e369b68f11d9f1cee3c130a4a08871b955bbb645f0e302ad8f187f2a'
PREVIOUS_GRAPH_SHA = '56385134c25e5615ca3138ee431668a90b6bf2b44fa5e2117e2536222a2dcfe8'
NEW_NAMES = ('mta_client_resource_budget', 'mta_client_files', 'mta_client_store',
    'mta_client_linux_provider', 'mta_client_dora')
NEW_ROOT = 'candidate/client-resource-v23/runtime/'
LAZY = {('ResourceBudget', '__init__'): 'mta_client_store',
        ('ResourceBudget', 'bind_provider'): 'mta_client_linux_provider'}


def _raw(relative, pin):
    value = (BASE / relative).read_bytes()
    if hashlib.sha256(value).hexdigest() != pin: raise ValueError('source_changed')
    return value


def _fingerprint(rows):
    fields = [[r['module'], r['path'], r['sha256'], r['bytes']] for r in rows]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def _dependencies(tree, module, available):
    used_lazy = []
    def walk(node, class_name=None, function_name=None):
        if isinstance(node, ast.ClassDef): class_name = node.name
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)): function_name = node.name
        names = []
        if isinstance(node, ast.Import): names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level: raise ValueError('relative_target_import')
            names = [node.module or '']
        for name in names:
            if not name.startswith(('mta_', 'p011_')) or name in available: continue
            if module == 'mta_client_files' and class_name == 'ClientJournalFiles' and \
                    function_name == '_pending_absent' and isinstance(node, ast.ImportFrom) and \
                    name == 'mta_client_pending' and [(a.name, a.asname) for a in node.names] == [('OwnedMarkerBinding', None)]:
                # Exact inherited v11 lazy marker type check, not a new forward allowance.
                used_lazy.append((class_name, function_name, name))
                continue
            if module != 'mta_client_resource_budget' or LAZY.get((class_name, function_name)) != name:
                raise ValueError('dependency_order')
            used_lazy.append((class_name, function_name, name))
        for child in ast.iter_child_nodes(node): walk(child, class_name, function_name)
    walk(tree)
    if module == 'mta_client_resource_budget' and sorted(used_lazy) != sorted(
            (c, f, name) for (c, f), name in LAZY.items()):
        raise ValueError('lazy_import_scope_changed')
    if module == 'mta_client_files' and used_lazy != [('ClientJournalFiles', '_pending_absent', 'mta_client_pending')]:
        raise ValueError('inherited_lazy_import_scope_changed')


def verify():
    previous_raw = _raw('host/client_store_close_v22_source_check.py', PREVIOUS_CHECK_SHA)
    _raw('host/client_store_close_v22_source_manifest.json', PREVIOUS_PLAN_SHA)
    previous = types.ModuleType('private_v23_pc_previous_checker')
    previous.__file__ = str(BASE / 'host/client_store_close_v22_source_check.py')
    exec(compile(previous_raw, previous.__file__, 'exec'), previous.__dict__)
    prior = previous.verify()  # Only frozen PC checker, never target definitions.
    if len(prior) != 28 or _fingerprint(prior) != PREVIOUS_GRAPH_SHA: raise ValueError('previous_graph_changed')
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if type(plan) is not dict or set(plan) != {'schema', 'previous_checker_sha256',
            'previous_manifest_sha256', 'previous_graph_sha256', 'sources'} or \
            plan['schema'] != KIND or plan['previous_checker_sha256'] != PREVIOUS_CHECK_SHA or \
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA or plan['previous_graph_sha256'] != PREVIOUS_GRAPH_SHA:
        raise ValueError('plan_invalid')
    rows = plan['sources']
    if type(rows) is not list or len(rows) != 29: raise ValueError('source_count')
    expected = [r['module'] for r in prior]
    expected.insert(expected.index('mta_client_files'), 'mta_client_resource_budget')
    if [r.get('module') for r in rows if type(r) is dict] != expected: raise ValueError('source_order')
    old = {r['module']: r for r in prior}
    available = set()
    for row in rows:
        if type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or \
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= 2097152 or \
                type(row['sha256']) is not str or len(row['sha256']) != 64 or \
                any(c not in '0123456789abcdef' for c in row['sha256']): raise ValueError('source_metadata')
        name = row['module']
        if name in NEW_NAMES:
            if row['path'] != NEW_ROOT + name + '.py': raise ValueError('new_path')
        elif row != old[name]: raise ValueError('untouched_source_changed')
        raw = _raw(row['path'], row['sha256'])
        if len(raw) != row['bytes']: raise ValueError('source_size')
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)): raise ValueError('target_assert_forbidden')
        if name in NEW_NAMES: _dependencies(tree, name, available)
        available.add(name)
    return rows


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments, target execution or device mode accepted')
        return 2
    try: rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('SOURCE_ONLY_FAIL: pinned source/syntax/dependency mismatch; no device action')
        return 1
    public = {'schema': KIND, 'source_integrity_verified': True, 'python35_syntax_verified': True,
        'static_dependency_order_verified': True, 'source_count': len(rows), 'sources': rows,
        'formal_executor_rewired': False, 'target_code_executed': False, 'tests_run': False,
        'device_accessed': False, 'rf_requested': False, 'restoration_verified': False,
        'full_init_tested': False, 'global_proc_history_complete': False,
        'payload_projection_complete': False, 'heap_bound_verified': False, 'cleanup_proved': False,
        'dhcp_verified_on_device': False, 'ip_installed': False, 'endpoint_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / (KIND + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static named resource candidates only. Partial payload accounting, no complete heap/proc history/recovery. No target imports, tests, ADB, RF, deployment or phone acceptance.\n'
    (output / 'result.json').write_bytes(encoded); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded); bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note: raise ValueError('archive_invalid')
    print(json.dumps({'source_only_pass': True, 'source_count': len(rows), 'result_zip': str(archive),
        'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())

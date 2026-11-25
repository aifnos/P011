"""PC SOURCE-only frozen v24 proc-history graph. Never load target definitions."""
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
PLAN = 'host/client_proc_history_v24_source_manifest.json'
PLAN_SHA = 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e'
KIND = 'client-proc-history-v24-source-only'
PREVIOUS_CHECK_SHA = '97e746b9df86774163f2957b6df41ddd28f4918d5ae0b94d2b9d7798de35e23d'
PREVIOUS_PLAN_SHA = '54636ca4449a334abeef54be3de57ad4d6c096c06de7feb45172590dd2338a27'
PREVIOUS_GRAPH_SHA = 'c7e2048573b5e04bf12999221ce8b90da215ab74899f21ea0bbe34715a52357d'
NEW_ROOT = 'candidate/client-proc-history-v24/runtime/'
NEW_SOURCES = {
    'mta_client_proc': ('a9b5845e70ddc4ed56ffb0577fe5dbe2214d66cb152d7d53158f56f9d0389035', 38519),
    'mta_client_resource_budget': ('316dd1dd8622abb9c18e11826d64100c4e73a214b9e7d69bf8a113bde10591d1', 14785),
    'mta_client_store': ('411fa831f91b0546b22908d2765654575f1f8f84d5899d7eacae38c9f218162f', 63429),
    'mta_client_linux_provider': ('6c5ab72eafeb477e4d7cdf4ff718b277fc44b94d3715e5fd4f9a7adf09343848', 129653)}
LAZY = {('ResourceBudget', '__init__'): ('mta_client_store', 'stores'),
        ('ResourceBudget', 'bind_provider'): ('mta_client_linux_provider', 'linux'),
        ('ResourceBudget', 'bind_reader'): ('mta_client_proc', 'proc')}


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
                used_lazy.append((class_name, function_name, name))
                continue
            expected = LAZY.get((class_name, function_name))
            if module != 'mta_client_resource_budget' or expected is None or name != expected[0] or \
                    not isinstance(node, ast.Import) or [(a.name, a.asname) for a in node.names] != [expected]:
                raise ValueError('dependency_order')
            used_lazy.append((class_name, function_name, name))
        for child in ast.iter_child_nodes(node): walk(child, class_name, function_name)
    walk(tree)
    if module == 'mta_client_resource_budget' and sorted(used_lazy) != sorted(
            (c, f, value[0]) for (c, f), value in LAZY.items()):
        raise ValueError('lazy_import_scope_changed')
    if module == 'mta_client_files' and used_lazy != [('ClientJournalFiles', '_pending_absent', 'mta_client_pending')]:
        raise ValueError('inherited_lazy_import_scope_changed')


def verify():
    previous_raw = _raw('host/client_resource_v23_source_check.py', PREVIOUS_CHECK_SHA)
    previous_plan_raw = _raw('host/client_resource_v23_source_manifest.json', PREVIOUS_PLAN_SHA)
    pinned_sources = json.loads(previous_plan_raw.decode('utf-8'))['sources']
    previous = types.ModuleType('private_v24_pc_previous_checker')
    previous.__file__ = str(BASE / 'host/client_resource_v23_source_check.py')
    exec(compile(previous_raw, previous.__file__, 'exec'), previous.__dict__)
    prior = previous.verify()  # Frozen PC-only verifier, not any target definitions/methods.
    if prior != pinned_sources or len(prior) != 29 or _fingerprint(prior) != PREVIOUS_GRAPH_SHA:
        raise ValueError('previous_graph_changed')
    plan = json.loads(_raw(PLAN, PLAN_SHA).decode('utf-8'))
    if type(plan) is not dict or set(plan) != {'schema', 'previous_checker_sha256',
            'previous_manifest_sha256', 'previous_graph_sha256', 'sources'} or \
            plan['schema'] != KIND or plan['previous_checker_sha256'] != PREVIOUS_CHECK_SHA or \
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA or plan['previous_graph_sha256'] != PREVIOUS_GRAPH_SHA:
        raise ValueError('plan_invalid')
    rows = plan['sources']
    if type(rows) is not list or len(rows) != 29: raise ValueError('source_count')
    expected = [r['module'] for r in prior]
    expected.remove('mta_client_resource_budget')
    expected.insert(expected.index('mta_client_proc'), 'mta_client_resource_budget')
    if [r.get('module') for r in rows if type(r) is dict] != expected: raise ValueError('source_order')
    old, available = {r['module']: r for r in prior}, set()
    for row in rows:
        if type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or \
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= 2097152 or \
                type(row['sha256']) is not str or len(row['sha256']) != 64 or \
                any(c not in '0123456789abcdef' for c in row['sha256']): raise ValueError('source_metadata')
        name = row['module']
        if name in NEW_SOURCES:
            pin, size = NEW_SOURCES[name]
            if row != {'module': name, 'path': NEW_ROOT + name + '.py', 'sha256': pin, 'bytes': size}:
                raise ValueError('new_source_changed')
        elif row != old[name]: raise ValueError('untouched_source_changed')
        raw = _raw(row['path'], row['sha256'])
        if len(raw) != row['bytes']: raise ValueError('source_size')
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)): raise ValueError('target_assert_forbidden')
        if name in NEW_SOURCES or name == 'mta_client_files': _dependencies(tree, name, available)
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
    note = b'PC static pinned 29-source candidate graph only. No target imports/execution, tests, full INIT, device/phone, complete proc namespace, complete payload projection, heap bound, cleanup, IP install or send/receive proof. HOST evidence is separate.\n'
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

"""PC-only fixed CLIENT CONNECT source graph; no target execution or ADB.

Hash, Python 3.5 syntax, literal executor MODULES and static eager import order.
Deferred imports must still belong to the exact graph; their calls are not proved.
Does not import these sources, test a connection, or approve device deployment.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = BASE / 'host/client_connect_v14_source_manifest.json'
EXPECTED = (
    ('p011_json', 'runtime/p011_json.py'),
    ('mta_ip', 'runtime/mta_ip.py'),
    ('mta_client_tmp_alias', 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py'),
    ('mta_p2p_client_init', 'candidate/client-caps-v7/runtime/mta_p2p_client_init.py'),
    ('mta_client_proc', 'runtime/mta_client_proc.py'),
    ('mta_client_caps', 'runtime/mta_client_caps.py'),
    ('mta_client_caps_transport', 'runtime/mta_client_caps_transport.py'),
    ('mta_client_baseline', 'candidate/client-readparts-v6/runtime/mta_client_baseline.py'),
    ('mta_client_journal_codec', 'runtime/mta_client_journal_codec.py'),
    ('mta_client_coordination', 'candidate/client-tmp-alias-v11/runtime/mta_client_coordination.py'),
    ('mta_client_files', 'candidate/client-tmp-alias-v11/runtime/mta_client_files.py'),
    ('mta_client_pending', 'candidate/client-recovery-budget-v8/runtime/mta_client_pending.py'),
    ('mta_client_store', 'candidate/client-recovery-budget-v8/runtime/mta_client_store.py'),
    ('mta_client_process_owner', 'candidate/client-init-nlink2/runtime/mta_client_process_owner.py'),
    ('mta_client_launch_registration', 'runtime/mta_client_launch_registration.py'),
    ('mta_client_two_phase_lease', 'candidate/client-diagnostic-v12/runtime/mta_client_two_phase_lease.py'),
    ('mta_p2p_client_ctrl', 'runtime/mta_p2p_client_ctrl.py'),
    ('mta_client_wpa_status', 'runtime/mta_client_wpa_status.py'),
    ('mta_protocol', 'runtime/mta_protocol.py'),
    ('mta_client_control_frame', 'candidate/client-connect-v13/runtime/mta_client_control_frame.py'),
    ('mta_client_connection', 'candidate/client-connect-v14/runtime/mta_client_connection.py'),
    ('mta_client_linux_provider', 'candidate/client-connect-v14/runtime/mta_client_linux_provider.py'),
    ('mta_client_executor', 'candidate/client-connect-v14/runtime/mta_client_executor.py'),
)


class _Imports(ast.NodeVisitor):
    """Import statements in function bodies are deferred, including nested ones."""
    def __init__(self):
        self.deferred, self.rows = False, []

    def visit_Import(self, node):
        self.rows.extend((item.name, 0, self.deferred) for item in node.names)

    def visit_ImportFrom(self, node):
        self.rows.append((node.module or '', node.level, self.deferred))

    def visit_FunctionDef(self, node):
        original = self.deferred
        self.deferred = True
        for child in node.body:
            self.visit(child)
        self.deferred = original

    visit_AsyncFunctionDef = visit_FunctionDef


def verify():
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if (type(plan) is not dict or set(plan) != {'version', 'kind', 'sources'} or
            type(plan['version']) is not int or plan['version'] != 1 or
            plan['kind'] != 'client-connect-v14-source-only' or
            type(plan['sources']) is not list or len(plan['sources']) != len(EXPECTED)):
        raise ValueError('manifest_invalid')
    loaded, result, trees = set(), [], {}
    for row, (name, relative) in zip(plan['sources'], EXPECTED):
        if (type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or
                row['module'] != name or row['path'] != relative or
                type(row['sha256']) is not str or len(row['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in row['sha256']) or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152):
            raise ValueError('manifest_invalid')
        raw = (BASE / relative).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != row['bytes'] or digest != row['sha256']:
            raise ValueError('source_mismatch')
        tree = ast.parse(raw.decode('utf-8'), filename=relative, feature_version=(3, 5))
        # Definition-time statements need already-loaded dependencies. A late
        # exact import breaks legitimate pending/store construction cycles; it
        # must be a known graph member, but this check cannot prove call timing.
        imports = _Imports()
        imports.visit(tree)
        for dependency, level, deferred in imports.rows:
            if level:
                raise ValueError('relative_import')
            if dependency.startswith(('mta_', 'p011_')) and (
                    dependency not in {value[0] for value in EXPECTED} or
                    not deferred and dependency not in loaded):
                raise ValueError('dependency_order')
        loaded.add(name)
        trees[name] = tree
        result.append({'module': name, 'path': relative, 'sha256': digest, 'bytes': len(raw)})
    module_values = [node.value for node in trees['mta_client_executor'].body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
            target.id == 'MODULES' for target in node.targets)]
    if len(module_values) != 1 or ast.literal_eval(module_values[0]) != tuple(name for name, unused in EXPECTED):
        raise ValueError('executor_graph')
    return result


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try:
        rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError):
        print('SOURCE_ONLY_FAIL: source, syntax or static dependency mismatch; no device action')
        return 1
    public = {'schema': 'client-connect-v14-source-only', 'source_integrity_verified': True,
        'python35_syntax_verified': True, 'static_dependency_order_verified': True,
        'deferred_import_call_timing_verified': False,
        'executor_modules_match': True, 'source_count': len(rows), 'sources': rows,
        'target_code_executed': False, 'tests_run': False, 'device_accessed': False,
        'rf_requested': False, 'restoration_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / ('client-connect-v14-source-only-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static source graph only. No target imports/tests, ADB, radio or phone acceptance.\n'
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

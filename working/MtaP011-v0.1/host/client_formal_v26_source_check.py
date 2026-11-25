"""PC SOURCE-only formal v26 graph check; no target/test/device execution."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/client_formal_v26_source_manifest.json'
PLAN_SHA = '1dbfc59425315d8ab2bcc3bf4a60aaa551fdb36d8707d884d5f9a512a694d586'
OLD_PLAN = 'host/client_proc_history_v24_source_manifest.json'
OLD_SHA = 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e'
KIND = 'client-formal-v26-source-only'
NEW = frozenset(('mta_client_executor', 'mta_client_process_owner',
    'mta_client_linux_provider', 'mta_client_dora'))
V25 = {
    'mta_client_proc': ('ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 39384),
    'mta_client_baseline': ('b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf', 29510),
    'mta_client_wpa_status': ('47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269', 39133),
}


def fixed(relative, pin, size=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin or size is not None and len(raw) != size:
        raise ValueError('fixed_source_changed')
    return raw


def private_imports(tree):
    rows = []
    def walk(node, scope=()):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = scope + (node.name,)
        if isinstance(node, ast.Import):
            names = [value.name for value in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level: raise ValueError('relative_target_import')
            names = [node.module or '']
        else: names = []
        for name in names:
            if name.startswith(('mta_', 'p011_')):
                rows.append((name, scope))
        for child in ast.iter_child_nodes(node): walk(child, scope)
    walk(tree)
    return rows


def verify():
    previous = json.loads(fixed(OLD_PLAN, OLD_SHA))['sources']
    plan = json.loads(fixed(PLAN, PLAN_SHA))
    if type(plan) is not dict or set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or \
            plan['schema'] != KIND or plan['previous_manifest_sha256'] != OLD_SHA:
        raise ValueError('plan_invalid')
    rows = plan['sources']
    if len(previous) != 29 or type(rows) is not list or len(rows) != 29 or \
            [row['module'] for row in rows] != [row['module'] for row in previous]:
        raise ValueError('graph_order_changed')
    old, available, deferred = {row['module']: row for row in previous}, set(), []
    names = set(old)
    for row in rows:
        if type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'} or \
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= 2097152 or \
                type(row['sha256']) is not str or len(row['sha256']) != 64 or \
                any(c not in '0123456789abcdef' for c in row['sha256']):
            raise ValueError('source_row_invalid')
        name = row['module']
        fixed(old[name]['path'], old[name]['sha256'], old[name]['bytes'])  # preserve every old source
        if name in NEW:
            if row['path'] != 'candidate/client-formal-v26/runtime/' + name + '.py':
                raise ValueError('new_source_path_changed')
        elif name in V25:
            pin, count = V25[name]
            if row != dict(module=name, path='candidate/client-proc-deadline-v25/runtime/' + name + '.py',
                    sha256=pin, bytes=count): raise ValueError('v25_source_changed')
        elif row != old[name]: raise ValueError('frozen_source_changed')
        raw = fixed(row['path'], row['sha256'], row['bytes'])
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_forbidden')
        for dependency, scope in private_imports(tree):
            if dependency not in names: raise ValueError('unknown_private_dependency')
            if not scope and dependency not in available: raise ValueError('eager_dependency_order')
            if scope: deferred.append(dict(module=name, dependency=dependency, scope=list(scope)))
        if name == 'mta_client_executor':
            assignments = [node.value for node in tree.body if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
            if len(assignments) != 1 or ast.literal_eval(assignments[0]) != tuple(row['module'] for row in rows):
                raise ValueError('executor_literal_graph_changed')
        # F is authenticated/read but skipped by the actual Loader, not an
        # available private dependency for another source or deferred import.
        if name != 'mta_client_executor': available.add(name)
    if any(row['dependency'] == 'mta_client_executor' for row in deferred):
        raise ValueError('unavailable_executor_dependency')
    return rows, deferred


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments, device or test mode accepted')
        return 2
    try: rows, deferred = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('SOURCE_ONLY_FAIL: frozen graph/source/syntax/order mismatch; no device action')
        return 1
    public = dict(schema=KIND, source_count=len(rows), sources=rows,
        source_integrity_verified=True, python35_syntax_verified=True,
        previous_sources_preserved=True, eager_dependency_order_verified=True,
        deferred_import_targets_fixed=True, deferred_imports=deferred,
        deferred_call_time_order_verified=False, formal_executor_source_rewired=True,
        target_code_executed=False, tests_run=False, full_formal_lifecycle_executed=False,
        all_syscall_wall_bound_verified=False, heap_bound_verified=False,
        device_accessed=False, rf_requested=False, restoration_verified=False,
        dhcp_verified_on_device=False, ip_installed=False, endpoint_verified=False,
        send_available=False, receive_available=False, phone_tested=False)
    output = BASE / 'results' / (KIND + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static source check only. No target/test/device execution. HOST receipts are separate. Not an installer; no RF, DHCP/IP install, endpoint, restoration, send/receive or phone acceptance.\n'
    (output / 'result.json').write_bytes(encoded); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded); bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps(dict(source_only_pass=True, source_count=len(rows), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())

"""PC-only DHCP setup source delta and actual Server74 with Native models.

Twenty sources are hash/AST checked; their complete graph is not executed.
Only the actual Server and neutral wire/IP definitions are exercised in the
sole new child. Native, Store, Bootstrap, kernel, RF and physical recovery are
not exercised by that child. No old lifecycle or status method is replayed.
"""
import ast
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/go_dhcp_setup_v74_check.py'
CMD = 'HOST_MTA_GO_DHCP_SETUP_V74_CHECK.cmd'
PLAN = 'host/go_dhcp_setup_v74_source_manifest.json'
OLD_PLAN = 'host/go_typed_live_v72_source_manifest.json'
TEST = 'tests/test_go_dhcp_setup_v74.py'
# ROOT binds these only after complete source/test review, before invocation.
PLAN_PIN = (4536, '7e1633f2365fb67ad768fe574b98cdfdb24468d116d11c4d94cfde4350b8100d')
TEST_PIN = (29050, '1951e0feca25380a5cf2dd88e38cd166ec558ecedb31ef736478a222006d3390')
NATIVE_CHANGED = ('__init__', 'ip_current', 'issue_dhcp_binding', '_dhcp_owner',
    '_dhcp_gate', 'prepare_dhcp', '_dhcp_socket', 'observe_dhcp', 'dhcp_current',
    'begin_dhcp_service')
NATIVE_ADDED = ('_ip_retained_current', '_dhcp_setup_parent', '_dhcp_setup_begin',
    '_dhcp_setup_ip', '_dhcp_next_canonical', '_dhcp_setup_canonical',
    '_dhcp_setup_consume', '_dhcp_setup_server_ready', '_dhcp_udp_readback')
OLD_PLAN_PIN = (4532, '55801b38c3bd46e54f5742abc6afae32c69a150bd3426d471193edbae2f8d32d')
EXTRA_PINS = {'candidate/go-restored-status-v73/runtime/mta_go_bootstrap.py':
    (22837, 'f52141612f6f25e0c049ed74dd3177d6ab250dba370ffe291709869a475be318')}
METHOD = 'GoDhcpSetup74Test.test_setup_and_first_service_scope'
MARKER = b'HOST74_DHCP_SETUP new_methods=1 old_methods=0 native_model=true device=false phone=false\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    if type(pin) is not tuple or len(pin) != 2:
        raise ValueError('unfrozen_source')
    raw = (BASE / path).read_bytes()
    if (len(raw), sha(raw)) != pin:
        raise ValueError('source_changed')
    return raw


def parsed(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def class_node(tree, name):
    found = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]
    if len(found) != 1:
        raise ValueError('class_inventory_changed')
    return found[0]


def methods(tree, name):
    nodes = [n for n in class_node(tree, name).body if isinstance(n, ast.FunctionDef)]
    result = {n.name: n for n in nodes}
    if len(nodes) != len(result):
        raise ValueError('duplicate_method')
    return result


def same(a, b):
    return ast.dump(a) == ast.dump(b)


def preserve_methods(old, new, name, changed, added_count):
    before, after = methods(old, name), methods(new, name)
    if not set(before) <= set(after) or len(set(after) - set(before)) != added_count:
        raise ValueError('method_inventory_changed')
    actual = {k for k in before if not same(before[k], after[k])}
    if actual != set(changed):
        raise ValueError('unrelated_method_changed')
    return set(after) - set(before)


def assignment(tree, name):
    found = [n.value for n in tree.body if isinstance(n, ast.Assign) and
             len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    if len(found) != 1:
        raise ValueError('assignment_inventory_changed')
    return ast.literal_eval(found[0])


def source_merge(inputs, graph, old_graph):
    new = {row['module']: parsed(inputs[row['path']]) for row in graph['sources']}
    old = {row['module']: parsed(inputs[row['path']]) for row in old_graph['sources']}
    donor = parsed(inputs['candidate/go-restored-status-v73/runtime/mta_go_bootstrap.py'])
    if type(NATIVE_CHANGED) is not tuple or type(NATIVE_ADDED) is not tuple:
        raise ValueError('unfrozen_native_delta')
    added = preserve_methods(old['mta_go_native'], new['mta_go_native'], 'NativeGoResources',
        NATIVE_CHANGED, len(NATIVE_ADDED))
    if added != set(NATIVE_ADDED):
        raise ValueError('native_helper_inventory_changed')
    if preserve_methods(old['mta_go_native'], new['mta_go_native'], 'GoDhcpBinding',
                        ('__init__', 'active_until'), 0):
        raise ValueError('binding_inventory_changed')
    preserve_methods(old['mta_go_bootstrap_store'], new['mta_go_bootstrap_store'], 'GoBootstrapStore',
                     ('__init__', '_native_observation'), 0)
    preserve_methods(donor, new['mta_go_bootstrap'], 'GoBootstrap', ('__init__', 'prepare_live'), 0)
    if preserve_methods(old['mta_go_dhcp'], new['mta_go_dhcp'], 'GoDhcpServer',
            ('__init__', '_context', '_check', '_timeout', 'open', 'serve_once', 'allocation'), 1) != {'start_service'}:
        raise ValueError('server_inventory_changed')
    # Loader, F, ownership/Proc and other modules remain byte-for-byte original.
    changed_modules = {'mta_go_native', 'mta_go_bootstrap_store', 'mta_go_bootstrap', 'mta_go_dhcp'}
    if tuple(row['module'] for row in graph['sources']) != tuple(row['module'] for row in old_graph['sources']):
        raise ValueError('graph_order_changed')
    for name in set(new)-changed_modules:
        before = next(r for r in old_graph['sources'] if r['module']==name)
        after = next(r for r in graph['sources'] if r['module']==name)
        if inputs[before['path']] != inputs[after['path']]:
            raise ValueError('unrelated_source_changed')
    for name in ('GoIpFacts', 'GoDhcpFacts', 'GoRecord'):
        if not same(class_node(old['mta_go_bootstrap_store'], name), class_node(new['mta_go_bootstrap_store'], name)):
            raise ValueError('disk_facts_changed')
    store = new['mta_go_bootstrap_store']
    values = {}
    for n in store.body:
        if isinstance(n, ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0], ast.Tuple):
            targets = [x.id for x in n.targets[0].elts]
            if targets==['MAX_FDS', 'MAX_RECORD', 'MAX_PUBLICATIONS']:
                values['ceilings'] = ast.literal_eval(n.value)
            if targets==['_STORE_OPEN_BOUND', '_PUBLICATION_OPEN_BOUND']:
                values['opens'] = ast.literal_eval(n.value)
    if values != {'ceilings': (256, 131072, 26), 'opens': (216, 7)} or assignment(store, '_PUBLICATION_LIMITS') != {'prepare':4,'positive':12,'cleanup':5}:
        raise ValueError('resource_ceiling_changed')
    if assignment(store, 'SCHEMA') != assignment(old['mta_go_bootstrap_store'], 'SCHEMA'):
        raise ValueError('journal_schema_changed')
    # Audit the stated cost change without calling production definitions.
    for name in ('_dhcp_socket', 'observe_dhcp', 'begin_dhcp_service'):
        node = methods(new['mta_go_native'], 'NativeGoResources')[name]
        hits = [n for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr=='ip_current']
        if len(hits)!=1:
            raise ValueError('execution_boundary_ip_check_changed')



def verified_inputs():
    plan, old_plan = fixed(PLAN, PLAN_PIN), fixed(OLD_PLAN, OLD_PLAN_PIN)
    graph, old_graph = json.loads(plan), json.loads(old_plan)
    if set(graph) != {'schema', 'sources'} or graph['schema'] != 'go-dhcp-setup-v74-source' or len(graph['sources']) != 20:
        raise ValueError('graph_changed')
    if set(old_graph) != {'schema', 'sources'} or len(old_graph['sources']) != 20:
        raise ValueError('original_graph_changed')
    inputs = {PLAN: plan, OLD_PLAN: old_plan, CHECKER: Path(__file__).read_bytes(),
              CMD: (BASE / CMD).read_bytes(), TEST: fixed(TEST, TEST_PIN)}
    for tree in (graph, old_graph):
        names = []
        for row in tree['sources']:
            if set(row) != {'module', 'path', 'bytes', 'sha256'}:
                raise ValueError('graph_shape')
            names.append(row['module'])
            raw = fixed(row['path'], (row['bytes'], row['sha256']))
            if row['path'] in inputs and inputs[row['path']] != raw:
                raise ValueError('source_alias_changed')
            inputs[row['path']] = raw
        if len(set(names)) != len(names):
            raise ValueError('module_inventory_changed')
    for path, pin in EXTRA_PINS.items():
        inputs[path] = fixed(path, pin)
    if len(inputs) != 30:
        raise ValueError('input_inventory_changed')
    source_merge(inputs, graph, old_graph)
    found = [n.name + '.' + m.name for n in parsed(inputs[TEST]).body if isinstance(n, ast.ClassDef)
             for m in n.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if found != [METHOD]:
        raise ValueError('affected_method_changed')
    return inputs


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device or method arguments')
        return 2
    output = BASE / 'results' / ('go-dhcp-setup-v74-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, rows, error = {}, [], None
    private = output / 'private-inputs'
    try:
        inputs = verified_inputs()
        for path, raw in sorted(inputs.items()):
            target = private / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw:
                raise ValueError('snapshot_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        error = 'source_or_snapshot_invalid'
    stdout, stderr, code, invoked, timed_out = b'', b'', None, False, False
    started = time.monotonic()
    if error is None:
        env = dict(os.environ)
        env.pop('PYTHONPATH', None); env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr = failure.stdout or b'', failure.stderr or b''
            timed_out, invoked = True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout); (output / 'stderr.raw').write_bytes(stderr)
    unchanged = bool(inputs)
    for path, raw in inputs.items():
        try:
            unchanged = (BASE / path).read_bytes() == raw and unchanged
        except OSError:
            unchanged = False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = error is None and invoked and code == 0 and not timed_out and unchanged and marker_ok and summary_ok
    value = dict(schema='go-dhcp-setup-v74-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=unchanged,
        fixed_graph_sources=20, fixed_graph_python35_ast=True if inputs else False,
        new_method=METHOD, child_invocations=int(invoked), old_methods_invoked=0,
        child_exit=code, child_timeout=timed_out, host_elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        native_binding_udp_closure_models=True, bootstrap_executed=False, store_executed=False,
        server_definition_executed=passed, complete_graph_executed=False,
        deployment_loader_executed=False, native_ip_dhcp_executed=False,
        physical_restore_verified=False, actual_provider_tested=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        receive_available=False, send_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = ('PC-only source delta and seven affected Server74 cases with actual neutral IP/wire definitions. '
        'Twenty fixed sources are hash/AST checked; the complete graph is not executed. '
        'Native binding/issuer/UDP/closure are explicit inert models. Bootstrap and Store definitions are not executed. '
        'No kernel, IP/DHCP Native, radio, physical restore, provider, device or phone result. '
        'The source sampling policy keeps full checks before UDP factory, after bind, and before first service. '
        'Its predicted 21-to-9 snapshots and unchanged resource ceilings are SOURCE contracts, not measured speed or success. '
        'Setup20 and the first post-setup service20 are each bounded by the original session; poll never renews. '
        'Strict marker, Ran1/OK, child0/no-timeout and source preservation gate raw publication; failures retain raw privately.\n').encode('ascii')

    (output / 'result.json').write_bytes(result); (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None:
            raise ValueError('zip_inventory_changed')
        for name, raw in members.items():
            entry = bundle.getinfo(name)
            if bundle.read(name) != raw or entry.file_size != len(raw) or entry.CRC != zlib.crc32(raw) & 0xffffffff:
                raise ValueError('zip_member_changed')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timed_out,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())

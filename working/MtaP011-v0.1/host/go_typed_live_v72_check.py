"""PC-only current typed GO source merge and affected orchestration models.

Twenty sources are hashed/AST checked; the complete graph is not executed.
The sole child executes Bootstrap72 definitions with explicit models; native IP,
DHCP, Loader, journal, kernel, radio and physical restore are not validated.
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
CHECKER = 'host/go_typed_live_v72_check.py'
CMD = 'HOST_MTA_GO_TYPED_LIVE_V72_CHECK.cmd'
PLAN = 'host/go_typed_live_v72_source_manifest.json'
OLD_PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
TEST = 'tests/test_go_typed_live_v72.py'
PLAN_PIN = (4532, '55801b38c3bd46e54f5742abc6afae32c69a150bd3426d471193edbae2f8d32d')
OLD_PLAN_PIN = (3955, 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842')
# ROOT completely read and bound the sole new test before its first invocation.
TEST_PIN = (42798, '2abb15bbc4c3dadc1d8b120270aa2f529645d9ac5e25f4a350ea7f2c36451724')
EXTRA_PINS = {
    'candidate/go-live-owner-v71/runtime/mta_go_bootstrap.py':
        (18394, 'e15a99747fc6b3fd47a0c714fdec45dd815ad377737183078fbc9809d041a442'),
    'candidate/go-ip-dhcp-v43/runtime/mta_go_bootstrap.py':
        (20520, '6458460e4e01040ab70cd616c25b462aacaa3b34bc240d65280cc7753b196444'),
    'candidate/go-ip-dhcp-v43/runtime/mta_go_bootstrap_store.py':
        (76579, '35f95f8ea78b6be54d4afb16629456ffe1359624d291f927262a8c07d6fba537'),
    'candidate/go-ip-dhcp-proc-vanish-v54/runtime/mta_go_native.py':
        (117388, 'b056c570ca0d9d887f6b9089dbcbd41ae26931c69965b944cc1078ca515d8c0f')}
METHOD = 'GoTypedLive72Test.test_typed_l3_same_owner_poll_and_restore'
MARKER = b'HOST72_GO_TYPED_LIVE new_methods=1 old_methods=0 orchestration_model=true device=false phone=false\n'


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
    native_donor = parsed(inputs['candidate/go-ip-dhcp-proc-vanish-v54/runtime/mta_go_native.py'])
    store_donor = parsed(inputs['candidate/go-ip-dhcp-v43/runtime/mta_go_bootstrap_store.py'])
    bootstrap_donor = parsed(inputs['candidate/go-ip-dhcp-v43/runtime/mta_go_bootstrap.py'])
    bootstrap_old = parsed(inputs['candidate/go-live-owner-v71/runtime/mta_go_bootstrap.py'])
    added = preserve_methods(old['mta_go_native'], new['mta_go_native'], 'NativeGoResources',
        ('__init__', '_socket', '_exchange', '_outside_key', 'prepare_cleanup',
         'stop_child', 'delete_interface', 'observe_restore'), 21)
    for name in added:
        if not same(methods(new['mta_go_native'], 'NativeGoResources')[name],
                    methods(native_donor, 'NativeGoResources')[name]):
            raise ValueError('typed_native_method_changed')
    for name in ('GoIpObservation', 'GoIpRestoreObservation', 'GoDhcpObservation', 'GoDhcpBinding'):
        if not same(class_node(new['mta_go_native'], name), class_node(native_donor, name)):
            raise ValueError('typed_native_class_changed')
    added = preserve_methods(old['mta_go_bootstrap_store'], new['mta_go_bootstrap_store'], 'GoBootstrapStore',
        ('_save', '_native_observation', 'reserve', 'finish_restore'), 10)
    for name in added:
        if not same(methods(new['mta_go_bootstrap_store'], 'GoBootstrapStore')[name],
                    methods(store_donor, 'GoBootstrapStore')[name]):
            raise ValueError('typed_store_method_changed')
    for name in ('GoIpFacts', 'GoDhcpFacts', 'GoRecord'):
        if not same(class_node(new['mta_go_bootstrap_store'], name), class_node(store_donor, name)):
            raise ValueError('typed_store_class_changed')
    if preserve_methods(bootstrap_old, new['mta_go_bootstrap'], 'GoBootstrap',
        ('__init__', 'prepare_live', 'restore', 'run', 'status'), 1) != {'poll_dhcp'} or not same(
            class_node(new['mta_go_bootstrap'], '_DhcpConstructor'),
            class_node(bootstrap_donor, '_DhcpConstructor')):
        raise ValueError('bootstrap_merge_changed')
    if preserve_methods(old['mta_go_deployment'], new['mta_go_deployment'], 'GoDeploymentLoader', ('load',), 0):
        raise ValueError('loader_inventory_changed')
    # The loader method itself changes only the fixed deployment schema.
    load = copy.deepcopy(methods(new['mta_go_deployment'], 'GoDeploymentLoader')['load'])
    changed = 0
    for node in ast.walk(load):
        if isinstance(node, ast.Constant) and node.value == 'p011-go-typed-live-v72':
            node.value = 'p011-go-bootstrap-v33'; changed += 1
    if changed != 1 or not same(load, methods(old['mta_go_deployment'], 'GoDeploymentLoader')['load']):
        raise ValueError('loader_mechanics_changed')
    if assignment(new['mta_go_deployment'], 'MODULES') != tuple(row['module'] for row in graph['sources']):
        raise ValueError('loader_order_changed')
    store = new['mta_go_bootstrap_store']
    values = {}
    for n in store.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Tuple):
            if [x.id for x in n.targets[0].elts] == ['MAX_FDS', 'MAX_RECORD', 'MAX_PUBLICATIONS']:
                values['ceilings'] = ast.literal_eval(n.value)
            if [x.id for x in n.targets[0].elts] == ['_STORE_OPEN_BOUND', '_PUBLICATION_OPEN_BOUND']:
                values['opens'] = ast.literal_eval(n.value)
    if values != {'ceilings': (256, 131072, 26), 'opens': (216, 7)} or assignment(
            store, '_PUBLICATION_LIMITS') != {'prepare': 4, 'positive': 12, 'cleanup': 5}:
        raise ValueError('resource_ceiling_changed')


def verified_inputs():
    plan, old_plan = fixed(PLAN, PLAN_PIN), fixed(OLD_PLAN, OLD_PLAN_PIN)
    graph, old_graph = json.loads(plan), json.loads(old_plan)
    if set(graph) != {'schema', 'sources'} or graph['schema'] != 'go-typed-live-v72-source' or len(graph['sources']) != 20:
        raise ValueError('graph_changed')
    if set(old_graph) != {'schema', 'sources'} or len(old_graph['sources']) != 17:
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
    if len(inputs) != 33:
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
    output = BASE / 'results' / ('go-typed-live-v72-host-' +
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
    value = dict(schema='go-typed-live-v72-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=unchanged,
        fixed_graph_sources=20, fixed_graph_python35_ast=True if inputs else False,
        new_method=METHOD, child_invocations=int(invoked), old_methods_invoked=0,
        child_exit=code, child_timeout=timed_out, host_elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        dependency_native_store_loader_children_models=True, complete_graph_executed=False,
        deployment_loader_executed=False, native_ip_dhcp_executed=False,
        physical_restore_verified=False, actual_provider_tested=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        receive_available=False, send_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = ('PC-only source merge and affected Bootstrap72 orchestration models. '
        'Twenty fixed sources are hash/AST checked; the complete graph is not executed. Bootstrap72 definitions execute with explicit dependency, Native, Store, Loader and children models. '
        'No actual graph, kernel, IP/DHCP, radio, physical restore, provider, device or phone result. '
        '21 publications and the retained resource ceilings are SOURCE contracts, not measured success or speed. '
        'The once 20-second service includes setup costs and is not guaranteed to complete. '
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

"""PC-only affected Native75 credentials/TCP tests; never accesses ADB.

Source snapshots and Python3.5 syntax checks are distinct from the child test.
The child exercises fixed production definitions with explicit inert owner,
IP/DHCP and Linux socket models, not a deployment or physical RF flow.
"""
import ast
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
PLAN = 'host/go_send_basis_v75_source_manifest.json'
OLD_PLAN = 'host/go_dhcp_setup_v74_source_manifest.json'
CHECKER = 'host/go_send_basis_v75_check.py'
CMD = 'HOST_MTA_GO_SEND_BASIS_V75_CHECK.cmd'
TEST = 'tests/test_go_send_basis_v75.py'
PLAN_PIN = (4535, 'c2ee688cdb8fbb2a6916e9a947516426a69c2e3dca267c46ea549069f130e057')
TEST_PIN = (38523, 'fe35bdcb1be155d6874d09952f648c243e7db67a3940470b614a31d1add614be')
OLD_PLAN_PIN = (4536, '7e1633f2365fb67ad768fe574b98cdfdb24468d116d11c4d94cfde4350b8100d')
NATIVE_CHANGED = ('__init__', 'close_dhcp', 'prepare_ip_cleanup', 'restore_ip', 'prepare_cleanup', 'delete_interface')
NATIVE_ADDED = ('_send_dhcp_v75', '_send_udp_current_v75', '_send_basis_gate_v75', 'issue_send_basis',
    '_send_tcp_current_v75', 'open_send_listener', '_send_inventory_v75', '_send_closed_v75', 'close_send_inventory')
METHOD = 'GoSendBasis75Test.test_go_credentials_and_owned_tcp'
MARKER = b'HOST75_SEND_BASIS new_methods=1 old_methods=0 os_model=true device=false phone=false\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    if type(pin) is not tuple or len(pin) != 2:
        raise ValueError('source_not_frozen')
    raw = (BASE / path).read_bytes()
    if (len(raw), sha(raw)) != pin:
        raise ValueError('source_changed')
    return raw


def parsed(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def definitions(tree):
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    values = {n.name: n for n in nodes}
    if len(values) != len(nodes):
        raise ValueError('duplicate_definition')
    return values


def methods(node):
    nodes = [n for n in node.body if isinstance(n, ast.FunctionDef)]
    values = {n.name: n for n in nodes}
    if len(values) != len(nodes):
        raise ValueError('duplicate_method')
    return values


def method_delta(before, after, changed, added):
    old, new = methods(before), methods(after)
    if not set(old) <= set(new) or set(new)-set(old) != set(added):
        raise ValueError('method_inventory_changed')
    actual = {name for name in old if ast.dump(old[name]) != ast.dump(new[name])}
    if actual != set(changed):
        raise ValueError('unrelated_method_changed')


def source_delta(inputs, current, original):
    before = {r['module']: r for r in original['sources']}
    after = {r['module']: r for r in current['sources']}
    if tuple(before) != tuple(after):
        raise ValueError('module_order_changed')
    if type(NATIVE_CHANGED) is not tuple or type(NATIVE_ADDED) is not tuple:
        raise ValueError('delta_not_frozen')
    for name in before:
        old_raw, new_raw = inputs[before[name]['path']], inputs[after[name]['path']]
        if name not in ('mta_go_native', 'mta_go_bootstrap'):
            if old_raw != new_raw:
                raise ValueError('unrelated_source_changed')
            continue
        old_tree, new_tree = parsed(old_raw), parsed(new_raw)
        old, new = definitions(old_tree), definitions(new_tree)
        if not set(old) <= set(new):
            raise ValueError('original_definition_missing')
        # Keep original imports/constants/module initialization unchanged;
        # only documentation and new definitions may be appended here.
        current_top = {ast.dump(n) for n in new_tree.body}
        for n in old_tree.body:
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                continue
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                continue
            if ast.dump(n) not in current_top:
                raise ValueError('original_top_level_changed')
        changing = {'NativeGoResources', '_LinuxIo', '_Resource'} if name == 'mta_go_native' else {'GoBootstrap'}
        for definition in set(old)-changing:
            if ast.dump(old[definition]) != ast.dump(new[definition]):
                raise ValueError('unrelated_definition_changed')
        if name == 'mta_go_native':
            method_delta(old['NativeGoResources'], new['NativeGoResources'], NATIVE_CHANGED, NATIVE_ADDED)
            method_delta(old['_LinuxIo'], new['_LinuxIo'], (), ('tcp',))
            method_delta(old['_Resource'], new['_Resource'], ('__init__',), ())
        else:
            method_delta(old['GoBootstrap'], new['GoBootstrap'], ('__init__', 'restore', 'status'), ('prepare_send_listener',))


def verified_inputs():
    plan = fixed(PLAN, PLAN_PIN)
    old_plan = fixed(OLD_PLAN, OLD_PLAN_PIN)
    current, original = json.loads(plan), json.loads(old_plan)
    if set(current) != {'schema', 'sources'} or current['schema'] != 'go-send-basis-v75-source':
        raise ValueError('plan_changed')
    if set(original) != {'schema', 'sources'} or len(current['sources']) != 20 or len(original['sources']) != 20:
        raise ValueError('graph_count_changed')
    inputs = {PLAN: plan, OLD_PLAN: old_plan, CHECKER: Path(__file__).read_bytes(),
              CMD: (BASE / CMD).read_bytes(), TEST: fixed(TEST, TEST_PIN)}
    for graph in (current, original):
        names = []
        for row in graph['sources']:
            if set(row) != {'module', 'path', 'bytes', 'sha256'}:
                raise ValueError('source_row_changed')
            names.append(row['module'])
            raw = fixed(row['path'], (row['bytes'], row['sha256']))
            parsed(raw)
            if row['path'] in inputs and inputs[row['path']] != raw:
                raise ValueError('source_alias_changed')
            inputs[row['path']] = raw
        if len(set(names)) != len(names):
            raise ValueError('duplicate_module')
    if len(inputs) != 27:
        raise ValueError('input_inventory_changed')
    source_delta(inputs, current, original)
    found = [n.name+'.'+m.name for n in parsed(inputs[TEST]).body if isinstance(n, ast.ClassDef)
             for m in n.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if found != [METHOD]:
        raise ValueError('test_method_changed')
    return inputs


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device or method arguments')
        return 2
    output = BASE / 'results' / ('go-send-basis-v75-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    private = output / 'private-inputs'
    inputs, rows, error = {}, [], None
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
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONSTARTUP', None)
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
    elapsed = time.monotonic()-started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    unchanged = bool(inputs)
    for path, raw in inputs.items():
        try:
            unchanged = ((BASE / path).read_bytes() == raw) and unchanged
        except OSError:
            unchanged = False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = error is None and invoked and code == 0 and not timed_out and unchanged and marker_ok and summary_ok
    value = dict(schema='go-send-basis-v75-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=unchanged,
        fixed_graph_sources=20, fixed_graph_python35_ast=bool(inputs), new_method=METHOD,
        child_invocations=int(invoked), old_methods_invoked=0, child_exit=code,
        child_timeout=timed_out, host_elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        affected_native_definition_executed=passed, os_owner_ip_dhcp_models=True,
        complete_graph_executed=False, deployment_loader_executed=False,
        actual_linux_tcp_tested=False, actual_gatt_tested=False, actual_tls_tested=False,
        physical_restore_verified=False, device_accessed=False, phone_tested=False,
        rf_requested=False, candidate_deployed=False, receive_available=False, send_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True)+'\n').encode('ascii')
    readme = ('PC-only affected Native75 credentials and owned TCP producer checks. '
        'Fixed source snapshots and Python3.5 AST checks are not execution of the full graph. '
        'Owner, IP/DHCP, Linux socket and EBADF inputs are explicit inert models. '
        'No actual network socket, device, RF, GATT, TLS, phone interop or physical restoration. '
        'Listener is only bound, not listening or accepting; private credentials are never archived. '
        'Original service cap is not renewed. No old test methods are replayed. '
        'Public raw is included only after exact marker, Ran1/OK, child0/no-timeout and source preservation.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
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

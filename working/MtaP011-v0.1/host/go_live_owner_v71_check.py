"""PC-only affected GO lifecycle check; no device, RF or native graph execution.

The unique child runs the new whole GoBootstrap definition with explicitly inert
dependency/worker/native/restore models. The existing fixed GO source graph is
hash checked and preserved, not executed and not declared device-compatible.
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
CHECKER = 'host/go_live_owner_v71_check.py'
CMD = 'HOST_MTA_GO_LIVE_V71_CHECK.cmd'
OWNER = 'candidate/go-live-owner-v71/runtime/mta_go_bootstrap.py'
TEST = 'tests/test_go_live_owner_v71.py'
ORIGINAL = 'candidate/go-baseline-budget-v58/runtime/mta_go_bootstrap.py'
PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
ORIGINAL_PIN = (17396, 'de98101c6c56661b9557cf2f857645ff5ecefa3d7663e58c4ebe1fd16187035d')
PLAN_PIN = (3955, 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842')
# Exact ROOT-reviewed fixed sources; only the affected new method is invoked.
OWNER_PIN = (18394, 'e15a99747fc6b3fd47a0c714fdec45dd815ad377737183078fbc9809d041a442')
TEST_PIN = (23987, '6b115228650b90b3acdc6a9155b1dfeddf52b2ae8b55eb00a117aadff5c42204')
METHOD = 'GoLiveOwner71Test.test_prepare_live_and_default_restore'
MARKER = b'HOST71_GO_LIVE new_methods=1 old_methods=0 lifecycle_model=true device=false phone=false\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    if type(pin) is not tuple or len(pin) != 2:
        raise ValueError('unfrozen_source')
    raw = (BASE / path).read_bytes()
    if len(raw) != pin[0] or sha(raw) != pin[1]:
        raise ValueError('source_changed')
    return raw


def preserved_definitions(original, owner):
    old = ast.parse(original.decode('utf-8'), feature_version=(3, 5))
    new = ast.parse(owner.decode('utf-8'), feature_version=(3, 5))
    previous = {n.name: n for n in old.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    current = {n.name: n for n in new.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    if set(previous) != set(current):
        raise ValueError('definition_inventory_changed')
    for name, before in previous.items():
        after = current[name]
        if name != 'GoBootstrap':
            if ast.dump(before) != ast.dump(after):
                raise ValueError('unchanged_definition_changed')
            continue
        old_methods = {n.name: n for n in before.body if isinstance(n, ast.FunctionDef)}
        new_methods = {n.name: n for n in after.body if isinstance(n, ast.FunctionDef)}
        if set(new_methods) != set(old_methods) | {'prepare_live'}:
            raise ValueError('new_method_inventory_changed')
        for method in old_methods:
            if method != 'run' and ast.dump(old_methods[method]) != ast.dump(new_methods[method]):
                raise ValueError('original_method_changed')
        old_try = next(n for n in old_methods['run'].body if isinstance(n, ast.Try))
        new_try = next(n for n in new_methods['prepare_live'].body if isinstance(n, ast.Try))
        if ast.dump(ast.Module(body=old_try.body, type_ignores=[])) != ast.dump(
                ast.Module(body=new_try.body[:len(old_try.body)], type_ignores=[])):
            raise ValueError('preparation_sequence_changed')


def verified_inputs():
    original, plan = fixed(ORIGINAL, ORIGINAL_PIN), fixed(PLAN, PLAN_PIN)
    owner, test = fixed(OWNER, OWNER_PIN), fixed(TEST, TEST_PIN)
    preserved_definitions(original, owner)
    tree = json.loads(plan)
    if type(tree) is not dict or set(tree) != {'schema', 'sources'} or len(tree['sources']) != 17:
        raise ValueError('original_graph_changed')
    inputs = {PLAN: plan, OWNER: owner, TEST: test, CHECKER: Path(__file__).read_bytes(),
              CMD: (BASE / CMD).read_bytes()}
    names = []
    for row in tree['sources']:
        if set(row) != {'module', 'path', 'bytes', 'sha256'}:
            raise ValueError('original_graph_shape')
        names.append(row['module'])
        inputs[row['path']] = fixed(row['path'], (row['bytes'], row['sha256']))
    if len(set(names)) != 17 or inputs.get(ORIGINAL) != original:
        raise ValueError('original_graph_inventory')
    methods = [n.name + '.' + m.name for n in ast.parse(test.decode('utf-8')).body
               if isinstance(n, ast.ClassDef) for m in n.body
               if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('affected_method_changed')
    return inputs


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device or method arguments')
        return 2
    output = BASE / 'results' / ('go-live-owner-v71-host-' +
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
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    unchanged = bool(inputs)
    for path, raw in inputs.items():
        try:
            unchanged = (BASE / path).read_bytes() == raw and unchanged
        except OSError:
            unchanged = False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = error is None and invoked and code == 0 and not timed_out and unchanged and marker_ok and summary_ok
    value = dict(schema='go-live-owner-v71-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=unchanged,
        new_method=METHOD, child_invocations=int(invoked), old_methods_invoked=0,
        child_exit=code, child_timeout=timed_out, host_elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        dependency_worker_native_restore_models=True, original_go_graph_executed=False,
        deployment_loader_executed=False, native_restore_verified=False,
        actual_ip_dhcp_tested=False, actual_provider_tested=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        receive_available=False, send_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = ('PC-only affected lifecycle test of the new whole GoBootstrap definition. '
        'Dependency, worker, native and restore seams are explicit inert models. '
        'Existing 17-source GO graph hashes are preserved, not executed. '
        'No old test, native kernel IO, deployment, IP/DHCP, provider, device, phone or RF evidence. '
        'The same-owner live preparation does not grant send/receive capability. '
        'Raw output is public only after exact fixed marker, Ran1/OK, child0/no-timeout and source preservation. '
        'Failures retain raw privately; all results and source snapshots have unique immutable paths.\n').encode('ascii')
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

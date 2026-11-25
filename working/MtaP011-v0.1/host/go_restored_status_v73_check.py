"""PC-only: execute the actual status projection against explicit inert facts.

No Bootstrap constructor, lifecycle, dependency graph, Loader, Native, device,
RF or phone is executed. Nine affected pure status vectors are not restoration.
The original HOST72 lifecycle method is not imported or replayed.
"""
import ast
import copy
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time
import types
import uuid
import zipfile
import zlib
from contextlib import ExitStack
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/go_restored_status_v73_check.py'
CMD = 'HOST_MTA_GO_RESTORED_STATUS_V73_CHECK.cmd'
OLD = 'candidate/go-typed-live-v72/runtime/mta_go_bootstrap.py'
NEW = 'candidate/go-restored-status-v73/runtime/mta_go_bootstrap.py'
PINS = {OLD: (22707, '1db6bcea1aab324ae7c21eb5d116d77728e73de01865c64a4a8fc778481b40e3'),
        NEW: (22837, 'f52141612f6f25e0c049ed74dd3177d6ab250dba370ffe291709869a475be318')}
MARKER = b'HOST73_RESTORED_STATUS affected_vectors=9 old_methods=0 lifecycle=false device=false phone=false\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def status_node(tree):
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GoBootstrap']
    if len(classes) != 1:
        raise ValueError('class_inventory_changed')
    nodes = [n for n in classes[0].body if isinstance(n, ast.FunctionDef) and n.name == 'status']
    if len(nodes) != 1:
        raise ValueError('status_inventory_changed')
    return classes[0], nodes[0]


def projected_function(inputs):
    old = ast.parse(inputs[OLD].decode('utf-8'), feature_version=(3, 5))
    new = ast.parse(inputs[NEW].decode('utf-8'), feature_version=(3, 5))
    old_class, old_status = status_node(old)
    new_class, new_status = status_node(new)
    if ast.dump(old_status) == ast.dump(new_status):
        raise ValueError('missing_status_delta')
    # Reverse only the status definition and documented source-version label.
    comparison = copy.deepcopy(new)
    cls, node = status_node(comparison)
    cls.body[cls.body.index(node)] = copy.deepcopy(old_status)
    expected_doc = ast.literal_eval(old.body[0].value).replace('SOURCE v72 only.', 'SOURCE v73 only.')
    if ast.literal_eval(new.body[0].value) != expected_doc:
        raise ValueError('unrelated_documentation_changed')
    comparison.body[0] = copy.deepcopy(old.body[0])
    if ast.dump(comparison) != ast.dump(old):
        raise ValueError('unrelated_definition_changed')
    calls = [n for n in ast.walk(new_status) if isinstance(n, ast.Call)]
    if len(calls) != 1 or not isinstance(calls[0].func, ast.Name) or calls[0].func.id != 'bool':
        raise ValueError('status_io_or_authority_changed')
    # Extract and execute ONLY the actual status function; not the source module.
    unit = ast.Module(body=[copy.deepcopy(new_status)], type_ignores=[])
    namespace = {}
    exec(compile(ast.fix_missing_locations(unit), 'HOST73_actual_status_only', 'exec'), namespace)
    return namespace['status']


def forbidden(*args, **kwargs):
    raise AssertionError('status_platform_io_forbidden')


def vectors(function):
    cases = (
        ('absent', False, 'idle', None, False, None, False),
        ('logical_without_attempt', False, 'restored', None, True, None, False),
        ('pending_final_failure', True, 'restore_pending', object(), True, None, False),
        ('pending_stale_logical', True, 'restore_pending', None, True, None, False),
        ('restored_with_error', True, 'restored', object(), True, None, False),
        ('logical_not_restored', True, 'restored', None, False, None, False),
        ('non_boolean_logical', True, 'restored', None, 1, None, False),
        ('business_failed_but_restored', True, 'restored', None, True, object(), True),
        ('restored_success', True, 'restored', None, True, None, True))
    results = []
    targets = [(io, 'open'), (socket, 'socket'), (subprocess, 'Popen'),
               (select, 'select'), (threading.Thread, 'start')]
    for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'mkdir',
                 'unlink', 'rename', 'fork', 'execve', 'kill'):
        if hasattr(os, name):
            targets.append((os, name))
    with ExitStack() as stack:
        probes = [stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
                  for owner, name in targets]
        # Builtins open is also forbidden while the extracted function runs.
        import builtins
        probes.append(stack.enter_context(mock.patch.object(builtins, 'open', side_effect=forbidden)))
        for name, attempted, phase, error, logical, business_error, expected in cases:
            owner = types.SimpleNamespace(phase=phase, restore_attempted=attempted,
                restore_failure=error, failure=business_error,
                store=types.SimpleNamespace(logical_restored=logical),
                group_confirmed=False, ip_confirmed=False, dhcp_listening=False,
                until=301.0, entry=types.SimpleNamespace(until=301.0))
            actual = function(owner)
            if actual['restored'] is not expected or actual['phase'] != phase:
                raise AssertionError('status_projection_wrong')
            for flag in ('go_ready', 'ip_ready', 'dhcp_ready', 'send_ready', 'device_tested', 'phone_tested'):
                if actual[flag] is not False:
                    raise AssertionError('status_promoted_authority')
            if not actual['original_until_unchanged'] or any(p.call_count for p in probes):
                raise AssertionError('status_unexpected_io')
            results.append({'case': name, 'restored': actual['restored'], 'passed': True})
    return results


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device arguments')
        return 2
    output = BASE / 'results' / ('go-restored-status-v73-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, rows, tested, error = {}, [], [], None
    started = time.monotonic()
    try:
        for path, pin in PINS.items():
            raw = (BASE / path).read_bytes()
            if (len(raw), sha(raw)) != pin:
                raise ValueError('source_changed')
            inputs[path] = raw
        inputs[CHECKER] = Path(__file__).read_bytes()
        inputs[CMD] = (BASE / CMD).read_bytes()
        for path, raw in sorted(inputs.items()):
            target = output / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw:
                raise ValueError('snapshot_changed')
            rows.append({'path': path, 'bytes': len(raw), 'sha256': sha(raw)})
        tested = vectors(projected_function(inputs))
    except (OSError, ValueError, AssertionError, KeyError, TypeError, SyntaxError, UnicodeError):
        error = 'status_projection_check_failed'
    preserved = bool(inputs) and all((BASE / path).read_bytes() == raw for path, raw in inputs.items())
    passed = error is None and len(tested) == 9 and preserved
    raw = MARKER if passed else b'HOST73_STATUS_CHECK_FAILED\n'
    value = dict(schema='go-restored-status-v73-host', passed=passed, verification_error=error,
        input_snapshot_count=len(rows), inputs=rows, sources_preserved=preserved,
        affected_vectors=len(tested), old_methods_invoked=0, child_invocations=0,
        status_definition_executed=True if tested else False, bootstrap_constructor_executed=False,
        lifecycle_executed=False, complete_graph_executed=False, physical_restore_verified=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        receive_available=False, send_available=False, host_elapsed_seconds=time.monotonic()-started,
        raw_bytes=len(raw), raw_sha256=sha(raw))
    members = {
        'result.json': (json.dumps(value, indent=2, sort_keys=True)+'\n').encode('ascii'),
        'README.txt': b'PC-only actual status projection with nine explicit inert fact vectors. No old lifecycle test is replayed. No constructor, dependency graph, native recovery, RF, device or phone result. A true projection in a model is not physical restoration. Source v72 and its results remain unchanged; v73 is not deployed or integrated into the v72 source graph.\n',
        'vectors.json': (json.dumps(tested, indent=2, sort_keys=True)+'\n').encode('ascii'),
        'model.raw': raw}
    for name, content in members.items():
        (output / name).write_bytes(content)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, content in members.items():
            bundle.writestr(name, content)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None:
            raise ValueError('zip_inventory_changed')
        for name, content in members.items():
            entry = bundle.getinfo(name)
            if bundle.read(name) != content or entry.file_size != len(content) or entry.CRC != (zlib.crc32(content)&0xffffffff):
                raise ValueError('zip_member_changed')
    print(json.dumps(dict(passed=passed, affected_vectors=len(tested), result_zip=str(archive),
        zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())

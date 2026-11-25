"""HOST94: new terminal request/response pure codecs and new-source AST.
No old tests, old-target AST, WSL, device, radio, observer IO or admission.
Generated result snapshots preserve exact inputs and unmodified raw output.
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

BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/go_terminal_packet_v94_source_manifest.json'
TEST = 'tests/test_go_terminal_packet_v94.py'
CHECKER = 'host/go_terminal_packet_v94_check.py'
CMD = 'HOST_MTA_GO_TERMINAL_PACKET_V94_CHECK.cmd'
PLAN_PIN = (2086, '8ad5eee67fb651764da4940c9f32a26f63966ff292dd2aa05a54e349f98d0107')
METHOD = 'GoTerminalPacket94Test.test_cleanup_request_and_complete_terminal_packet'
MARKER = (b'HOST94_TERMINAL_PACKET new_methods=1 old_methods=0 domains=2 fixtures=26 '
          b'pure_codec=true device=false phone=false\n')
HOST_PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
HOST_PYTHON_PIN = (103192, '42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    raw = path.read_bytes()
    if type(pin) is not tuple or (len(raw), sha(raw)) != pin:
        raise ValueError('input_identity_changed')
    return raw


def inputs():
    if Path(sys.executable).resolve() != HOST_PYTHON.resolve() or sys.version_info[:2] != (3, 12):
        raise ValueError('fixed_host_python_required')
    fixed(HOST_PYTHON, HOST_PYTHON_PIN)
    plan_raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(plan_raw)
    if (set(plan) != {'schema', 'sources', 'runtime_source_count'} or
        plan['schema'] != 'go-terminal-packet-v94-host-source' or
        type(plan['sources']) is not list or len(plan['sources']) != 9 or
        type(plan['runtime_source_count']) is not int or plan['runtime_source_count'] != 4):
        raise ValueError('source_manifest_invalid')
    values = {PLAN: plan_raw, CHECKER: Path(__file__).read_bytes(), CMD: (BASE / CMD).read_bytes()}
    targets = 0
    for row in plan['sources']:
        if type(row) is not dict or set(row) != {'path', 'bytes', 'sha256', 'python35_target'}:
            raise ValueError('source_manifest_row_invalid')
        path = row['path']
        if (type(path) is not str or path.startswith('/') or '..' in path.split('/') or
            ':' in path or '\\' in path or path in values or type(row['python35_target']) is not bool):
            raise ValueError('source_manifest_inventory_invalid')
        raw = fixed(BASE / path, (row['bytes'], row['sha256']))
        if row['python35_target']:
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            targets += 1
        values[path] = raw
    if targets != 4 or TEST not in values:
        raise ValueError('source_manifest_count_invalid')
    tree = ast.parse(values[TEST].decode('utf-8'))
    methods = [node.name + '.' + method.name for node in tree.body
               if isinstance(node, ast.ClassDef) for method in node.body
               if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('unexpected_test_method')
    return values, targets


def main():
    if len(sys.argv) != 1:
        print('HOST_ONLY no device arguments')
        return 2
    output = BASE / 'results' / ('go-terminal-packet-v94-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    private = output / 'private-inputs'
    source, rows, error, targets = {}, [], None, 0
    try:
        source, targets = inputs()
        for path, raw in sorted(source.items()):
            target = private / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw:
                raise ValueError('snapshot_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError):
        error = 'source_snapshot_or_tool_invalid'
    started = time.monotonic()
    stdout, stderr, child_exit, invoked, timeout = b'', b'', None, False, False
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([str(HOST_PYTHON), '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            stdout, stderr, child_exit, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, invoked, timeout = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    preserved = bool(source)
    for path, raw in source.items():
        try:
            preserved = (BASE / path).read_bytes() == raw and preserved
        except OSError:
            preserved = False
    host_preserved = False
    try:
        host_preserved = bool(fixed(HOST_PYTHON, HOST_PYTHON_PIN))
    except (OSError, ValueError):
        pass
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = bool(error is None and invoked and not timeout and child_exit == 0 and
                  preserved and host_preserved and marker_ok and summary_ok)
    value = dict(schema='go-terminal-packet-v94-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=targets,
        new_method=METHOD, domains=2, fixtures=26, positive_fixtures=3, refusal_fixtures=23,
        fixed_pure_definition_inputs=5, child_invocations=int(invoked),
        new_method_dispatch_attempts=int(invoked), new_methods_verified=int(passed),
        old_methods_invoked=0, old_python35_targets_parsed=0, child_exit=child_exit,
        child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout),
        stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        host_python_pin=HOST_PYTHON_PIN, host_python_preserved=host_preserved,
        actual_pure_terminal_codec_executed=passed, finish_journal_snapshot_absence_inputs_modelled=True,
        actual_kernel_pipe_executed=False, actual_entry_io_executed=False,
        actual_observer_collection_executed=False, actual_observer_source_graph_loaded=False,
        actual_parent_process_executed=False, full_private_go_graph_loaded=False,
        actual_python_arm_image_executed=False, actual_helper_executed=False,
        state_constructed=False, server_constructed=False, owner_start_executed=False,
        target_staging_executed=False, production_bundle_seal_issued=False,
        admission_issued=False, device_accessed=False, phone_tested=False,
        rf_requested=False, interface_or_address_configuration=False,
        physical_restore_verified=False, candidate_deployed=False,
        send_available=False, receive_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One new HOST94 method: request/response DATA codecs, 26 explicit fixtures '
        b'(3 positive, 23 refusals). Actual fixed pure JSON/IP/Core/Snapshot/Packet '
        b'definitions execute; no native Actor/Snapshot or observer IO is issued. '
        b'Finish/Journal/Snapshot/absence input facts are models, not observations. '
        b'Only four new runtime sources receive Python3.5 AST; no old test or AST replay. '
        b'No Entry/Loader graph, Parent/pipes/reap, State, helper, RF/device/phone, '
        b'physical restore or admission. Failed raw stays private; strict marker and Ran1/OK gate public raw.\n')
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
        if bundle.namelist() != list(members) or bundle.testzip() is not None or any(
                bundle.read(name) != raw for name, raw in members.items()):
            raise ValueError('public_zip_changed')
    print(json.dumps(dict(passed=passed, child_exit=child_exit, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())

"""Three new affected HOST methods for Parent86 / Entry87 / Owner88.

Old method suites and old target AST checks are never replayed. Runtime
compatibility checks apply only to these four new runtime sources; execution is
HOST Python3.12. Private original-child tail, pipe/FD/clock and service
constructor observations are explicit models, not actual P011 operations.
Full packet algorithms and snapshot DATA decoding are tested in their stated
domains only. No real collect/helper/restore, Parent process launch, server,
staging, RF, phone, final seal or production admission.
Successful child raw must be its exact safe marker and Ran1/OK; failure raw is
kept private and cannot enter the public result ZIP.
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
PLAN = 'host/go_send_parent_entry_v88_source_manifest.json'
CHECKER = 'host/go_send_parent_entry_v88_check.py'
CMD = 'HOST_MTA_GO_SEND_PARENT_ENTRY_V88_CHECK.cmd'
PLAN_PIN = (12472, '69a8ae78ee7cc3dde1e54c77d27670a443a1f19246963422dbc3c048ab1c9310')
PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
TESTS = (
    ('parent', 'tests/test_go_finish_parent_v86.py',
     'GoFinishParent86Test.test_original_child_tail_data_and_refusals', 16,
     b'HOST86_FINISH_PARENT new_methods=1 old_methods=0 cases=16 child_tail_model=true device=false phone=false\n'),
    ('entry', 'tests/test_go_readonly_entry_v87.py',
     'GoReadonlyEntry87Test.test_private_packet_and_entry_boundaries', 13,
     b'HOST87_ENTRY new_methods=1 old_methods=0 cases=13 filesystem_model=true pipe_model=true device=false phone=false\n'),
    ('owner', 'tests/test_service_owner_v88.py',
     'ServiceOwner88Test.test_fixed_boot_roles_and_original_service_cap', 10,
     b'HOST88_SERVICE_CAP new_methods=1 old_methods=0 cases=10 dependencies_model=true device=false phone=false\n'),
)



def sha(raw): return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    raw = path.read_bytes()
    if type(pin) is not tuple or (len(raw), sha(raw)) != pin:
        raise ValueError('input_identity_changed')
    return raw


def inputs():
    if Path(sys.executable).resolve() != PYTHON.resolve():
        raise ValueError('fixed_python_required')
    raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(raw)
    if (set(plan) != {'schema', 'sources'} or
            plan['schema'] != 'go-send-parent-entry-v88-host-source' or
            type(plan['sources']) is not list or not 10 <= len(plan['sources']) <= 70):
        raise ValueError('invalid_source_plan')
    source = {PLAN: raw, CHECKER: Path(__file__).read_bytes(), CMD: (BASE / CMD).read_bytes()}
    target_count = 0
    for row in plan['sources']:
        if set(row) != {'path', 'bytes', 'sha256', 'python35_target'}:
            raise ValueError('invalid_source_row')
        path = row['path']
        if (type(path) is not str or path.startswith('/') or ':' in path or '\\' in path or
                '..' in path.split('/') or path in source or
                type(row['python35_target']) is not bool):
            raise ValueError('invalid_source_path')
        value = fixed(BASE / path, (row['bytes'], row['sha256']))
        if row['python35_target']:
            ast.parse(value.decode('utf-8'), feature_version=(3, 5))
            target_count += 1
        source[path] = value
    for scope, test, method, cases, marker in TESTS:
        if not cases or not marker or test not in source:
            raise ValueError('test_not_frozen')
        tree = ast.parse(source[test].decode('utf-8'))
        methods = [node.name + '.' + item.name for node in tree.body if isinstance(node, ast.ClassDef)
                   for item in node.body if isinstance(item, ast.FunctionDef) and item.name.startswith('test_')]
        if methods != [method]: raise ValueError('unexpected_test_method')
    if target_count != 4: raise ValueError('new_target_count_changed')
    return source, target_count


def main():
    if len(sys.argv) != 1:
        print('HOST_ONLY no device arguments')
        return 2
    run = BASE / 'results' / ('go-send-parent-entry-v88-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    run.mkdir()
    private = run / 'private-inputs'
    source, rows, error, python_pin, ast_count = {}, [], None, None, 0
    try:
        source, ast_count = inputs()
        binary = PYTHON.read_bytes()
        python_pin = (len(binary), sha(binary))
        for path, raw in sorted(source.items()):
            target = private / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw: raise ValueError('snapshot_changed')
            rows.append({'path': path, 'bytes': len(raw), 'sha256': sha(raw)})
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError):
        error = 'source_snapshot_invalid'
    children, raw_members = [], {}
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        for scope, test, method, cases, marker in TESTS:
            started = time.monotonic()
            stdout, stderr, code, invoked, timeout, child_error = b'', b'', None, False, False, None
            try:
                child = subprocess.run([str(PYTHON), '-I', '-B', str(private / test), '-q'],
                    cwd=str(private), env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
            except subprocess.TimeoutExpired as failure:
                stdout, stderr = failure.stdout or b'', failure.stderr or b''
                invoked, timeout = True, True
            except OSError:
                child_error = 'child_not_started'
            elapsed = time.monotonic() - started
            (run / (scope + '-stdout.raw')).write_bytes(stdout)
            (run / (scope + '-stderr.raw')).write_bytes(stderr)
            marker_ok = stdout in (marker, marker.replace(b'\n', b'\r\n'))
            summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
            passed = bool(invoked and code == 0 and not timeout and child_error is None and marker_ok and summary_ok)
            children.append(dict(scope=scope, method=method, cases=cases, passed=passed,
                child_invocations=int(invoked), new_method_dispatch_attempts=int(invoked),
                new_methods_verified=int(passed), old_methods_invoked=0,
                child_exit=code, timeout=timeout, error=child_error, elapsed_seconds=elapsed,
                stdout_bytes=len(stdout), stdout_sha256=sha(stdout),
                stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
                marker_verified=marker_ok, unittest_summary_verified=summary_ok))
            if passed:
                raw_members[scope + '-stdout.raw'] = stdout
                raw_members[scope + '-stderr.raw'] = stderr
    preserved, tools_preserved = bool(source), False
    try:
        preserved = preserved and all((BASE / path).read_bytes() == raw for path, raw in source.items())
        binary = PYTHON.read_bytes()
        tools_preserved = python_pin is not None and (len(binary), sha(binary)) == python_pin
    except OSError:
        preserved, tools_preserved = False, False
    passed = bool(error is None and len(children) == 3 and all(c['passed'] for c in children)
                  and preserved and tools_preserved)
    value = dict(schema='go-send-parent-entry-v88-host', passed=passed, verification_error=error,
        inputs=rows, source_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=ast_count,
        children=children, old_methods_invoked=0, python_version=sys.version.split()[0],
        python_pin=python_pin, python_preserved=tools_preserved,
        packet_pure_definition_domain=True, parent_child_tail_model=True,
        entry_fs_fd_clock_model=True, owner_loader_state_constructor_model=True,
        real_baseline_collection_executed=False, helper_process_executed=False,
        bootstrap_restore_executed=False, parent_observer_channel_executed=False, actual_state_server_constructor_executed=False,
        source_staging_executed=False, production_seal_issued=False, admission_issued=False,
        device_accessed=False, phone_tested=False, rf_requested=False,
        physical_restore_verified=False, send_available=False, receive_available=False)
    raw_result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Three new affected HOST methods planned; each child at most once. '
        b'Actual dispatch and verified counts are separate in result children. '
        b'Old method tests and old target AST checks zero. Only four new runtime '
        b'sources have Python3.5 AST source checks; executing HOST is Python3.12. '
        b'Parent original child/EOF/reap DATA uses explicit models. Entry clock, '
        b'filesystem, descriptors and service constructors use explicit models. '
        b'Packet pure algorithms and snapshot decoding have their separately stated '
        b'domains. No real collect/helper, F restore/emission, actual Parent launch, '
        b'actual State/Server constructor, deployment/staging/seal/admission, '
        b'ADB/device/RF/reboot/phone or physical restoration. Passing child raw '
        b'requires its exact safe marker and Ran1/OK; failed raw is private.\n')
    (run / 'result.json').write_bytes(raw_result)
    (run / 'README.txt').write_bytes(readme)
    members = {'result.json': raw_result, 'README.txt': readme}
    if preserved and tools_preserved: members.update(raw_members)
    archive = run / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as output:
        for name, raw in members.items(): output.writestr(name, raw)
    with zipfile.ZipFile(archive) as output:
        if output.namelist() != list(members) or output.testzip() is not None or any(
                output.read(name) != raw for name, raw in members.items()):
            raise ValueError('public_zip_changed')
    print(json.dumps(dict(passed=passed, scopes=[{'scope': c['scope'], 'passed': c['passed'],
        'child_exit': c['child_exit']} for c in children], result_zip=str(archive),
        zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__': sys.exit(main())

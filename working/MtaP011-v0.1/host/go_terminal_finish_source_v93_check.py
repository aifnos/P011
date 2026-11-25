"""HOST93 full terminal identity DATA and strict consumer.
One new method/two affected domains/eighteen explicit model fixtures.
Only new F/Bridge targets receive Python3.5 AST; no old test/AST replay.
Actual selected issuer and pure wire algorithms, restore/FD/reap models.
No private GO runtime, deployment, device, radio or restoration grant.
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
PLAN = 'host/go_terminal_finish_source_v93_source_manifest.json'
TEST = 'tests/test_go_terminal_finish_source_v93.py'
CHECKER = 'host/go_terminal_finish_source_v93_check.py'
CMD = 'HOST_MTA_GO_TERMINAL_FINISH_SOURCE_V93_CHECK.cmd'
# ROOT seals only the new affected source graph; old methods stay uninvoked.
PLAN_PIN = (2990, '2ddc562a469abf2785bcb64714c773b2ce4bf2859118d78a4e16c8ebd5a1fbff')
METHOD = 'GoTerminalFinishSource93Test.test_full_actor_outcomes_and_strict_consumer'
MARKER = (b'HOST93_TERMINAL_FINISH_SOURCE new_methods=1 old_methods=0 domains=2 '
          b'issuer_model=true pure_codec=true device=false phone=false\n')
PYTHON_PIN = (6915048, 'ecf651f545bcef039d29503acf695a38903b7e8e9867a1ce0994ff6924e0274b')
HOST_PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
HOST_PYTHON_PIN = (103192, '42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0')
WSL_PREFIX = ['wsl.exe', '-d', 'kali-linux', '--user', 'root', '--exec',
              '/usr/bin/python3', '-I', '-B']
PROFILE_CODE = ("import hashlib,json,os,pathlib,platform,sys; "
    "p=pathlib.Path(sys.executable).resolve(); b=p.read_bytes(); "
    "print(json.dumps({'uid':os.getuid(),'python':platform.python_version(),"
    "'linux':platform.release(),'python_path':str(p),'python_bytes':len(b),"
    "'python_sha256':hashlib.sha256(b).hexdigest()},sort_keys=True))")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    raw = path.read_bytes()
    if type(pin) is not tuple or (len(raw), sha(raw)) != pin:
        raise ValueError('input_identity_changed')
    return raw


def linux_path(path):
    path = path.resolve()
    if not re.fullmatch('[A-Za-z]:', path.drive):
        raise ValueError('windows_drive_required')
    return '/mnt/' + path.drive[0].lower() + '/' + '/'.join(path.parts[1:])


def profile():
    child = subprocess.run(WSL_PREFIX + ['-c', PROFILE_CODE], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if child.returncode != 0 or child.stderr or len(child.stdout) > 1024:
        raise ValueError('wsl_tool_identity_unavailable')
    value = json.loads(child.stdout)
    if (set(value) != {'uid', 'python', 'linux', 'python_path', 'python_bytes', 'python_sha256'} or
        value['uid'] != 0 or value['python'] != '3.13.12' or
        value['linux'] != '6.6.87.2-microsoft-standard-WSL2' or
        (value['python_bytes'], value['python_sha256']) != PYTHON_PIN or
        value['python_path'] != '/usr/bin/python3.13'):
        raise ValueError('wsl_tool_identity_changed')
    return value


def inputs():
    if Path(sys.executable).resolve() != HOST_PYTHON.resolve():
        raise ValueError('fixed_host_python_required')
    fixed(HOST_PYTHON, HOST_PYTHON_PIN)
    plan_raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(plan_raw)
    if (set(plan) != {'schema', 'sources', 'runtime_source_count'} or
        plan['schema'] != 'go-terminal-finish-source-v93-host-source' or
        type(plan['sources']) is not list or len(plan['sources']) != 13 or
        type(plan['runtime_source_count']) is not int):
        raise ValueError('source_manifest_invalid')
    values = {PLAN: plan_raw, CHECKER: Path(__file__).read_bytes(), CMD: (BASE / CMD).read_bytes()}
    target_count = 0
    for row in plan['sources']:
        if set(row) != {'path', 'bytes', 'sha256', 'python35_target'}:
            raise ValueError('source_manifest_row_invalid')
        path = row['path']
        if (type(path) is not str or path.startswith('/') or '..' in path.split('/') or
            ':' in path or '\\' in path or path in values or
            type(row['python35_target']) is not bool):
            raise ValueError('source_manifest_inventory_invalid')
        raw = fixed(BASE / path, (row['bytes'], row['sha256']))
        if row['python35_target']:
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            target_count += 1
        values[path] = raw
    if target_count != 2 or target_count != plan['runtime_source_count'] or TEST not in values:
        raise ValueError('source_manifest_count_invalid')
    tree = ast.parse(values[TEST].decode('utf-8'))
    methods = [node.name + '.' + method.name for node in tree.body
               if isinstance(node, ast.ClassDef) for method in node.body
               if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('unexpected_test_method')
    return values, target_count


def main():
    if len(sys.argv) != 1:
        print('HOST_ONLY no device arguments')
        return 2
    output = BASE / 'results' / ('go-terminal-finish-source-v93-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    private = output / 'private-inputs'
    source, rows, error, target_count = {}, [], None, 0
    tools_before = tools_after = None
    try:
        source, target_count = inputs()
        for path, raw in sorted(source.items()):
            destination = private / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            if destination.read_bytes() != raw:
                raise ValueError('snapshot_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
        tools_before = profile()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError, subprocess.SubprocessError):
        error = 'source_snapshot_or_tool_invalid'
    started = time.monotonic()
    stdout, stderr, exit_code, invoked, timeout = b'', b'', None, False, False
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run(WSL_PREFIX + [linux_path(private / TEST), '-q'],
                cwd=str(private), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            stdout, stderr, exit_code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, invoked, timeout = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    preserved = bool(source)
    host_tool_preserved = False
    try:
        host_tool_preserved = bool(fixed(HOST_PYTHON, HOST_PYTHON_PIN))
    except (OSError, ValueError):
        pass
    for path, raw in source.items():
        try:
            preserved = (BASE / path).read_bytes() == raw and preserved
        except OSError:
            preserved = False
    if tools_before is not None:
        try:
            tools_after = profile()
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    tool_preserved = tools_before is not None and tools_after == tools_before
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = bool(error is None and invoked and not timeout and exit_code == 0 and
                  preserved and tool_preserved and host_tool_preserved and marker_ok and summary_ok)
    value = dict(schema='go-terminal-finish-source-v93-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=target_count, new_method=METHOD, domains=2, fixtures=18, fixed_runtime_inputs=12,
        child_invocations=int(invoked), new_method_dispatch_attempts=int(invoked),
        new_methods_verified=int(passed), old_methods_invoked=0, child_exit=exit_code,
        child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        wsl_tool_identity=tools_before, wsl_tool_preserved=tool_preserved,
        host_python_pin=HOST_PYTHON_PIN, host_python_preserved=host_tool_preserved,
        selected_finish_data_issuer_algorithm_executed=passed,
        strict_finish_wire_decoder_executed=passed,
        original_restore_fd_child_reap_models=True, actual_kernel_pipes_executed=False,
        actual_native_baseline_executed=False, state_constructed=False, server_constructed=False,
        owner_start_executed=False, fixed_ordinary_source_graph_sealed=False,
        full_private_go_graph_loaded=False, actual_observer_source_graph_loaded=False,
        actual_observer_collection_executed=False,
        actual_parent_process_executed=False, actual_python_arm_image_executed=False,
        actual_helper_executed=False, target_staging_executed=False,
        production_bundle_seal_issued=False, admission_issued=False,
        device_accessed=False, phone_tested=False, rf_requested=False,
        interface_or_address_configuration=False, physical_restore_verified=False,
        candidate_deployed=False, send_available=False, receive_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One new HOST93 method: two affected domains, eighteen explicit fixtures. '
        b'Actual selected finish issuer and pure strict wire algorithms execute; '
        b'restore/FD/child-ticket/identity/IO/reap are explicit models. Full Actor '
        b'and original child outcomes remain DATA, not independent observations. '
        b'Only new F/Bridge targets receive AST; no old test or target AST replay. '
        b'No full private GO runtime, process/kernel pipes/helper, deployment, '
        b'State/service, RF/device/phone, independent restore or admission. '
        b'Failed raw stays private; strict marker and Ran1/OK gate public raw.\n')
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
    print(json.dumps(dict(passed=passed, child_exit=exit_code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())

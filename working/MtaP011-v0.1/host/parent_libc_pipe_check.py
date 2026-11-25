"""One new HOST Linux libc pipe method, no Parent collection or device access.

Only the two changed Parent syntax targets and one new method are checked.
ROOT alone executes this checker and its unique child.
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
import traceback
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_parent_libc_pipe.py'
CHECKER = 'host/parent_libc_pipe_check.py'
CMD = 'HOST_MTA_PARENT_LIBC_PIPE_CHECK.cmd'
PARENTS = (
    ('candidate/go-parent-libc-v1/runtime/mta_go_readonly_parent.py', 52873,
     '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
    ('candidate/go-parent-libc-v1/runtime/mta_go_readonly_terminal_parent.py', 66973,
     '42ef91c27805d080f80706097834c6a73e4d5fe7b7683533a60fb33e59025a7a'),
)
TEST_PIN = (13428, 'ca9230c44efbea37f69a81b43322d8fe60a5e253952792302e7a7bff7cc2f6da')
METHOD = 'ParentLibcPipeTest.test_ctypes_flags_and_real_pipe_lifecycle'
MARKER = (b'HOST_PARENT_LIBC_PIPE new_methods=1 old_methods=0 domains=5 fixtures=10 '
          b'kernel_pipes=true platform_model=true errno_fault_model=true device=false phone=false\n')
HOST_PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
HOST_PYTHON_PIN = (103192, '42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0')
WARNING = b"wsl: Failed to start the systemd user session for 'admin'. See journalctl for more details.\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def linux_path(path):
    value = str(path.resolve())
    if len(value) < 3 or value[0].lower() != 'd' or value[1:3] != ':\\':
        raise ValueError('fixed_workspace_required')
    return '/mnt/d/' + value[3:].replace('\\', '/')


def main():
    if len(sys.argv) != 1:
        return 2
    if Path(sys.executable).resolve() != HOST_PYTHON.resolve() or \
            (len(HOST_PYTHON.read_bytes()), sha(HOST_PYTHON.read_bytes())) != HOST_PYTHON_PIN:
        raise ValueError('fixed_HOST_python_required')
    out = BASE / 'results' / ('parent-libc-pipe-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex)
    out.mkdir()  # No mutation of an existing output namespace.
    private = out / 'private-inputs'
    originals, error, targets = {}, None, 0
    try:
        if len(PARENTS) != 2 or TEST_PIN is None:
            raise ValueError('final_SOURCE_pins_required')
        names = (TEST,) + tuple(row[0] for row in PARENTS) + (CHECKER, CMD)
        if len(set(names)) != 5:
            raise ValueError('fixed_input_count')
        for name in names:
            if ':' in name or '\\' in name or name.startswith('/') or '..' in name.split('/'):
                raise ValueError('unsafe_fixed_input')
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            target = private / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as handle:
                handle.write(raw)
            if target.read_bytes() != raw:
                raise ValueError('snapshot_readback')
        for name, count, digest in ((TEST, TEST_PIN[0], TEST_PIN[1]),) + PARENTS:
            if (len(originals[name]), sha(originals[name])) != (count, digest):
                raise ValueError('fixed_SOURCE_pin_changed')
        for name, _, _ in PARENTS:
            ast.parse(originals[name].decode('utf-8'), filename=name, feature_version=(3, 5))
            targets += 1  # Each changed Parent exactly once; no old syntax/test replay.
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError):
        error = 'fixed_source_or_new_syntax_invalid'
        (out / 'setup-failure.private.txt').write_text(traceback.format_exc(), encoding='utf-8')
    started = time.monotonic()
    stdout, stderr, code, invoked, timed_out = b'', b'', None, False, False
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        try:
            invoked = True
            child = subprocess.run(['wsl.exe', '-d', 'kali-linux', '--user', 'root', '--exec',
                '/usr/bin/python3', '-I', '-B', linux_path(private / TEST), METHOD],
                cwd=str(private), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            stdout, stderr, code = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, timed_out = failure.stdout or b'', failure.stderr or b'', True
        except OSError:
            error = 'child_not_started'
            invoked = False
    elapsed = time.monotonic() - started
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    preserved = bool(len(originals) == 5)
    for name, raw in originals.items():
        try:
            preserved = (BASE / name).read_bytes() == raw and (private / name).read_bytes() == raw and preserved
        except OSError:
            preserved = False
    try:
        host_raw = HOST_PYTHON.read_bytes()
        host_tool_preserved = (len(host_raw), sha(host_raw)) == HOST_PYTHON_PIN
    except OSError:
        host_tool_preserved = False
    derived = stderr.replace(b'\r\n', b'\n')
    warning_present = derived.startswith(WARNING)
    if warning_present:
        derived = derived[len(WARNING):]  # One exact known WSL warning only; raw remains unchanged.
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(br'\.\n-{70}\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived) is not None
    component_passed = bool(error is None and invoked and code == 0 and not timed_out and
        preserved and host_tool_preserved and targets == 2 and marker_ok and summary_ok)
    environment_verified = bool(component_passed and not warning_present)
    passed = bool(component_passed and environment_verified)
    report = dict(schema='parent-libc-pipe-host-v1', passed=passed, verification_error=error,
        observed_host_component_passed=component_passed, overall_environment_verified=environment_verified,
        child_invocations=int(invoked), child_exit=code, timeout=timed_out, elapsed_seconds=elapsed,
        new_method=METHOD, new_methods_verified=int(component_passed), old_methods_invoked=0,
        completed_domains=5 if component_passed else None, completed_fixtures=10 if component_passed else None,
        snapshot_count=len(originals), sources_preserved=preserved, target_python35_ast_sources=targets,
        wsl_user_session_warning=warning_present, fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        actual_HOST_linux_kernel_pipe_tested=component_passed, actual_libc_fcntl_tested=component_passed,
        host_linux_machine='x86_64' if component_passed else None,
        host_python_version='3.13.12' if component_passed else None,
        platform_ARM_Python_root_fields_model=True, errno_failure_model=True,
        fcntl_Python_module_imported=False, parent_constructed=False, parent_collect_executed=False,
        popen_executed=False, packet_or_entry_executed=False, clock_or_parent_deadline_tested=False,
        actual_ARM_tested=False, device_accessed=False, phone_tested=False, native_or_rf_tested=False,
        source_graph_sealed=False, receive_available=False, send_available=False,
        admission_issued=False, restoration_verified=False, private_raw_included=False,
        host_python_pin=list(HOST_PYTHON_PIN), host_python_preserved=host_tool_preserved,
        inputs=[dict(path=name, bytes=len(raw), sha256=sha(raw)) for name, raw in originals.items()],
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr))
    result = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new method: five domains for each of two changed Parent IO classes (ten fixtures). '
        b'Actual HOST Linux libc fcntl and kernel pipes: GETFL/SETFL NONBLOCK/readback, EAGAIN, byte IO, '
        b'EOF and physical close/typed EBADF; Terminal stdin write uses real pipe. '
        b'ARM/Python/root validation fields and errno failures are explicit models. No Python fcntl import, '
        b'Parent ctor/collect/Popen, Packet/Entry, parent deadline, old test, RF/device/phone/admission/restore. '
        b'Only two changed Parent Python3.5 AST; raw and snapshots stay private. '
        b'An exact known WSL warning may permit a separately recorded child component observation, '
        b'but overall environment/passed stays false whenever the warning is present.\n')
    members = {'result.json': result, 'README.txt': note}
    for name, raw in members.items():
        with (out / name).open('xb') as handle:
            handle.write(raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive, 'r') as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(name) != raw for name, raw in members.items()):
            raise ValueError('result_zip_readback')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timed_out,
        result_dir=str(out), result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    raise SystemExit(main())

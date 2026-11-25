"""Windows host entry for one new WSL Linux-kernel transport test.

No ADB, radio, interface/address configuration or old test replay. Sources and
tool identities are frozen before the sole test child. Failure raw stays local;
public success raw must match the exact nonsecret marker and unittest summary.
This does not test the old GO/IP/DHCP producers, the parent State/F bridge, P011,
Xiaomi, native interoperability or physical restoration.
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
PLAN = 'host/go_send_transport_v76_r5_source_manifest.json'
TEST = 'tests/test_go_send_transport_v76_r5.py'
CHECKER = 'host/go_send_transport_v76_r5_check.py'
CMD = 'HOST_MTA_GO_SEND_TRANSPORT_V76_R5_CHECK.cmd'
# ROOT seals this after all authors freeze their changed SOURCE.
PLAN_PIN = (6055, '518a7366dcf8b5e7745187f184c2e3f89e01d7f7f2d5b8d34cb0d67c4ee8d350')
METHOD = 'GoSendTransport76Test.test_native_linux_owner_and_tls'
MARKER = (b'HOST76_GO_SEND_TRANSPORT new_methods=1 old_methods=0 '
          b'linux_kernel=true loopback_tls=true ancestors_model=true '
          b'device=false phone=false\n')
OPENSSL_PIN = (1115656, 'fbb31216b8284302d94559609c3a6f226d506aa52835b748b9803615718aa2dd')
WSL_PREFIX = ['wsl.exe', '-d', 'kali-linux', '--user', 'root', '--exec',
              '/usr/bin/python3', '-I', '-B']
PROFILE_CODE = ("import hashlib,json,os,pathlib,platform,sys; "
    "b=pathlib.Path('/usr/bin/openssl').read_bytes(); "
    "print(json.dumps({'uid':os.getuid(),'python':platform.python_version(),"
    "'linux':platform.release(),'openssl_bytes':len(b),"
    "'openssl_sha256':hashlib.sha256(b).hexdigest()},sort_keys=True))")


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
    if (set(value) != {'uid', 'python', 'linux', 'openssl_bytes', 'openssl_sha256'} or
        value['uid'] != 0 or value['python'] != '3.13.12' or
        value['linux'] != '6.6.87.2-microsoft-standard-WSL2' or
        (value['openssl_bytes'], value['openssl_sha256']) != OPENSSL_PIN):
        raise ValueError('wsl_tool_identity_changed')
    return value


def inputs():
    plan_raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(plan_raw)
    if (set(plan) != {'schema', 'sources', 'runtime_source_count'} or
        plan['schema'] != 'go-send-transport-v76-r5-host-source' or
        type(plan['sources']) is not list or not 20 <= len(plan['sources']) <= 35 or
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
    if target_count != plan['runtime_source_count'] or TEST not in values:
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
    output = BASE / 'results' / ('go-send-transport-v76-r5-host-' +
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
                  preserved and tool_preserved and marker_ok and summary_ok)
    value = dict(schema='go-send-transport-v76-r5-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=target_count, new_method=METHOD,
        child_invocations=int(invoked), old_methods_invoked=0, child_exit=exit_code,
        child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        wsl_tool_identity=tools_before, wsl_tool_preserved=tool_preserved,
        actual_linux_socket_transport_tested=passed, actual_loopback_tls_tested=passed,
        actual_native_go_producer_tested=False, actual_ip_installation_tested=False,
        actual_dhcp_ack_transmission_tested=False, station_control_ancestor_model=True,
        parent_state_bridge_executed=False, f_send_ipc_executed=False,
        device_accessed=False, phone_tested=False, rf_requested=False,
        interface_or_address_configuration=False, physical_restore_verified=False,
        candidate_deployed=False, send_available=False, receive_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One new actual Linux lo TCP/listen/accept/TLS/detach/close transport scenario '
        b'under WSL kali-linux. Actual file preparation and protocol-pump dependencies; '
        b'only the phone-protocol fixture has a thread. Old GO/journal/IP/DHCP issuance/ACK '
        b'and WPA station control are explicit modeled ancestors, not tested producers. '
        b'No interface/address configuration, radio, ADB, P011, Xiaomi, parent State/F IPC '
        b'or physical restoration. No old test method replay. Private material and failure '
        b'raw are excluded; success raw requires an exact safe marker and Ran1/OK.\n')
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

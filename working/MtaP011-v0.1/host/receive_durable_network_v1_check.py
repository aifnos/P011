"""Default SOURCE; --run is one current-source HOST Linux real-TLS fault method.

No device, native admission, phone, graph generation, staging or radio action.
Raw outputs/keys stay private; only validated fixed facts enter the public ZIP.
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_durable_network_v1_check.py'
TEST = 'tests/test_receive_durable_network_v1.py'
SELECTOR = 'ReceiveDurableNetworkV1Tests.test_actual_tls_durable_late_cancel_and_missing_ack'
CMDS = ('HOST_MTA_RECEIVE_DURABLE_NETWORK_V1_SOURCE_ONLY.cmd',
        'HOST_MTA_RECEIVE_DURABLE_NETWORK_V1_CHECK.cmd')
TEST_PIN = (27020, '27d3dfb98857cf080a887fca8564e6b3e2dfb125c1752597fca7e5a7628f7124')
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/formal_receive_scope_dispatch_v1_private_source_manifest.json', 8168,
     '52f0360b3fb0138b8fa6fd5589bb2d9f29e68d47e601e6d63ff5ebf60e3942ca'),
    ('candidate/formal-receive-durable-state-v1/runtime/mta_transport.py', 41435,
     '9b05ef49059e9b06536de32186e7de1cfd531461d3e096eb266d49f760069f8e'),
    ('candidate/formal-receive-durable-state-v1/runtime/mta_storage.py', 56595,
     '365490e2dfe8a2c65d2b38fc8ae1a49747d09ed3b127677e9fe61e69866052d0'),
    ('runtime/mta_sender_pump.py', 33455,
     '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c'),
    ('runtime/mta_send_preparation.py', 28532,
     '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('candidate/file-utf8-v67/runtime/mta_files.py', 10987,
     'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('tests/test_sender_pump.py', 34154,
     '7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7'),
    ('tests/test_receive_bound_integration.py', 13877,
     'd0790f870bf62848ccfcb6f8c4937dbd6961aae63c5d849179f84af2187798ee'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def literals(raw):
    tree = ast.parse(raw.decode('utf-8'))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return values, tree


def validate(value, contract):
    fixed = contract['FIXED_RESULT']
    need(type(value) is dict and set(value) == set(fixed) | {'phase_elapsed_seconds'}, 'result_fields')

    def exact(actual, expected):
        if type(actual) is not type(expected):
            return False
        if type(expected) is tuple:
            return len(actual) == len(expected) and all(exact(left, right) for left, right in zip(actual, expected))
        return actual == expected

    need(all(exact(value[key], expected) for key, expected in fixed.items()), 'fixed_result_facts')
    elapsed = value['phase_elapsed_seconds']
    need(type(elapsed) is tuple and len(elapsed) == 2 and
         all(type(seconds) is float and math.isfinite(seconds) and 0.0 <= seconds <= 35.0
             for seconds in elapsed), 'phase_durations')


def run(execute):
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), sha(raw)) == PINS[0][1:], 'sealer_pin')
    sealer = types.ModuleType('_fixed_durable_network_sealer')
    sealer.__file__ = str(BASE / PINS[0][0])
    exec(compile(raw, sealer.__file__, 'exec'), sealer.__dict__)
    mode = 'host' if execute else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('receive-durable-network-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}
    evidence = sealer.InputEvidence(inputs)
    report = dict(schema='receive-durable-network-v1-parent', mode=mode,
        passed=False, checker_exit=1, error=None, child_invocations=0,
        child_exit=None, timed_out=False, source_preserved=False,
        snapshot_preserved=False, actual_selected_lowlevel_match=False,
        actual_linux=False, actual_tls=False, actual_p011=False, phone=False,
        native_admission=False, native_owner=False, rf=False, staging=False,
        graph_changed=False, full_restore_verified=False, observation=None)
    failure = None
    snapshotted = False
    try:
        need(type(TEST_PIN) is tuple and len(TEST_PIN) == 2, 'test_pin_not_frozen')
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        evidence.read(BASE / TEST, key=TEST, pin=TEST_PIN)
        for key in (SELF,) + CMDS:
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        snapshotted = True
        current = json.loads(inputs[PINS[1][0]])
        need(current['schema'] == 'client-receive-directory-v1-private-source', 'current_manifest_schema')
        for module, reference in (('mta_transport', PINS[2]), ('mta_storage', PINS[3])):
            rows = [row for row in current['sources'] if row['module'] == module]
            need(len(rows) == 1 and rows[0]['path'] == reference[0] and
                 rows[0]['bytes'] == reference[1] and rows[0]['sha256'] == reference[2], 'actual_graph_lowlevel_pin')
        report['actual_selected_lowlevel_match'] = True
        for key, _, _ in PINS[2:9]:
            ast.parse(inputs[key].decode('utf-8'), feature_version=(3, 5))
        contract, tree = literals(inputs[TEST])
        need(contract.get('SELECTOR') == SELECTOR and
             contract.get('RESULT_SCHEMA') == 'p011-receive-durable-network-v1' and
             type(contract.get('FIXED_RESULT')) is dict and
             contract['FIXED_RESULT'].get('schema') == contract['RESULT_SCHEMA'] and
             'phase_elapsed_seconds' not in contract['FIXED_RESULT'], 'fixed_result_contract')
        expected_sources = {row[0]: row[1:] for row in PINS[2:]}
        source_pins = contract.get('SOURCE_PINS')
        need(type(source_pins) is tuple and len(source_pins) == 9 and
             all(type(row) is tuple and len(row) == 3 for row in source_pins) and
             {row[0]: row[1:] for row in source_pins} == expected_sources, 'test_original_sources')
        methods = [cls.name + '.' + node.name for cls in tree.body if isinstance(cls, ast.ClassDef)
                   for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
        need(methods == [SELECTOR], 'only_affected_method')
        need(str(BASE) == r'D:\project\P011\working\MtaP011-v0.1', 'fixed_workspace')
        script = str(out / 'private-inputs' / TEST)
        need(script.startswith(str(BASE / 'results') + '\\') and script[:3].lower() == 'd:\\', 'snapshot_entry_path')
        linux_script = '/mnt/d/' + script[3:].replace('\\', '/')
        bootstrap = ('import runpy,signal,sys;signal.alarm(80);'
                     'sys.argv=[sys.argv[1],sys.argv[2]];'
                     'runpy.run_path(sys.argv[0],run_name="__main__")')
        argv = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
                '-I', '-B', '-c', bootstrap, linux_script, SELECTOR]
        sealer.fresh(out / 'private-raw/argv.json', (json.dumps(argv) + '\n').encode('ascii'))
        report.update(input_count=len(inputs), target_python35_ast_sources=7,
            requested_methods=1, old_methods_run=0, child_alarm_seconds=80,
            child_host_timeout_seconds=90, alarm_before_entry=True,
            inputs=[dict(path=key, bytes=len(value), sha256=sha(value))
                    for key, value in inputs.items()])
        if execute:
            report['child_invocations'] = 1
            try:
                child = subprocess.run(argv, cwd=str(out / 'private-inputs'),
                    capture_output=True, timeout=90)
                code, stdout, stderr = child.returncode, child.stdout, child.stderr
            except subprocess.TimeoutExpired as error:
                code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
                report['timed_out'] = True
            sealer.fresh(out / 'private-raw/stdout.raw', stdout)
            sealer.fresh(out / 'private-raw/stderr.raw', stderr)
            sealer.fresh(out / 'private-raw/child-exit.txt', (str(code) + '\n').encode('ascii'))
            report['child_exit'] = code
            report['streams'] = [dict(name=name, bytes=len(value), sha256=sha(value))
                                for name, value in (('stdout.raw', stdout), ('stderr.raw', stderr))]
            need(code == 0 and not report['timed_out'], 'child_exit')
            lines = stdout.decode('ascii').splitlines()
            need(len(lines) == 1 and lines[0].startswith('RESULT='), 'result_marker')
            observation = ast.literal_eval(lines[0][7:])
            validate(observation, contract)
            diagnostic = stderr.replace(b'\r\n', b'\n')
            warning = b"wsl: Failed to start the systemd user session for 'admin'. See journalctl for more details.\n"
            report['wsl_user_session_warning'] = diagnostic.startswith(warning)
            if report['wsl_user_session_warning']:
                diagnostic = diagnostic[len(warning):]
            need(re.fullmatch(br'-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', diagnostic) is not None,
                 'single_method_runner_result')
            report.update(observation=observation, actual_linux=True, actual_tls=True)
    except BaseException as error:
        failure = error
        sealer.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected, 'source_changed')
                if snapshotted:
                    need((out / 'private-inputs' / key).read_bytes() == expected, 'snapshot_changed')
            report['source_preserved'] = True
            report['snapshot_preserved'] = snapshotted
        except BaseException as error:
            sealer.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None:
                failure = error
        try:
            if not snapshotted or evidence.partial or evidence.changed_attempts:
                evidence.snapshot(out / 'private-final-evidence' if snapshotted else out, lambda key: key)
        except BaseException as error:
            sealer.fresh(out / 'private-raw/snapshot-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None:
                failure = error
        if failure is None:
            report.update(passed=True, checker_exit=0)
        else:
            report['error'] = type(failure).__name__
    readme = ("One new HOST Linux method with two separate real loopback TLS/HTTP/durable-storage fault phases.\n"
        "Late cancellation preserves committed bytes and the original failure, never transfer success.\n"
        "Real control-peer close before terminal ACK preserves local bytes without sender/peer completion.\n"
        "Actual selected low-level source pins match; constructor loopback admission and socket owner are HOST fixtures.\n"
        "Current-source network/storage evidence only: no P011, phone, native interface/admission, full Bridge or restore claim.\n"
        "SOURCE default starts no child. Explicit --run starts one finite WSL child, no old methods or full suites.\n"
        "Raw streams, complete inputs, exception traces, ephemeral certificates and private keys stay private.\n").encode('ascii')
    sealed = sealer.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        error=sealed['report']['error'], child_exit=sealed['report']['child_exit'],
        result_dir=str(out), result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='explicit current-source real-TLS HOST fault check')
    return run(parser.parse_args().run)


if __name__ == '__main__':
    sys.exit(main())

"""SOURCE by default; --run executes one real HOST Linux HTTP deadline test.

No ADB, device, radio, native Owner, old tests, graph generation or staging.
Versioned candidate sources only. Original raw streams and inputs stay private.
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
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/filecenter_http_parent_cap_v1_check.py'
TEST = 'tests/test_filecenter_http_parent_cap_v1.py'
TEST_PIN = (21691, 'a0529db68247d85d06d0289397f350d09c1d7a1bf66e9f39ca45fb96b291912c')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
CMDS = ('HOST_MTA_FILECENTER_HTTP_PARENT_CAP_V1_SOURCE_ONLY.cmd',
        'HOST_MTA_FILECENTER_HTTP_PARENT_CAP_V1_CHECK.cmd')
COMPANIONS = (
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_companion.py',
     'candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py',
     'candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py'))
HTTP = ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py',
        'candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py')


def need(value, code):
    if value is not True: raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def literals(raw):
    tree = ast.parse(raw.decode('utf-8'))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError): pass
    return values, tree


def validate(value, contract):
    fixed = contract['FIXED_RESULT']
    need(type(value) is dict and set(value) == set(fixed) | {'durations'}, 'result_fields')
    def exact(actual, expected):
        if type(actual) is not type(expected): return False
        if type(expected) is tuple:
            return len(actual) == len(expected) and all(exact(a, b) for a, b in zip(actual, expected))
        if type(expected) is dict:
            return set(actual) == set(expected) and all(exact(actual[key], expected[key]) for key in expected)
        return actual == expected
    need(all(exact(value[key], expected) for key, expected in fixed.items()), 'result_fixed_facts')
    durations = value['durations']
    count = fixed.get('total_phases')
    need(type(count) is int and 1 <= count <= 32 and type(durations) is tuple and len(durations) == count and
         all(type(item) is float and math.isfinite(item) and 0.0 <= item <= 40.0 for item in durations),
         'result_durations')


def narrow_delta(inputs):
    setup = (b'    def setup(self):\n'
             b'        self.deadline = min(self.deadline, self.server.companion.until)\n'
             b'        Handler.setup(self)\n\n')
    for old, new in COMPANIONS:
        need(inputs[new].count(setup) == 1 and inputs[new].replace(setup, b'') == inputs[old],
             'companion_setup_only')
    before = b'header_deadline = time.monotonic()+4'
    after = b'header_deadline = min(self.deadline, time.monotonic()+4)'
    need(inputs[HTTP[1]].count(after) == 1 and inputs[HTTP[1]].replace(after, before) == inputs[HTTP[0]],
         'http_header_cap_only')


def run(execute):
    raw = (BASE / SEALER[0]).read_bytes()
    need((len(raw), sha(raw)) == SEALER[1:], 'sealer_pin')
    seal = types.ModuleType('_filecenter_http_parent_cap_sealer')
    seal.__file__ = str(BASE / SEALER[0])
    exec(compile(raw, seal.__file__, 'exec'), seal.__dict__)
    mode = 'host' if execute else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('filecenter-http-parent-cap-v1-' + mode + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {SEALER[0]: raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='filecenter-http-parent-cap-v1-parent', mode=mode,
        passed=False, error=None, child_invocations=0, child_exit=None, timed_out=False,
        source_preserved=False, snapshot_preserved=False, input_count=1, observation=None,
        actual_p011=False, phone=False, rf=False, ui=False, native_owner=False,
        full_filecenter_parent_deadline_verified=False, graph_changed=False, staging=False,
        original_sources_modified=False, full_restore_verified=False, narrow_source_delta_verified=False)
    snapshotted = False
    try:
        need(type(TEST_PIN) is tuple and len(TEST_PIN) == 2, 'test_pin_not_frozen')
        evidence.read(BASE / TEST, key=TEST, pin=TEST_PIN)
        contract, tree = literals(inputs[TEST])
        selector, prefix = contract.get('SELECTOR'), contract.get('RESULT_PREFIX')
        need(type(selector) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*\.test_[A-Za-z0-9_]+', selector) is not None,
             'test_selector')
        need(prefix == b'FILECENTER_HTTP_PARENT_CAP_V1=' and type(contract.get('FIXED_RESULT')) is dict and
             contract['FIXED_RESULT'].get('passed') is True and 'durations' not in contract['FIXED_RESULT'],
             'result_contract')
        methods = [cls.name + '.' + node.name for cls in tree.body if isinstance(cls, ast.ClassDef)
                   for node in cls.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')]
        need(methods == [selector], 'only_affected_method')
        pins = contract.get('SOURCE_PINS')
        need(type(pins) is tuple and 3 <= len(pins) <= 32, 'source_pins')
        seen = set()
        for row in pins:
            need(type(row) is tuple and len(row) == 3, 'source_pin_row')
            key, size, digest = row
            need(type(key) is str and not Path(key).is_absolute() and '..' not in Path(key).parts and
                 key.endswith('.py') and key not in seen and key not in inputs and
                 type(size) is int and 0 < size <= 262144 and type(digest) is str and
                 re.fullmatch(r'[0-9a-f]{64}', digest) is not None, 'source_pin_fields')
            seen.add(key)
            evidence.read(BASE / key, key=key, pin=(size, digest))
            ast.parse(inputs[key].decode('utf-8'), feature_version=(3, 5))
        narrow_delta(inputs)
        report['narrow_source_delta_verified'] = True
        for key in (SELF,) + CMDS: evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        snapshotted = True
        need(str(BASE) == r'D:\project\P011\working\MtaP011-v0.1', 'fixed_workspace')
        script = str(out / 'private-inputs' / TEST)
        need(script.startswith(str(BASE / 'results') + '\\') and script[:3].lower() == 'd:\\', 'snapshot_entry_path')
        linux_script = '/mnt/d/' + script[3:].replace('\\', '/')
        bootstrap = ('import runpy,signal,sys;signal.alarm(50);'
                     'sys.argv=[sys.argv[1],sys.argv[2]];'
                     'runpy.run_path(sys.argv[0],run_name="__main__")')
        argv = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
                '-I', '-B', '-c', bootstrap, linux_script, selector]
        seal.fresh(out / 'private-raw/argv.json', (json.dumps(argv) + '\n').encode('ascii'))
        report.update(input_count=len(inputs), requested_methods=1, old_methods_run=0,
            child_alarm_seconds=50, child_host_timeout_seconds=60, alarm_before_entry=True)
        if execute:
            report['child_invocations'] = 1
            try:
                child = subprocess.run(argv, cwd=str(out / 'private-inputs'), capture_output=True, timeout=60)
                code, stdout, stderr = child.returncode, child.stdout, child.stderr
            except subprocess.TimeoutExpired as error:
                report['timed_out'] = True
                code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
            for name, data in (('stdout', stdout), ('stderr', stderr)):
                seal.fresh(out / ('private-raw/child.' + name + '.raw'), data)
            seal.fresh(out / 'private-raw/child.host-exit', (str(code) + '\n').encode('ascii'))
            report['child_exit'] = code
            need(report['timed_out'] is False and type(code) is int and code == 0, 'child_failed')
            lines = stdout.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n').splitlines()
            matches = [line for line in lines if line.startswith(prefix)]
            need(len(matches) == 1 and len(lines) == 1 and len(matches[0]) <= 16384, 'result_marker')
            result = ast.literal_eval(matches[0][len(prefix):].decode('ascii'))
            validate(result, contract)
            derived = stderr.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
            need(re.search(br'\nRan 1 test in [0-9.]+s\n\nOK\n?$', derived) is not None, 'one_method_completed')
            report['observation'] = result
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)[:180]
        seal.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            if not snapshotted: evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['source_preserved'] = all((BASE / key).read_bytes() == raw for key, raw in inputs.items())
            report['snapshot_preserved'] = all((out / 'private-inputs' / key).read_bytes() == raw for key, raw in inputs.items())
            need(report['source_preserved'] and report['snapshot_preserved'], 'inputs_changed')
        except BaseException as error:
            report['passed'] = False
            report['error'] = report['error'] or type(error).__name__ + ':' + str(error)[:180]
            seal.fresh(out / 'private-raw/preservation-exception.txt', traceback.format_exc().encode('utf-8'))
    readme = (b'Default SOURCE only; --run executes one affected HOST Linux real HTTP/socket method.\n'
              b'Two versioned FileCenter handlers and shared HTTP header cap only; originals retained.\n'
              b'Private Companion root/guard are explicit binding fixtures, not native Owner authority.\n'
              b'No device, RF, phone, UI, deployment or complete FileCenter/Owner deadline claim.\n'
              b'Raw dual streams, exit codes and input snapshots remain private.\n')
    result = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=result['report']['passed'], output=str(out),
        archive=str(result['archive']) if result['archive'] else None,
        archive_sha256=result['archive_sha256'], error=result['report']['error']), ensure_ascii=True))
    return result['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    raise SystemExit(run(parser.parse_args().run))

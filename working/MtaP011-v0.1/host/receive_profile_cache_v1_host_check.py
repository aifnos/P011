"""Only the three new profile DATA HOST tests, with raw logs and result ZIP.

No device, old suite, graph writer, clock benchmark, RF or phone action.
The whole-profile fixture is explicitly synthetic IO/Owner, not admission.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_profile_cache_v1_host_check.py'
CMD = 'HOST_MTA_RECEIVE_PROFILE_CACHE_V1_CHECK.cmd'
TEST = ('tests/test_receive_profile_cache_v1_host.py', 22361,
        '4b9f6571bf09cf582b5a9bb2abdfa456bb9cb64f90a42c8e016cd8449b7b534a')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
TEST_METHODS = ('test_whole_profile_cache_contract',
                'test_actual_v2_and_profile_injection_full_inverse',
                'test_actual_passive_reader_and_strict_parser_data_contract')
README = (b'Only three new HOST tests for private cached profile DATA.\n'
          b'Whole real methods use explicit synthetic IO/platform/Owner fixtures.\n'
          b'Nine flow scenarios compare original calls, output and error with the new seed.\n'
          b'Actual passive reader/parser and whole-target V2/profile byte injection are checked.\n'
          b'No real FD close, additional-PID guard, device timing, admission, RF or phone is certified.\n'
          b'No old suite, graph writer, device, radio, UI or credential operation runs.\n'
          b'Raw stdout/stderr, timeout/exit and exact input snapshots remain private.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    target = BASE
    need(type(path) is str and all(part not in ('', '.', '..') for part in path.split('/')) and
         ':' not in path and '\\' not in path, 'fixed_relative_input')
    for part in path.split('/'):
        target = target / part
        value = target.lstat()
        need(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
             'fixed_input_link')
    need(stat.S_ISREG(value.st_mode), 'fixed_regular_input')
    return target.read_bytes()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'artifact_short_write')
    need(path.read_bytes() == raw, 'artifact_readback')


def main():
    need(sys.argv[1:] == [], 'only_new_host_tests')
    out = BASE / 'results' / ('receive-profile-cache-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    inputs, sealer = {}, None
    report = dict(schema='p011-receive-profile-cache-v1-host', passed=False, error=None,
        child_exit='NOT_RUN', checker_exit=1, raw_timeout=False, source_preserved=False,
        new_test_methods=3, whole_profile_fixture_scenarios=9, whole_profile_method_calls=18,
        whole_profile_io_owner_fixtures=True, actual_device_identity_verified=False,
        actual_profile_performance_verified=False, real_fd_close_verified=False,
        old_tests_replayed=0, device_invoked=False, rf_requested=False, phone_requested=False,
        graph_writer_invoked=False, original_deadlines_unchanged=True)
    try:
        def fixed(row):
            raw = read(row[0]); inputs[row[0]] = raw
            need((len(raw), digest(raw)) == row[1:], 'fixed_input_pin')
            return raw
        own, command = read(SELF), read(CMD)
        inputs[SELF], inputs[CMD] = own, command
        sealed_raw = fixed(SEALER)
        sealer = types.ModuleType('fixed_profile_host_sealer')
        exec(compile(sealed_raw, str(BASE / SEALER[0]), 'exec'), sealer.__dict__)
        test_raw = fixed(TEST)
        tree = ast.parse(test_raw.decode('ascii'))
        bindings = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 and
                    isinstance(node.targets[0], ast.Name) and node.targets[0].id in
                    ('MOTHER', 'CANDIDATE', 'DELTA', 'SEED', 'V2_PROJECTION',
                     'PROFILE_PROJECTION', 'RETAINED_TARGET')}
        need(len(bindings) == 7, 'seven_frozen_test_inputs')
        for row in bindings.values():
            fixed(row)
        methods = tuple(node.name for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'))
        need(methods == TEST_METHODS, 'exactly_three_new_test_methods')
        try:
            result = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST[0]), '-v'],
                                    cwd=str(BASE), capture_output=True, timeout=60, check=False)
            stdout, stderr = result.stdout, result.stderr
            report['child_exit'] = result.returncode
        except subprocess.TimeoutExpired as failure:
            stdout, stderr = failure.stdout or b'', failure.stderr or b''
            report['child_exit'], report['raw_timeout'] = 'TIMEOUT', True
        for label, raw in (('stdout', stdout), ('stderr', stderr)):
            fresh(out / 'private-raw' / (label + '.raw'), raw)
            report[label + '_bytes'], report[label + '_sha256'] = len(raw), digest(raw)
        fresh(out / 'private-raw/child-exit', (str(report['child_exit']) + '\n').encode('ascii'))
        derived_stderr = stderr.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
        need(report['child_exit'] == 0 and b'Ran 3 tests in ' in derived_stderr and
             derived_stderr.endswith(b'\nOK\n'), 'three_new_host_tests_failed')
    except BaseException as failure:
        report['error'] = type(failure).__name__
        fresh(out / 'private-raw/host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        for path, raw in inputs.items():
            fresh(out / 'private-inputs' / path, raw)
        report['source_preserved'] = bool(inputs) and all(read(path) == raw and
            (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items())
    report['passed'] = report['error'] is None and report['source_preserved'] and report['child_exit'] == 0
    report['checker_exit'] = 0 if report['passed'] else 1
    report['input_pins'] = [dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()]
    if sealer is None:
        fresh(out / 'private-unsealed-failure.json', (json.dumps(report, sort_keys=True) + '\n').encode('ascii'))
        return 1
    sealed = sealer.seal_result(out, report, README)
    print(json.dumps(dict(passed=sealed['report']['passed'], result_dir=str(out),
        public_result_zip=str(sealed['archive']), zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())

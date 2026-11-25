"""PC-only SOURCE or one actual-QML method with an explicit delayed HTTP model.

No old suite, XHR, server/socket, native role, Owner, device, ADB, build or RF.
The current sender bundle is only read as the frozen source binding; never edited.
"""
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_status_presentation_v1_host_check.py'
TEST = ('tests/test_formal_send_status_presentation_v1.py', 17254,
        'e6d41be565d89d4dd3a0445f6b1593659b42f65cf52765c8dfba327fdfda875a')
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
COMMANDS = (
    ('HOST_MTA_FORMAL_SEND_STATUS_PRESENTATION_V1_SOURCE_CHECK.cmd', 182,
     'b4fcf6787238f0c55ea297c97b392816681e4dff74b96e9e6de18699e6f23216'),
    ('TEST_MTA_FORMAL_SEND_STATUS_PRESENTATION_V1.cmd', 193,
     '8a0e37e09e935e8adf0605f142040f8a24f041a64c324ceffcb5982ff01da279'))
SELECTOR = 'StatusPresentationTests.test_actual_status_action_fence_delayed_callbacks'
EXPECTED = b'HOST_STATUS_PRESENTATION_V1_PASS methods=1 scenarios=9 http_model=true xhr=false old_suite=0'
TIMEOUT = 60
RAW_LIMIT = 1048576
README = b"""This result covers only source derivation and, if explicitly requested, one
actual offscreen HOST Qt/QML method with delayed in-memory request callbacks.
Original GET/POST overwrite counterexamples and the independent candidate are
selected components, not an old-suite replay. The request()/XHR implementation
is unchanged and not executed. HTTP completion and timeout replies are models;
not real HTTP, XHR timeout, socket, Owner, backend/admission, P011, device, phone,
RF, rendering/physical touch, transfer/ACK or network restoration acceptance.
Old source/out assets/results remain unchanged. Private immutable snapshots and
raw stdout/stderr are retained; public ZIP has only result.json and README.txt.
"""


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_seal(inputs):
    raw = (BASE / SEAL[0]).read_bytes()
    inputs[SEAL[0]] = raw
    need((len(raw), digest(raw)) == SEAL[1:], 'seal_pin')
    tree = ast.parse(raw.decode('ascii'))
    need(not any(isinstance(row, ast.If) for row in tree.body), 'seal_no_main')
    module = types.ModuleType('private_status_presentation_artifact_seal')
    exec(compile(tree, '<fixed-host-seal>', 'exec'), module.__dict__)
    return module


def source_namespace(raw, filename):
    tree = ast.parse(raw.decode('utf-8'))
    assignments = ('SOURCE', 'CANDIDATE', 'DELTA', 'HELPER', 'BINDING',
                   'DEPENDENCIES', 'INPUT_ROWS', 'SELECTOR')
    # The narrow SOURCE route cannot import Qt, the fixture or a test class.
    body = [row for row in tree.body if isinstance(row, ast.Import) and
            all(name.name in ('hashlib', 'json') for name in row.names)]
    body += [row for row in tree.body if isinstance(row, ast.Assign) and
             len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
             row.targets[0].id in assignments]
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and
                 row.name == 'source_contract']
    need(len(functions) == 1 and len(body) == len(assignments) + 2, 'source_definition_shape')
    body += functions
    classes = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'StatusPresentationTests']
    need(len(classes) == 1 and [row.name for row in classes[0].body if isinstance(row, ast.FunctionDef) and
         row.name.startswith('test_')] == [SELECTOR.split('.')[1]], 'single_new_method')
    namespace = {'__file__': str(filename), '__name__': 'private_status_presentation_source'}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 '<pure-status-presentation-source>', 'exec'), namespace)
    need(namespace['SELECTOR'] == SELECTOR, 'selector_binding')
    return namespace


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ['--run-host']):
        raise SystemExit('default SOURCE or fixed --run-host only')
    run_host = args == ['--run-host']
    label = 'host' if run_host else 'source'
    out = BASE / 'results' / ('formal-send-status-presentation-v1-' + label + '-' +
        datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs, seal, evidence = {}, None, None
    contract, error, child_code, requested, invoked, preserved = None, None, None, False, False, False
    stdout, stderr = b'', b''
    try:
        need(sys.platform == 'win32' and BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_host')
        seal = load_seal(inputs)
        evidence = seal.InputEvidence(inputs)
        evidence.read(BASE / SELF, SELF)
        test_raw = evidence.read(BASE / TEST[0], TEST[0], TEST[1:])
        for key, size, pin in COMMANDS:
            raw = evidence.read(BASE / key, key, (size, pin))
            expected_flag = '--run-host' if key.startswith('TEST_') else ''
            need('%*' not in raw.decode('ascii') and SELF.replace('/', '\\') in raw.decode('ascii') and
                 raw.count(b'--run-host') == (1 if expected_flag else 0), 'fixed_command')
        namespace = source_namespace(test_raw, out / 'private-inputs' / TEST[0])
        for key, size, pin in namespace['INPUT_ROWS']:
            evidence.read(BASE / key, key, (size, pin))
        evidence.snapshot(out, lambda key: key)
        contract = namespace['source_contract'](inputs)
        if run_host:
            requested = True
            command = [sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST[0]), SELECTOR]
            try:
                child = subprocess.run(command, cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
                invoked = True
                stdout, stderr, child_code = child.stdout, child.stderr, child.returncode
            except subprocess.TimeoutExpired as failure:
                invoked = True
                stdout, stderr = failure.stdout or b'', failure.stderr or b''
                raise
            finally:
                seal.fresh(out / 'private-raw/child.stdout.raw', stdout)
                seal.fresh(out / 'private-raw/child.stderr.raw', stderr)
            need(len(stdout) <= RAW_LIMIT and len(stderr) <= RAW_LIMIT, 'child_raw_budget')
            need(child_code == 0 and stdout.splitlines() == [EXPECTED] and
                 re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
                 re.search(rb'^OK\r?$', stderr, re.M) is not None, 'single_method_result')
        preserved = all((BASE / key).read_bytes() == raw for key, raw in inputs.items())
        need(preserved, 'inputs_changed')
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        if seal is not None:
            seal.fresh(out / 'private-raw/check.exception.raw', traceback.format_exc().encode('utf-8'))
    finally:
        if evidence is not None:
            try:
                evidence.snapshot(out, lambda key: key)
            except BaseException as failure:
                error = error or type(failure).__name__ + ':' + str(failure)
        if inputs:
            try:
                preserved = all((BASE / key).read_bytes() == raw for key, raw in inputs.items())
            except BaseException:
                preserved = False
    passed = error is None and contract is not None and preserved and (
        not run_host or invoked and child_code == 0 and stdout.splitlines() == [EXPECTED])
    report = dict(schema='p011-formal-send-status-presentation-v1-host', mode=label,
        passed=passed, host_exit=0 if passed else 1, error=error,
        source_contract_verified=contract is not None, source_contract=contract,
        inputs_preserved=preserved, input_count=len(inputs),
        source_inputs=[dict(path=key, bytes=len(raw), sha256=digest(raw)) for key, raw in inputs.items()],
        child_requested=requested, child_invoked=invoked, child_exit=child_code, remote_exit='NOT_RUN_HOST_ONLY',
        methods_verified=1 if passed and run_host else None,
        scenarios_verified=9 if passed and run_host else None,
        actual_qml_delayed_http_model_configured=True, unchanged_xhr_executed=False,
        old_suite_methods_requested=0, backend_admission_changed=False,
        deployed=False, device_invoked=False, build_invoked=False, rf_invoked=False,
        phone_invoked=False, physical_rendering_verified=False,
        real_mobile_transfer_verified=False, full_network_restore_verified=False)
    if seal is None:
        (out / 'unsealed.failure.raw').write_bytes((error or 'seal_unavailable').encode('utf-8'))
        print(json.dumps(dict(report, result_directory=str(out), archive=None), sort_keys=True))
        return 1
    sealed = seal.seal_result(out, report, README)
    print(json.dumps(dict(sealed['report'], result_directory=str(out),
        archive=str(sealed['archive']) if sealed['archive'] is not None else None,
        archive_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())

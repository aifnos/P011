"""PC-only SOURCE contract or one explicit, modeled affected HOST method.

No ADB, device, build, network/RF, historical main or historical suite dispatch.
The test compiles selected actual Owner definitions with explicit syscall,
DirectoryBinding and Parent models. PASS is not actual Linux/P011 close proof.
"""
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/send_failed_preflight_directory_cleanup_v1_host_check.py'
TEST = ('tests/test_send_failed_preflight_directory_cleanup_v1.py', 25657,
        'c99a3c6c55826e3112005f2f148e154695f590fa5c058c0c14af6dc26f95c5ee')
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
COMMANDS = (
    ('HOST_MTA_SEND_FAILED_PREFLIGHT_CLEANUP_V1_SOURCE_CHECK.cmd', 234,
     '1a21bceed7dceb1a6e227bfdb067339d55e6a260c6294e4e6514d3fd05efc2a8'),
    ('TEST_MTA_SEND_FAILED_PREFLIGHT_CLEANUP_V1.cmd', 234,
     '0382ece05c537a17754a15cb84b2d0366a5256d114aeacc89fcc9c07ea111835'))
SELECTOR = 'FailedPreflightCleanup.test_actual_owner_failed_preflight_directory_release'
EXPECTED = b'HOST_FAILED_PREFLIGHT_DIRECTORY_CLEANUP_V1_PASS methods=1 cases=40 models=true physical_os=false old_suite=0'
TIMEOUT = 60
RAW_LIMIT = 1048576
READ_ME = b"""This result covers only SOURCE and, when explicitly requested, one modeled HOST method.
No old suite/main, Linux physical close, P011, child Parent, device, ADB, RF or
startup/restoration evidence is produced. Parent cache/closed/wait/reap and
DirectoryBinding are explicit models; actual selected Owner methods are used.
The actual prepare finally seals before the modeled outer catch sets Owner.failure.
Business failure and unknown remain; total Owner closure remains refused.
Private input snapshots and child stdout/stderr are retained. Public ZIP contains
only result.json and README.txt. No passed historical result is rewritten.
"""


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_seal(inputs):
    # Retain exact read bytes before pin rejection. The frozen module has no main.
    raw = (BASE/SEAL[0]).read_bytes()
    inputs[SEAL[0]] = raw
    need((len(raw), digest(raw)) == SEAL[1:], 'seal_pin')
    tree = ast.parse(raw.decode('ascii'))
    need(not any(isinstance(v, ast.If) for v in tree.body), 'seal_no_main')
    module = types.ModuleType('private_host_artifact_seal_v1')
    exec(compile(tree, '<fixed-host-artifact-seal>', 'exec'), module.__dict__)
    return module


def contract_namespace(raw, filename):
    tree = ast.parse(raw.decode('ascii'))
    allowed_assignments = ('MOTHER', 'CANDIDATE', 'DELTA', 'INPUT_ROWS', 'CHANGED', 'ADDED', 'SELECTOR')
    allowed_functions = ('need', 'method_map', 'source_contract')
    body = [v for v in tree.body if isinstance(v, (ast.Import, ast.ImportFrom))]
    # Importing stdlib is permitted; no test fixture or historical imports.
    need(all((isinstance(v, ast.Import) and all(n.name in
        ('ast','errno','hashlib','json','math','sys','threading','types','unittest') for n in v.names)) or
        (isinstance(v, ast.ImportFrom) and v.module == 'pathlib') for v in body), 'contract_imports')
    body += [v for v in tree.body if isinstance(v, ast.Assign) and
             len(v.targets) == 1 and isinstance(v.targets[0], ast.Name) and
             v.targets[0].id in allowed_assignments]
    body += [v for v in tree.body if isinstance(v, ast.FunctionDef) and v.name in allowed_functions]
    need(len([v for v in body if isinstance(v, ast.FunctionDef)]) == 3, 'contract_functions')
    namespace = {'__file__': str(filename), '__name__': 'private_source_contract'}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 '<pure-source-contract>', 'exec'), namespace)
    need(namespace['SELECTOR'] == SELECTOR, 'selector_binding')
    return namespace


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args not in ([], ['--run-host']):
        raise SystemExit('default SOURCE or fixed --run-host only')
    run_host = args == ['--run-host']
    label = 'host' if run_host else 'source'
    out = BASE/'results'/('send-failed-preflight-cleanup-v1-'+label+'-'+
        datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs, seal, evidence = {}, None, None
    error, contract, child_code, child_invoked, preserved = None, None, None, False, False
    stdout, stderr = b'', b''
    try:
        seal = load_seal(inputs)
        evidence = seal.InputEvidence(inputs)
        evidence.read(BASE/SELF, SELF)
        test_raw = evidence.read(BASE/TEST[0], TEST[0], TEST[1:])
        for key, size, pin in COMMANDS:
            raw = evidence.read(BASE/key, key, (size, pin))
            command = raw.decode('ascii')
            expected_flag = '--run-host' if key.startswith('TEST_') else ''
            need('%*' not in command and SELF.replace('/', '\\') in command and
                 command.count('--run-host') == (1 if expected_flag else 0), 'fixed_command')
        # Parsing only; this does not execute any model or unittest method.
        contract_ns = contract_namespace(test_raw, out/'private-inputs'/TEST[0])
        for key, size, pin in contract_ns['INPUT_ROWS']:
            evidence.read(BASE/key, key, (size, pin))
        evidence.snapshot(out, lambda key: key)
        contract = contract_ns['source_contract'](inputs)
        if run_host:
            child_invoked = True
            command = [sys.executable, '-I', '-B', str(out/'private-inputs'/TEST[0]), SELECTOR]
            try:
                completed = subprocess.run(command, cwd=str(out/'private-inputs'),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
                stdout, stderr, child_code = completed.stdout, completed.stderr, completed.returncode
            except subprocess.TimeoutExpired as failure:
                stdout, stderr = failure.stdout or b'', failure.stderr or b''
                raise
            finally:
                seal.fresh(out/'private-raw/child.stdout.raw', stdout)
                seal.fresh(out/'private-raw/child.stderr.raw', stderr)
            need(len(stdout) <= RAW_LIMIT and len(stderr) <= RAW_LIMIT, 'child_raw_budget')
            need(child_code == 0 and stdout.splitlines() == [EXPECTED], 'single_method_result')
        preserved = all((BASE/key).read_bytes() == raw for key, raw in inputs.items())
        need(preserved, 'inputs_changed')
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        raw = traceback.format_exc().encode('utf-8')
        if seal is not None:
            seal.fresh(out/'private-raw/check.exception.raw', raw)
    finally:
        if evidence is not None:
            try:
                evidence.snapshot(out, lambda key: key)
            except BaseException as failure:
                error = error or type(failure).__name__ + ':' + str(failure)
        # Count only source bytes actually read and retained.
        if inputs:
            try:
                preserved = all((BASE/key).read_bytes() == raw for key, raw in inputs.items())
            except BaseException:
                preserved = False
    passed = error is None and contract is not None and preserved and (
        not run_host or child_invoked and child_code == 0 and stdout.splitlines() == [EXPECTED])
    report = dict(schema='p011-send-failed-preflight-directory-cleanup-v1-host',
        mode=label, passed=passed, host_exit=0 if passed else 1, error=error,
        source_contract_verified=contract is not None, source_contract=contract,
        inputs_preserved=preserved, input_count=len(inputs),
        source_inputs=[dict(path=key, bytes=len(raw), sha256=digest(raw)) for key, raw in inputs.items()],
        child_invoked=child_invoked, child_exit=child_code,
        methods_verified=1 if passed and run_host else None,
        cases_verified=40 if passed and run_host else None,
        explicit_syscall_parent_directory_models_configured=True,
        actual_selected_owner_definitions_configured=True,
        old_suite_methods_requested=0, physical_linux_close_verified=False,
        device_invoked=False, native_or_rf_verified=False,
        business_failure_unknown_retained_verified=True if passed and run_host else None)
    if seal is None:
        # Untrusted/missing sealer: retain failure locally, never publish a PASS ZIP.
        (out/'unsealed.failure.raw').write_bytes((error or 'seal_unavailable').encode('utf-8'))
        print(json.dumps(dict(report, result_directory=str(out), archive=None), sort_keys=True))
        return 1
    result = seal.seal_result(out, report, READ_ME)
    print(json.dumps(dict(result['report'], result_directory=str(out),
        archive=str(result['archive']) if result['archive'] is not None else None,
        archive_sha256=result['archive_sha256']), sort_keys=True))
    return result['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())

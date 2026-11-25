"""PC-only one-method Proc contract with private-before-public result sealing.

Default is SOURCE-only: fixed source/metadata validation, no child or method.
Only explicit --run-host selects the one affected actual-reader FakeFs method.
No historical test method, device, RF, phone, Owner or restoration is executed.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import traceback
import types


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_proc_freezer_v2_host_check.py'
TEST = ('tests/test_receive_proc_freezer_v1.py', 26161,
        'b73c525822dc35cd98005cd0f4886faddde48f8e704f81e8f5a05c4e5a39c35f')
ONECLICK = ('HOST_MTA_RECEIVE_PROC_FREEZER_V2_CONTRACT_CHECK.cmd', 262,
            '0e8d5800c38ea77cda1e83ccd0948e0021b561c1aa2640977c4b4b72c7635093')
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
SELECTOR = 'ReceiveProcFreezerV1Contract.test_actual_reader_single_dynamic_bit_all_identity_paths_and_closed_inventory'
MARKER = b'RECEIVE_PROC_FREEZER_V1_HOST_PASS methods=1 old_methods=0 actual_proc=true actual_budget=true fakefs=true'
SCOPE = b'HOST_SCOPE cases=63 flag_bits_retained=31 physical_os=false rf=false phone=false restoration=false'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(row):
    relative, size, expected = row
    path = Path(relative)
    need(not path.is_absolute() and '..' not in path.parts, 'relative_input')
    raw = (BASE / path).read_bytes()
    need((len(raw), sha(raw)) == (size, expected), 'fixed_source_pin:' + relative)
    return raw


def metadata_definitions(raw):
    """Select pinned pure source metadata helpers; no method/domain execution."""
    need((len(raw), sha(raw)) == TEST[1:], 'test_definitions_pin')
    tree = ast.parse(raw.decode('ascii'))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and
               node.name == 'ReceiveProcFreezerV1Contract']
    method = SELECTOR.split('.')[1]
    need(len(classes) == 1 and
         [node.name for node in classes[0].body if isinstance(node, ast.FunctionDef)] == [method],
         'exact_one_affected_method')
    need(len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and
              node.name.startswith('test_')]) == 1, 'no_other_test_method')
    constants = {'BASE', 'GENERATOR', 'MANIFEST', 'V25_FIXTURE', 'FS_FIXTURE',
                 'ORIGINAL', 'GENERATED', 'MASK', 'SELECTOR', 'MARKER'}
    functions = {'digest', 'fixed', 'generator_definitions', 'input_rows'}
    imports = {'ast', 'hashlib', 'json', 'pathlib', 'types'}
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Import) and all(alias.name in imports for alias in node.names):
            nodes.append(node)
        elif isinstance(node, ast.ImportFrom) and node.module in imports:
            nodes.append(node)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1 and
              isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants):
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in functions:
            nodes.append(node)
    need({node.targets[0].id for node in nodes if isinstance(node, ast.Assign)} == constants and
         {node.name for node in nodes if isinstance(node, ast.FunctionDef)} == functions,
         'pure_metadata_definitions_complete')
    namespace = types.ModuleType('freezer_pure_metadata_definitions')
    namespace.__file__ = str(BASE / TEST[0])
    exec(compile(ast.Module(body=nodes, type_ignores=[]), namespace.__file__, 'exec'), namespace.__dict__)
    need(namespace.SELECTOR == SELECTOR and namespace.MARKER.encode('ascii') == MARKER and
         namespace.MASK == 1073741824, 'actual_affected_scope_binding')
    return namespace


def metadata_rows(namespace):
    rows = namespace.input_rows()
    need(type(rows) is tuple and len(rows) == 36 and len({row[0] for row in rows}) == 36,
         'exact_36_runtime_and_metadata_inputs')
    for row in rows:
        need(type(row) is tuple and len(row) == 3 and type(row[0]) is str and
             type(row[1]) is int and row[1] > 0 and type(row[2]) is str and len(row[2]) == 64,
             'fixed_input_row_shape')
        relative = Path(row[0])
        need(not relative.is_absolute() and '..' not in relative.parts, 'fixed_input_row_scope')
    return rows


def source_validation():
    namespace = metadata_definitions(fixed(TEST))
    rows = metadata_rows(namespace)
    retained = {row[0]: fixed(row) for row in rows}
    actual = namespace.generator_definitions().generated_inputs()
    need(all(retained[key] == raw for key, raw in actual.items()), 'actual_proc_generation_binding')
    fixed(SEAL)
    fixed(ONECLICK)
    return dict(mode='SOURCE_ONLY', fixed_input_rows=len(rows) + 3,
                exact_one_line_delta=True, original_line_numbers=True,
                candidate_artifacts_already_generated=True, no_future_pin=True,
                methods_run=0, old_methods_run=0, child_invoked=False,
                device_tested=False, rf_tested=False, phone_tested=False,
                restoration_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    if not args.run_host:
        print(json.dumps(source_validation(), sort_keys=True))
        return 0
    seal_raw = fixed(SEAL)
    seal = types.ModuleType('freezer_original_artifact_sealer')
    exec(compile(seal_raw, str(BASE / SEAL[0]), 'exec'), seal.__dict__)
    out = BASE / 'results' / ('receive-proc-freezer-v2-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    inputs = {}
    evidence = seal.InputEvidence(inputs)
    code, timed_out, invoked, unchanged = None, False, False, False
    source_contract_verified = False
    stdout, stderr, failure, detail = b'', b'', None, b''
    started = time.monotonic()
    try:
        evidence.read(BASE / SELF, key=SELF)
        evidence.read(BASE / SEAL[0], key=SEAL[0], pin=SEAL[1:])
        evidence.read(BASE / ONECLICK[0], key=ONECLICK[0], pin=ONECLICK[1:])
        test_raw = evidence.read(BASE / TEST[0], key=TEST[0], pin=TEST[1:])
        namespace = metadata_definitions(test_raw)
        rows = metadata_rows(namespace)
        for relative, size, expected in rows:
            evidence.read(BASE / relative, key=relative, pin=(size, expected))
        need(len(inputs) == 40, 'exact_40_captured_inputs')
        actual = namespace.generator_definitions().generated_inputs()
        need(all(inputs[key] == raw for key, raw in actual.items()), 'actual_proc_delta_captured')
        source_contract_verified = True
        evidence.snapshot(out, lambda key: key)
        snapshot = out / 'private-inputs'
        invoked = True
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(snapshot / TEST[0]), SELECTOR],
                cwd=str(snapshot), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout, stderr = error.stdout or b'', error.stderr or b''
        unchanged = all((BASE / relative).read_bytes() == raw and
                        (snapshot / relative).read_bytes() == raw for relative, raw in inputs.items())
    except BaseException as error:
        failure = type(error).__name__ + ':' + str(error)
        detail = traceback.format_exc().encode('utf-8')
    finally:
        evidence.snapshot(out, lambda key: key)
        seal.fresh(out / 'private-raw/stdout.raw', stdout)
        seal.fresh(out / 'private-raw/stderr.raw', stderr)
        if detail:
            seal.fresh(out / 'private-raw/host-exception.txt', detail)
    passed = (failure is None and code == 0 and not timed_out and unchanged and
              stdout.splitlines().count(MARKER) == 1 and stdout.splitlines().count(SCOPE) == 1)
    report = dict(schema='p011-receive-proc-freezer-v2-affected-host',
        passed=passed, host_exit=0 if passed else 1, child_exit=code, error=failure,
        child_invoked=invoked, timed_out=timed_out, host_elapsed_seconds=time.monotonic() - started,
        source_unchanged=unchanged, source_contract_verified=source_contract_verified,
        methods_requested=1, old_methods_run=0, selector=SELECTOR,
        child_reads_private_snapshot_configured=True, child_python_isolated_configured=True,
        actual_frozen_v25_and_new_module_definitions_configured=True, actual_proc_reader_configured=True,
        actual_durable_store_resource_budget_configured=True, original_fakefs_selected_ast_configured=True,
        original_fixture_methods_run=0, synthetic_clock_configured=True, actual_reader_cases_requested=63,
        actual_reader_cases_verified=63 if passed else None,
        retained_flag_bits_requested=31, retained_flag_bits_verified=31 if passed else None,
        mask=1073741824, original_raw_flags_preservation_checked=passed,
        original_boot_exe_command_tasks_directory_and_deadline_guards_checked=passed,
        resources_closed_and_ledger_checked=passed, current_generation_cleared_checked=passed,
        physical_os_operations_blocked_configured=True, full_owner_graph_executed=False,
        device_tested=False, rf_tested=False, phone_tested=False, gui_tested=False,
        restoration_verified=False, performance_measured=False, runtime75_modified=False,
        runner_modified=False, business_admission=False, stable_key_line=120,
        return_line=121, actor_pass_line=484, identity_failure_line=524,
        sources=[dict(path=relative, bytes=len(raw), sha256=sha(raw)) for relative, raw in inputs.items()],
        streams=[dict(name=name, bytes=len(raw), sha256=sha(raw)) for name, raw in
                 (('stdout.raw', stdout), ('stderr.raw', stderr))])
    sealed = seal.seal_result(out, report,
        b'One affected HOST method only: actual v25 and single-bit candidate ProcReader '
        b'plus actual DurableClientInitStore and ResourceBudget over selected original FakeFs.\n'
        b'63 actual-reader subcases plus parser/stable-key edges cover the transient freezer '
        b'bit, all other 31 flags, actor/task/aggregate/absence identities, retained directory '
        b'and classification gates, original deadline and closed resource inventory.\n'
        b'Clock/filesystem are explicit models. Original fixture methods and previous suites '
        b'are not executed. Physical OS operations are blocked in the method. No full Owner '
        b'graph, device, RF, phone, GUI, performance, admission or restoration acceptance.\n'
        b'Captured source and separate raw streams remain private. Public ZIP contains '
        b'the scalar result and this scope boundary only.\n')
    print(json.dumps(dict(passed=sealed['report']['passed'], child_exit=code,
        host_exit=sealed['host_exit'], result=str(out / 'result.json'),
        zip=None if sealed['archive'] is None else str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())

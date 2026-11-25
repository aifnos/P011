"""Fixed PC SOURCE receipt for the already generated independent deploy-v7 graph.

Recompute exactly this graph through its pinned pure definitions, then compare
all 12 actual output files. No write-generator/main, older verifier/test, Stage,
Parent/Owner/UI, native helper, subprocess, build, transport or device runs.
Raw source inputs and output readback stay private. Public ZIP has two files.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_preflight_native_graph_v1_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_PREFLIGHT_NATIVE_GRAPH_V1_SOURCE_CHECK.cmd'
GENERATOR = ('candidate/formal-send-preflight-native-graph-v1/generate_graph.py', 35171,
             '6379b0ca7543fd4c23c691848acb65e4ebae0d538bb6070f46471b8127814a87')
PURE = frozenset(('need', 'digest', 'pin', 'encoded', 'read_fixed', 'mechanical_helpers',
                  'definition_locations', 'source_record', 'json_record', 'json_pin',
                  'preserved', 'verified_owner', 'compose', 'finish_graph'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'private_short_write')
    need(path.read_bytes() == raw, 'private_readback')


def snapshot(inputs, out, path):
    relative = PurePosixPath(path)
    need(not relative.is_absolute() and '..' not in relative.parts and
         str(relative) == path, 'source_path')
    file = BASE / path
    raw = file.read_bytes()
    need(path not in inputs or inputs[path] == raw, 'source_changed')
    if path not in inputs:
        inputs[path] = raw
        write_new(out / 'private-inputs' / path, raw)
    return raw


def prepare(inputs, out):
    for path in (SELF, CMD, GENERATOR[0]):
        snapshot(inputs, out, path)
    raw = inputs[GENERATOR[0]]
    need((len(raw), digest(raw)) == GENERATOR[1:], 'generator_pin')
    tree = ast.parse(raw.decode('utf-8'))
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in PURE]
    need(len(functions) == len(PURE) and {row.name for row in functions} == PURE, 'pure_definition_roster')
    nodes = [row for row in tree.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
             row in functions]
    driver = dict(__file__=str(BASE / GENERATOR[0]), __name__='preflight_native_graph_source_private')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pinned-graph-PC-source-only>', 'exec'), driver)
    original = driver['read_fixed']
    def private_first(current_inputs, row):
        observed = snapshot(inputs, out, row[0])
        # Retain bytes before the fixed pin/identity gate; original guards still
        # execute and both reads must be exact. No business source is imported.
        current = original(current_inputs, row)
        need(current == observed, 'source_changed')
        return current
    driver['read_fixed'] = private_first
    need('main' not in driver and 'write_exclusive' not in driver, 'write_entry_excluded')
    return driver


def main():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('formal-send-preflight-native-graph-v1-source-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    (out / 'private-inputs').mkdir()
    (out / 'private-raw').mkdir()
    inputs = {}
    report = dict(kind='formal-send-preflight-native-graph-v1-source', passed=False,
        source_complete=False, source_preserved=False, input_count=0,
        generated_output_count=0, actual_outputs_matched=0, graph_business_edits=None,
        ordinary_roles=None, staged_files=None, staged_bytes=None,
        sender_files=27, sender_bytes=2402458, observer_files=41, observer_bytes=1548495,
        observer_changes=4, observer_reused=37, filecenter_files=9,
        write_generator_invoked=False, old_tests_run=0, stage_invoked=False,
        parent_invoked=False, owner_invoked=False, ui_invoked=False, build_invoked=False,
        device_invoked=False, rf_requested=False, production_admitted=False, error_code=None)
    try:
        driver = prepare(inputs, out)
        computed_inputs, outputs, generation = driver['compose']()
        need(len(outputs) == 12 and generation['graph_business_edits'] == 0 and
             generation['observer_bytes'] == 1548495 and generation['observer_changes'] == 4 and
             generation['observer_reused'] == 37 and generation['sender_bytes'] == 2402458 and
             generation['filecenter_bytes'] == 99972, 'graph_source_scope')
        need(all(path in inputs and inputs[path] == raw for path, raw in computed_inputs.items()),
             'input_capture_complete')
        report['generated_output_count'] = len(outputs)
        report['graph_business_edits'] = generation['graph_business_edits']
        report['ordinary_roles'] = generation['ordinary_roles']
        report['staged_files'], report['staged_bytes'] = generation['staged_files'], generation['staged_bytes']
        report['generation_input_count'] = generation['input_count']
        output_rows = []
        for path, expected in sorted(outputs.items()):
            actual = snapshot(inputs, out, path)
            need(actual == expected, 'actual_output_mismatch')
            report['actual_outputs_matched'] += 1
            output_rows.append(dict(path=path, bytes=len(actual), sha256=digest(actual)))
        write_new(out / 'private-raw' / 'computed-generation.private.json',
                  (json.dumps(generation, sort_keys=True, indent=2) + '\n').encode('ascii'))
        write_new(out / 'private-raw' / 'actual-output-pins.private.json',
                  (json.dumps(output_rows, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report['source_complete'] = True
    except BaseException as error:
        report['error_code'] = 'source_contract' if type(error) is ValueError else 'unexpected'
        detail = dict(type=type(error).__name__, reason=(error.args[0] if len(error.args) == 1 and
                      type(error.args[0]) is str and len(error.args[0]) <= 512 else None))
        write_new(out / 'private-raw' / 'error.private.json',
                  (json.dumps(detail, sort_keys=True, indent=2) + '\n').encode('ascii'))
    finally:
        inventory = {}
        preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                inventory[path] = dict(bytes=len(raw), sha256=digest(raw))
                preserved = ((out / 'private-inputs' / path).read_bytes() == raw and
                             (BASE / path).read_bytes() == raw and preserved)
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        write_new(out / 'private-inputs.json',
                  (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = report['source_complete'] and report['source_preserved'] and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Fixed PC SOURCE only: pure current graph composition and actual 12-output equality.\n'
        b'No --write generator, old main/suite/test, Stage, Parent/Owner/UI, build, ADB or RF.\n'
        b'Ordinary32/stage37, immutable sender27, fresh observer41/1548495/four changed/37 reused.\n'
        b'FileCenter9, shared lock, original Proc, helper binaries and UI bundle unchanged.\n'
        b'All input/readback bytes private; public ZIP only result.json and README.txt.\n'
        b'This source receipt is not device admission, whole Owner/UI closure or phone acceptance.\n')
    write_new(out / 'result.json', result)
    write_new(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == readme, 'zip_readback')
    code = 0 if report['passed'] else 1
    write_new(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out)), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())

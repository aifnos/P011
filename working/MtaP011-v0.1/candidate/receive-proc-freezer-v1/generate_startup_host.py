"""Fresh PC mechanical startup HOST binding over the frozen original envelope.

No historical main, suite, device or runtime executes here. Only actual generated
graph constants/pins and result/entry labels propagate. The complete byte inverse
and unchanged IO/closed-policy envelope are retained for a separate SOURCE run.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-proc-freezer-v1/'
SELF = PREFIX + 'generate_startup_host.py'
SOURCE = ('host/device_receive_durable_state_v1_startup_check.py', 18445,
          'b3bf58eb9b02170a69dc54f44207f0e27f8ef6c565431590a1f5d39de39668fd')
OLD_DEFS = ('host/formal_receive_durable_state_v1_definitions.py', 45031,
            'b98c66604bdb250820630f1844e5ea4b0af9bbd260e05388478034e37254e43b')
DEFS_PATH = 'host/formal_receive_proc_freezer_v1_definitions.py'
TARGET = 'host/device_receive_proc_freezer_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_FREEZER_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_FREEZER_V1_STARTUP.cmd')
DELTA = PREFIX + 'startup-host-exactsource-delta.json'
REPORT = PREFIX + 'startup-host-generation.json'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return [path, len(raw), digest(raw)]


def jraw(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')


def read(path, expected=None):
    target = BASE / path
    need(not target.is_symlink() and target.resolve().is_relative_to(BASE.resolve()), 'input_scope')
    raw = target.read_bytes()
    need(expected is None or (len(raw), digest(raw)) == tuple(expected), 'frozen_input_pin:' + path)
    return raw


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before = row['after' if inverse else 'before'].encode('utf-8')
        after = row['before' if inverse else 'after'].encode('utf-8')
        need(before and raw.count(before) == row['count'], 'exact_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


def build():
    old = read(SOURCE[0], SOURCE[1:])
    defs_raw = read(DEFS_PATH)
    defs = types.ModuleType('fixed_freezer_startup_graph_interface')
    defs.__file__ = str(BASE / DEFS_PATH)
    exec(compile(defs_raw, defs.__file__, 'exec'), defs.__dict__)
    need('main' not in defs.__dict__ and defs.STATE_ALIAS == '/tmp/p011-mta-rx-freezer-v1' and
         defs.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-freezer-v1' and
         0 < defs.PAYLOAD_BYTES <= 4194304, 'current_graph_interface')
    count = len(defs.ORIGIN_SOURCE_PINS)
    closures = defs.MECHANICAL_CLOSURE_COUNT
    need(type(closures) is int and 0 < closures <= 16 and type(count) is int and
         count >= 164 and len(defs.FILECENTER_SOURCE_PINS) == 9 and
         sum(row[2] for row in defs.FILECENTER_SOURCE_PINS) == 113690, 'current_graph_counts')
    actual_defs = tuple(pin(DEFS_PATH, defs_raw))
    edits = []
    def change(name, before, after, number=1):
        if before == after:
            need(old.count(before.encode('utf-8')) == number, 'unchanged_count:' + name)
            return
        edits.append(dict(name=name, before=before, after=after, count=number))
    change('self_entry', "SELF = '" + SOURCE[0] + "'", "SELF = '" + TARGET + "'")
    change('source_cmd', "'HOST_MTA_RECEIVE_DURABLE_STATE_V1_STARTUP_CHECK.cmd'", repr(CMDS[0]))
    change('device_cmd', "'TEST_MTA_RECEIVE_DURABLE_STATE_V1_STARTUP.cmd'", repr(CMDS[1]))
    change('actual_definitions_pin', 'DEFINITIONS = ' + repr(OLD_DEFS[:2])[:-1] + ',\n               ' + repr(OLD_DEFS[2]) + ')',
           'DEFINITIONS = ' + repr(actual_defs))
    change('isolated_root', "ROOT_NAME = 'p011-mta-rx-durable-v1'", "ROOT_NAME = 'p011-mta-rx-freezer-v1'")
    change('actual_payload_constant', 'PAYLOAD_BYTES = 4191752', 'PAYLOAD_BYTES = ' + str(defs.PAYLOAD_BYTES))
    change('isolated_results_and_diagnostic_label', "'receive-durable-state-v1-startup", "'receive-proc-freezer-v1-startup", 2)
    change('new_result_schema', 'p011-receive-durable-state-v1-startup', 'p011-receive-proc-freezer-v1-startup')
    change('exclusive_remote_command_label', 'p011-receive-durable-v1-startup; ', 'p011-receive-proc-freezer-v1-startup; ')
    change('actual_origin_gate', 'len(definitions.ORIGIN_SOURCE_PINS) == 164', 'len(definitions.ORIGIN_SOURCE_PINS) == ' + str(count))
    change('actual_delta_closure_gate', "definitions.verify_inputs(inputs) == 9, 'new_nine_mechanical_closures'",
           'definitions.verify_inputs(inputs) == ' + str(closures) + ", 'new_freezer_mechanical_closures'")
    change('actual_remaining_report', 'payload_remaining_bytes=2552', 'payload_remaining_bytes=' + str(4194304 - defs.PAYLOAD_BYTES))
    change('actual_origin_report', 'flat_origin_pins=164', 'flat_origin_pins=' + str(count))
    change('actual_closure_report', 'mechanical_closures=9,', 'mechanical_closures=' + str(closures) + ',')
    change('readme_origin', 'Flat164 provenance and new nine mechanical closures;',
           'Actual flat' + str(count) + ' provenance and new ' + str(closures) + ' mechanical closures;')
    change('readme_actual_payload', 'Actual75/4191752 retains original4MiB cap;',
           'Actual75/' + str(defs.PAYLOAD_BYTES) + ' retains original4MiB cap;')
    raw = replay(old, edits)
    need(replay(raw, edits, True) == old, 'complete_host_byte_inverse')
    ast.parse(raw, feature_version=(3, 5))
    tree, new_tree = ast.parse(old), ast.parse(raw)
    unchanged = ('need', 'digest', 'metadata', 'read_fixed', 'fresh', 'shape', 'pure_startup', 'io_inverse')
    functions = lambda value: {row.name: ast.dump(row, include_attributes=False) for row in value.body if isinstance(row, ast.FunctionDef)}
    first, last = functions(tree), functions(new_tree)
    need(set(first) == set(last) and all(first[name] == last[name] for name in unchanged), 'original_pure_definitions_exact')
    generator = pin(SELF, read(SELF))
    guards = dict(payload_roles=75, payload_bytes=defs.PAYLOAD_BYTES, payload_cap=4194304,
        filecenter_roles=9, filecenter_bytes=113690, filecenter_cap=131072,
        startup_seconds=10, activity_seconds=60, cleanup_seconds=60,
        remote_alarm_seconds=240, host_timeout_seconds=250, source_cap=2097152,
        target_line_cap=256, original_closed_policy=True, original_io_ast_unchanged=True,
        original_trial_none_refuses=True, old_main_called=False, old_verifier_called=False,
        old_tests_called=False, device_executed=False, gui_rebuilt=False, radio_action=False)
    outputs = {TARGET: raw}
    for name, device in zip(CMDS, (False, True)):
        command = ('@echo off\r\nsetlocal\r\ncd /d "%~dp0"\r\n'
                   'rem ' + ('Explicit new core75 startup-close; no RF/UI/phone.' if device else 'PC SOURCE only; no ADB/RF/UI/phone.') + '\r\n'
                   '"C:\\Users\\P011_USER\\AppData\\Local\\Programs\\Python\\Python312\\python.exe" -I -B '
                   '"' + TARGET.replace('/', '\\') + '"' + (' --check-device' if device else '') + ' %*\r\n'
                   'exit /b %errorlevel%\r\n')
        outputs[name] = command.encode('ascii')
    outputs[DELTA] = jraw(dict(schema='p011-receive-proc-freezer-v1-startup-host-delta',
        evidence='MECHANICAL_GENERATED_NOT_SOURCE_CHECKED', generator=generator,
        source=list(SOURCE), candidate=pin(TARGET, raw), definitions=list(actual_defs),
        replacements=edits, guards=guards))
    outputs[REPORT] = jraw(dict(schema='p011-receive-proc-freezer-v1-startup-host-generation',
        status='MECHANICAL_GENERATED_NOT_SOURCE_CHECKED', generator=generator,
        source=list(SOURCE), definitions=list(actual_defs), guards=guards,
        outputs=[pin(path, value) for path, value in sorted(outputs.items())]))
    return outputs


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_fresh_write_required')
    outputs = build()
    allowed = {TARGET, *CMDS, DELTA, REPORT}
    need(set(outputs) == allowed, 'fixed_output_inventory')
    for name in outputs:
        target = BASE / name
        need(target.resolve().is_relative_to(BASE.resolve()) and not target.exists(), 'fresh_output:' + name)
    for name, raw in outputs.items():
        target = BASE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'mechanical_short_write')
        need(target.read_bytes() == raw, 'mechanical_readback')
    need(read(SOURCE[0], SOURCE[1:]) == replay(outputs[TARGET], json.loads(outputs[DELTA])['replacements'], True), 'original_host_preserved')
    print(json.dumps(dict(status='MECHANICAL_GENERATED_NOT_SOURCE_CHECKED',
        outputs=[pin(name, raw) for name, raw in sorted(outputs.items())]), sort_keys=True))


if __name__ == '__main__':
    main()

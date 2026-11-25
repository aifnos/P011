"""PC-only fresh binding of the original protected closed-startup checker.

No original entry is executed. Only fixed graph bindings and descriptive result
labels/counts change; IO, 60+60/10/240/250 and closed-policy checks are retained.
Run once with --write after the new headless graph is verified by Root.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-publication-progress-graph-v1/'
SELF = PREFIX + 'generate_startup_host.py'
MOTHER = ('host/device_receive_proc_freezer_v1_startup_check.py', 18436,
          'e92a65f81bf1a2ad729b03b5c82579c81cc7c5c496ff5d33ae7817dc6590ac0b')
DEFINITIONS = 'host/formal_receive_publication_progress_v1_definitions.py'
TARGET = 'host/device_receive_publication_progress_v1_startup_check.py'
SOURCE_CMD = 'HOST_MTA_RECEIVE_PUBLICATION_PROGRESS_V1_STARTUP_CHECK.cmd'
DEVICE_CMD = 'TEST_MTA_RECEIVE_PUBLICATION_PROGRESS_V1_STARTUP.cmd'
DELTA = PREFIX + 'startup-host-exactsource-delta.json'
GENERATION = PREFIX + 'startup-host-generation.json'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(name, raw):
    return [name, len(raw), digest(raw)]


def read(name):
    path = BASE / name
    need(not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()), 'source_scope')
    raw = path.read_bytes()
    need(0 < len(raw) <= 2097152, 'source_size')
    return raw


def assignment(raw, name):
    tree = ast.parse(raw.decode('ascii'))
    nodes = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
             isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(nodes) == 1, 'unique_assignment:' + name)
    return ast.literal_eval(nodes[0].value)


def region(raw, name):
    tree = ast.parse(raw.decode('ascii'))
    node = next(node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
                isinstance(node.targets[0], ast.Name) and node.targets[0].id == name)
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode('ascii')


def build():
    inputs = {name: read(name) for name in (MOTHER[0], DEFINITIONS, SELF)}
    original, defs = inputs[MOTHER[0]], inputs[DEFINITIONS]
    need((len(original), digest(original)) == MOTHER[1:], 'frozen_startup_mother')
    payload = assignment(defs, 'PAYLOAD_BYTES')
    origins = assignment(defs, 'ORIGIN_SOURCE_PINS')
    closures = assignment(defs, 'MECHANICAL_CLOSURE_COUNT')
    need(type(payload) is int and 0 < payload <= 4194304 and
         type(origins) is tuple and origins and type(closures) is int and closures > 0,
         'actual_graph_interface')
    need(assignment(defs, 'STATE_ROOT') == '/var/volatile/tmp/p011-mta-rx-progress-v1' and
         assignment(defs, 'STATE_ALIAS') == '/tmp/p011-mta-rx-progress-v1', 'new_graph_root')
    edits = []

    def replace(label, before, after, count=1):
        nonlocal current
        need(before != after and current.count(before.encode('ascii')) == count, 'binding_count:' + label)
        current = current.replace(before.encode('ascii'), after.encode('ascii'))
        edits.append(dict(name=label, before=before, after=after, count=count))

    current = original
    for label, name, value in (
        ('self', 'SELF', TARGET), ('commands', 'CMDS', (SOURCE_CMD, DEVICE_CMD)),
        ('definitions', 'DEFINITIONS', tuple(pin(DEFINITIONS, defs))),
        ('root', 'ROOT_NAME', 'p011-mta-rx-progress-v1'), ('payload', 'PAYLOAD_BYTES', payload)):
        replace(label, region(current, name), name + ' = ' + repr(value) + '\n')
    replace('result_labels', 'receive-proc-freezer-v1-startup', 'receive-publication-progress-v1-startup', 4)
    replace('origin_count_gate', 'len(definitions.ORIGIN_SOURCE_PINS) == 208',
            'len(definitions.ORIGIN_SOURCE_PINS) == ' + str(len(origins)))
    replace('mechanical_gate', "definitions.verify_inputs(inputs) == 8, 'new_freezer_mechanical_closures'",
            "definitions.verify_inputs(inputs) == " + str(closures) + ", 'new_progress_mechanical_closures'")
    replace('remaining_report', 'payload_remaining_bytes=2538', 'payload_remaining_bytes=' + str(4194304-payload))
    replace('origin_count_report', 'flat_origin_pins=208', 'flat_origin_pins=' + str(len(origins)))
    replace('closure_count_report', 'mechanical_closures=8', 'mechanical_closures=' + str(closures))
    replace('readme_origin', 'Actual flat208 provenance and new 8 mechanical closures',
            'Actual flat' + str(len(origins)) + ' provenance and new ' + str(closures) + ' mechanical closures')
    replace('readme_payload', 'Actual75/4191766 retains', 'Actual75/' + str(payload) + ' retains')
    inverse = current
    for edit in reversed(edits):
        need(inverse.count(edit['after'].encode('ascii')) == edit['count'], 'inverse_count')
        inverse = inverse.replace(edit['after'].encode('ascii'), edit['before'].encode('ascii'))
    need(inverse == original and ast.dump(ast.parse(inverse), include_attributes=True) ==
         ast.dump(ast.parse(original), include_attributes=True), 'whole_startup_inverse')
    ast.parse(current.decode('ascii'))
    outputs = {TARGET: current}
    for name, suffix in ((SOURCE_CMD, ''), (DEVICE_CMD, ' --check-device')):
        outputs[name] = ('@echo off\r\n"C:\\Users\\P011_USER\\AppData\\Local\\Programs\\Python\\Python312\\python.exe"'
            ' -E -s -B "%~dp0host\\device_receive_publication_progress_v1_startup_check.py"' + suffix + '\r\n').encode('ascii')
    delta = dict(schema='publication-progress-startup-host-delta', source=list(MOTHER),
                 candidate=pin(TARGET, current), definitions=pin(DEFINITIONS, defs), edits=edits,
                 old_entry_executed=False, tests_executed=False, device_executed=False)
    outputs[DELTA] = (json.dumps(delta, indent=2, sort_keys=True) + '\n').encode('ascii')
    report = dict(schema='publication-progress-startup-host-generation',
                  inputs=[pin(name, raw) for name, raw in inputs.items()],
                  output_pins=[pin(name, raw) for name, raw in outputs.items()],
                  tests_executed=False, device_executed=False, original_full_byte_ast_inverse=True)
    outputs[GENERATION] = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    return inputs, outputs


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_fresh_write_required')
    inputs, outputs = build()
    for name in outputs:
        path = BASE / name
        need(not path.exists() and not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()),
             'fresh_output_only')
    for name, raw in outputs.items():
        path = BASE / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'output_write')
        need(path.read_bytes() == raw, 'output_readback')
    need(all(read(name) == raw for name, raw in inputs.items()), 'input_changed')
    print(json.dumps(dict(outputs=[pin(name, raw) for name, raw in outputs.items()],
                         tests_executed=False, device_executed=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

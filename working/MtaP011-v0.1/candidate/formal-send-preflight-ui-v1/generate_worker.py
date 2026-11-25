"""PC-only fresh preflight UI constant closure, default SOURCE plan only.

An explicit --write publishes four new EXCL files. Existing UI SESSION,
validator, 19 assets, ELF/QRC, FC9, sender27 and all business definitions are
unchanged. No imported runtime, old builder/main/test, device or RF runs here.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/formal-send-preflight-ui-v1/generate_worker.py'
PREFIX = 'candidate/formal-send-preflight-ui-v1/'
SESSION = 'c69296a193ff43ce8e5b901d'
OLD_SUFFIX = '-formal-send-picker-package-v1'
SUFFIX = '-formal-send-preflight-native-v1'
ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v7'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v7'
BUNDLE = 'out/mta-ui-send-picker-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
WORKER = ('candidate/formal-send-repair-package-v1/runtime/ui_session.py',
          46416, '719507f6207c2d94720007f5593092a6d6c5da5b8f1ec7428140347b9525996e')
GUARDIAN = ('candidate/formal-send-picker-package-v1/runtime/ui_guardian.py',
            43994, 'c118e4f1a6c8f2000a6ae97680d58304af5d8cd55ea30c08cf3a96df16c61477')
VALIDATOR = ('candidate/formal-send-picker-package-v1/runtime/ui_assets.py',
             12526, '7bf8bd1e239ab8cf21a6662ea9217de3e2bef634fb20f31880482abbaca4fd21')
OUTER = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_session.py',
         24060, '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f')
CATALOG = ('candidate/formal-send-filecenter-deploy-v7/assets/ordinary-source-manifest.json',
           20810, '9be61347f4a44d031cf7c07095692b4cd0de21f79410a9f45c5ad6b2073f9d52')
GRAPH_GENERATION = ('candidate/formal-send-filecenter-deploy-v7/generation.json',
                    22477, 'a5da1b8c31a550712c5115077d28f13b4e5cca456acdaced4d84e046ee540c55')
UI_GENERATION = ('candidate/formal-send-picker-package-v1/generation.json',
                 18953, '4b35068be0fac257a7568d3790a593c42e09d43efe32e96a1a14865ed2658b80')
SOURCE_PINS = (WORKER, GUARDIAN, VALIDATOR, OUTER, CATALOG, GRAPH_GENERATION, UI_GENERATION)
DEST_GUARDIAN = PREFIX + 'runtime/ui_guardian.py'
DEST_WORKER = PREFIX + 'runtime/ui_session.py'
DELTA = PREFIX + 'exactsource-delta.json'
GENERATION = PREFIX + 'generation.json'
OUTPUT_PATHS = (DEST_GUARDIAN, DEST_WORKER, DELTA, GENERATION)
WORKER_NAMES = ('SENDER_PIN', 'GUARDIAN_PIN', 'SENDER_ROOT', 'SENDER_PHYSICAL_ROOT', 'CONTROL_NAME')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def take(path, inputs, pin=None):
    file = BASE / path
    need(file.is_file() and not file.is_symlink(), 'source_file')
    before = file.stat()
    raw = file.read_bytes()
    after = file.stat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in keys) ==
         tuple(getattr(after, key) for key in keys), 'source_changed')
    if pin is not None:
        need((len(raw), digest(raw)) == tuple(pin), 'source_pin')
    if path in inputs:
        need(inputs[path] == raw, 'source_changed')
    inputs[path] = raw
    return raw


def tree(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def assignment(raw, name):
    rows = [node for node in tree(raw).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
            node.targets[0].id == name]
    need(len(rows) == 1, 'assignment_identity')
    return rows[0]


def literal(raw, name):
    return ast.literal_eval(assignment(raw, name).value)


def expression_is(raw, name, expression):
    return (ast.dump(assignment(raw, name).value, include_attributes=False) ==
            ast.dump(ast.parse(expression, mode='eval').body, include_attributes=False))


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return tuple((type(node).__name__, node.name, node.lineno, node.col_offset,
                  node.end_lineno, b''.join(lines[node.lineno - 1:node.end_lineno]))
                 for node in ast.walk(tree(raw))
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def changed(raw, replacements):
    origin = raw
    edits = []
    for name, expression in replacements:
        node = assignment(raw, name)
        need(node.lineno == node.end_lineno, 'one_line_assignment')
        lines = raw.splitlines(keepends=True)
        before = lines[node.lineno - 1]
        need(before.endswith(b'\n') and not before.endswith(b'\r\n'), 'source_lf')
        after = (name + ' = ' + expression + '\n').encode('ascii')
        need(before != after and raw.count(before) == 1, 'forward_identity')
        raw = raw.replace(before, after, 1)
        need(raw.count(after) == 1, 'inverse_identity')
        edits.append(dict(name=name, before=before.decode('utf-8'),
                          after=after.decode('ascii'), count=1, line=node.lineno))
    restored = raw
    for row in reversed(edits):
        after, before = row['after'].encode('ascii'), row['before'].encode('utf-8')
        need(restored.count(after) == 1, 'inverse_count')
        restored = restored.replace(after, before, 1)
    need(restored == origin, 'full_byte_inverse')
    need(ast.dump(tree(restored), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'full_ast_inverse')
    names = {row[0] for row in replacements}
    def shape(value):
        return [ast.dump(node, include_attributes=False) for node in tree(value).body
                if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                        isinstance(node.targets[0], ast.Name) and node.targets[0].id in names)]
    need(shape(raw) == shape(origin), 'other_ast_unchanged')
    need(definitions(raw) == definitions(origin), 'definitions_bytes_and_lines_unchanged')
    return raw, edits


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')


def compose():
    inputs = {}
    for pin in SOURCE_PINS:
        take(pin[0], inputs, pin[1:])
    self_raw = take(SELF, inputs)
    worker, guardian = inputs[WORKER[0]], inputs[GUARDIAN[0]]
    validator, outer = inputs[VALIDATOR[0]], inputs[OUTER[0]]
    catalog, graph = json.loads(inputs[CATALOG[0]]), json.loads(inputs[GRAPH_GENERATION[0]])
    ui = json.loads(inputs[UI_GENERATION[0]])
    need(catalog['schema'] == 'p011-formal-send-filecenter-deploy-v7-ordinary-source-catalog' and
         catalog['source_count'] == 32 and catalog['ordinary_source_bytes'] == 1078691 and
         catalog['ordinary_root'] == ROOT + '/runtime' and
         catalog['physical_ordinary_root'] == PHYSICAL_ROOT + '/runtime', 'catalog_identity')
    outer_rows = [row for row in catalog['startup_sources'] if row['module'] == 'formal_send_session']
    need(len(outer_rows) == 1 and
         (outer_rows[0]['source'], outer_rows[0]['bytes'], outer_rows[0]['sha256']) == OUTER,
         'catalog_outer_pin')
    need(graph['schema'] == 'p011-formal-send-preflight-native-graph-v1-generation' and
         graph['root'] == ROOT and graph['physical_root'] == PHYSICAL_ROOT and
         graph['ordinary_roles'] == 32 and graph['ordinary_source_bytes'] == 1078691 and
         graph['staged_files'] == 37 and graph['staged_bytes'] == 1368142 and
         graph['sender_files'] == 27 and graph['sender_bytes'] == 2402458 and
         graph['observer_files'] == 41 and graph['observer_bytes'] == 1548495 and
         graph['observer_changes'] == 4 and graph['observer_reused'] == 37 and
         graph['filecenter_files'] == 9 and graph['filecenter_bytes'] == 99972 and
         graph['graph_business_edits'] == 0, 'graph_generation_identity')
    need(ui['session'] == SESSION and ui['bundle'] == BUNDLE and
         ui['remote'] == REMOTE and ui['stage_file_count'] == 19 and ui['asset_bytes'] == 4184758 and
         ui['control_suffix'] == OLD_SUFFIX, 'ui_generation_identity')
    need(literal(worker, 'SESSION') == literal(guardian, 'SESSION') ==
         literal(validator, 'SESSION') == SESSION, 'session_identity')
    need(literal(outer, 'ROOT') == ROOT and literal(outer, 'PHYSICAL_ROOT') == PHYSICAL_ROOT,
         'outer_roots')
    control_before = "'p011-mta-ui-session-' + SESSION + " + repr(OLD_SUFFIX)
    need(expression_is(worker, 'CONTROL_NAME', control_before) and
         expression_is(guardian, 'CONTROL_NAME', control_before), 'old_control_identity')
    need(literal(worker, 'SENDER_ROOT') == '/tmp/p011-mta-formal-send-filecenter-deploy-v6' and
         literal(worker, 'SENDER_PHYSICAL_ROOT') ==
         '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6' and
         literal(worker, 'ASSETS_PIN') == VALIDATOR[1:] and
         literal(worker, 'GUARDIAN_PIN') == GUARDIAN[1:], 'old_worker_identity')
    control_after = "'p011-mta-ui-session-' + SESSION + " + repr(SUFFIX)
    new_guardian, guardian_edits = changed(guardian, (('CONTROL_NAME', control_after),))
    guardian_pin = (len(new_guardian), digest(new_guardian))
    replacements = (('SENDER_PIN', repr(OUTER[1:])), ('GUARDIAN_PIN', repr(guardian_pin)),
                    ('SENDER_ROOT', repr(ROOT)), ('SENDER_PHYSICAL_ROOT', repr(PHYSICAL_ROOT)),
                    ('CONTROL_NAME', control_after))
    need(tuple(row[0] for row in replacements) == WORKER_NAMES, 'worker_edit_set')
    new_worker, worker_edits = changed(worker, replacements)
    need(literal(new_worker, 'SENDER_PIN') == OUTER[1:] and
         literal(new_worker, 'GUARDIAN_PIN') == guardian_pin and
         literal(new_worker, 'ASSETS_PIN') == VALIDATOR[1:] and
         literal(new_worker, 'SENDER_ROOT') == ROOT and
         literal(new_worker, 'SENDER_PHYSICAL_ROOT') == PHYSICAL_ROOT and
         literal(new_worker, 'FILECENTER_PINS') == literal(worker, 'FILECENTER_PINS') and
         expression_is(new_worker, 'CONTROL_NAME', control_after) and
         expression_is(new_guardian, 'CONTROL_NAME', control_after), 'new_constant_closure')
    evidence = dict(schema='p011-formal-send-preflight-ui-v1-exactsource-delta',
        guardian=dict(origin=list(GUARDIAN), candidate=[DEST_GUARDIAN] + list(guardian_pin),
                      replacements=guardian_edits),
        worker=dict(origin=list(WORKER), candidate=[DEST_WORKER, len(new_worker), digest(new_worker)],
                    replacements=worker_edits),
        changed_guardian_assignments=1, changed_worker_assignments=5,
        full_byte_inverse=True, full_ast_inverse=True, other_ast_unchanged=True,
        all_definition_bytes_and_lines_unchanged=True, business_definitions_executed=False)
    delta = json_bytes(evidence)
    output_pins = ([DEST_GUARDIAN, len(new_guardian), digest(new_guardian)],
                   [DEST_WORKER, len(new_worker), digest(new_worker)], [DELTA, len(delta), digest(delta)])
    facts = dict(schema='p011-formal-send-preflight-ui-v1-generation',
        scope='PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN',
        generator=[SELF, len(self_raw), digest(self_raw)],
        root=ROOT, physical_root=PHYSICAL_ROOT, session=SESSION, bundle=BUNDLE, remote=REMOTE,
        control_suffix=SUFFIX, control_name='p011-mta-ui-session-' + SESSION + SUFFIX,
        control='/var/volatile/tmp/p011-mta-ui-session-' + SESSION + SUFFIX,
        ordinary_files=37, ordinary_bytes=1368142, ordinary_roles=32, ordinary_source_bytes=1078691,
        sender_files=27, sender_bytes=2402458, observer_files=41, observer_bytes=1548495,
        filecenter_files=9, filecenter_bytes=99972, stage_files=19, asset_bytes=4184758,
        ui_bundle_rebuilt=False, ui_resources_changed=False, ui_validator=list(VALIDATOR),
        ui_generation=list(UI_GENERATION), graph_generation=list(GRAPH_GENERATION),
        sender_outer=list(OUTER), worker_assignments=list(WORKER_NAMES), guardian_assignments=['CONTROL_NAME'],
        changed_worker_assignments=5, changed_guardian_assignments=1,
        full_byte_inverse=True, full_ast_inverse=True, other_ast_unchanged=True,
        all_definition_bytes_and_lines_unchanged=True,
        source_inputs=[[path, len(raw), digest(raw)] for path, raw in inputs.items()],
        input_count=len(inputs), output_count=4, output_pins=output_pins,
        original_window_seconds=600, original_cleanup_seconds=60, smoke_seconds=20,
        business_definitions_executed=False, old_builders=0, old_mains=0, old_tests=0,
        device=False, rf=False, phone=False, source_preserved=True)
    outputs = ((DEST_GUARDIAN, new_guardian), (DEST_WORKER, new_worker),
               (DELTA, delta), (GENERATION, json_bytes(facts)))
    need(tuple(path for path, raw in outputs) == OUTPUT_PATHS, 'exclusive_output_set')
    need(all((BASE / path).read_bytes() == raw for path, raw in inputs.items()), 'source_preserved')
    return inputs, outputs, facts


def write_new(path, raw):
    need(not path.exists() and not path.is_symlink(), 'exclusive_output_conflict')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'output_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='EXCL publish the four new PC files only.')
    args = parser.parse_args()
    inputs, outputs, facts = compose()
    if args.write:
        need(all(not (BASE / path).exists() and not (BASE / path).is_symlink()
                 for path, raw in outputs), 'exclusive_output_conflict')
        for path, raw in outputs:
            write_new(BASE / path, raw)
        need(all((BASE / path).read_bytes() == raw for path, raw in inputs.items()), 'source_preserved')
    print(json.dumps(dict(write_requested=args.write, input_count=len(inputs), output_count=len(outputs),
        outputs=[[path, len(raw), digest(raw)] for path, raw in outputs],
        guardian_assignments=1, worker_assignments=5, full_byte_inverse=True, full_ast_inverse=True,
        definitions_bytes_and_lines_unchanged=True, ui_rebuilt=False, device=False, rf=False,
        phone=False, old_tests=0, old_mains=0), sort_keys=True))


if __name__ == '__main__':
    main()

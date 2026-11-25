"""Fresh native-preflight sender UI carrier; default PC SOURCE only.

Use the frozen repair HOST's pure preparation, never its historical main.
The final derived main alone supplies the unchanged 20-second smoke, original
17 fields, 600+60 window, 800/810 carrier deadline, FD and stock restoration.
No UI build, 19-file stage, native/observer stage, phone action or RF is added.
The fresh CONTROL must be absent before the sole explicitly authorized run.
"""
import ast
import hashlib
import json
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_preflight_ui_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_PREFLIGHT_UI_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_PREFLIGHT_UI_V1_SOURCE_CHECK.cmd'
MOTHER = ('host/device_formal_send_repair_ui_v1_check.py', 13163,
          '3efc100b3a91fa5b6cdf9dc3f51a9c545d3fbc1a885d0c3ab288823997dc390c')
ORIGINAL = ('host/device_formal_send_filecenter_ui_v7_check.py', 28635,
            'b888055f21b21eb60d003e8dd00fde62646ef1dd2628d568146b987689ed2449')
OLD_COMMANDS = (
    ('HOST_MTA_FORMAL_SEND_REPAIR_UI_V1_SOURCE_CHECK.cmd', 307,
     '9f78f871ca0dcc8aa6cd2a50d42514e4fc1579f6f78183b5e1a4ad96b30db336'),
    ('TEST_MTA_FORMAL_SEND_REPAIR_UI_V1.cmd', 323,
     '976740b981b52b05390f7c363678502d0f27bd50225cb34c5b257d659658229d'))
ORIGIN_WORKER = ('candidate/formal-send-repair-package-v1/runtime/ui_session.py', 46416,
                 '719507f6207c2d94720007f5593092a6d6c5da5b8f1ec7428140347b9525996e')
ORIGIN_GUARDIAN = ('candidate/formal-send-picker-package-v1/runtime/ui_guardian.py', 43994,
                   'c118e4f1a6c8f2000a6ae97680d58304af5d8cd55ea30c08cf3a96df16c61477')
ORIGIN_OUTER = ('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_session.py', 24059,
                '9c7f87dc4eb7cca9cc09e65a75063365429c363ea1e68da27e9597f228bbf036')
WORKER = ('candidate/formal-send-preflight-ui-v1/runtime/ui_session.py', 46418,
          'eb1f076560b8061a48b7138a747e805fd9fa32fad86d7d2a025e428d555ab9b7')
GUARDIAN = ('candidate/formal-send-preflight-ui-v1/runtime/ui_guardian.py', 43996,
            '8df81808cbd6e32848e5698a5adc486f1027daf8270e5841f83f852d3513b3c1')
VALIDATOR = ('candidate/formal-send-picker-package-v1/runtime/ui_assets.py', 12526,
             '7bf8bd1e239ab8cf21a6662ea9217de3e2bef634fb20f31880482abbaca4fd21')
OUTER = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_session.py', 24060,
         '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f')
GENERATOR = ('candidate/formal-send-preflight-ui-v1/generate_worker.py', 14343,
             '694e1deb96b4f8d1a6abbcf5d9deafc6633e8477d5a2117efb618ff25912c80e')
DELTA = ('candidate/formal-send-preflight-ui-v1/exactsource-delta.json', 2936,
         'db377afb5bc06e45351a96a5e44cf98594ca3ae75c226402716e62e4372326a9')
GENERATION = ('candidate/formal-send-preflight-ui-v1/generation.json', 4591,
              '48c5435e54ba0aaab867801580f919aa9e4db522516b686f05f5bbcc53d9dd8f')
CATALOG = ('candidate/formal-send-filecenter-deploy-v7/assets/ordinary-source-manifest.json', 20810,
           '9be61347f4a44d031cf7c07095692b4cd0de21f79410a9f45c5ad6b2073f9d52')
GRAPH_GENERATION = ('candidate/formal-send-filecenter-deploy-v7/generation.json', 22477,
                    'a5da1b8c31a550712c5115077d28f13b4e5cca456acdaced4d84e046ee540c55')
UI_GENERATION = ('candidate/formal-send-picker-package-v1/generation.json', 18953,
                 '4b35068be0fac257a7568d3790a593c42e09d43efe32e96a1a14865ed2658b80')
SESSION = 'c69296a193ff43ce8e5b901d'
BUNDLE = 'out/mta-ui-send-picker-v1-' + SESSION
ROOT = '/tmp/p011-mta-formal-send-filecenter-deploy-v7'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v7'
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
CONTROL_SUFFIX = '-formal-send-preflight-native-v1'
OLD_SUFFIX = '-formal-send-picker-package-v1'
WORKER_ASSIGNMENTS = frozenset(('SENDER_PIN', 'GUARDIAN_PIN', 'SENDER_ROOT',
                               'SENDER_PHYSICAL_ROOT', 'CONTROL_NAME'))
HOST_ASSIGNMENTS = frozenset(('SELF', 'CMD', 'RUNTIME', 'WORKER', 'GUARDIAN',
                             'OUTER', 'SOURCE_BASELINES'))
PREPARE_NAMES = frozenset(('need', 'digest', 'checked_input', 'literal', 'definition_rows',
                          'constants_inverse', 'repair_source_boundary', 'derive_host', 'prepare'))
SOURCE_BASELINES = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_input(inputs, pin):
    raw = inputs[pin[0]]
    need(type(raw) is bytes and (len(raw), digest(raw)) == pin[1:], 'preflight_input_pin')
    return raw


def tree(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def assignment(raw, name):
    rows = [row for row in tree(raw).body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'preflight_assignment_identity')
    return rows[0]


def literal(raw, name):
    return ast.literal_eval(assignment(raw, name).value)


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return tuple((type(row).__name__, row.name, row.lineno, row.col_offset, row.end_lineno,
                  b''.join(lines[row.lineno - 1:row.end_lineno]))
                 for row in ast.walk(tree(raw)) if isinstance(row, (ast.FunctionDef, ast.ClassDef)))


def constants_inverse(origin, current, rows, names):
    need(type(rows) is list and len(rows) == len(names) and
         {row['name'] for row in rows} == names, 'preflight_constant_scope')
    forward, inverse = origin, current
    for row in rows:
        before, after = row['before'].encode('utf-8'), row['after'].encode('ascii')
        node = assignment(forward, row['name'])
        lines = forward.splitlines(keepends=True)
        need(node.lineno == node.end_lineno == row['line'] and
             lines[node.lineno - 1] == before and row['count'] == 1 and
             forward.count(before) == 1, 'preflight_forward_identity')
        forward = forward.replace(before, after, 1)
    for row in reversed(rows):
        before, after = row['before'].encode('utf-8'), row['after'].encode('ascii')
        need(inverse.count(after) == 1, 'preflight_inverse_count')
        inverse = inverse.replace(after, before, 1)
    need(forward == current and inverse == origin and
         ast.dump(tree(inverse), include_attributes=True) == ast.dump(tree(origin), include_attributes=True),
         'preflight_full_byte_ast_inverse')
    def shape(raw):
        return [ast.dump(row, include_attributes=False) for row in tree(raw).body
                if not (isinstance(row, ast.Assign) and len(row.targets) == 1 and
                        isinstance(row.targets[0], ast.Name) and row.targets[0].id in names)]
    need(shape(origin) == shape(current) and definitions(origin) == definitions(current),
         'preflight_other_bytes_lines_ast_unchanged')


def control_is(raw, suffix):
    expected = ast.parse("'p011-mta-ui-session-' + SESSION + " + repr(suffix), mode='eval').body
    return (ast.dump(assignment(raw, 'CONTROL_NAME').value, include_attributes=False) ==
            ast.dump(expected, include_attributes=False))


def preflight_source_boundary(inputs):
    """Actual byte closure only; no old graph/verifier, business or test runs."""
    need(type(SOURCE_BASELINES) is tuple, 'preflight_prepared_inputs')
    for pin in SOURCE_BASELINES + (WORKER, GUARDIAN, VALIDATOR, OUTER):
        checked_input(inputs, pin)
    delta = json.loads(inputs[DELTA[0]])
    need(delta['schema'] == 'p011-formal-send-preflight-ui-v1-exactsource-delta' and
         delta['guardian']['origin'] == list(ORIGIN_GUARDIAN) and
         delta['guardian']['candidate'] == list(GUARDIAN) and
         delta['worker']['origin'] == list(ORIGIN_WORKER) and
         delta['worker']['candidate'] == list(WORKER), 'preflight_delta_identity')
    constants_inverse(inputs[ORIGIN_GUARDIAN[0]], inputs[GUARDIAN[0]],
                      delta['guardian']['replacements'], frozenset(('CONTROL_NAME',)))
    constants_inverse(inputs[ORIGIN_WORKER[0]], inputs[WORKER[0]],
                      delta['worker']['replacements'], WORKER_ASSIGNMENTS)
    current = json.loads(inputs[GENERATION[0]])
    expected_inputs = [list(row) for row in (ORIGIN_WORKER, ORIGIN_GUARDIAN, VALIDATOR, OUTER,
                                             CATALOG, GRAPH_GENERATION, UI_GENERATION, GENERATOR)]
    need(current['schema'] == 'p011-formal-send-preflight-ui-v1-generation' and
         current['generator'] == list(GENERATOR) and current['source_inputs'] == expected_inputs and
         current['input_count'] == 8 and current['output_count'] == 4 and
         current['output_pins'] == [list(GUARDIAN), list(WORKER), list(DELTA)] and
         current['root'] == ROOT and current['physical_root'] == PHYSICAL_ROOT and
         current['session'] == SESSION and current['bundle'] == BUNDLE and current['remote'] == REMOTE and
         current['control_suffix'] == CONTROL_SUFFIX and
         current['control_name'] == 'p011-mta-ui-session-' + SESSION + CONTROL_SUFFIX and
         current['ui_validator'] == list(VALIDATOR) and current['ui_generation'] == list(UI_GENERATION) and
         current['graph_generation'] == list(GRAPH_GENERATION) and current['sender_outer'] == list(OUTER) and
         current['stage_files'] == 19 and current['asset_bytes'] == 4184758 and
         current['ordinary_files'] == 37 and current['ordinary_bytes'] == 1368142 and
         current['observer_files'] == 41 and current['observer_bytes'] == 1548495 and
         current['sender_files'] == 27 and current['sender_bytes'] == 2402458 and
         current['ui_bundle_rebuilt'] is False and current['ui_resources_changed'] is False and
         current['business_definitions_executed'] is False and current['device'] is False and
         current['original_window_seconds'] == 600 and current['original_cleanup_seconds'] == 60 and
         current['smoke_seconds'] == 20, 'preflight_generation_identity')
    catalog = json.loads(inputs[CATALOG[0]])
    rows = [row for row in catalog['startup_sources'] if row['module'] == 'formal_send_session']
    need(catalog['source_count'] == 32 and catalog['ordinary_source_bytes'] == 1078691 and
         catalog['ordinary_root'] == ROOT + '/runtime' and
         catalog['physical_ordinary_root'] == PHYSICAL_ROOT + '/runtime' and len(rows) == 1 and
         (rows[0]['source'], rows[0]['bytes'], rows[0]['sha256']) == OUTER, 'preflight_catalog_binding')
    # Existing UI metadata still certifies the original unmodified 19 assets,
    # validator and old guardian. It does not certify the new control constant.
    ui = json.loads(inputs[UI_GENERATION[0]])
    need(ui['session'] == SESSION and ui['bundle'] == BUNDLE and ui['remote'] == REMOTE and
         ui['stage_file_count'] == 19 and ui['asset_bytes'] == 4184758 and
         ui['control_suffix'] == OLD_SUFFIX, 'preflight_existing_ui_identity')
    pins = ui['output_pins']
    need(len(pins) == 24 and len({row[0] for row in pins}) == 24, 'preflight_existing_ui_inventory')
    required = {BUNDLE + '/' + row[0] for row in literal(inputs[VALIDATOR[0]], 'PINS')}
    required.update((BUNDLE + '/SOURCE.sha256', BUNDLE + '/stage-manifest.json',
                     ORIGIN_GUARDIAN[0], VALIDATOR[0]))
    matched = set()
    for path, size, sha in pins:
        if path in required:
            checked_input(inputs, (path, size, sha))
            matched.add(path)
    need(matched == required and len(required) == 22, 'preflight_existing_ui_exact')
    raw = inputs[WORKER[0]]
    need(literal(raw, 'SESSION') == literal(inputs[GUARDIAN[0]], 'SESSION') ==
         literal(inputs[VALIDATOR[0]], 'SESSION') == SESSION and
         literal(raw, 'SENDER_ROOT') == ROOT and literal(raw, 'SENDER_PHYSICAL_ROOT') == PHYSICAL_ROOT and
         literal(inputs[OUTER[0]], 'ROOT') == ROOT and literal(inputs[OUTER[0]], 'PHYSICAL_ROOT') == PHYSICAL_ROOT and
         literal(raw, 'SENDER_PIN') == OUTER[1:] and literal(raw, 'GUARDIAN_PIN') == GUARDIAN[1:] and
         literal(raw, 'ASSETS_PIN') == VALIDATOR[1:] and
         literal(raw, 'FILECENTER_PINS') == literal(inputs[ORIGIN_WORKER[0]], 'FILECENTER_PINS') and
         control_is(raw, CONTROL_SUFFIX) and control_is(inputs[GUARDIAN[0]], CONTROL_SUFFIX),
         'preflight_actual_decoder_root_control_closure')
    return True


def mother_prepare():
    """Load only nine fixed pure helpers and constants; no old entry main."""
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'preflight_mother_pin')
    parsed = tree(raw)
    chosen = [row for row in parsed.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
              isinstance(row, ast.FunctionDef) and row.name in PREPARE_NAMES]
    need({row.name for row in chosen if isinstance(row, ast.FunctionDef)} == PREPARE_NAMES,
         'preflight_pure_prepare_inventory')
    module = types.ModuleType('fixed_formal_send_preflight_ui_v1_mother_pure_definitions')
    module.__file__ = str(BASE / MOTHER[0])
    body = ast.Module(body=chosen, type_ignores=[])
    exec(compile(body, '<fixed-preflight-ui-mother-pure-definitions>', 'exec'), module.__dict__)
    need(module.MOTHER == ORIGINAL and module.WORKER == ORIGIN_WORKER and
         module.GUARDIAN == ORIGIN_GUARDIAN and module.OUTER == ORIGIN_OUTER and
         module.VALIDATOR == VALIDATOR and module.SESSION == SESSION and module.BUNDLE == BUNDLE,
         'preflight_mother_constants')
    return module


def derive_host(origin):
    """Seven fixed assignments and finite identity literals, complete inverse."""
    raw, edits = origin, []
    def change(before, after, count=1):
        nonlocal raw
        need(type(before) is bytes and type(after) is bytes and before != after and
             raw.count(before) == count, 'preflight_host_forward_count')
        raw = raw.replace(before, after)
        edits.append((before, after, count))
    def constant(name, expression):
        node = assignment(raw, name)
        before = b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
        change(before, (name + ' = ' + expression + '\n').encode('ascii'))
    for name, value in (('SELF', SELF), ('CMD', CMD),
                        ('RUNTIME', 'candidate/formal-send-preflight-ui-v1/runtime/'),
                        ('WORKER', WORKER), ('GUARDIAN', GUARDIAN), ('OUTER', OUTER),
                        ('SOURCE_BASELINES', SOURCE_BASELINES)):
        constant(name, repr(value))
    for before, after, count in (
        (b'Thin fixed sender repair UI-v1 closure diagnostic carrier entry.',
         b'Thin fixed sender preflight UI-v1 closure diagnostic carrier entry.', 1),
        (b'requires v6 ordinary and existing repaired 19UI assets.',
         b'requires v7 ordinary and the unchanged existing 19UI assets.', 1),
        (b'fixed_sender_repair_ui_v1_', b'fixed_sender_preflight_ui_v1_', 5),
        (b'fixed-sender-repair-ui-v1-', b'fixed-sender-preflight-ui-v1-', 1),
        (b'formal_send_repair_ui_v1_fixed_carrier_entry', b'formal_send_preflight_ui_v1_fixed_carrier_entry', 1),
        (b'fixed-formal-send-repair-ui-v1-bootstrap', b'fixed-formal-send-preflight-ui-v1-bootstrap', 1),
        (b'fixed-repair-ui-v1-carrier', b'fixed-preflight-ui-v1-carrier', 1),
        (b"('formal-send-repair-ui-v1-'+mode+", b"('formal-send-preflight-ui-v1-'+mode+", 1),
        (b"+SESSION+'-formal-send-picker-package-v1'", b"+SESSION+'-formal-send-preflight-native-v1'", 1),
        (b"for path in (SELF,CMD,CONTRACT,'HOST_MTA_FORMAL_SEND_REPAIR_UI_V1_SOURCE_CHECK.cmd'):",
         ('for path in (SELF,CMD,CONTRACT,' + repr(SOURCE_CMD) + '):').encode('ascii'), 1),
    ):
        change(before, after, count)
    inverse = raw
    for before, after, count in reversed(edits):
        need(inverse.count(after) == count, 'preflight_host_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == origin and ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'preflight_host_complete_byte_ast_inverse')
    old_tree, new_tree = tree(origin), tree(raw)
    need(len(old_tree.body) == len(new_tree.body), 'preflight_host_toplevel_shape')
    allowed_methods = frozenset(('ui_program', 'carrier_body', 'carrier_command', 'main'))
    changed_assignments, changed_methods = set(), set()
    for old, new in zip(old_tree.body, new_tree.body):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            names = {target.id for target in old.targets if isinstance(target, ast.Name)}
            need(len(names) == 1 and names <= HOST_ASSIGNMENTS and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]), 'preflight_host_assignment_scope')
            changed_assignments.update(names)
        elif isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef):
            need(old.name == new.name and old.name in allowed_methods, 'preflight_host_method_scope')
            changed_methods.add(old.name)
        else:
            need(isinstance(old, ast.Expr) and isinstance(new, ast.Expr) and
                 old is old_tree.body[0] and new is new_tree.body[0], 'preflight_host_other_toplevel')
    need(changed_assignments == HOST_ASSIGNMENTS and changed_methods == allowed_methods,
         'preflight_host_edit_inventory')
    return raw


def prepare():
    """In-memory overlays only; SOURCE/device action belongs to final main."""
    global SOURCE_BASELINES
    mother = mother_prepare()
    previous, origin = mother.prepare()
    need(previous.SESSION == SESSION and previous.BUNDLE == BUNDLE and previous.REMOTE == REMOTE,
         'preflight_unchanged_ui_environment')
    sources = (MOTHER,) + OLD_COMMANDS + mother.SOURCE_BASELINES + (
        ORIGIN_WORKER, ORIGIN_GUARDIAN, ORIGIN_OUTER, VALIDATOR, GENERATOR, DELTA,
        GENERATION, CATALOG, GRAPH_GENERATION)
    need(len({row[0] for row in sources}) == len(sources), 'preflight_unique_source_baselines')
    SOURCE_BASELINES = sources
    raw = derive_host(origin)
    module = types.ModuleType('fixed_formal_send_preflight_ui_v1_host_definitions')
    module.__file__ = str(BASE / SELF)
    exec(compile(raw, '<derived-formal-send-preflight-ui-v1-host>', 'exec'), module.__dict__)
    module._REPAIR_SOURCE_BOUNDARY = preflight_source_boundary
    need(module.WORKER == WORKER and module.GUARDIAN == GUARDIAN and module.OUTER == OUTER and
         module.SESSION == SESSION and module.BUNDLE == BUNDLE and module.REMOTE == REMOTE,
         'preflight_final_host_bindings')
    return module, raw


def main():
    module, raw = prepare()
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())

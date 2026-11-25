"""Fixed repair-package sender UI carrier. Default PC SOURCE only.

This thin entry derives the frozen UI-v7 HOST in memory; it never runs that
historical main or diagnostic. Only the explicitly selected derived main may
run. --check-device preserves the existing 20-second display-only smoke and
its original guardian, 600+60, 800/810, FD and stock-restoration predicates.
No WATCH/screenshot, asset stage, RF, phone action or old test is added.
The unchanged private sender/observer Proc remains a separate runtime risk.
"""
import ast
import hashlib
import json
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_repair_ui_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_REPAIR_UI_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_UI_V1_SOURCE_CHECK.cmd'
MOTHER = ('host/device_formal_send_filecenter_ui_v7_check.py', 28635,
          'b888055f21b21eb60d003e8dd00fde62646ef1dd2628d568146b987689ed2449')
WORKER = ('candidate/formal-send-repair-package-v1/runtime/ui_session.py', 46416,
          '719507f6207c2d94720007f5593092a6d6c5da5b8f1ec7428140347b9525996e')
GUARDIAN = ('candidate/formal-send-picker-package-v1/runtime/ui_guardian.py', 43994,
            'c118e4f1a6c8f2000a6ae97680d58304af5d8cd55ea30c08cf3a96df16c61477')
VALIDATOR = ('candidate/formal-send-picker-package-v1/runtime/ui_assets.py', 12526,
             '7bf8bd1e239ab8cf21a6662ea9217de3e2bef634fb20f31880482abbaca4fd21')
OUTER = ('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_session.py', 24059,
         '9c7f87dc4eb7cca9cc09e65a75063365429c363ea1e68da27e9597f228bbf036')
OLD_WORKER = ('candidate/formal-send-filecenter-ui-v7/runtime/ui_session.py', 46415,
              'bbbaf091f20715531e045d1b7b1a281bc78d569f5bac6089da1b105d2282dbe4')
OLD_GUARDIAN = ('candidate/formal-send-filecenter-ui-v7/runtime/ui_guardian.py', 43993,
                '30b7157cabf3dd75eb82a671a343a106c1f9e688c1ad60e12c7b8e172ffc255e')
OLD_VALIDATOR = ('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py', 12526,
                 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')
WORKER_DELTA = ('candidate/formal-send-repair-package-v1/exactsource-delta.json', 3723,
                'c17ee9d76805212b009b5ee0849e0bacbda6b41a693ac4e4aae0bf483e6113a7')
UI_GENERATION = ('candidate/formal-send-picker-package-v1/generation.json', 18953,
                 '4b35068be0fac257a7568d3790a593c42e09d43efe32e96a1a14865ed2658b80')
SOURCE_BASELINES = (MOTHER, OLD_WORKER, OLD_GUARDIAN, OLD_VALIDATOR,
                    WORKER_DELTA, UI_GENERATION)
SESSION = 'c69296a193ff43ce8e5b901d'
BUNDLE = 'out/mta-ui-send-picker-v1-' + SESSION
CONTROL_SUFFIX = '-formal-send-picker-package-v1'
ASSIGNMENTS = frozenset(('SELF', 'CMD', 'SESSION', 'BUNDLE', 'RUNTIME',
                         'WORKER', 'GUARDIAN', 'VALIDATOR', 'OUTER', 'SOURCE_BASELINES'))
WORKER_ASSIGNMENTS = frozenset(('SENDER_PIN', 'GUARDIAN_PIN', 'ASSETS_PIN',
    'SENDER_ROOT', 'SENDER_PHYSICAL_ROOT', 'SESSION', 'CONTROL_NAME', 'SENDER_ASSET_SEAL'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_input(inputs, pin):
    raw = inputs[pin[0]]
    need(type(raw) is bytes and (len(raw), digest(raw)) == pin[1:], 'repair_input_pin')
    return raw


def literal(raw, name):
    values = [row.value for row in ast.parse(raw, feature_version=(3, 5)).body
              if isinstance(row, ast.Assign) and any(isinstance(target, ast.Name)
                  and target.id == name for target in row.targets)]
    need(len(values) == 1, 'repair_single_assignment')
    return ast.literal_eval(values[0])


def definition_rows(raw):
    return {row.name: ast.dump(row, include_attributes=False)
            for row in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(row, (ast.FunctionDef, ast.ClassDef))}


def constants_inverse(origin, current, rows, names):
    need(type(rows) is list and len(rows) == len(names) and
         {row['name'] for row in rows} == names, 'repair_constant_scope')
    forward, inverse = origin, current
    for row in rows:
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(row.get('count', 1) == 1 and forward.count(before) == 1,
             'repair_forward_count')
        forward = forward.replace(before, after, 1)
    for row in reversed(rows):
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(inverse.count(after) == 1, 'repair_inverse_count')
        inverse = inverse.replace(after, before, 1)
    need(forward == current and inverse == origin, 'repair_full_byte_inverse')
    def shape(raw):
        return [ast.dump(row, include_attributes=False)
                for row in ast.parse(raw, feature_version=(3, 5)).body
                if not (isinstance(row, ast.Assign) and any(isinstance(target, ast.Name)
                    and target.id in names for target in row.targets))]
    need(shape(origin) == shape(current) and definition_rows(origin) == definition_rows(current),
         'repair_other_ast_unchanged')


def repair_source_boundary(inputs):
    """Pure checks of actual retained bytes; no old diagnostic/main/test call."""
    for pin in SOURCE_BASELINES + (WORKER, GUARDIAN, VALIDATOR, OUTER):
        checked_input(inputs, pin)
    delta = json.loads(inputs[WORKER_DELTA[0]])
    need(delta['origin'] == list(OLD_WORKER) and delta['candidate'] == list(WORKER),
         'repair_worker_fixed_origin')
    constants_inverse(inputs[OLD_WORKER[0]], inputs[WORKER[0]],
                      delta['replacements'], WORKER_ASSIGNMENTS)
    generation = json.loads(inputs[UI_GENERATION[0]])
    need(generation['session'] == SESSION and generation['bundle'] == BUNDLE and
         generation['stage_file_count'] == 19 and generation['asset_bytes'] == 4184758 and
         generation['control_suffix'] == CONTROL_SUFFIX, 'repair_ui_generation_identity')
    constants_inverse(inputs[OLD_GUARDIAN[0]], inputs[GUARDIAN[0]],
        generation['guardian_constant_replacements'], frozenset(('SESSION', 'CONTROL_NAME')))
    constants_inverse(inputs[OLD_VALIDATOR[0]], inputs[VALIDATOR[0]],
        generation['validator_constant_replacements'], frozenset(('SESSION', 'MANIFEST_PIN', 'PINS')))
    # The inherited main has independently read all 19 files from the pinned
    # actual validator. Authenticate these same bytes against the frozen
    # actual generation, not an unfrozen future output table.
    pins = generation['output_pins']
    need(len(pins) == 24 and len({row[0] for row in pins}) == 24, 'repair_output_inventory')
    required = {BUNDLE + '/' + row[0] for row in literal(inputs[VALIDATOR[0]], 'PINS')}
    required.update((BUNDLE + '/SOURCE.sha256', BUNDLE + '/stage-manifest.json',
                     GUARDIAN[0], VALIDATOR[0]))
    matched = set()
    for path, size, sha in pins:
        if path in required:
            checked_input(inputs, (path, size, sha))
            matched.add(path)
    need(matched == required and len(required) == 22, 'repair_required_output_pins')
    raw = inputs[WORKER[0]]
    need(literal(raw, 'SESSION') == SESSION and
         literal(raw, 'SENDER_ROOT') == '/tmp/p011-mta-formal-send-filecenter-deploy-v6' and
         literal(raw, 'SENDER_PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6' and
         literal(raw, 'SENDER_PIN') == OUTER[1:] and
         literal(raw, 'GUARDIAN_PIN') == GUARDIAN[1:] and
         literal(raw, 'ASSETS_PIN') == VALIDATOR[1:], 'repair_actual_worker_binding')
    return True


def derive_host(origin):
    """Complete frozen byte inverse; only finite HOST identity edits."""
    need((len(origin), digest(origin)) == MOTHER[1:], 'repair_mother_pin')
    raw, edits = origin, []
    def change(before, after, count=1):
        nonlocal raw
        need(type(before) is bytes and type(after) is bytes and before != after and
             raw.count(before) == count, 'repair_host_edit_count')
        raw = raw.replace(before, after)
        edits.append((before, after, count))
    def assignment(name, expression):
        tree = ast.parse(raw, feature_version=(3, 5))
        rows = [row for row in tree.body if isinstance(row, ast.Assign) and
                any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
        need(len(rows) == 1, 'repair_host_assignment')
        row = rows[0]
        lines = raw.splitlines(True)
        before = b''.join(lines[row.lineno - 1:row.end_lineno])
        change(before, (name + ' = ' + expression + '\n').encode('ascii'))
    assignment('SELF', repr(SELF))
    assignment('CMD', repr(CMD))
    assignment('SESSION', repr(SESSION))
    assignment('BUNDLE', repr(BUNDLE))
    assignment('RUNTIME', repr('candidate/formal-send-repair-package-v1/runtime/'))
    for name, value in (('WORKER', WORKER), ('GUARDIAN', GUARDIAN),
                        ('VALIDATOR', VALIDATOR), ('OUTER', OUTER),
                        ('SOURCE_BASELINES', SOURCE_BASELINES)):
        assignment(name, repr(value))
    tree = ast.parse(raw, feature_version=(3, 5))
    rows = [row for row in tree.body if isinstance(row, ast.FunctionDef) and
            row.name == 'diagnostic_source_boundary']
    need(len(rows) == 1, 'repair_boundary_single')
    row = rows[0]
    before = b''.join(raw.splitlines(True)[row.lineno - 1:row.end_lineno])
    change(before, b'def diagnostic_source_boundary(inputs):\n'
                   b'    return _REPAIR_SOURCE_BOUNDARY(inputs)\n')
    for before, after, count in (
        (b'Thin fixed sender UI-v7 closure diagnostic carrier entry.',
         b'Thin fixed sender repair UI-v1 closure diagnostic carrier entry.', 1),
        (b'requires v5 ordinary and existing 19UI assets.',
         b'requires v6 ordinary and existing repaired 19UI assets.', 1),
        (b'fixed_sender_ui_v7_', b'fixed_sender_repair_ui_v1_', 5),
        (b'fixed-sender-ui-v7-', b'fixed-sender-repair-ui-v1-', 1),
        (b'formal_send_ui_v7_fixed_carrier_entry', b'formal_send_repair_ui_v1_fixed_carrier_entry', 1),
        (b'fixed-formal-send-ui-v7-bootstrap', b'fixed-formal-send-repair-ui-v1-bootstrap', 1),
        (b'fixed-ui-v7-carrier', b'fixed-repair-ui-v1-carrier', 1),
        (b"('formal-send-filecenter-ui-v7-'+mode+", b"('formal-send-repair-ui-v1-'+mode+", 1),
        (b"+SESSION+'-formal-send-filecenter-ui-v7'", b"+SESSION+'-formal-send-picker-package-v1'", 1),
        (b'4184498', b'4184758', 2),
        (b'for path in (SELF,CMD,CONTRACT):',
         ('for path in (SELF,CMD,CONTRACT,' + repr(SOURCE_CMD) + '):').encode('ascii'), 1),
    ):
        change(before, after, count)
    inverse = raw
    for before, after, count in reversed(edits):
        need(inverse.count(after) == count, 'repair_host_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == origin and definition_rows(inverse) == definition_rows(origin),
         'repair_host_complete_inverse')
    old_tree, new_tree = ast.parse(origin, feature_version=(3, 5)), ast.parse(raw, feature_version=(3, 5))
    need(len(old_tree.body) == len(new_tree.body), 'repair_host_toplevel_shape')
    allowed_methods = frozenset(('diagnostic_source_boundary', 'ui_program', 'carrier_body',
                                 'carrier_command', 'main'))
    changed_assignments, changed_methods = set(), set()
    for old, new in zip(old_tree.body, new_tree.body):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            names = {target.id for target in old.targets if isinstance(target, ast.Name)}
            need(len(names) == 1 and names <= ASSIGNMENTS and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]), 'repair_host_assignment_scope')
            changed_assignments.update(names)
        elif isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef):
            need(old.name == new.name and old.name in allowed_methods, 'repair_host_method_scope')
            changed_methods.add(old.name)
        else:
            need(isinstance(old, ast.Expr) and isinstance(new, ast.Expr) and
                 old is old_tree.body[0] and new is new_tree.body[0], 'repair_host_other_toplevel')
    need(changed_assignments == ASSIGNMENTS and changed_methods == allowed_methods,
         'repair_host_edit_inventory')
    return raw


def prepare():
    """Pure PC preparation, no historical main, child, device or file write."""
    origin = (BASE / MOTHER[0]).read_bytes()
    raw = derive_host(origin)
    module = types.ModuleType('fixed_formal_send_repair_ui_v1_host_definitions')
    module.__file__ = str(BASE / MOTHER[0])
    exec(compile(raw, '<derived-formal-send-repair-ui-v1-host>', 'exec'), module.__dict__)
    module._REPAIR_SOURCE_BOUNDARY = repair_source_boundary
    return module, raw


def main():
    module, raw = prepare()
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())

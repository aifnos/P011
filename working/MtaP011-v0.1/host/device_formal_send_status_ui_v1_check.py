"""Protected status sender UI; default SOURCE, explicit original20s smoke.

Pure frozen preparation is reused, not historical entry mains or SOURCE suites.
The new actual package changes only UI identities, byte budget, private CONTROL
pull and the PC source boundary. Original17 fields, 600+60, 800/810, FileCenter,
FD closure, private raw and stock/finally restoration remain the derived main.
No asset/core Stage, build, old Qt test, phone transfer or RF is added.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_status_ui_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_STATUS_UI_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_STATUS_UI_V1_SOURCE_CHECK.cmd'
MOTHER = ('host/device_formal_send_preflight_ui_v1_check.py', 19048,
          'fcbf17242702204af54476798dffcc402f748b32a8f05a50933df695a3e9120e')
ASSET_BOUNDARY = ('host/device_formal_send_status_ui_assets_v1_check.py', 15921,
                  '7f1d9a506c980f64daaea8f6bb327301c5f4626d4592b45de8a1d59abc002ee8')
SESSION = '6d4fb1fd4af949cbb3515870'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
RUNTIME = 'candidate/formal-send-status-package-v3/runtime/'
CONTROL_SUFFIX = '-formal-send-status-package-v3'
WORKER = (RUNTIME + 'ui_session.py', 46416,
          'adc1561cd32d53257c5df123c4516c63e38198a7c08a04be0fc51249d2893c25')
GUARDIAN = (RUNTIME + 'ui_guardian.py', 43994,
            'c36560f4d481677ce61ec9cbed5910f4f202e381215a4cd5f2eb564965712998')
VALIDATOR = (RUNTIME + 'ui_assets.py', 12526,
             '430308223593d5d783c1ec1d29a90dcbe82606b33690fc263572b8353d9fd4e8')
OUTER = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_session.py', 24060,
         '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f')
ASSET_BYTES = 4185296
PREPARE_NAMES = frozenset(('need', 'digest', 'checked_input', 'tree', 'assignment', 'literal',
    'definitions', 'constants_inverse', 'control_is', 'preflight_source_boundary',
    'mother_prepare', 'derive_host', 'prepare'))
PACKAGE_NAMES = frozenset(('need', 'digest', 'tree', 'assignment', 'literal', 'span',
                          'runtime_inverse', 'package_boundary'))
HOST_ASSIGNMENTS = frozenset(('SELF', 'CMD', 'RUNTIME', 'SESSION', 'BUNDLE', 'WORKER',
                             'GUARDIAN', 'VALIDATOR', 'SOURCE_BASELINES'))
SOURCE_BASELINES = None
PACKAGE = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tree(raw):
    return ast.parse(raw.decode('utf-8'))


def assignment(raw, name):
    rows = [row for row in tree(raw).body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'status_ui_assignment_unique')
    return rows[0]


def span(raw, node):
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def pure_definitions(pin, names, namespace):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), digest(raw)) == pin[1:], 'status_ui_pure_input_pin')
    chosen = [row for row in tree(raw).body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
              isinstance(row, ast.FunctionDef) and row.name in names]
    need({row.name for row in chosen if isinstance(row, ast.FunctionDef)} == names,
         'status_ui_pure_inventory')
    module = types.ModuleType(namespace)
    module.__file__ = str(BASE / pin[0])
    exec(compile(ast.Module(body=chosen, type_ignores=[]), '<' + namespace + '>', 'exec'), module.__dict__)
    need('main' not in module.__dict__, 'status_ui_old_main_excluded')
    return module


def source_boundary(inputs, helper, validator):
    """Actual package closure only; no old preflight/repair verifier is called."""
    need(type(SOURCE_BASELINES) is tuple and PACKAGE is not None, 'status_ui_prepared_boundary')
    for pin in SOURCE_BASELINES + (WORKER, GUARDIAN, VALIDATOR, OUTER):
        need(pin[0] in inputs and (len(inputs[pin[0]]), digest(inputs[pin[0]])) == pin[1:],
             'status_ui_actual_input_pin')
    facts = PACKAGE.package_boundary(inputs, helper, validator)
    need(facts['actual_package_outputs'] == 27 and facts['runtime_constant_byte_ast_inverse'] is True and
         facts['source_manifest_bound'] is True and facts['new_control_suffix'] == CONTROL_SUFFIX,
         'status_ui_package_source_closure')
    # The 3/2/5 exact inverse preserves every Worker/Guardian business definition,
    # including 17-field result, restoration, FileCenter and original600+60.
    return True


def derive_host(origin):
    raw, edits = origin, []
    def change(before, after, count=1):
        nonlocal raw
        need(type(before) is bytes and type(after) is bytes and before != after and raw.count(before) == count,
             'status_ui_host_forward_count')
        raw = raw.replace(before, after)
        edits.append((before, after, count))
    for name, value in (('SELF', SELF), ('CMD', CMD), ('RUNTIME', RUNTIME), ('SESSION', SESSION),
                        ('BUNDLE', BUNDLE), ('WORKER', WORKER), ('GUARDIAN', GUARDIAN),
                        ('VALIDATOR', VALIDATOR), ('SOURCE_BASELINES', SOURCE_BASELINES)):
        change(span(raw, assignment(raw, name)), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after, count in (
        (b'Thin fixed sender preflight UI-v1 closure diagnostic carrier entry.',
         b'Thin fixed sender status UI-v1 closure diagnostic carrier entry.', 1),
        (b'requires v7 ordinary and the unchanged existing 19UI assets.',
         b'requires v7 ordinary and the exclusive status 19UI assets.', 1),
        (b'fixed_sender_preflight_ui_v1_', b'fixed_sender_status_ui_v1_', 5),
        (b'fixed-sender-preflight-ui-v1-', b'fixed-sender-status-ui-v1-', 1),
        (b'formal_send_preflight_ui_v1_fixed_carrier_entry', b'formal_send_status_ui_v1_fixed_carrier_entry', 1),
        (b'fixed-formal-send-preflight-ui-v1-bootstrap', b'fixed-formal-send-status-ui-v1-bootstrap', 1),
        (b'fixed-preflight-ui-v1-carrier', b'fixed-status-ui-v1-carrier', 1),
        (b"('formal-send-preflight-ui-v1-'+mode+", b"('formal-send-status-ui-v1-'+mode+", 1),
        (b"+SESSION+'-formal-send-preflight-native-v1'", ("+SESSION+" + repr(CONTROL_SUFFIX)).encode('ascii'), 1),
        (b'4184758', str(ASSET_BYTES).encode('ascii'), 2),
        (b"for path in (SELF,CMD,CONTRACT,'HOST_MTA_FORMAL_SEND_PREFLIGHT_UI_V1_SOURCE_CHECK.cmd'):",
         ('for path in (SELF,CMD,CONTRACT,' + repr(SOURCE_CMD) + '):').encode('ascii'), 1),
        (b"report['diagnostic_source_boundary_verified']=diagnostic_source_boundary(inputs)",
         b"report['diagnostic_source_boundary_verified']=_STATUS_UI_SOURCE_BOUNDARY(inputs,helper,validator)", 1),
    ):
        change(before, after, count)
    inverse = raw
    for before, after, count in reversed(edits):
        need(inverse.count(after) == count, 'status_ui_host_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == origin and ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'status_ui_host_complete_byte_ast_inverse')
    old_nodes, new_nodes = tree(origin).body, tree(raw).body
    need(len(old_nodes) == len(new_nodes), 'status_ui_host_shape')
    changed_assignments, changed_methods = set(), set()
    allowed_methods = {'ui_program', 'carrier_body', 'carrier_command', 'main'}
    for old, new in zip(old_nodes, new_nodes):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            need(len(old.targets) == len(new.targets) == 1 and isinstance(old.targets[0], ast.Name) and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]) and old.targets[0].id in HOST_ASSIGNMENTS,
                 'status_ui_host_assignment_scope')
            changed_assignments.add(old.targets[0].id)
        elif isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef):
            need(old.name == new.name and old.name in allowed_methods, 'status_ui_host_method_scope')
            changed_methods.add(old.name)
        else:
            need(isinstance(old, ast.Expr) and old is old_nodes[0] and new is new_nodes[0],
                 'status_ui_host_other_scope')
    need(changed_assignments == HOST_ASSIGNMENTS and changed_methods == allowed_methods,
         'status_ui_host_exact_edit_inventory')
    return raw


def prepare():
    global SOURCE_BASELINES, PACKAGE
    previous = pure_definitions(MOTHER, PREPARE_NAMES, 'fixed_status_ui_v1_previous_pure_definitions')
    old_module, origin = previous.prepare()
    need(old_module.SESSION == 'c69296a193ff43ce8e5b901d' and
         old_module.WORKER == previous.WORKER and old_module.GUARDIAN == previous.GUARDIAN and
         old_module.OUTER == OUTER and old_module.VALIDATOR == previous.VALIDATOR,
         'status_ui_original_final_bindings')
    PACKAGE = pure_definitions(ASSET_BOUNDARY, PACKAGE_NAMES, 'fixed_status_ui_v1_package_pure_definitions')
    need(PACKAGE.SESSION == SESSION and PACKAGE.BUNDLE == BUNDLE and PACKAGE.REMOTE == REMOTE and
         PACKAGE.WORKER == WORKER and PACKAGE.GUARDIAN == GUARDIAN and PACKAGE.VALIDATOR == VALIDATOR and
         PACKAGE.OUTER == OUTER and PACKAGE.ASSET_BYTES == ASSET_BYTES and PACKAGE.CONTROL_SUFFIX == CONTROL_SUFFIX,
         'status_ui_package_shared_bindings')
    # Keep the actual preparation lineage, not the historical58-input SOURCE
    # replay. The new boundary additionally seals actual27 package/origin bytes.
    SOURCE_BASELINES = (MOTHER, previous.MOTHER, previous.ORIGINAL, ASSET_BOUNDARY)
    need(len({row[0] for row in SOURCE_BASELINES}) == len(SOURCE_BASELINES), 'status_ui_unique_source_baselines')
    raw = derive_host(origin)
    module = types.ModuleType('fixed_status_ui_v1_final_host_definitions')
    module.__file__ = str(BASE / SELF)
    exec(compile(raw, '<fixed-status-ui-v1-derived-host>', 'exec'), module.__dict__)
    module._STATUS_UI_SOURCE_BOUNDARY = source_boundary
    need(module.SESSION == SESSION and module.BUNDLE == BUNDLE and module.REMOTE == REMOTE and
         module.RUNTIME == RUNTIME and module.WORKER == WORKER and module.GUARDIAN == GUARDIAN and
         module.VALIDATOR == VALIDATOR and module.OUTER == OUTER and module.SOURCE_BASELINES == SOURCE_BASELINES,
         'status_ui_final_bindings')
    return module, raw


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'fixed_source_or_ui_smoke_only')
    module, raw = prepare()
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())

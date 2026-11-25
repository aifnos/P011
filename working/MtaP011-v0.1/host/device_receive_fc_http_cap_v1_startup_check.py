"""Independent FC HTTP-cap75 startup with the unchanged passive V2 projection.

Default SOURCE; explicit --check-device stages the absent independent root.
The fixed Scope wrapper's pure derivation, original IO, Startup10, 60+60,
alarm240/HOST250 and original closed gates remain. Only graph/source bindings
and truthful FC2 provenance labels change. No old main, phone, FC or RF runs.
"""
import ast
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_fc_http_cap_v1_startup_check.py'
MOTHER = ('host/device_receive_scope_dispatch_v1_startup_check.py', 8334,
          'f783bda303a2975dc09a0beb67daac3fd9879230517418ea107f1ddce43d915e')
CARRIER = ('host/device_receive_publication_progress_v1_startup_check.py', 18494,
           'f47479a85dd54dd1e192509dfe125d1da336edae20a4cd607fa24e5cca02dadf')
PROJECTION = ('host/receive_startup_retained_v2_projection.py', 21095,
              'ba0a54148c700ac28c5ee090490696dac0aec419ba440ad7be0642938b7a9912')
CMDS = ('HOST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP.cmd')


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2 * 1024 * 1024:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(2 * 1024 * 1024 + 1)
        if metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), hashlib.sha256(raw).hexdigest()) != pin: raise ValueError('fixed_pin')
    return raw


def function_source(raw, name):
    text = raw.decode('ascii')
    rows = [row for row in ast.parse(text).body if isinstance(row, ast.FunctionDef) and row.name == name]
    if len(rows) != 1 or rows[0].decorator_list:
        raise ValueError('single_plain_helper')
    return ast.get_source_segment(text, rows[0])


def unchanged_helpers(mother, own):
    for name in ('metadata', 'read_fixed', 'attach_projection'):
        if function_source(mother, name) != function_source(own, name):
            raise ValueError('scope_wrapper_helper_changed')


def derive(raw, carrier):
    """Pinned Scope pure recipe, then finite FC-cap bindings with full inverse."""
    if (len(raw), hashlib.sha256(raw).hexdigest()) != MOTHER[1:] or (
            len(carrier), hashlib.sha256(carrier).hexdigest()) != CARRIER[1:]:
        raise ValueError('fixed_mother_carrier_pin')
    tree = ast.parse(raw, feature_version=(3, 5))
    bindings = {row.targets[0].id: ast.literal_eval(row.value) for row in tree.body
                if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id in ('MOTHER', 'PROJECTION')}
    if bindings != {'MOTHER': CARRIER, 'PROJECTION': PROJECTION}:
        raise ValueError('scope_original_bindings')
    nodes = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == 'derive']
    if len(nodes) != 1 or nodes[0].decorator_list:
        raise ValueError('scope_pure_recipe')
    recipe = types.ModuleType('fixed_scope_startup_recipe_only')
    recipe.__dict__.update(MOTHER=CARRIER, ast=ast, hashlib=hashlib)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BASE / MOTHER[0]), 'exec'), recipe.__dict__)
    if 'main' in recipe.__dict__ or 'prepare' in recipe.__dict__:
        raise ValueError('old_main_prepare_forbidden')
    original = recipe.derive(carrier)
    replacements = (
        ("SELF = 'host/device_receive_scope_dispatch_v1_startup_check.py'",
         "SELF = 'host/device_receive_fc_http_cap_v1_startup_check.py'", 1),
        ("CMDS = ('HOST_MTA_RECEIVE_SCOPE_DISPATCH_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_SCOPE_DISPATCH_V1_STARTUP.cmd')",
         "CMDS = ('HOST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP_CHECK.cmd', 'TEST_MTA_RECEIVE_FC_HTTP_CAP_V1_STARTUP.cmd')", 1),
        ("DEFINITIONS = ('host/formal_receive_scope_dispatch_v1_definitions.py', 178958, 'bcf738217c0821a14d732872cb1520e0e090f507272e588f8659d40b07bf28e3')",
         "DEFINITIONS = ('host/formal_receive_fc_http_cap_v1_definitions.py', 169842, 'c43f342a7c7ccafe5e2780de7f4068bdfe84195579b5f1c6e970d78ad19abfc2')", 1),
        ("ROOT_NAME = 'p011-mta-rx-scope-v0001'", "ROOT_NAME = 'p011-mta-rx-fccap-v0001'", 1),
        ("b'Actual flat260 provenance, 6 mechanical closures and one Scope delta; prior Owner dispatch retained.\\n'",
         "b'Actual flat274 provenance, 6 mechanical closures and two FC HTTP business sources; inherited Owner/Scope deltas retained.\\n'", 1),
        ("b'Actual75/4193464 retains original4MiB cap (840 spare); FC9/113690 retains separate131072 cap.\\n'",
         "b'Actual75/4193464 retains original4MiB cap (840 spare); FC9/113832 retains separate131072 cap.\\n'", 1),
        ("'receive-scope-dispatch-v1-startup-'", "'receive-fc-http-cap-v1-startup-'", 1),
        ("label = 'receive-scope-dispatch-v1-startup'", "label = 'receive-fc-http-cap-v1-startup'", 1),
        ('p011-receive-scope-dispatch-v1-startup', 'p011-receive-fc-http-cap-v1-startup', 2),
        ('        fixed(MOTHER)\n        projection_raw = fixed(PROJECTION)',
         '        fixed(MOTHER)\n        fixed(CARRIER)\n        projection_raw = fixed(PROJECTION)', 1),
        ('len(definitions.ORIGIN_SOURCE_PINS) == 260', 'len(definitions.ORIGIN_SOURCE_PINS) == 274', 1),
        ('sum(row[2] for row in fc_rows) == 113690 <= 131072',
         'sum(row[2] for row in fc_rows) == 113832 <= 131072', 1),
        ("        need(definitions.verify_inputs(inputs) == 6, 'new_scope_dispatch_mechanical_closures')",
         "        need(definitions.verify_inputs(inputs) == 6 and\n"
         "             definitions.BUSINESS_CLOSURE_COUNT == 2 and\n"
         "             tuple(row['name'] for row in definitions.FC_HTTP_EXPECTED) ==\n"
         "             ('mta_toolbox_minhttp', 'mta_filecenter_companion'),\n"
         "             'new_fc_http_cap_mechanical_and_source_closures')", 1),
        ('filecenter_sources=9, filecenter_bytes=113690, flat_origin_pins=260,',
         'filecenter_sources=9, filecenter_bytes=113832, flat_origin_pins=274,', 1),
        ('mechanical_closures=6, business_closures=1, original_io_definition_inverse_verified=True,',
         'mechanical_closures=6, filecenter_http_business_sources=2, original_io_definition_inverse_verified=True,', 1))
    current, changes = original, []
    for before, after, count in replacements:
        before, after = before.encode('ascii'), after.encode('ascii')
        if current.count(before) != count or current.count(after):
            raise ValueError('finite_fc_forward_anchor')
        current = current.replace(before, after)
        changes.append((before, after, count))
    inverse = current
    for before, after, count in reversed(changes):
        if inverse.count(after) != count:
            raise ValueError('finite_fc_reverse_anchor')
        inverse = inverse.replace(after, before)
    if inverse != original or ast.dump(ast.parse(inverse), include_attributes=True) != ast.dump(
            ast.parse(original), include_attributes=True):
        raise ValueError('complete_fc_host_byte_position_ast_inverse')
    old, selected = ast.parse(original, feature_version=(3, 5)), ast.parse(current, feature_version=(3, 5))
    if any(isinstance(row, ast.If) for row in selected.body):
        raise ValueError('old_guard_forbidden')
    original_defs = {row.name: ast.get_source_segment(original.decode('ascii'), row)
                     for row in old.body if isinstance(row, ast.FunctionDef)}
    current_defs = {row.name: ast.get_source_segment(current.decode('ascii'), row)
                    for row in selected.body if isinstance(row, ast.FunctionDef)}
    if len(changes) != 15 or set(original_defs) != set(current_defs) or any(
            original_defs[name] != current_defs[name] for name in original_defs if name != 'main'):
        raise ValueError('unchanged_original_host_helpers')
    return current


def attach_projection(pure, raw):
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PROJECTION[1:]:
        raise ValueError('fixed_projection_pin')
    projection = types.ModuleType('fixed_startup_scope_dispatch_v1_projection')
    exec(compile(raw, str(BASE / PROJECTION[0]), 'exec'), projection.__dict__)
    original_make = pure.make_source

    def make_source(definitions, helpers, inputs, payload):
        original, selected = original_make(definitions, helpers, inputs, payload)
        return original, projection.inject(selected, raw)

    pure.make_source = make_source
    return pure


def prepare():
    raw = read_fixed(MOTHER[0], MOTHER[1:])
    carrier = read_fixed(CARRIER[0], CARRIER[1:])
    unchanged_helpers(raw, read_fixed(SELF))
    derived = derive(raw, carrier)
    value = types.ModuleType('fixed_startup_fc_http_cap_v1_host')
    value.__file__ = str(BASE / SELF)
    exec(compile(derived, str(BASE / SELF), 'exec'), value.__dict__)
    value.__dict__.update(MOTHER=MOTHER, CARRIER=CARRIER, PROJECTION=PROJECTION,
                          HOST_RAW=derived, attach_projection=attach_projection)
    return value


if __name__ == '__main__':
    raise SystemExit(prepare().main())

"""Narrow ordinary-v7 files-only carrier bridge; default PC SOURCE.

Mother is the actually measured repair ordinary-v1 stage carrier. Its limits,
FD/stock/finally/readback/PASS remain byte-derived. Only v7 inventory pins, fresh
observer prerequisite and result identities differ. No Parent/Owner/UI/RF start.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_coldstart_ordinary_v1_check.py'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_COLDSTART_ORDINARY_V1_SOURCE_CHECK.cmd'
STAGE_CMD = 'TEST_MTA_FORMAL_SEND_COLDSTART_ORDINARY_V1.cmd'
MOTHER = ('host/device_formal_send_repair_ordinary_v1_check.py', 20427,
    '1b29868ff72d40a5d5f9b5a021c29a981f4f096312ed3b061281ac8806249dcf')
OLD_SOURCE_CMD = ('HOST_MTA_FORMAL_SEND_REPAIR_ORDINARY_V1.cmd', 237,
    '222de7982020df8a2ffae0a7e57cb273f9d904927f96ad1ed4f1207f00e2c1f8')
OLD_STAGE_CMD = ('TEST_MTA_FORMAL_SEND_REPAIR_ORDINARY_V1.cmd', 252,
    '87bef1cf0af7158f0f2f7fbfbb3b54c2fc9320d8e032a7199507aaffa6f2fe3e')
BRIDGE_INPUTS = (MOTHER, OLD_SOURCE_CMD, OLD_STAGE_CMD)
OLD_STAGE = ('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_stage.py', 37417,
    '49e9f972d093d7f7749f5dd4a38558a73cc0e36ea894e558455238aeb8f840da')
STAGE = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_stage.py', 37421,
    'eafc45ced6c0b4b0598b9bfb6fc86adefed68a5b94137303ca91d2256e7adc14')


def need(value):
    if value is not True:
        raise ValueError('stage_contract')


def fixed(inputs, row):
    raw = inputs[row[0]] if row[0] in inputs else (BASE/row[0]).read_bytes()
    inputs[row[0]] = raw
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:])
    return raw


def derive(raw):
    """Only fixed literals, offset-bound complete byte and positioned AST inverse."""
    changes = (
        ("SELF = 'host/device_formal_send_repair_ordinary_v1_check.py'", "SELF = " + repr(SELF), 1),
        ("CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_ORDINARY_V1.cmd'", "CMD = " + repr(SOURCE_CMD), 1),
        ("TEST_CMD = 'TEST_MTA_FORMAL_SEND_REPAIR_ORDINARY_V1.cmd'", "TEST_CMD = " + repr(STAGE_CMD), 1),
        ("CATALOG = ('candidate/formal-send-filecenter-deploy-v6/assets/ordinary-source-manifest.json',\n"
         "    20796, 'd2300225159796bee6f6d2664ba86cdd1d13f8033899596effeb0431c7633052')",
         "CATALOG = ('candidate/formal-send-filecenter-deploy-v7/assets/ordinary-source-manifest.json',\n"
         "    20810, '9be61347f4a44d031cf7c07095692b4cd0de21f79410a9f45c5ad6b2073f9d52')", 1),
        ("ASSETS = ('candidate/formal-send-filecenter-deploy-v4/assets/asset-sources.json',\n"
         "    24267, 'be76740f8d7283e2db5806790c87997dee24a0911beb1306d7c9833086745ec0')",
         "ASSETS = ('candidate/formal-send-filecenter-deploy-v7/assets/asset-sources.json',\n"
         "    24365, '76368b95981aa206eeb2a7eaa929fb1263a3ffd94d78b8757422626baab3db73')", 1),
        ("OBSERVER = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json',\n"
         "    15861, '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')",
         "OBSERVER = ('candidate/go-observer-native-v2/assets/observer-source-catalog.json',\n"
         "    15982, '72b817785e3986f29792d5ef5a0f0557ef5324e877b1a0668def79c3a7013560')", 1),
        ("STAGE = ('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_stage.py',\n"
         "    37417, '49e9f972d093d7f7749f5dd4a38558a73cc0e36ea894e558455238aeb8f840da')",
         "STAGE = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_stage.py',\n"
         "    37421, 'eafc45ced6c0b4b0598b9bfb6fc86adefed68a5b94137303ca91d2256e7adc14')", 1),
        ("'/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6'",
         "'/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v7'", 1),
        ("'/var/volatile/tmp/p011-mta-go-observer-libc-v1'",
         "'/var/volatile/tmp/p011-mta-go-observer-native-v2'", 1),
        ('1353776', '1368142', 6),
        ('1442508', '1548495', 2),
        ('repair-ordinary-v1', 'coldstart-ordinary-v1', 3),
        ('ordinary v6', 'ordinary v7', 2),
    )
    original, ledger = raw, []
    for before, after, count in changes:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count)
        positions = [index for index in range(len(raw)) if raw.startswith(before, index)]
        for offset in reversed(positions):
            need(raw[offset:offset+len(before)] == before)
            raw = raw[:offset] + after + raw[offset+len(before):]
            ledger.append((offset, before, after))
    reverse = raw
    for offset, before, after in reversed(ledger):
        need(reverse[offset:offset+len(after)] == after)
        reverse = reverse[:offset] + before + reverse[offset+len(after):]
    need(reverse == original)
    # Columns may change with longer literals. Definition names and lines cannot.
    def positioned_without_columns(value):
        tree = ast.parse(value.decode('ascii'))
        for node in ast.walk(tree):
            for name in ('col_offset', 'end_col_offset'):
                if hasattr(node, name):
                    setattr(node, name, 0)
        class Literals(ast.NodeTransformer):
            def visit_Constant(self, node):
                return ast.copy_location(ast.Constant(value=None), node)
        return ast.dump(Literals().visit(tree), include_attributes=True)
    need(positioned_without_columns(raw) == positioned_without_columns(original))
    need(ast.dump(ast.parse(reverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))
    # Every unmodified PC definition stays complete bytes, no old main executed.
    old_tree, new_tree = ast.parse(original.decode('ascii')), ast.parse(raw.decode('ascii'))
    old_lines, new_lines = original.splitlines(keepends=True), raw.splitlines(keepends=True)
    old_defs = [v for v in old_tree.body if isinstance(v, (ast.ClassDef, ast.FunctionDef))]
    new_defs = [v for v in new_tree.body if isinstance(v, (ast.ClassDef, ast.FunctionDef))]
    need([v.name for v in old_defs] == [v.name for v in new_defs])
    for old, new in zip(old_defs, new_defs):
        need((old.lineno, old.end_lineno) == (new.lineno, new.end_lineno))
        if old.name not in ('payloads', 'main'):
            need(b''.join(old_lines[old.lineno-1:old.end_lineno]) ==
                 b''.join(new_lines[new.lineno-1:new.end_lineno]))
    return raw, dict(literal_edits=len(ledger), complete_byte_inverse=True,
        complete_positioned_ast_inverse=True, unchanged_pc_definitions_byte_exact=True,
        payloads_and_main_only_literal_changes=True, old_main_executed=False,
        derived_pc_bytes=len(raw), derived_pc_sha256=hashlib.sha256(raw).hexdigest())


def target_methods(inputs):
    old, new = fixed(inputs, OLD_STAGE), fixed(inputs, STAGE)
    old_tree, new_tree = ast.parse(old.decode('ascii')), ast.parse(new.decode('ascii'))
    old_defs = [v for v in old_tree.body if isinstance(v, (ast.FunctionDef, ast.ClassDef))]
    new_defs = [v for v in new_tree.body if isinstance(v, (ast.FunctionDef, ast.ClassDef))]
    need([v.name for v in old_defs] == [v.name for v in new_defs])
    old_lines, new_lines = old.splitlines(keepends=True), new.splitlines(keepends=True)
    for a, b in zip(old_defs, new_defs):
        need((a.lineno, a.end_lineno) == (b.lineno, b.end_lineno) and
             ast.dump(a, include_attributes=True) == ast.dump(b, include_attributes=True) and
             b''.join(old_lines[a.lineno-1:a.end_lineno]) ==
             b''.join(new_lines[b.lineno-1:b.end_lineno]))
    return dict(stage_methods_byte_and_positions_equal=True,
        compared_to_measured_v6_stage=list(OLD_STAGE), stage_actual_pin=list(STAGE),
        stage_classes_or_functions=len(old_defs), stage_methods_invoked=False)


def load(inputs=None):
    inputs = {} if inputs is None else inputs
    for row in BRIDGE_INPUTS:
        fixed(inputs, row)
    raw, proof = derive(inputs[MOTHER[0]])
    value = types.ModuleType('formal_send_coldstart_ordinary_v1_pc_private')
    value.__file__ = str(BASE/SELF)
    # Only derived fixed PC definitions. Both old/current __main__ guards false.
    exec(compile(raw, value.__file__+':literal-bridge', 'exec'), value.__dict__)
    inherited = value.payloads
    def payloads(snapshot):
        # Preserve original bridge bytes already read before invoking new payloads.
        for row in BRIDGE_INPUTS:
            snapshot[row[0]] = inputs[row[0]]
            fixed(snapshot, row)
        methods = target_methods(snapshot)
        result = inherited(snapshot)
        value._coldstart_source_facts = dict(pc_literal_bridge=proof, stage_methods=methods)
        return result
    value.payloads = payloads
    need(value.SELF == SELF and value.CMD == SOURCE_CMD and value.TEST_CMD == STAGE_CMD and
         value.STAGE == STAGE and value.ROOT == '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v7')
    return value


def main():
    return load().main()


if __name__ == '__main__':
    raise SystemExit(main())

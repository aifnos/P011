"""Narrow prerequisite SOURCE-expression correction; v1 remains unchanged.

Default PC SOURCE plans only; explicit --stage sender OR --stage observer
keeps the original one-profile carrier, full inventory/FD/stock/close gates.
The sole functional correction checks the frozen Stage RAW_LIMIT expression
as exact source bytes, never generic eval. No Stage/limits/runtime change.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_repair_prerequisite_assets_v2_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_PREREQUISITE_ASSETS_V2_SOURCE_CHECK.cmd'
TEST_CMDS = ('TEST_MTA_FORMAL_SEND_REPAIR_SENDER_ASSETS_V2.cmd',
             'TEST_MTA_FORMAL_SEND_REPAIR_OBSERVER_ASSETS_V2.cmd')
MOTHER = ('host/device_formal_send_repair_prerequisite_assets_v1_check.py',
          20669, 'ffd8413f92767eb1f3d78ef6752ab3a66f1e39de7f2f41799edfa63cecb0f268')
ASSIGNMENTS = frozenset(('SELF', 'CMD', 'TEST_CMDS'))
METHODS = frozenset(('payloads', 'main'))
DEFINITIONS = frozenset(('sha', 'need', 'write_new', 'fixed', 'literal',
                         'module', 'selected_generator', 'payloads', 'main'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tree(raw):
    return ast.parse(raw.decode('ascii'), feature_version=(3, 5))


def definition_bytes(raw):
    rows = {}
    lines = raw.splitlines(True)
    for node in tree(raw).body:
        if isinstance(node, ast.FunctionDef):
            need(node.name not in rows, 'prerequisite_duplicate_definition')
            rows[node.name] = (node.lineno, node.end_lineno,
                              b''.join(lines[node.lineno - 1:node.end_lineno]))
    need(set(rows) == DEFINITIONS, 'prerequisite_definition_inventory')
    return rows


def derive_host(origin):
    """Six fixed deltas with complete byte/AST inverse; no old entry call."""
    need(type(origin) is bytes and (len(origin), digest(origin)) == MOTHER[1:],
         'prerequisite_mother_pin')
    edits = (
        (b"SELF = 'host/device_formal_send_repair_prerequisite_assets_v1_check.py'\n",
         ("SELF = " + repr(SELF) + "\n").encode('ascii'), 1),
        (b"CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_PREREQUISITE_ASSETS_V1_SOURCE_CHECK.cmd'\n",
         ("CMD = " + repr(CMD) + "\n").encode('ascii'), 1),
        (b"TEST_CMDS = ('TEST_MTA_FORMAL_SEND_REPAIR_SENDER_ASSETS_V1.cmd',\n"
         b"             'TEST_MTA_FORMAL_SEND_REPAIR_OBSERVER_ASSETS_V1.cmd')\n",
         ("TEST_CMDS = (" + repr(TEST_CMDS[0]) + ",\n             " +
          repr(TEST_CMDS[1]) + ")\n").encode('ascii'), 1),
        (b'    for row in (ASSETS, OBSERVER, STAGE, GENERATOR, ENVELOPE,\n',
         b'    for row in (MOTHER, ASSETS, OBSERVER, STAGE, GENERATOR, ENVELOPE,\n', 1),
        (b"literal(stage, 'RAW_LIMIT') == 4194304",
         b"stage.count(b'RAW_LIMIT = 4 * 1024 * 1024\\n') == 1", 1),
        (b'formal-send-repair-prerequisite-assets-v1-',
         b'formal-send-repair-prerequisite-assets-v2-', 2),
    )
    raw = origin
    for before, after, count in edits:
        need(before != after and raw.count(before) == count,
             'prerequisite_forward_count')
        raw = raw.replace(before, after)
    inverse = raw
    for before, after, count in reversed(edits):
        need(inverse.count(after) == count, 'prerequisite_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == origin and
         ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True),
         'prerequisite_complete_byte_ast_inverse')
    old, new = tree(origin), tree(raw)
    need(len(old.body) == len(new.body), 'prerequisite_toplevel_count')
    assignments, methods = set(), set()
    for before, after in zip(old.body, new.body):
        if ast.dump(before, include_attributes=True) == ast.dump(after, include_attributes=True):
            continue
        # Column offsets can change in the two permitted functions. All
        # unchanged definitions are separately exact byte/line checked below.
        if isinstance(before, ast.Assign) and isinstance(after, ast.Assign):
            names = {target.id for target in before.targets if isinstance(target, ast.Name)}
            need(len(names) == 1 and names <= ASSIGNMENTS and
                 ast.dump(before.targets[0], include_attributes=True) ==
                 ast.dump(after.targets[0], include_attributes=True),
                 'prerequisite_assignment_scope')
            assignments.update(names)
        elif isinstance(before, ast.FunctionDef) and isinstance(after, ast.FunctionDef):
            need(before.name == after.name and before.name in METHODS and
                 before.lineno == after.lineno and before.end_lineno == after.end_lineno,
                 'prerequisite_method_scope')
            methods.add(before.name)
        else:
            need(False, 'prerequisite_other_ast_changed')
    need(assignments == ASSIGNMENTS and methods == METHODS,
         'prerequisite_exact_edit_inventory')
    before_defs, after_defs = definition_bytes(origin), definition_bytes(raw)
    need(all(before_defs[name] == after_defs[name] for name in DEFINITIONS - METHODS),
         'prerequisite_seven_definitions_exact')
    return raw


def prepare():
    """Pure in-memory fixed derivation; no device, result write or old main."""
    origin = (BASE / MOTHER[0]).read_bytes()
    raw = derive_host(origin)
    value = types.ModuleType('fixed_formal_send_repair_prerequisite_assets_v2')
    value.__file__ = str(BASE / SELF)
    value.MOTHER = MOTHER
    # The retained historical __main__ guard is false in this module. Only
    # the independently derived v2 main is callable from this new entry.
    exec(compile(raw, '<derived-prerequisite-assets-v2-host>', 'exec'), value.__dict__)
    return value, raw


def main():
    value, raw = prepare()
    return value.main()


if __name__ == '__main__':
    raise SystemExit(main())

"""Thin PC-only LF bridge over frozen diagnostic v1; import itself is inert.

Only 19 source-string newline escapes change CRLF -> LF in memory. The
frozen source, failed attempt and every actual mother/41-role source stay
untouched. The inherited helper newline conversion becomes LF -> LF (noop).
Only derived PC definitions are loaded, never the frozen __main__ guard,
target definitions, tests or device code. Prefix/root/seven output paths and
inherited facts/generation metadata are unchanged; bridge provenance is this
separate fixed source contract, not a new device or closure claim.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
MOTHER = ('host/go_observer_diag_v1_source.py', 24747,
          'b589880919577a37b7992e56f935a2f8af9967c57eb275a715704e786ce08496')
BRIDGE_INPUTS = (MOTHER,)
OLD_ESCAPE, NEW_ESCAPE = b'\\r\\n', b'\\n'
ESCAPE_COUNT = 19
LINE_COUNTS = {32: 1, 33: 1, 34: 2, 246: 1, 274: 1, 275: 1, 277: 1,
               278: 1, 302: 1, 303: 1, 307: 2, 308: 2, 317: 2, 318: 2}


def need(condition, code):
    if condition is not True:
        raise ValueError(code)


def _mother_raw(bridge_inputs=None):
    if bridge_inputs is None:
        raw = (BASE / MOTHER[0]).read_bytes()
    else:
        need(type(bridge_inputs) is dict and set(bridge_inputs) == {MOTHER[0]}, 'bridge_exact_inputs')
        raw = bridge_inputs[MOTHER[0]]
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == MOTHER[1:],
         'bridge_frozen_mother_pin')
    return raw


def _derive(raw):
    need(raw.count(OLD_ESCAPE) == ESCAPE_COUNT, 'bridge_literal_escape_count')
    offsets, line_counts, cursor = [], {}, 0
    while True:
        position = raw.find(OLD_ESCAPE, cursor)
        if position < 0:
            break
        offsets.append(position)
        line = raw.count(b'\n', 0, position) + 1
        line_counts[line] = line_counts.get(line, 0) + 1
        cursor = position + len(OLD_ESCAPE)
    need(line_counts == LINE_COUNTS, 'bridge_fixed_line_whitelist')
    current = raw.replace(OLD_ESCAPE, NEW_ESCAPE)
    inverse, start = [], 0
    for ordinal, original_position in enumerate(offsets):
        position = original_position - ordinal * (len(OLD_ESCAPE) - len(NEW_ESCAPE))
        need(current[position:position + len(NEW_ESCAPE)] == NEW_ESCAPE, 'bridge_inverse_offset')
        inverse.extend((current[start:position], OLD_ESCAPE))
        start = position + len(NEW_ESCAPE)
    inverse.append(current[start:])
    need(b''.join(inverse) == raw, 'bridge_complete_byte_inverse')
    old_tree, tree = ast.parse(raw.decode('ascii')), ast.parse(current.decode('ascii'))
    constant_counts = {}
    for node in ast.walk(old_tree):
        if isinstance(node, ast.Constant) and type(node.value) in (bytes, str):
            before = b'\r\n' if type(node.value) is bytes else '\r\n'
            after = b'\n' if type(node.value) is bytes else '\n'
            count = node.value.count(before)
            if count:
                constant_counts[node.lineno] = constant_counts.get(node.lineno, 0) + count
                node.value = node.value.replace(before, after)
    need(constant_counts == LINE_COUNTS and
         ast.dump(old_tree, include_attributes=False) == ast.dump(tree, include_attributes=False),
         'bridge_only_newline_constant_ast_delta')
    noop = b"    helper = helper.replace(b'\\n', b'\\n')\n"
    need(current.count(noop) == 1 and raw.count(b"    helper = helper.replace(b'\\n', b'\\r\\n')\n") == 1,
         'bridge_helper_newline_noop')
    guards = [node for node in tree.body if isinstance(node, ast.If)]
    need(len(guards) == 1 and tree.body[-1] is guards[0] and
         ast.dump(guards[0].test, include_attributes=False) ==
         ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False) and
         ast.dump(guards[0].body[0], include_attributes=False) ==
         ast.dump(ast.parse('raise SystemExit(main())').body[0], include_attributes=False) and
         len(guards[0].body) == 1 and not guards[0].orelse, 'bridge_exact_unused_main_guard')
    tree.body.pop()
    need(all(isinstance(node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
             for node in tree.body), 'bridge_pc_definition_selector')
    return tree


def _module(bridge_inputs=None):
    tree = _derive(_mother_raw(bridge_inputs))
    module = types.ModuleType('_p011_observer_diag_v2_pc_definitions')
    module.__file__ = str(BASE / MOTHER[0])
    # PC stdlib/constants/functions only; HELPER_TEMPLATE remains inert text.
    exec(compile(tree, '<private-observer-diag-v2-pc-definitions>', 'exec'), module.__dict__)
    return module


def bridge_source_inputs():
    """Additional fixed parent source row; not part of the inherited 43 roles."""
    return BRIDGE_INPUTS


def source_inputs():
    return _module().source_inputs()


def load_inputs():
    return _module().load_inputs()


def assemble(inputs=None, bridge_inputs=None):
    """Same seven files/facts as v1, derived in memory with LF anchors only."""
    return _module(bridge_inputs).assemble(inputs)


def main(argv=None):
    # Explicitly call derived main only: default SOURCE/no writes; --write EXCL.
    return _module().main(argv)


if __name__ == '__main__':
    raise SystemExit(main())

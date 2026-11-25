"""PC-only quoted-alias bridge; retain both failed derivation sources.

Reuse the frozen LF bridge. Only one catalogue edit changes from an alias
substring to its exact quoted JSON value. No target bytes, gate, test or device
operation execute here. Default SOURCE and explicit fresh --write are inherited.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
V1 = ('host/go_observer_diag_v1_source.py', 24747,
      'b589880919577a37b7992e56f935a2f8af9967c57eb275a715704e786ce08496')
V2 = ('host/go_observer_diag_v2_source.py', 5348,
      '1ab4929bc725549edfb87d334150e74145110917051324cb72086052ef6f5ee5')
BRIDGE_INPUTS = (V1, V2)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def _read(row, inputs):
    raw = (BASE / row[0]).read_bytes() if inputs is None else inputs[row[0]]
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:], 'bridge_input_pin')
    return raw


def _quoted(name):
    value = ast.BinOp(left=ast.BinOp(left=ast.Constant(value='"'), op=ast.Add(),
        right=ast.Name(id=name, ctx=ast.Load())), op=ast.Add(), right=ast.Constant(value='"'))
    return ast.Call(func=ast.Attribute(value=value, attr='encode', ctx=ast.Load()),
        args=[ast.Constant(value='ascii')], keywords=[])


def _module(bridge_inputs=None):
    need(bridge_inputs is None or type(bridge_inputs) is dict and
        set(bridge_inputs) == {row[0] for row in BRIDGE_INPUTS}, 'bridge_exact_inputs')
    v1, v2 = _read(V1, bridge_inputs), _read(V2, bridge_inputs)
    bridge = types.ModuleType('_observer_diag_v3_lf_pc_bridge')
    bridge.__file__ = str(BASE / V2[0])
    # V2 import is inert. Its main guard cannot execute in this private module.
    exec(compile(v2, bridge.__file__, 'exec'), bridge.__dict__)
    tree = bridge._derive(v1)
    before = ast.dump(tree, include_attributes=True)
    assemble_defs = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'assemble']
    need(len(assemble_defs) == 1, 'one_pc_assemble')
    calls = [node for node in ast.walk(assemble_defs[0]) if isinstance(node, ast.Call) and
        isinstance(node.func, ast.Name) and node.func.id == '_edit' and node.lineno == 356]
    need(len(calls) == 1 and len(calls[0].args) == 4, 'one_catalogue_alias_edit')
    call = calls[0]
    originals = tuple(call.args[1:3])
    for original, name in zip(originals, ('OLD_ALIAS', 'ALIAS')):
        expected = ast.parse(name + ".encode('ascii')", mode='eval').body
        need(ast.dump(original, include_attributes=False) == ast.dump(expected, include_attributes=False),
            'fixed_alias_argument')
    replacements = tuple(ast.copy_location(_quoted(name), original)
        for name, original in zip(('OLD_ALIAS', 'ALIAS'), originals))
    call.args[1:3] = replacements
    ast.fix_missing_locations(tree)
    # Restore the original argument objects and require the entire AST unchanged.
    call.args[1:3] = originals
    need(ast.dump(tree, include_attributes=True) == before, 'complete_alias_ast_inverse')
    call.args[1:3] = replacements
    module = types.ModuleType('_observer_diag_v3_pc_definitions')
    module.__file__ = str(BASE / V1[0])
    exec(compile(tree, '<private-observer-diag-v3-pc-definitions>', 'exec'), module.__dict__)
    return module


def bridge_source_inputs():
    return BRIDGE_INPUTS


def source_inputs():
    return _module().source_inputs()


def load_inputs():
    return _module().load_inputs()


def assemble(inputs=None, bridge_inputs=None):
    return _module(bridge_inputs).assemble(inputs)


def main(argv=None):
    return _module().main(argv)


if __name__ == '__main__':
    raise SystemExit(main())

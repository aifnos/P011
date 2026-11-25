"""Independent narrow PC bridge for the frozen observer-native-v2 HOST.

Default SOURCE only. The single counter-anchor fix includes its comma, so
changed_assets=3 cannot also match unchanged_assets=38. The frozen failed V2
file and this V3 source are retained; no existing source/result is modified.
Only the result namespace and fixed CMD/SELF bindings become V3. The eight
actual native-v2 assets, target Stage/Parent/caps/FAIL/stock/finally stay exact.
"""
import ast
import hashlib
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_observer_native_v3_check.py'
SOURCE_CMD = 'HOST_MTA_GO_OBSERVER_NATIVE_V3_SOURCE_CHECK.cmd'
TEST_CMD = 'TEST_MTA_GO_OBSERVER_NATIVE_V3.cmd'
V2_SOURCE = ('host/device_go_observer_native_v2_check.py', 10005,
             '929196159235132934ae3c8fd8e493074645659970380a3f6641efbe4ab49fe3')
DEFINITIONS = frozenset(('need', 'fixed', 'function_raw', 'change', 'proof',
    'derive_stage', 'derive_payloads', 'derive_main_factory', 'prepare'))


def need(value):
    if value is not True:
        raise ValueError('native_v3_bridge_contract')


def fixed_v2():
    raw = (BASE / V2_SOURCE[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == V2_SOURCE[1:])
    return raw


def derive(raw):
    changes = (
        (b"b'changed_assets=3', b'changed_assets=4'",
         b"b'changed_assets=3,', b'changed_assets=4,'"),
        (b"b\"b'go-observer-native-v2-'\"", b"b\"b'go-observer-native-v3-'\""))
    result = raw
    for before, after in changes:
        need(result.count(before) == 1 and result.count(after) == 0)
        result = result.replace(before, after)
        need(result.count(after) == 1 and result.replace(after, before).count(before) == 1)
    inverse = result
    for before, after in reversed(changes):
        need(inverse.count(after) == 1)
        inverse = inverse.replace(after, before)
    need(inverse == raw and
         ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(raw.decode('ascii')), include_attributes=True))
    return result, dict(frozen_origin=list(V2_SOURCE), complete_byte_ast_inverse=True,
        replacements=[dict(before=before.decode('ascii'), after=after.decode('ascii'), count=1)
                      for before, after in changes], target_assets_changed=0,
        original_counter_anchor_restricted_only=True, original_caps_gates_unchanged=True)


def prepare():
    origin = fixed_v2()
    changed, contract = derive(origin)
    tree = ast.parse(changed.decode('ascii'))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in DEFINITIONS]
    need(len(functions) == len(DEFINITIONS) and {node.name for node in functions} == DEFINITIONS)
    # The V2 main and guard are excluded; only frozen pure PC definitions load.
    selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or node in functions]
    namespace = dict(__file__=str(BASE / V2_SOURCE[0]), __name__='observer_native_v3_PC_bridge', __doc__=__doc__)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<observer-native-v3-narrow-PC-bridge>', 'exec'), namespace)
    namespace.update(SELF=SELF, SOURCE_CMD=SOURCE_CMD, TEST_CMD=TEST_CMD)
    driver = namespace['prepare']()
    previous = driver['payloads']

    def preserve_origin(inputs):
        need(fixed_v2() == origin)
        if V2_SOURCE[0] in inputs:
            need(inputs[V2_SOURCE[0]] == origin)
        inputs[V2_SOURCE[0]] = origin
        result = previous(inputs)
        driver['DERIVED_CONTRACT']['host_bridge_v3'] = contract
        return result

    # Same driver globals: the unchanged main calls this evidence-only adapter.
    driver['payloads'] = preserve_origin
    return driver


def main():
    return prepare()['main']()


if __name__ == '__main__':
    raise SystemExit(main())

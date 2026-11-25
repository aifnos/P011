"""Thin PC-only V2 bridge: one exact Stage doc literal fix, same native-v1 assets.

Default SOURCE, explicit --stage-native only. The failed V1 and its assets are
preserved; no tolerance, target method, native byte, cap or inventory rule changes.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_readonly_native_v2_check.py'
V1 = ('host/device_go_readonly_native_v1_check.py', 18663,
    '85a5ffb2d271d321e6e693edec549cff187c73aa35e3f7e5e5a6424d612adb53')
OLD_SOURCE_CMD = ('HOST_MTA_GO_READONLY_NATIVE_V1_SOURCE_CHECK.cmd', 330,
    'e637b2ad8fade62fdc416e9f4860f68eaaa970c2e2c44a9ac3e0e8ebe5f9bd9d')
OLD_STAGE_CMD = ('STAGE_MTA_GO_READONLY_NATIVE_V1.cmd', 333,
    'b9d4c226c0b51d9758ce3b1a6cf019361d951aee23bcdc3bb06127c4dfbf2761')
BRIDGE_INPUTS = (V1, OLD_SOURCE_CMD, OLD_STAGE_CMD)
SOURCE_CMD = 'HOST_MTA_GO_READONLY_NATIVE_V2_SOURCE_CHECK.cmd'
STAGE_CMD = 'STAGE_MTA_GO_READONLY_NATIVE_V2.cmd'
NEW_SOURCE_SHA = '33e1a94acf3cbb3426d7b6ecabba235f7634577485d426d2ca43c82dd58f31a7'
NEW_STAGE_SHA = '025bb8d61e5345ed431e34d0f2787b5081945bb442e3d6bf4baa8f3f2148265d'


def need(value):
    if not value:
        raise ValueError('stage_contract')


def fixed(inputs, row):
    raw = inputs[row[0]] if row[0] in inputs else (BASE / row[0]).read_bytes()
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == row[1:])
    inputs[row[0]] = raw
    return raw


def shape(raw):
    class Literals(ast.NodeTransformer):
        def visit_Constant(self, node):
            return ast.copy_location(ast.Constant(value=None), node)
    return ast.dump(Literals().visit(ast.parse(raw.decode('ascii'))), include_attributes=False)


def derive(raw):
    """Nine unique fixed literal edits; complete offset-bound byte/AST reverse."""
    changes = (
        ("old_doc.replace('observer-libc-v1',", "old_doc.replace('isolated observer-libc-v1',"),
        ("SELF = 'host/device_go_readonly_native_v1_check.py'", "SELF = " + repr(SELF)),
        ("SOURCE_CMD = 'HOST_MTA_GO_READONLY_NATIVE_V1_SOURCE_CHECK.cmd'", "SOURCE_CMD = " + repr(SOURCE_CMD)),
        ("STAGE_CMD = 'STAGE_MTA_GO_READONLY_NATIVE_V1.cmd'", "STAGE_CMD = " + repr(STAGE_CMD)),
        ("(SOURCE_CMD, 330, '" + OLD_SOURCE_CMD[2] + "')", "(SOURCE_CMD, 330, '" + NEW_SOURCE_SHA + "')"),
        ("(STAGE_CMD, 333, '" + OLD_STAGE_CMD[2] + "')", "(STAGE_CMD, 333, '" + NEW_STAGE_SHA + "')"),
        (r"host\\device_go_readonly_native_v1_check.py", r"host\\device_go_readonly_native_v2_check.py"),
        ("\"'go-readonly-native-v1-' + mode\"", "\"'go-readonly-native-v2-' + mode\""),
        ("\"kind='go-readonly-native-v1-files-only'\"", "\"kind='go-readonly-native-v2-files-only'\""),
    )
    original = raw
    ledger = []
    for before, after in changes:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == 1)
        offset = raw.index(before)
        raw = raw[:offset] + after + raw[offset + len(before):]
        ledger.append((offset, before, after))
    reverse = raw
    for offset, before, after in reversed(ledger):
        need(reverse[offset:offset + len(after)] == after)
        reverse = reverse[:offset] + before + reverse[offset + len(after):]
    need(reverse == original and shape(raw) == shape(original))
    need(ast.dump(ast.parse(reverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))
    return raw, dict(fixed_literal_edits=9, complete_byte_inverse=True,
        complete_ast_inverse=True, constant_only_ast_shape_equal=True,
        target_methods_changed=False, native_assets_changed=False,
        v1_pin=(V1[1], V1[2]), derived_pc_pin=(len(raw), hashlib.sha256(raw).hexdigest()))


def load(inputs=None):
    inputs = {} if inputs is None else inputs
    for row in BRIDGE_INPUTS:
        fixed(inputs, row)
    raw, proof = derive(inputs[V1[0]])
    value = types.ModuleType('go_readonly_native_v2_pc_private')
    value.__file__ = str(BASE / SELF)
    # V1's __main__ guard is false. Only newly derived PC definitions load.
    exec(compile(raw, value.__file__ + ':literal-bridge', 'exec'), value.__dict__)
    inherited_payloads = value.native_payloads
    def payloads(snapshot, namespace):
        for row in BRIDGE_INPUTS:
            fixed(snapshot, row)
        result = inherited_payloads(snapshot, namespace)
        namespace['_native_source_facts']['pc_literal_bridge'] = proof
        return result
    value.native_payloads = payloads
    need(value.SELF == SELF and value.SOURCE_CMD == SOURCE_CMD and value.STAGE_CMD == STAGE_CMD)
    need(value.ROOT == '/var/volatile/tmp/p011-mta-go-readonly-native-v1' and
         value.STAGE == ('candidate/go-readonly-native-v1/runtime/formal_native_stage.py', 24524,
             'c5f9873d7f0a31aef3178421d8a3514b381ca777d39013bff893e2ab386fd3a8'))
    return value


def main():
    return load().main()


if __name__ == '__main__':
    raise SystemExit(main())

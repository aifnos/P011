"""Independent PC-only UTF-8 AST bridge for frozen empty-lock initializer.

Default SOURCE; explicit --initialize-device is the sole device action.
From frozen V1, retain V2's complete readonly_existing_lock PC-token fix,
change only the two full transport-source AST decodes to UTF-8, and give
this entry its own identities. TARGET and transport byte edits stay exact.
Frozen V1/V2 and all four old CMDs are saved before source_contract runs.
No old source, results, assets or stages are changed or replayed.
"""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_device_lock_init_v3_check.py'
HOST_CMD = 'HOST_MTA_GO_DEVICE_LOCK_INIT_V3_SOURCE_CHECK.cmd'
INIT_CMD = 'INIT_MTA_GO_DEVICE_LOCK_V3.cmd'
V1 = ('host/device_go_device_lock_init_v1_check.py', 31802,
      'fabde7eb204193e7838715e52c6606f16b669e8ef94dfb7ece984986263ee8f9')
V2 = ('host/device_go_device_lock_init_v2_check.py', 5012,
      'de0660ae44016f81f3a92353e52bbc4c66f54d9e2f713a6fae7f4712ea5d29d3')
ORIGIN_INPUTS = (V1,
    ('HOST_MTA_GO_DEVICE_LOCK_INIT_V1_SOURCE_CHECK.cmd', 242,
     '04d4c93621d37da5e5eec7937737b1d2113a4a9454e3404b598c7a0fc46d36d9'),
    ('INIT_MTA_GO_DEVICE_LOCK_V1.cmd', 252,
     '00d2afdd97136c7fcb6c9e9a8a2f4149996f247bff6cce78438ae1560e15720a'),
    V2,
    ('HOST_MTA_GO_DEVICE_LOCK_INIT_V2_SOURCE_CHECK.cmd', 242,
     '2524fc6a7be2d93d04ea88acce1bef7ac89266228b3dbd034d7b529cd7f986cf'),
    ('INIT_MTA_GO_DEVICE_LOCK_V2.cmd', 252,
     'e6ee2f30063a76a1446294ce079019dc53c152bb1cb9d1406ba057d45e213609'))
DEFINITIONS = frozenset(('need', 'sha', 'read_input', 'prepare', 'derive_transport',
                        'initializer_budget', 'source_contract', 'accept', 'main'))


def need(value):
    if value is not True:
        raise ValueError('source_contract')


def fixed_v1():
    raw = (BASE / V1[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == V1[1:])
    return raw


def target_literal(raw):
    tree = ast.parse(raw.decode('utf-8'))
    values = [n.value for n in tree.body if isinstance(n, ast.Assign) and
              len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and
              n.targets[0].id == 'TARGET']
    need(len(values) == 1)
    return ast.literal_eval(values[0])


def derive(raw):
    # This complete expression occurs only in derive_transport. Fixed ASCII
    # markers, fixed ASCII target, and source bytes are not recoded or changed.
    before_codec = (b"ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==\n"
                    b"         ast.dump(ast.parse(raw.decode('ascii')), include_attributes=True)")
    after_codec = (b"ast.dump(ast.parse(inverse.decode('utf-8')), include_attributes=True) ==\n"
                   b"         ast.dump(ast.parse(raw.decode('utf-8')), include_attributes=True)")
    changes = ((b'b"meta[3:7] != (0, 0, 1, 0)"',
                b"b\"meta[3:7] != (0, 0, 1, 0)): _fail('readonly_existing_lock')\"", 1),
               (before_codec, after_codec, 1),
               (b'go-device-lock-init-v1', b'go-device-lock-init-v3', 2))
    result = raw
    for before, after, count in changes:
        need(result.count(before) == count and result.count(after) == 0)
        result = result.replace(before, after)
        need(result.count(after) == count)
    inverse = result
    for before, after, count in reversed(changes):
        need(inverse.count(after) == count)
        inverse = inverse.replace(after, before)
    need(inverse == raw and ast.dump(ast.parse(inverse.decode('utf-8')), include_attributes=True) ==
         ast.dump(ast.parse(raw.decode('utf-8')), include_attributes=True))
    need(target_literal(result) == target_literal(raw))
    return result, dict(origin_inputs=[list(row) for row in ORIGIN_INPUTS],
        direct_derivation_origin=list(V1), frozen_failed_v2_provenance=list(V2),
        derived_bytes=len(result), derived_sha256=hashlib.sha256(result).hexdigest(),
        complete_byte_ast_inverse=True, target_literal_exact_unchanged=True,
        transport_ast_source_codec='utf-8', transport_byte_edit_literals_unchanged=True,
        changes=[dict(before=a.decode('ascii'), after=b.decode('ascii'), count=c)
                 for a, b, c in changes], old_results_modified=False)


def prepare():
    origin = fixed_v1()
    changed, contract = derive(origin)
    tree = ast.parse(changed.decode('utf-8'))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in DEFINITIONS]
    need(len(functions) == len(DEFINITIONS) and {n.name for n in functions} == DEFINITIONS)
    # Select pure PC definitions only; never execute a frozen module guard.
    # The selected main is this independent clone with its own result identity.
    nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign)) or n in functions]
    driver = dict(__file__=str(BASE / SELF), __name__='device_lock_init_v3_private', __doc__=__doc__)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<empty-lock-init-v3-PC-bridge>', 'exec'), driver)
    driver.update(SELF=SELF, HOST_CMD=HOST_CMD, INIT_CMD=INIT_CMD)
    previous = driver['prepare']

    def preserve_first(inputs, out):
        # Six immutable prior source/CMD identities are immediately saved and
        # read back before metadata-helper preparation or source_contract gates.
        for row in ORIGIN_INPUTS:
            driver['read_input'](inputs, out, row)
        need(inputs[V1[0]] == origin)
        private = out / 'private-raw'
        for name, raw in (('v3-derived-PC-source.private.py', changed),
                          ('v3-bridge-contract.private.json',
                           (json.dumps(contract, sort_keys=True, indent=2) + '\n').encode('ascii'))):
            with (private / name).open('xb') as handle:
                need(handle.write(raw) == len(raw))
            need((private / name).read_bytes() == raw)
        return previous(inputs, out)

    driver['prepare'] = preserve_first
    return driver


def main():
    return prepare()['main']()


if __name__ == '__main__':
    raise SystemExit(main())

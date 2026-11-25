"""Narrow independent PC bridge for frozen empty-device-lock init V1.

Default SOURCE; explicit --initialize-device remains the only device action.
Only the duplicate generic observer PC token becomes one complete original
readonly_existing_lock line; result/SELF/CMD identities become V2. The target,
all source pins, transport delta, limits, process gates and closure stay exact.
Frozen V1 and both original CMDs are saved before any source_contract runs.
No old source/results/assets are modified or automatically replayed.
"""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_device_lock_init_v2_check.py'
HOST_CMD = 'HOST_MTA_GO_DEVICE_LOCK_INIT_V2_SOURCE_CHECK.cmd'
INIT_CMD = 'INIT_MTA_GO_DEVICE_LOCK_V2.cmd'
V1 = ('host/device_go_device_lock_init_v1_check.py', 31802,
      'fabde7eb204193e7838715e52c6606f16b669e8ef94dfb7ece984986263ee8f9')
ORIGIN_INPUTS = (V1,
    ('HOST_MTA_GO_DEVICE_LOCK_INIT_V1_SOURCE_CHECK.cmd', 242,
     '04d4c93621d37da5e5eec7937737b1d2113a4a9454e3404b598c7a0fc46d36d9'),
    ('INIT_MTA_GO_DEVICE_LOCK_V1.cmd', 252,
     '00d2afdd97136c7fcb6c9e9a8a2f4149996f247bff6cce78438ae1560e15720a'))
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
    tree = ast.parse(raw.decode('ascii'))
    values = [n.value for n in tree.body if isinstance(n, ast.Assign) and
              len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and
              n.targets[0].id == 'TARGET']
    need(len(values) == 1)
    return ast.literal_eval(values[0])


def derive(raw):
    changes = ((b'b"meta[3:7] != (0, 0, 1, 0)"',
                b"b\"meta[3:7] != (0, 0, 1, 0)): _fail('readonly_existing_lock')\"", 1),
               (b'go-device-lock-init-v1', b'go-device-lock-init-v2', 2))
    result = raw
    for before, after, count in changes:
        need(result.count(before) == count and result.count(after) == 0)
        result = result.replace(before, after)
        need(result.count(after) == count)
    inverse = result
    for before, after, count in reversed(changes):
        need(inverse.count(after) == count)
        inverse = inverse.replace(after, before)
    need(inverse == raw and ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(raw.decode('ascii')), include_attributes=True))
    need(target_literal(result) == target_literal(raw))
    return result, dict(origin_inputs=[list(row) for row in ORIGIN_INPUTS],
        derived_bytes=len(result), derived_sha256=hashlib.sha256(result).hexdigest(),
        complete_byte_ast_inverse=True, target_literal_exact_unchanged=True,
        changes=[dict(before=a.decode('ascii'), after=b.decode('ascii'), count=c)
                 for a, b, c in changes], old_results_modified=False)


def prepare():
    origin = fixed_v1()
    changed, contract = derive(origin)
    tree = ast.parse(changed.decode('ascii'))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in DEFINITIONS]
    need(len(functions) == len(DEFINITIONS) and {n.name for n in functions} == DEFINITIONS)
    # No old module import/guard/main execution. The selected main is the new
    # independently named PC clone, with exactly the proven identity changes.
    nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom, ast.Assign)) or n in functions]
    driver = dict(__file__=str(BASE / SELF), __name__='device_lock_init_v2_private', __doc__=__doc__)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<empty-lock-init-v2-PC-bridge>', 'exec'), driver)
    driver.update(SELF=SELF, HOST_CMD=HOST_CMD, INIT_CMD=INIT_CMD)
    previous = driver['prepare']

    def preserve_first(inputs, out):
        # All three immutable old origins are retained before even the old
        # metadata-helper preparation, and before any source_contract gate.
        for row in ORIGIN_INPUTS:
            driver['read_input'](inputs, out, row)
        need(inputs[V1[0]] == origin)
        private = out / 'private-raw'
        for name, raw in (('v2-derived-PC-source.private.py', changed),
                          ('v2-bridge-contract.private.json',
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

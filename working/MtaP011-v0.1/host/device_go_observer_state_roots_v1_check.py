"""Fixed State/native metadata observation; default PC SOURCE only.

The two project paths come from the pinned actual observer Body's STATE_ROOT
literal and its original native anchor. Explicit --check-device takes exactly
two lstat samples per path, with the frozen stock checks before and after.
Typed ENOENT is endpoint metadata evidence, not independent leaf absence when
a parent may be missing. Observation PASS never means roots exist, inventory,
admission, restoration or repair. No Parent, Owner, Stage or RF runs here.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_observer_state_roots_v1_check.py'
HOST_CMD = 'HOST_MTA_GO_OBSERVER_STATE_ROOTS_V1_SOURCE_CHECK.cmd'
TEST_CMD = 'TEST_MTA_GO_OBSERVER_STATE_ROOTS_V1.cmd'
MOTHER = ('host/device_formal_send_repair_prerequisite_roots_v1_check.py', 16667,
          '94325f0c0f666c88e198dec11a18efce39daf3d1463c925c9ee51bbe649450fd')
BODY_SOURCE = ('candidate/go-observer-diag-v1/runtime/mta_go_readonly_preflight.py',
               64948, 'a10d6c9ff9ec4bf4b2d542120b19af3e36a111caf1153eaa8bc7d842aaa245eb')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
EXPECTED_ROOTS = (('state', '/var/volatile/tmp/p011-mta-state-v69'),
                  ('native', '/var/volatile/tmp/p011-mta-state-v69/native'))
HELPERS = frozenset(('sha', 'need', 'write_new', 'fixed', 'literal',
                    'probe_definitions', 'compressed_budget', 'receipt',
                    'run_readonly', 'stock_identity'))
CONSTANTS = frozenset(('BASE', 'TRANSPORT', 'FALSE_FIELDS', 'ERRORS'))


def need(value, code='source_contract'):
    if value is not True:
        raise ValueError(code)


def pinned(inputs, row):
    raw = (BASE / row[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == row[1:], 'input_pin')
    if row[0] in inputs:
        need(inputs[row[0]] == raw, 'source_changed')
    inputs[row[0]] = raw
    return raw


def value(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name
                for target in node.targets)]
    need(len(rows) == 1)
    return ast.literal_eval(rows[0])


def function_raw(raw, tree, name):
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == name]
    need(len(rows) == 1)
    node = rows[0]
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def edit(raw, changes, label, before, after, count=1):
    need(type(before) is bytes and type(after) is bytes and before != after and
         raw.count(before) == count)
    changed = raw.replace(before, after)
    need(changed.count(after) == count)
    changes.append((label, before, after, count))
    return changed


def inverse(changed, changes, original):
    for label, before, after, count in reversed(changes):
        need(changed.count(after) == count)
        changed = changed.replace(after, before)
    need(changed == original and
         ast.dump(ast.parse(changed.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))


def derive_body(mother_raw):
    original = value(mother_raw, 'BODY').encode('ascii')
    changes = []
    changed = edit(original, changes, 'typed_enoent_data',
        b"return ('missing',None)", b"return ('missing',errno.ENOENT)")
    inverse(changed, changes, original)
    need(changed.count(b'calls+=1') == 1 and
         changed.count(b'os.lstat(path)') == 1 and
         changed.count(b'first=tuple(sample(path) for role,path in ROOTS)') == 1 and
         changed.count(b'second=tuple(sample(path) for role,path in ROOTS)') == 1)
    ast.parse(changed.decode('ascii'), feature_version=(3, 5))
    return changed.decode('ascii')


def derive_classify(mother_raw, tree):
    original = function_raw(mother_raw, tree, 'classify')
    changes = []
    changed = edit(original, changes, 'four_fixed_lstat_calls',
        b"value['lstat_calls'] == 6", b"value['lstat_calls'] == 4")
    changed = edit(changed, changes, 'two_fixed_roots',
        b"len(value['samples']) == 3", b"len(value['samples']) == 2")
    changed = edit(changed, changes, 'strict_enoent_data',
        b"need(sample[1] is None, 'remote_result')",
        b"need(type(sample[1]) is int and sample[1] == 2, 'remote_result')")
    changed = edit(changed, changes, 'bounded_metadata_evidence',
        b"evidence='ROOT_METADATA_ONLY', inventory_verified=False, safety_admitted=False))",
        b"evidence='ROOT_METADATA_ONLY', inventory_verified=False, safety_admitted=False,\n"
        b"                         typed_enoent=stable and first[0] == 'missing',\n"
        b"                         independent_leaf_absence_verified=False))")
    inverse(changed, changes, original)
    # The unchanged prerequisite calculation now covers exactly the two roots.
    need(changed.count(b'rows[:2]') == original.count(b'rows[:2]') == 2)
    return changed


def derive_main(mother_raw, tree):
    original = function_raw(mother_raw, tree, 'main')
    changes = []
    changed = edit(original, changes, 'independent_result_namespace',
        b'formal-send-repair-prerequisite-roots-v1', b'go-observer-state-roots-v1', 2)
    changed = edit(changed, changes, 'fixed_actual_body_root_notice',
        b'Two lstat samples each of sender, observer, ordinary roots from pinned v6 Stage.',
        b'Two lstat samples each of State and native roots from the pinned actual Body.')
    changed = edit(changed, changes, 'typed_enoent_scope_notice',
        b'ordinary target missing is separate from sender/observer prerequisites missing.',
        b'Typed ENOENT does not distinguish a missing leaf from a missing ancestor.')
    inverse(changed, changes, original)
    # Every original transport, remote exit, stock, raw and finally gate stays.
    for token in (b'run_readonly(adb, probe, private,', b'    finally:\n',
                  b'report[\'stock_identity_ok\']', b'report[\'stock_unchanged\']',
                  b"['result.json', 'README.txt']", b"(BASE / path).read_bytes() == raw"):
        need(changed.count(token) == original.count(token))
    return changed


def source_contract(inputs, driver, mother_raw):
    need(pinned(inputs, MOTHER) == mother_raw, 'source_changed')
    body = pinned(inputs, BODY_SOURCE)
    transport = pinned(inputs, TRANSPORT)
    state = value(body, 'STATE_ROOT')
    roots = (('state', state), ('native', state + '/native'))
    need(type(state) is str and roots == EXPECTED_ROOTS and
         body.count(b'                (STATE_ROOT, stat.S_IFDIR | 0o700, None),\n') == 1 and
         body.count(b"                (STATE_ROOT + '/native', stat.S_IFDIR | 0o700, None)):\n") == 1)
    program = 'ROOTS=' + repr(roots) + '\n' + driver['BODY']
    driver['compressed_budget'](program)
    baseline = 'PINS=' + repr(driver['literal'](transport, 'PINS')) + '\n' + driver['literal'](transport, 'PROBE')
    driver['compressed_budget'](baseline)
    return roots, program


def prepare():
    mother_raw = pinned({}, MOTHER)
    tree = ast.parse(mother_raw.decode('ascii'))
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name in HELPERS]
    need(len(helpers) == len(HELPERS) and {node.name for node in helpers} == HELPERS)
    constants = [node for node in tree.body if isinstance(node, ast.Assign) and
                 len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
                 node.targets[0].id in CONSTANTS]
    need(len(constants) == len(CONSTANTS) and
         {node.targets[0].id for node in constants} == CONSTANTS)
    # The old main, source_contract, classify and module guard are never selected.
    nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom)) or
             node in helpers or node in constants]
    driver = dict(__file__=str(BASE / SELF), __name__='observer_state_roots_private', __doc__=__doc__)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<frozen-root-metadata-PC-definitions>', 'exec'), driver)
    need(driver['TRANSPORT'] == TRANSPORT)
    driver.update(SELF=SELF, HOST_CMD=HOST_CMD, TEST_CMD=TEST_CMD,
                  EXPECTED_ROOTS=EXPECTED_ROOTS, BODY=derive_body(mother_raw))
    driver['source_contract'] = lambda inputs: source_contract(inputs, driver, mother_raw)
    exec(compile(derive_classify(mother_raw, tree), '<fixed-State-native-metadata-classifier>', 'exec'), driver)
    exec(compile(derive_main(mother_raw, tree), '<independent-State-native-PC-driver>', 'exec'), driver)
    return driver


def main():
    return prepare()['main']()


if __name__ == '__main__':
    raise SystemExit(main())

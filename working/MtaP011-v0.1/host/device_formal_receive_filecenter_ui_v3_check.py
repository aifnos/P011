"""Receiver/FileCenter credential-directory fix; SOURCE default, no RF action.

Reuse the v2 comparison carrier, private diagnosis, assets and core exactly.
The new Worker uses the validator's original credential-only directory chain,
not the all-asset list containing sibling mta/toolbox directories. A fresh
exclusive control root preserves both failed trials. No screenshot observer
runs during Startup; all original 46 facts and cleanup gates remain required.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v3_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V3_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V3.cmd')
COMPARISON = ('host/device_formal_receive_filecenter_ui_v2_check.py', 10090,
              'c47f71990c78569a94e16d90b7af652d01d2193a63f918ff30942a271c426e6e')
OLD_WORKER = ('candidate/formal-receive-filecenter-ui-v2/runtime/ui_session.py', 91414,
              '9f529fc41b3dd847174547b9e2aab4ee0153e66c84986f35a965a16e715c0272')
WORKER = ('candidate/formal-receive-filecenter-ui-v3/runtime/ui_session.py', 91420,
          'a00c8f863bb75fd65af06cbbc1a32b23322dfada55d0926cc9eedcd668068fa3')
OLD_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v2'"
NEW_CONTROL = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v3'"
OLD_CHAIN = b"for name, metadata in _RETAINED['assets']['directory_bindings'][:-1]:"
NEW_CHAIN = b"for name, metadata in _RETAINED['assets']['credential_directory_bindings']:"


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'credential_fix_source_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    value = types.ModuleType(name)
    value.__file__ = str(BASE / pin[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    need(value.BASE == BASE, 'credential_fix_base')
    return value, raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def retained_main(original, comparison_raw, old_worker_raw):
    """Only new result label and two actual frozen PC inputs; inverse exact."""
    def adapted(raw):
        tree = original(raw)
        before = copy.deepcopy(tree)
        seeds = [row for row in tree.body[0].body if isinstance(row, ast.Assign) and
                 len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                 row.targets[0].id == 'inputs']
        labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and
                  row.value == 'formal-receive-filecenter-ui-v2-']
        need(len(seeds) == len(labels) == 1 and isinstance(seeds[0].value, ast.Dict),
             'credential_fix_main_shape')
        old_seed = copy.deepcopy(seeds[0].value)
        labels[0].value = 'formal-receive-filecenter-ui-v3-'
        for path, value in ((COMPARISON[0], comparison_raw), (OLD_WORKER[0], old_worker_raw)):
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        final = copy.deepcopy(tree)
        seeds[0].value = old_seed
        labels[0].value = 'formal-receive-filecenter-ui-v2-'
        need(shape(tree) == shape(before), 'credential_fix_inverse_main')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    comparison, comparison_raw = definitions(COMPARISON, 'fixed_fc_ui_v3_comparison_definitions')
    old_worker_raw, worker_raw = fixed(OLD_WORKER), fixed(WORKER)
    need(old_worker_raw.count(OLD_CONTROL) == worker_raw.count(NEW_CONTROL) == 1 and
         old_worker_raw.count(OLD_CHAIN) == worker_raw.count(NEW_CHAIN) == 1 and
         worker_raw.replace(NEW_CONTROL, OLD_CONTROL, 1).replace(NEW_CHAIN, OLD_CHAIN, 1) == old_worker_raw,
         'credential_fix_inverse_worker')
    ast.parse(worker_raw, feature_version=(3, 5))
    original, original_raw = definitions(comparison.ORIGINAL, 'fixed_fc_ui_v3_original_definitions')
    original_worker_raw = fixed(comparison.OLD_WORKER)
    need(original.WORKER == comparison.OLD_WORKER and original_raw == comparison.fixed(comparison.ORIGINAL),
         'credential_fix_original_chain')
    comparison.NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v3'"
    adapted = comparison.comparison_main(original.new_main, original_raw, original_worker_raw)
    original.SELF, original.CMDS, original.WORKER = SELF, CMDS, WORKER
    original.new_main = retained_main(adapted, comparison_raw, old_worker_raw)
    original.DIAGNOSTIC_RAW += comparison.INNER_DIAGNOSTIC
    # Definitions-only composition: neither archived v1/v2 compiled main is
    # invoked. Only this narrowly derived main can dispatch the fixed trial.
    return original.main()


if __name__ == '__main__':
    raise SystemExit(main())

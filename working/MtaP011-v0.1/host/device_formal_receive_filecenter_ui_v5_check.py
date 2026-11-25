"""Fixed post-cleanup Startup expiry projection; SOURCE by default.

Keep the v4 carrier, raw-preserving stream, post-READY read-only screenshot,
original46 facts,20s display and600+60 unchanged. Only the exclusive CONTROL,
result label, retained PC inputs and bounded private diagnostic differ.
No new Startup collector, clock renewal, RF, input, file or phone action.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v5_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V5_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V5.cmd')
PREVIOUS = ('host/device_formal_receive_filecenter_ui_v4_check.py', 18256,
            '5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556')
WORKER = ('candidate/formal-receive-filecenter-ui-v5/runtime/ui_session.py', 91420,
          '1ad7cde1ed7e5e9271e5d4e1fc400676833897c9df57eead7e57e85828f93e6d')
PROJECTION = ('host/receive_startup_deadline_projection_v1.py', 7569,
              '8f0c5e8d4bc6db9420d990bfb099ce9a428719efd066e3876ca0130f77887551')
CONTROL_OLD = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v4'"
CONTROL_NEW = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v5'"


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'expiry_projection_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def derived_main(original, inputs):
    def adapted(raw):
        tree = original(raw)
        before = copy.deepcopy(tree)
        controls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                    len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                    row.targets[0].id == 'control']
        labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and
                  row.value == 'formal-receive-filecenter-ui-v4-']
        seeds = [row for row in tree.body[0].body if isinstance(row, ast.Assign) and
                 len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                 row.targets[0].id == 'inputs']
        need(len(controls) == len(labels) == len(seeds) == 1 and
             shape(controls[0].value) == shape(ast.parse(CONTROL_OLD, mode='eval').body) and
             isinstance(seeds[0].value, ast.Dict), 'expiry_projection_shape')
        old_control, old_seed = copy.deepcopy(controls[0].value), copy.deepcopy(seeds[0].value)
        controls[0].value = ast.parse(CONTROL_NEW, mode='eval').body
        labels[0].value = 'formal-receive-filecenter-ui-v5-'
        for path, value in inputs.items():
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        final = copy.deepcopy(tree)
        controls[0].value, seeds[0].value = old_control, old_seed
        labels[0].value = 'formal-receive-filecenter-ui-v4-'
        need(shape(tree) == shape(before), 'expiry_projection_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    need(PROJECTION[1] > 0 and len(PROJECTION[2]) == 64, 'expiry_projection_unsealed')
    previous, previous_raw = definitions(PREVIOUS, 'fixed_expiry_v5_carrier_definitions')
    projection, projection_raw = definitions(PROJECTION, 'fixed_expiry_v5_projection_definitions')
    fragment = projection.TARGET_FRAGMENT
    need(type(fragment) is bytes and 0 < len(fragment) <= 8192, 'expiry_projection_fragment')
    ast.parse(fragment, feature_version=(3, 5))
    original_worker = previous.WORKER
    previous.OLD_WORKER, previous.WORKER = original_worker, WORKER
    previous.OLD_SUFFIX = b'-formal-receive-filecenter-ui-v4'
    previous.NEW_SUFFIX = b'-formal-receive-filecenter-ui-v5'
    previous.SELF, previous.CMDS = SELF, CMDS
    actual_definitions = previous.definitions

    def projected_definitions(pin, name):
        module, raw = actual_definitions(pin, name)
        if pin[0] == 'host/device_formal_receive_filecenter_ui_v1_check.py':
            # The actual frozen worker returns and performs original cleanup
            # before this private projection executes. No new target IO.
            need(module.DIAGNOSTIC_RAW.endswith(b'\n'), 'expiry_diagnostic_anchor')
            module.DIAGNOSTIC_RAW += fragment
        return module, raw

    previous.definitions = projected_definitions
    actual_adapter = previous.adapted_main
    retained_inputs = {PREVIOUS[0]: previous_raw, PROJECTION[0]: projection_raw}

    def projected_main(original, inputs):
        return derived_main(actual_adapter(original, inputs), retained_inputs)

    previous.adapted_main = projected_main
    return previous.main()


if __name__ == '__main__':
    raise SystemExit(main())

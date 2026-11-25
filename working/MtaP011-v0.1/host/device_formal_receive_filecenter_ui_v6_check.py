"""SOURCE default; finite original Proc observation after original cleanup.

Keep the v4 stream/capture and 46 facts, 20s, 600+60 and restoration unchanged.
Worker6 differs from Worker5 only by the unique CONTROL suffix. No RF/input.
Both finite projections run after run_fixed; Proc projection follows INNER.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_ui_v6_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V6_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_UI_V6.cmd')
PREVIOUS = ('host/device_formal_receive_filecenter_ui_v4_check.py', 18256,
            '5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556')
PREDECESSOR = ('host/device_formal_receive_filecenter_ui_v5_check.py', 5245,
               '950907aec31e01f2b0778d8e00503de48d87fa975fe012f05c9e510385a43f0a')
OLD_WORKER = ('candidate/formal-receive-filecenter-ui-v5/runtime/ui_session.py', 91420,
              '1ad7cde1ed7e5e9271e5d4e1fc400676833897c9df57eead7e57e85828f93e6d')
WORKER = ('candidate/formal-receive-filecenter-ui-v6/runtime/ui_session.py', 91420,
          '0f2ce377a7871c4ef9d596731fa9117fd5c6dc913e69600e12539e66462ba7e9')
DEADLINE = ('host/receive_startup_deadline_projection_v1.py', 7569,
            '8f0c5e8d4bc6db9420d990bfb099ce9a428719efd066e3876ca0130f77887551')
PROC = ('host/receive_startup_proc_projection_v1.py', 6137,
        'aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002')
CONTROL_OLD = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v4'"
CONTROL_NEW = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v6'"


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'proc_projection_pin')
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
             isinstance(seeds[0].value, ast.Dict), 'proc_projection_shape')
        old_control, old_seed = copy.deepcopy(controls[0].value), copy.deepcopy(seeds[0].value)
        controls[0].value = ast.parse(CONTROL_NEW, mode='eval').body
        labels[0].value = 'formal-receive-filecenter-ui-v6-'
        for path, value in inputs.items():
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        final = copy.deepcopy(tree)
        controls[0].value, seeds[0].value = old_control, old_seed
        labels[0].value = 'formal-receive-filecenter-ui-v4-'
        need(shape(tree) == shape(before), 'proc_projection_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    previous, previous_raw = definitions(PREVIOUS, 'fixed_proc_v6_carrier_definitions')
    predecessor_raw = fixed(PREDECESSOR)  # Retain only; do not execute old main.
    deadline, deadline_raw = definitions(DEADLINE, 'fixed_proc_v6_deadline_definitions')
    proc, proc_raw = definitions(PROC, 'fixed_proc_v6_observation_definitions')
    for fragment in (deadline.TARGET_FRAGMENT, proc.TARGET_FRAGMENT):
        need(type(fragment) is bytes and 0 < len(fragment) <= 8192, 'proc_projection_fragment')
        ast.parse(fragment, feature_version=(3, 5))
    previous.OLD_WORKER, previous.WORKER = OLD_WORKER, WORKER
    previous.OLD_SUFFIX = b'-formal-receive-filecenter-ui-v5'
    previous.NEW_SUFFIX = b'-formal-receive-filecenter-ui-v6'
    previous.SELF, previous.CMDS = SELF, CMDS
    actual_definitions = previous.definitions

    def projected_definitions(pin, name):
        module, raw = actual_definitions(pin, name)
        if pin[0] == 'host/device_formal_receive_filecenter_ui_v1_check.py':
            need(module.DIAGNOSTIC_RAW.endswith(b'\n'), 'proc_diagnostic_anchor')
            module.DIAGNOSTIC_RAW += deadline.TARGET_FRAGMENT
        if pin[0] == 'host/device_formal_receive_filecenter_ui_v2_check.py':
            # v4 appends this complete literal after the generic diagnostic.
            # Thus the new fragment runs after INNER has bound its originals.
            need(module.INNER_DIAGNOSTIC.endswith(b'\n'), 'proc_inner_anchor')
            module.INNER_DIAGNOSTIC += proc.TARGET_FRAGMENT
        return module, raw

    previous.definitions = projected_definitions
    actual_adapter = previous.adapted_main
    retained = {PREVIOUS[0]: previous_raw, PREDECESSOR[0]: predecessor_raw,
                DEADLINE[0]: deadline_raw, PROC[0]: proc_raw}

    def projected_main(original, inputs):
        return derived_main(actual_adapter(original, inputs), retained)

    previous.adapted_main = projected_main
    return previous.main()


if __name__ == '__main__':
    raise SystemExit(main())

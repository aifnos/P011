"""Fixed Startup alias-clock graph in the original Receiver/FileCenter UI.

SOURCE is the default. Reuse the frozen HOST4 real READY stream, held-log/PID
watch and DRM reader. No observer runs before READY, no GUI asset is rebuilt,
and no RF/input/phone action is requested. The Worker differs from Worker6
only by its Runner pin, two graph roots and exclusive CONTROL suffix. Original
46 facts, launched+20 display, true600+60 and all restoration gates remain.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_startup_alias_clock_ui_v1_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_STARTUP_ALIAS_CLOCK_UI_V1_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_STARTUP_ALIAS_CLOCK_UI_V1.cmd')
PREVIOUS = ('host/device_formal_receive_filecenter_ui_v4_check.py', 18256,
            '5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556')
V6 = ('host/device_formal_receive_filecenter_ui_v6_check.py', 5980,
      '36a82117f0f084dd4878eef95521fc77589cede8e8368fea97a30d60e0effcdf')
OLD_WORKER = ('candidate/formal-receive-filecenter-ui-v6/runtime/ui_session.py', 91420,
              '0f2ce377a7871c4ef9d596731fa9117fd5c6dc913e69600e12539e66462ba7e9')
WORKER = ('candidate/formal-receive-startup-alias-clock-ui-v1/runtime/ui_session.py', 91433,
          'eea638c6c0e15b40cd93b049b3a1507c73e4d15063723f0c88ae9aa5ad852831')
GRAPH = ('host/formal_receive_startup_alias_clock_v1_definitions.py', 15123,
         '18502b3f17d4baeb8ed1bb19eaf53998b4edf2ebcfed38e91b75eda8107c662b')
DEADLINE = ('host/receive_startup_deadline_projection_v2.py', 7569,
            'b4cd05a9c7d3abe3e99da05e8ad72a9a9f13886c2cc8529b330606b7c984d637')
OLD_DEADLINE = ('host/receive_startup_deadline_projection_v1.py', 7569,
                '8f0c5e8d4bc6db9420d990bfb099ce9a428719efd066e3876ca0130f77887551')
PROC = ('host/receive_startup_proc_projection_v1.py', 6137,
        'aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002')
OLD_SUFFIX = b'-formal-receive-filecenter-ui-v6'
NEW_SUFFIX = b'-formal-receive-startup-alias-clock-ui-v1'
CONTROL_OLD = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v4'"
CONTROL_NEW = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-startup-alias-clock-ui-v1'"
WORKER_DELTAS = (
    (b"RUNNER_PIN = (79232, 'c8c4a0cafe08e2f2d269fd08c4b0167978c19e4b752dc01c9687c88c0aaefa1b')",
     b"RUNNER_PIN = (79236, '30df3797ed980f435749aa4c9b1e3bfbd2aca9bdb8c7fbff9c72e5f538df42a8')"),
    (b"STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1'",
     b"STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-startup-alias-clock-v1'"),
    (b"STATE_ALIAS = '/tmp/p011-mta-formal-receive-filecenter-v1'",
     b"STATE_ALIAS = '/tmp/p011-mta-receive-startup-alias-clock-v1'"),
    (b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v6'",
     b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-startup-alias-clock-ui-v1'"))
DEADLINE_DELTAS = ((b'check.__code__.co_firstlineno!=468', b'check.__code__.co_firstlineno!=499'),
                   (b'tb.tb_lineno==1177', b'tb.tb_lineno==1267'),
                   (b'tb.tb_lineno==478', b'tb.tb_lineno==509'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'startup_ui_source_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def exact_inverse(current, original, deltas):
    if type(current) is not bytes or type(original) is not bytes:
        return False
    for before, after in reversed(deltas):
        if current.count(after) != 1 or original.count(before) != 1:
            return False
        current = current.replace(after, before, 1)
    return current == original


def startupfix_worker_inverse(current, original):
    return exact_inverse(current, original, WORKER_DELTAS)


def shape(node):
    return ast.dump(node, include_attributes=False)


def bind_carrier_main(module, raw):
    """Change exactly the four-binding inverse predicate, not carrier logic."""
    source = ast.parse(raw)
    mains = [row for row in source.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(mains) == 1, 'startup_ui_carrier_main')
    tree = ast.Module(body=copy.deepcopy(mains), type_ignores=[])
    before = copy.deepcopy(tree)
    calls = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
             isinstance(row.func, ast.Name) and row.func.id == 'need' and len(row.args) == 2 and
             isinstance(row.args[1], ast.Constant) and row.args[1].value == 'ready_worker_inverse']
    expected = ('worker_raw.count(NEW_SUFFIX) == old_worker_raw.count(OLD_SUFFIX) == 1 and '
                'worker_raw.replace(NEW_SUFFIX, OLD_SUFFIX, 1) == old_worker_raw')
    need(len(calls) == 1 and shape(calls[0].args[0]) ==
         shape(ast.parse(expected, mode='eval').body), 'startup_ui_inverse_seam')
    original = copy.deepcopy(calls[0].args[0])
    calls[0].args[0] = ast.parse('startupfix_worker_inverse(worker_raw, old_worker_raw)', mode='eval').body
    final = copy.deepcopy(tree)
    calls[0].args[0] = original
    need(shape(tree) == shape(before), 'startup_ui_carrier_main_inverse')
    module.startupfix_worker_inverse = startupfix_worker_inverse
    exec(compile(ast.fix_missing_locations(final), str(BASE / SELF), 'exec'), module.__dict__)


def derived_main(original, inputs):
    """Only the exclusive control, result label and retained actual PC bytes."""
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
             isinstance(seeds[0].value, ast.Dict), 'startup_ui_main_shape')
        old_control, old_seed = copy.deepcopy(controls[0].value), copy.deepcopy(seeds[0].value)
        controls[0].value = ast.parse(CONTROL_NEW, mode='eval').body
        labels[0].value = 'formal-receive-startup-alias-clock-ui-v1-'
        for path, value in inputs.items():
            seeds[0].value.keys.append(ast.Constant(value=path))
            seeds[0].value.values.append(ast.Constant(value=value))
        final = copy.deepcopy(tree)
        controls[0].value, seeds[0].value = old_control, old_seed
        labels[0].value = 'formal-receive-filecenter-ui-v4-'
        need(shape(tree) == shape(before), 'startup_ui_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


def main():
    previous, previous_raw = definitions(PREVIOUS, 'fixed_startup_ui_carrier_definitions')
    v6_raw, graph_raw = fixed(V6), fixed(GRAPH)  # Read/preserve, no historical main dispatch.
    worker_raw, old_worker_raw = fixed(WORKER), fixed(OLD_WORKER)
    need(startupfix_worker_inverse(worker_raw, old_worker_raw), 'startup_ui_worker_inverse')
    deadline, deadline_raw = definitions(DEADLINE, 'fixed_startup_ui_deadline_definitions')
    old_deadline_raw = fixed(OLD_DEADLINE)
    need(exact_inverse(deadline_raw, old_deadline_raw, DEADLINE_DELTAS), 'startup_ui_deadline_inverse')
    proc, proc_raw = definitions(PROC, 'fixed_startup_ui_proc_definitions')
    for fragment in (deadline.TARGET_FRAGMENT, proc.TARGET_FRAGMENT):
        need(type(fragment) is bytes and 0 < len(fragment) <= 8192, 'startup_ui_fragment')
        ast.parse(fragment, feature_version=(3, 5))
    previous.OLD_WORKER, previous.WORKER = OLD_WORKER, WORKER
    previous.OLD_SUFFIX, previous.NEW_SUFFIX = OLD_SUFFIX, NEW_SUFFIX
    previous.SELF, previous.CMDS = SELF, CMDS
    bind_carrier_main(previous, previous_raw)
    actual_definitions = previous.definitions

    def bound_definitions(pin, name):
        module, raw = actual_definitions(pin, name)
        if pin[0] == 'host/device_formal_receive_filecenter_ui_v1_check.py':
            module.DEFINITIONS, module.PAYLOAD_BYTES = GRAPH, 4164334
            need(module.DIAGNOSTIC_RAW.endswith(b'\n'), 'startup_ui_diagnostic_anchor')
            module.DIAGNOSTIC_RAW += deadline.TARGET_FRAGMENT
        if pin[0] == 'host/device_formal_receive_filecenter_ui_v2_check.py':
            need(module.INNER_DIAGNOSTIC.endswith(b'\n'), 'startup_ui_inner_anchor')
            module.INNER_DIAGNOSTIC += proc.TARGET_FRAGMENT
        return module, raw

    previous.definitions = bound_definitions
    actual_adapter = previous.adapted_main
    retained = {PREVIOUS[0]: previous_raw, V6[0]: v6_raw, GRAPH[0]: graph_raw,
                DEADLINE[0]: deadline_raw, OLD_DEADLINE[0]: old_deadline_raw, PROC[0]: proc_raw}

    def bound_main(original, inputs):
        return derived_main(actual_adapter(original, inputs), retained)

    previous.adapted_main = bound_main
    return previous.main()


if __name__ == '__main__':
    raise SystemExit(main())

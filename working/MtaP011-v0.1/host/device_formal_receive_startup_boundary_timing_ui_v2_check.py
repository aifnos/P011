"""Five-boundary diagnostics in the unchanged bounded Receiver/FileCenter UI.

Default SOURCE only. Explicit --ui-smoke retains the original real READY stream,
watch/DRM after READY, 46 facts, launched+20s, 600+60 and closure checks. Only the
new fixed graph/Worker bindings, private after-run diagnostics and report/input
identity differ. No automatic RF, input, phone or GUI asset rebuild.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_startup_boundary_timing_ui_v2_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_STARTUP_BOUNDARY_TIMING_UI_V2_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_STARTUP_BOUNDARY_TIMING_UI_V2.cmd')
PARENT = ('host/device_formal_receive_startup_alias_clock_ui_v1_check.py', 9770,
          'fc128ce46255a9231eb0809682f2a5206414f112c4e60f9768ace20d655285d4')
OLD_WORKER = ('candidate/formal-receive-startup-alias-clock-ui-v1/runtime/ui_session.py',
              91433, 'eea638c6c0e15b40cd93b049b3a1507c73e4d15063723f0c88ae9aa5ad852831')
WORKER = ('candidate/formal-receive-startup-boundary-timing-ui-v2/runtime/ui_session.py',
          91445, 'f858357c0e5089b3129c6d5e076b0213eefdadea2278b29ab94242ab69a4d23a')
PREVIOUS_WORKER = ('candidate/formal-receive-startup-boundary-timing-ui-v1/runtime/ui_session.py',
                   91445, '2b629efa7781bab24adc7e8f127aafb044065755cd50e3c3c772212955e2f9d2')
PREVIOUS_HOST = ('host/device_formal_receive_startup_boundary_timing_ui_v1_check.py',
                 8591, '2c9c2b47fca3b5e6b98d91397c657b579e03f632bde6322a8573cdcf64f5d272')
GRAPH = ('host/formal_receive_startup_boundary_timing_v1_definitions.py', 14907,
         '56e0483b0af1c9490b4415fac6f98f7e679ddf76b3db67c7bdbd1a7c88413f0b')
DEADLINE = ('host/receive_startup_deadline_projection_v3.py', 7569,
            '5d11588de738b23bd9c3bc9c5263c9f89e8308462a013f0466ed59d5478dc2d1')
PREVIOUS_DEADLINE = ('host/receive_startup_deadline_projection_v2.py', 7569,
                     'b4cd05a9c7d3abe3e99da05e8ad72a9a9f13886c2cc8529b330606b7c984d637')
BOUNDARY = ('host/receive_startup_boundary_projection_v1.py', 6911,
            '1ab35b075c6cb03a1eddcd2d789ff5c118fccd4f312dfb96246c65fc93d8e445')
GENERATOR = ('host/generate_formal_receive_startup_boundary_timing_v1.py', 25279,
             '21e3b120007d9d4efb93ed1573c6c1a954b8facfa3a2356fddb99eaa2ae39a1a')
PAYLOAD_BYTES = 4164961
OLD_SUFFIX = b'-formal-receive-startup-alias-clock-ui-v1'
NEW_SUFFIX = b'-formal-receive-startup-boundary-timing-ui-v2'
WORKER_DELTAS = (
    (b"RUNNER_PIN = (79236, '30df3797ed980f435749aa4c9b1e3bfbd2aca9bdb8c7fbff9c72e5f538df42a8')",
     b"RUNNER_PIN = (79244, '76cb6bc68925509c59f1035b5e6b05f88c8886c3f6a5884a08cae3893aa6bc3e')"),
    (b"STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-startup-alias-clock-v1'",
     b"STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-startup-boundary-timing-v1'"),
    (b"STATE_ALIAS = '/tmp/p011-mta-receive-startup-alias-clock-v1'",
     b"STATE_ALIAS = '/tmp/p011-mta-receive-startup-boundary-timing-v1'"),
    (b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-startup-alias-clock-ui-v1'",
     b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-startup-boundary-timing-ui-v2'"))
DEADLINE_DELTAS = ((b'check.__code__.co_firstlineno!=499', b'check.__code__.co_firstlineno!=504'),
                   (b'tb.tb_lineno==1267', b'tb.tb_lineno==1276'),
                   (b'tb.tb_lineno==509', b'tb.tb_lineno==514'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'boundary_ui_pin')
    return raw


def definitions(pin, name):
    raw = fixed(pin)
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def bind_parent_payload(parent, raw):
    """One actual HOST literal, inverse checked; no runtime body replacement."""
    source = ast.parse(raw)
    mains = [row for row in source.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(mains) == 1, 'boundary_ui_parent_main')
    tree = ast.Module(body=copy.deepcopy(mains), type_ignores=[])
    before = copy.deepcopy(tree)
    assignments = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                   len(row.targets) == 1 and isinstance(row.targets[0], ast.Tuple) and
                   parent.shape(row.targets[0]) == parent.shape(ast.parse(
                       'module.DEFINITIONS, module.PAYLOAD_BYTES = GRAPH, 4164334').body[0].targets[0])]
    need(len(assignments) == 1 and parent.shape(assignments[0].value) ==
         parent.shape(ast.parse('GRAPH, 4164334', mode='eval').body), 'boundary_ui_payload_seam')
    original = copy.deepcopy(assignments[0].value)
    assignments[0].value = ast.parse('GRAPH, ' + str(PAYLOAD_BYTES), mode='eval').body
    final = copy.deepcopy(tree)
    assignments[0].value = original
    need(parent.shape(tree) == parent.shape(before), 'boundary_ui_payload_inverse')
    exec(compile(ast.fix_missing_locations(final), str(BASE / SELF), 'exec'), parent.__dict__)


def main():
    parent, parent_raw = definitions(PARENT, 'fixed_boundary_ui_parent_definitions')
    need(parent.WORKER == OLD_WORKER and parent.DEADLINE == PREVIOUS_DEADLINE,
         'boundary_ui_actual_parent')
    worker_raw, old_worker_raw = fixed(WORKER), fixed(OLD_WORKER)
    previous_worker_raw, previous_host_raw = fixed(PREVIOUS_WORKER), fixed(PREVIOUS_HOST)
    need(worker_raw.count(NEW_SUFFIX) == previous_worker_raw.count(
         b'-formal-receive-startup-boundary-timing-ui-v1') == 1 and worker_raw.replace(
         NEW_SUFFIX, b'-formal-receive-startup-boundary-timing-ui-v1', 1) == previous_worker_raw,
         'boundary_ui_previous_worker_inverse')
    need(parent.exact_inverse(worker_raw, old_worker_raw, WORKER_DELTAS),
         'boundary_ui_worker_inverse')
    deadline_raw, previous_deadline_raw = fixed(DEADLINE), fixed(PREVIOUS_DEADLINE)
    need(parent.exact_inverse(deadline_raw, previous_deadline_raw, DEADLINE_DELTAS),
         'boundary_ui_deadline_inverse')
    projection, projection_raw = definitions(BOUNDARY, 'fixed_boundary_projection_definitions')
    fragment = projection.TARGET_FRAGMENT
    need(type(fragment) is bytes and len(fragment) == 5711 and
         hashlib.sha256(fragment).hexdigest() ==
         '07392849191dedcc56a40b4c377fc3775862ff46049c4ea29bd3b3d3ef423d71',
         'boundary_ui_fragment_identity')
    ast.parse(fragment, feature_version=(3, 5))
    generator_raw = fixed(GENERATOR)
    parent.OLD_WORKER, parent.WORKER, parent.GRAPH = OLD_WORKER, WORKER, GRAPH
    parent.OLD_SUFFIX, parent.NEW_SUFFIX = OLD_SUFFIX, NEW_SUFFIX
    parent.WORKER_DELTAS = WORKER_DELTAS
    parent.DEADLINE = DEADLINE
    parent.DEADLINE_DELTAS = ((b'check.__code__.co_firstlineno!=468', b'check.__code__.co_firstlineno!=504'),
                             (b'tb.tb_lineno==1177', b'tb.tb_lineno==1276'),
                             (b'tb.tb_lineno==478', b'tb.tb_lineno==514'))
    parent.SELF, parent.CMDS = SELF, CMDS
    parent.CONTROL_NEW = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-startup-boundary-timing-ui-v2'"
    bind_parent_payload(parent, parent_raw)
    actual_definitions = parent.definitions

    def extended_definitions(pin, name):
        module, raw = actual_definitions(pin, name)
        if pin == parent.PREVIOUS:
            original_definitions = module.definitions

            def with_boundary(source_pin, source_name):
                child, child_raw = original_definitions(source_pin, source_name)
                if source_pin[0] == 'host/device_formal_receive_filecenter_ui_v2_check.py':
                    need(child.INNER_DIAGNOSTIC.endswith(b'\n'), 'boundary_ui_inner_anchor')
                    child.INNER_DIAGNOSTIC += fragment
                return child, child_raw

            module.definitions = with_boundary
        return module, raw

    parent.definitions = extended_definitions
    original_derived = parent.derived_main
    extras = {PARENT[0]: parent_raw, BOUNDARY[0]: projection_raw,
              PREVIOUS_DEADLINE[0]: previous_deadline_raw, GENERATOR[0]: generator_raw,
              PREVIOUS_WORKER[0]: previous_worker_raw, PREVIOUS_HOST[0]: previous_host_raw}

    def derived_main(original, inputs):
        inputs = dict(inputs)
        inputs.update(extras)
        adapted = original_derived(original, inputs)

        def renamed(raw):
            tree = adapted(raw)
            before = copy.deepcopy(tree)
            labels = [row for row in ast.walk(tree) if isinstance(row, ast.Constant) and
                      row.value == 'formal-receive-startup-alias-clock-ui-v1-']
            need(len(labels) == 1, 'boundary_ui_report_label')
            labels[0].value = 'formal-receive-startup-boundary-timing-ui-v2-'
            final = copy.deepcopy(tree)
            labels[0].value = 'formal-receive-startup-alias-clock-ui-v1-'
            need(parent.shape(tree) == parent.shape(before), 'boundary_ui_report_inverse')
            return ast.fix_missing_locations(final)
        return renamed

    parent.derived_main = derived_main
    return parent.main()


if __name__ == '__main__':
    raise SystemExit(main())

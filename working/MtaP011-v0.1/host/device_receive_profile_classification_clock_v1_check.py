"""Default SOURCE; explicit new graph75 preparation/startup-close, no RF/UI.

The actual parent carrier's pure compilation helper is retained. Its main is
not called. Only real new graph pins, provenance and report identities change;
original diagnostic60+cleanup60, Startup10, IO/SHA/close and closed policy stay.
This trial exercises Startup classification but is not a performance A/B.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_profile_classification_clock_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROFILE_CLASSIFICATION_CLOCK_V1_CORE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROFILE_CLASSIFICATION_CLOCK_V1_CORE.cmd')
ORIGIN = ('host/device_receive_filecenter_v1_startup_check.py', 6387,
          '9f78b9edf0458250fc5adafc07a9e910975500e81a84ea13a1b60e84371914a0')
DEFINITIONS = ('host/formal_receive_profile_classification_clock_v1_definitions.py', 16712,
               '3a1cf025b4a088960e6d7a23f44ecac4ff7d3de35082d1c3795e52c377a9169e')
ROOT_NAME = 'p011-mta-receive-profile-classification-clock-v1'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def verify_graph(definitions, helpers, inputs, retain):
    need(definitions.STATE_ALIAS == '/tmp/' + ROOT_NAME and
         definitions.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME and
         definitions.PAYLOAD_BYTES == 4172818,
         'classification_graph_identity')
    pins = definitions.ORIGIN_SOURCE_PINS
    # 69 actual parent provenance rows plus 20 classification rows, not roles.
    need(type(pins) is tuple and len(pins) == 89, 'classification_origin_inventory')
    for pin in pins:
        need(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and pin[1] > 0 and type(pin[2]) is str and
             len(pin[2]) == 64, 'classification_origin_pin')
        retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
    for name, path, size, sha in definitions.FILECENTER_SOURCE_PINS:
        retain(path, helpers.read_fixed(path, (size, sha)))
    need(definitions.verify_inputs(inputs) == 7, 'classification_inverse_closure')
    retain(ORIGIN[0], ORIGIN_RAW)
    retain(PREVIOUS_ORIGIN[0], PREVIOUS_ORIGIN_RAW)


def shape(node):
    return ast.dump(node, include_attributes=False)


def adapted_main(original):
    def adapted(raw):
        tree = original(raw)
        before = copy.deepcopy(tree)
        changed = []
        for row in ast.walk(tree):
            if isinstance(row, ast.Constant) and type(row.value) is str and 'receive-filecenter-v1-startup' in row.value:
                changed.append((row, row.value))
                row.value = row.value.replace('receive-filecenter-v1-startup', 'receive-profile-classification-clock-v1')
        need(len(changed) == 5, 'classification_report_identities')
        readmes = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                   len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme']
        need(len(readmes) == 1, 'classification_readme')
        previous_readme = copy.deepcopy(readmes[0].value)
        readmes[0].value = ast.Constant(value=(
            b'New isolated profile-classification metadata-clock graph75 preparation only. Default SOURCE; '
            b'explicit device mode stages absent exact75 roles and uses original diagnostic60+cleanup60, '
            b'alarm240/host250 and closed-policy gates. Startup preparation retains original10s cap. '
            b'The first classification iteration and actual IO/SHA/import/close/success full checks stay; '
            b'intervening pure classification uses the original authenticated metadata clock. '
            b'Received/Handoff full validation and failure effects during pure classification are deferred '
            b'until the next actual IO full boundary or success full, not per-term failure-order equivalence. '
            b'Actual parent and new source graphs and inverse closure are retained. '
            b'Graph75/4MiB, separate FC9 limits and Publication120/phone15 remain unchanged. '
            b'No FileCenter companion, credentials, UI, RF, phone, HTTP request, audio, transfer or pending handling. '
            b'Original failure and Trial=None parsing are unchanged; raw FAIL is not upgraded. '
            b'Startup-close is not navigation, phone compatibility, transfer or measured performance. '
            b'Only result.json and README.txt are public; raw streams and real pinned inputs stay private.\n'))
        final = copy.deepcopy(tree)
        for row, value in changed:
            row.value = value
        readmes[0].value = previous_readme
        need(shape(tree) == shape(before), 'classification_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


ORIGIN_RAW = (BASE / ORIGIN[0]).read_bytes()
need((len(ORIGIN_RAW), hashlib.sha256(ORIGIN_RAW).hexdigest()) == ORIGIN[1:], 'classification_origin_pin')
previous = types.ModuleType('fixed_classification_carrier_compilation_definitions')
previous.__file__ = str(BASE / ORIGIN[0])
exec(compile(ORIGIN_RAW, previous.__file__, 'exec'), previous.__dict__)
PREVIOUS_ORIGIN, PREVIOUS_ORIGIN_RAW = previous.ORIGIN, previous.ORIGIN_RAW


def main():
    # Load the actual carrier helper definitions with __name__ != __main__.
    # Neither archived wrapper main is called; compile the new narrow PC main.
    namespace = types.ModuleType('new_classification_startup_carrier')
    namespace.__file__ = str(BASE / PREVIOUS_ORIGIN[0])
    exec(compile(PREVIOUS_ORIGIN_RAW, namespace.__file__, 'exec'), namespace.__dict__)
    namespace.SELF, namespace.CMDS, namespace.DEFINITIONS = SELF, CMDS, DEFINITIONS
    namespace.verify_graph = verify_graph
    tree = adapted_main(previous.patched_main)(PREVIOUS_ORIGIN_RAW)
    exec(compile(tree, str(BASE / SELF), 'exec'), namespace.__dict__)
    return namespace.main()


if __name__ == '__main__':
    raise SystemExit(main())

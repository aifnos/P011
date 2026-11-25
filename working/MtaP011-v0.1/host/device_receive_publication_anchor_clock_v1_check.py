"""Default SOURCE; explicit isolated graph75 startup-close, no RF/UI/phone.

Reuse the tested diagnostic60+60 carrier and unchanged closed-policy gates.
Only new graph/input/report identities change. No historical main is called.
This core trial does not exercise or measure the Publication metadata branch.
Definition pin must be sealed after the new SOURCE-only closure is generated.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_publication_anchor_clock_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_PUBLICATION_ANCHOR_CLOCK_V1_CORE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PUBLICATION_ANCHOR_CLOCK_V1_CORE.cmd')
ORIGIN = ('host/device_receive_filecenter_v1_startup_check.py', 6387,
          '9f78b9edf0458250fc5adafc07a9e910975500e81a84ea13a1b60e84371914a0')
# ROOT seals this only from the final fresh graph; unsealed inputs are refused.
DEFINITIONS = ('host/formal_receive_publication_anchor_clock_v1_definitions.py', 15660,
               '8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4')
ROOT_NAME = 'p011-mta-receive-publication-anchor-clock-v1'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def verify_graph(definitions, helpers, inputs, retain):
    need(definitions.STATE_ALIAS == '/tmp/' + ROOT_NAME and
         definitions.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME,
         'publication_anchor_graph_root')
    pins = definitions.ORIGIN_SOURCE_PINS
    # This fixed graph retains 52 parent provenance rows plus 17 new rows.
    # These PC inputs are not target payload roles or resource-cap extensions.
    need(type(pins) is tuple and len(pins) == 69, 'publication_anchor_origin_inventory')
    for pin in pins:
        need(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and pin[1] > 0 and type(pin[2]) is str and
             len(pin[2]) == 64, 'publication_anchor_origin_pin')
        retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
    for name, path, size, sha in definitions.FILECENTER_SOURCE_PINS:
        retain(path, helpers.read_fixed(path, (size, sha)))
    need(definitions.verify_inputs(inputs) == 7, 'publication_anchor_inverse_closure')
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
                row.value = row.value.replace('receive-filecenter-v1-startup', 'receive-publication-anchor-clock-v1')
        need(len(changed) == 5, 'publication_anchor_report_identities')
        readmes = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                   len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme']
        need(len(readmes) == 1, 'publication_anchor_readme')
        previous_readme = copy.deepcopy(readmes[0].value)
        readmes[0].value = ast.Constant(value=(
            b'New isolated Publication anchor-metadata graph75 preparation only. Default SOURCE; explicit '
            b'device mode uses original diagnostic60+cleanup60, alarm240/host250 and exact closed-policy gates. '
            b'Startup preparation keeps its original10s cap and unchanged full private IO/SHA/close checks. '
            b'Only deep fixed Publication ancestor metadata is changed in the new graph; '
            b'this closed-policy Boot/Receiver startup-close trial does not exercise that Publication branch. '
            b'Publication prepare120 and phone observer15 are not enlarged or exercised here. '
            b'The original diagnostic clock markers, graph75/4MiB and separate FC9 bounds are retained. '
            b'No FileCenter companion, credentials, UI, RF, phone, HTTP request, audio, transfer or pending handling. '
            b'Original failure and Trial=None parsing are unchanged; raw FAIL is not upgraded. '
            b'Startup-close PASS is not phone compatibility, Publication progress or measured performance. '
            b'Raw streams and pinned inputs stay private; old sources, main and suites are not replayed.\n'))
        final = copy.deepcopy(tree)
        for row, value in changed:
            row.value = value
        readmes[0].value = previous_readme
        need(shape(tree) == shape(before), 'publication_anchor_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


ORIGIN_RAW = (BASE / ORIGIN[0]).read_bytes()
need((len(ORIGIN_RAW), hashlib.sha256(ORIGIN_RAW).hexdigest()) == ORIGIN[1:], 'publication_anchor_origin_pin')
previous = types.ModuleType('fixed_publication_anchor_carrier_definitions')
previous.__file__ = str(BASE / ORIGIN[0])
exec(compile(ORIGIN_RAW, previous.__file__, 'exec'), previous.__dict__)
PREVIOUS_ORIGIN, PREVIOUS_ORIGIN_RAW = previous.ORIGIN, previous.ORIGIN_RAW


def main():
    need(DEFINITIONS[1] > 0 and len(DEFINITIONS[2]) == 64, 'publication_anchor_definitions_unsealed')
    previous.SELF, previous.CMDS, previous.DEFINITIONS = SELF, CMDS, DEFINITIONS
    previous.verify_graph = verify_graph
    previous.patched_main = adapted_main(previous.patched_main)
    # The preceding wrapper compiles a narrowly derived new main; it never calls
    # the old top-level entry. Acceptance, caps, transport and finalizer stay exact.
    return previous.main()


if __name__ == '__main__':
    raise SystemExit(main())

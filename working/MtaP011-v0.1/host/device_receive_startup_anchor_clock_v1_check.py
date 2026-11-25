"""Default SOURCE; explicit isolated graph75 startup-close, no RF/UI/phone.

Reuse the tested diagnostic60+60 carrier and unchanged closed-policy gates.
Only new graph/input/report identities change. No historical main is called.
Definition pin must be sealed after the new SOURCE-only closure is generated.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_startup_anchor_clock_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_STARTUP_ANCHOR_CLOCK_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_STARTUP_ANCHOR_CLOCK_V1.cmd')
ORIGIN = ('host/device_receive_filecenter_v1_startup_check.py', 6387,
          '9f78b9edf0458250fc5adafc07a9e910975500e81a84ea13a1b60e84371914a0')
# Sealed from ROOT's fresh generated closure; no historical entry is replayed.
DEFINITIONS = ('host/formal_receive_startup_anchor_clock_v1_definitions.py', 14863,
               'e437decd608149a3489340f4e0761bdf0772233862092b57198e0ae5cf488cea')
ROOT_NAME = 'p011-mta-receive-startup-anchor-clock-v1'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def verify_graph(definitions, helpers, inputs, retain):
    need(definitions.STATE_ALIAS == '/tmp/' + ROOT_NAME and
         definitions.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME,
         'startup_alias_graph_root')
    pins = definitions.ORIGIN_SOURCE_PINS
    need(type(pins) is tuple and 0 < len(pins) < 64, 'startup_alias_origin_inventory')
    for pin in pins:
        need(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and pin[1] > 0 and type(pin[2]) is str and
             len(pin[2]) == 64, 'startup_alias_origin_pin')
        retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
    for name, path, size, sha in definitions.FILECENTER_SOURCE_PINS:
        retain(path, helpers.read_fixed(path, (size, sha)))
    need(definitions.verify_inputs(inputs) == 7, 'startup_alias_inverse_closure')
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
                row.value = row.value.replace('receive-filecenter-v1-startup', 'receive-startup-anchor-clock-v1')
        need(len(changed) == 5, 'startup_alias_report_identities')
        readmes = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
                   len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme']
        need(len(readmes) == 1, 'startup_alias_readme')
        previous_readme = copy.deepcopy(readmes[0].value)
        readmes[0].value = ast.Constant(value=(
            b'New isolated startup anchor-metadata graph75. Default SOURCE; explicit '
            b'device mode uses original diagnostic60+cleanup60, alarm240/host250 and exact closed-policy gates. '
            b'Startup preparation keeps the original10s cap, full private IO and file SHA/close checks. '
            b'Only deep fixed startup ancestor metadata uses the retained checked alias clock. '
            b'First/return anchors and original file IO/SHA/import/close checks keep full validation. '
            b'The original five diagnostic clock markers are unchanged; no expanded deadline. '
            b'No FileCenter companion, credentials, UI, RF, phone, HTTP request, audio, transfer or pending handling. '
            b'Startup-close PASS is not phone compatibility or measured phase performance. '
            b'Raw streams and pinned inputs stay private; old sources, main and suites are not replayed.\n'))
        final = copy.deepcopy(tree)
        for row, value in changed:
            row.value = value
        readmes[0].value = previous_readme
        need(shape(tree) == shape(before), 'startup_alias_main_inverse')
        return ast.fix_missing_locations(final)
    return adapted


ORIGIN_RAW = (BASE / ORIGIN[0]).read_bytes()
need((len(ORIGIN_RAW), hashlib.sha256(ORIGIN_RAW).hexdigest()) == ORIGIN[1:], 'startup_alias_origin_pin')
previous = types.ModuleType('fixed_startup_alias_carrier_definitions')
previous.__file__ = str(BASE / ORIGIN[0])
exec(compile(ORIGIN_RAW, previous.__file__, 'exec'), previous.__dict__)
PREVIOUS_ORIGIN, PREVIOUS_ORIGIN_RAW = previous.ORIGIN, previous.ORIGIN_RAW


def main():
    need(DEFINITIONS[1] > 0 and len(DEFINITIONS[2]) == 64, 'startup_alias_definitions_unsealed')
    previous.SELF, previous.CMDS, previous.DEFINITIONS = SELF, CMDS, DEFINITIONS
    previous.verify_graph = verify_graph
    previous.patched_main = adapted_main(previous.patched_main)
    # The preceding wrapper compiles a narrowly derived new main; it never calls
    # the old top-level entry. Acceptance, caps, transport and finalizer stay exact.
    return previous.main()


if __name__ == '__main__':
    raise SystemExit(main())

"""New Receiver FileCenter graph preparation, not a FileCenter/UI/RF trial.

Default SOURCE. Explicit --check-device stages the new fixed graph75 and
runs the original diagnostic60+60 Boot/Receiver startup/close. It does not
create the FileCenter companion or issue either credential pair. The original
startup envelope and closed-policy predicates are retained unchanged.
Only the new definitions and fixed report/input identities are substituted.
No historical checker main, suite, builder or production graph is replayed.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_filecenter_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_FILECENTER_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_FILECENTER_V1_STARTUP.cmd')
ORIGIN = ('host/device_receive_ui_v1_startup_check.py', 11249,
          'ac4f02cfeac7d97de9d763cbc4dedf3f6b6984ef7f1ed8a9615c05ff717d944c')
# Filled only from the final independently inspected mechanical composition.
DEFINITIONS = ('host/formal_receive_filecenter_v1_definitions.py', 13159,
               '632d12d5d4f4cb7f30df634ec3e32b22ca4eadfb2dc03e3c2867cce0ff908414')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def shape(node):
    return ast.dump(node, include_attributes=False)


def verify_graph(definitions, helpers, inputs, retain):
    """Retain exact origin inputs needed by the new seven-source verifier."""
    need(definitions.STATE_ALIAS == '/tmp/p011-mta-formal-receive-filecenter-v1' and
         definitions.STATE_ROOT == '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1',
         'new_graph_root')
    pins = definitions.ORIGIN_SOURCE_PINS
    need(type(pins) is tuple and 0 < len(pins) < 64, 'origin_source_inventory')
    for pin in pins:
        need(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and pin[1] > 0 and type(pin[2]) is str and
             len(pin[2]) == 64, 'origin_source_pin')
        retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
    for name, path, size, sha in definitions.FILECENTER_SOURCE_PINS:
        retain(path, helpers.read_fixed(path, (size, sha)))
    need(definitions.verify_inputs(inputs) == 7, 'new_graph_mechanical_verification')
    retain(ORIGIN[0], ORIGIN_RAW)


def patched_main(raw):
    """A new main with an auditable narrow delta; never call the old main."""
    original = ast.parse(raw, feature_version=(3, 5))
    selected = [row for row in original.body
                if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(selected) == 1, 'origin_main_count')
    source = ast.Module(body=selected, type_ignores=[])
    tree = copy.deepcopy(source)
    main = tree.body[0]
    blocks = [row for row in main.body if isinstance(row, ast.Try)]
    need(len(blocks) == 1, 'origin_main_try')
    block = blocks[0]
    anchor = [at for at, row in enumerate(block.body)
              if isinstance(row, ast.For) and isinstance(row.target, ast.Name) and
              row.target.id == 'path' and
              shape(row.iter) == shape(ast.parse('(SELF,) + CMDS', mode='eval').body)]
    need(len(anchor) == 1, 'origin_inputs_anchor')
    inserted = ast.parse('verify_graph(definitions, helpers, inputs, retain)').body[0]
    block.body.insert(anchor[0], inserted)
    replacements = []
    for row in ast.walk(tree):
        if isinstance(row, ast.Constant) and type(row.value) is str and 'receive-ui-v1-startup' in row.value:
            replacements.append((row, row.value))
            row.value = row.value.replace('receive-ui-v1-startup', 'receive-filecenter-v1-startup')
    need(len(replacements) == 5, 'origin_report_identity_count')
    # The old README is not carried into the new public result.
    readmes = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and
               len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
               row.targets[0].id == 'readme']
    need(len(readmes) == 1, 'origin_readme_count')
    old_readme = copy.deepcopy(readmes[0].value)
    readmes[0].value = ast.Constant(value=(
        b'New Receiver FileCenter graph75 preparation only. Default SOURCE; explicit device mode '
        b'uses original diagnostic60+cleanup60, alarm240/host250 and original closed-policy gates. '
        b'New seven-source root/pin closure is independently verified; all fixed inputs are preserved. '
        b'No FileCenter companion, credentials, UI, RF, phone, HTTP request, audio or file transfer. '
        b'Boot/Receiver startup-close is not FileCenter create/guardian/UI/phone acceptance. '
        b'Raw stdout/stderr/input bytes and exits stay private. Historical main/suites/builders '
        b'are not run; the new main narrowly retains the proven startup carrier algorithm.\n'))
    audit = copy.deepcopy(tree)
    audit_block = next(row for row in audit.body[0].body if isinstance(row, ast.Try))
    del audit_block.body[anchor[0]]
    for row in ast.walk(audit):
        if isinstance(row, ast.Constant) and type(row.value) is str and 'receive-filecenter-v1-startup' in row.value:
            row.value = row.value.replace('receive-filecenter-v1-startup', 'receive-ui-v1-startup')
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme':
            row.value = old_readme
    need(shape(audit) == shape(source), 'startup_main_inverse_delta')
    return ast.fix_missing_locations(tree)


ORIGIN_RAW = (BASE / ORIGIN[0]).read_bytes()
need((len(ORIGIN_RAW), hashlib.sha256(ORIGIN_RAW).hexdigest()) == ORIGIN[1:], 'origin_pin')


def main():
    need(DEFINITIONS[1] > 0 and len(DEFINITIONS[2]) == 64, 'new_definitions_unsealed')
    namespace = types.ModuleType('new_receiver_filecenter_startup_definitions')
    namespace.__file__ = str(BASE / ORIGIN[0])
    # __name__ is not __main__; the historical top-level entry is not invoked.
    exec(compile(ORIGIN_RAW, namespace.__file__, 'exec'), namespace.__dict__)
    namespace.SELF, namespace.CMDS, namespace.DEFINITIONS = SELF, CMDS, DEFINITIONS
    namespace.verify_graph = verify_graph
    exec(compile(patched_main(ORIGIN_RAW), str(BASE / SELF), 'exec'), namespace.__dict__)
    return namespace.main()


if __name__ == '__main__':
    raise SystemExit(main())

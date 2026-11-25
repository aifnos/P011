"""Default SOURCE; explicit existing phone observer on the classification graph.

Only the PC entry composition changes. The pinned 26305-byte phone observer,
trace, strict parsers, native READY and cancellation/finalizer stay original.
No separate pre-staging, UI, accept/send, record cleanup or fabricated phone verdict.
Explicit device mode retains the original runtime preflight/stage/load_owner.
"""
import ast
import copy
import hashlib
from pathlib import Path
import types
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_handoff_classification_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_HANDOFF_CLASSIFICATION_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_HANDOFF_CLASSIFICATION_V1.cmd')
ORIGIN = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
          '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
DEFINITIONS = ('host/formal_receive_profile_classification_clock_v1_definitions.py', 16712,
               '3a1cf025b4a088960e6d7a23f44ecac4ff7d3de35082d1c3795e52c377a9169e')
ROOT_NAME = 'p011-mta-receive-profile-classification-clock-v1'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


ORIGIN_RAW = (BASE / ORIGIN[0]).read_bytes()
need((len(ORIGIN_RAW), digest(ORIGIN_RAW)) == ORIGIN[1:], 'classification_phone_origin_pin')
frozen = types.ModuleType('fixed_handoff_progress_v2_compilation_definitions')
frozen.__file__ = str(BASE / ORIGIN[0])
exec(compile(ORIGIN_RAW, frozen.__file__, 'exec'), frozen.__dict__)


def verify_graph(definitions, helpers, inputs, retain):
    """Read the actual graph's provenance; never encode these extra PC inputs."""
    need(definitions.STATE_ALIAS == '/tmp/' + ROOT_NAME and
         definitions.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME and
         definitions.PAYLOAD_BYTES == 4172818, 'classification_phone_graph_identity')
    pins = definitions.ORIGIN_SOURCE_PINS
    need(type(pins) is tuple and len(pins) == 89 and
         len({pin[0] for pin in pins}) == 89, 'classification_phone_origin_inventory')
    for pin in pins:
        need(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and pin[1] > 0 and type(pin[2]) is str and
             len(pin[2]) == 64 and all(char in '0123456789abcdef' for char in pin[2]),
             'classification_phone_origin_shape')
        retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
    need(len(definitions.FILECENTER_SOURCE_PINS) == 9 and
         sum(row[2] for row in definitions.FILECENTER_SOURCE_PINS) == 113690,
         'classification_phone_filecenter_inputs')
    for name, path, size, sha in definitions.FILECENTER_SOURCE_PINS:
        retain(path, helpers.read_fixed(path, (size, sha)))
    need(definitions.verify_inputs(inputs) == 7, 'classification_phone_inverse_closure')
    # The observer proof below uses its actual frozen SELF, not this wrapper.
    retain(ORIGIN[0], ORIGIN_RAW)


def verify_selected_inputs(inputs, v1):
    need(inputs[ORIGIN[0]] == ORIGIN_RAW and frozen.SELF == ORIGIN[0],
         'classification_phone_observer_source')
    need(frozen.verify_progress_inputs(inputs, v1) == 1,
         'classification_phone_observer_derivation')
    # Seven graph-source closures plus the unchanged phone-v2 observer proof.
    return 8


def seal_source_bundle(out, inputs, program):
    """Private SOURCE ZIP only; public ZIP remains result.json plus README."""
    rows = [('private-inputs/' + path, raw) for path, raw in sorted(inputs.items())]
    rows += [('private-advertise-target.py', program),
             ('private-inputs.json', (out / 'private-inputs.json').read_bytes())]
    path = out / 'private-source.zip'
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in rows:
            bundle.writestr(name, raw)
    with zipfile.ZipFile(path) as bundle:
        need(bundle.namelist() == [name for name, raw in rows] and bundle.testzip() is None and
             all(bundle.read(name) == raw for name, raw in rows),
             'classification_phone_source_zip_readback')
    raw = path.read_bytes()
    return dict(private_source_zip=True, private_source_zip_bytes=len(raw),
                private_source_zip_sha256=digest(raw), private_source_zip_readback=True)


def shape(node):
    return ast.dump(node, include_attributes=False)


def adapted_main(raw):
    """Compile one new main; prove inverse to the actual frozen parent's main."""
    origin_tree = ast.parse(raw.decode('ascii'))
    candidates = [node for node in origin_tree.body if isinstance(node, ast.FunctionDef) and
                  node.name == 'main']
    need(len(candidates) == 1, 'classification_phone_main')
    node = copy.deepcopy(candidates[0])
    before = copy.deepcopy(node)
    undo = []
    identities = []
    for row in ast.walk(node):
        if isinstance(row, ast.Constant) and type(row.value) is str and \
                'receive-handoff-progress-120s-v2' in row.value:
            identities.append(row)
            undo.append((row, 'value', row.value))
            row.value = row.value.replace('receive-handoff-progress-120s-v2',
                                          'receive-handoff-classification-v1')
    need(len(identities) == 3, 'classification_phone_report_identities')
    reports = [row for row in ast.walk(node) if isinstance(row, ast.Assign) and
               len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
               row.targets[0].id == 'report' and isinstance(row.value, ast.Call)]
    need(len(reports) == 1 and isinstance(reports[0].value.func, ast.Name) and
         reports[0].value.func.id == 'dict', 'classification_phone_report')
    changed_fields = dict(graph_derived=True, frozen_compat_v2_graph_reused=False,
                          changed_business_role_count=1, changed_payload_role_count=6,
                          private_changed_role_count=1, old_graph_ast_replayed=True,
                          handshake_observer_changed=False, stage_inventory_changed=False)
    for name, value in changed_fields.items():
        fields = [row for row in reports[0].value.keywords if row.arg == name]
        need(len(fields) == 1, 'classification_phone_report_field')
        undo.append((fields[0], 'value', fields[0].value))
        fields[0].value = ast.Constant(value=value)
    additions = ast.parse("""report.update(
        selected_graph='profile-classification-clock-v1',
        graph_derivation_base='publication-anchor-clock-v1',
        graph_origin_source_count=89, graph_derivation_source_count=7,
        ordinary_changed_roles_from_phone_compat_v2=6,
        private_changed_roles_from_phone_compat_v2=1,
        entry_business_source_changes=0, phone_runtime_source_changes=0,
        payload_bytes=4172818, payload_max_bytes=4194304,
        filecenter_private_source_count=9, filecenter_private_source_bytes=113690,
        filecenter_inputs_are_not_payload_roles=True,
        classification_graph_selected=True, phone_v2_observer_reused=True,
        startup_preparation_max_seconds=10, publication_preparation_max_seconds=120,
        separate_pre_staging_requested=False, runtime_original_stage_retained=True,
        pending_cleanup_requested=False,
        private_source_zip=False, private_source_zip_readback=False)
""").body[0]
    report_index = node.body.index(reports[0])
    node.body.insert(report_index + 1, additions)
    tries = [row for row in node.body if isinstance(row, ast.Try)]
    need(len(tries) == 1, 'classification_phone_main_try')
    actions = tries[0].body
    input_loop = ast.parse('for path in (SELF,) + CMDS + (TEST_SOURCE,):\n'
                           '    retain(path, helpers.read_fixed(path))\n').body[0]
    loops = [row for row in actions if shape(row) == shape(input_loop)]
    need(len(loops) == 1, 'classification_phone_input_loop')
    graph_call = ast.parse('verify_graph(original, helpers, inputs, retain)\n').body[0]
    actions.insert(actions.index(loops[0]), graph_call)
    test_ast = ast.parse("ast.parse(inputs[TEST_SOURCE].decode('ascii'))\n").body[0]
    old_test_parse = [row for row in actions if shape(row) == shape(test_ast)]
    need(len(old_test_parse) == 1, 'classification_phone_old_test_parse')
    test_index = actions.index(old_test_parse[0])
    actions.pop(test_index)
    source_writes = [row for row in actions if isinstance(row, ast.Expr) and
                     isinstance(row.value, ast.Call) and isinstance(row.value.func, ast.Name) and
                     row.value.func.id == 'write_new' and len(row.value.args) == 2 and
                     isinstance(row.value.args[0], ast.BinOp) and
                     isinstance(row.value.args[0].right, ast.Constant) and
                     row.value.args[0].right.value == 'private-inputs.json']
    need(len(source_writes) == 1, 'classification_phone_source_manifest_write')
    source_seal = ast.parse('report.update(seal_source_bundle(out, inputs, program))\n').body[0]
    actions.insert(actions.index(source_writes[0]) + 1, source_seal)
    readmes = [row for row in node.body if isinstance(row, ast.Assign) and
               len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
               row.targets[0].id == 'readme']
    need(len(readmes) == 1, 'classification_phone_readme')
    undo.append((readmes[0], 'value', readmes[0].value))
    readmes[0].value = ast.Constant(value=(
        b'New profile-classification-clock-v1 actual75-role graph; no separate pre-staging step. '
        b'Explicit device mode retains original runtime preflight/stage/load_owner. '
        b'Actual89 provenance inputs and seven forward/inverse source closures are checked. '
        b'Graph75 totals4172818B within4MiB; separate FC9/113690B and origins are PC private inputs, '
        b'not extra target roles. Classification is based on Publication graph, not frozen compat-v2. '
        b'Pinned phone-v2 observer26305B and original trace14820B remain unchanged. '
        b'Original observer source is checked using its own frozen SELF, not the new wrapper. '
        b'All original strict smoke/trace/trial/READY/stage/progress parsers and passed/closed/pending '
        b'predicates remain. Unknown stage DATA are not authentication or Wi-Fi/restore proof. '
        b'Actual native listen/advert must arrive within15s to start the original one120s opportunity; '
        b'first peer/p2p is observed at most15s before original cancel. No renewal. '
        b'Startup10, Publication120, Owner600+cleanup60, alarm780/host790 remain unchanged. '
        b'Classification pure-loop full failure effects defer to next IO/success full validation; '
        b'actual IO/SHA/import/close boundaries stay. No per-term failure-order equivalence claim. '
        b'Parent/F may initialize Wi-Fi; Parent presence is not connectivity proof. '
        b'No accept/send/answer/file/UI/HTTP action/guardian/Disconnect/record cleanup/system writes. '
        b'Default SOURCE compiles only the new main/composition, does not run a runtime graph, old '
        b'main or old tests. Existing old test bytes are retained without AST replay or execution. '
        b'Only explicit --check-device runs the original restricted discovery/cancel observer. '
        b'Use fresh phone readiness, current read-only baseline and actual native READY before clicking. '
        b'Phone compatibility, CONNECT/TLS, transfer and full restoration remain separate evidence. '
        b'Private SOURCE ZIP contains exact PC inputs/target/manifest but no runtime streams. '
        b'Only result.json and README.txt are public; raw stdout/stderr and source ZIP stay private.\n'))
    final = copy.deepcopy(node)
    # Inverse exactly these PC edits. Native dispatch/parsers/verdict are untouched.
    actions.remove(source_seal)
    actions.insert(test_index, old_test_parse[0])
    actions.remove(graph_call)
    node.body.remove(additions)
    for row, field, value in undo:
        setattr(row, field, value)
    need(shape(node) == shape(before), 'classification_phone_main_inverse')
    return ast.fix_missing_locations(ast.Module(body=[final], type_ignores=[]))


def main():
    # Execute only helper definitions with a non-main module identity. The old
    # main is never called; replace it with the separately compiled new main.
    namespace = types.ModuleType('new_handoff_classification_v1_entry')
    namespace.__file__ = str(BASE / ORIGIN[0])
    exec(compile(ORIGIN_RAW, namespace.__file__, 'exec'), namespace.__dict__)
    namespace.__doc__ = __doc__
    namespace.SELF, namespace.CMDS, namespace.COMPAT = SELF, CMDS, DEFINITIONS
    namespace.verify_graph = verify_graph
    namespace.verify_progress_inputs = verify_selected_inputs
    namespace.seal_source_bundle = seal_source_bundle
    tree = adapted_main(ORIGIN_RAW)
    exec(compile(tree, str(BASE / SELF), 'exec'), namespace.__dict__)
    return namespace.main()


if __name__ == '__main__':
    raise SystemExit(main())

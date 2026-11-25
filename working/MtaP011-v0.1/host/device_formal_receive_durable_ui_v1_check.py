"""Fixed durable receive core + actual GUI20 + original navigation/closure.

Default SOURCE only. Explicit stage-device is files only; navigation-test
uses the original launched+20 display under the unchanged 600+60 service.
Pure fixed donor definitions supply the carrier/READY/QtTest algorithms;
no historical main, graph verifier, test suite, builder or phone action runs.
"""
import ast
import base64
import copy
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import sys
import time
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_durable_ui_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_DURABLE_UI_V1_SOURCE_CHECK.cmd',
        'STAGE_MTA_RECEIVE_DURABLE_UI_V1_ASSETS.cmd',
        'TEST_MTA_RECEIVE_DURABLE_UI_V1_NAVIGATION.cmd')
DONOR = ('host/device_formal_receive_filecenter_navigation_anchor_v1_check.py', 24423,
         '0e9f182b8ff01d8de0020fb3513ddd7b08fd4a33d0d58b10e62543d0ce559e42')
DEFINITIONS = ('host/formal_receive_durable_state_v1_definitions.py', 45031,
               'b98c66604bdb250820630f1844e5ea4b0af9bbd260e05388478034e37254e43b')
RUNTIME = 'candidate/formal-receive-durable-ui-v1/runtime/'
NEW_RUNNER = (RUNTIME + 'mta_formal_receive_session.py', 88773,
              'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')
WORKER = (RUNTIME + 'ui_session.py', 95352,
          '7690e2c87f8438c3422986d180381858e7e47588ee60c725c9eb8f73dd628972')
VALIDATOR = ('candidate/formal-receive-durable-state-gui-v1/runtime/ui_assets.py', 12798,
             '67e3d2d1bd7654cde6993d9746c8dd2cb3447676f0fb0f4bb2dec4a2ffb8d1bb')
DELTA = ('candidate/formal-receive-durable-ui-v1/exactsource-delta.json', 15404,
         '465584428e4e9a1c4967279a7e8889abbd66b6d2a77aede06d49ac6dc70929c6')
GENERATOR = ('candidate/formal-receive-durable-ui-v1/generate_mechanical.py', 10893,
             'b1d13651880bcd49ebafbc36b2a54a1c7006d4b1d1e1c95e68791d6962da711f')
GENERATION = ('candidate/formal-receive-durable-ui-v1/generation.json', 2870,
              'bdb78d72f2261a5b3700cd439e1a9d46063363cd0325817874851983e422c084')
SESSION = '559c72ccf8f8ff1b7fc83fb6'
BUNDLE = 'out/mta-ui-receive-durable-state-gui-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 4563,
                  'c3c708bb5e023864c74ca2fd4cff8d0cc9150582cfc1eb865b497e5931b04973')
ASSET_BYTES, PAYLOAD_BYTES = 4192479, 4191752
NEW_SUFFIX = b'-formal-receive-durable-ui-v1'
DEADLINE = ('host/receive_classification_startup_deadline_projection_v1.py', 7569,
            'f0dc91ee5e4a5da4eb8cee5b44702d3d94f5e887727d35dfc9b747caab5d3010')
BOUNDARY = ('host/receive_classification_startup_boundary_projection_v1.py', 6911,
            '39b31c956641b50033626f4ca2a63a2576e1785e5b468481d41a2606f2ff826d')
INNER = ('host/device_formal_receive_filecenter_ui_v2_check.py', 10090,
         'c47f71990c78569a94e16d90b7af652d01d2193a63f918ff30942a271c426e6e')
PROC = ('host/receive_startup_proc_projection_v1.py', 6137,
        'aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002')
REFUSAL = ('host/receive_navigation_refusal_projection_v1.py', 7474,
           'c48192bd978e0bb056f5ea0c74617628b6d9e27936ca9e5697310e39b7bb1bb4')
VENDOR = ('host/receive_navigation_vendor_frame_v2.py', 3738,
          '35f7fde1fc30876747c9d856919656662c6856fb15245c38ae5234e6cf33a4aa')
VENDOR_RESULT = ('results/navigation-vendor-frame-v2-host-20261005-191955-b7881998/result.json', 2379,
                 'c0ff9676ed31fa8cfde2191cd9fb4899dd45fd0cc9c63cdd71d5315892cc59bf')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
HOST_INPUTS = {}
EXTERNAL_INPUTS = {}
FACTS = {}
NAV = EVIDENCE = EXTERNAL_EVIDENCE = SEAL = HOST_OUT = None
READ_ME = (b'Durable runtime75/4191752 and actual GUI20/4192479, independent budgets.\n'
           b'Default SOURCE; explicit exclusive files-only stage or original navigation20 test.\n'
           b'Original75 order, FC9/131072, public51, QtTest and post-READY capture retained.\n'
           b'Original600+60 service, launched+20 navigation, bootstrap2MiB and wire6MiB.\n'
           b'No historical main/graph verifier/test/builder replay or automatic RF/phone/file action.\n'
           b'SOURCE is not P011 runtime, physical output, phone transfer or restoration acceptance.\n'
           b'Raw streams, exception details, exact inputs, carrier and images are private.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    return EVIDENCE.read(BASE / pin[0], key=pin[0], pin=pin[1:])


def selected(pin, names, constants=False):
    """Actual fixed pure AST nodes only; no guarded or archived entry call."""
    raw = fixed(pin)
    tree = ast.parse(raw, feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name in names]
    need(len(nodes) == len(names) and {row.name for row in nodes} == set(names) and
         'main' not in names and all(not row.decorator_list for row in nodes), 'pure_definition_shape')
    if constants:
        nodes = [row for row in tree.body if isinstance(row, ast.Assign) and
                 (all(isinstance(target, ast.Name) and target.id.isupper() for target in row.targets) or
                  len(row.targets) == 1 and isinstance(row.targets[0], ast.Tuple) and
                  tuple(target.id for target in row.targets[0].elts) == ('ASSET_BYTES', 'PAYLOAD_BYTES'))] + nodes
    scope = types.ModuleType('fixed_durable_ui_pure_' + Path(pin[0]).stem)
    scope.__dict__.update(globals())
    scope.__file__ = str(BASE / pin[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), scope.__file__, 'exec'),
         scope.__dict__)
    return scope, raw


def literal_bytes(pin, name):
    raw = fixed(pin)
    rows = [row.value for row in ast.parse(raw, feature_version=(3, 5)).body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'diagnostic_literal')
    value = rows[0]
    if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and
            value.func.attr == 'encode' and isinstance(value.func.value, ast.Constant) and
            type(value.func.value.value) is str and len(value.args) == 1 and not value.keywords and
            isinstance(value.args[0], ast.Constant) and value.args[0].value == 'ascii'):
        fragment = value.func.value.value.encode('ascii')
    else:
        fragment = ast.literal_eval(value)
    need(type(fragment) is bytes and 0 < len(fragment) <= 8192 and fragment.endswith(b'\n'), 'diagnostic_bound')
    return fragment


def module(pin, name):
    raw = fixed(pin)
    value = types.ModuleType(name)
    value.__file__ = str(BASE / pin[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value, raw


def replay(raw, replacements, inverse=False):
    for row in reversed(replacements) if inverse else replacements:
        need(type(row) is dict and set(row) == {'name', 'before', 'after', 'count'} and
             type(row['name']) is str and type(row['count']) is int and row['count'] == 1 and
             type(row['before']) is str and type(row['after']) is str and row['before'] and row['after'] and
             row['before'] != row['after'], 'ui_delta_replacement')
        before, after = row['after' if inverse else 'before'].encode('ascii'), row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == 1, 'ui_delta_count')
        raw = raw.replace(before, after, 1)
    return raw


def verify_ui_overlay(graph, read, inputs):
    spec = json.loads(read(DELTA).decode('ascii'))
    need(spec['schema'] == 'p011-formal-receive-durable-ui-v1-mechanical-delta' and
         spec['evidence'] == 'MECHANICAL_READBACK_NOT_SOURCE_CHECKED' and len(spec['sources']) == 5 and
         len(spec['entries']) == 2 and tuple(spec['generator']) == GENERATOR, 'ui_delta_shape')
    read(GENERATOR); read(GENERATION)
    for pin in spec['sources']:
        read(tuple(pin))
    for entry, expected, count in zip(spec['entries'], (NEW_RUNNER, WORKER), (1, 6)):
        need(tuple(entry['candidate']) == expected and len(entry['replacements']) == count, 'ui_delta_identity')
        before, after = read(tuple(entry['source'])), read(expected)
        need(replay(before, entry['replacements']) == after and
             replay(after, entry['replacements'], True) == before, 'ui_delta_exact_inverse')
    start, end = b'    def original_receive_ui_cancelled_empty(self):\n', b'    def load_owner(self):\n'
    raw = inputs[NEW_RUNNER[0]]
    need(raw.count(start) == raw.count(end) == 1, 'ui_observer_anchor')
    left, right = raw.index(start), raw.index(end)
    block = raw[left:right]
    need(right-left == 9571 and digest(block) == 'a030215a7fb95f9524c11b6afd5998cfba7f26a241ae26a88b8156d6f2a6560c' and
         raw[:left] + raw[right:] == inputs[graph.RUNNER[0]] and
         tuple(spec['entries'][0]['source']) == graph.RUNNER, 'actual_ordinary_runner_overlay')
    old_worker = inputs[spec['entries'][1]['source'][0]]
    worker = inputs[WORKER[0]]
    def definitions_only(source):
        return [ast.dump(row, include_attributes=False) for row in ast.parse(source, feature_version=(3, 5)).body
                if isinstance(row, (ast.FunctionDef, ast.ClassDef))]
    need(definitions_only(old_worker) == definitions_only(worker), 'worker_business_logic_changed')
    scope = {row.targets[0].id: ast.literal_eval(row.value) for row in ast.parse(worker, feature_version=(3, 5)).body
             if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
             row.targets[0].id in ('RUNNER_PIN', 'VALIDATOR_PIN', 'SESSION', 'STATE_ROOT', 'STATE_ALIAS',
                 'READY_SECONDS', 'SMOKE_DISPLAY_SECONDS', 'INTERACTIVE_SECONDS', 'AUDIO_ACK_SECONDS')}
    need(scope == dict(RUNNER_PIN=NEW_RUNNER[1:], VALIDATOR_PIN=VALIDATOR[1:], SESSION=SESSION,
         STATE_ROOT=graph.STATE_ROOT, STATE_ALIAS=graph.STATE_ALIAS, READY_SECONDS=10.0,
         SMOKE_DISPLAY_SECONDS=20.0, INTERACTIVE_SECONDS=600.0, AUDIO_ACK_SECONDS=2.0), 'worker_fixed_identity')
    order = (b'        component.preflight()\n'
             b"        need(component.result['private_assets_verified'], 'private_assets_required')\n"
             b'        component.stage()\n')
    need(worker.count(order) == 1, 'original_preflight_private_stage_order')
    tree = ast.parse(worker, feature_version=(3, 5))
    functions = {row.name: row for row in tree.body if isinstance(row, ast.FunctionDef)}
    need(functions['need'].lineno == 112 and functions['run_fixed'].lineno == 1246 and
         sum(isinstance(row, ast.Call) and row.lineno == 1557 and isinstance(row.func, ast.Name) and
             row.func.id == 'need' and len(row.args) == 2 and isinstance(row.args[1], ast.Constant) and
             row.args[1].value == 'navigation_receive_activity' for row in
             ast.walk(functions['run_fixed'])) == 1, 'refusal_actual_worker_callsite')
    need(raw[:left].count(b'\n') + 1 == 816, 'refusal_actual_observer_line')
    qml = inputs[BUNDLE + '/NavigationTest.qml']
    for token in (b'page.directory==="Received"', b'page.navigationListedGeneration===page.listingGeneration',
                  b'page.listingGeneration>0', b'now-stableAt>=750', b'driver.mouseClick(button',
                  b'finish(true,"received_page_stable")'):
        need(qml.count(token) == 1, 'original_navigation_qml_gate')
    FACTS.update(ui_overlay_inverse_verified=True, observer_bytes=9571, worker_business_unchanged=True,
                 original_preflight_stage_order=True)


def graph_payload(graph, read, inputs):
    """New actual flat graph only; never re-enter historical graph_payload."""
    need(graph.RUNNER == ('candidate/formal-receive-durable-state-v1/runtime/mta_formal_receive_session.py',
         79202, '38b7345454df94b1f5742d8c2f6a91a4cd8d0b1262909d4deacea2d48456008e') and
         graph.PAYLOAD_BYTES == PAYLOAD_BYTES and graph.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-durable-v1' and
         graph.STATE_ALIAS == '/tmp/p011-mta-rx-durable-v1' and len(graph.ORIGIN_SOURCE_PINS) == 164,
         'actual_durable_graph')
    ordinary = graph.manifest_rows(read(graph.MANIFEST))
    private = graph.manifest_rows(read(graph.PRIVATE_MANIFEST), True)
    payload = ordinary + graph.HELPERS + private + (graph.WPA, graph.MONITOR)
    need(len(ordinary) == len(private) == 35 and len(payload) == 75 and
         len({row[0] for row in payload}) == 75 and sum(row[2] for row in payload) == PAYLOAD_BYTES <= 4194304,
         'actual_payload_inventory')
    for name, path, size, sha in payload:
        read((path, size, sha))
    for pin in graph.ORIGIN_SOURCE_PINS + (graph.RUNNER, graph.ORIGINAL_MANIFEST, graph.OLD_PRIVATE_MANIFEST):
        read(pin)
    rows = graph.FILECENTER_SOURCE_PINS
    need(type(rows) is tuple and len(rows) == 9 and sum(row[2] for row in rows) == 113690 <= 131072,
         'filecenter_original_budget')
    for name, path, size, sha in rows:
        read((path, size, sha))
    NAV.FC.FC_ROWS = rows
    need(graph.verify_inputs(inputs) == 9, 'durable_nine_closures')
    factory_pin = next(pin for pin in graph.MECHANICAL_EXPECTED if pin[0] == 'mta_client_receive_factory')[2]
    factory = ast.parse(read(factory_pin), feature_version=(3, 5))
    methods = [row for node in factory.body if isinstance(node, ast.ClassDef) and
               node.name == 'FixedReceiveDeploymentFactory' for row in node.body if
               isinstance(row, ast.FunctionDef) and row.name == 'startup_readonly']
    need(len(methods) == 1 and sum(isinstance(row, ast.Call) and row.lineno == 1379 and
         ast.dump(row.func) == ast.dump(ast.parse('scope.check_active', mode='eval').body) for row in
         ast.walk(methods[0])) == 1, 'actual_factory_diagnostic_callsite')
    verify_ui_overlay(graph, read, inputs)
    FACTS.update(payload_roles=75, ordinary_roles=35, private_roles=35,
                 payload_bytes=PAYLOAD_BYTES, payload_remaining_bytes=2552,
                 filecenter_sources=9, filecenter_bytes=113690, flat_origin_pins=164, mechanical_closures=9)
    return payload


def finalize(out, report, readme):
    """Failure snapshots and private-before-public sealing, not a target gate."""
    try:
        EVIDENCE.snapshot(out, lambda name: name)
        EXTERNAL_EVIDENCE.snapshot(out / 'private-external', lambda name: name)
        need(all((BASE.parent / name).read_bytes() == raw for name, raw in EXTERNAL_INPUTS.items()),
             'external_source_changed')
    except BaseException as error:
        report['passed'] = False
        report['error_kind'] = report.get('error_kind') or 'InputEvidenceError'
        SEAL.fresh(out / 'private-raw/finalize-error.private.txt', traceback.format_exc().encode('utf-8'))
    report.update(source_graph='durable-state-v1', gui_session=SESSION, integration_facts=dict(FACTS),
        checker_exit=0 if report.get('passed') is True else 1,
        business_tests_replayed=0, historical_main_called=False, historical_verify_inputs_called=False,
        input_pins=[dict(path=name, bytes=len(raw), sha256=digest(raw), complete=name not in EVIDENCE.partial)
                    for name, raw in HOST_INPUTS.items()],
        external_input_pins=[dict(path=name, bytes=len(raw), sha256=digest(raw))
                             for name, raw in EXTERNAL_INPUTS.items()])
    sealed = SEAL.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=report['mode'],
        error_kind=sealed['report'].get('error_kind'), error=sealed['report'].get('error'),
        result_dir=str(out), public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


def composed_main(raw):
    """Retain one original PC carrier algorithm; finite AST identity/seal delta."""
    tree = NAV.composed_main(raw, {})
    original = copy.deepcopy(tree)
    changes = []
    def change(parent, field, value):
        before = parent[field] if type(parent) is list else getattr(parent, field)
        changes.append((parent, field, copy.deepcopy(before)))
        NAV.FC.set_child(parent, field, value)
    expressions = (
        ("stage['schema'] == 'p011-formal-receive-filecenter-navigation-gui-v1-stage'",
         "stage['schema'] == 'p011-formal-receive-durable-state-gui-v1-stage'"),
        ("'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-anchor-v1'",
         "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-durable-ui-v1'"),
    )
    for before, after in expressions:
        matches = []
        for parent in ast.walk(tree):
            for field, child in ast.iter_fields(parent):
                for container, slot, item in ([(child, at, item) for at, item in enumerate(child)]
                                             if type(child) is list else [(parent, field, child)]):
                    if isinstance(item, ast.AST) and NAV.FC.shape(item) == NAV.FC.shape(NAV.FC.expression(before)):
                        matches.append((container, slot))
        need(len(matches) == 1, 'durable_main_expression_count')
        change(matches[0][0], matches[0][1], NAV.FC.expression(after))
    body = tree.body[0].body
    for name, replacement in (('out', 'HOST_OUT'), ('inputs', 'HOST_INPUTS')):
        assignments = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                       isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
        need(len(assignments) == 1, 'main_shared_evidence_assignment')
        change(assignments[0], 'value', ast.Name(id=replacement, ctx=ast.Load()))
    results = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
               isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'result']
    need(len(results) == 1 and isinstance(body[-1], ast.Return), 'main_seal_tail')
    at = body.index(results[0])
    tail = copy.deepcopy(body[at:])
    body[at:] = ast.parse('return finalize(out, report, READ_ME)').body
    final = copy.deepcopy(tree)
    body[at:] = tail
    for parent, field, before in reversed(changes):
        NAV.FC.set_child(parent, field, before)
    need(NAV.FC.shape(tree) == NAV.FC.shape(original), 'durable_main_exact_ast_inverse')
    FACTS.update(host_ast_inverse_verified=True, host_output_private_before_public=True,
                 public_fields=51, gui_files=20, gui_bytes=ASSET_BYTES, gui_remaining_bytes=1825,
                 bootstrap_cap=2097152, wire_cap=6291456, host_source_cap=26624,
                 navigation_seconds=20, owner_seconds=600, cleanup_seconds=60,
                 ui_outer_seconds=800, ui_host_seconds=810)
    return ast.fix_missing_locations(final)


def prepare():
    global NAV
    NAV, unused = selected(DONOR, ('need', 'digest', 'fixed', 'selected', 'module', 'asset_helper',
        'ui_program', 'accepted', 'composed_main'), constants=True)
    for name in ('SELF', 'CMDS', 'DEFINITIONS', 'RUNTIME', 'NEW_RUNNER', 'WORKER', 'VALIDATOR',
                 'DELTA', 'SESSION', 'BUNDLE', 'REMOTE', 'STAGE_MANIFEST', 'ASSET_BYTES', 'PAYLOAD_BYTES', 'NEW_SUFFIX'):
        NAV.__dict__[name] = globals()[name]
    NAV.fixed = fixed
    # Populate identity globals before the donor selectors copy their namespaces.
    NAV.FC, unused = NAV.selected(NAV.FC_DONOR, ('need', 'shape', 'expression', 'set_child', 'fixed',
        'definitions', 'asset_helper', 'ui_program', 'new_main'))
    NAV.FC.fixed = fixed
    NAV.ORIGIN_RAW, NAV.DIAGNOSTIC_SOURCE = fixed(NAV.ORIGIN), fixed(NAV.DIAGNOSTIC)
    NAV.FC.ORIGIN_RAW, NAV.FC.DIAGNOSTIC_SOURCE = NAV.ORIGIN_RAW, NAV.DIAGNOSTIC_SOURCE
    NAV.FC.DIAGNOSTIC_RAW = (literal_bytes(NAV.DIAGNOSTIC, 'DIAGNOSTIC') + literal_bytes(INNER, 'INNER_DIAGNOSTIC') +
        literal_bytes(PROC, 'TARGET_FRAGMENT') + literal_bytes(DEADLINE, 'TARGET_FRAGMENT') +
        literal_bytes(BOUNDARY, 'TARGET_FRAGMENT') + literal_bytes(REFUSAL, 'TARGET_FRAGMENT'))
    parser, unused = module(VENDOR, 'fixed_durable_navigation_vendor_v2')
    proof = json.loads(fixed(VENDOR_RESULT).decode('ascii'))
    need(proof['passed'] is True and proof['test_exit'] == 0 and proof['test_timeout'] is False and
         proof['source_preserved'] is True and proof['recorded_evidence_preserved'] is True and
         proof['recorded_navigation_receipt_verified'] is True and proof['device_invoked'] is False and
         (proof['input_pins'][0]['path'], proof['input_pins'][0]['bytes'], proof['input_pins'][0]['sha256']) == VENDOR,
         'vendor_v2_existing_evidence')
    NAV.navigation_receipt = parser.navigation_receipt
    ready, unused = NAV.selected(NAV.READY_DONOR, ('need', 'digest', 'fixed', 'definitions',
        'shape', 'watch_source', 'scanout_main'), ('ReadyCapture',))
    ready.fixed = fixed
    stream, unused = module(NAV.STREAM, 'fixed_durable_original_ready_stream')
    probe, unused = module(NAV.PROBE, 'fixed_durable_original_probe')
    watch_raw = fixed(NAV.WATCHER)
    scanout, scanout_raw = module(NAV.SCANOUT, 'fixed_durable_scanout_definitions')
    ready.scanout_main(scanout, scanout_raw)  # Compile only; no observer or ADB.
    drm = EXTERNAL_EVIDENCE.read(NAV.DRM_PATH, key=NAV.DRM_PATH.relative_to(BASE.parent).as_posix(), pin=NAV.DRM_PIN)
    need(type(drm) is bytes, 'drm_source')
    NAV.READY_CAPTURE = ready.ReadyCapture(stream, probe, ready.watch_source(watch_raw))
    old, origin_raw = module(NAV.ORIGIN, 'fixed_durable_original_carrier_definitions')
    need(origin_raw == NAV.ORIGIN_RAW, 'original_carrier_identity')
    old.__doc__ = __doc__
    NAV.UI_SUCCESS = tuple(key for key in old.UI_SUCCESS if key not in NAV.SMOKE_BOOLS)
    old.SELF, old.CMDS = SELF, CMDS
    for name in ('SESSION', 'BUNDLE', 'REMOTE', 'WORKER', 'VALIDATOR', 'DEFINITIONS',
                 'STAGE_MANIFEST', 'NATIVE', 'ASSET_BYTES', 'PAYLOAD_BYTES', 'NEW_RUNNER',
                 'ORIGIN', 'ORIGIN_RAW', 'DIAGNOSTIC', 'DIAGNOSTIC_SOURCE', 'READY_CAPTURE'):
        old.__dict__[name] = NAV.__dict__[name]
    old.UI_BOOLS += NAV.FILECENTER_FIELDS + NAV.NAVIGATION_BOOLS
    old.UI_COUNTS += ('navigation_display_seconds',)
    old.UI_FIELDS = frozenset(old.UI_BOOLS + old.UI_COUNTS + old.UI_REASONS)
    need(len(old.UI_FIELDS) == 51, 'original_51_field_schema')
    old.asset_helper, old.graph_payload, old.ui_program, old.accepted = (
        NAV.asset_helper, graph_payload, NAV.ui_program, NAV.accepted)
    old.navigation_receipt = NAV.navigation_receipt
    old.HOST_OUT, old.HOST_INPUTS, old.READ_ME, old.finalize = HOST_OUT, HOST_INPUTS, READ_ME, finalize
    original_definitions = old.definitions
    def retained_definitions(path, raw, name):
        value = original_definitions(path, raw, name)
        if path == NAV.NATIVE[0]:
            original_read = value.read_fixed
            def tracked_read(relative, pin=None):
                # Original path/link/type/budget/metadata gates precede any read.
                checked = original_read(relative)
                EVIDENCE._retain(relative, checked)
                if pin is not None and (len(checked), digest(checked)) != pin:
                    raise ValueError('fixed_pin')
                return checked
            value.read_fixed = tracked_read
        return value
    old.definitions = retained_definitions
    # Capture the original seven first-pass inputs before their pin rejection.
    for pin in (NAV.NATIVE, old.UI_CARRIER, old.CARRIER, old.TRANSPORT, VALIDATOR, WORKER, DEFINITIONS):
        fixed(pin)
    for path in (SELF,) + CMDS:
        EVIDENCE.read(BASE / path, key=path)
    exec(compile(composed_main(origin_raw), str(BASE / SELF), 'exec'), old.__dict__)
    return old


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--stage-device'], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    HOST_OUT = BASE / 'results' / ('formal-receive-durable-ui-v1-' +
        ('navigation-test-' if sys.argv[1:] == ['--navigation-test'] else
         'stage-' if sys.argv[1:] else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_durable_host_sealer')
    exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), SEAL.__dict__)
    EVIDENCE, EXTERNAL_EVIDENCE = SEAL.InputEvidence(HOST_INPUTS), SEAL.InputEvidence(EXTERNAL_INPUTS)
    for path in (SELF,) + CMDS:
        EVIDENCE.read(BASE / path, key=path)
    fixed(SEALER)
    try:
        driver = prepare()
        return driver.main()  # Newly compiled identity-bound driver, not archived entry.
    except BaseException as error:
        SEAL.fresh(HOST_OUT / 'private-raw/outer-error.private.txt', traceback.format_exc().encode('utf-8'))
        return finalize(HOST_OUT, dict(passed=False, mode='source' if not sys.argv[1:] else sys.argv[1][2:],
            source_checked=False, source_preserved=False, error_kind=type(error).__name__,
            device_invoked=False, device_execution_unknown=bool(sys.argv[1:]),
            phone_tested=False, restoration_verified=False, old_graphs=0, old_suites=0, old_builders=0), READ_ME)


if __name__ == '__main__':
    raise SystemExit(main())

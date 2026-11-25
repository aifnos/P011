"""Fixed navigation GUI20 and current anchor graph75; SOURCE by default.

Only explicit --stage-device stages files, or --navigation-test launches the
true Receiver600+60 with the original launched+20 display. The original
carrier/finally/stock receipts remain. Worker completion additionally needs
the unique actual QtTest navigation frame and post-READY read-only capture.
No old wrapper main, core test, suite, builder or automatic RF is executed.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import time
import types


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_filecenter_navigation_anchor_v1_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_ANCHOR_V1_CHECK.cmd',
        'STAGE_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_ANCHOR_V1_ASSETS.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_ANCHOR_V1.cmd')
ORIGIN = ('host/device_formal_receive_ui_v1_check.py', 24136,
          'f72c802ab8fbec8cc1e0b228ed8c779dd69752b9fa279ad1b966558c4d095857')
FC_DONOR = ('host/device_formal_receive_filecenter_ui_v1_check.py', 16312,
            '2388ba10e035ca42f250af557cfa040cbe2a16a4aa0d19e58027e89d9bba58c0')
READY_DONOR = ('host/device_formal_receive_filecenter_ui_v4_check.py', 18256,
               '5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556')
DIAGNOSTIC = ('host/device_formal_receive_ui_v3_check.py', 9924,
              '102915d0061ba8834cd40c0a519124cc42e5902f28adaab9516d857d94d44b90')
NATIVE = ('host/device_receive_filecenter_assets_v1_check.py', 46084,
          'cd5dc6cdf074a71d5309b1444e37c2fa0489c0fd5ca62e9fba9860eaa9f8c5e9')
DEFINITIONS = ('host/formal_receive_startup_anchor_clock_v1_definitions.py', 14863,
               'e437decd608149a3489340f4e0761bdf0772233862092b57198e0ae5cf488cea')
RUNTIME = 'candidate/formal-receive-filecenter-navigation-anchor-v1/runtime/'
NEW_RUNNER = (RUNTIME + 'mta_formal_receive_session.py', 85538,
              '9c5786d96a20751b97cae6c5a2d95757892a14092a3a7096ce96cec3a8ccbe40')
WORKER = (RUNTIME + 'ui_session.py', 95247,
          '1c8ba7b41148d1d4261ebeb1245a99d756dfbf9228abae1a7ebada539bba4547')
VALIDATOR = (RUNTIME + 'ui_assets.py', 12642,
             'a620878186a3005f36febf5487675c3031c8831fd91d5e8962660ad99466c4be')
DELTA = ('candidate/formal-receive-filecenter-navigation-anchor-v1/exactsource-delta.json', 20037,
         '80f77027e41acfc3250ed66fac38e9405026ed5f96668a726ea8cb146df461da')
SESSION = 'a87de5c1d0e0b90b35bb2a91'
BUNDLE = 'out/mta-ui-receive-filecenter-navigation-gui-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 4571,
                  '099321f576d36d9a0c798a22028147ccba36a1fb1b316a4adf3c5dab55a5ff75')
ASSET_BYTES, PAYLOAD_BYTES = 4191494, 4166862
NEW_SUFFIX = b'-formal-receive-filecenter-navigation-anchor-v1'
STREAM = ('host/ready_capture_stream_v2.py', 8040,
          '1dbac1b1c4c164b84f53b323acdace78175b00d838229df0251af9c7a596dc9b')
WATCHER = ('host/capture_formal_ui_v7_ready.py', 3650,
           'd3b6934a6b1b1a099345153d615d5cc9ae9c42cb646685187cb8c10e6a5c3c69')
SCANOUT = ('host/capture_ui_scanout_v1.py', 5051,
           '18bddf409d82382319a2ac3fe63125d39314dfc03a9771168737437a9237ab7d')
PROBE = ('host/device_probe.py', 8759,
         'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
DRM_PIN = (4120, '2f8baf2c724a69faab9825f3155f79cc9b9a610a13d9967b02221733c2cf281d')
DRM_PATH = BASE.parent / 'BiliP011-v0.1/host/capture_drm_scanout.py'
FILECENTER_FIELDS = ('filecenter_constructed', 'filecenter_credentials_issued',
                    'filecenter_close_called', 'filecenter_closed', 'filecenter_http_observed',
                    'filecenter_guardian_bound', 'filecenter_audio_settled')
NAVIGATION_BOOLS = ('navigation_test_requested', 'navigation_display_finished',
                    'navigation_cancelled_empty_observed', 'navigation_receive_activity_free')
SMOKE_BOOLS = ('smoke_requested', 'smoke_display_finished', 'smoke_idle_observed')
FC = READY_CAPTURE = None
UI_SUCCESS = ()
ORIGIN_RAW = DIAGNOSTIC_SOURCE = b''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), digest(raw)) == pin[1:], 'navigation_source_pin')
    return raw


def selected(pin, functions, classes=()):
    """Compile actual pure definitions only; never historical wrapper mains."""
    raw = fixed(pin)
    tree = ast.parse(raw, feature_version=(3, 5))
    wanted = functions + classes
    nodes = [row for row in tree.body if
        isinstance(row, ast.FunctionDef) and row.name in functions or
        isinstance(row, ast.ClassDef) and row.name in classes]
    need(len(nodes) == len(wanted) and {row.name for row in nodes} == set(wanted) and
         all(not row.decorator_list for row in nodes), 'navigation_definition_shape')
    scope = types.ModuleType('fixed_navigation_pure_definitions')
    scope.__dict__.update(globals())
    scope.__file__ = str(BASE / pin[0])
    subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(subset, scope.__file__, 'exec'), scope.__dict__)
    need('main' not in {row.name for row in nodes}, 'historical_main_selected')
    return scope, raw


def module(pin, name):
    raw = fixed(pin)
    value = types.ModuleType(name)
    value.__file__ = str(BASE / pin[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value, raw


def navigation_receipt(raw):
    """One complete actual terminal QML frame; no Worker-to-event inference."""
    need(type(raw) is bytes and 0 < len(raw) <= 4194304, 'navigation_log_bound')
    marker = 'P011_MTA NAVIGATION_QTTEST_V1'
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    need(text.count(marker) == 1, 'navigation_frame_count')
    rows = [row for row in text.splitlines(keepends=True) if marker in row]
    need(len(rows) == 1 and rows[0].endswith('\n') and len(rows[0]) <= 2304, 'navigation_frame_complete')
    frame = re.fullmatch(r'(?:qml: )?P011_MTA NAVIGATION_QTTEST_V1 (\{[^\r\n]{1,2048}\})\n', rows[0])
    need(frame is not None, 'navigation_frame_format')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value, 'navigation_json_duplicate')
            value[key] = item
        return value
    value = json.loads(frame.group(1), object_pairs_hook=unique)
    observed = ('ready_observed', 'button_ready_observed', 'cancel_confirmed_observed',
                'fresh_status_approved_observed', 'files_page_observed',
                'received_listing_observed', 'stable_observed')
    forbidden = ('business_start_action_issued', 'file_opened', 'media_played', 'restoration_verified')
    need(type(value) is dict and set(value) == set(observed + forbidden +
         ('schema', 'outcome', 'code', 'click_count')), 'navigation_frame_fields')
    need(value['schema'] == 'navigation_qttest_v1' and value['outcome'] == 'pass' and
         value['code'] == 'received_page_stable' and
         all(type(value[key]) is str for key in ('schema', 'outcome', 'code')) and
         type(value['click_count']) is int and value['click_count'] == 1 and
         all(value[key] is True for key in observed) and
         all(value[key] is False for key in forbidden), 'navigation_frame_refused')
    return value


def asset_helper(helper, validator):
    helper = FC.asset_helper(helper, validator)
    before = helper.TARGET
    edits = (('len(ARTIFACT_ROWS)==19', 'len(ARTIFACT_ROWS)==20', 1),
             ("facts['files_verified']==19", "facts['files_verified']==20", 1),
             ("facts['readback_passes']==38", "facts['readback_passes']==40", 1),
             ("facts['fds_opened']==facts['fds_closed']==27", "facts['fds_opened']==facts['fds_closed']==28", 2),
             ("len(facts['file_bindings'])==19", "len(facts['file_bindings'])==20", 1))
    current = before
    for old, new, count in edits:
        need(current.count(old) == count, 'navigation_stage_count')
        current = current.replace(old, new)
    reverse = current
    for old, new, count in reversed(edits):
        need(reverse.count(new) == count, 'navigation_stage_inverse_count')
        reverse = reverse.replace(new, old)
    need(reverse == before, 'navigation_stage_inverse')
    helper.TARGET = current
    return helper


def graph_payload(graph, read, inputs):
    """Verify the original graph with its original Runner, then literal overlay."""
    payload = FC.graph_payload(graph, read, inputs)
    spec = json.loads(read(DELTA).decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'sources', 'candidates', 'replacements'} and
         spec['schema'] == 'p011-receive-filecenter-navigation-anchor-v1-exact-source-delta' and
         type(spec['sources']) is list and len(spec['sources']) == 7 and
         type(spec['candidates']) is list and len(spec['candidates']) == 2 and
         type(spec['replacements']) is list and len(spec['replacements']) == 21, 'navigation_delta_shape')
    for row in spec['sources']:
        need(type(row) is dict and set(row) == {'role', 'path', 'bytes', 'sha256'}, 'navigation_delta_source')
        read((row['path'], row['bytes'], row['sha256']))
    targets = {'runtime/mta_formal_receive_session.py': NEW_RUNNER,
               'runtime/ui_session.py': WORKER}
    baseline = {row['role']: row['path'] for row in spec['sources']}
    need(baseline['current_anchor_runner'] == graph.RUNNER[0] and
         baseline['actual_gui20_validator_binding'] == VALIDATOR[0], 'navigation_delta_binding')
    for row in spec['candidates']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             (row['path'], row['bytes'], row['sha256']) in (NEW_RUNNER, WORKER), 'navigation_candidate_pin')
        read((row['path'], row['bytes'], row['sha256']))
    before = {'runtime/mta_formal_receive_session.py': inputs[graph.RUNNER[0]],
              'runtime/ui_session.py': inputs[baseline['current_anchor_worker']]}
    current = dict(before)
    for row in spec['replacements']:
        need(type(row) is dict and set(row) == {'name', 'file', 'before', 'after', 'count'} and
             row['file'] in targets and type(row['count']) is int and row['count'] == 1 and
             type(row['before']) is str and type(row['after']) is str and
             row['before'] and row['after'] and row['before'] != row['after'], 'navigation_delta_row')
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(old) == 1, 'navigation_delta_count')
        current[row['file']] = current[row['file']].replace(old, new, 1)
    need(all(raw == inputs[targets[name][0]] for name, raw in current.items()), 'navigation_delta_forward')
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(new) == 1, 'navigation_inverse_count')
        current[row['file']] = current[row['file']].replace(new, old, 1)
    need(current == before, 'navigation_delta_inverse')
    # The cancellation/listing generation gate is actual pinned QML, not data
    # invented by the parser. Its terminal code is accepted only after all events.
    qml = inputs[BUNDLE + '/NavigationTest.qml']
    for token in (b'page.directory==="Received"',
                  b'page.navigationListedGeneration===page.listingGeneration',
                  b'page.listingGeneration>0', b'now-stableAt>=750',
                  b'driver.mouseClick(button', b'finish(true,"received_page_stable")'):
        need(qml.count(token) == 1, 'navigation_qml_gate')
    return payload


def ui_program(inputs, payload, runner, carrier):
    raw, wire = FC.ui_program(inputs, payload, runner, carrier)
    new_wire = b'P011_FORMAL_RECEIVE_FILECENTER_NAVIGATION_ANCHOR_V1\n'
    edits = ((b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],smoke_only=True,filecenter_sources=tuple(fc))',
              b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],navigation_test=True,filecenter_sources=tuple(fc))'),
             (('wire=sys.stdin.buffer.read(' + str(len(wire)) + ')').encode('ascii'),
              ('wire=sys.stdin.buffer.read(' + str(len(new_wire)) + ')').encode('ascii')),
             (('if wire!=' + repr(wire) + ':').encode('ascii'),
              ('if wire!=' + repr(new_wire) + ':').encode('ascii')))
    current = raw
    for old, new in edits:
        need(current.count(old) == 1, 'navigation_program_anchor')
        current = current.replace(old, new, 1)
    reverse = current
    for old, new in reversed(edits):
        need(reverse.count(new) == 1, 'navigation_program_inverse_count')
        reverse = reverse.replace(new, old, 1)
    need(reverse == raw, 'navigation_program_inverse')
    return current, new_wire


def accepted(value, helper, ui):
    if ui:
        return (all(value[key] is True for key in UI_SUCCESS + FILECENTER_FIELDS + NAVIGATION_BOOLS) and
            all(value[key] is False for key in SMOKE_BOOLS) and value['smoke_display_seconds'] == 0 and
            value['navigation_display_seconds'] == 20 and value['resource_pending'] is False and
            value['auto_receive_action_issued'] is False and
            value['physical_ui_verified'] is False and value['receive_trial_claimed'] is False and
            value['receive_trial_claim_count'] == 0 and value['receive_trial_session_attached'] is False and
            value['interactive_window_expired'] is False and value['reason'] == 'receive_filecenter_navigation_finished')
    return (value['complete'] is True and value['reason'] == 'complete' and
        value['resource_pending'] is False and value['staging_pending'] is False and
        all(value[key] is True for key in helper.BOOL_FIELDS if key not in ('resource_pending', 'staging_pending')) and
        value['created_file_count'] in (0, 20) and value['created_directory_count'] in (0, 3, 4) and
        value['original_opened_fd_count'] == value['original_closed_fd_count'] > 0 and
        value['validator_opened_fd_count'] == value['validator_closed_fd_count'] == 28 and
        value['validator_files_verified'] == 20 and value['validator_readback_passes'] == 40)


def composed_main(raw, extra_inputs):
    """One actual Receiver main; exact inverse of this second, bounded delta."""
    tree = FC.new_main(raw)
    before = copy.deepcopy(tree)
    changed = []
    def change(parent, field, value):
        old = parent[field] if type(parent) is list else getattr(parent, field)
        changed.append((parent, field, copy.deepcopy(old)))
        FC.set_child(parent, field, value)
    replacements = (
        ('len(helper.PINS) == 18', 'len(helper.PINS) == 19', 1),
        ('len(helper.ASSET_PINS) == 19', 'len(helper.ASSET_PINS) == 20', 1),
        ("stage['staged_file_count'] == 19", "stage['staged_file_count'] == 20", 1),
        ("stage['payload_file_count'] == 18", "stage['payload_file_count'] == 19", 1),
        ('ui_program(inputs, payload, graph.RUNNER, carrier)', 'ui_program(inputs, payload, NEW_RUNNER, carrier)', 1),
        ("'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-ui-v1'",
         "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-anchor-v1'", 1),
        ("stage['schema'] == 'p011-formal-receive-filecenter-ui-v1-stage'",
         "stage['schema'] == 'p011-formal-receive-filecenter-navigation-gui-v1-stage'", 1),
    )
    for source, target, expected in replacements:
        matches = []
        for parent in ast.walk(tree):
            for field, child in ast.iter_fields(parent):
                children = [(child, at, item) for at, item in enumerate(child)] if type(child) is list else [(parent, field, child)]
                for container, slot, item in children:
                    if isinstance(item, ast.AST) and FC.shape(item) == FC.shape(FC.expression(source)):
                        matches.append((container, slot))
        need(len(matches) == expected, 'navigation_main_expression_count')
        for parent, field in matches:
            change(parent, field, FC.expression(target))
    body = tree.body[0].body
    seeds = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
             isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'inputs']
    need(len(seeds) == 1 and isinstance(seeds[0].value, ast.Dict), 'navigation_inputs_shape')
    extra = copy.deepcopy(seeds[0].value)
    for path, value in extra_inputs.items():
        extra.keys.append(ast.Constant(value=path)); extra.values.append(ast.Constant(value=value))
    change(seeds[0], 'value', extra)
    counters = dict(argument=0, mode=0, attributes=0, label=0, asset_count=0)
    for row in list(ast.walk(tree)):
        if isinstance(row, ast.Constant) and row.value == '--ui-smoke':
            change(row, 'value', '--navigation-test'); counters['argument'] += 1
        elif isinstance(row, ast.Constant) and row.value == 'ui-smoke':
            change(row, 'value', 'navigation-test'); counters['mode'] += 1
        elif isinstance(row, ast.Constant) and row.value == 'formal-receive-filecenter-ui-v1-':
            change(row, 'value', 'formal-receive-filecenter-navigation-anchor-v1-'); counters['label'] += 1
        elif isinstance(row, ast.Attribute) and isinstance(row.value, ast.Name) and row.value.id == 'args' and row.attr == 'ui_smoke':
            change(row, 'attr', 'navigation_test'); counters['attributes'] += 1
        elif isinstance(row, ast.keyword) and row.arg == 'asset_files':
            need(FC.shape(row.value) == FC.shape(FC.expression('19')), 'navigation_report_count')
            change(row, 'value', FC.expression('20')); counters['asset_count'] += 1
    need(counters == dict(argument=1, mode=5, attributes=4, label=1, asset_count=1), 'navigation_main_literal_count')
    launch = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
              FC.shape(row.func) == FC.shape(FC.expression('carrier.run_carrier')) and
              len(row.args) == 5 and isinstance(row.args[2], ast.Constant) and row.args[2].value == 'carrier-launch']
    need(len(launch) == 1, 'navigation_capture_launch')
    change(launch[0], 'func', FC.expression('READY_CAPTURE.carrier'))
    change(launch[0], 'args', [ast.Name(id='carrier', ctx=ast.Load())] + launch[0].args)
    passes = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
              isinstance(row.targets[0], ast.Subscript) and isinstance(row.targets[0].value, ast.Name) and
              row.targets[0].value.id == 'report' and isinstance(row.targets[0].slice, ast.Constant) and
              row.targets[0].slice.value == 'passed']
    readmes = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
               isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'readme']
    need(len(passes) == len(readmes) == 1, 'navigation_completion_shape')
    change(passes[0], 'value', ast.BoolOp(op=ast.And(), values=[passes[0].value, FC.expression(
        "mode != 'navigation-test' or report.get('navigation_receipt_verified') is True and READY_CAPTURE.complete()")]))
    side = ast.parse("""report['ready_capture'] = READY_CAPTURE.facts()
report['navigation_receipt'] = None
report['navigation_receipt_verified'] = False
if mode == 'navigation-test':
 try:
  need(report['private_ui_logs_collected'] is True, 'navigation_logs_not_collected')
  report['navigation_receipt'] = navigation_receipt((private / 'ui-logs' / 'candidate.stderr.raw').read_bytes())
  report['navigation_receipt_verified'] = True
 except BaseException:
  write_new(private / 'navigation-receipt-error.private.txt', traceback.format_exc().encode('utf-8'))
  if report['error_kind'] is None: report['error_kind'] = 'NavigationReceiptError'
""").body
    at = body.index(passes[0])
    body[at:at] = side
    change(readmes[0], 'value', ast.Constant(value=(
        b'Default SOURCE; explicit GUI20 file-only stage or one real navigation-test600+60. '
        b'Current anchor graph75/4166862 and original Runner proof retained; only UI Runner adds the frozen passive observer. '
        b'Actual Item click/cancel/fresh-status/Received-current-generation/stability must produce one strict terminal QML PASS frame. '
        b'Original Worker, FC7, no automatic RF/claim/session, raw/exits/stock/finally gates and post-READY watch/DRM all required. '
        b'Navigation20 is launched+20, never a renewed cap; smoke fields remain false/0. '
        b'GUI20/4191494, graph4MiB, FC9/131072, bootstrap2MiB, wire6MiB and HOST26KiB budgets unchanged. '
        b'Images/private raw failures and inputs stay outside the metadata-only ZIP. No physical output/phone/RF acceptance.\n')))
    final = copy.deepcopy(tree)
    for row in side:
        body.remove(row)
    for parent, field, original in reversed(changed):
        FC.set_child(parent, field, original)
    need(FC.shape(tree) == FC.shape(before), 'navigation_main_inverse')
    return ast.fix_missing_locations(final)


def main():
    global FC, READY_CAPTURE, UI_SUCCESS, ORIGIN_RAW, DIAGNOSTIC_SOURCE
    fc_names = ('need', 'shape', 'expression', 'set_child', 'fixed', 'definitions',
                'asset_helper', 'graph_payload', 'ui_program', 'new_main')
    FC, fc_raw = selected(FC_DONOR, fc_names)
    ORIGIN_RAW, DIAGNOSTIC_SOURCE = fixed(ORIGIN), fixed(DIAGNOSTIC)
    diag_tree = ast.parse(DIAGNOSTIC_SOURCE, feature_version=(3, 5))
    diag = [row.value for row in diag_tree.body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'DIAGNOSTIC']
    need(len(diag) == 1, 'navigation_diagnostic_literal')
    FC.ORIGIN_RAW, FC.DIAGNOSTIC_SOURCE = ORIGIN_RAW, DIAGNOSTIC_SOURCE
    FC.DIAGNOSTIC_RAW = ast.literal_eval(diag[0])
    ready, ready_raw = selected(READY_DONOR, ('need', 'digest', 'fixed', 'definitions',
        'shape', 'watch_source', 'scanout_main'), ('ReadyCapture',))
    stream, stream_raw = module(STREAM, 'navigation_original_stream')
    probe, probe_raw = module(PROBE, 'navigation_original_probe')
    watch_raw, scanout_raw = fixed(WATCHER), fixed(SCANOUT)
    source_scanout, _ = module(SCANOUT, 'navigation_source_scanout_definitions')
    ready.scanout_main(source_scanout, scanout_raw)  # Compile only; never invoke.
    drm_raw = DRM_PATH.read_bytes()
    need((len(drm_raw), digest(drm_raw)) == DRM_PIN, 'navigation_drm_pin')
    READY_CAPTURE = ready.ReadyCapture(stream, probe, ready.watch_source(watch_raw))
    old, old_raw = module(ORIGIN, 'navigation_original_receiver_carrier_definitions')
    need(old_raw == ORIGIN_RAW, 'navigation_original_readback')
    old.__doc__ = __doc__
    UI_SUCCESS = tuple(key for key in old.UI_SUCCESS if key not in SMOKE_BOOLS)
    old.SELF, old.CMDS = SELF, CMDS
    for name in ('SESSION', 'BUNDLE', 'REMOTE', 'WORKER', 'VALIDATOR', 'DEFINITIONS',
                 'STAGE_MANIFEST', 'NATIVE', 'ASSET_BYTES', 'PAYLOAD_BYTES', 'NEW_RUNNER',
                 'ORIGIN', 'ORIGIN_RAW', 'DIAGNOSTIC', 'DIAGNOSTIC_SOURCE', 'READY_CAPTURE'):
        old.__dict__[name] = globals()[name]
    old.UI_BOOLS += FILECENTER_FIELDS + NAVIGATION_BOOLS
    old.UI_COUNTS += ('navigation_display_seconds',)
    old.UI_FIELDS = frozenset(old.UI_BOOLS + old.UI_COUNTS + old.UI_REASONS)
    need(len(old.UI_FIELDS) == 51, 'navigation_component_schema')
    old.asset_helper, old.graph_payload, old.ui_program, old.accepted = (
        asset_helper, graph_payload, ui_program, accepted)
    old.navigation_receipt = navigation_receipt
    # Both old wrappers are pure definition donors, not main-call layers.
    extra = {FC_DONOR[0]: fc_raw, READY_DONOR[0]: ready_raw, STREAM[0]: stream_raw,
             PROBE[0]: probe_raw, WATCHER[0]: watch_raw, SCANOUT[0]: scanout_raw}
    exec(compile(composed_main(ORIGIN_RAW, extra), str(BASE / SELF), 'exec'), old.__dict__)
    return old.main()


if __name__ == '__main__':
    raise SystemExit(main())

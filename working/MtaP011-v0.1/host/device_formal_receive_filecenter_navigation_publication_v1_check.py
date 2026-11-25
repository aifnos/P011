"""Publication navigation adapter: fixed pure donors, SOURCE by default.

The real graph keeps its ordinary Runner and 75 roles. Only the UI overlay
retains the already frozen passive cancelled-empty observer and four Worker
literals. No historical navigation main is called. After-run diagnostics add
only retained deadline/boundary metadata; original 51 fields, GUI20, caps,
closure, QtTest receipt and post-READY capture remain mandatory.
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
SELF = 'host/device_formal_receive_filecenter_navigation_publication_v1_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_PUBLICATION_V1_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_PUBLICATION_V1.cmd')
DONOR = ('host/device_formal_receive_filecenter_navigation_anchor_v1_check.py', 24423,
         '0e9f182b8ff01d8de0020fb3513ddd7b08fd4a33d0d58b10e62543d0ce559e42')
DEFINITIONS = ('host/formal_receive_publication_anchor_clock_v1_definitions.py', 15660,
               '8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4')
RUNTIME = 'candidate/formal-receive-filecenter-navigation-publication-v1/runtime/'
NEW_RUNNER = (RUNTIME + 'mta_formal_receive_session.py', 85546,
              '521f5110bafdbde3a3539fff5f2b2a53a911a8e1008597ca646e3b0acff8ca8b')
WORKER = (RUNTIME + 'ui_session.py', 95260,
          '2b8c413d2fb39b3c5b03958a0b9ab59b196e626bf15eba1899dcd8365080d938')
VALIDATOR = ('candidate/formal-receive-filecenter-navigation-anchor-v1/runtime/ui_assets.py', 12642,
             'a620878186a3005f36febf5487675c3031c8831fd91d5e8962660ad99466c4be')
DELTA = ('candidate/formal-receive-filecenter-navigation-publication-v1/exactsource-delta.json', 5730,
         '63108a204b26f1d4a47fc556e5b4459f7ce99dc80516783af358f7cfe412080d')
DEADLINE = ('host/receive_publication_startup_deadline_projection_v1.py', 7569,
            'ed1a2d4e95de159edc9c7f90ceed12e7e00a22140136d8bc4298ac73178fb033')
BOUNDARY = ('host/receive_publication_startup_boundary_projection_v1.py', 6911,
            '8c85b1128d4a5fd15f4e6973ad0714288a07cbe33a0203c1dbd232752e545180')
NEW_SUFFIX = b'-formal-receive-filecenter-navigation-publication-v1'
PAYLOAD_BYTES = 4169378
BINDING_SOURCES = (
    ('current_anchor_runner', 'candidate/formal-receive-startup-anchor-clock-v1/runtime/mta_formal_receive_session.py',
     79238, '8bff07e82b49d5d6bd540b78dc20179ae842f417c5a3b8d12fd042770741c93b'),
    ('current_navigation_runner', 'candidate/formal-receive-filecenter-navigation-anchor-v1/runtime/mta_formal_receive_session.py',
     85538, '9c5786d96a20751b97cae6c5a2d95757892a14092a3a7096ce96cec3a8ccbe40'),
    ('current_navigation_worker', 'candidate/formal-receive-filecenter-navigation-anchor-v1/runtime/ui_session.py',
     95247, '1c8ba7b41148d1d4261ebeb1245a99d756dfbf9228abae1a7ebada539bba4547'),
    ('actual_publication_runner', 'candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_formal_receive_session.py',
     79246, '71b42ad391844cc67b86c019f80d96ade720dbe4be73270f12ce6210bf5ba5a6'),
    ('actual_gui20_validator_binding', VALIDATOR[0], VALIDATOR[1], VALIDATOR[2]),
)
NAV = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), digest(raw)) == pin[1:], 'publication_navigation_source_pin')
    return raw


def donor():
    """Select fixed constants and ten pure defs; original main is excluded."""
    raw = fixed(DONOR)
    tree = ast.parse(raw, feature_version=(3, 5))
    names = ('need', 'digest', 'fixed', 'selected', 'module', 'navigation_receipt',
             'asset_helper', 'ui_program', 'accepted', 'composed_main')
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in names]
    constants = [row for row in tree.body if isinstance(row, ast.Assign) and
                 all(isinstance(target, ast.Name) and target.id.isupper() for target in row.targets)]
    # Retain the donor's original paired budget assignment as actual AST;
    # the current Publication PAYLOAD_BYTES is rebound below, not invented.
    budgets = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
               isinstance(row.targets[0], ast.Tuple) and
               all(isinstance(target, ast.Name) for target in row.targets[0].elts) and
               tuple(target.id for target in row.targets[0].elts) == ('ASSET_BYTES', 'PAYLOAD_BYTES')]
    need(len(budgets) == 1 and ast.literal_eval(budgets[0].value) == (4191494, 4166862),
         'publication_donor_original_budgets')
    constants += budgets
    need(len(functions) == len(names) and {row.name for row in functions} == set(names) and
         all(not row.decorator_list for row in functions) and
         not any(row.name == 'main' for row in functions), 'publication_donor_definitions')
    subset = ast.Module(body=constants + functions, type_ignores=[])
    before = copy.deepcopy(subset)
    literals = (
        ("'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-anchor-v1'",
         "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-publication-v1'"),
        ('formal-receive-filecenter-navigation-anchor-v1-', 'formal-receive-filecenter-navigation-publication-v1-'),
        (b'P011_FORMAL_RECEIVE_FILECENTER_NAVIGATION_ANCHOR_V1\n',
         b'P011_FORMAL_RECEIVE_FILECENTER_NAVIGATION_PUBLICATION_V1\n'),
    )
    changes = []
    for source, target in literals:
        matches = [row for function in functions for row in ast.walk(function)
                   if isinstance(row, ast.Constant) and row.value == source]
        need(len(matches) == 1, 'publication_donor_literal_count')
        changes.append((matches[0], source))
        matches[0].value = target
    old_phrase = b'Current anchor graph75/4166862'
    new_phrase = b'Current Publication graph75/4169378'
    readmes = [row for function in functions for row in ast.walk(function)
               if isinstance(row, ast.Constant) and type(row.value) is bytes and old_phrase in row.value]
    need(len(readmes) == 1 and readmes[0].value.count(old_phrase) == 1, 'publication_donor_readme')
    changes.append((readmes[0], readmes[0].value))
    readmes[0].value = readmes[0].value.replace(old_phrase, new_phrase, 1)
    final = copy.deepcopy(subset)
    for row, original in reversed(changes):
        row.value = original
    need(ast.dump(subset, include_attributes=False) == ast.dump(before, include_attributes=False),
         'publication_donor_inverse')
    value = types.ModuleType('fixed_publication_navigation_pure_definitions')
    value.__dict__.update(globals())
    value.__file__ = str(BASE / SELF)
    exec(compile(ast.fix_missing_locations(final), value.__file__, 'exec'), value.__dict__)
    for name in ('SELF', 'CMDS', 'DEFINITIONS', 'RUNTIME', 'NEW_RUNNER', 'WORKER',
                 'VALIDATOR', 'DELTA', 'NEW_SUFFIX', 'PAYLOAD_BYTES'):
        value.__dict__[name] = globals()[name]
    return value, raw


def graph_payload(graph, read, inputs):
    """Validate real ordinary graph, then separately prove pinned UI overlays."""
    payload = NAV.FC.graph_payload(graph, read, inputs)
    need(graph.RUNNER == BINDING_SOURCES[3][1:] and
         graph.STATE_ROOT == '/var/volatile/tmp/p011-mta-receive-publication-anchor-clock-v1' and
         graph.STATE_ALIAS == '/tmp/p011-mta-receive-publication-anchor-clock-v1' and
         type(graph.ORIGIN_SOURCE_PINS) is tuple and len(graph.ORIGIN_SOURCE_PINS) == 69,
         'publication_original_graph_binding')
    spec = json.loads(read(DELTA).decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'sources', 'candidates', 'replacements'} and
         spec['schema'] == 'p011-receive-filecenter-navigation-publication-v1-exact-source-delta' and
         spec['evidence'] == 'source_data_only_not_executed' and
         type(spec['sources']) is list and len(spec['sources']) == 5 and
         type(spec['candidates']) is list and len(spec['candidates']) == 2 and
         type(spec['replacements']) is list and len(spec['replacements']) == 11, 'publication_binding_shape')
    for row, expected in zip(spec['sources'], BINDING_SOURCES):
        need(type(row) is dict and set(row) == {'role', 'path', 'bytes', 'sha256'} and
             (row['role'], row['path'], row['bytes'], row['sha256']) == expected, 'publication_binding_source')
        read(expected[1:])
    for row, expected in zip(spec['candidates'], (NEW_RUNNER, WORKER)):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             (row['path'], row['bytes'], row['sha256']) == expected, 'publication_candidate_pin')
        read(expected)
    targets = {'runtime/mta_formal_receive_session.py': NEW_RUNNER, 'runtime/ui_session.py': WORKER}
    before = {'runtime/mta_formal_receive_session.py': inputs[BINDING_SOURCES[1][1]],
              'runtime/ui_session.py': inputs[BINDING_SOURCES[2][1]]}
    current = dict(before)
    for at, row in enumerate(spec['replacements']):
        runner = at < 7
        expected_file = 'runtime/mta_formal_receive_session.py' if runner else 'runtime/ui_session.py'
        expected_count = 2 if at == 2 else 1
        expected_name = ('runner_mechanical_' + str(at)) if runner else ('worker_mechanical_' + str(at - 7))
        need(type(row) is dict and set(row) == {'name', 'file', 'before', 'after', 'count'} and
             row['name'] == expected_name and row['file'] == expected_file and
             type(row['count']) is int and row['count'] == expected_count and
             type(row['before']) is str and type(row['after']) is str and
             row['before'] and row['after'] and row['before'] != row['after'], 'publication_binding_row')
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(old) == row['count'], 'publication_forward_count')
        current[row['file']] = current[row['file']].replace(old, new)
    need(all(raw == inputs[targets[name][0]] for name, raw in current.items()), 'publication_forward_exact')
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(new) == row['count'], 'publication_inverse_count')
        current[row['file']] = current[row['file']].replace(new, old)
    need(current == before, 'publication_inverse_exact')
    # The actual observer alone separates each UI Runner from its real ordinary
    # Runner. No virtual ordinary bytes are fed to graph.verify_inputs.
    start = b'    def original_receive_ui_cancelled_empty(self):\n'
    end = b'    def load_owner(self):\n'
    def split_observer(raw):
        need(raw.count(start) == raw.count(end) == 1, 'publication_observer_anchor')
        left, right = raw.index(start), raw.index(end)
        need(left < right and right - left == 6300, 'publication_observer_bound')
        return raw[:left] + raw[right:], raw[left:right]
    old_base, old_observer = split_observer(before['runtime/mta_formal_receive_session.py'])
    new_base, new_observer = split_observer(inputs[NEW_RUNNER[0]])
    need(old_base == inputs[BINDING_SOURCES[0][1]] and new_base == inputs[graph.RUNNER[0]] and
         old_observer == new_observer, 'publication_original_observer_exact')
    qml = inputs[NAV.BUNDLE + '/NavigationTest.qml']
    for token in (b'page.directory==="Received"',
                  b'page.navigationListedGeneration===page.listingGeneration',
                  b'page.listingGeneration>0', b'now-stableAt>=750',
                  b'driver.mouseClick(button', b'finish(true,"received_page_stable")'):
        need(qml.count(token) == 1, 'publication_navigation_qml_gate')
    return payload


def main():
    global NAV
    NAV, donor_raw = donor()
    fc_names = ('need', 'shape', 'expression', 'set_child', 'fixed', 'definitions',
                'asset_helper', 'graph_payload', 'ui_program', 'new_main')
    NAV.FC, fc_raw = NAV.selected(NAV.FC_DONOR, fc_names)
    NAV.ORIGIN_RAW, NAV.DIAGNOSTIC_SOURCE = NAV.fixed(NAV.ORIGIN), NAV.fixed(NAV.DIAGNOSTIC)
    diag_tree = ast.parse(NAV.DIAGNOSTIC_SOURCE, feature_version=(3, 5))
    diag = [row.value for row in diag_tree.body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'DIAGNOSTIC']
    need(len(diag) == 1, 'publication_generic_diagnostic_literal')
    deadline, deadline_raw = NAV.module(DEADLINE, 'publication_deadline_literal_definitions')
    boundary, boundary_raw = NAV.module(BOUNDARY, 'publication_boundary_literal_definitions')
    generic = ast.literal_eval(diag[0])
    need(type(generic) is bytes and type(deadline.TARGET_FRAGMENT) is bytes and
         type(boundary.TARGET_FRAGMENT) is bytes and
         all(raw.endswith(b'\n') for raw in (generic, deadline.TARGET_FRAGMENT, boundary.TARGET_FRAGMENT)),
         'publication_diagnostic_fragments')
    NAV.FC.ORIGIN_RAW, NAV.FC.DIAGNOSTIC_SOURCE = NAV.ORIGIN_RAW, NAV.DIAGNOSTIC_SOURCE
    NAV.FC.DIAGNOSTIC_RAW = generic + deadline.TARGET_FRAGMENT + boundary.TARGET_FRAGMENT
    ready, ready_raw = NAV.selected(NAV.READY_DONOR, ('need', 'digest', 'fixed', 'definitions',
        'shape', 'watch_source', 'scanout_main'), ('ReadyCapture',))
    stream, stream_raw = NAV.module(NAV.STREAM, 'publication_original_stream')
    probe, probe_raw = NAV.module(NAV.PROBE, 'publication_original_probe')
    watch_raw, scanout_raw = NAV.fixed(NAV.WATCHER), NAV.fixed(NAV.SCANOUT)
    source_scanout, _ = NAV.module(NAV.SCANOUT, 'publication_source_scanout_definitions')
    ready.scanout_main(source_scanout, scanout_raw)  # Compile only, never invoke.
    drm_raw = NAV.DRM_PATH.read_bytes()
    need((len(drm_raw), digest(drm_raw)) == NAV.DRM_PIN, 'publication_drm_pin')
    NAV.READY_CAPTURE = ready.ReadyCapture(stream, probe, ready.watch_source(watch_raw))
    old, old_raw = NAV.module(NAV.ORIGIN, 'publication_original_receiver_carrier_definitions')
    need(old_raw == NAV.ORIGIN_RAW, 'publication_original_readback')
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
    need(len(old.UI_FIELDS) == 51, 'publication_component_schema')
    old.asset_helper, old.graph_payload, old.ui_program, old.accepted = (
        NAV.asset_helper, graph_payload, NAV.ui_program, NAV.accepted)
    old.navigation_receipt = NAV.navigation_receipt
    extra = {DONOR[0]: donor_raw, NAV.FC_DONOR[0]: fc_raw, NAV.READY_DONOR[0]: ready_raw,
             NAV.STREAM[0]: stream_raw, NAV.PROBE[0]: probe_raw, NAV.WATCHER[0]: watch_raw,
             NAV.SCANOUT[0]: scanout_raw, DEADLINE[0]: deadline_raw, BOUNDARY[0]: boundary_raw}
    exec(compile(NAV.composed_main(NAV.ORIGIN_RAW, extra), str(BASE / SELF), 'exec'), old.__dict__)
    return old.main()


if __name__ == '__main__':
    raise SystemExit(main())

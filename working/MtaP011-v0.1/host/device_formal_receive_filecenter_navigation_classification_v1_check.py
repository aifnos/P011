"""Classification graph plus unchanged v3 navigation diagnosis, SOURCE default.

Only the already HOST-checked classification block changes business behavior.
Both actual parent and new byte graphs are verified, never virtual old inputs.
The historical main is not invoked; one provenance-only AST delta compiles the
fixed PC driver. GUI20, public51, all caps, admission and closure stay unchanged.
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
SELF = 'host/device_formal_receive_filecenter_navigation_classification_v1_check.py'
CMDS = ('HOST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_CLASSIFICATION_V1_CHECK.cmd',
        'TEST_MTA_FORMAL_RECEIVE_FILECENTER_NAVIGATION_CLASSIFICATION_V1.cmd')
PARENT_HOST = ('host/device_formal_receive_filecenter_navigation_publication_v3_check.py', 23950,
               'e9bcb9452a306a8de3942e3f984003c345971829782191cd8b83a9ca04691f30')
PARENT_DEFINITIONS = ('host/formal_receive_publication_anchor_clock_v1_definitions.py', 15660,
                      '8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4')
DEFINITIONS = ('host/formal_receive_profile_classification_clock_v1_definitions.py', 16712,
               '3a1cf025b4a088960e6d7a23f44ecac4ff7d3de35082d1c3795e52c377a9169e')
RUNTIME = 'candidate/formal-receive-filecenter-navigation-classification-v1/runtime/'
NEW_RUNNER = (RUNTIME + 'mta_formal_receive_session.py', 88825,
              '421e8aa52f224e3a1f6d5ee9508af7bb2f49efc7d246a5bf59315b01e45e4ae3')
WORKER = (RUNTIME + 'ui_session.py', 95430,
          '698c629f1a0cd468af2e8168899c381939624014e7642834849c8107cfbed6c8')
DELTA = ('candidate/formal-receive-filecenter-navigation-classification-v1/exactsource-delta.json', 9731,
         '7027bbd7c4590be402f00f9c8c7ca8bd1885735ee3852dd594ccf109b87ba4f0')
NEW_SUFFIX = b'-formal-receive-filecenter-navigation-classification-v1'
PAYLOAD_BYTES = 4172818
ORDINARY_RUNNER = ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_formal_receive_session.py',
                   79254, '3fe23e4e9d9e1c9900985ee04153ce4b479ca1f2bc194458b91a702cd4f8258f')
DEADLINE = ('host/receive_classification_startup_deadline_projection_v1.py', 7569,
            'f0dc91ee5e4a5da4eb8cee5b44702d3d94f5e887727d35dfc9b747caab5d3010')
BOUNDARY = ('host/receive_classification_startup_boundary_projection_v1.py', 6911,
            '39b31c956641b50033626f4ca2a63a2576e1785e5b468481d41a2606f2ff826d')
FACTORIES = (
    ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py',
     94393, '887942d83faf27f781981f426cce5890fa4894219365545901df9310887cd8d3'),
    ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_client_receive_factory.py',
     97809, '8f37fcbfaaeedb7a0b86704c7a0368d1b23e93365423eeb5ff67e583f3e57549'))
PARENT = NAV = None
PARENT_RAW = b''
PROJECTION_PARENTS = {}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == pin[1:], 'classification_navigation_source_pin')
    return raw


def parent_definitions(raw):
    """Select actual pure functions/constants; never call the archived main."""
    tree = ast.parse(raw, feature_version=(3, 5))
    main = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(main) == 1, 'classification_parent_main_shape')
    nodes = [copy.deepcopy(row) for row in tree.body if
             isinstance(row, ast.FunctionDef) and row.name != 'main' or
             isinstance(row, ast.Assign) and all(isinstance(t, ast.Name) and t.id.isupper() for t in row.targets)]
    original = copy.deepcopy(nodes)
    donor_node = [row for row in nodes if isinstance(row, ast.FunctionDef) and row.name == 'donor']
    need(len(donor_node) == 1, 'classification_donor_shape')
    before = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-publication-v3'"
    after = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-filecenter-navigation-classification-v1'"
    matches = [row for row in ast.walk(donor_node[0]) if isinstance(row, ast.Constant) and row.value == before]
    labels = [row for row in ast.walk(donor_node[0]) if isinstance(row, ast.Constant) and
              row.value == 'formal-receive-filecenter-navigation-publication-v3-']
    readmes = [row for row in ast.walk(donor_node[0]) if isinstance(row, ast.Constant) and
               row.value == b'Current Publication graph75/4169378']
    need(len(matches) == len(labels) == len(readmes) == 1, 'classification_donor_literals')
    matches[0].value = after
    labels[0].value = 'formal-receive-filecenter-navigation-classification-v1-'
    readmes[0].value = b'Current classification graph75/4172818'
    final = copy.deepcopy(nodes)
    matches[0].value = before
    labels[0].value = 'formal-receive-filecenter-navigation-publication-v3-'
    readmes[0].value = b'Current Publication graph75/4169378'
    need(ast.dump(ast.Module(body=nodes, type_ignores=[])) ==
         ast.dump(ast.Module(body=original, type_ignores=[])), 'classification_donor_inverse')
    value = types.ModuleType('fixed_actual_v3_navigation_pure_definitions')
    value.__dict__.update(globals())
    value.__file__ = str(BASE / PARENT_HOST[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=final, type_ignores=[])), value.__file__, 'exec'),
         value.__dict__)
    return value, main[0]


def donor():
    global NAV
    value, raw = PARENT.donor()
    for name in ('SELF', 'CMDS', 'DEFINITIONS', 'RUNTIME', 'NEW_RUNNER', 'WORKER', 'NEW_SUFFIX', 'PAYLOAD_BYTES'):
        value.__dict__[name] = globals()[name]
    NAV = value
    return value, raw


def graph_payload(graph, read, inputs):
    """Verify the new real graph, preserved v3 overlays, then mechanical binding."""
    payload = NAV.FC.graph_payload(graph, read, inputs)
    need(graph.RUNNER == ORDINARY_RUNNER and graph.PAYLOAD_BYTES == PAYLOAD_BYTES and
         graph.STATE_ROOT == '/var/volatile/tmp/p011-mta-receive-profile-classification-clock-v1' and
         graph.STATE_ALIAS == '/tmp/p011-mta-receive-profile-classification-clock-v1' and
         type(graph.ORIGIN_SOURCE_PINS) is tuple and len(graph.ORIGIN_SOURCE_PINS) == 89,
         'classification_navigation_actual_graph')
    parent_raw = read(PARENT_DEFINITIONS)
    parent = types.ModuleType('fixed_actual_parent_publication_graph')
    parent.__file__ = str(BASE / PARENT_DEFINITIONS[0])
    exec(compile(parent_raw, parent.__file__, 'exec'), parent.__dict__)
    parent_nav, unused = PARENT.donor()
    parent_nav.FC, unused = parent_nav.selected(parent_nav.FC_DONOR, ('need', 'graph_payload'))
    PARENT.NAV = parent_nav
    original_payload = PARENT.graph_payload(parent, read, inputs)
    need(len(original_payload) == 75 and parent.PAYLOAD_BYTES == 4169378,
         'classification_navigation_parent_retained')
    spec = json.loads(read(DELTA).decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'sources', 'candidates', 'replacements'} and
         spec['evidence'] == 'source_data_only_not_executed' and
         spec['schema'] == 'p011-receive-filecenter-navigation-classification-v1-exact-source-delta' and
         type(spec['sources']) is list and len(spec['sources']) == 22 and
         type(spec['candidates']) is list and len(spec['candidates']) == 2 and
         type(spec['replacements']) is list and len(spec['replacements']) == 9,
         'classification_navigation_delta_shape')
    seen = set()
    for row in spec['sources']:
        need(type(row) is dict and set(row) == {'role', 'path', 'bytes', 'sha256'} and
             type(row['role']) is str and type(row['path']) is str and row['path'] not in seen and
             row['path'] in inputs and type(row['bytes']) is int and row['bytes'] > 0 and
             type(row['sha256']) is str and len(row['sha256']) == 64,
             'classification_navigation_source_shape')
        seen.add(row['path'])
        read((row['path'], row['bytes'], row['sha256']))
    need(PARENT.NEW_RUNNER[0] in seen and PARENT.WORKER[0] in seen and
         PARENT_DEFINITIONS[0] in seen and DEFINITIONS[0] in seen and
         parent.RUNNER[0] in seen and graph.RUNNER[0] in seen,
         'classification_navigation_source_domains')
    for row, pin in zip(spec['candidates'], (NEW_RUNNER, WORKER)):
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             (row['path'], row['bytes'], row['sha256']) == pin, 'classification_navigation_candidate_pin')
        read(pin)
    before = {'runtime/mta_formal_receive_session.py': inputs[PARENT.NEW_RUNNER[0]],
              'runtime/ui_session.py': inputs[PARENT.WORKER[0]]}
    current = dict(before)
    for row in spec['replacements']:
        need(type(row) is dict and set(row) == {'name', 'file', 'before', 'after', 'count'} and
             row['file'] in current and type(row['name']) is str and
             type(row['before']) is str and type(row['after']) is str and
             row['before'] and row['after'] and row['before'] != row['after'] and
             type(row['count']) is int and row['count'] in (1, 2), 'classification_navigation_delta_row')
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(old) == row['count'], 'classification_navigation_forward_count')
        current[row['file']] = current[row['file']].replace(old, new)
    need(current == {'runtime/mta_formal_receive_session.py': inputs[NEW_RUNNER[0]],
                     'runtime/ui_session.py': inputs[WORKER[0]]}, 'classification_navigation_forward_exact')
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(current[row['file']].count(new) == row['count'], 'classification_navigation_inverse_count')
        current[row['file']] = current[row['file']].replace(new, old)
    need(current == before, 'classification_navigation_inverse_exact')
    start, end = b'    def original_receive_ui_cancelled_empty(self):\n', b'    def load_owner(self):\n'
    def strip(raw):
        need(raw.count(start) == raw.count(end) == 1, 'classification_navigation_observer_anchor')
        left, right = raw.index(start), raw.index(end)
        need(left < right and right - left == 9571, 'classification_navigation_observer_length')
        return raw[:left] + raw[right:], raw[left:right]
    base, observer = strip(inputs[NEW_RUNNER[0]])
    old_base, old_observer = strip(before['runtime/mta_formal_receive_session.py'])
    need(base == inputs[graph.RUNNER[0]] and old_base == inputs[parent.RUNNER[0]] and
         observer == old_observer, 'classification_navigation_actual_ordinary_runner')
    return payload


def main():
    global PARENT, PARENT_RAW, PROJECTION_PARENTS
    PARENT_RAW = fixed(PARENT_HOST)
    PARENT, original_main = parent_definitions(PARENT_RAW)
    # Only the exact post-import source position moved by 43 lines. Neither
    # diagnostic calls business methods or changes the original deadline.
    for old, new in ((PARENT.DEADLINE, DEADLINE), (PARENT.BOUNDARY, BOUNDARY)):
        old_raw, new_raw = fixed(old), fixed(new)
        need(old_raw.count(b'tb.tb_lineno==1336') == new_raw.count(b'tb.tb_lineno==1379') == 1 and
             old_raw.replace(b'tb.tb_lineno==1336', b'tb.tb_lineno==1379', 1) == new_raw and
             new_raw.replace(b'tb.tb_lineno==1379', b'tb.tb_lineno==1336', 1) == old_raw,
             'classification_postimport_projection_inverse')
        PROJECTION_PARENTS[old[0]] = old_raw
    for pin, line in zip(FACTORIES, (1336, 1379)):
        raw = fixed(pin)
        tree = ast.parse(raw, feature_version=(3, 5))
        cls = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedReceiveDeploymentFactory']
        need(len(cls) == 1, 'classification_factory_type')
        methods = [row for row in cls[0].body if isinstance(row, ast.FunctionDef) and row.name == 'startup_readonly']
        need(len(methods) == 1 and sum(isinstance(row, ast.Call) and row.lineno == line and
             ast.dump(row.func) == ast.dump(ast.parse('scope.check_active', mode='eval').body)
             for row in ast.walk(methods[0])) == 1, 'classification_actual_postimport_callsite')
        PROJECTION_PARENTS[pin[0]] = raw
    # Compile only one provenance delta of the PC main, not the old entry point.
    before = copy.deepcopy(original_main)
    current = copy.deepcopy(original_main)
    rows = [row for row in ast.walk(current) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'extra']
    need(len(rows) == 1 and isinstance(rows[0].value, ast.Dict), 'classification_main_provenance')
    original_seed = copy.deepcopy(rows[0].value)
    rows[0].value.keys.append(ast.parse('PARENT_HOST[0]', mode='eval').body)
    rows[0].value.values.append(ast.Name(id='PARENT_RAW', ctx=ast.Load()))
    for path, raw in PROJECTION_PARENTS.items():
        rows[0].value.keys.append(ast.Constant(value=path))
        rows[0].value.values.append(ast.Constant(value=raw))
    final = copy.deepcopy(current)
    rows[0].value = original_seed
    need(ast.dump(current) == ast.dump(before), 'classification_main_inverse')
    namespace = dict(PARENT.__dict__)
    namespace.update(globals())
    namespace['__file__'] = str(BASE / SELF)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[final], type_ignores=[])), str(BASE / SELF), 'exec'), namespace)
    # This is the newly compiled provenance/binding driver, not PARENT.main.
    return namespace['main']()


if __name__ == '__main__':
    raise SystemExit(main())

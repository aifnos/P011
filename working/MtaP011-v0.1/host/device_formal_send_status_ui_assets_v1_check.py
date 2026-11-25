"""Fixed status UI19 Stage adapter; default SOURCE, explicit assets-only Stage.

The frozen Stage target, transport, caps, FD gates and stock/finally checks are
unchanged. Only actual new UI identities and a PC byte/AST provenance boundary
are attached. No generator, old main, Qt test, ordinary Stage, Owner or RF runs.
"""
import ast
import hashlib
import json
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_status_ui_assets_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_STATUS_UI_ASSETS_V1.cmd'
SOURCE_CMD = 'HOST_MTA_FORMAL_SEND_STATUS_UI_ASSETS_V1_SOURCE_CHECK.cmd'
MOTHER = ('host/device_formal_send_repair_ui_assets_v1_check.py', 18805,
          '133ec33f07079bab39470f3fa1eececc16dcf25cf17069ff3eeabadda511a926')
SESSION = '6d4fb1fd4af949cbb3515870'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
RUNTIME = 'candidate/formal-send-status-package-v3/runtime/'
CONTROL_SUFFIX = '-formal-send-status-package-v3'
GENERATOR = ('candidate/formal-send-status-package-v3/generate_ui.py', 12871,
             '07788d35b2eccd7cdd68877b6b854efbb9a02ddf08f282c0295e71939e4888a7')
GENERATION = ('candidate/formal-send-status-package-v3/generation.json', 18646,
              '94776f16255f2a7ecd15b5a17c096ee34038e929386e0d8def3637d5a1d142b9')
DELTA = ('candidate/formal-send-status-package-v3/exactsource-delta.json', 10759,
         '90e70524c115ffd3a43e66dce7dcf5049bd597fb32a7bc50f681e82b5f8c3ebd')
VALIDATOR = (RUNTIME + 'ui_assets.py', 12526,
             '430308223593d5d783c1ec1d29a90dcbe82606b33690fc263572b8353d9fd4e8')
GUARDIAN = (RUNTIME + 'ui_guardian.py', 43994,
            'c36560f4d481677ce61ec9cbed5910f4f202e381215a4cd5f2eb564965712998')
WORKER = (RUNTIME + 'ui_session.py', 46416,
          'adc1561cd32d53257c5df123c4516c63e38198a7c08a04be0fc51249d2893c25')
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 4228,
                  '0498ebe2f531a4e34b787ca792ca0e748394c9c01c6766f206d7d9896adcf5f1')
SOURCE_MANIFEST = (BUNDLE + '/SOURCE.sha256', 1603,
                   '5f0e30136af76a1fb998ed2e2b17e8727a623edf1fcd0c3ce02f1d49272b34ba')
ASSET_BYTES = 4185296
OUTER = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_session.py', 24060,
         '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f')
ORIGINS = (
    ('candidate/formal-send-picker-package-v1/runtime/ui_assets.py', 12526,
     '7bf8bd1e239ab8cf21a6662ea9217de3e2bef634fb20f31880482abbaca4fd21'),
    ('candidate/formal-send-preflight-ui-v1/runtime/ui_guardian.py', 43996,
     '8df81808cbd6e32848e5698a5adc486f1027daf8270e5841f83f852d3513b3c1'),
    ('candidate/formal-send-preflight-ui-v1/runtime/ui_session.py', 46418,
     'eb1f076560b8061a48b7138a747e805fd9fa32fad86d7d2a025e428d555ab9b7'),
)
BRIDGES = (
    ('candidate/formal-send-status-package-v1/generate_ui.py', 24159,
     'a424b9b28583797ea669beb983437a9ad6a277d527cc808f6160775a6810980c'),
    ('candidate/formal-send-status-package-v2/generate_ui.py', 10647,
     '72ebe7e1479eeac72fbfa7903d4c27a997143e79e2edef525491b58fa2c6bb23'),
)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tree(raw):
    return ast.parse(raw.decode('utf-8'))


def assignment(raw, name):
    rows = [row for row in tree(raw).body if isinstance(row, ast.Assign) and
            len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'status_assignment_unique')
    return rows[0]


def literal(raw, name):
    return ast.literal_eval(assignment(raw, name).value)


def span(raw, node):
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def runtime_inverse(origin, current, replacements, allowed):
    """Actual no-trailing-LF assignment records, not generic text matching."""
    need(type(replacements) is list and {row['name'] for row in replacements} == allowed and
         len(replacements) == len(allowed), 'status_runtime_assignment_inventory')
    forward = origin
    for row in replacements:
        name = row['name']
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        old, new = assignment(origin, name), assignment(current, name)
        need(span(origin, old).rstrip(b'\n') == before and span(current, new).rstrip(b'\n') == after and
             old.lineno == new.lineno and old.end_lineno == new.end_lineno and
             forward.count(before + b'\n') == 1, 'status_runtime_forward_exact_span')
        forward = forward.replace(before + b'\n', after + b'\n', 1)
    need(forward == current, 'status_runtime_full_forward')
    inverse = current
    for row in reversed(replacements):
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(inverse.count(after + b'\n') == 1, 'status_runtime_inverse_exact_span')
        inverse = inverse.replace(after + b'\n', before + b'\n', 1)
    need(inverse == origin and ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'status_runtime_complete_byte_ast_inverse')
    old_nodes, new_nodes = tree(origin).body, tree(current).body
    need(len(old_nodes) == len(new_nodes), 'status_runtime_shape')
    changed = set()
    for old, new in zip(old_nodes, new_nodes):
        if ast.dump(old, include_attributes=False) != ast.dump(new, include_attributes=False):
            need(isinstance(old, ast.Assign) and isinstance(new, ast.Assign) and
                 len(old.targets) == len(new.targets) == 1 and isinstance(old.targets[0], ast.Name) and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]) and old.targets[0].id in allowed,
                 'status_runtime_nonconstant_change')
            changed.add(old.targets[0].id)
        if isinstance(old, (ast.FunctionDef, ast.ClassDef)):
            need(old.lineno == new.lineno and old.end_lineno == new.end_lineno and
                 span(origin, old) == span(current, new), 'status_runtime_definitions_bytes_lines')
    need(changed == allowed, 'status_runtime_changed_constants')


def package_boundary(inputs, helper, validator):
    """Read actual27 package bytes and prove the three constant-only runtimes."""
    def take(pin):
        raw = helper.read_fixed(pin[0], pin[1:])
        need(pin[0] not in inputs or inputs[pin[0]] == raw, 'status_input_consistency')
        inputs[pin[0]] = raw
        return raw
    for pin in (MOTHER, GENERATOR, GENERATION, DELTA, OUTER) + ORIGINS + BRIDGES:
        take(pin)
    current = json.loads(inputs[GENERATION[0]])
    delta = json.loads(inputs[DELTA[0]])
    need(current['schema'] == 'p011-formal-send-status-package-v3-generation' and
         delta['schema'] == 'p011-formal-send-status-package-v3-exactsource-delta' and
         current['session'] == SESSION and current['bundle'] == BUNDLE and current['remote'] == REMOTE and
         current['control_suffix'] == CONTROL_SUFFIX and
         current['control_name'] == 'p011-mta-ui-session-' + SESSION + CONTROL_SUFFIX and
         current['control'] == '/var/volatile/tmp/' + current['control_name'] and
         current['stage_file_count'] == 19 and current['payload_file_count'] == 18 and
         current['asset_bytes'] == ASSET_BYTES and current['stage_spare'] == 4 * 1024 * 1024 - ASSET_BYTES and
         current['output_count'] == 27 and current['original_window_seconds'] == 600 and
         current['original_cleanup_seconds'] == 60 and current['smoke_seconds'] == 20 and
         current['caps']['geometry'] == '800x268' and current['caps']['stage_bytes'] == 4 * 1024 * 1024 and
         current['ordinary_graph_changed'] is False and current['filecenter_changed'] is False and
         current['lock_changed'] is False and current['old_tests'] == current['old_mains'] == current['old_builders'] == 0,
         'status_generation_scope')
    need(tuple(current['generator']) == GENERATOR and tuple(current['ui_validator']) == VALIDATOR and
         tuple(current['guardian']) == GUARDIAN and tuple(current['worker']) == WORKER and
         tuple(current['source_manifest']) == SOURCE_MANIFEST and tuple(current['stage_manifest']) == STAGE_MANIFEST and
         tuple(current['exactsource_delta']) == DELTA and tuple(current['sender_outer']) == OUTER and
         tuple(current['bridge_origin']) == BRIDGES[0] and tuple(current['bridge_body_source']) == BRIDGES[1],
         'status_actual_output_bindings')
    rows = tuple(tuple(row) for row in current['output_pins'])
    asset_pins = tuple(validator.PINS) + (('SOURCE.sha256',) + validator.MANIFEST_PIN,)
    expected = {BUNDLE + '/' + row[0] for row in asset_pins} | {
        BUNDLE + '/' + name for name in ('NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json')
    } | {VALIDATOR[0], GUARDIAN[0], WORKER[0], DELTA[0]}
    need(len(rows) == len({row[0] for row in rows}) == 26 and {row[0] for row in rows} == expected and
         all(type(row[0]) is str and type(row[1]) is int and type(row[2]) is str for row in rows),
         'status_actual27_inventory')
    for pin in rows:
        take(pin)
    need(validator.SESSION == SESSION and validator.REMOTE == REMOTE and
         validator.MANIFEST_PIN == SOURCE_MANIFEST[1:] and
         sum(row[1] for row in asset_pins) == ASSET_BYTES and len(asset_pins) == 19,
         'status_validator_asset_closure')
    contracts = {tuple(row) for row in current['inputs']}
    need(len(contracts) == current['input_count'] == 48 and
         all(pin in contracts for pin in (GENERATOR,) + ORIGINS + BRIDGES), 'status_origin_contract')
    for role, origin, candidate, allowed in (
        ('validator', ORIGINS[0], VALIDATOR, {'SESSION', 'MANIFEST_PIN', 'PINS'}),
        ('guardian', ORIGINS[1], GUARDIAN, {'SESSION', 'CONTROL_NAME'}),
        ('worker', ORIGINS[2], WORKER, {'SESSION', 'CONTROL_NAME', 'GUARDIAN_PIN', 'ASSETS_PIN', 'SENDER_ASSET_SEAL'}),
    ):
        record = delta[role]
        need(tuple(record['origin']) == origin and tuple(record['candidate']) == candidate,
             'status_runtime_delta_actual_pins')
        runtime_inverse(inputs[origin[0]], inputs[candidate[0]], record['replacements'], allowed)
        need(literal(inputs[candidate[0]], 'SESSION') == SESSION, 'status_runtime_session')
    control = ast.parse("'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_SUFFIX), mode='eval').body
    for pin in (WORKER, GUARDIAN):
        need(ast.dump(assignment(inputs[pin[0]], 'CONTROL_NAME').value) == ast.dump(control),
             'status_runtime_control_closure')
    seal = ast.parse('(SESSION, ASSETS, ' + repr(SOURCE_MANIFEST[1:]) + ')', mode='eval').body
    need(ast.dump(assignment(inputs[WORKER[0]], 'SENDER_ASSET_SEAL').value) == ast.dump(seal) and
         literal(inputs[WORKER[0]], 'GUARDIAN_PIN') == GUARDIAN[1:] and
         literal(inputs[WORKER[0]], 'ASSETS_PIN') == VALIDATOR[1:] and
         literal(inputs[WORKER[0]], 'SENDER_PIN') == OUTER[1:] and
         literal(inputs[WORKER[0]], 'SENDER_ROOT') == '/tmp/p011-mta-formal-send-filecenter-deploy-v7',
         'status_worker_actual_pins_seal')
    need(current['cached_qt_evidence']['methods'] == 1 and current['cached_qt_evidence']['scenarios'] == 9 and
         current['cached_qt_evidence']['reexecuted'] is False and
         current['unchanged_payload_files'] == 14 and current['changed_staged_files'] == 5 and
         current['changed_payload'] == delta['changed_payload'] ==
         ['Bridge.qml', 'FormalEntry.qml', 'Z03.mta-ui-candidate', 'mta/MtaPage.qml'], 'status_cached_scope')
    return dict(actual_package_outputs=27, runtime_constant_byte_ast_inverse=True,
                runtime_business_definitions_unchanged=True, cached_qt_reexecuted=False,
                cached_qt_methods=1, cached_qt_scenarios=9, ordinary_graph_changed=False,
                source_manifest_bound=True, new_control_suffix=CONTROL_SUFFIX)


def derive_stage(origin):
    raw, edits = origin, []
    def change(before, after, count=1):
        nonlocal raw
        need(before != after and raw.count(before) == count, 'status_stage_forward_count')
        raw = raw.replace(before, after)
        edits.append((before, after, count))
    for name, value in (('SELF', SELF), ('CMD', CMD), ('SOURCE_CMD', SOURCE_CMD), ('SESSION', SESSION),
                        ('BUNDLE', BUNDLE), ('VALIDATOR', VALIDATOR), ('STAGE_MANIFEST', STAGE_MANIFEST),
                        ('ASSET_BYTES', ASSET_BYTES)):
        change(span(raw, assignment(raw, name)), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after in (
        (b'19-asset repaired sender UI stage', b'19-asset status sender UI stage'),
        (b'fixed_sender_repair_ui_assets_v1_stage', b'fixed_sender_status_ui_assets_v1_stage'),
        (b'fixed-sender-repair-ui-assets-v1-stage', b'fixed-sender-status-ui-assets-v1-stage'),
        (b"('formal-send-repair-ui-assets-v1-' + mode", b"('formal-send-status-ui-assets-v1-' + mode"),
    ):
        change(before, after)
    anchor = b'        for path in (SELF, CMD, SOURCE_CMD): inputs[path] = helper.read_fixed(path)\n'
    change(anchor, anchor + b"        report['package_source'] = _STATUS_ASSET_BOUNDARY(inputs, helper, validator)\n")
    inverse = raw
    for before, after, count in reversed(edits):
        need(inverse.count(after) == count, 'status_stage_inverse_count')
        inverse = inverse.replace(after, before)
    need(inverse == origin and ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'status_stage_complete_byte_ast_inverse')
    changed_assignments, changed_methods = set(), set()
    old_nodes, new_nodes = tree(origin).body, tree(raw).body
    need(len(old_nodes) == len(new_nodes), 'status_stage_shape')
    for old, new in zip(old_nodes, new_nodes):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            need(len(old.targets) == len(new.targets) == 1 and isinstance(old.targets[0], ast.Name) and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]), 'status_stage_assignment_scope')
            changed_assignments.add(old.targets[0].id)
        elif isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef):
            need(old.name == new.name and old.name in ('stage_program', 'main'), 'status_stage_method_scope')
            changed_methods.add(old.name)
        else:
            need(old is old_nodes[0] and new is new_nodes[0] and isinstance(old, ast.Expr), 'status_stage_other_scope')
    need(changed_assignments == {'SELF', 'CMD', 'SOURCE_CMD', 'SESSION', 'BUNDLE', 'VALIDATOR',
                                'STAGE_MANIFEST', 'ASSET_BYTES'} and changed_methods == {'stage_program', 'main'},
         'status_stage_exact_edit_inventory')
    return raw


def prepare():
    origin = (BASE / MOTHER[0]).read_bytes()
    need((len(origin), digest(origin)) == MOTHER[1:], 'status_stage_mother_pin')
    raw = derive_stage(origin)
    module = types.ModuleType('fixed_status_ui_assets_v1_definitions')
    module.__file__ = str(BASE / SELF)
    exec(compile(raw, '<fixed-status-ui-assets-v1-derived-host>', 'exec'), module.__dict__)
    module._STATUS_ASSET_BOUNDARY = package_boundary
    need(module.SESSION == SESSION and module.BUNDLE == BUNDLE and module.REMOTE == REMOTE and
         module.VALIDATOR == VALIDATOR and module.ASSET_BYTES == ASSET_BYTES, 'status_stage_final_bindings')
    return module, raw


def main():
    need(sys.argv[1:] in ([], ['--stage-device']), 'fixed_source_or_assets_stage_only')
    module, raw = prepare()
    return module.main()


if __name__ == '__main__':
    raise SystemExit(main())

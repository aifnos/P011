"""Immutable PC-only package of the already-passed QML presentation fence.

Default SOURCE computes a bounded plan without writing. Explicit --write alone
creates the fresh bundle/runtime and 27 EXCL files. Only fixed pure definitions
are selected from the pinned picker generator; no old module/main/build/test,
runtime validator/Guardian/Worker, Qt, ADB, ordinary Stage, lock or RF runs.
Computed pins describe actual in-memory bytes, not a future device acceptance.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib

BASE = Path(__file__).resolve().parents[2]
PROJECT = BASE.parents[1]
ROOT = 'candidate/formal-send-status-package-v1'
SELF = ROOT + '/generate_ui.py'
SESSION = '6d4fb1fd4af949cbb3515870'
OLD_SESSION = 'c69296a193ff43ce8e5b901d'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
OLD_BUNDLE = 'out/mta-ui-send-picker-v1-' + OLD_SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
OLD_REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + OLD_SESSION
CONTROL_SUFFIX = '-formal-send-status-package-v1'
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + CONTROL_SUFFIX
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
VALIDATOR = ROOT + '/runtime/ui_assets.py'
GUARDIAN = ROOT + '/runtime/ui_guardian.py'
WORKER = ROOT + '/runtime/ui_session.py'
DELTA = ROOT + '/exactsource-delta.json'
GENERATION = ROOT + '/generation.json'
SOURCE_BUDGET = 262144
FILE_BUDGET = 5 * 1024 * 1024
STAGE_BUDGET = 4 * 1024 * 1024
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET, NAV_SLOT = 1946708, 1580
STAGE_DIRECTORIES = ('', 'mta', 'toolbox')
PC_NAMES = ('NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json')
PAYLOAD_CHANGED = ('Bridge.qml', 'FormalEntry.qml', 'Z03.mta-ui-candidate', 'mta/MtaPage.qml')
ORIGINAL_PATH = '06_Firmware/backups/v2.4.0-20260923-162730/files/Z03'
ORIGINAL_PIN = (4103844, 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a')
MOTHER = ('candidate/formal-send-picker-package-v1/generate_ui.py', 32033,
          '8ed44c223b538ab13cdbc9d2d30dcfbd3e053c436b1177a0b68e3646a6aebd69')
BUILDER = ('host/build_formal_send_filecenter_ui_v5.py', 18604,
           '6c97c44dd54059eb3b78150bfb2a033aa0a9e8273e900d748df2a0ebca829f49')
QRC_HELPER = ('host/build_formal_ui_candidate_v1.py', 11889,
              '5215ebff474016262900c0599355bfa9b6e48e5960ed0a20f07f17428f87e70c')
OLD_VALIDATOR = ('candidate/formal-send-picker-package-v1/runtime/ui_assets.py', 12526,
                 '7bf8bd1e239ab8cf21a6662ea9217de3e2bef634fb20f31880482abbaca4fd21')
OLD_GUARDIAN = ('candidate/formal-send-preflight-ui-v1/runtime/ui_guardian.py', 43996,
                '8df81808cbd6e32848e5698a5adc486f1027daf8270e5841f83f852d3513b3c1')
OLD_WORKER = ('candidate/formal-send-preflight-ui-v1/runtime/ui_session.py', 46418,
              'eb1f076560b8061a48b7138a747e805fd9fa32fad86d7d2a025e428d555ab9b7')
OUTER = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_session.py', 24060,
         '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f')
OLD_GENERATION = ('candidate/formal-send-picker-package-v1/generation.json', 18953,
                  '4b35068be0fac257a7568d3790a593c42e09d43efe32e96a1a14865ed2658b80')
PAGE = ('candidate/formal-send-status-presentation-v1/device/mta/MtaPage.qml', 27307,
        '667b3e54c9fc7dbbd41e4fe8533e9926eab7a1942b6220248626bb30acf0f6fc')
PAGE_DELTA = ('candidate/formal-send-status-presentation-v1/exactsource-delta.json', 3589,
              '2525a8e170129c7ab4682f33c8b99e4c320b1e22b2ff36796d3bc95dc2862bf6')
QT_RESULT = ('results/formal-send-status-presentation-v1-host-20261006-084552-973b4819/result.json',
             3555, '64714ba0823759436cce100bf5a8b036a82b22a8e5e77ee61996ffed59788add')
SOURCE_PINS = (MOTHER, BUILDER, QRC_HELPER, OLD_VALIDATOR, OLD_GUARDIAN,
               OLD_WORKER, OUTER, OLD_GENERATION, PAGE, PAGE_DELTA, QT_RESULT)
PURE_NAMES = ('need', 'digest', 'pin', 'json_raw', 'meta', 'safe_directory',
              'relative', 'scoped', 'read_pinned', 'assignments', 'span', 'node_bytes',
              'constant_overlay', 'literal', 'pure_qrc', 'inventory', 'verify_inputs', 'write_new')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def core_definitions():
    """Select only authenticated pure definitions; no mother module import."""
    path = BASE / MOTHER[0]
    for node in reversed((path.parent,) + tuple(path.parent.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'mother_directory')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == MOTHER[1] and not path.is_symlink() and
         not getattr(before, 'st_file_attributes', 0) & 0x400, 'mother_file')
    with path.open('rb') as stream:
        raw = stream.read(MOTHER[1] + 1)
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in keys) ==
         tuple(getattr(path.lstat(), key) for key in keys) and
         (len(raw), digest(raw)) == MOTHER[1:], 'mother_pin')
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in PURE_NAMES]
    need(tuple(row.name for row in nodes) == PURE_NAMES and all(not row.decorator_list for row in nodes),
         'pure_definition_inventory')
    scope = dict(globals(), __name__='fixed_status_package_pure_definitions')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), scope)
    need(all(name not in {row.name for row in nodes} for name in ('prepare', 'main', 'build')),
         'old_entry_forbidden')
    return scope, raw


def expression_is(core, raw, name, expression):
    rows = core['assignments'](raw)[1]
    return ast.dump(rows[name].value, include_attributes=False) == ast.dump(
        ast.parse(expression, mode='eval').body, include_attributes=False)


def presentation_proof(core, inputs, old_page):
    spec = json.loads(inputs[PAGE_DELTA[0]])
    need(spec['schema'] == 'p011-formal-send-status-presentation-source-delta-v1' and
         spec['candidate'] == list(PAGE) and spec['source'][1:] == [len(old_page), digest(old_page)] and
         spec['bindings'][1] == [OLD_BUNDLE + '/mta/MtaPage.qml', len(old_page), digest(old_page)] and
         len(spec['replacements']) == 5 and spec['runtime_source_only'] is True and
         all(spec[key] is False for key in ('deployed', 'actions_changed', 'native_changed')), 'page_delta')
    forward = old_page
    for row in spec['replacements']:
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(row['count'] == 1 and old and new and forward.count(old) == 1, 'page_forward_unique')
        forward = forward.replace(old, new, 1)
    candidate = inputs[PAGE[0]]
    need(forward == candidate, 'page_forward')
    inverse = candidate
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(inverse.count(new) == 1, 'page_inverse_unique')
        inverse = inverse.replace(new, old, 1)
    need(inverse == old_page, 'page_inverse')
    result = json.loads(inputs[QT_RESULT[0]])
    need(result['schema'] == 'p011-formal-send-status-presentation-v1-host' and result['passed'] is True and
         result['source_contract_verified'] is True and result['inputs_preserved'] is True and
         result['host_exit'] == result['child_exit'] == 0 and result['methods_verified'] == 1 and
         result['scenarios_verified'] == 9 and result['old_suite_methods_requested'] == 0 and
         result['unchanged_xhr_executed'] is False and
         all(result[key] is False for key in ('device_invoked', 'rf_invoked', 'phone_invoked', 'deployed',
             'build_invoked', 'physical_rendering_verified', 'real_mobile_transfer_verified')), 'cached_qt_result')
    rows = result['source_inputs']
    need(len(rows) == result['input_count'] == 13 and len({row['path'] for row in rows}) == 13,
         'cached_qt_sources')
    for row in rows:
        path = row['path']
        raw = core['read_pinned'](core['scoped'](path), (row['bytes'], row['sha256']))
        need(path not in inputs or inputs[path] == raw, 'cached_source_consistency')
        inputs[path] = raw
    need(inputs[spec['source'][0]] == old_page and inputs[PAGE[0]] == candidate,
         'cached_actual_page_binding')
    return spec, dict(result=list(QT_RESULT), methods=1, scenarios=9, reexecuted=False,
        boundary='Actual HOST Qt/QML with delayed request seam; not real XHR/device/phone/rendering.')


def prepare():
    need(os.name == 'nt' and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
         Path(__file__).resolve() == BASE / SELF, 'fixed_pc')
    core, mother_raw = core_definitions()
    take, literal, pin, encode = (core[key] for key in ('read_pinned', 'literal', 'pin', 'json_raw'))
    core['safe_directory'](BASE / ROOT)
    core['safe_directory'](BASE / 'out')
    need(re.fullmatch(r'[0-9a-f]{24}', SESSION) is not None and SESSION != OLD_SESSION, 'fresh_session')
    inputs = {path: take(core['scoped'](path), (size, sha)) for path, size, sha in SOURCE_PINS}
    need(inputs[MOTHER[0]] == mother_raw, 'mother_preserved')
    own_size = Path(__file__).lstat().st_size
    need(0 < own_size <= SOURCE_BUDGET, 'generator_budget')
    with Path(__file__).open('rb') as stream:
        own = stream.read(own_size + 1)
    need(len(own) == own_size, 'generator_read')
    inputs[SELF] = take(BASE / SELF, (len(own), digest(own)))
    inputs['PROJECT:' + ORIGINAL_PATH] = take(PROJECT / ORIGINAL_PATH, ORIGINAL_PIN)
    validator, guardian, worker = (inputs[row[0]] for row in (OLD_VALIDATOR, OLD_GUARDIAN, OLD_WORKER))
    old_pins, old_manifest = literal(validator, 'PINS'), literal(validator, 'MANIFEST_PIN')
    need(literal(validator, 'SESSION') == literal(guardian, 'SESSION') == literal(worker, 'SESSION') == OLD_SESSION and
         len(old_pins) == len({row[0] for row in old_pins}) == 18 and tuple(sorted(old_pins)) == old_pins and
         literal(worker, 'GUARDIAN_PIN') == OLD_GUARDIAN[1:] and literal(worker, 'ASSETS_PIN') == OLD_VALIDATOR[1:] and
         literal(worker, 'SENDER_PIN') == OUTER[1:] and literal(worker, 'SENDER_ROOT') == literal(inputs[OUTER[0]], 'ROOT') and
         literal(worker, 'SENDER_PHYSICAL_ROOT') == literal(inputs[OUTER[0]], 'PHYSICAL_ROOT'), 'old_runtime_closure')
    old_control = "'p011-mta-ui-session-' + SESSION + '-formal-send-preflight-native-v1'"
    need(expression_is(core, worker, 'CONTROL_NAME', old_control) and
         expression_is(core, guardian, 'CONTROL_NAME', old_control) and
         expression_is(core, worker, 'SENDER_ASSET_SEAL', '(SESSION, ASSETS, ' + repr(old_manifest) + ')'), 'old_seal')
    ui = json.loads(inputs[OLD_GENERATION[0]])
    need(ui['session'] == OLD_SESSION and ui['bundle'] == OLD_BUNDLE and ui['remote'] == OLD_REMOTE and
         ui['stage_file_count'] == 19 and ui['asset_bytes'] == 4184758, 'old_generation')
    old_stage_pins = tuple(sorted(old_pins + (('SOURCE.sha256',) + old_manifest,)))
    old_files = {}
    required = {OLD_BUNDLE + '/' + name for name, size, sha in old_stage_pins} | {
        OLD_BUNDLE + '/' + name for name in PC_NAMES}
    rows = ui['output_pins']
    need(len(rows) == 24 and len({row[0] for row in rows}) == 24, 'old_output_inventory')
    for path, size, sha in rows:
        if path in required:
            inputs[path] = take(core['scoped'](path), (size, sha))
    need(required <= set(inputs), 'old_bundle_sources')
    core['inventory'](BASE / OLD_BUNDLE, [row[0] for row in old_stage_pins], PC_NAMES)
    for name, size, sha in old_stage_pins:
        raw = inputs[OLD_BUNDLE + '/' + name]
        need((len(raw), digest(raw)) == (size, sha), 'old_bundle_pin')
        old_files[name] = raw
    need(old_files['SOURCE.sha256'] == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
         for name, size, sha in old_pins).encode('ascii') and sum(map(len, old_files.values())) == 4184758,
         'old_checksum')
    stage = json.loads(inputs[OLD_BUNDLE + '/stage-manifest.json'])
    need(stage['session'] == OLD_SESSION and stage['remote'] == OLD_REMOTE and
         stage['directories'] == [dict(path=name, mode='0700') for name in STAGE_DIRECTORIES] and
         tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files']) == old_stage_pins and
         all(row['mode'] == ('0500' if row['path'] == 'Z03.mta-ui-candidate' else '0400') for row in stage['files']) and
         stage['excluded_pc_files'] == list(PC_NAMES) and stage['credentials_in_stage'] is False and
         stage['font_files_bundled'] is False, 'old_stage')
    spec, cached = presentation_proof(core, inputs, old_files['mta/MtaPage.qml'])
    enumerate_resources, patch = core['pure_qrc'](inputs)
    original = inputs['PROJECT:' + ORIGINAL_PATH]
    old_elf, old_nav, old_used = patch(original, OLD_REMOTE, enumerate_resources)
    old_build = json.loads(inputs[OLD_BUNDLE + '/build-result.json'])
    need(old_elf == old_files['Z03.mta-ui-candidate'] and old_nav == inputs[OLD_BUNDLE + '/NaviPanel.embedded.qml'] and
         old_used == old_build['used_bytes'] == 1567 and old_build['candidate_sha256'] == digest(old_elf) and
         old_build['original_sha256'] == ORIGINAL_PIN[1], 'old_qrc_binding')
    new_elf, new_nav, used = patch(original, REMOTE, enumerate_resources)
    end = NAV_OFFSET + 4 + NAV_SLOT
    before, after = enumerate_resources(original), enumerate_resources(new_elf)
    need(len(new_elf) == len(original) == ORIGINAL_PIN[0] and 0 < used <= NAV_SLOT and
         new_elf[:NAV_OFFSET] == original[:NAV_OFFSET] and new_elf[end:] == original[end:] and
         len(before) == len(after) == 400 and set(before) == set(after) and
         sum(after[name] == row for name, row in before.items() if name != '/NaviPanel.qml') == 399 and
         old_nav.count(OLD_REMOTE.encode('ascii')) == 1 and
         new_nav == old_nav.replace(OLD_REMOTE.encode('ascii'), REMOTE.encode('ascii'), 1) and
         new_nav.replace(REMOTE.encode('ascii'), OLD_REMOTE.encode('ascii'), 1) == old_nav, 'qrc_exact_scope')
    files = {name: raw for name, raw in old_files.items() if name != 'SOURCE.sha256'}
    files['Z03.mta-ui-candidate'], files['mta/MtaPage.qml'] = new_elf, inputs[PAGE[0]]
    entries = []
    for name, count in (('Bridge.qml', 1), ('FormalEntry.qml', 2)):
        old = files[name]
        need(old.count(OLD_SESSION.encode('ascii')) == count, 'entry_anchor')
        new = old.replace(OLD_SESSION.encode('ascii'), SESSION.encode('ascii'))
        need(new.count(SESSION.encode('ascii')) == count and len(new) == len(old) and
             new.replace(SESSION.encode('ascii'), OLD_SESSION.encode('ascii')) == old, 'entry_inverse')
        files[name] = new
        entries.append(dict(path=name, occurrences=count, complete_byte_inverse=True))
    need(tuple(sorted(name for name in files if files[name] != old_files[name])) == PAYLOAD_CHANGED and
         sum(files[name] == old_files[name] for name in files) == 14, 'four_changed_fourteen_exact')
    text = [raw for name, raw in files.items() if name != 'Z03.mta-ui-candidate']
    need(sum(map(len, text)) <= SOURCE_BUDGET and all(b'\0' not in raw and OLD_SESSION.encode('ascii') not in raw and
         re.search(rb'@[A-Z_]+@', raw) is None for raw in text), 'ui_text_budget_identity')
    for raw in text: raw.decode('utf-8')
    pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    source = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in pins).encode('ascii')
    need(len(source) <= 4096 and len(source.splitlines()) == 18, 'manifest_cap')
    staged = dict(files, **{'SOURCE.sha256': source})
    asset_bytes = sum(map(len, staged.values()))
    need(len(staged) == 19 and asset_bytes <= STAGE_BUDGET and
         sum(staged[name] != old_files[name] for name in staged) == 5, 'five_staged_delta_4mib')
    overlay = core['constant_overlay']
    pins_expression = '(\n' + ''.join('    ' + repr(row) + ',\n' for row in pins) + ')'
    new_validator, vp = overlay(validator, {'SESSION': repr(SESSION),
        'MANIFEST_PIN': repr((len(source), digest(source))), 'PINS': pins_expression}, 'validator')
    control_expression = "'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_SUFFIX)
    new_guardian, gp = overlay(guardian, {'SESSION': repr(SESSION), 'CONTROL_NAME': control_expression}, 'guardian')
    new_worker, wp = overlay(worker, {'SESSION': repr(SESSION), 'CONTROL_NAME': control_expression,
        'GUARDIAN_PIN': repr(pin(GUARDIAN, new_guardian)[1:]), 'ASSETS_PIN': repr(pin(VALIDATOR, new_validator)[1:]),
        'SENDER_ASSET_SEAL': '(SESSION, ASSETS, ' + repr((len(source), digest(source))) + ')'}, 'worker')
    need(literal(new_worker, 'SENDER_PIN') == OUTER[1:] and
         literal(new_worker, 'FILECENTER_PINS') == literal(worker, 'FILECENTER_PINS') and
         literal(new_worker, 'GUARDIAN_PIN') == pin(GUARDIAN, new_guardian)[1:] and
         literal(new_worker, 'ASSETS_PIN') == pin(VALIDATOR, new_validator)[1:] and
         literal(new_validator, 'PINS') == pins and
         all(literal(raw, 'SESSION') == SESSION for raw in (new_validator, new_guardian, new_worker)), 'new_runtime_closure')
    for raw in (new_validator, new_guardian, new_worker):
        ast.parse(raw, feature_version=(3, 5))
        need(max(map(len, raw.splitlines())) <= 2048, 'target_line_cap')
    outputs = {BUNDLE + '/' + name: raw for name, raw in staged.items()}
    stage.update(schema='p011-formal-send-status-package-v1-stage', session=SESSION, remote=REMOTE,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        files=[dict(path=name, bytes=len(raw), sha256=digest(raw),
                    mode='0500' if name == 'Z03.mta-ui-candidate' else '0400') for name, raw in sorted(staged.items())])
    outputs[BUNDLE + '/NaviPanel.embedded.qml'], outputs[BUNDLE + '/stage-manifest.json'] = new_nav, encode(stage)
    outputs.update({VALIDATOR: new_validator, GUARDIAN: new_guardian, WORKER: new_worker})
    delta = dict(schema='p011-formal-send-status-package-v1-exactsource-delta',
        page_source=list(PAGE_DELTA), page_replacements=spec['replacements'], entry_replacements=entries,
        nav_root_only_complete_inverse=True, qrc_same_slot=True, other_399_original=True,
        validator=dict(origin=list(OLD_VALIDATOR), candidate=list(pin(VALIDATOR, new_validator)), replacements=vp),
        guardian=dict(origin=list(OLD_GUARDIAN), candidate=list(pin(GUARDIAN, new_guardian)), replacements=gp),
        worker=dict(origin=list(OLD_WORKER), candidate=list(pin(WORKER, new_worker)), replacements=wp),
        runtime_complete_byte_ast_inverse=True, runtime_definition_bytes_and_lines_unchanged=True,
        changed_payload=list(PAYLOAD_CHANGED), changed_staged_files=5, ordinary_graph_changed=False)
    outputs[DELTA] = encode(delta)
    build = dict(schema='p011-formal-send-status-package-v1-pc-build', evidence_level='PC_SOURCE_COMPUTED_NOT_DEVICE',
        session=SESSION, bundle=BUNDLE, remote=REMOTE, original_path=ORIGINAL_PATH, original_sha256=ORIGINAL_PIN[1],
        candidate_bytes=len(new_elf), candidate_sha256=digest(new_elf), resources_verified=400,
        other_resources_original_bytes=399, record_offset=NAV_OFFSET, slot_bytes=NAV_SLOT, used_bytes=used,
        slot_spare=NAV_SLOT-used, elf_total_length_unchanged=True, elf_outside_slot_unchanged=True,
        compressed_qml_readback=True, geometry='parent-owned 800x268; no additional offset or rotation',
        payload_changed=list(PAYLOAD_CHANGED), unchanged_payload_files=14, changed_staged_files=5,
        payload_file_count=18, staged_file_count=19, staged_directory_count=3, asset_bytes=asset_bytes,
        stage_spare=STAGE_BUDGET-asset_bytes, cached_qt_evidence=cached, device_tested=False,
        qml_runtime_verified=False, phone_interop_verified=False, rf=False, old_tests_reexecuted=False)
    outputs[BUNDLE + '/build-result.json'] = encode(build)
    generation = dict(schema='p011-formal-send-status-package-v1-generation',
        scope='PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN', generator=list(pin(SELF, own)),
        session=SESSION, bundle=BUNDLE, remote=REMOTE, control_name=CONTROL_NAME, control=CONTROL,
        control_suffix=CONTROL_SUFFIX, payload_file_count=18, stage_file_count=19, output_count=27,
        asset_bytes=asset_bytes, stage_spare=STAGE_BUDGET-asset_bytes, changed_payload=list(PAYLOAD_CHANGED),
        unchanged_payload_files=14, changed_staged_files=5, sender_outer=list(OUTER),
        ui_validator=list(pin(VALIDATOR, new_validator)), guardian=list(pin(GUARDIAN, new_guardian)),
        worker=list(pin(WORKER, new_worker)), source_manifest=list(pin(BUNDLE+'/SOURCE.sha256', source)),
        stage_manifest=list(pin(BUNDLE+'/stage-manifest.json', outputs[BUNDLE+'/stage-manifest.json'])),
        exactsource_delta=list(pin(DELTA, outputs[DELTA])), cached_qt_evidence=cached,
        input_count=len(inputs), inputs=[list(pin(path, raw)) for path, raw in sorted(inputs.items())],
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        caps=dict(stage_bytes=STAGE_BUDGET, ui_text_bytes=SOURCE_BUDGET, file_bytes=FILE_BUDGET,
                  source_manifest_bytes=4096, target_max_line=2048, qrc_slot_bytes=NAV_SLOT, geometry='800x268'),
        original_window_seconds=600, original_cleanup_seconds=60, smoke_seconds=20,
        ordinary_graph_changed=False, filecenter_changed=False, lock_changed=False,
        business_definitions_executed=False, old_builders=0, old_mains=0, old_tests=0,
        device=False, rf=False, phone=False, failed_partial_outputs_preserved=True)
    outputs[GENERATION] = encode(generation)
    need(len(outputs) == 27 and all(path.startswith(BUNDLE+'/') or path in
         (VALIDATOR, GUARDIAN, WORKER, DELTA, GENERATION) for path in outputs) and
         all(type(raw) is bytes and 0 < len(raw) <= FILE_BUDGET for raw in outputs.values()), 'output_partition')
    core['verify_inputs'](inputs)
    return outputs, generation, inputs


def main():
    need(sys.argv[1:] in ([], ['--write']), 'explicit_write_only')
    writing = sys.argv[1:] == ['--write']
    outputs, facts, inputs = prepare()
    core, ignored = core_definitions()
    if writing:
        for folder in (BASE / BUNDLE, BASE / ROOT / 'runtime'):
            core['safe_directory'](folder.parent)
            need(not os.path.lexists(folder), 'exclusive_directory')
        need(all(not os.path.lexists(BASE / path) for path in outputs), 'exclusive_files')
        core['verify_inputs'](inputs)
        (BASE / BUNDLE).mkdir(exist_ok=False)
        for name in ('mta', 'toolbox'): (BASE / BUNDLE / name).mkdir(exist_ok=False)
        (BASE / ROOT / 'runtime').mkdir(exist_ok=False)
        for path, raw in outputs.items(): core['write_new'](BASE / path, raw)
        core['inventory'](BASE / BUNDLE, [path[len(BUNDLE)+1:] for path in outputs
                          if path.startswith(BUNDLE+'/') and path[len(BUNDLE)+1:] not in PC_NAMES], PC_NAMES)
        core['verify_inputs'](inputs)
    print(json.dumps(dict(mode='WRITE_EXCLUSIVE_PC_ONLY' if writing else 'SOURCE_ONLY_NO_WRITES',
        session=SESSION, bundle=BUNDLE, remote=REMOTE, control=CONTROL, input_count=len(inputs),
        output_count=len(outputs), outputs=[list(core['pin'](path, raw)) for path, raw in sorted(outputs.items())],
        asset_bytes=facts['asset_bytes'], stage_spare=facts['stage_spare'], device=False, rf=False,
        phone=False, old_builders=0, old_mains=0, old_tests=0), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()

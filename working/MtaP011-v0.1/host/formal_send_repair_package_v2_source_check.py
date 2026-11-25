"""PC SOURCE verification of actual independent sender graph, UI and Worker.

No target module execution, old test/build/main, ADB, RF or phone operation.
Only generated file bytes, pins, AST and retained immutable source are read.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_repair_package_v2_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_PACKAGE_V2_SOURCE_CHECK.cmd'
OLD_GRAPH = ('candidate/formal-send-filecenter-deploy-v5/assets/ordinary-source-manifest.json',
             20796, 'd000945a5e749a7f4d651305ef0e3a0b9f7fce96ffc2360dfed04b0d37ba230c')
NEW_GRAPH = 'candidate/formal-send-filecenter-deploy-v6/assets/ordinary-source-manifest.json'
UI_BUNDLE = 'out/mta-ui-send-picker-v1-c69296a193ff43ce8e5b901d'
OLD_BUNDLE = 'out/mta-ui-send-v5-a44b98dd639095d9063c9e1a'
UI = 'candidate/formal-send-picker-package-v1/runtime/'
WORKER = 'candidate/formal-send-repair-package-v1/runtime/ui_session.py'
WORKER_DELTA = 'candidate/formal-send-repair-package-v1/exactsource-delta.json'
# Freeze actual producer bytes after their independent review, before SOURCE.
GENERATOR_PINS = (
    ('candidate/formal-send-cancel-graph-v1/generate_graph.py', 26849,
     'b6f4d51c451461cc9627e432699ccf5afe51496d24d7dd2f1da783520ba58d5a'),
    ('candidate/formal-send-picker-package-v1/generate_ui.py', 32033,
     '8ed44c223b538ab13cdbc9d2d30dcfbd3e053c436b1177a0b68e3646a6aebd69'),
    ('candidate/formal-send-repair-package-v1/generate_worker.py', 7532,
     'ef9bb3ea0e84ca2617d3d1571655320e7e5c1ef143990a4f7fe3eaac5d32c086'),
)
DERIVATION_PINS = (
    ('candidate/formal-send-filecenter-deploy-v6/exactsource-delta.json', 26221,
     'ebcd9ecbdec8b474d6a9dd9c7306a8b1b959c72fd18beb156ac5736d044ed3be'),
    ('candidate/formal-send-picker-package-v1/generation.json', 18953,
     '4b35068be0fac257a7568d3790a593c42e09d43efe32e96a1a14865ed2658b80'),
    ('candidate/formal-send-repair-package-v1/exactsource-delta.json', 3723,
     'c17ee9d76805212b009b5ee0849e0bacbda6b41a693ac4e4aae0bf483e6113a7'),
)
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EVIDENCE = None
OLD_ROOT = 'p011-mta-formal-send-filecenter-deploy-v5'
NEW_ROOT = 'p011-mta-formal-send-filecenter-deploy-v6'
SESSION = 'c69296a193ff43ce8e5b901d'


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'readback')


def take(path, inputs, pin=None):
    file = BASE / path
    need(file.is_file() and not file.is_symlink(), 'source_file')
    before = file.stat()
    need(EVIDENCE is not None and EVIDENCE.inputs is inputs, 'input_evidence_identity')
    raw = EVIDENCE.read(file, key=path)
    after = file.stat()
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in keys) ==
         tuple(getattr(after, key) for key in keys), 'source_changed')
    if pin is not None:
        need((len(raw), digest(raw)) == tuple(pin), 'source_pin')
    if path in inputs:
        need(inputs[path] == raw, 'source_changed')
    inputs[path] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw, feature_version=(3, 5))
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'literal_identity')
    return ast.literal_eval(rows[0])


def definitions(raw):
    return [ast.dump(node, include_attributes=False) for node in
        ast.parse(raw, feature_version=(3, 5)).body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))]


def replay_pair(origin, current, rows, label):
    need(type(rows) is list and 0 < len(rows) <= 20, label + '_replacement_count')
    forward = origin
    for row in rows:
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        count = row.get('count', 1)
        need(type(count) is int and 0 < count <= 100 and before and after and
             forward.count(before) == count, label + '_forward_count')
        forward = forward.replace(before, after)
    need(forward == current, label + '_full_forward')
    reverse = current
    for row in reversed(rows):
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        count = row.get('count', 1)
        need(reverse.count(after) == count, label + '_inverse_count')
        reverse = reverse.replace(after, before)
    need(reverse == origin, label + '_full_inverse')


def check_derivations(inputs, report):
    graph = json.loads(inputs[DERIVATION_PINS[0][0]])
    ui = json.loads(inputs[DERIVATION_PINS[1][0]])
    need(len(graph['files']) == 8 and graph['business_edits'] == 1, 'graph_derivation_scope')
    allowed = {'mta_service', 'mta_send_trial', 'mta_send_terminal_consumer',
        'mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session',
        'formal_send_stage', 'ordinary-source-manifest'}
    seen = set()
    for row in graph['files']:
        before = take(row['source'][0], inputs, row['source'][1:])
        after = take(row['candidate'][0], inputs, row['candidate'][1:])
        name = Path(row['candidate'][0]).stem
        need(name in allowed and name not in seen and row['candidate'][0].startswith(
             'candidate/formal-send-filecenter-deploy-v6/'), 'graph_derivation_role')
        seen.add(name)
        replay_pair(before, after, row['replacements'], 'graph_' + name)
    need(seen == allowed, 'graph_derivation_complete')
    ui_pairs = (
        ('validator', 'candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py',
         (12526, 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890'),
         UI + 'ui_assets.py', {'SESSION', 'MANIFEST_PIN', 'PINS'}),
        ('guardian', 'candidate/formal-send-filecenter-ui-v7/runtime/ui_guardian.py',
         (43993, '30b7157cabf3dd75eb82a671a343a106c1f9e688c1ad60e12c7b8e172ffc255e'),
         UI + 'ui_guardian.py', {'SESSION', 'CONTROL_NAME'}),
    )
    for label, old_path, old_pin, new_path, names in ui_pairs:
        rows = ui[label + '_constant_replacements']
        need(len(rows) == len(names) and {row['name'] for row in rows} == names,
             'ui_constant_scope')
        before = take(old_path, inputs, old_pin)
        after = take(new_path, inputs)
        replay_pair(before, after, rows, 'ui_' + label)
        need(definitions(before) == definitions(after), 'ui_business_definitions_changed')
    # Frozen UI derivation authenticates all actual output bytes, including
    # ELF/QRC, stage manifest, validator/guardian and PC-only build diagnostics.
    need(len(ui['output_pins']) == 24, 'ui_derived_output_count')
    for path, size, sha in ui['output_pins']:
        take(path, inputs, (size, sha))
    report.update(graph_eight_full_byte_derivations=True,
        ui_validator_three_guardian_two_constants_full_inverse=True,
        ui_twenty_four_derived_outputs_match=True)


def check_graph(inputs, report):
    old = json.loads(take(OLD_GRAPH[0], inputs, OLD_GRAPH[1:]))
    new = json.loads(take(NEW_GRAPH, inputs))
    need(new['source_count'] == 32 and len(new['sources']) == 32 and
         len(new['startup_sources']) == len(new['helper_sources']) == 3, 'graph_count')
    changed = []
    new_raw = {}
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for left, right in zip(old[group], new[group]):
            need(left.get('module') == right.get('module') and left['mode'] == right['mode'] and
                 left.get('reused_sender_asset') == right.get('reused_sender_asset') and
                 right['target'] == left['target'].replace(OLD_ROOT, NEW_ROOT) and
                 right['physical_target'] == left['physical_target'].replace(OLD_ROOT, NEW_ROOT),
                 'graph_role_mapping')
            origin = take(left['source'], inputs, (left['bytes'], left['sha256']))
            current = take(right['source'], inputs, (right['bytes'], right['sha256']))
            name = right.get('module', right['target'].split('/')[-1])
            new_raw[name] = current
            if origin != current:
                changed.append(name)
                if name == 'mta_service':
                    tested = take('candidate/formal-send-cancel-status-v1/runtime/mta_service.py',
                        inputs, (145733, '4b1971056673e492e42d59410594192ea7165687ec0ac807cb61deccd5e75d82'))
                    need(current.replace(NEW_ROOT.encode('ascii'), OLD_ROOT.encode('ascii')) == tested,
                         'only_tested_service_change')
                else:
                    # Only this Owner embeds the independently versioned path in a method.
                    # Full frozen byte inverse above still binds both exact root occurrences.
                    normalized = (current.replace(NEW_ROOT.encode('ascii'), OLD_ROOT.encode('ascii'))
                                  if name == 'mta_client_service_owner' else current)
                    need(definitions(origin) == definitions(normalized), 'business_definitions_changed')
            else:
                need(right['source'] == left['source'], 'unchanged_source_not_reused')
    need(set(changed) == {'mta_service', 'mta_send_trial', 'mta_send_terminal_consumer',
        'mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session'}, 'graph_delta_scope')
    pins = tuple((row['module'], row['bytes'], row['sha256']) for row in new['sources'])
    boot_pin = (len(new_raw['mta_client_receive_boot']), digest(new_raw['mta_client_receive_boot']))
    owner_pin = (len(new_raw['mta_client_service_owner']), digest(new_raw['mta_client_service_owner']))
    need(literal(new_raw['mta_client_receive_boot'], 'SOURCE_PINS') == pins and
         literal(new_raw['mta_client_service_owner'], 'BOOT_PIN') == boot_pin and
         literal(new_raw['formal_send_session'], 'BOOT_PIN') == boot_pin and
         literal(new_raw['formal_send_session'], 'OWNER_PIN') == owner_pin, 'boot_owner_outer_closure')
    items = [row for row in new['sources'] if not row['reused_sender_asset']]
    items += new['startup_sources'] + new['helper_sources']
    total = sum(row['bytes'] for row in items)
    need(len(items) == new['ordinary_batch_files'] == 37 and total == new['ordinary_batch_bytes'] and
         total < 4 * 1024 * 1024 and sum(row['bytes'] for row in new['sources']) ==
         new['ordinary_source_bytes'] == old['ordinary_source_bytes'] + 193, 'graph_actual_bytes')
    for field in ('separate_asset_catalog', 'separate_sender_manifest', 'filecenter_source_manifest'):
        need(new[field] == old[field], 'separate_domains_changed')
        row = new[field]
        take(row['source'], inputs, (row['bytes'], row['sha256']))
    old_stage = take('candidate/formal-send-filecenter-deploy-v5/runtime/formal_send_stage.py', inputs,
        (37417, '7ea5f8a058da636c7f1b16f29199b3c6cd2bc2541a4825791668005413ba6398'))
    new_stage = take('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_stage.py', inputs)
    need(definitions(old_stage) == definitions(new_stage), 'stage_business_changed')
    table = literal(new_stage, 'PROFILE_FILES')
    expected = tuple((row['physical_target'].split('/' + NEW_ROOT + '/', 1)[1],
                      row['bytes'], row['sha256'], row['mode']) for row in items)
    need(table[2] == ('ordinary', '/var/volatile/tmp/' + NEW_ROOT, expected) and
         table[:2] == literal(old_stage, 'PROFILE_FILES')[:2] and
         literal(new_stage, 'MAX_SECONDS') == 120.0, 'stage_manifest_closure')
    report.update(ordinary_roles=32, startup_roles=3, helper_roles=3,
        actual_staged_file_count=37, ordinary_bytes=total, actual_graph_changed_roles=changed,
        actual_service_is_tested_cancel_candidate=True, boot_owner_outer_pin_closure=True,
        separate_sender_observer_filecenter_unchanged=True, actual_stage_table_matches=True)


def check_ui_worker(inputs, report):
    stage = json.loads(take(UI_BUNDLE + '/stage-manifest.json', inputs))
    need(stage['session'] == SESSION and stage['staged_file_count'] == 19 and
         stage['payload_file_count'] == 18 and len(stage['files']) == 19 and
         stage['credentials_in_stage'] is False and stage['font_files_bundled'] is False, 'ui_shape')
    validator = take(UI + 'ui_assets.py', inputs)
    guardian = take(UI + 'ui_guardian.py', inputs)
    old_validator = take('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py', inputs,
        (12526, 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890'))
    old_pin_map = {name: (size, sha) for name, size, sha in literal(old_validator, 'PINS')}
    old_pin_map['SOURCE.sha256'] = literal(old_validator, 'MANIFEST_PIN')
    pins = tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files']
                 if row['path'] != 'SOURCE.sha256')
    need(literal(validator, 'SESSION') == literal(guardian, 'SESSION') == SESSION and
         literal(validator, 'PINS') == tuple(sorted(pins)), 'ui_runtime_pins')
    changed, reused, total = [], [], 0
    for row in stage['files']:
        name = row['path']
        current = take(UI_BUNDLE + '/' + name, inputs, (row['bytes'], row['sha256']))
        origin = take(OLD_BUNDLE + '/' + name, inputs, old_pin_map[name])
        total += len(current)
        (reused if current == origin else changed).append(name)
    need(set(changed) == {'mta/MtaHost.qml', 'Bridge.qml', 'FormalEntry.qml',
        'Z03.mta-ui-candidate', 'SOURCE.sha256'} and len(reused) == 14 and total <= 4194304,
        'ui_delta_scope_budget')
    host = take('candidate/formal-send-picker-generation-v1/device/mta/MtaHost.qml', inputs,
        (6602, 'dcb6178f6d3179b7bab61e6818ae21a02443c902446f6b203c82bd16b8b479c3'))
    need(inputs[UI_BUNDLE + '/mta/MtaHost.qml'] == host, 'actual_tested_picker_bytes')
    manifest = inputs[UI_BUNDLE + '/SOURCE.sha256']
    need(literal(validator, 'MANIFEST_PIN') == (len(manifest), digest(manifest)) and
         manifest == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
             for name, size, sha in sorted(pins)).encode('ascii'), 'ui_manifest')
    delta = json.loads(take(WORKER_DELTA, inputs))
    need(delta['origin'] == ['candidate/formal-send-filecenter-ui-v7/runtime/ui_session.py',
        46415, 'bbbaf091f20715531e045d1b7b1a281bc78d569f5bac6089da1b105d2282dbe4'],
        'fixed_worker_origin')
    origin = take(delta['origin'][0], inputs, delta['origin'][1:])
    worker = take(WORKER, inputs, delta['candidate'][1:])
    need(delta['candidate'][0] == WORKER and len(delta['replacements']) == 8, 'worker_delta')
    names = {'SENDER_PIN', 'GUARDIAN_PIN', 'ASSETS_PIN', 'SENDER_ROOT',
             'SENDER_PHYSICAL_ROOT', 'SESSION', 'CONTROL_NAME', 'SENDER_ASSET_SEAL'}
    need({row['name'] for row in delta['replacements']} == names, 'worker_assignment_scope')
    restored = worker
    for row in reversed(delta['replacements']):
        after, before = row['after'].encode('ascii'), row['before'].encode('ascii')
        need(row['count'] == 1 and restored.count(after) == 1, 'worker_inverse_count')
        restored = restored.replace(after, before, 1)
    need(restored == origin and definitions(worker) == definitions(origin), 'worker_full_inverse')
    shape = lambda raw: [ast.dump(node, include_attributes=False) for node in ast.parse(raw).body
        if not (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names
            for target in node.targets))]
    need(shape(worker) == shape(origin), 'worker_other_toplevel_ast')
    outer = [row for row in json.loads(inputs[NEW_GRAPH])['startup_sources']
             if row['module'] == 'formal_send_session'][0]
    need(literal(worker, 'SENDER_PIN') == (outer['bytes'], outer['sha256']) and
         literal(worker, 'GUARDIAN_PIN') == (len(guardian), digest(guardian)) and
         literal(worker, 'ASSETS_PIN') == (len(validator), digest(validator)) and
         literal(worker, 'SESSION') == SESSION, 'worker_actual_pin_closure')
    for row in delta['source_inputs']:
        take(row['path'], inputs, (row['bytes'], row['sha256']))
    report.update(ui_stage_files=19, ui_payload_files=18, ui_actual_bytes=total,
        ui_unchanged_payloads=14, ui_changed_files=changed,
        actual_picker_is_tested_bytes=True, ui_manifest_validator_closure=True,
        worker_assignments_changed=8, worker_full_byte_inverse=True,
        worker_business_definitions_unchanged=True, worker_actual_pins_match=True)


def main():
    global EVIDENCE
    need(not sys.argv[1:] and len(GENERATOR_PINS) == len(DERIVATION_PINS) == 3 and len(SEALER) == 3,
         'fixed_SOURCE_only_frozen_producers')
    seal_raw = (BASE / SEALER[0]).read_bytes()
    need((len(seal_raw), digest(seal_raw)) == SEALER[1:], 'sealer_pin')
    sealer = types.ModuleType('sender_repair_private_host_seal')
    sealer.__file__ = str(BASE / SEALER[0])
    exec(compile(seal_raw, sealer.__file__, 'exec'), sealer.__dict__)
    out = BASE / 'results' / ('formal-send-repair-package-v2-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    inputs = {}
    EVIDENCE = sealer.InputEvidence(inputs)
    report = dict(schema='p011-formal-send-repair-package-v2-source', passed=False,
        error=None, source_preserved=False, target_business_invoked=False,
        old_methods_run=0, new_methods_run=0, stage_invoked=False, device=False,
        rf=False, phone=False, send_verified=False, restoration_verified=False,
        candidate_deployed=False, production_admitted=False, remote_exit='NOT_RUN_SOURCE_ONLY',
        snapshot_complete=False, input_read_complete=False)
    try:
        EVIDENCE.read(BASE / SEALER[0], key=SEALER[0], pin=SEALER[1:])
        for path, size, sha in GENERATOR_PINS:
            take(path, inputs, (size, sha))
        for path, size, sha in DERIVATION_PINS:
            take(path, inputs, (size, sha))
        take(SELF, inputs); take(CMD, inputs)
        check_derivations(inputs, report)
        check_graph(inputs, report)
        check_ui_worker(inputs, report)
    except Exception as error:
        report['error'] = type(error).__name__ + ':' + str(error)
        try:
            save(out / 'private-raw' / 'host-error.txt', traceback.format_exc().encode('utf-8'))
        except Exception as diagnostic_error:
            report['diagnostic_error'] = type(diagnostic_error).__name__
    finally:
        report['source_count'] = len(inputs)
        report['input_read_complete'] = not EVIDENCE.partial and not EVIDENCE.changed_attempts
        try:
            EVIDENCE.snapshot(out, lambda path: path)
            save(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
                for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
            report['snapshot_complete'] = True
            report['source_preserved'] = bool(inputs) and all(
                (BASE / path).read_bytes() == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items())
        except Exception as snapshot_error:
            report['snapshot_error'] = type(snapshot_error).__name__
            if report['error'] is None:
                report['error'] = 'source_snapshot_failed'
    report['passed'] = report['error'] is None and report['source_preserved']
    report['host_exit'] = 0 if report['passed'] else 1
    readme = (b'PC SOURCE only: actual new sender32/startup3/helper3 graph, ordinary37 stage table; '
        b'tested cancellation service + mechanical root/pin closure; UI19 includes actual tested '
        b'picker6602 and fourteen unchanged payloads; actual eight Worker constants verified. '
        b'Old status33 and Qt picker9 are reused evidence, not rerun. No old methods/build/main, '
        b'target modules, device/RF/phone, user files, runtime send or restoration verification. '
        b'Existing separate sender27/observer41 and FileCenter9 stay unchanged, including their '
        b'old Proc source; receiver freezer success does not certify this sender. '
        b'Public ZIP exactly result.json and README.txt; inputs and full error diagnostics are private.\n')
    try:
        save(out / 'private-raw/component-checker-code-before-seal.raw',
             (str(report['host_exit']) + '\n').encode('ascii'))
        save(out / 'private-raw/remote-exit.raw', b'NOT_RUN_SOURCE_ONLY\n')
    except Exception as exit_error:
        report['error'] = 'exit_evidence_failed:' + type(exit_error).__name__
        report['passed'] = False
        report['host_exit'] = 1
    sealed = sealer.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], result_dir=str(out),
        zip_sha256=sealed['archive_sha256'], checker_exit=sealed['host_exit'], device=False), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())

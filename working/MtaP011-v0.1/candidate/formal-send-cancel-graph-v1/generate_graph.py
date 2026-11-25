"""PC-only SOURCE plan; only --write exclusively creates absent deploy-v6.
No old main/helper/suite/test/target module, build, subprocess, ADB, device, UI,
RF, credential or transport code executes. Only State.status has a business
delta; all other changes are reversible root/pin/catalog propagation. Preserve
sender27, observer41, helper3, FC9 and 29 ordinary source bytes at original PC
paths; mta_go_deployment retains its original sender-private target.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/formal-send-cancel-graph-v1/generate_graph.py'
OLD = 'candidate/formal-send-filecenter-deploy-v5'
NEW = 'candidate/formal-send-filecenter-deploy-v6'
OLD_NAME = 'p011-mta-formal-send-filecenter-deploy-v5'
NEW_NAME = 'p011-mta-formal-send-filecenter-deploy-v6'
OLD_ROOT = '/tmp/' + OLD_NAME
NEW_ROOT = '/tmp/' + NEW_NAME
OLD_PHYSICAL = '/var/volatile/tmp/' + OLD_NAME
NEW_PHYSICAL = '/var/volatile/tmp/' + NEW_NAME
CATALOG = (OLD + '/assets/ordinary-source-manifest.json', 20796, 'd000945a5e749a7f4d651305ef0e3a0b9f7fce96ffc2360dfed04b0d37ba230c')
STAGE = (OLD + '/runtime/formal_send_stage.py', 37417, '7ea5f8a058da636c7f1b16f29199b3c6cd2bc2541a4825791668005413ba6398')
CANCEL = ('candidate/formal-send-cancel-status-v1/runtime/mta_service.py', 145733, '4b1971056673e492e42d59410594192ea7165687ec0ac807cb61deccd5e75d82')
CANCEL_DELTA = ('candidate/formal-send-cancel-status-v1/exactsource-delta.json', 1458, '1dcaa43c0d0bc465bda3e8a1b0f8ea18f342346713fb80e1e5a3dff0f6e4d2aa')
ASSETS = ('candidate/formal-send-filecenter-deploy-v4/assets/asset-sources.json', 24267, 'be76740f8d7283e2db5806790c87997dee24a0911beb1306d7c9833086745ec0')
OBSERVER = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json', 15861, '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
FILECENTER = ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json', 2466, '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')
BOOT = 'mta_client_receive_boot'
OWNER = 'mta_client_service_owner'
OUTER = 'formal_send_session'
CHANGED_ORDINARY = ('mta_send_trial', 'mta_send_terminal_consumer', 'mta_service')
GENERATED_ROLES = CHANGED_ORDINARY + (BOOT, OWNER, OUTER)
ROOT_COUNTS = {'mta_send_trial': 1, 'mta_send_terminal_consumer': 1,
               'mta_service': 1, BOOT: 2, OWNER: 2, OUTER: 2,
               'formal_send_stage': 1}
BUSINESS_BEFORE = (
    "                    elif sending and session['phase']=='failed':state='error';reason="
    "'发送未完成；资源已关闭，没有报告成功'\n")
BUSINESS_AFTER = BUSINESS_BEFORE + (
    "                    elif sending and session['phase']=='cancelled':\n"
    "                        state='idle'\n"
    "                        if not pending:reason='已取消发送；未报告传输成功'\n")
def need(value, code):
    if value is not True:
        raise ValueError(code)
def digest(raw):
    return hashlib.sha256(raw).hexdigest()
def pin(raw):
    return (len(raw), digest(raw))
def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
def read_fixed(inputs, row):
    relative, size, checksum = row
    parts = PurePosixPath(relative)
    need(not parts.is_absolute() and '..' not in parts.parts and
         str(parts) == relative, 'input_path')
    path = BASE / relative
    need(path.resolve() == path and stat.S_ISREG(path.lstat().st_mode) and
         not path.is_symlink(), 'input_identity')
    raw = path.read_bytes()
    need(pin(raw) == (size, checksum), 'input_pin:' + relative)
    if relative in inputs:
        need(inputs[relative] == raw, 'duplicate_input_changed')
    inputs[relative] = raw
    return raw
def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    values = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == name
                      for target in node.targets)]
    need(len(values) == 1, 'literal_count:' + name)
    return ast.literal_eval(values[0])
def ast_shape(raw):
    return ast.dump(ast.parse(raw.decode('utf-8'), feature_version=(3, 5)),
                    include_attributes=False)
def definitions(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    rows = []
    def visit(body, prefix):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                name = prefix + node.name
                rows.append((name, type(node).__name__))
                visit(node.body, name + '.')
    visit(tree.body, '')
    return tuple(rows)
def without_status(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    classes = [node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == 'State']
    need(len(classes) == 1, 'business_class')
    matches = [node for node in classes[0].body
               if isinstance(node, ast.FunctionDef) and node.name == 'status']
    need(len(matches) == 1, 'business_method')
    classes[0].body.remove(matches[0])
    return ast.dump(tree, include_attributes=False)
def replace(raw, changes, name, before, after, count=1, scope='mechanical'):
    need(type(before) is str and type(after) is str and before != after and
         type(count) is int and count > 0, 'replacement_shape')
    old, new = before.encode('utf-8'), after.encode('utf-8')
    need(raw.count(old) == count and raw.count(new) == 0,
         'replacement_unique:' + name)
    result = raw.replace(old, new)
    need(result.count(new) == count and result.replace(new, old) == raw,
         'replacement_inverse:' + name)
    changes.append(dict(name=name, before=before, after=after, count=count, scope=scope))
    return result
def replay(raw, changes, reverse=False):
    for change in reversed(changes) if reverse else changes:
        old, new = (change['after'], change['before']) if reverse else (
            change['before'], change['after'])
        old, new = old.encode('utf-8'), new.encode('utf-8')
        need(raw.count(old) == change['count'], 'replay_count')
        raw = raw.replace(old, new)
    return raw
def root_change(raw, changes, role):
    return replace(raw, changes, 'independent_root', OLD_NAME, NEW_NAME,
                   ROOT_COUNTS[role])
def tuple_pin_line(raw, changes, name, old_pin, new_pin, module_name=None,
                   double_quotes=False, tail=''):
    quote = '"' if double_quotes else "'"
    if module_name is None:
        before = '%s = (%d, %s%s%s)' % (name, old_pin[0], quote, old_pin[1], quote)
        after = '%s = (%d, %s%s%s)' % (name, new_pin[0], quote, new_pin[1], quote)
    else:
        before = '(%s%s%s, %d, %s%s%s%s)' % (
            quote, module_name, quote, old_pin[0], quote, old_pin[1], quote, tail)
        after = '(%s%s%s, %d, %s%s%s%s)' % (
            quote, module_name, quote, new_pin[0], quote, new_pin[1], quote, tail)
    return replace(raw, changes, 'pin_' + name, before, after)
def record(source, destination, old_raw, new_raw, changes, business_raw=None):
    need(replay(old_raw, changes) == new_raw and
         replay(new_raw, changes, True) == old_raw, 'whole_byte_inverse')
    mechanical = [change for change in changes if change['scope'] == 'mechanical']
    restored = replay(new_raw, mechanical, True)
    reference = old_raw if business_raw is None else business_raw
    need(restored == reference and ast_shape(restored) == ast_shape(reference),
         'mechanical_ast_inverse')
    need(definitions(old_raw) == definitions(new_raw), 'definition_roster')
    return dict(source=[source, len(old_raw), digest(old_raw)],
                candidate=[destination, len(new_raw), digest(new_raw)],
                replacements=changes, exact_bytes_forward=True,
                exact_bytes_reverse=True, mechanical_inverse_definitions_exact=True,
                definition_roster_unchanged=True)
def rows_from_catalog(catalog, physical):
    items = [row for row in catalog['sources'] if not row['reused_sender_asset']]
    items += catalog['startup_sources'] + catalog['helper_sources']
    need(len(items) == 37, 'ordinary_file_count')
    result = []
    for item in items:
        target = item['physical_target']
        need(target.startswith(physical + '/') and item['mode'] in (256, 320, 448),
             'ordinary_target')
        result.append((target[len(physical) + 1:], item['bytes'], item['sha256'], item['mode']))
    need(len(set(row[0] for row in result)) == 37, 'ordinary_unique')
    return tuple(result)
def compose():
    need(not (BASE / NEW).exists() and not (BASE / NEW).is_symlink(), 'new_tree_exists')
    self_raw = (BASE / SELF).read_bytes()
    inputs = {}
    read_fixed(inputs, (SELF, len(self_raw), digest(self_raw)))
    raw_catalog = read_fixed(inputs, CATALOG)
    raw_stage = read_fixed(inputs, STAGE)
    raw_cancel = read_fixed(inputs, CANCEL)
    cancel_delta = json.loads(read_fixed(inputs, CANCEL_DELTA))
    assets = json.loads(read_fixed(inputs, ASSETS))
    observer = json.loads(read_fixed(inputs, OBSERVER))
    fc = json.loads(read_fixed(inputs, FILECENTER))
    catalog = json.loads(raw_catalog)
    need(catalog['schema'] == 'p011-formal-send-filecenter-deploy-v5-ordinary-source-catalog'
         and catalog['kind'] == 'fixed-deployment-source-not-staged-not-run'
         and catalog['source_count'] == len(catalog['sources']) == 32
         and catalog['ordinary_source_bytes'] == 1078493
         and catalog['ordinary_root'] == OLD_ROOT + '/runtime'
         and catalog['physical_ordinary_root'] == OLD_PHYSICAL + '/runtime'
         and len(catalog['startup_sources']) == len(catalog['helper_sources']) == 3
         and (catalog['ordinary_batch_files'], catalog['ordinary_batch_bytes']) == (37, 1353583)
         and catalog['original_boot_load_seconds'] == 10
         and catalog['original_per_source_cap_bytes'] == catalog['program_cap_bytes'] == 2097152
         and catalog['wire_cap_bytes'] == 4194304
         and catalog['source_pins_do_not_admit_rf'] is True and catalog['asset_payload_inline'] is False,
         'catalog_shape')
    need(catalog['separate_asset_catalog']['source'] == ASSETS[0] and
         (catalog['separate_asset_catalog']['bytes'],
          catalog['separate_asset_catalog']['sha256']) == ASSETS[1:] and
         catalog['filecenter_source_manifest']['source'] == FILECENTER[0] and
         (catalog['filecenter_source_manifest']['bytes'],
          catalog['filecenter_source_manifest']['sha256']) == FILECENTER[1:],
         'private_catalog_binding')
    ordinary = {}
    all_rows = catalog['sources'] + catalog['startup_sources'] + catalog['helper_sources']
    need(len(all_rows) == 38, 'catalog_role_count')
    for item in all_rows:
        raw = read_fixed(inputs, (item['source'], item['bytes'], item['sha256']))
        if 'module' in item:
            need(item['module'] not in ordinary, 'module_duplicate')
            ordinary[item['module']] = (item, raw)
    need(len(ordinary) == 35 and sum(row['bytes'] for row in catalog['sources']) == 1078493,
         'role_bytes')
    special = [row for row in catalog['sources'] if row['reused_sender_asset']]
    need(len(special) == 1 and special[0]['module'] == 'mta_go_deployment' and
         special[0]['physical_target'] == assets['sender_root'] + '/runtime/mta_go_deployment.py'
         and special[0]['target'] == special[0]['physical_target'], 'private_role_target')
    for role, (item, raw) in ordinary.items():
        count = ROOT_COUNTS.get(role, 0)
        need(raw.count(OLD_NAME.encode('ascii')) == count, 'root_scope:' + role)
    need(raw_stage.count(OLD_NAME.encode('ascii')) == 1, 'stage_root_scope')
    # Authenticate private inventories as data, never replay their acceptance.
    table = literal(raw_stage, 'PROFILE_FILES')
    old_rows = rows_from_catalog(catalog, OLD_PHYSICAL)
    need(literal(raw_stage, 'PROFILE_TOTALS') == (
        ('sender', 27, 2402458), ('observer', 41, 1442508), ('ordinary', 37, 1353583))
        and literal(raw_stage, 'MAX_SECONDS') == 120.0
        and table[2] == ('ordinary', OLD_PHYSICAL, old_rows), 'stage_binding')
    sender_rows = []
    for item in assets['sender_sources'] + [assets['sender_manifest'], assets['wpa']]:
        need(item['target'].startswith(assets['sender_root'] + '/'), 'sender_target')
        sender_rows.append((item['target'][len(assets['sender_root']) + 1:],
                            item['bytes'], item['sha256'], int(item.get('mode', '0400'), 8)))
    observer_rows = tuple(('runtime/' + item['module'] + '.py', item['bytes'],
                           item['sha256'], 256) for item in observer['files'])
    need(len(sender_rows) == 27 and sum(row[1] for row in sender_rows) == 2402458
         and len(observer_rows) == 41 and sum(row[1] for row in observer_rows) == 1442508
         and table[:2] == (('sender', assets['sender_root'], tuple(sender_rows)),
                          ('observer', observer['root'], observer_rows)), 'private_profiles')
    fc_rows = tuple((row['module'], row['bytes'], row['sha256']) for row in fc['sources'])
    need(fc['source_count'] == 9 and fc['source_bytes'] == 99972
         and fc['source_cap'] == 131072 and len(fc_rows) == 9
         and sum(row[1] for row in fc_rows) == 99972
         and literal(ordinary[OWNER][1], 'FILECENTER_PINS') == fc_rows,
         'filecenter_pins')
    for item in fc['sources']:
        read_fixed(inputs, (item['source'], item['bytes'], item['sha256']))
    old_service = ordinary['mta_service'][1]
    expected_business = dict(name='closed_sender_cancelled_status_reason',
                             before=BUSINESS_BEFORE, after=BUSINESS_AFTER, count=1)
    need(cancel_delta['schema'] == 'p011-formal-send-cancel-status-source-delta-v1'
         and cancel_delta['source'] == [ordinary['mta_service'][0]['source'],
                                      len(old_service), digest(old_service)]
         and cancel_delta['candidate'] == list(CANCEL)
         and cancel_delta['selected_manifest'] == list(CATALOG)
         and cancel_delta['replacements'] == [expected_business]
         and cancel_delta['session_close_predicate_changed'] is False
         and cancel_delta['restoration_branch_changed'] is False
         and cancel_delta['success_predicate_changed'] is False, 'business_contract')
    business_changes = []
    rebuilt_cancel = replace(old_service, business_changes, expected_business['name'],
                              BUSINESS_BEFORE, BUSINESS_AFTER, scope='business')
    need(rebuilt_cancel == raw_cancel and len(raw_cancel) - len(old_service) == 193
         and without_status(old_service) == without_status(raw_cancel)
         and definitions(old_service) == definitions(raw_cancel), 'business_only_status')
    outputs, delta_rows = {}, []
    changed = {}
    def retain(role, raw, changes, business=None):
        source, before = ordinary[role][0]['source'], ordinary[role][1]
        destination = NEW + '/runtime/' + role + '.py'
        delta_rows.append(record(source, destination, before, raw, changes, business))
        outputs[destination] = raw
        changed[role] = raw
    for role in CHANGED_ORDINARY:
        changes = copy.deepcopy(business_changes) if role == 'mta_service' else []
        base_raw = raw_cancel if role == 'mta_service' else ordinary[role][1]
        raw = root_change(base_raw, changes, role)
        retain(role, raw, changes, raw_cancel if role == 'mta_service' else None)
    changes = []
    raw = root_change(ordinary[BOOT][1], changes, BOOT)
    for role in CHANGED_ORDINARY:
        raw = tuple_pin_line(raw, changes, role, pin(ordinary[role][1]), pin(changed[role]), role)
    retain(BOOT, raw, changes)
    boot_pins = literal(raw, 'SOURCE_PINS')
    need(len(boot_pins) == 32 and tuple(row[0] for row in boot_pins) ==
         tuple(row['module'] for row in catalog['sources']), 'boot_roles')
    for item, row in zip(catalog['sources'], boot_pins):
        expected = pin(changed[item['module']]) if item['module'] in changed else (
            item['bytes'], item['sha256'])
        need(row == (item['module'],) + expected, 'boot_role_pin')
    changes = []
    raw = root_change(ordinary[OWNER][1], changes, OWNER)
    raw = tuple_pin_line(raw, changes, 'BOOT_PIN', pin(ordinary[BOOT][1]), pin(changed[BOOT]))
    retain(OWNER, raw, changes)
    need(literal(raw, 'FILECENTER_PINS') == fc_rows
         and literal(raw, 'FIXED_ASSET_PINS') == literal(ordinary[OWNER][1], 'FIXED_ASSET_PINS')
         and literal(raw, 'HELPER_PINS') == literal(ordinary[OWNER][1], 'HELPER_PINS')
         and literal(raw, 'CONNMAN_PIN') == literal(ordinary[OWNER][1], 'CONNMAN_PIN'),
         'owner_private_unchanged')
    changes = []
    raw = root_change(ordinary[OUTER][1], changes, OUTER)
    for name, role in (('BOOT_PIN', BOOT), ('OWNER_PIN', OWNER)):
        raw = tuple_pin_line(raw, changes, name, pin(ordinary[role][1]), pin(changed[role]))
    retain(OUTER, raw, changes)
    need(literal(raw, 'PROFILES') == (('diagnostic', 60.0, False),
                                    ('send-interactive-v1', 600.0, True)), 'outer_caps')
    # JSON byte edits retain order/whitespace and a complete inverse.
    role_delta = sum(len(changed[role]) - len(ordinary[role][1]) for role in CHANGED_ORDINARY)
    staged_delta = sum(len(raw) - len(ordinary[role][1]) for role, raw in changed.items())
    ordinary_bytes, staged_bytes = 1078493 + role_delta, 1353583 + staged_delta
    need(role_delta == staged_delta == 193, 'same_width_mechanical_bytes')
    manifest_changes = []
    new_manifest = replace(raw_catalog, manifest_changes, 'catalog_schema',
        'p011-formal-send-filecenter-deploy-v5-ordinary-source-catalog',
        'p011-formal-send-filecenter-deploy-v6-ordinary-source-catalog')
    new_manifest = replace(new_manifest, manifest_changes, 'catalog_target_roots',
        OLD_NAME, NEW_NAME, raw_catalog.count(OLD_NAME.encode('ascii')))
    for role in GENERATED_ROLES:
        item = ordinary[role][0]
        before = ('"source": "%s",\n      "bytes": %d,\n      "sha256": "%s"' % (
            item['source'], item['bytes'], item['sha256']))
        after = ('"source": "%s/runtime/%s.py",\n      "bytes": %d,\n      "sha256": "%s"' % (
            NEW, role, len(changed[role]), digest(changed[role])))
        new_manifest = replace(new_manifest, manifest_changes, 'catalog_pin_' + role,
                               before, after)
    new_manifest = replace(new_manifest, manifest_changes, 'catalog_role_bytes',
        '"ordinary_source_bytes": 1078493', '"ordinary_source_bytes": %d' % ordinary_bytes)
    new_manifest = replace(new_manifest, manifest_changes, 'catalog_staged_bytes',
        '"ordinary_batch_bytes": 1353583', '"ordinary_batch_bytes": %d' % staged_bytes)
    destination = NEW + '/assets/ordinary-source-manifest.json'
    need(replay(raw_catalog, manifest_changes) == new_manifest and
         replay(new_manifest, manifest_changes, True) == raw_catalog, 'catalog_byte_inverse')
    outputs[destination] = new_manifest
    delta_rows.append(dict(source=list(CATALOG),
        candidate=[destination, len(new_manifest), digest(new_manifest)],
        replacements=manifest_changes, exact_bytes_forward=True, exact_bytes_reverse=True))
    final_catalog = json.loads(new_manifest)
    new_rows = rows_from_catalog(final_catalog, NEW_PHYSICAL)
    need(len(new_rows) == 37 and sum(row[1] for row in new_rows) == staged_bytes
         and final_catalog['ordinary_source_bytes'] == sum(
             row['bytes'] for row in final_catalog['sources']) == ordinary_bytes,
         'new_catalog_bytes')
    need(final_catalog['helper_sources'] == [dict(row,
        target=row['target'].replace(OLD_NAME, NEW_NAME),
        physical_target=row['physical_target'].replace(OLD_NAME, NEW_NAME))
        for row in catalog['helper_sources']]
        and [row for row in final_catalog['sources'] if row['reused_sender_asset']] == special,
        'helper_private_unchanged')
    expected_catalog = copy.deepcopy(catalog)
    expected_catalog['schema'] = final_catalog['schema']
    expected_catalog['ordinary_root'] = NEW_ROOT + '/runtime'
    expected_catalog['physical_ordinary_root'] = NEW_PHYSICAL + '/runtime'
    expected_catalog['ordinary_source_bytes'] = ordinary_bytes
    expected_catalog['ordinary_batch_bytes'] = staged_bytes
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for item in expected_catalog[group]:
            for key in ('target', 'physical_target'):
                item[key] = item[key].replace(OLD_NAME, NEW_NAME)
            role = item.get('module')
            if role in changed:
                item['source'] = NEW + '/runtime/' + role + '.py'
                item['bytes'], item['sha256'] = pin(changed[role])
    need(final_catalog == expected_catalog, 'catalog_no_extra_change')
    stage_changes = []
    new_stage = root_change(raw_stage, stage_changes, 'formal_send_stage')
    for role in GENERATED_ROLES:
        new_stage = tuple_pin_line(new_stage, stage_changes, role,
            pin(ordinary[role][1]), pin(changed[role]), 'runtime/' + role + '.py',
            double_quotes=True, tail=', 256')
    new_stage = replace(new_stage, stage_changes, 'ordinary_profile_bytes',
        "('ordinary', 37, 1353583)", "('ordinary', 37, %d)" % staged_bytes)
    destination = NEW + '/runtime/formal_send_stage.py'
    delta_rows.append(record(STAGE[0], destination, raw_stage, new_stage, stage_changes))
    outputs[destination] = new_stage
    need(literal(new_stage, 'PROFILE_FILES') == table[:2] + (('ordinary', NEW_PHYSICAL, new_rows),)
         and literal(new_stage, 'PROFILE_TOTALS') == (
             ('sender', 27, 2402458), ('observer', 41, 1442508), ('ordinary', 37, staged_bytes))
         and literal(new_stage, 'MAX_SECONDS') == 120.0, 'new_stage_binding')
    need(len(outputs) == 8 and len(changed) == 6
         and len(changed['mta_service']) - len(old_service) == 193,
         'generated_scope')
    for relative, raw in outputs.items():
        need(relative.startswith(NEW + '/') and len(raw) <= 2097152, 'output_budget')
        if relative.endswith('.py'):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    input_rows = [[path, len(raw), digest(raw)] for path, raw in sorted(inputs.items())]
    for path, raw in inputs.items():
        need((BASE / path).read_bytes() == raw, 'input_changed_before_return')
    delta = dict(schema='p011-formal-send-cancel-graph-v1-exact-source-delta',
                 evidence='PC_SOURCE_TRANSFORM_NOT_DEVICE_OR_RF', generator=[SELF, len(self_raw), digest(self_raw)],
                 inputs=input_rows, files=delta_rows, business_edits=1,
                 changed_ordinary_roles=list(CHANGED_ORDINARY),
                 ordinary_roles=32, staged_files=37, reused_ordinary_roles=29,
                 reused_helper_files=3, sender_profile_unchanged=True,
                 observer_profile_unchanged=True, filecenter9_unchanged=True,
                 generated_runtime_sources=7, generated_manifests=1,
                 source_bytes_forward_and_reverse=True, target_code_not_executed=True)
    report = dict(schema='p011-formal-send-cancel-graph-v1-generation',
        scope='GENERATED_SOURCE_ONLY_NOT_STAGED_NOT_RUN', generator=[SELF, len(self_raw), digest(self_raw)],
        original_root=OLD_ROOT, root=NEW_ROOT, physical_root=NEW_PHYSICAL,
        business_edits=1, business_method='State.status', business_byte_delta=193,
        ordinary_roles=32, ordinary_source_bytes=ordinary_bytes, staged_files=37, staged_bytes=staged_bytes,
        sender_files=27, sender_bytes=2402458, observer_files=41, observer_bytes=1442508,
        helper_files=3, filecenter_files=9, filecenter_source_bytes=99972,
        original_loader_seconds=10, stage_seconds=120,
        original_service_profiles=[['diagnostic', 60.0, False], ['send-interactive-v1', 600.0, True]],
        program_cap_bytes=2097152, wire_cap_bytes=4194304,
        source_forward_reverse_verified=True, mechanical_ast_inverse_verified=True,
        source_definition_rosters_unchanged=True, only_status_business_ast_changed=True,
        minhttp_close_fix_reused=True, source_unchanged_checked=True,
        runtime=False, host_test=False, build=False, ui=False, device=False, rf=False,
        phone=False, production=False, tests_replayed=False, input_count=len(input_rows), inputs=input_rows,
        outputs=[[path, len(raw), digest(raw)] for path, raw in sorted(outputs.items())])
    outputs[NEW + '/exactsource-delta.json'] = encoded(delta)
    outputs[NEW + '/generation.json'] = encoded(report)
    return inputs, outputs, report
def write_exclusive(inputs, outputs):
    target = BASE / NEW
    need(target.parent.resolve() == BASE / 'candidate' and
         not target.exists() and not target.is_symlink(), 'output_root_identity')
    for path, raw in inputs.items():
        need((BASE / path).read_bytes() == raw, 'input_changed_before_write')
    target.mkdir(mode=0o700, exist_ok=False)
    for child in ('runtime', 'assets'):
        (target / child).mkdir(mode=0o700, exist_ok=False)
    # Failure retains partial exclusive output; no repair/overwrite/delete/retry.
    for relative, raw in sorted(outputs.items()):
        path = BASE / relative
        need(path.parent.resolve() in (target, target / 'runtime', target / 'assets')
             and not path.exists() and not path.is_symlink(), 'output_path_identity')
        with path.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'output_write')
        need(path.read_bytes() == raw, 'output_readback')
    for path, raw in inputs.items():
        need((BASE / path).read_bytes() == raw, 'input_changed_after_write')
    need({str(path.relative_to(BASE)).replace('\\', '/') for path in target.rglob('*')
          if path.is_file()} == set(outputs), 'output_inventory')
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true',
                        help='exclusively generate the absent fixed deploy-v6 PC tree')
    arguments = parser.parse_args()
    inputs, outputs, report = compose()
    if arguments.write:
        write_exclusive(inputs, outputs)
    result = dict(report)
    result['mode'] = 'WRITE_SOURCE_ONLY' if arguments.write else 'SOURCE_PLAN_NO_WRITE'
    result['written'] = bool(arguments.write)
    result['planned_output_count'] = len(outputs)
    result['all_output_readbacks_verified'] = bool(arguments.write)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
